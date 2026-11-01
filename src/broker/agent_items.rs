//! Agent tools that add credentials (ADR 0025 §6): capture, generate, save, ask the
//! owner, update, and describe.
//!
//! Rules for every tool:
//!
//! - **The value never leaves.** No answer, activity entry, decision log entry, item
//!   history event, error text, question, or Debug output has the value or a part of it.
//!   The agent gets the item: its ID, its name, its variable, and a one-line summary.
//! - **Create only.** An agent creates items. It changes only its *own* items: the items
//!   whose value it made with capture, generate, or save (`item_origin`). Any other item,
//!   also an item that does not exist, gives `not_owner`. A change of another item is not
//!   a proposal to the owner in this version.
//! - **No oracle.** A value that an own item of the agent has returns that item and
//!   creates nothing. The check reads only the agent's own items, so the answer tells
//!   nothing about the other items of the vault.
//! - **Limit.** An agent adds or changes at most [`MAX_AGENT_ITEMS_PER_HOUR`] items in one
//!   hour: each new item and each new value counts (`too_many_items`; the agent asks the
//!   owner). The limit is checked before a capture runs.
//! - **A normal item.** The new item has the detection of ADR 0025 §4 (provider,
//!   variable, hosts, declaration with sources; a value without a signal gets the most
//!   careful default) and the bouncer decides each use of it as for any item. The history
//!   says "Added by AGENT in PROJECT (TOOL)." An agent with "only these items" gets its
//!   new item on its list: no authority of an existing item moves.
//!
//! Capture (`apassy_capture_credential`) runs outside the sandbox of the agent host, as
//! the broker, so it is mediated:
//!
//! - **A known token command** ([`KNOWN_COMMANDS`], exact argument shapes, such as
//!   `gh auth token` or `op read op://…`) runs at once. Its program comes only from
//!   [`KNOWN_DIRS`] (the system and Homebrew folders), never from the `PATH` or the
//!   working directory of the agent, and it gets [`KNOWN_PATH`]. It may use the network:
//!   the CLI asks its own service for the token.
//! - **Any other command** waits for the owner first: a question "AGENT wants to capture
//!   the output of: ARGV in PROJECT" with the program as the agent's `PATH` finds it
//!   (absolute). Only "Allow once" or "Deny"; nothing is remembered. It waits like a run
//!   question (ADR 0025 §3e): up to the question time, the same request again joins it,
//!   and an agent has one waiting question.
//! - **A file** inside the project of the agent (the root of `project_of(cwd)`, else
//!   `cwd`) is read at once. Any other file waits for the owner the same way.
//! - **Never**, also not after an answer: the Keychain tool `security`, and a path of
//!   Apassy in an argument or as the file: the data folder, the vault files of the vault
//!   list and their backups and synced copies, the Apassy folder in iCloud Drive, and the
//!   Keychain folders (the deny list of `apassy-sandbox`, `docs/operations/isolation.md`).
//!
//! The output is the standard output, trimmed. It must be UTF-8, at most
//! [`MAX_CAPTURE_BYTES`], not empty, and the command must end with exit code 0 within
//! the run time limit. The standard error is erased; it never leaves. `extract` (a JSON
//! path, a line, or the text after a label) picks the credential from the output in the
//! broker, before the detection; an error names the rule, never the output.
//!
//! Ask the owner (`apassy_ask_owner_for_credential`) stores a credential request and
//! waits like a question (ADR 0025 §3e): up to the question time, then `waiting`; the
//! request stays open, and the same request again (the agent, the project, and the name)
//! waits again, also with other words for the purpose. A different request while a
//! question or a request of the agent waits gives `question_waiting` with the ID of the
//! waiting request. At most [`MAX_AGENT_REQUESTS_PER_HOUR`] requests are open or new in an
//! hour (`too_many_requests`). The owner saves (the agent gets the item) or dismisses
//! (`dismissed`).
//!
//! Update (`apassy_update_credential`) keeps the replaced value for a restore by the
//! owner, and makes the declaration the stricter of the old one and the detected one
//! (`Vault::replace_own_item_value`).
//!
//! Describe (`apassy_describe_credential`) changes the name, the notes, the variable, and
//! the placeholder hosts of an own item. Hosts only narrow where the value goes, and only
//! an API key or a login gets them.

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

use super::action_kind::ActionKind;
use super::approvals::{
    AnswerKind, ApprovalOutcome, PendingRun, QuestionInfo, QuestionRefusal, Settled,
};
use super::decide::{BrokerContext, authenticate, lock, locked_response};
use super::exec;
use super::project::{Project, project_of};
use super::shell_risk;
use crate::agent::wire::{Extract, GenerateSpec, WireResponse, codes};
use crate::contracts::CredentialKind;
use crate::vault::agent_items::{
    CredentialRequestState, ItemDescription, MAX_AGENT_ITEMS_PER_HOUR, MAX_AGENT_REQUESTS_PER_HOUR,
    NewCredentialRequest, UPDATE_OPERATION, placeholder_kind,
};
use crate::vault::detect::{self, Detected, Sources};
use crate::vault::exceptions::ExceptionKind;
use crate::vault::usage::InteractionKind;
use crate::vault::{
    ActivityDecision, AgentSummary, EnvDelivery, Field, ItemOrigin, NewActivity, OriginTool,
    SecretValue, Vault, VaultErrorKind, checked_env_name, providers,
};

/// The largest value that capture, a file, or save takes, in bytes.
pub const MAX_CAPTURE_BYTES: usize = 64 * 1024;
pub const DEFAULT_GENERATED_LENGTH: u32 = 32;
pub const MIN_GENERATED_LENGTH: u32 = 16;
pub const MAX_GENERATED_LENGTH: u32 = 128;
/// The folders of a known token command, in this order. The `PATH` and the working
/// directory of the agent never change which program runs.
pub const KNOWN_DIRS: &[&str] = &[
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/opt/homebrew/bin",
    "/usr/local/bin",
];
/// The `PATH` of a known token command.
pub const KNOWN_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin";
/// The `PATH` of a run without one (`exec`).
const RUN_DEFAULT_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// One argument of a known command after the program.
#[derive(Debug, Clone, Copy)]
pub enum Word {
    /// Exactly this text.
    Is(&'static str),
    /// One argument that is not empty and does not start with `-`.
    Any,
    /// One argument that starts with this text and has more after it, such as `op://`.
    Starts(&'static str),
}

/// A command that prints a credential and nothing else, with its exact argument shape.
/// It runs without a question (see the module documentation).
#[derive(Debug)]
pub struct KnownCommand {
    /// The program names, such as `fly` and `flyctl`.
    pub programs: &'static [&'static str],
    /// The arguments that are not options, in order.
    pub words: &'static [Word],
    /// Options with one value: `--name VALUE` or `--name=VALUE`.
    pub options: &'static [&'static str],
    /// Options without a value.
    pub flags: &'static [&'static str],
    /// Options or flags that must be there.
    pub required: &'static [&'static str],
}

const fn known(
    programs: &'static [&'static str],
    words: &'static [Word],
    options: &'static [&'static str],
) -> KnownCommand {
    KnownCommand {
        programs,
        words,
        options,
        flags: &[],
        required: &[],
    }
}

/// The known token commands (`docs/operations/agent-path.md`, section 8e).
pub const KNOWN_COMMANDS: &[KnownCommand] = &[
    known(
        &["gh"],
        &[Word::Is("auth"), Word::Is("token")],
        &["--hostname", "-h", "--user", "-u"],
    ),
    KnownCommand {
        programs: &["op"],
        words: &[Word::Is("read"), Word::Starts("op://")],
        options: &["--account"],
        flags: &["--no-newline", "-n"],
        required: &[],
    },
    known(
        &["aws"],
        &[Word::Is("configure"), Word::Is("get"), Word::Any],
        &["--profile"],
    ),
    known(
        &["aws"],
        &[Word::Is("sts"), Word::Is("get-session-token")],
        &[
            "--profile",
            "--region",
            "--duration-seconds",
            "--output",
            "--query",
        ],
    ),
    known(
        &["aws"],
        &[Word::Is("ecr"), Word::Is("get-login-password")],
        &["--profile", "--region"],
    ),
    known(
        &["gcloud"],
        &[Word::Is("auth"), Word::Is("print-access-token")],
        &["--account"],
    ),
    known(
        &["gcloud"],
        &[Word::Is("auth"), Word::Is("print-identity-token")],
        &["--account", "--audiences"],
    ),
    known(
        &["gcloud"],
        &[
            Word::Is("auth"),
            Word::Is("application-default"),
            Word::Is("print-access-token"),
        ],
        &[],
    ),
    known(
        &["az"],
        &[Word::Is("account"), Word::Is("get-access-token")],
        &[
            "--resource",
            "--scope",
            "--tenant",
            "--subscription",
            "--query",
            "--output",
            "-o",
        ],
    ),
    known(
        &["fly", "flyctl"],
        &[Word::Is("auth"), Word::Is("token")],
        &[],
    ),
    known(&["heroku"], &[Word::Is("auth:token")], &[]),
    KnownCommand {
        programs: &["doppler"],
        words: &[Word::Is("secrets"), Word::Is("get"), Word::Any],
        options: &["--project", "-p", "--config", "-c"],
        flags: &["--plain"],
        required: &["--plain"],
    },
    KnownCommand {
        programs: &["vault"],
        words: &[Word::Is("kv"), Word::Is("get"), Word::Any],
        options: &["-field", "-mount"],
        flags: &[],
        required: &["-field"],
    },
    known(&["vault"], &[Word::Is("print"), Word::Is("token")], &[]),
];

impl KnownCommand {
    /// The arguments after the program have exactly this shape.
    pub fn matches(&self, args: &[String]) -> bool {
        let mut words = Vec::new();
        let mut seen: Vec<&str> = Vec::new();
        let mut index = 0;
        while index < args.len() {
            let arg = args[index].as_str();
            if arg.len() > 1 && arg.starts_with('-') {
                let (name, inline) = match arg.split_once('=') {
                    Some((name, value)) => (name, Some(value)),
                    None => (arg, None),
                };
                if self.options.contains(&name) {
                    let value = match inline {
                        Some(value) => value,
                        None => {
                            index += 1;
                            match args.get(index) {
                                Some(value) => value.as_str(),
                                None => return false,
                            }
                        }
                    };
                    if value.is_empty() || value.starts_with('-') {
                        return false;
                    }
                } else if inline.is_some() || !self.flags.contains(&name) {
                    return false;
                }
                seen.push(name);
            } else {
                words.push(arg);
            }
            index += 1;
        }
        words.len() == self.words.len()
            && words.iter().zip(self.words).all(|(arg, word)| match word {
                Word::Is(text) => arg == text,
                Word::Any => !arg.is_empty(),
                Word::Starts(prefix) => arg.len() > prefix.len() && arg.starts_with(prefix),
            })
            && self.required.iter().all(|name| seen.contains(name))
    }

    /// The shape for a person, such as `gh auth token [--hostname VALUE]`.
    pub fn describe(&self) -> String {
        let mut parts = vec![self.programs.join("|")];
        for word in self.words {
            parts.push(match word {
                Word::Is(text) => (*text).to_owned(),
                Word::Any => "VALUE".to_owned(),
                Word::Starts(prefix) => format!("{prefix}…"),
            });
        }
        for required in self.required {
            parts.push((*required).to_owned());
        }
        for option in self.options {
            parts.push(format!("[{option} VALUE]"));
        }
        for flag in self
            .flags
            .iter()
            .filter(|flag| !self.required.contains(flag))
        {
            parts.push(format!("[{flag}]"));
        }
        parts.join(" ")
    }
}

/// The longest item name: the longest title of the vault.
const MAX_NAME_BYTES: usize = 128;
const MAX_ARGS: usize = 64;
const MAX_ARG_BYTES: usize = 4096;
const MAX_PATH_BYTES: usize = 4096;
const MAX_PURPOSE_BYTES: usize = 500;
/// The longest JSON path or label of `extract`.
const MAX_EXTRACT_BYTES: usize = 128;
/// How often a waiting credential request reads its state.
const POLL: Duration = Duration::from_millis(100);
/// A dismissed request, asked again within this time, is still dismissed.
const DISMISSED_REPEAT_SECONDS: u64 = 3600;
const QUESTION_SUPERSEDED: &str = "A newer call with the same request took over the waiting question. The answer goes to that call.";

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const HEX: &[u8] = b"0123456789abcdef";
const BASE64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/// Letters, digits, and symbols that need no quotes in most shells and formats: no
/// quote, backslash, backtick, `$`, `&`, or space.
const SYMBOLS: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#%()*+,-./:;<=>?@[]^_{|}~";

#[cfg(target_os = "macos")]
const O_NONBLOCK: i32 = 0x0004;
#[cfg(target_os = "macos")]
const O_NOFOLLOW: i32 = 0x0100;
#[cfg(not(target_os = "macos"))]
const O_NONBLOCK: i32 = 0o4000;
#[cfg(not(target_os = "macos"))]
const O_NOFOLLOW: i32 = 0o400_000;

/// A capture: a command or a file.
#[derive(Debug, Clone, Copy)]
pub(super) enum Source<'a> {
    Command(&'a [String]),
    File(&'a str),
    Generate(&'a GenerateSpec),
}

impl<'a> Source<'a> {
    /// Exactly one of `command`, `file`, and `generate`.
    pub(super) fn one_of(
        command: Option<&'a [String]>,
        file: Option<&'a str>,
        generate: Option<&'a GenerateSpec>,
    ) -> Result<Self, WireResponse> {
        match (command, file, generate) {
            (Some(command), None, None) => Ok(Self::Command(command)),
            (None, Some(file), None) => Ok(Self::File(file)),
            (None, None, Some(spec)) => Ok(Self::Generate(spec)),
            _ => Err(invalid(
                "Give exactly one of command (a program and its arguments), file (an absolute path), or generate.",
            )),
        }
    }
}

/// A `capture_credential` request.
#[derive(Debug)]
pub(super) struct CaptureRequest<'a> {
    pub name: Option<&'a str>,
    pub command: Option<&'a [String]>,
    pub file: Option<&'a str>,
    pub cwd: Option<&'a str>,
    pub folder: Option<&'a str>,
    pub purpose: Option<&'a str>,
    pub path: Option<&'a str>,
    pub extract: Option<&'a Extract>,
}

/// An `ask_owner_for_credential` request.
#[derive(Debug)]
pub(super) struct AskRequest<'a> {
    pub name: &'a str,
    pub purpose: &'a str,
    pub where_to_get: Option<&'a str>,
    pub cwd: Option<&'a str>,
    pub folder: Option<&'a str>,
}

/// An `update_credential` request.
#[derive(Debug)]
pub(super) struct UpdateRequest<'a> {
    pub item_id: u64,
    pub command: Option<&'a [String]>,
    pub file: Option<&'a str>,
    pub generate: Option<&'a GenerateSpec>,
    pub cwd: Option<&'a str>,
    pub path: Option<&'a str>,
    pub extract: Option<&'a Extract>,
}

/// The agent, the vault session, and the place of a request.
struct Caller {
    agent: AgentSummary,
    vault_file: PathBuf,
    /// The vault epoch of the first check. A question belongs to this session.
    epoch: [u8; 32],
    project: Option<Project>,
    folder: Option<String>,
    cwd: Option<PathBuf>,
    /// Paths that a capture never reads.
    protected: Protected,
}

impl Caller {
    fn origin(&self, tool: OriginTool) -> ItemOrigin {
        ItemOrigin {
            agent_id: self.agent.id,
            agent_name: self.agent.name.clone(),
            project_key: self.project_key(),
            project_label: self.project_label(),
            tool,
        }
    }

    fn project_key(&self) -> String {
        self.project
            .as_ref()
            .map_or_else(String::new, |project| project.key.clone())
    }

    fn project_label(&self) -> String {
        self.project
            .as_ref()
            .map_or_else(String::new, |project| project.label.clone())
    }

    fn place(&self) -> String {
        let label = self.project_label();
        if label.is_empty() {
            String::new()
        } else {
            format!(" in {label}")
        }
    }

    /// The folder where a file is read without a question: the root of the project, or
    /// the working directory.
    fn own_tree(&self) -> Option<PathBuf> {
        self.project
            .as_ref()
            .and_then(|project| fs::canonicalize(&project.root).ok())
            .or_else(|| self.cwd.clone())
    }

    /// The place for a question: the project, or the folder.
    fn question_place(&self) -> String {
        match (&self.project, &self.cwd) {
            (Some(project), _) => project.label.clone(),
            (None, Some(cwd)) => cwd.display().to_string(),
            (None, None) => "no project".to_owned(),
        }
    }
}

fn invalid(message: &str) -> WireResponse {
    WireResponse::failure("invalid_request", message)
}

fn refused(message: impl Into<String>) -> WireResponse {
    WireResponse::failure(codes::CAPTURE_REFUSED, message)
}

fn not_owner() -> WireResponse {
    WireResponse::failure(
        codes::NOT_OWNER,
        "An agent changes only a credential that it made with apassy_capture_credential, apassy_generate_credential, or apassy_save_credential. Ask the owner to change this one in Apassy.",
    )
}

fn too_many_items() -> WireResponse {
    WireResponse::failure(
        codes::TOO_MANY_ITEMS,
        format!(
            "This agent added or changed {MAX_AGENT_ITEMS_PER_HOUR} credentials in the last hour, so Apassy refused this one. Ask the owner with apassy_ask_owner_for_credential, or wait."
        ),
    )
}

fn waiting(request_id: u64) -> WireResponse {
    WireResponse::failure(
        codes::WAITING,
        format!(
            "The owner has not saved the credential yet. Request {request_id} stays open in Apassy. Call again with the same name to wait again."
        ),
    )
}

fn dismissed() -> WireResponse {
    WireResponse::failure(
        codes::DISMISSED,
        "The owner dismissed this request. Do not ask again for the same credential now; tell the user.",
    )
}

/// Store a refusal in the activity log and return it. The text has no secret value.
fn deny(
    vault: &mut Vault,
    agent: &AgentSummary,
    item_id: Option<u64>,
    operation: &str,
    response: WireResponse,
) -> WireResponse {
    let reason = response
        .error
        .as_ref()
        .map_or_else(String::new, |error| error.message.clone());
    let _ = vault.record_activity(&NewActivity {
        agent_id: Some(agent.id),
        agent_name: agent.name.clone(),
        item_id,
        operation: operation.to_owned(),
        decision: ActivityDecision::Deny,
        reason,
    });
    response
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
}

/// `~/x` with the home folder.
fn expand_home(text: &str) -> PathBuf {
    match (text.strip_prefix("~/"), home_dir()) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => PathBuf::from(text),
    }
}

/// The path with `.` and `..` resolved by text, without the filesystem.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// `FILE.backup`: the default backup of a vault file (`apassy-sandbox`).
fn backup_of(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(".backup");
    PathBuf::from(name)
}

/// Paths that a capture never reads, the deny list of `apassy-sandbox`
/// (`docs/operations/isolation.md`, section 1): the Apassy data folder (with the vault
/// list and the vaults that Apassy made), the open vault file and each vault file of the
/// vault list with its backup and its synced file, the Apassy folder in iCloud Drive,
/// and the Keychain folders. A file covers each path that starts with it: its sidecars
/// (`-wal`, `-shm`, `.lock`), `.backup`, and `.push.nosync`.
///
/// A backup that the owner saved elsewhere is not known. It is an encrypted SQLite file:
/// not UTF-8 text and larger than [`MAX_CAPTURE_BYTES`], so a capture refuses it as
/// output; a file outside the project also waits for the owner.
#[derive(Debug, Clone, Default)]
struct Protected {
    folders: Vec<PathBuf>,
    files: Vec<PathBuf>,
}

impl Protected {
    fn of(vault: &Vault) -> Self {
        let data_dir = crate::paths::data_dir();
        let mut folders = vec![data_dir.clone()];
        if let Some(home) = home_dir() {
            folders.push(home.join("Library").join("Keychains"));
            folders.push(
                home.join("Library")
                    .join("Mobile Documents")
                    .join("com~apple~CloudDocs")
                    .join("Apassy"),
            );
        }
        folders.push(PathBuf::from("/Library/Keychains"));
        let mut files = vec![vault.path().to_path_buf(), backup_of(vault.path())];
        if let Ok(Some(registry)) = crate::vaults::Registry::read(&data_dir) {
            for entry in registry.entries() {
                files.push(entry.path.clone());
                files.push(backup_of(&entry.path));
                files.extend(entry.sync_file());
            }
        }
        let mut protected = Self { folders, files };
        // The canonical form too: `/tmp` is `/private/tmp` on macOS.
        let canonical = |paths: &[PathBuf]| -> Vec<PathBuf> {
            paths
                .iter()
                .filter_map(|path| fs::canonicalize(path).ok())
                .collect()
        };
        let folders = canonical(&protected.folders);
        let files = canonical(&protected.files);
        protected.folders.extend(folders);
        protected.files.extend(files);
        protected
    }

    fn covers_one(&self, path: &Path) -> bool {
        let text = path.to_string_lossy();
        self.folders.iter().any(|folder| path.starts_with(folder))
            || self
                .files
                .iter()
                .any(|file| path == file || text.starts_with(file.to_string_lossy().as_ref()))
    }

    /// The path, by text and as the filesystem resolves it, is a protected path.
    fn covers(&self, path: &Path) -> bool {
        let plain = lexical(path);
        if self.covers_one(&plain) {
            return true;
        }
        // A file that does not exist yet: resolve its folder.
        let resolved = fs::canonicalize(&plain).ok().or_else(|| {
            let parent = fs::canonicalize(plain.parent()?).ok()?;
            Some(parent.join(plain.file_name()?))
        });
        resolved.is_some_and(|path| self.covers_one(&path))
    }
}

/// The canonical working directory. `None` when the request has none.
fn working_dir(cwd: Option<&str>) -> Result<Option<PathBuf>, WireResponse> {
    let Some(cwd) = cwd else {
        return Ok(None);
    };
    if !cwd.starts_with('/') || cwd.contains('\0') || cwd.len() > MAX_PATH_BYTES {
        return Err(invalid("The cwd must be an absolute path."));
    }
    match fs::canonicalize(cwd) {
        Ok(dir) if dir.is_dir() => Ok(Some(dir)),
        _ => Err(invalid("The cwd does not exist or is not a folder.")),
    }
}

/// The UUID of the folder that `text` names: the names from the top level, joined with
/// `/` (as `folder` in the catalog), without regard to case. Empty: the top level.
fn resolve_folder(vault: &Vault, text: Option<&str>) -> Result<Option<String>, WireResponse> {
    let wanted: Vec<String> = text
        .unwrap_or_default()
        .split('/')
        .map(|part| part.trim().to_lowercase())
        .filter(|part| !part.is_empty())
        .collect();
    if wanted.is_empty() {
        return Ok(None);
    }
    let folders = vault.folders().map_err(|_| {
        WireResponse::failure("broker_error", "The broker cannot read the folders.")
    })?;
    folders
        .iter()
        .find(|folder| {
            vault.folder_path(Some(&folder.uuid)).is_ok_and(|path| {
                path.len() == wanted.len()
                    && path
                        .iter()
                        .zip(&wanted)
                        .all(|(name, want)| name.to_lowercase() == *want)
            })
        })
        .map(|folder| Some(folder.uuid.clone()))
        .ok_or_else(|| {
            WireResponse::failure(
                "unknown_folder",
                "No folder has this path. Use a folder from the catalog of apassy_list_access, or leave folder out.",
            )
        })
}

/// Authenticate and read the place of a request. The caller holds no lock after it.
fn begin(
    ctx: &BrokerContext,
    token: &str,
    operation: &str,
    cwd: Option<&str>,
    folder: Option<&str>,
) -> Result<Caller, WireResponse> {
    let mut guard = lock(&ctx.vault);
    let Some(vault) = guard.as_mut().filter(|vault| !vault.is_locked()) else {
        return Err(locked_response());
    };
    let agent = authenticate(vault, token, operation)?;
    let cwd = match working_dir(cwd) {
        Ok(cwd) => cwd,
        Err(response) => return Err(deny(vault, &agent, None, operation, response)),
    };
    let folder = match resolve_folder(vault, folder) {
        Ok(folder) => folder,
        Err(response) => return Err(deny(vault, &agent, None, operation, response)),
    };
    let project = cwd
        .as_deref()
        .and_then(|cwd| project_of(cwd, home_dir().as_deref()));
    Ok(Caller {
        vault_file: vault.path().to_path_buf(),
        epoch: vault.epoch(),
        project,
        folder,
        cwd,
        protected: Protected::of(vault),
        agent,
    })
}

/// The vault of the request again, after a step without the lock: unlocked, the same
/// file, and the agent still connected.
fn resume<'a>(
    guard: &'a mut std::sync::MutexGuard<'_, Option<Vault>>,
    caller: &Caller,
    token: &str,
    operation: &str,
) -> Result<&'a mut Vault, WireResponse> {
    let Some(vault) = guard
        .as_mut()
        .filter(|vault| !vault.is_locked() && vault.path() == caller.vault_file)
    else {
        return Err(locked_response());
    };
    let agent = authenticate(vault, token, operation)?;
    if agent.id != caller.agent.id {
        return Err(WireResponse::failure(
            "authorization_changed",
            "The agent changed while Apassy worked on this request. Send it again.",
        ));
    }
    Ok(vault)
}

/// The agent added or changed the most items in the last hour (ADR 0025 §6).
fn over_limit(vault: &Vault, agent: &AgentSummary) -> bool {
    vault
        .agent_changes_in_last_hour(agent.id)
        .map_or(true, |count| count >= MAX_AGENT_ITEMS_PER_HOUR)
}

/// The name of a new item: one line of at most the longest title.
fn checked_name(name: &str) -> Result<String, WireResponse> {
    let clean: String = name
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let clean = clean.trim();
    if clean.is_empty() || clean.len() > MAX_NAME_BYTES {
        return Err(invalid("The name must have 1 to 128 bytes."));
    }
    Ok(clean.to_owned())
}

/// A variable name from an item name: `Database password` gives `DATABASE_PASSWORD`.
/// `None` when the result is not a valid, free-to-use name.
pub fn env_from_name(name: &str) -> Option<String> {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_uppercase());
        } else if !out.ends_with('_') && !out.is_empty() {
            out.push('_');
        }
    }
    let out = out.trim_end_matches('_').to_owned();
    if out.is_empty() {
        return None;
    }
    let out = if out.starts_with(|c: char| c.is_ascii_digit()) {
        format!("_{out}")
    } else {
        out
    };
    checked_env_name(&out).ok().map(str::to_owned)
}

// ---- Commands ----

/// The rules that no answer of the owner changes: the shape of the arguments, not the
/// Keychain tool `security`, and no path of Apassy in an argument. The text names the
/// rule.
fn check_command(command: &[String], cwd: &Path, protected: &Protected) -> Result<(), String> {
    if command.is_empty() || command.len() > MAX_ARGS {
        return Err(format!("The command must have 1 to {MAX_ARGS} arguments."));
    }
    if command[0].is_empty()
        || command[0].starts_with('-')
        || command
            .iter()
            .any(|arg| arg.len() > MAX_ARG_BYTES || arg.contains('\0'))
    {
        return Err(
            "A command argument is empty, too long, or has a NUL byte, or the program name starts with -."
                .to_owned(),
        );
    }
    let program = Path::new(&command[0])
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    if program == "security" {
        return Err(
            "\"security\" reads the Keychain, so Apassy never captures its output.".to_owned(),
        );
    }
    for arg in command {
        let candidates = [
            Some(arg.as_str()),
            arg.split_once('=').map(|(_, value)| value),
            arg.strip_prefix('@'),
        ];
        for candidate in candidates.into_iter().flatten() {
            // `op://…` and `https://…` name no file; `file://…` does.
            let candidate = candidate.strip_prefix("file://").unwrap_or(candidate);
            if candidate.is_empty() || candidate.starts_with('-') || candidate.contains("://") {
                continue;
            }
            let path = expand_home(candidate);
            let path = if path.is_absolute() {
                path
            } else {
                cwd.join(path)
            };
            if protected.covers(&path) {
                return Err(
                    "The command names a path of Apassy: its data folder, a vault file or its backup, the Apassy folder in iCloud Drive, or the Keychain. Apassy does not capture it."
                        .to_owned(),
                );
            }
        }
    }
    Ok(())
}

/// A regular file that the user may run.
fn executable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// How a capture command runs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Plan {
    /// A known token command: this program from `dirs`, with [`KNOWN_PATH`], at once.
    Known(PathBuf),
    /// Any other command: this program, as the `PATH` of the agent finds it, after the
    /// owner allows it.
    Ask(PathBuf),
}

/// The known token command program: a known name in one of `dirs` (in order), or an
/// absolute path in one of them. The `PATH` and the working directory of the agent play
/// no part.
fn known_program(command: &[String], dirs: &[&str]) -> Option<PathBuf> {
    let (program, args) = command.split_first()?;
    let shape = KNOWN_COMMANDS.iter().find(|known| {
        let name = Path::new(program)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        known.programs.contains(&name) && known.matches(args)
    })?;
    if program.contains('/') {
        let path = Path::new(program);
        let parent = path.parent()?.to_str()?;
        return (dirs.contains(&parent) && path.is_absolute() && executable(path))
            .then(|| path.to_path_buf());
    }
    if !shape.programs.contains(&program.as_str()) {
        return None;
    }
    dirs.iter()
        .map(|dir| Path::new(dir).join(program))
        .find(|path| executable(path))
}

/// The program as the `PATH` of the agent finds it: an absolute path. A name with `/` is
/// a path, from `cwd` when it is relative. Relative `PATH` entries are skipped.
fn path_program(program: &str, agent_path: Option<&str>, cwd: &Path) -> Option<PathBuf> {
    if program.contains('/') {
        let path = lexical(&cwd.join(program));
        return executable(&path).then_some(path);
    }
    agent_path
        .filter(|path| !path.is_empty())
        .unwrap_or(RUN_DEFAULT_PATH)
        .split(':')
        .filter(|dir| dir.starts_with('/'))
        .map(|dir| Path::new(dir).join(program))
        .find(|path| executable(path))
}

fn plan_command(
    command: &[String],
    agent_path: Option<&str>,
    cwd: &Path,
    dirs: &[&str],
) -> Option<Plan> {
    if let Some(program) = known_program(command, dirs) {
        return Some(Plan::Known(program));
    }
    path_program(command.first()?, agent_path, cwd).map(Plan::Ask)
}

/// An argument list for a person: an argument with a space or a quote is quoted.
fn shown_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| {
            if !arg.is_empty()
                && !arg
                    .chars()
                    .any(|c| c.is_whitespace() || "'\"\\$`;&|<>()*?".contains(c))
            {
                arg.clone()
            } else {
                format!("'{}'", arg.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ---- Values ----

/// Bytes as trimmed text. Every copy is erased.
fn into_text(bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, String> {
    match std::str::from_utf8(&bytes) {
        Ok(text) => Ok(Zeroizing::new(text.trim().to_owned())),
        Err(_) => Err("The output is not UTF-8 text.".to_owned()),
    }
}

/// A file path for a capture: absolute (`~/` is the home folder), not a path of Apassy.
/// Returns the canonical path.
fn checked_file(text: &str, protected: &Protected) -> Result<PathBuf, String> {
    if text.contains('\0') || text.len() > MAX_PATH_BYTES {
        return Err("The file path is not valid.".to_owned());
    }
    let path = expand_home(text);
    if !path.is_absolute() {
        return Err("The file must be an absolute path.".to_owned());
    }
    let refusal = "The file is a path of Apassy: its data folder, a vault file or its backup, the Apassy folder in iCloud Drive, or the Keychain. Apassy does not capture it.";
    if protected.covers(&path) {
        return Err(refusal.to_owned());
    }
    let canonical = fs::canonicalize(&path).map_err(|_| "The file does not exist.".to_owned())?;
    if protected.covers(&canonical) {
        return Err(refusal.to_owned());
    }
    Ok(canonical)
}

/// A regular file of at most [`MAX_CAPTURE_BYTES`]. Checked before a question too, so
/// the owner is not asked about a file that cannot be captured.
fn file_metadata(canonical: &Path) -> Result<fs::Metadata, String> {
    let meta = fs::metadata(canonical).map_err(|_| "The file cannot be read.".to_owned())?;
    if !meta.file_type().is_file() {
        return Err(
            "The path is not a regular file: a folder, a FIFO, a device, or a socket is refused."
                .to_owned(),
        );
    }
    if meta.len() > MAX_CAPTURE_BYTES as u64 {
        return Err(format!(
            "The file is larger than {} KiB.",
            MAX_CAPTURE_BYTES / 1024
        ));
    }
    Ok(meta)
}

/// Read one file for a capture (see the module documentation).
fn read_file(text: &str, protected: &Protected) -> Result<Zeroizing<String>, String> {
    let canonical = checked_file(text, protected)?;
    let before = file_metadata(&canonical)?;
    // Non-blocking and without a last symbolic link: a FIFO that took the place of the
    // file does not block, and the identity check below refuses it.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK | O_NOFOLLOW)
        .open(&canonical)
        .map_err(|_| "The file cannot be read.".to_owned())?;
    let after = file
        .metadata()
        .map_err(|_| "The file cannot be read.".to_owned())?;
    if !after.file_type().is_file() || after.dev() != before.dev() || after.ino() != before.ino() {
        return Err("The file changed while Apassy read it.".to_owned());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_CAPTURE_BYTES + 1));
    file.take(MAX_CAPTURE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "The file cannot be read.".to_owned())?;
    if bytes.len() > MAX_CAPTURE_BYTES {
        return Err(format!(
            "The file is larger than {} KiB.",
            MAX_CAPTURE_BYTES / 1024
        ));
    }
    into_text(bytes)
}

/// Run a capture command without the vault lock: `program` with the arguments of
/// `command`, in `cwd`, with `path`.
fn run_capture(
    ctx: &BrokerContext,
    program: &Path,
    command: &[String],
    cwd: &Path,
    path: Option<&str>,
) -> Result<Zeroizing<String>, WireResponse> {
    if !super::operations::start_effect() {
        return Err(super::operations::cancelled_response());
    }
    let mut argv = Vec::with_capacity(command.len());
    argv.push(program.display().to_string());
    argv.extend(command.iter().skip(1).cloned());
    let captured = exec::capture(&argv, cwd, path, ctx.run_timeout).map_err(|_| {
        WireResponse::failure(
            "start_failed",
            "The command did not start. Check the program name and PATH.",
        )
    })?;
    if captured.timed_out {
        return Err(refused(format!(
            "The command did not end in {} seconds. Nothing was saved.",
            ctx.run_timeout.as_secs()
        )));
    }
    if captured.exit_code != Some(0) {
        return Err(refused(format!(
            "The command ended with exit code {}. Nothing was saved.",
            captured
                .exit_code
                .map_or_else(|| "none".to_owned(), |code| code.to_string())
        )));
    }
    if captured.truncated {
        return Err(refused(format!(
            "The output is larger than {} KiB. Nothing was saved.",
            MAX_CAPTURE_BYTES / 1024
        )));
    }
    into_text(Zeroizing::new(captured.stdout.to_vec())).map_err(refused)
}

/// Check `extract` before anything runs. A label ends with `:` or `=` and has no other
/// `:` or `=`, so it names a label of the output and cannot test a part of the value.
fn checked_extract(extract: Option<&Extract>) -> Result<(), WireResponse> {
    match extract {
        None => Ok(()),
        Some(Extract::Json(path)) => {
            if path.is_empty()
                || path.len() > MAX_EXTRACT_BYTES
                || path.split('.').any(str::is_empty)
                || path.chars().any(char::is_control)
            {
                return Err(invalid(
                    "extract.json is a dot path of keys and array indexes, such as \"Credentials.SessionToken\" or \"items.0.key\", of at most 128 bytes.",
                ));
            }
            Ok(())
        }
        Some(Extract::Line(line)) => {
            if *line == 0 || *line > 10_000 {
                return Err(invalid("extract.line is a line number from 1."));
            }
            Ok(())
        }
        Some(Extract::After(label)) => {
            let body = label
                .strip_suffix(':')
                .or_else(|| label.strip_suffix('='))
                .unwrap_or_default();
            let ok = !body.trim().is_empty()
                && label.len() <= MAX_EXTRACT_BYTES
                && body
                    .chars()
                    .all(|c| c.is_alphanumeric() || " _-./".contains(c));
            if ok {
                Ok(())
            } else {
                Err(invalid(
                    "extract.after is a label of the output that ends with \":\" or \"=\", such as \"Token:\", with only letters, digits, spaces, and _ - . / before it.",
                ))
            }
        }
    }
}

/// Erase each string of a parsed JSON output.
fn erase_json(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(erase_json),
        Value::Object(map) => map.values_mut().for_each(erase_json),
        _ => {}
    }
}

/// The part of the output that `extract` names, trimmed (ADR 0025 §6). An error names the
/// rule, never a part of the output.
fn extract_value(text: &str, extract: &Extract) -> Result<Zeroizing<String>, String> {
    let found = match extract {
        Extract::Json(path) => {
            let mut parsed: Value =
                serde_json::from_str(text).map_err(|_| "The output is not JSON.".to_owned())?;
            let mut at = &parsed;
            let mut missing = false;
            for key in path.split('.') {
                let next = match at {
                    Value::Object(map) => map.get(key),
                    Value::Array(items) => key.parse::<usize>().ok().and_then(|i| items.get(i)),
                    _ => None,
                };
                match next {
                    Some(next) => at = next,
                    None => {
                        missing = true;
                        break;
                    }
                }
            }
            let picked = match (missing, at) {
                (false, Value::String(value)) => Ok(Zeroizing::new(value.trim().to_owned())),
                (false, Value::Number(value)) => Ok(Zeroizing::new(value.to_string())),
                (false, _) => Err(format!(
                    "The JSON path \"{path}\" leads to no text or number."
                )),
                (true, _) => Err(format!("The JSON output has no path \"{path}\".")),
            };
            erase_json(&mut parsed);
            picked?
        }
        Extract::Line(number) => {
            let index = usize::try_from(*number)
                .ok()
                .and_then(|n| n.checked_sub(1))
                .ok_or_else(|| "The line number is not valid.".to_owned())?;
            let line = text
                .lines()
                .nth(index)
                .ok_or_else(|| format!("The output has fewer than {number} lines."))?;
            Zeroizing::new(line.trim().to_owned())
        }
        Extract::After(label) => {
            let rest = text
                .lines()
                .find_map(|line| line.split_once(label.as_str()).map(|(_, rest)| rest))
                .ok_or_else(|| format!("No line of the output has the label \"{label}\"."))?;
            Zeroizing::new(rest.trim().to_owned())
        }
    };
    if found.is_empty() {
        return Err("The extracted part of the output is empty. Nothing was saved.".to_owned());
    }
    Ok(found)
}

fn alphabet(name: Option<&str>) -> Result<&'static [u8], WireResponse> {
    match name.unwrap_or("alnum") {
        "alnum" => Ok(ALNUM),
        "hex" => Ok(HEX),
        "base64url" => Ok(BASE64URL),
        "symbols" => Ok(SYMBOLS),
        _ => Err(invalid(
            "The alphabet must be alnum, hex, base64url, or symbols.",
        )),
    }
}

/// The length and the alphabet of a generated value.
fn generation(spec: &GenerateSpec) -> Result<(usize, &'static [u8]), WireResponse> {
    let length = spec.length.unwrap_or(DEFAULT_GENERATED_LENGTH);
    if !(MIN_GENERATED_LENGTH..=MAX_GENERATED_LENGTH).contains(&length) {
        return Err(invalid(&format!(
            "The length must be {MIN_GENERATED_LENGTH} to {MAX_GENERATED_LENGTH}."
        )));
    }
    let length = usize::try_from(length).map_err(|_| invalid("The length is not valid."))?;
    Ok((length, alphabet(spec.alphabet.as_deref())?))
}

/// A random value from the system random source (CSPRNG), with no bias: a byte at or
/// above the largest multiple of the alphabet size is drawn again.
pub fn generate_value(length: usize, alphabet: &[u8]) -> Option<Zeroizing<String>> {
    let size = alphabet.len();
    if size == 0 || size > 256 || length == 0 {
        return None;
    }
    let limit = 256 - (256 % size);
    let mut out = Zeroizing::new(String::with_capacity(length));
    let mut buffer = Zeroizing::new([0u8; 64]);
    while out.len() < length {
        getrandom::fill(&mut buffer[..]).ok()?;
        for &byte in buffer.iter() {
            if usize::from(byte) < limit && out.len() < length {
                out.push(char::from(alphabet[usize::from(byte) % size]));
            }
        }
    }
    Some(out)
}

/// The detection of a generated value: a Custom item with one secret field, a variable
/// from the name, and the most careful declaration (no signal).
fn generated(name: &str, value: &str) -> Detected {
    Detected {
        title: name.to_owned(),
        kind: CredentialKind::Custom,
        provider: None,
        env_name: env_from_name(name),
        env_field: None,
        hosts: Vec::new(),
        fields: vec![Field {
            name: "secret".to_owned(),
            value: SecretValue::new(value.to_owned()),
            secret: true,
        }],
        environment: providers::DEFAULT_ENVIRONMENT,
        risk: providers::DEFAULT_RISK,
        scope: providers::DEFAULT_SCOPE,
        reversibility: providers::DEFAULT_REVERSIBILITY,
        sources: Sources::DEFAULT,
        line: None,
    }
}

/// The detection of a value that an agent captured or saved: exactly one credential.
fn detected(value: &str, name: Option<&str>) -> Result<Detected, WireResponse> {
    if value.is_empty() {
        return Err(refused("The value is empty. Nothing was saved."));
    }
    if value.len() > MAX_CAPTURE_BYTES {
        return Err(refused(format!(
            "The value is larger than {} KiB. Nothing was saved.",
            MAX_CAPTURE_BYTES / 1024
        )));
    }
    let mut found = detect::detect(value);
    if found.len() != 1 {
        return Err(refused(format!(
            "The value holds {} credentials, for example a .env file or a JSON answer. Save one credential at a time; extract picks one from an output.",
            found.len()
        )));
    }
    let mut one = found.remove(0);
    if let Some(name) = name {
        let name = checked_name(name)?;
        if value.len() >= 4 && name.contains(value) {
            return Err(invalid("The name must not contain the value."));
        }
        if one.env_name.is_none() {
            one.env_name = env_from_name(&name);
        }
        one.title = name;
    }
    Ok(one)
}

// ---- Questions ----

/// What a capture question asks the owner about.
enum Ask<'a> {
    /// Run this command, shown with its resolved program.
    Command(&'a [String]),
    /// Read this file.
    File(&'a Path),
}

/// Another question or credential request of the agent waits: the text with the ID of the
/// request when it is one.
fn busy_request(vault: &Vault, ctx: &BrokerContext, agent: &AgentSummary) -> Option<String> {
    let wait = ctx.approval_timeout.as_secs();
    let now = crate::broker::learning::now();
    vault
        .agent_credential_requests(agent.id)
        .ok()?
        .into_iter()
        .rev()
        .find(|known| {
            known.state == CredentialRequestState::Open
                && known.created_at.saturating_add(wait) > now
        })
        .map(|known| {
            format!(
                "Credential request {} (\"{}\") of this agent waits for the owner in Apassy (up to 5 minutes). Wait for it: call apassy_ask_owner_for_credential again with the name \"{}\". Then call again with this request.",
                known.id, known.name, known.name
            )
        })
}

/// Ask the owner before a capture runs a command or reads a file that is not known
/// (ADR 0025 §6). The question waits like a run question: up to the question time, the
/// same request again joins it, and an agent has one waiting question. Only "Allow once"
/// or "Deny"; nothing is remembered. `Ok` when the owner allowed it in the same vault
/// session, and the agent is still connected.
fn ask_first(
    ctx: &BrokerContext,
    token: &str,
    caller: &Caller,
    ask: &Ask<'_>,
    purpose: &str,
    operation: &str,
) -> Result<(), WireResponse> {
    {
        let guard = lock(&ctx.vault);
        if let Some(vault) = guard.as_ref().filter(|vault| !vault.is_locked())
            && let Some(text) = busy_request(vault, ctx, &caller.agent)
        {
            return Err(WireResponse::failure(codes::QUESTION_WAITING, text));
        }
    }
    let place = caller.question_place();
    let (command, question, why) = match ask {
        Ask::Command(argv) => {
            let refs: Vec<String> = argv
                .iter()
                .filter(|arg| !arg.contains("op://"))
                .cloned()
                .collect();
            let hosts = shell_risk::command_hosts(&refs);
            let mut why = "This is not a known token command, so Apassy asks before it runs. It runs outside the sandbox of the agent, without a secret, and can use the network.".to_owned();
            if !hosts.is_empty() {
                why.push_str(&format!(" It names: {}.", hosts.join(", ")));
            }
            (
                argv.to_vec(),
                format!(
                    "{} wants to capture the output of: {} in {place}",
                    caller.agent.name,
                    shown_argv(argv)
                ),
                why,
            )
        }
        Ask::File(path) => (
            vec!["read".to_owned(), path.display().to_string()],
            format!(
                "{} wants to capture the file: {} in {place}",
                caller.agent.name,
                path.display()
            ),
            "The file is outside the project of the agent, so Apassy asks before it reads it."
                .to_owned(),
        ),
    };
    let pending = PendingRun {
        id: 0,
        agent: caller.agent.name.clone(),
        command,
        cwd: caller
            .cwd
            .as_ref()
            .map_or_else(String::new, |cwd| cwd.display().to_string()),
        env_names: Vec::new(),
        purpose: question.clone(),
        risk: why.clone(),
        user_request: String::new(),
        request_source: String::new(),
        agent_request: purpose.to_owned(),
        remember: None,
        question: QuestionInfo {
            id: 0,
            item_ids: Vec::new(),
            project: caller.project.clone(),
            action: ActionKind::Read,
            production: false,
            why,
            items: Vec::new(),
            valid_answers: vec![AnswerKind::Once],
        },
    };
    let same_session = || {
        lock(&ctx.vault)
            .as_ref()
            .is_some_and(|vault| !vault.is_locked() && vault.epoch() == caller.epoch)
    };
    // A capture uses no credential, so there is nothing to check again but the agent:
    // every call of the agent has the same baseline.
    let settled = ctx.approvals.wait_for_question(
        pending,
        caller.agent.id,
        caller.epoch,
        [0; 32],
        ctx.approval_timeout,
        same_session,
    );
    let Settled {
        outcome, attached, ..
    } = match settled {
        Ok(settled) => settled,
        Err(QuestionRefusal::Busy) => {
            return Err(WireResponse::failure(
                codes::QUESTION_WAITING,
                super::run::QUESTION_WAITING,
            ));
        }
        Err(QuestionRefusal::Superseded) => {
            return Err(WireResponse::failure(
                codes::QUESTION_WAITING,
                QUESTION_SUPERSEDED,
            ));
        }
    };
    let mut guard = lock(&ctx.vault);
    let Some(vault) = guard
        .as_mut()
        .filter(|vault| !vault.is_locked() && vault.epoch() == caller.epoch)
    else {
        return Err(WireResponse::failure(
            codes::APPROVAL_INVALIDATED,
            "The vault was locked, or Apassy stopped, before the capture ran. Nothing was saved. Send the request again after the owner unlocks the vault.",
        ));
    };
    if !attached {
        let _ = vault.record_interaction(InteractionKind::Question, &question, &[]);
    }
    match outcome {
        ApprovalOutcome::Approved
        | ApprovalOutcome::ApprovedAndRemembered
        | ApprovalOutcome::ApprovedAndGranted => {
            let agent = authenticate(vault, token, operation)?;
            if agent.id != caller.agent.id {
                return Err(WireResponse::failure(
                    "authorization_changed",
                    "The agent changed while the owner answered. Send the request again.",
                ));
            }
            Ok(())
        }
        ApprovalOutcome::Denied => Err(WireResponse::failure(
            codes::APPROVAL_DENIED,
            "The owner denied this capture. Nothing ran and nothing was saved.",
        )),
        ApprovalOutcome::TimedOut => Err(WireResponse::failure(
            codes::APPROVAL_TIMEOUT,
            format!(
                "The owner did not answer in {} seconds. Nothing ran. Call again to ask again.",
                ctx.approval_timeout.as_secs()
            ),
        )),
        ApprovalOutcome::Invalidated => Err(WireResponse::failure(
            codes::APPROVAL_INVALIDATED,
            "The vault was locked, or Apassy stopped, before the capture ran. Nothing was saved. Send the request again after the owner unlocks the vault.",
        )),
    }
}

// ---- Answers ----

/// The answer for an item. It has no secret value.
fn item_answer(vault: &Vault, item_id: u64, created: bool, note: &str) -> Value {
    let title = vault
        .details(item_id)
        .map(|details| details.summary.title)
        .unwrap_or_default();
    let binding = vault.process_binding(item_id).ok().flatten();
    let environment = vault
        .declaration(item_id)
        .ok()
        .flatten()
        .map(|declaration| declaration.environment.as_str());
    let mut summary = vec![title.clone()];
    summary.extend(binding.as_ref().map(|binding| binding.env_name.clone()));
    summary.extend(environment.map(str::to_owned));
    let (holds, hosts) = match binding.as_ref().map(|binding| &binding.delivery) {
        Some(EnvDelivery::Placeholder(hosts)) => (Some("a placeholder"), hosts.clone()),
        Some(EnvDelivery::Value) => (Some("the real value"), Vec::new()),
        None => (None, Vec::new()),
    };
    json!({
        "item_id": item_id,
        "name": title,
        "env_name": binding.as_ref().map(|binding| binding.env_name.clone()),
        "env_holds": holds,
        "real_value_only_for_hosts": hosts,
        "summary": summary.join(" · "),
        "created": created,
        "note": note,
    })
}

const NOTE_CREATED: &str = "Apassy saved the credential. You never get the value. Use the item_id in apassy_run_with_secrets and the env_name in your command; the bouncer decides each use.";
const NOTE_EXISTS: &str = "A credential that this agent added before has this value. Apassy created nothing and returns that credential.";
const NOTE_SAVED: &str = "Apassy saved the credential. The value is in your transcript already: next time prefer apassy_capture_credential or apassy_generate_credential. Use the item_id in apassy_run_with_secrets and the env_name in your command.";

/// A value with how it was obtained: `approved` when the owner allowed the command or
/// the file first.
struct Obtained {
    value: Zeroizing<String>,
    approved: bool,
}

/// Store a new item for the agent, or return its own item with the same value.
fn store(
    vault: &mut Vault,
    caller: &Caller,
    operation: &str,
    found: &Detected,
    tool: OriginTool,
    approved: bool,
) -> WireResponse {
    if !super::operations::start_effect() {
        return super::operations::cancelled_response();
    }
    let agent = &caller.agent;
    if tool != OriginTool::Generate
        && let Some(secret) = found.secret()
    {
        match vault.own_item_with_value(agent.id, secret.expose()) {
            Ok(Some(item_id)) => {
                return WireResponse::success(item_answer(vault, item_id, false, NOTE_EXISTS));
            }
            Ok(None) => {}
            Err(_) => {
                return WireResponse::failure(
                    "broker_error",
                    "The broker cannot read the credentials of this agent.",
                );
            }
        }
    }
    if over_limit(vault, agent) {
        return deny(vault, agent, None, operation, too_many_items());
    }
    let origin = caller.origin(tool);
    let summary = match vault.add_detected(found, caller.folder.as_deref(), Some(&origin)) {
        Ok(summary) => summary,
        Err(err) => {
            let response = match err.kind() {
                VaultErrorKind::NotFound => WireResponse::failure(
                    "unknown_folder",
                    "The folder is gone. Leave folder out, or use a folder from the catalog.",
                ),
                VaultErrorKind::InvalidInput => invalid(
                    "Apassy cannot store this value as a credential: it is too long, or a field is not valid.",
                ),
                _ => {
                    WireResponse::failure("broker_error", "The broker cannot store the credential.")
                }
            };
            return deny(vault, agent, None, operation, response);
        }
    };
    // ADR 0025 §3f: an agent with "only these items" can use its own new item. No
    // authority of an existing item moves.
    if vault
        .agent_view(agent.id)
        .is_ok_and(|view| view.restricted && !view.visible(summary.id))
    {
        let _ = vault.add_agent_exception(agent.id, summary.id, ExceptionKind::Only);
    }
    let _ = vault.record_activity(&NewActivity {
        agent_id: Some(agent.id),
        agent_name: agent.name.clone(),
        item_id: Some(summary.id),
        operation: operation.to_owned(),
        decision: ActivityDecision::Allow,
        reason: format!(
            "Added by {}{} ({}).{} The value was not returned.",
            agent.name,
            caller.place(),
            tool.as_str(),
            if approved {
                " The owner allowed the capture."
            } else {
                ""
            }
        ),
    });
    let note = if tool == OriginTool::Save {
        NOTE_SAVED
    } else {
        NOTE_CREATED
    };
    WireResponse::success(item_answer(vault, summary.id, true, note))
}

/// The value of a capture or an update, without the vault lock. A command or a file that
/// is not known waits for the owner first ([`ask_first`]).
fn obtain(
    ctx: &BrokerContext,
    token: &str,
    caller: &Caller,
    source: Source<'_>,
    purpose: &str,
    request: (Option<&str>, Option<&Extract>),
    operation: &str,
) -> Result<Obtained, WireResponse> {
    let (path, extract) = request;
    if path.is_some_and(|path| path.len() > MAX_PATH_BYTES || path.contains('\0')) {
        return Err(invalid("The PATH value is not valid."));
    }
    let (value, approved) = match source {
        Source::Command(command) => {
            let Some(cwd) = caller.cwd.as_deref() else {
                return Err(invalid(
                    "A capture command needs the cwd: the absolute folder where it runs.",
                ));
            };
            if caller.protected.covers(cwd) {
                return Err(refused(
                    "The cwd is a folder of Apassy. Apassy does not run a capture there.",
                ));
            }
            check_command(command, cwd, &caller.protected).map_err(refused)?;
            match plan_command(command, path, cwd, KNOWN_DIRS) {
                Some(Plan::Known(program)) => (
                    run_capture(ctx, &program, command, cwd, Some(KNOWN_PATH))?,
                    false,
                ),
                Some(Plan::Ask(program)) => {
                    let mut shown = command.to_vec();
                    shown[0] = program.display().to_string();
                    ask_first(
                        ctx,
                        token,
                        caller,
                        &Ask::Command(&shown),
                        purpose,
                        operation,
                    )?;
                    (run_capture(ctx, &program, command, cwd, path)?, true)
                }
                None => {
                    return Err(WireResponse::failure(
                        "start_failed",
                        "The program was not found. Check the program name and PATH.",
                    ));
                }
            }
        }
        Source::File(file) => {
            let canonical = checked_file(file, &caller.protected).map_err(refused)?;
            file_metadata(&canonical).map_err(refused)?;
            let inside = caller
                .own_tree()
                .is_some_and(|tree| canonical.starts_with(tree));
            if !inside {
                ask_first(
                    ctx,
                    token,
                    caller,
                    &Ask::File(&canonical),
                    purpose,
                    operation,
                )?;
            }
            // The canonical path that the owner saw, checked again.
            let text = canonical.display().to_string();
            (
                read_file(&text, &caller.protected).map_err(refused)?,
                !inside,
            )
        }
        Source::Generate(spec) => {
            if extract.is_some() {
                return Err(invalid("extract is for a command or a file, not generate."));
            }
            let (length, alphabet) = generation(spec)?;
            let value = generate_value(length, alphabet).ok_or_else(|| {
                WireResponse::failure("broker_error", "The system random source failed.")
            })?;
            (value, false)
        }
    };
    let value = match extract {
        Some(extract) => extract_value(&value, extract).map_err(refused)?,
        None => value,
    };
    Ok(Obtained { value, approved })
}

// ---- Tools ----

pub(super) fn capture(
    ctx: &BrokerContext,
    token: &str,
    request: &CaptureRequest<'_>,
) -> WireResponse {
    let operation = "capture credential";
    let source = match Source::one_of(request.command, request.file, None) {
        Ok(source) => source,
        Err(response) => return response,
    };
    let purpose = request.purpose.unwrap_or_default().trim();
    if purpose.len() > MAX_PURPOSE_BYTES {
        return invalid("The purpose must have at most 500 bytes.");
    }
    if let Err(response) = checked_extract(request.extract) {
        return response;
    }
    let caller = match begin(ctx, token, operation, request.cwd, request.folder) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    {
        let mut guard = lock(&ctx.vault);
        let vault = match resume(&mut guard, &caller, token, operation) {
            Ok(vault) => vault,
            Err(response) => return response,
        };
        if over_limit(vault, &caller.agent) {
            return deny(vault, &caller.agent, None, operation, too_many_items());
        }
    }
    let obtained = obtain(
        ctx,
        token,
        &caller,
        source,
        purpose,
        (request.path, request.extract),
        operation,
    );
    let mut guard = lock(&ctx.vault);
    let vault = match resume(&mut guard, &caller, token, operation) {
        Ok(vault) => vault,
        Err(response) => return response,
    };
    let obtained = match obtained {
        Ok(obtained) => obtained,
        Err(response) => return deny(vault, &caller.agent, None, operation, response),
    };
    match detected(&obtained.value, request.name) {
        Ok(found) => store(
            vault,
            &caller,
            operation,
            &found,
            OriginTool::Capture,
            obtained.approved,
        ),
        Err(response) => deny(vault, &caller.agent, None, operation, response),
    }
}

pub(super) fn generate(
    ctx: &BrokerContext,
    token: &str,
    name: &str,
    spec: &GenerateSpec,
    cwd: Option<&str>,
    folder: Option<&str>,
) -> WireResponse {
    let operation = "generate credential";
    let name = match checked_name(name) {
        Ok(name) => name,
        Err(response) => return response,
    };
    if let Err(response) = generation(spec) {
        return response;
    }
    let caller = match begin(ctx, token, operation, cwd, folder) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let obtained = match obtain(
        ctx,
        token,
        &caller,
        Source::Generate(spec),
        "",
        (None, None),
        operation,
    ) {
        Ok(obtained) => obtained,
        Err(response) => return response,
    };
    let mut guard = lock(&ctx.vault);
    let vault = match resume(&mut guard, &caller, token, operation) {
        Ok(vault) => vault,
        Err(response) => return response,
    };
    store(
        vault,
        &caller,
        operation,
        &generated(&name, &obtained.value),
        OriginTool::Generate,
        false,
    )
}

pub(super) fn save(
    ctx: &BrokerContext,
    token: &str,
    name: Option<&str>,
    value: &str,
    cwd: Option<&str>,
    folder: Option<&str>,
) -> WireResponse {
    let operation = "save credential";
    let caller = match begin(ctx, token, operation, cwd, folder) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let mut guard = lock(&ctx.vault);
    let vault = match resume(&mut guard, &caller, token, operation) {
        Ok(vault) => vault,
        Err(response) => return response,
    };
    let mut trimmed = Zeroizing::new(value.trim().to_owned());
    let result = match detected(&trimmed, name) {
        Ok(found) => store(vault, &caller, operation, &found, OriginTool::Save, false),
        Err(response) => deny(vault, &caller.agent, None, operation, response),
    };
    trimmed.zeroize();
    result
}

pub(super) fn ask_owner(
    ctx: &BrokerContext,
    token: &str,
    request: &AskRequest<'_>,
) -> WireResponse {
    let operation = "ask the owner for a credential";
    let caller = match begin(ctx, token, operation, request.cwd, request.folder) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let wanted = NewCredentialRequest {
        agent_id: caller.agent.id,
        agent_name: caller.agent.name.clone(),
        project_key: caller.project_key(),
        project_label: caller.project_label(),
        name: request.name.to_owned(),
        purpose: request.purpose.to_owned(),
        where_to_get: request.where_to_get.unwrap_or_default().to_owned(),
        folder: caller.folder.clone(),
    };
    let Ok(wanted) = wanted.normalized() else {
        return invalid(
            "State the name in 1 to 128 bytes, the purpose in 1 to 500 bytes, and where_to_get in at most 500 bytes.",
        );
    };
    let (request_id, created) = {
        let mut guard = lock(&ctx.vault);
        let vault = match resume(&mut guard, &caller, token, operation) {
            Ok(vault) => vault,
            Err(response) => return response,
        };
        let Ok(mine) = vault.agent_credential_requests(caller.agent.id) else {
            return WireResponse::failure("broker_error", "The broker cannot read the requests.");
        };
        let now = crate::broker::learning::now();
        // ADR 0025 §6: the same request is the agent, the project, and the name. A retry
        // with other words for the purpose waits for the same answer.
        let same = mine.iter().rev().find(|known| known.same_as(&wanted));
        match same.map(|known| (known.state, known.item_id, known.decided_at, known.id)) {
            Some((CredentialRequestState::Open, _, _, id)) => (id, false),
            Some((CredentialRequestState::Saved, Some(item_id), ..))
                if vault.details(item_id).is_ok() =>
            {
                return WireResponse::success(item_answer(vault, item_id, true, NOTE_CREATED));
            }
            Some((CredentialRequestState::Dismissed, _, Some(at), _))
                if at.saturating_add(DISMISSED_REPEAT_SECONDS) > now =>
            {
                return dismissed();
            }
            _ => {
                // ADR 0025 §3: one waiting question per agent. A run or capture
                // question of an agent with the same name counts too.
                let busy = busy_request(vault, ctx, &caller.agent).or_else(|| {
                    ctx.approvals
                        .pending()
                        .iter()
                        .any(|pending| pending.agent == caller.agent.name)
                        .then(|| super::run::QUESTION_WAITING.to_owned())
                });
                if let Some(text) = busy {
                    return deny(
                        vault,
                        &caller.agent,
                        None,
                        operation,
                        WireResponse::failure(codes::QUESTION_WAITING, text),
                    );
                }
                let load = vault
                    .agent_requests_in_last_hour(caller.agent.id)
                    .unwrap_or(MAX_AGENT_REQUESTS_PER_HOUR);
                if load >= MAX_AGENT_REQUESTS_PER_HOUR {
                    return deny(
                        vault,
                        &caller.agent,
                        None,
                        operation,
                        WireResponse::failure(
                            codes::TOO_MANY_REQUESTS,
                            format!(
                                "This agent has {MAX_AGENT_REQUESTS_PER_HOUR} credential requests that are open or new in the last hour. Wait for the owner, or tell the user."
                            ),
                        ),
                    );
                }
                match vault.open_credential_request(&wanted) {
                    Ok(id) => {
                        let _ = vault.record_activity(&NewActivity {
                            agent_id: Some(caller.agent.id),
                            agent_name: caller.agent.name.clone(),
                            item_id: None,
                            operation: operation.to_owned(),
                            decision: ActivityDecision::Allow,
                            reason: format!(
                                "{} asked the owner for \"{}\"{}. It waits for the owner.",
                                caller.agent.name,
                                wanted.name,
                                caller.place()
                            ),
                        });
                        (id, true)
                    }
                    Err(err) => {
                        let response = if err.kind() == VaultErrorKind::NotFound {
                            WireResponse::failure("unknown_folder", "The folder is gone.")
                        } else {
                            WireResponse::failure(
                                "broker_error",
                                "The broker cannot store the request.",
                            )
                        };
                        return deny(vault, &caller.agent, None, operation, response);
                    }
                }
            }
        }
    };
    if created {
        ctx.approvals.notify_owner();
    }
    let _waiting = super::operations::waiting();
    let deadline = Instant::now() + ctx.approval_timeout;
    loop {
        if super::operations::cancelled() {
            let mut guard = lock(&ctx.vault);
            if let Some(vault) = guard
                .as_mut()
                .filter(|v| !v.is_locked() && v.epoch() == caller.epoch)
            {
                if let Ok(known) = vault.credential_request(request_id)
                    && known.state == CredentialRequestState::Saved
                    && let Some(item_id) = known.item_id
                {
                    super::operations::observed_effect();
                    return WireResponse::success(item_answer(vault, item_id, true, NOTE_CREATED));
                }
                let _ = vault.settle_credential_request(
                    request_id,
                    crate::vault::agent_items::RequestOutcome::Dismissed,
                );
            }
            ctx.approvals.notify_owner();
            return super::operations::cancelled_response();
        }
        {
            let guard = lock(&ctx.vault);
            let Some(vault) = guard
                .as_ref()
                .filter(|vault| !vault.is_locked() && vault.path() == caller.vault_file)
            else {
                return waiting(request_id);
            };
            match vault.credential_request(request_id) {
                Ok(known) => match (known.state, known.item_id) {
                    (CredentialRequestState::Saved, Some(item_id))
                        if vault.details(item_id).is_ok() =>
                    {
                        super::operations::observed_effect();
                        return WireResponse::success(item_answer(
                            vault,
                            item_id,
                            true,
                            NOTE_CREATED,
                        ));
                    }
                    (CredentialRequestState::Open, _) => {}
                    _ => return dismissed(),
                },
                Err(_) => return dismissed(),
            }
        }
        let now = Instant::now();
        if now >= deadline {
            return waiting(request_id);
        }
        std::thread::sleep(POLL.min(deadline - now));
    }
}

pub(super) fn update(
    ctx: &BrokerContext,
    token: &str,
    request: &UpdateRequest<'_>,
) -> WireResponse {
    let operation = UPDATE_OPERATION;
    let source = match Source::one_of(request.command, request.file, request.generate) {
        Ok(source) => source,
        Err(response) => return response,
    };
    if let Source::Generate(spec) = source
        && let Err(response) = generation(spec)
    {
        return response;
    }
    if let Err(response) = checked_extract(request.extract) {
        return response;
    }
    let caller = match begin(ctx, token, operation, request.cwd, None) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let item_id = request.item_id;
    {
        let mut guard = lock(&ctx.vault);
        let vault = match resume(&mut guard, &caller, token, operation) {
            Ok(vault) => vault,
            Err(response) => return response,
        };
        if let Err(response) = own_and_usable(vault, &caller.agent, item_id) {
            return deny(vault, &caller.agent, Some(item_id), operation, response);
        }
        // ADR 0025 §6: a new value counts toward the hourly limit.
        if over_limit(vault, &caller.agent) {
            return deny(
                vault,
                &caller.agent,
                Some(item_id),
                operation,
                too_many_items(),
            );
        }
    }
    let obtained = obtain(
        ctx,
        token,
        &caller,
        source,
        "",
        (request.path, request.extract),
        operation,
    );
    let mut guard = lock(&ctx.vault);
    let vault = match resume(&mut guard, &caller, token, operation) {
        Ok(vault) => vault,
        Err(response) => return response,
    };
    let obtained = match obtained {
        Ok(obtained) => obtained,
        Err(response) => return deny(vault, &caller.agent, Some(item_id), operation, response),
    };
    if obtained.value.is_empty() {
        return deny(
            vault,
            &caller.agent,
            Some(item_id),
            operation,
            refused("The value is empty. Nothing was changed."),
        );
    }
    if let Err(response) = own_and_usable(vault, &caller.agent, item_id) {
        return deny(vault, &caller.agent, Some(item_id), operation, response);
    }
    if over_limit(vault, &caller.agent) {
        return deny(
            vault,
            &caller.agent,
            Some(item_id),
            operation,
            too_many_items(),
        );
    }
    // The previous value stays for a restore by the owner, and the declaration becomes
    // the stricter of the old one and the detected one (ADR 0025 §5), in one transaction.
    if !super::operations::start_effect() {
        return super::operations::cancelled_response();
    }
    if let Err(err) = vault.replace_own_item_value(caller.agent.id, item_id, &obtained.value) {
        let response = match err.kind() {
            VaultErrorKind::NotFound => not_owner(),
            VaultErrorKind::InvalidInput => invalid(
                "Apassy cannot use this value for the credential: it is too long, or too short for its placeholder.",
            ),
            _ => WireResponse::failure("broker_error", "The broker cannot store the value."),
        };
        return deny(vault, &caller.agent, Some(item_id), operation, response);
    }
    let _ = vault.record_activity(&NewActivity {
        agent_id: Some(caller.agent.id),
        agent_name: caller.agent.name.clone(),
        item_id: Some(item_id),
        operation: operation.to_owned(),
        decision: ActivityDecision::Allow,
        reason: format!(
            "{} gave its credential a new value.{} Apassy keeps the previous value for the owner to restore. The value was not returned.",
            caller.agent.name,
            if obtained.approved {
                " The owner allowed the capture."
            } else {
                ""
            }
        ),
    });
    let mut answer = item_answer(
        vault,
        item_id,
        false,
        "Apassy stored the new value. You never get the value. The owner can restore the previous value.",
    );
    answer["updated"] = json!(true);
    WireResponse::success(answer)
}

/// The item is an own item of the agent, not archived, and not waiting for the review
/// of a restore. Each other case is `not_owner`, so the answer does not tell which items
/// exist.
fn own_and_usable(vault: &Vault, agent: &AgentSummary, item_id: u64) -> Result<(), WireResponse> {
    if !vault.agent_owns_item(agent.id, item_id).unwrap_or(false) {
        return Err(not_owner());
    }
    if vault.is_archived(item_id).unwrap_or(true) {
        return Err(WireResponse::failure(
            "item_archived",
            super::run::archived_reason(item_id),
        ));
    }
    if vault.needs_review(item_id).unwrap_or(true) {
        return Err(WireResponse::failure(
            "review_required",
            super::run::review_reason(item_id),
        ));
    }
    Ok(())
}

pub(super) fn describe(
    ctx: &BrokerContext,
    token: &str,
    item_id: u64,
    change: &ItemDescription,
) -> WireResponse {
    let operation = "describe credential";
    if change == &ItemDescription::default() {
        return invalid("Give at least one of name, notes, env_name, and placeholder_hosts.");
    }
    let mut guard = lock(&ctx.vault);
    let Some(vault) = guard.as_mut().filter(|vault| !vault.is_locked()) else {
        return locked_response();
    };
    let agent = match authenticate(vault, token, operation) {
        Ok(agent) => agent,
        Err(response) => return response,
    };
    if let Err(response) = own_and_usable(vault, &agent, item_id) {
        return deny(vault, &agent, Some(item_id), operation, response);
    }
    if change.placeholder_hosts.is_some()
        && vault
            .details(item_id)
            .is_ok_and(|details| !placeholder_kind(details.summary.kind))
    {
        return deny(
            vault,
            &agent,
            Some(item_id),
            operation,
            invalid(
                "placeholder_hosts is only for an API key or a login: a placeholder goes in an HTTPS header or key parameter. A custom value, a database password, or an SSH key gets the real value.",
            ),
        );
    }
    match vault.describe_own_item(agent.id, item_id, change) {
        Ok(_) => {
            let mut changed = Vec::new();
            for (set, word) in [
                (change.title.is_some(), "name"),
                (change.notes.is_some(), "notes"),
                (change.env_name.is_some(), "variable"),
                (change.placeholder_hosts.is_some(), "placeholder hosts"),
            ] {
                if set {
                    changed.push(word);
                }
            }
            let _ = vault.record_activity(&NewActivity {
                agent_id: Some(agent.id),
                agent_name: agent.name.clone(),
                item_id: Some(item_id),
                operation: operation.to_owned(),
                decision: ActivityDecision::Allow,
                reason: format!(
                    "{} changed the {} of its credential.",
                    agent.name,
                    changed.join(", ")
                ),
            });
            WireResponse::success(item_answer(
                vault,
                item_id,
                false,
                "Apassy changed the credential.",
            ))
        }
        Err(err) => {
            let response = match err.kind() {
                VaultErrorKind::NotFound => not_owner(),
                VaultErrorKind::AlreadyExists => WireResponse::failure(
                    "env_name_taken",
                    "Another credential uses this env_name, or it is the variable of the provider of another credential. Choose another name.",
                ),
                VaultErrorKind::InvalidInput => invalid(
                    "Use a name of 1 to 128 bytes, notes of at most 8192 bytes, an env_name like MY_API_KEY that is not reserved (PATH, HOME, DYLD_*, APASSY_*, ...), and placeholder_hosts that only narrow where the value goes: hosts for a placeholder instead of the real value, or some of the placeholder hosts that the credential has.",
                ),
                _ => WireResponse::failure(
                    "broker_error",
                    "The broker cannot change the credential.",
                ),
            };
            deny(vault, &agent, Some(item_id), operation, response)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| (*p).to_owned()).collect()
    }

    #[test]
    fn generated_values_have_the_length_and_the_alphabet() {
        for (alphabet, length) in [(ALNUM, 16), (HEX, 32), (BASE64URL, 64), (SYMBOLS, 128)] {
            let value = generate_value(length, alphabet).expect("value");
            assert_eq!(value.len(), length);
            assert!(value.bytes().all(|b| alphabet.contains(&b)));
        }
        let a = generate_value(32, ALNUM).expect("value");
        let b = generate_value(32, ALNUM).expect("value");
        assert_ne!(*a, *b);
        assert!(generate_value(0, ALNUM).is_none());
    }

    #[test]
    fn variable_names_come_from_item_names() {
        assert_eq!(
            env_from_name("Database password").as_deref(),
            Some("DATABASE_PASSWORD")
        );
        assert_eq!(
            env_from_name("  stripe--test key ").as_deref(),
            Some("STRIPE_TEST_KEY")
        );
        assert_eq!(env_from_name("2fa seed").as_deref(), Some("_2FA_SEED"));
        assert_eq!(env_from_name("path"), None, "reserved");
        assert_eq!(env_from_name("---"), None);
    }

    /// The rules that no answer changes: `security` and the paths of Apassy. Any other
    /// command passes here and then is a known command or a question.
    #[test]
    fn capture_commands_never_name_apassy_paths_or_the_keychain() {
        let protected = Protected {
            folders: vec![PathBuf::from("/synthetic/apassy-data")],
            files: vec![PathBuf::from("/synthetic/vaults/main.db")],
        };
        let cwd = Path::new("/tmp");
        for good in [
            argv(&["gh", "auth", "token"]),
            argv(&["op", "read", "op://Private/Stripe/key"]),
            argv(&["sh", "-c", "echo x"]),
        ] {
            assert!(check_command(&good, cwd, &protected).is_ok(), "{good:?}");
        }
        for bad in [
            argv(&["security", "find-generic-password", "-w"]),
            argv(&["/usr/bin/security", "dump-keychain"]),
            argv(&["cat", "/synthetic/apassy-data/vault.db"]),
            argv(&["cat", "/synthetic/vaults/main.db-wal"]),
            argv(&["cat", "/synthetic/vaults/main.db.backup"]),
            argv(&["cp", "--from=/synthetic/apassy-data/x", "y"]),
            argv(&["curl", "file:///synthetic/vaults/main.db"]),
            argv(&["-gh"]),
        ] {
            assert!(check_command(&bad, cwd, &protected).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn known_commands_match_their_exact_shape() {
        let find = |command: &[&str]| {
            let command = argv(command);
            KNOWN_COMMANDS.iter().any(|known| {
                known.programs.contains(&command[0].as_str()) && known.matches(&command[1..])
            })
        };
        for good in [
            &["gh", "auth", "token"][..],
            &["gh", "auth", "token", "--hostname", "github.example.com"],
            &["gh", "auth", "token", "--hostname=github.example.com"],
            &["op", "read", "op://Private/Stripe/credential"],
            &[
                "op",
                "read",
                "--no-newline",
                "op://Private/Stripe/credential",
            ],
            &[
                "aws",
                "configure",
                "get",
                "aws_secret_access_key",
                "--profile",
                "dev",
            ],
            &[
                "aws",
                "sts",
                "get-session-token",
                "--duration-seconds",
                "900",
            ],
            &["aws", "ecr", "get-login-password", "--region", "eu-west-1"],
            &["gcloud", "auth", "print-access-token"],
            &["gcloud", "auth", "print-identity-token", "--audiences", "x"],
            &[
                "gcloud",
                "auth",
                "application-default",
                "print-access-token",
            ],
            &[
                "az",
                "account",
                "get-access-token",
                "--query",
                "accessToken",
                "-o",
                "tsv",
            ],
            &["fly", "auth", "token"],
            &["flyctl", "auth", "token"],
            &["heroku", "auth:token"],
            &["doppler", "secrets", "get", "API_KEY", "--plain"],
            &["vault", "kv", "get", "-field=password", "secret/app"],
            &["vault", "print", "token"],
        ] {
            assert!(find(good), "{good:?}");
        }
        for bad in [
            &["gh", "auth", "status"][..],
            &["gh", "auth", "token", "--show-token"],
            &["gh", "auth", "token", "extra"],
            &["gh", "auth", "token", "--hostname"],
            &["gh", "api", "user"],
            &["op", "read", "op://"],
            &["op", "read", "/etc/passwd"],
            &["op", "run", "--", "env"],
            &["aws", "configure", "get"],
            &["aws", "s3", "ls"],
            &["doppler", "secrets", "get", "API_KEY"],
            &["doppler", "secrets", "download", "--plain"],
            &["vault", "kv", "get", "secret/app"],
            &["heroku", "auth:token", "--app", "x"],
            &["cat", "token.txt"],
        ] {
            assert!(!find(bad), "{bad:?}");
        }
        assert!(KNOWN_COMMANDS.iter().any(|known| known.describe()
            == "gh auth token [--hostname VALUE] [-h VALUE] [--user VALUE] [-u VALUE]"),);
    }

    fn script(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, "#!/bin/sh\necho FAKE-not-run\n").expect("script");
        let mut permissions = fs::metadata(&path).expect("meta").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("mode");
        path
    }

    /// The program of a known command comes only from the fixed folders: neither the
    /// `PATH` of the agent nor the working directory changes it.
    #[test]
    fn the_path_of_the_agent_cannot_change_a_known_program() {
        let root = tempfile::TempDir::new().expect("temp");
        let root = fs::canonicalize(root.path()).expect("canonical");
        let fixed = root.join("fixed");
        let evil = root.join("evil");
        let cwd = root.join("project");
        for dir in [&fixed, &evil, &cwd] {
            fs::create_dir_all(dir).expect("dir");
        }
        let real = script(&fixed, "gh");
        let fake = script(&evil, "gh");
        script(&cwd, "gh");
        let dirs = [fixed.to_str().expect("utf8")];
        let agent_path = format!("{}:/usr/bin:/bin", evil.display());
        let plan = |command: &[&str]| plan_command(&argv(command), Some(&agent_path), &cwd, &dirs);
        assert_eq!(
            plan(&["gh", "auth", "token"]),
            Some(Plan::Known(real.clone()))
        );
        // A relative PATH entry, as `.`, is never searched.
        assert_eq!(
            plan_command(
                &argv(&["gh", "auth", "token"]),
                Some(".:/usr/bin"),
                &cwd,
                &dirs
            ),
            Some(Plan::Known(real.clone()))
        );
        assert_eq!(
            plan(&[real.to_str().expect("utf8"), "auth", "token"]),
            Some(Plan::Known(real.clone()))
        );
        // The same program from another folder, or another shape: the owner decides, and
        // the question shows the program that would run.
        assert_eq!(
            plan(&[fake.to_str().expect("utf8"), "auth", "token"]),
            Some(Plan::Ask(fake.clone()))
        );
        assert_eq!(
            plan(&["./gh", "auth", "token"]),
            Some(Plan::Ask(cwd.join("gh")))
        );
        assert_eq!(plan(&["gh", "api", "user"]), Some(Plan::Ask(fake.clone())));
        // Not in the fixed folders: a question, never a known command.
        let empty = root.join("empty");
        fs::create_dir_all(&empty).expect("dir");
        let none = [empty.to_str().expect("utf8")];
        assert_eq!(
            plan_command(
                &argv(&["gh", "auth", "token"]),
                Some(&agent_path),
                &cwd,
                &none
            ),
            Some(Plan::Ask(fake))
        );
        assert_eq!(
            plan_command(
                &argv(&["no-such-program-x"]),
                Some(&agent_path),
                &cwd,
                &dirs
            ),
            None
        );
    }

    #[test]
    fn extract_picks_a_part_and_never_echoes_the_output() {
        let json = r#"{"Credentials":{"SessionToken":"FAKE-json-canary-1","Expiration":3},"items":[{"key":"FAKE-json-canary-2"}]}"#;
        let pick = |extract: Extract, text: &str| extract_value(text, &extract);
        assert_eq!(
            *pick(Extract::Json("Credentials.SessionToken".into()), json).unwrap(),
            "FAKE-json-canary-1"
        );
        assert_eq!(
            *pick(Extract::Json("items.0.key".into()), json).unwrap(),
            "FAKE-json-canary-2"
        );
        assert_eq!(
            *pick(Extract::Json("Credentials.Expiration".into()), json).unwrap(),
            "3"
        );
        for path in ["Credentials", "Credentials.Missing", "items.5.key"] {
            let error = pick(Extract::Json(path.into()), json).unwrap_err();
            assert!(!error.contains("FAKE"), "{error}");
        }
        assert!(
            !pick(Extract::Json("a".into()), "FAKE-not-json")
                .unwrap_err()
                .contains("FAKE")
        );
        let text = "Logged in as someone\nToken: FAKE-after-canary-3\nDone";
        assert_eq!(
            *pick(Extract::Line(2), text).unwrap(),
            "Token: FAKE-after-canary-3"
        );
        assert_eq!(
            *pick(Extract::After("Token:".into()), text).unwrap(),
            "FAKE-after-canary-3"
        );
        assert!(!pick(Extract::Line(9), text).unwrap_err().contains("FAKE"));
        assert!(
            !pick(Extract::After("Secret:".into()), text)
                .unwrap_err()
                .contains("FAKE")
        );
        assert!(
            pick(Extract::After("Done:".into()), "Done:  ").is_err(),
            "empty"
        );
        // A label cannot test a part of the value.
        for label in ["Token: FAKE", "FAKE-after", "Token:F:", ":", "Token"] {
            assert!(
                checked_extract(Some(&Extract::After(label.into()))).is_err(),
                "{label}"
            );
        }
        assert!(checked_extract(Some(&Extract::After("Access token:".into()))).is_ok());
        assert!(checked_extract(Some(&Extract::Json("a..b".into()))).is_err());
        assert!(checked_extract(Some(&Extract::Line(0))).is_err());
    }

    #[test]
    fn a_question_shows_the_argv_with_quotes() {
        assert_eq!(
            shown_argv(&argv(&["/usr/bin/printf", "a b", "it's", "plain"])),
            "/usr/bin/printf 'a b' 'it'\\''s' plain"
        );
    }
}
