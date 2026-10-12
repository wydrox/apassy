//! Agent tools that add credentials (ADR 0025 §6): capture, generate, save, ask the
//! owner, update, and describe.
//!
//! Rules for every tool:
//!
//! - **The value never leaves.** No answer, activity entry, decision log entry, item
//!   history event, error text, or Debug output has the value or a part of it. The agent
//!   gets the item: its ID, its name, its variable, and a one-line summary.
//! - **Create only.** An agent creates items. It changes only its *own* items: the items
//!   whose value it made with capture, generate, or save (`item_origin`). Any other item,
//!   also an item that does not exist, gives `not_owner`. A change of another item is not
//!   a proposal to the owner in this version.
//! - **No oracle.** A value that an own item of the agent has returns that item and
//!   creates nothing. The check reads only the agent's own items, so the answer tells
//!   nothing about the other items of the vault.
//! - **Limit.** An agent creates at most [`MAX_AGENT_ITEMS_PER_HOUR`] items in one hour
//!   (`too_many_items`). The limit is checked before a capture runs.
//! - **A normal item.** The new item has the detection of ADR 0025 §4 (provider,
//!   variable, hosts, declaration with sources; a value without a signal gets the most
//!   careful default) and the bouncer decides each use of it as for any item. The history
//!   says "Added by AGENT in PROJECT (TOOL)." An agent with "only these items" gets its
//!   new item on its list: no authority of an existing item moves.
//!
//! Capture (`apassy_capture_credential`):
//!
//! - A command runs through the same process path as a run ([`exec`]), in the working
//!   directory of the agent, with the base environment and `PATH` and **no secret**. So it
//!   needs no credential decision. In place of the bouncer, these rules apply, and a
//!   command that fails one is refused (`capture_refused`):
//!   - one program: no shell, script interpreter, or wrapper ([`NOT_ONE_PROGRAM`]), and
//!     not the Keychain tool `security`;
//!   - no host or URL in the command (`shell_risk::command_hosts`): a capture sends
//!     nothing to a host that the agent names;
//!   - no rule flag of the command analysis except `secret_output` (printing a token is
//!     the point of a capture), and no kind of action "deploy" or "delete";
//!   - no argument that names a path of Apassy: the data folder, a vault file of this
//!     Mac, or a Keychain folder.
//!
//!   The output is the standard output, trimmed. It must be UTF-8, at most
//!   [`MAX_CAPTURE_BYTES`], not empty, and the command must end with exit code 0 within
//!   the run time limit. The standard error is erased; it never leaves.
//! - A file: an absolute path (`~/` is the home folder) of a regular file of at most
//!   [`MAX_CAPTURE_BYTES`]. A folder, a FIFO, a device, or a socket is refused, and so is
//!   a path of Apassy (as above). Any other file that the agent names is allowed, also a
//!   key in `~/.ssh`: the agent could read it itself, and capture keeps it out of the
//!   transcript.
//!
//! Ask the owner (`apassy_ask_owner_for_credential`) stores a credential request and
//! waits like a question (ADR 0025 §3e): up to the question time, then `waiting`; the
//! request stays open, and the same request again waits again. A different request while
//! a question or a request of the agent waits gives `question_waiting`. The owner saves
//! (the agent gets the item) or dismisses (`dismissed`).
//!
//! Describe (`apassy_describe_credential`) changes the name, the notes, the variable, and
//! the hosts of an own item. Hosts only narrow where the value goes: a placeholder for
//! the given hosts instead of the real value, or a subset of the placeholder hosts.

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

use super::action_kind::{ActionKind, classify};
use super::decide::{BrokerContext, authenticate, lock, locked_response};
use super::exec;
use super::project::project_of;
use super::shell_risk;
use crate::agent::wire::{GenerateSpec, WireResponse, codes};
use crate::contracts::CredentialKind;
use crate::vault::agent_items::{
    CredentialRequestState, ItemDescription, MAX_AGENT_ITEMS_PER_HOUR, MAX_OPEN_REQUESTS_PER_AGENT,
    NewCredentialRequest,
};
use crate::vault::detect::{self, Detected, Sources};
use crate::vault::exceptions::ExceptionKind;
use crate::vault::{
    ActivityDecision, AgentSummary, EnvDelivery, Field, ItemOrigin, NewActivity, OriginTool,
    SecretValue, Vault, VaultErrorKind, checked_env_name, providers,
};

/// The largest value that capture, a file, or save takes, in bytes.
pub const MAX_CAPTURE_BYTES: usize = 64 * 1024;
pub const DEFAULT_GENERATED_LENGTH: u32 = 32;
pub const MIN_GENERATED_LENGTH: u32 = 16;
pub const MAX_GENERATED_LENGTH: u32 = 128;
/// Programs that run other code or other programs. A capture runs one program.
pub const NOT_ONE_PROGRAM: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "csh",
    "tcsh",
    "env",
    "sudo",
    "doas",
    "su",
    "xargs",
    "nohup",
    "time",
    "exec",
    "eval",
    "command",
    "nice",
    "timeout",
    "osascript",
    "python",
    "python2",
    "python3",
    "node",
    "deno",
    "bun",
    "ruby",
    "perl",
    "php",
    "lua",
    "pwsh",
    "powershell",
    "Rscript",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "tclsh",
    "expect",
    "security",
];
/// The longest item name: the longest title of the vault.
const MAX_NAME_BYTES: usize = 128;
const MAX_ARGS: usize = 64;
const MAX_ARG_BYTES: usize = 4096;
const MAX_PATH_BYTES: usize = 4096;
const MAX_PURPOSE_BYTES: usize = 500;
/// How often a waiting credential request reads its state.
const POLL: Duration = Duration::from_millis(100);
/// A dismissed request, asked again within this time, is still dismissed.
const DISMISSED_REPEAT_SECONDS: u64 = 3600;

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
}

/// The agent, the vault session, and the place of a request.
struct Caller {
    agent: AgentSummary,
    vault_file: PathBuf,
    project_key: String,
    project_label: String,
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
            project_key: self.project_key.clone(),
            project_label: self.project_label.clone(),
            tool,
        }
    }

    fn place(&self) -> String {
        if self.project_label.is_empty() {
            String::new()
        } else {
            format!(" in {}", self.project_label)
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
            "This agent added {MAX_AGENT_ITEMS_PER_HOUR} credentials in the last hour. Wait, or ask the owner to add the credential in Apassy."
        ),
    )
}

fn waiting() -> WireResponse {
    WireResponse::failure(
        codes::WAITING,
        "The owner has not saved the credential yet. The request stays open in Apassy. Call again with the same arguments to wait again.",
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

/// Paths that a capture never reads: the Apassy data folder (with the vault list and the
/// vaults that Apassy made), the open vault file, and the Keychain folders. A vault file
/// covers its sidecars (`-wal`, `-shm`, `.lock`). A synced copy elsewhere is encrypted,
/// so it is not listed.
#[derive(Debug, Clone, Default)]
struct Protected {
    folders: Vec<PathBuf>,
    files: Vec<PathBuf>,
}

impl Protected {
    fn of(vault: &Vault) -> Self {
        let mut folders = vec![crate::paths::data_dir()];
        if let Some(home) = home_dir() {
            folders.push(home.join("Library").join("Keychains"));
        }
        folders.push(PathBuf::from("/Library/Keychains"));
        let files = vec![vault.path().to_path_buf()];
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
        project_key: project
            .as_ref()
            .map_or_else(String::new, |project| project.key.clone()),
        project_label: project
            .as_ref()
            .map_or_else(String::new, |project| project.label.clone()),
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

fn over_limit(vault: &Vault, agent: &AgentSummary) -> bool {
    vault
        .agent_items_in_last_hour(agent.id)
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

// ---- Values ----

/// Check a capture command (see the module documentation). The text names the rule.
fn check_command(
    command: &[String],
    cwd: &Path,
    purpose: &str,
    protected: &Protected,
) -> Result<(), String> {
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
    if NOT_ONE_PROGRAM
        .iter()
        .any(|name| program == *name || program.starts_with(&format!("{name}3.")))
    {
        return Err(format!(
            "A capture runs one program that prints the credential, such as [\"gh\", \"auth\", \"token\"]. \"{program}\" runs other code or reads the Keychain, so Apassy does not capture its output."
        ));
    }
    let hosts = shell_risk::command_hosts(command);
    if !hosts.is_empty() {
        return Err(format!(
            "The command names a host or a URL ({}). A capture command must not name where it connects; use the provider's own command.",
            hosts.join(", ")
        ));
    }
    let analysis = shell_risk::analyze(command, purpose, &[]);
    let flags: Vec<&String> = analysis
        .flags
        .iter()
        .filter(|flag| flag.as_str() != "secret_output")
        .collect();
    if !flags.is_empty() {
        return Err(format!(
            "The command analysis flags it: {}.",
            flags
                .iter()
                .map(|flag| flag.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if matches!(
        classify(command, &analysis),
        ActionKind::Deploy | ActionKind::Delete
    ) {
        return Err(
            "The command deploys or deletes. A capture command only prints a credential."
                .to_owned(),
        );
    }
    for arg in &command[1..] {
        let candidates = [
            Some(arg.as_str()),
            arg.split_once('=').map(|(_, value)| value),
            arg.strip_prefix('@'),
        ];
        for candidate in candidates.into_iter().flatten() {
            if candidate.is_empty() || candidate.starts_with('-') {
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
                    "The command names a path of Apassy: its data folder, a vault file, or the Keychain. Apassy does not capture it."
                        .to_owned(),
                );
            }
        }
    }
    Ok(())
}

/// Bytes as trimmed text. Every copy is erased.
fn into_text(bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, String> {
    match std::str::from_utf8(&bytes) {
        Ok(text) => Ok(Zeroizing::new(text.trim().to_owned())),
        Err(_) => Err("The output is not UTF-8 text.".to_owned()),
    }
}

/// Read one file for a capture (see the module documentation).
fn read_file(text: &str, protected: &Protected) -> Result<Zeroizing<String>, String> {
    if text.contains('\0') || text.len() > MAX_PATH_BYTES {
        return Err("The file path is not valid.".to_owned());
    }
    let path = expand_home(text);
    if !path.is_absolute() {
        return Err("The file must be an absolute path.".to_owned());
    }
    if protected.covers(&path) {
        return Err(
            "The file is a path of Apassy: its data folder, a vault file, or the Keychain. Apassy does not capture it."
                .to_owned(),
        );
    }
    let canonical = fs::canonicalize(&path).map_err(|_| "The file does not exist.".to_owned())?;
    if protected.covers(&canonical) {
        return Err(
            "The file is a path of Apassy: its data folder, a vault file, or the Keychain. Apassy does not capture it."
                .to_owned(),
        );
    }
    let before = fs::metadata(&canonical).map_err(|_| "The file cannot be read.".to_owned())?;
    if !before.file_type().is_file() {
        return Err(
            "The path is not a regular file: a folder, a FIFO, a device, or a socket is refused."
                .to_owned(),
        );
    }
    if before.len() > MAX_CAPTURE_BYTES as u64 {
        return Err(format!(
            "The file is larger than {} KiB.",
            MAX_CAPTURE_BYTES / 1024
        ));
    }
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

/// Run a capture command without the vault lock.
fn run_capture(
    ctx: &BrokerContext,
    command: &[String],
    cwd: &Path,
    path: Option<&str>,
) -> Result<Zeroizing<String>, WireResponse> {
    if path.is_some_and(|path| path.len() > MAX_PATH_BYTES || path.contains('\0')) {
        return Err(invalid("The PATH value is not valid."));
    }
    let captured = exec::capture(command, cwd, path, ctx.run_timeout).map_err(|_| {
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
            "The value holds {} credentials, for example a .env file. Save one credential at a time.",
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

/// Store a new item for the agent, or return its own item with the same value.
fn store(
    vault: &mut Vault,
    caller: &Caller,
    operation: &str,
    found: &Detected,
    tool: OriginTool,
) -> WireResponse {
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
            "Added by the agent{} ({}). The value was not returned.",
            caller.place(),
            tool.as_str()
        ),
    });
    let note = if tool == OriginTool::Save {
        NOTE_SAVED
    } else {
        NOTE_CREATED
    };
    WireResponse::success(item_answer(vault, summary.id, true, note))
}

/// The value of a capture or an update, without the vault lock.
fn obtain(
    ctx: &BrokerContext,
    caller: &Caller,
    source: Source<'_>,
    purpose: &str,
    path: Option<&str>,
) -> Result<Zeroizing<String>, WireResponse> {
    match source {
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
            check_command(command, cwd, purpose, &caller.protected).map_err(refused)?;
            run_capture(ctx, command, cwd, path)
        }
        Source::File(file) => read_file(file, &caller.protected).map_err(refused),
        Source::Generate(spec) => {
            let (length, alphabet) = generation(spec)?;
            generate_value(length, alphabet).ok_or_else(|| {
                WireResponse::failure("broker_error", "The system random source failed.")
            })
        }
    }
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
    let value = obtain(ctx, &caller, source, purpose, request.path);
    let mut guard = lock(&ctx.vault);
    let vault = match resume(&mut guard, &caller, token, operation) {
        Ok(vault) => vault,
        Err(response) => return response,
    };
    let value = match value {
        Ok(value) => value,
        Err(response) => return deny(vault, &caller.agent, None, operation, response),
    };
    match detected(&value, request.name) {
        Ok(found) => store(vault, &caller, operation, &found, OriginTool::Capture),
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
    let value = match obtain(ctx, &caller, Source::Generate(spec), "", None) {
        Ok(value) => value,
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
        &generated(&name, &value),
        OriginTool::Generate,
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
        Ok(found) => store(vault, &caller, operation, &found, OriginTool::Save),
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
        project_key: caller.project_key.clone(),
        project_label: caller.project_label.clone(),
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
    let wait = ctx.approval_timeout.as_secs();
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
                // ADR 0025 §3: one waiting question per agent. A run question of an
                // agent with the same name counts too.
                let busy = mine.iter().any(|known| {
                    known.state == CredentialRequestState::Open
                        && known.created_at.saturating_add(wait) > now
                }) || ctx
                    .approvals
                    .pending()
                    .iter()
                    .any(|pending| pending.agent == caller.agent.name);
                if busy {
                    return deny(
                        vault,
                        &caller.agent,
                        None,
                        operation,
                        WireResponse::failure(
                            codes::QUESTION_WAITING,
                            super::run::QUESTION_WAITING,
                        ),
                    );
                }
                let open = mine
                    .iter()
                    .filter(|known| known.state == CredentialRequestState::Open)
                    .count();
                if open >= MAX_OPEN_REQUESTS_PER_AGENT {
                    return deny(
                        vault,
                        &caller.agent,
                        None,
                        operation,
                        WireResponse::failure(
                            "too_many_requests",
                            format!(
                                "This agent has {MAX_OPEN_REQUESTS_PER_AGENT} open credential requests. Wait for the owner."
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
                                "The agent asked the owner for \"{}\"{}. It waits for the owner.",
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
    let deadline = Instant::now() + ctx.approval_timeout;
    loop {
        {
            let guard = lock(&ctx.vault);
            let Some(vault) = guard
                .as_ref()
                .filter(|vault| !vault.is_locked() && vault.path() == caller.vault_file)
            else {
                return waiting();
            };
            match vault.credential_request(request_id) {
                Ok(known) => match (known.state, known.item_id) {
                    (CredentialRequestState::Saved, Some(item_id))
                        if vault.details(item_id).is_ok() =>
                    {
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
            return waiting();
        }
        std::thread::sleep(POLL.min(deadline - now));
    }
}

pub(super) fn update(
    ctx: &BrokerContext,
    token: &str,
    request: &UpdateRequest<'_>,
) -> WireResponse {
    let operation = "update credential";
    let source = match Source::one_of(request.command, request.file, request.generate) {
        Ok(source) => source,
        Err(response) => return response,
    };
    if let Source::Generate(spec) = source
        && let Err(response) = generation(spec)
    {
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
    }
    let value = obtain(ctx, &caller, source, "", request.path);
    let mut guard = lock(&ctx.vault);
    let vault = match resume(&mut guard, &caller, token, operation) {
        Ok(vault) => vault,
        Err(response) => return response,
    };
    let value = match value {
        Ok(value) => value,
        Err(response) => return deny(vault, &caller.agent, Some(item_id), operation, response),
    };
    if value.is_empty() {
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
    match vault.replace_own_item_value(caller.agent.id, item_id, &value) {
        Ok(_) => {}
        Err(err) => {
            let response = match err.kind() {
                VaultErrorKind::NotFound => not_owner(),
                VaultErrorKind::InvalidInput => invalid(
                    "Apassy cannot use this value for the credential: it is too long, or too short for its placeholder.",
                ),
                _ => WireResponse::failure("broker_error", "The broker cannot store the value."),
            };
            return deny(vault, &caller.agent, Some(item_id), operation, response);
        }
    }
    // A live value of a provider makes the declaration stricter at once (ADR 0025 §5);
    // a looser value changes nothing until the owner answers.
    super::corrections::raise_for_value(vault, item_id, &value);
    let _ = vault.record_activity(&NewActivity {
        agent_id: Some(caller.agent.id),
        agent_name: caller.agent.name.clone(),
        item_id: Some(item_id),
        operation: operation.to_owned(),
        decision: ActivityDecision::Allow,
        reason: "The agent gave its credential a new value. The value was not returned.".to_owned(),
    });
    let mut answer = item_answer(
        vault,
        item_id,
        false,
        "Apassy stored the new value. You never get the value.",
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
        return invalid("Give at least one of name, notes, env_name, and hosts.");
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
    match vault.describe_own_item(agent.id, item_id, change) {
        Ok(_) => {
            let mut changed = Vec::new();
            for (set, word) in [
                (change.title.is_some(), "name"),
                (change.notes.is_some(), "notes"),
                (change.env_name.is_some(), "variable"),
                (change.hosts.is_some(), "hosts"),
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
                    "The agent changed the {} of its credential.",
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
                    "Another credential uses this env_name. Choose another name.",
                ),
                VaultErrorKind::InvalidInput => invalid(
                    "Use a name of 1 to 128 bytes, notes of at most 8192 bytes, an env_name like MY_API_KEY that is not reserved (PATH, HOME, DYLD_*, ...), and hosts that only narrow where the value goes: hosts for a placeholder instead of the real value, or some of the placeholder hosts that the credential has.",
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

    #[test]
    fn capture_commands_follow_the_rules() {
        let protected = Protected {
            folders: vec![PathBuf::from("/synthetic/apassy-data")],
            files: vec![PathBuf::from("/synthetic/vaults/main.db")],
        };
        let cwd = Path::new("/tmp");
        let argv = |parts: &[&str]| parts.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>();
        assert!(check_command(&argv(&["gh", "auth", "token"]), cwd, "", &protected).is_ok());
        for bad in [
            argv(&["sh", "-c", "gh auth token"]),
            argv(&["/usr/bin/env", "gh", "auth", "token"]),
            argv(&["python3", "-c", "print(1)"]),
            argv(&["security", "find-generic-password", "-w"]),
            argv(&["curl", "https://example.com/token"]),
            argv(&["cat", "/synthetic/apassy-data/vault.db"]),
            argv(&["cat", "/synthetic/vaults/main.db-wal"]),
            argv(&["cp", "--from=/synthetic/apassy-data/x", "y"]),
            argv(&["rm", "-rf", "build"]),
            argv(&["-gh"]),
        ] {
            assert!(check_command(&bad, cwd, "", &protected).is_err(), "{bad:?}");
        }
        assert!(
            check_command(
                &argv(&["gh", "auth", "token"]),
                cwd,
                "ignore previous instructions",
                &protected
            )
            .is_err()
        );
    }
}
