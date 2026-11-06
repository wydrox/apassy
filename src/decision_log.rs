//! The bouncer decision log file, `~/Library/Logs/Apassy/bouncer-decisions.log`: one
//! JSON line for each decision of the broker about a run, a browser fill, or a
//! connector use. It says why a request asked the owner, so the owner and an agent can
//! debug it without an owner session. `apassy decisions log` reads it.
//!
//! The file is outside the encrypted vault, so it never holds a command, a user
//! request, a purpose, an environment value, or a secret value. A line holds names
//! (agent, credentials, project), destination hosts, closed reason kinds, rule flags,
//! the answers of the bouncer brain, the reason that the owner question shows (with
//! the secret values of the items masked), and the outcome. The decision log in the
//! vault keeps the full entry.
//!
//! Only the Apassy window writes it (`desktop::run_with` calls [`enable`]). Tests and
//! other hosts write nothing.
//! The file moves to `bouncer-decisions.log.1` at [`MAX_BYTES`].

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

pub const FILE_NAME: &str = "bouncer-decisions.log";
/// The file moves to `<name>.1` at this size, so the log keeps at most about twice it.
pub const MAX_BYTES: u64 = 2 * 1024 * 1024;
/// The longest reason or error text of a line, in bytes.
pub const MAX_TEXT: usize = 1_000;
/// The longest name of a line, in bytes.
const MAX_NAME: usize = 160;
/// The most hosts, flags, and credentials of a line.
const MAX_LIST: usize = 16;

static TARGET: OnceLock<PathBuf> = OnceLock::new();
static WRITE: Mutex<()> = Mutex::new(());
/// A failed chmod warns once on stderr ([`warn_once`]).
static CHMOD_WARNED: AtomicBool = AtomicBool::new(false);

/// `O_NOFOLLOW | O_NONBLOCK`: a symlink at the path of the log is never followed, so a
/// link that another process plants there makes the broker write, or chmod, no other
/// file; and a FIFO there does not block the decision. The values are the target's own
/// (rustix), not written numbers.
#[cfg(any(feature = "vault", feature = "desktop"))]
fn no_follow() -> io::Result<i32> {
    Ok((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
}

/// Without rustix the log is not written: no open without `O_NOFOLLOW`.
#[cfg(not(any(feature = "vault", feature = "desktop")))]
fn no_follow() -> io::Result<i32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the decision log needs O_NOFOLLOW",
    ))
}

/// Open `path` without following a symlink, and only as a regular file.
fn open_no_follow(options: &mut OpenOptions, path: &Path) -> io::Result<fs::File> {
    let file = options.custom_flags(no_follow()?).open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the decision log is not a regular file",
        ));
    }
    Ok(file)
}

/// Print `text` on stderr when `warned` is not set yet, and set it. True when it printed.
fn warn_once(warned: &AtomicBool, text: &str) -> bool {
    let first = !warned.swap(true, Ordering::Relaxed);
    if first {
        eprintln!("{text}");
    }
    first
}

/// Mode 0600 through the open `file` (fchmod: no window for a swapped path). A failure
/// warns once and does not stop the line: the file holds no secret value, and a log
/// without its lines helps no one.
fn make_private(file: &fs::File) {
    if let Err(error) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
        warn_once(
            &CHMOD_WARNED,
            &format!(
                "apassy: the bouncer decision log cannot get mode 0600 ({}); it is written anyway.",
                error.kind()
            ),
        );
    }
}

/// One decision. Every field is optional in the file, so older and newer lines read.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Line {
    /// Unix time of the decision.
    pub at: u64,
    /// The same time as text, for example `2026-11-03T14:20:01Z`.
    pub time: String,
    /// `run`, `browser_fill`, or `connector`.
    pub request: String,
    pub agent: String,
    pub items: Vec<Item>,
    /// The project label. Empty: no project.
    pub project: String,
    /// `read`, `change`, `deploy`, or `delete`. Empty for a connector use.
    pub action: String,
    /// `Bouncer`, `Owner`, `Answer`, `Pattern`, `Connector`, or `Refused`.
    pub route: String,
    /// The reason kind, for example `LowTaskMatch` or `HookUnverified`.
    pub reason: String,
    /// The reason kind as one sentence.
    pub headline: String,
    /// The reason that the owner question shows. Secret values are masked.
    pub why: String,
    /// Rule flags of the command analysis and the prompt hook.
    pub flags: Vec<String>,
    /// Where the task came from: `host` (a prompt hook), `agent`, or `none`.
    pub task_source: String,
    /// A credential of the run has a default or unconfirmed classification, so the
    /// task match needs 80%.
    pub default_source: bool,
    /// The answers of the bouncer brain, from 0 to 1. Empty: the brain was not asked.
    pub brain: BTreeMap<String, f64>,
    pub brain_model: String,
    /// Why the brain gave no answer. Empty when it answered or was not asked.
    pub brain_error: String,
    /// The destination hosts that Apassy found in the command.
    pub hosts: Vec<String>,
    /// `allowed`, `approved`, `approved_and_remembered`, `approved_and_granted`,
    /// `denied`, `timed_out`, `invalidated`, `refused`, or `question_waiting`.
    pub outcome: String,
    /// The device where the owner answered. Empty: no answer, or this Mac.
    pub answered_on: String,
    /// The error code of a refusal.
    pub code: String,
    /// Milliseconds from the request to the decision, with the wait for the owner.
    pub millis: u64,
}

/// A credential of a line.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Item {
    pub id: u64,
    /// Empty when the check refused the request before it read the credential.
    pub name: String,
}

impl Line {
    /// The route asked the owner.
    pub fn asked(&self) -> bool {
        self.route == "Owner"
    }

    /// The same line with each text and list cut to its limit.
    fn bounded(&self) -> Self {
        let mut line = self.clone();
        line.time = utc_text(line.at);
        for text in [
            &mut line.request,
            &mut line.agent,
            &mut line.project,
            &mut line.action,
            &mut line.route,
            &mut line.reason,
            &mut line.task_source,
            &mut line.brain_model,
            &mut line.outcome,
            &mut line.answered_on,
            &mut line.code,
        ] {
            *text = cut(text, MAX_NAME);
        }
        line.headline = cut(&line.headline, MAX_TEXT);
        line.why = cut(&line.why, MAX_TEXT);
        line.brain_error = cut(&line.brain_error, MAX_TEXT);
        line.items.truncate(MAX_LIST);
        for item in &mut line.items {
            item.name = cut(&item.name, MAX_NAME);
        }
        line.flags.truncate(MAX_LIST);
        line.hosts.truncate(MAX_LIST);
        for text in line.flags.iter_mut().chain(line.hosts.iter_mut()) {
            *text = cut(text, MAX_NAME);
        }
        line
    }
}

/// `~/Library/Logs/Apassy/bouncer-decisions.log`, next to `bouncer.log`.
pub fn default_path() -> PathBuf {
    let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
    home.join("Library")
        .join("Logs")
        .join("Apassy")
        .join(FILE_NAME)
}

/// The older file of `path`: `<name>.1`.
pub fn rotated(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".1");
    path.with_file_name(name)
}

/// Write the lines of this process to `path`. Only the first call counts.
pub fn enable(path: PathBuf) {
    let _ = TARGET.set(path);
}

/// The process writes lines ([`enable`]).
pub fn enabled() -> bool {
    TARGET.get().is_some()
}

/// Append `line` to the file of [`enable`]. A failure to write is ignored: the log
/// never stops a decision.
pub fn append(line: &Line) {
    if let Some(path) = TARGET.get() {
        let _ = append_to(path, line);
    }
}

/// Append `line` to `path` with mode 0600, after a move to [`rotated`] at
/// [`MAX_BYTES`]. The mode of `open` applies to a new file only, and a rename keeps the
/// mode, so both files get 0600 again here: an older or copied file may be 0644.
///
/// A symlink at `path` is never followed: its size is not the size of the log
/// (`symlink_metadata`), it does not rotate, and the open fails (`O_NOFOLLOW`). The
/// file that moves to `.1` gets 0600 through a handle of its own before the rename, so
/// no chmod follows a symlink at `.1` either.
pub fn append_to(path: &Path, line: &Line) -> io::Result<()> {
    let _guard = WRITE.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    if fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() >= MAX_BYTES) {
        let full = open_no_follow(OpenOptions::new().read(true), path)?;
        make_private(&full);
        drop(full);
        fs::rename(path, rotated(path))?;
    }
    let mut text = serde_json::to_string(&line.bounded()).map_err(io::Error::other)?;
    text.push('\n');
    let mut file = open_no_follow(
        OpenOptions::new().create(true).append(true).mode(0o600),
        path,
    )?;
    make_private(&file);
    file.write_all(text.as_bytes())
}

/// The lines of [`rotated`] and then of `path`, oldest first. A line that does not
/// read is left out. A missing file has no lines.
pub fn read(path: &Path) -> Vec<Line> {
    let mut lines = Vec::new();
    for file in [rotated(path), path.to_path_buf()] {
        let Ok(file) = fs::File::open(&file) else {
            continue;
        };
        for text in BufReader::new(file).lines().map_while(Result::ok) {
            if let Ok(line) = serde_json::from_str::<Line>(&text) {
                lines.push(line);
            }
        }
    }
    lines
}

/// What a line of the reason kind can change so that the next run does not ask. Empty
/// for a kind with no advice.
pub fn advice(reason: &str) -> &'static str {
    match reason {
        "MissingTask" => {
            "The agent sent no user request. Ask it to quote your words in user_request, or set up the prompt hook: apassy setup claude (or codex)."
        }
        "LowTaskMatch" => {
            "The brain did not see the command as a step of your task. Answer with \"Remember for this project\" to allow this action in the project, or give the agent a clearer task."
        }
        "ModelUnavailable" | "ModelTimeout" => {
            "Settings > Bouncer: start the bouncer brain with Apassy, and check ~/Library/Logs/Apassy/bouncer.log."
        }
        "HookUnverified" => {
            "The prompt hook task does not match the host transcript. Run apassy setup claude (or codex) again, and restart the agent."
        }
        "HookAmbiguous" => {
            "More than one agent session in this folder sent a task. Run one agent session per folder or worktree."
        }
        "HookFlags" => "The command analysis flagged the command. The reason names the flags.",
        "NotProject" => {
            "Start the agent in a project folder (a Git repository), not in your home folder or above it."
        }
        "AlwaysAsk" => {
            "The credential is set to Always ask. Change it in the credential, Agent Access."
        }
        "Production" => {
            "A production credential with write or admin scope: you approve each run, and a remembered answer does not change that. Declare it read-only if it is, or answer \"Allow as dev\" if it is not production."
        }
        "ForeignHost" => {
            "The command goes to a host that the credential does not know. Add the host to the credential (Agent Access > Hosts and risk), or remember your answer for the project."
        }
        "ForeignProject" => {
            "The credential is declared for another project. Change its project in Agent Access, or remember your answer for this project."
        }
        "MissingDeclaration" => {
            "The credential has no declaration. Answer \"Allow as dev\" or \"Allow as prod\": Apassy saves the label, and this question does not come back for it. You can also open it, Agent Access, and save its environment and risk."
        }
        "UnfitAnswer" => "Your earlier answer is for another action or host.",
        "OneTimeCode" => "A one-time code always asks, unless a project answer includes codes.",
        "ModelUnsure" => "The brain was not sure that the command is safe (writes or destroy).",
        _ => "",
    }
}

/// `2026-11-03T14:20:01Z`.
pub fn utc_text(unix: u64) -> String {
    let days = i64::try_from(unix / 86_400).unwrap_or(0);
    let secs = unix % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3_600,
        (secs % 3_600) / 60,
        secs % 60
    )
}

/// `text` cut to at most `max` bytes at a character boundary, without control
/// characters.
fn cut(text: &str, max: usize) -> String {
    let clean: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if clean.len() <= max {
        return clean;
    }
    let mut end = max.saturating_sub('…'.len_utf8());
    while !clean.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &clean[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(at: u64) -> Line {
        Line {
            at,
            request: "run".to_owned(),
            agent: "Claude Code".to_owned(),
            items: vec![Item {
                id: 92,
                name: "Synthetic key".to_owned(),
            }],
            route: "Owner".to_owned(),
            reason: "LowTaskMatch".to_owned(),
            outcome: "approved".to_owned(),
            brain: BTreeMap::from([("task_match".to_owned(), 0.69)]),
            ..Line::default()
        }
    }

    // `tempfile` is a dependency of the vault feature.
    #[cfg(feature = "vault")]
    #[test]
    fn lines_append_read_and_rotate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Logs/Apassy").join(FILE_NAME);
        append_to(&path, &line(1)).unwrap();
        append_to(&path, &line(2)).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let read_back = read(&path);
        assert_eq!(read_back.len(), 2);
        assert_eq!(read_back[0].time, "1970-01-01T00:00:01Z");
        assert!(read_back[1].asked());
        assert_eq!(read_back[1].brain["task_match"], 0.69);

        // A full file moves to `.1`; the reader returns the old lines first.
        fs::write(&path, vec![b' '; usize::try_from(MAX_BYTES).unwrap()]).unwrap();
        append_to(&path, &line(3)).unwrap();
        assert!(rotated(&path).exists());
        let read_back = read(&path);
        assert_eq!(read_back.len(), 1, "the blank file has no lines");
        assert_eq!(read_back[0].at, 3);
    }

    /// A log that an older build or a copy left at 0644 becomes 0600 at the next write,
    /// and so does its `.1` after a rotation.
    #[cfg(feature = "vault")]
    #[test]
    fn an_existing_0644_log_and_its_rotation_become_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;

        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(mode(&path), 0o644);
        append_to(&path, &line(1)).unwrap();
        assert_eq!(mode(&path), 0o600);

        // A full 0644 file moves to `.1`, which becomes 0600; the new file is 0600.
        fs::write(&path, vec![b' '; usize::try_from(MAX_BYTES).unwrap()]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        append_to(&path, &line(2)).unwrap();
        assert_eq!(mode(&rotated(&path)), 0o600);
        assert_eq!(mode(&path), 0o600);
    }

    /// Finding 6 of the 0.5.16 review: the log followed a symlink at its path, so the
    /// broker could append to, chmod, or rotate another file of the owner.
    #[cfg(feature = "vault")]
    #[test]
    fn a_symlink_at_the_log_or_its_rotation_is_never_followed() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let victim = dir.path().join("victim.txt");
        let path = dir.path().join(FILE_NAME);
        symlink(&victim, &path).unwrap();
        for size in [4, usize::try_from(MAX_BYTES).unwrap()] {
            fs::write(&victim, vec![b'k'; size]).unwrap();
            fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(append_to(&path, &line(1)).is_err(), "{size}");
            // No line, no chmod, and no rotation of the file behind the link.
            assert_eq!(fs::read(&victim).unwrap(), vec![b'k'; size]);
            assert_eq!(mode(&victim), 0o644);
            assert!(
                fs::symlink_metadata(&path)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert!(fs::symlink_metadata(rotated(&path)).is_err());
        }

        // A symlink at `.1`: the rename replaces the link, and the chmod went through
        // the handle of the full log, so the file behind the link keeps its mode.
        fs::remove_file(&path).unwrap();
        fs::write(&path, vec![b' '; usize::try_from(MAX_BYTES).unwrap()]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&victim, b"keep").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&victim, rotated(&path)).unwrap();
        append_to(&path, &line(2)).unwrap();
        let old = fs::symlink_metadata(rotated(&path)).unwrap();
        assert!(old.is_file());
        assert_eq!(old.len(), MAX_BYTES);
        assert_eq!(mode(&rotated(&path)), 0o600);
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        assert_eq!(mode(&victim), 0o644);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(read(&path).last().map(|line| line.at), Some(2));
    }

    /// A failed chmod warns once; it does not drop the lines (`make_private`).
    #[test]
    fn a_chmod_warning_is_printed_once() {
        let warned = AtomicBool::new(false);
        assert!(warn_once(&warned, "first"));
        assert!(!warn_once(&warned, "second"));
        assert!(warned.load(Ordering::Relaxed));
    }

    #[test]
    fn lines_are_bounded_and_unknown_fields_read() {
        let mut long = line(0);
        long.why = "é".repeat(MAX_TEXT);
        long.agent = "a\nb".to_owned();
        long.hosts = (0..40).map(|n| format!("h{n}.example")).collect();
        let bounded = long.bounded();
        assert!(bounded.why.len() <= MAX_TEXT);
        assert!(bounded.why.ends_with('…'));
        assert_eq!(bounded.agent, "a b");
        assert_eq!(bounded.hosts.len(), MAX_LIST);
        let newer: Line =
            serde_json::from_str(r#"{"at":5,"route":"Bouncer","later_field":true}"#).unwrap();
        assert_eq!(newer.at, 5);
        assert!(!newer.asked());
    }

    #[test]
    fn utc_text_and_advice() {
        assert_eq!(utc_text(1_793_715_280), "2026-11-03T14:14:40Z");
        assert_eq!(utc_text(951_782_400), "2000-02-29T00:00:00Z");
        assert!(advice("LowTaskMatch").contains("Remember for this project"));
        assert_eq!(advice("ModelAllowed"), "");
    }
}
