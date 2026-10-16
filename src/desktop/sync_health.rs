//! The sync log and the notice of a vault that keeps failing to sync
//! (docs/operations/sync.md, section 7).
//!
//! The sync worker ([`super::sync_worker`]) tells [`SyncHealth`] each failed and each
//! working sync of the open vault, the status that it reads for that vault, and each
//! sync that the owner starts. [`SyncHealth`]:
//!
//! - appends one line for each failure to the sync log ([`sync_log_path`]: mode
//!   `0600`; at [`MAX_LOG_BYTES`] the log becomes `sync.log.1` and a new one starts).
//!   The same failure of the same vault again writes at most one line every
//!   [`REPEAT_EVERY`], with the count of the repeats since the last line. The first sync
//!   that works after failures writes one line with their count and the time of the
//!   first one.
//! - says when a vault keeps failing ([`StuckNotice`]): after [`STUCK_AFTER`] for an
//!   error, after [`WAITING_STUCK_AFTER`] while iCloud does not deliver the newest copy,
//!   never for a folder or a relay that is away (the owner's drive or network). Once for
//!   each streak of failures; a sync that works ends the streak.
//!
//! A line has the time (UTC), the list ID of the vault, the kind of sync, the name and
//! the text of the error, the status of the synced file, and the first 12 hexadecimal
//! digits of the hash of the synced file on this Mac and of the hash after the last
//! sync. The error texts are fixed: no vault name, credential, passphrase, or path goes
//! into the log.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::native::SyncStuckReason;
use crate::sync::{FileStatus, SyncError};

/// The file name of the sync log.
pub(crate) const LOG_FILE: &str = "sync.log";
/// The log becomes `sync.log.1` when a line would make it larger than this.
pub(crate) const MAX_LOG_BYTES: u64 = 256 * 1024;
/// The same failure of a vault writes at most one line in this time.
pub(crate) const REPEAT_EVERY: Duration = Duration::from_secs(10 * 60);
/// A vault that fails this long gets a notification.
pub(crate) const STUCK_AFTER: Duration = Duration::from_secs(5 * 60);
/// A vault whose newest copy iCloud does not deliver this long gets a notification.
pub(crate) const WAITING_STUCK_AFTER: Duration = Duration::from_secs(10 * 60);
/// Digits of a hash in a line.
const HASH_DIGITS: usize = 12;

/// The sync log of the app with the data folder `data_dir`:
/// `~/Library/Logs/Apassy/sync.log` on macOS for the usual data folder (next to
/// `bouncer.log`), else `<data_dir>/logs/sync.log`. So a test or an app with another
/// data folder never writes to the owner's log.
pub(crate) fn sync_log_path(data_dir: &Path) -> PathBuf {
    let home = std::env::var_os("HOME").filter(|home| !home.is_empty());
    match home {
        Some(home) if cfg!(target_os = "macos") && data_dir == crate::paths::data_dir() => {
            PathBuf::from(home)
                .join("Library")
                .join("Logs")
                .join("Apassy")
                .join(LOG_FILE)
        }
        _ => data_dir.join("logs").join(LOG_FILE),
    }
}

/// How a vault syncs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncKind {
    Folder,
    Relay,
}

impl SyncKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Folder => "folder",
            Self::Relay => "relay",
        }
    }
}

/// What a line says about the synced file. No content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LogDetails {
    pub(crate) file_status: Option<FileStatus>,
    /// The hash of the synced file on this Mac.
    pub(crate) file_sha256: Option<String>,
    /// The hash of the synced file after the last sync.
    pub(crate) last_sha256: Option<String>,
}

/// A vault that keeps failing: one notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StuckNotice {
    /// The list ID of the vault.
    pub(crate) id: String,
    pub(crate) reason: SyncStuckReason,
}

/// The failures of one vault since its last sync that worked.
#[derive(Debug)]
struct Streak {
    kind: SyncKind,
    started: Instant,
    started_at: SystemTime,
    failures: u64,
    /// The failure of the last line, and when the line was written.
    logged: Option<(SyncError, Instant)>,
    /// The same failure again since that line.
    repeats: u64,
    notified: bool,
}

/// The sync log and the stuck-vault notice. The worker holds one.
#[derive(Debug)]
pub(crate) struct SyncHealth {
    /// `None`: no log (a unit test of the worker, or before the app sets it).
    log: Option<PathBuf>,
    /// The time of a line. A test gives a fixed time.
    wall: fn() -> SystemTime,
    streaks: BTreeMap<String, Streak>,
}

impl Default for SyncHealth {
    fn default() -> Self {
        Self {
            log: None,
            wall: SystemTime::now,
            streaks: BTreeMap::new(),
        }
    }
}

impl SyncHealth {
    /// Write the log at `log`, or no log.
    pub(crate) fn set_log(&mut self, log: Option<PathBuf>) {
        self.log = log;
    }

    #[cfg(test)]
    pub(crate) fn with_wall(mut self, wall: fn() -> SystemTime) -> Self {
        self.wall = wall;
        self
    }

    /// A sync of the vault `id` failed with `err`, or its status says so, at `now`.
    /// `details` runs only when a line is written. Returns a notice when the vault fails
    /// long enough for a notification, once for each streak.
    pub(crate) fn failure(
        &mut self,
        now: Instant,
        id: &str,
        kind: SyncKind,
        err: SyncError,
        details: impl FnOnce() -> LogDetails,
    ) -> Option<StuckNotice> {
        let Self { log, wall, streaks } = self;
        let at = wall();
        let streak = streaks.entry(id.to_owned()).or_insert_with(|| Streak {
            kind,
            started: now,
            started_at: at,
            failures: 0,
            logged: None,
            repeats: 0,
            notified: false,
        });
        streak.kind = kind;
        streak.failures = streak.failures.saturating_add(1);
        let same = streak.logged.is_some_and(|(last, _)| last == err);
        let due = streak.logged.is_none_or(|(_, written)| {
            !same || now.saturating_duration_since(written) >= REPEAT_EVERY
        });
        if due {
            let repeats = if same { streak.repeats } else { 0 };
            append(
                log.as_deref(),
                &failure_line(at, id, kind, err, repeats, &details()),
            );
            streak.logged = Some((err, now));
            streak.repeats = 0;
        } else {
            streak.repeats = streak.repeats.saturating_add(1);
        }
        let (after, reason) = stuck_after(err)?;
        if streak.notified || now.saturating_duration_since(streak.started) < after {
            return None;
        }
        streak.notified = true;
        Some(StuckNotice {
            id: id.to_owned(),
            reason,
        })
    }

    /// A sync of the vault `id` worked, or its status is up to date. The first one after
    /// failures writes a line and ends the streak.
    pub(crate) fn success(&mut self, id: &str) {
        if let Some(streak) = self.streaks.remove(id) {
            let line = format!(
                "{} sync-ok vault={} kind={} after={} failures since={}\n",
                utc((self.wall)()),
                clean_id(id),
                streak.kind.as_str(),
                streak.failures,
                utc(streak.started_at),
            );
            append(self.log.as_deref(), &line);
        }
    }

    /// Keep the streak of the vault `open` only: a vault that is not open is not
    /// watched.
    pub(crate) fn retain(&mut self, open: Option<&str>) {
        self.streaks.retain(|id, _| Some(id.as_str()) == open);
    }
}

/// How long a vault fails with `err` before a notification, and its reason. `None`: a
/// folder or a relay that is away gets none.
fn stuck_after(err: SyncError) -> Option<(Duration, SyncStuckReason)> {
    match err {
        SyncError::FolderUnavailable | SyncError::RelayUnreachable => None,
        SyncError::NotDownloaded => Some((WAITING_STUCK_AFTER, SyncStuckReason::WaitingForIcloud)),
        SyncError::NeedsPassphrase => Some((STUCK_AFTER, SyncStuckReason::NeedsPassphrase)),
        SyncError::Damaged => Some((STUCK_AFTER, SyncStuckReason::Damaged)),
        _ => Some((STUCK_AFTER, SyncStuckReason::Error)),
    }
}

fn failure_line(
    at: SystemTime,
    id: &str,
    kind: SyncKind,
    err: SyncError,
    repeats: u64,
    details: &LogDetails,
) -> String {
    let text: String = err
        .to_string()
        .chars()
        .filter(|ch| !ch.is_control())
        .map(|ch| if ch == '"' { '\'' } else { ch })
        .collect();
    let file = details
        .file_status
        .map_or_else(|| "-".to_owned(), |status| format!("{status:?}"));
    let mut line = format!(
        "{} sync-failed vault={} kind={} error={err:?} text=\"{text}\" file={file} hash={} last={}",
        utc(at),
        clean_id(id),
        kind.as_str(),
        hash_prefix(details.file_sha256.as_deref()),
        hash_prefix(details.last_sha256.as_deref()),
    );
    if repeats > 0 {
        line.push_str(&format!(" repeats={repeats}"));
    }
    line.push('\n');
    line
}

/// The list ID as it is in `vaults.json`: letters, digits, `-`, and `_`, at most 64.
fn clean_id(id: &str) -> String {
    let id: String = id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
        .take(64)
        .collect();
    if id.is_empty() { "-".to_owned() } else { id }
}

/// The first 12 digits of a lowercase hexadecimal hash, or `-`.
fn hash_prefix(hash: Option<&str>) -> String {
    match hash {
        Some(hash) if hash.len() >= HASH_DIGITS && hash.bytes().all(|b| b.is_ascii_hexdigit()) => {
            hash[..HASH_DIGITS].to_ascii_lowercase()
        }
        _ => "-".to_owned(),
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ`.
fn utc(at: SystemTime) -> String {
    let unix = at
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let text = crate::vault::format_utc(unix);
    let text = text.trim_end_matches(" UTC");
    format!("{}Z", text.replacen(' ', "T", 1))
}

/// Append `line` to the log at `log`. A full log becomes `<log>.1` first. A failure of
/// the log changes nothing else: sync goes on.
fn append(log: Option<&Path>, line: &str) {
    let Some(log) = log else {
        return;
    };
    let _ = try_append(log, line);
}

fn try_append(log: &Path, line: &str) -> std::io::Result<()> {
    if let Some(dir) = log.parent()
        && !dir.is_dir()
    {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let len = fs::metadata(log).map_or(0, |meta| meta.len());
    if len > 0 && len + line.len() as u64 > MAX_LOG_BYTES {
        let mut rotated = log.as_os_str().to_owned();
        rotated.push(".1");
        fs::rename(log, PathBuf::from(rotated))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(log)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(line.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn fixed_time() -> SystemTime {
        // 2026-10-17 18:41:05 UTC.
        UNIX_EPOCH + Duration::from_secs(1_792_262_465)
    }

    fn health(log: &Path) -> SyncHealth {
        let mut health = SyncHealth::default().with_wall(fixed_time);
        health.set_log(Some(log.to_owned()));
        health
    }

    fn details() -> LogDetails {
        LogDetails {
            file_status: Some(FileStatus::NotDownloaded),
            file_sha256: Some("ab".repeat(32)),
            last_sha256: Some("cd".repeat(32)),
        }
    }

    fn lines(log: &Path) -> Vec<String> {
        fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// Each failure has one line; the same failure again writes once in 10 minutes with
    /// the count, another failure at once, and a sync that works ends the streak.
    #[test]
    fn the_same_failure_logs_once_in_ten_minutes_with_its_count() {
        let dir = tempfile::tempdir().expect("dir");
        let log = dir.path().join("logs").join(LOG_FILE);
        let mut health = health(&log);
        let t0 = Instant::now();
        let mut asked = 0;
        for step in 0..20u64 {
            health.failure(
                t0 + Duration::from_secs(30 * step),
                ID,
                SyncKind::Folder,
                SyncError::NotDownloaded,
                || {
                    asked += 1;
                    details()
                },
            );
        }
        assert_eq!(asked, 1, "the details are read only for a line");
        assert_eq!(lines(&log).len(), 1);
        assert_eq!(
            lines(&log)[0],
            format!(
                "2026-10-17T18:41:05Z sync-failed vault={ID} kind=folder error=NotDownloaded text=\"the synced file is not on this Mac yet; wait for the download\" file=NotDownloaded hash=abababababab last=cdcdcdcdcdcd"
            )
        );
        // 10 minutes after the first line: one line with the 19 repeats since it.
        health.failure(
            t0 + REPEAT_EVERY,
            ID,
            SyncKind::Folder,
            SyncError::NotDownloaded,
            details,
        );
        let all = lines(&log);
        assert_eq!(all.len(), 2);
        assert!(all[1].ends_with(" repeats=19"), "{}", all[1]);
        // Another failure writes at once.
        health.failure(
            t0 + REPEAT_EVERY + Duration::from_secs(1),
            ID,
            SyncKind::Folder,
            SyncError::Vault(crate::vault::VaultErrorKind::Locked),
            LogDetails::default,
        );
        let all = lines(&log);
        assert_eq!(all.len(), 3);
        assert!(
            all[2].contains(" error=Vault(Locked) ") && all[2].contains(" file=- hash=- last=-"),
            "{}",
            all[2]
        );
        health.success(ID);
        let all = lines(&log);
        assert_eq!(
            all[3],
            format!(
                "2026-10-17T18:41:05Z sync-ok vault={ID} kind=folder after=22 failures since=2026-10-17T18:41:05Z"
            )
        );
        // No streak: a second success writes nothing.
        health.success(ID);
        assert_eq!(lines(&log).len(), 4);
        assert_eq!(
            fs::metadata(&log).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(log.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    /// Each error writes only its name, its fixed text, the file status, and hash
    /// digits: never a name, a path, or another value that the caller has.
    #[test]
    fn a_line_has_only_fixed_words_ids_and_hash_digits() {
        let dir = tempfile::tempdir().expect("dir");
        let log = dir.path().join(LOG_FILE);
        let mut health = health(&log);
        let now = Instant::now();
        let errors = [
            SyncError::NotEnabled,
            SyncError::FolderUnavailable,
            SyncError::NotDownloaded,
            SyncError::NeedsPassphrase,
            SyncError::Damaged,
            SyncError::OtherVault,
            SyncError::WrongVault,
            SyncError::State,
            SyncError::Vault(crate::vault::VaultErrorKind::WrongKeyOrCorrupt),
            SyncError::Io,
            SyncError::TimedOut,
            SyncError::RelayUnreachable,
            SyncError::StaleCopy,
            SyncError::Relay(crate::sync::RelayRefusal::RateLimited),
        ];
        for err in errors {
            health.failure(now, ID, SyncKind::Relay, err, || LogDetails {
                file_status: Some(FileStatus::Changed),
                // Not a hash: it does not get into the log.
                file_sha256: Some("Personal synthetic-secret-canary /Users/x".to_owned()),
                last_sha256: Some("ab".repeat(32)),
            });
        }
        // A list ID with other characters keeps only the safe ones.
        health.failure(
            now,
            "id with \"quotes\"\nand a newline",
            SyncKind::Folder,
            SyncError::Io,
            LogDetails::default,
        );
        let text = fs::read_to_string(&log).unwrap();
        assert_eq!(text.lines().count(), errors.len() + 1);
        for (line, err) in text.lines().zip(errors) {
            assert!(line.contains(&format!(" error={err:?} ")), "{line}");
            assert!(
                line.contains(&format!(" text=\"{}\" ", err.to_string().replace('"', "'"))),
                "{line}"
            );
        }
        for canary in [
            "synthetic-secret-canary",
            "Personal",
            "/Users/x",
            "\"quotes\"",
        ] {
            assert!(!text.contains(canary), "{canary} in {text}");
        }
        assert!(text.contains(" vault=idwithquotesandanewline "), "{text}");
    }

    #[test]
    fn a_full_log_moves_to_a_second_file() {
        let dir = tempfile::tempdir().expect("dir");
        let log = dir.path().join(LOG_FILE);
        fs::write(&log, vec![b'x'; MAX_LOG_BYTES as usize - 10]).unwrap();
        let mut health = health(&log);
        health.failure(
            Instant::now(),
            ID,
            SyncKind::Folder,
            SyncError::Io,
            LogDetails::default,
        );
        assert_eq!(
            fs::metadata(dir.path().join("sync.log.1")).unwrap().len(),
            MAX_LOG_BYTES - 10
        );
        assert_eq!(lines(&log).len(), 1);
    }

    /// An error notifies after 5 minutes, once for each streak; waiting for iCloud after
    /// 10 minutes; a folder or relay that is away never.
    #[test]
    fn a_stuck_vault_notifies_once_after_its_time() {
        let mut health = SyncHealth::default();
        let t0 = Instant::now();
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        let fail = |health: &mut SyncHealth, secs, err| {
            health.failure(at(secs), ID, SyncKind::Folder, err, LogDetails::default)
        };
        assert_eq!(fail(&mut health, 0, SyncError::Io), None);
        assert_eq!(fail(&mut health, 299, SyncError::Io), None);
        assert_eq!(
            fail(&mut health, 300, SyncError::Io),
            Some(StuckNotice {
                id: ID.to_owned(),
                reason: SyncStuckReason::Error
            })
        );
        assert_eq!(fail(&mut health, 330, SyncError::Io), None, "once");
        assert_eq!(fail(&mut health, 3600, SyncError::Damaged), None, "once");
        health.success(ID);
        // A new streak.
        assert_eq!(fail(&mut health, 3700, SyncError::NotDownloaded), None);
        assert_eq!(
            fail(&mut health, 3700 + 300, SyncError::NotDownloaded),
            None
        );
        assert_eq!(
            fail(&mut health, 3700 + 600, SyncError::NotDownloaded),
            Some(StuckNotice {
                id: ID.to_owned(),
                reason: SyncStuckReason::WaitingForIcloud
            })
        );
        health.success(ID);
        assert_eq!(fail(&mut health, 5000, SyncError::FolderUnavailable), None);
        assert_eq!(fail(&mut health, 9000, SyncError::FolderUnavailable), None);
        assert_eq!(fail(&mut health, 9000, SyncError::RelayUnreachable), None);
        // A real error later in the same streak: the streak is long already.
        assert_eq!(
            fail(&mut health, 9001, SyncError::NeedsPassphrase),
            Some(StuckNotice {
                id: ID.to_owned(),
                reason: SyncStuckReason::NeedsPassphrase
            })
        );
        // A vault that is not open any more is not watched.
        health.retain(Some("another"));
        assert_eq!(fail(&mut health, 9002, SyncError::Io), None);
    }

    #[test]
    fn the_log_of_another_data_folder_stays_in_it() {
        let dir = tempfile::tempdir().expect("dir");
        assert_eq!(
            sync_log_path(dir.path()),
            dir.path().join("logs").join(LOG_FILE)
        );
    }
}
