//! Local, metadata-only relay observations. No keys or plaintext journal leave the core.
//! The caller holds the questions mutex for disk work, so lock/removal cannot race writes.
//! Version 2 uses a device-local key independent of rotating relay question keys.
use super::{
    config::valid_id,
    errors::{CoreError, CoreResult},
    questions::envelope,
};
use apassy::sync::{decode_b64u, encode_b64u};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

/// Failure to retrieve a durable, device-local history key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryKeyError {
    Missing,
    Unavailable,
}

/// Called only while an authorized vault context is held. Implementations must never
/// replace an existing key, and must not create one when `may_create` is false.
pub trait HistoryKeyProvider: Send + Sync {
    fn key(&self, vault_id: &str, may_create: bool)
    -> Result<Zeroizing<[u8; 32]>, HistoryKeyError>;
}

pub(super) const RETENTION_DAYS: u64 = 30;
pub(super) const MAX_ENTRIES: usize = 1000;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Entry {
    pub id: String,
    pub vault_id: String,
    pub qid: String,
    pub source: String,
    pub title: String,
    pub agent: String,
    pub project: Option<String>,
    pub action: String,
    pub production: bool,
    pub device_name: String,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
    pub expires_at: u64,
    pub selected_kind: Option<String>,
    pub selected_environment: Option<String>,
    pub selected_item_id: Option<String>,
    pub sent_at: Option<u64>,
    pub attempted_at: Option<u64>,
    answer_time: Option<u64>,
    pub outcome: Option<String>,
    pub confirmed_kind: Option<String>,
    pub confirmed_at: Option<u64>,
    pub confirmed_by: Option<String>,
    pub replaced_by: Option<String>,
    // Detect a reused qid: never inherit a different request's selected answer/outcome.
    digest: String,
}

impl Entry {
    fn live_attempt(&self, at: u64) -> bool {
        self.attempted_at.is_some() && self.outcome.is_none() && self.expires_at > at
    }

    pub fn observed(vault_id: &str, card: &envelope::Card, expires_at: u64, at: u64) -> Self {
        let title = card
            .question
            .items
            .iter()
            .take(4)
            .map(|item| envelope::shown(&item.name, 64))
            .collect::<Vec<_>>()
            .join(", ");
        Self {
            id: format!("relay:{vault_id}:{}", card.qid),
            vault_id: vault_id.into(),
            qid: card.qid.clone(),
            source: "relay".into(),
            title: if title.is_empty() {
                "Request".into()
            } else {
                title
            },
            agent: envelope::shown(&card.run.agent, 64),
            project: card
                .question
                .project
                .as_ref()
                .map(|p| envelope::shown(&p.label, 80)),
            action: envelope::shown(&card.question.action, 64),
            production: card.question.production,
            device_name: envelope::shown(&card.asker.name, 64),
            first_seen_at: at,
            last_seen_at: at,
            expires_at,
            selected_kind: None,
            selected_environment: None,
            selected_item_id: None,
            sent_at: None,
            attempted_at: None,
            answer_time: None,
            outcome: None,
            confirmed_kind: None,
            confirmed_at: None,
            confirmed_by: None,
            replaced_by: None,
            digest: card.digest.clone(),
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct Journal {
    pub entries: Vec<Entry>,
}

impl Journal {
    pub fn observe(&mut self, entry: Entry, settle: Option<envelope::Settle>) {
        let entry = if let Some(old) = self.entries.iter_mut().find(|old| old.qid == entry.qid) {
            if old.digest != entry.digest {
                return;
            }
            old.last_seen_at = old.last_seen_at.max(entry.last_seen_at);
            old
        } else {
            self.entries.push(entry);
            self.entries.last_mut().expect("just inserted")
        };
        if let Some(settle) = settle {
            if entry.confirmed_at.is_some_and(|at| at > settle.at) {
                return;
            }
            entry.outcome = Some(settle.outcome);
            entry.confirmed_kind = settle.kind.map(|value| envelope::shown(&value, 64));
            entry.confirmed_at = Some(settle.at);
            entry.confirmed_by = settle.device_name.map(|value| envelope::shown(&value, 64));
            entry.replaced_by = settle.replaced_by.filter(|qid| envelope::valid_qid(qid));
        }
    }

    pub fn attempt(
        &mut self,
        qid: &str,
        digest: &str,
        choice: &envelope::Choice,
        at: u64,
        answer_time: u64,
    ) -> bool {
        // Never replace another live authority guard to make room for a new POST.
        let already_pending = self
            .entries
            .iter()
            .any(|entry| entry.qid == qid && entry.digest == digest && entry.live_attempt(at));
        if !already_pending
            && self
                .entries
                .iter()
                .filter(|entry| entry.live_attempt(at))
                .count()
                >= MAX_ENTRIES
        {
            return false;
        }
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.qid == qid && entry.digest == digest)
        {
            entry.selected_kind = Some(choice.kind().into());
            if let envelope::Choice::CorrectEnvironment {
                item_id,
                environment,
            } = choice
            {
                entry.selected_environment = Some(environment.clone());
                entry.selected_item_id = Some(item_id.to_string());
            } else {
                entry.selected_environment = None;
                entry.selected_item_id = None;
            }
            entry.attempted_at = Some(at);
            entry.answer_time = Some(answer_time);
            return true;
        }
        false
    }

    pub fn reject_fresh_attempt(
        &mut self,
        qid: &str,
        digest: &str,
        choice: &envelope::Choice,
        time: u64,
    ) -> bool {
        if !self.permits_answer(qid, digest, choice, time) {
            return false;
        }
        let Some(entry) = self.entries.iter_mut().find(|entry| {
            entry.qid == qid
                && entry.digest == digest
                && entry.sent_at.is_none()
                && entry.outcome.is_none()
        }) else {
            return false;
        };
        entry.selected_kind = None;
        entry.selected_environment = None;
        entry.selected_item_id = None;
        entry.attempted_at = None;
        entry.answer_time = None;
        true
    }

    pub fn sent(&mut self, qid: &str, digest: &str, at: u64) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.qid == qid && entry.digest == digest)
        {
            entry.sent_at = Some(at);
        }
    }

    /// Only the exact prior signed payload can be retried after delivery.
    pub fn permits_answer(
        &self,
        qid: &str,
        digest: &str,
        choice: &envelope::Choice,
        time: u64,
    ) -> bool {
        let Some(entry) = self.entries.iter().find(|entry| {
            entry.qid == qid
                && entry.digest == digest
                && (entry.sent_at.is_some() || entry.attempted_at.is_some())
        }) else {
            return true;
        };
        let correction_matches = match choice {
            envelope::Choice::CorrectEnvironment {
                item_id,
                environment,
            } => {
                entry.selected_environment.as_deref() == Some(environment.as_str())
                    && entry.selected_item_id.as_deref() == Some(item_id.to_string().as_str())
            }
            _ => true,
        };
        entry.answer_time == Some(time)
            && entry.selected_kind.as_deref() == Some(choice.kind())
            && correction_matches
    }

    pub fn answered(&self, qid: &str, digest: &str) -> Option<&'static str> {
        let entry = self.entries.iter().find(|entry| {
            entry.qid == qid
                && entry.digest == digest
                && (entry.sent_at.is_some() || entry.attempted_at.is_some())
        })?;
        match entry.selected_kind.as_deref()? {
            "approve_once" => Some("approve_once"),
            "approve_in_project" => Some("approve_in_project"),
            "allow_production" => Some("allow_production"),
            "correct_environment" => Some("correct_environment"),
            "deny" => Some("deny"),
            "never_for_agent" => Some("never_for_agent"),
            "always_ask_for_agent" => Some("always_ask_for_agent"),
            "disconnect" => Some("disconnect"),
            _ => None,
        }
    }

    pub fn prune(&mut self, at: u64) {
        // Retention starts at first observation; repeated relay reads cannot keep a record forever.
        let cutoff = at.saturating_sub(RETENTION_DAYS * 86400);
        self.entries
            .retain(|entry| entry.live_attempt(at) || entry.first_seen_at >= cutoff);
        // Pending, unexpired authority guards outrank newer passive observations.
        self.entries.sort_by(|a, b| {
            (b.live_attempt(at), b.first_seen_at, &b.id).cmp(&(
                a.live_attempt(at),
                a.first_seen_at,
                &a.id,
            ))
        });
        self.entries.truncate(MAX_ENTRIES);
    }
}

#[derive(Serialize, Deserialize)]
struct Sealed {
    version: u32,
    key_id: String,
    nonce: String,
    ciphertext: String,
}

fn unavailable() -> CoreError {
    CoreError::new(
        "history_unavailable",
        "History could not be read or saved. Retry when local storage is available.",
    )
}

fn directory(data: &Path) -> CoreResult<PathBuf> {
    // Created and excluded from backup by the native host before it opts into persistence.
    let dir = data.join("request-history");
    let metadata = fs::symlink_metadata(&dir).map_err(|_| unavailable())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(unavailable());
    }
    Ok(dir)
}
fn path(data: &Path, vault_id: &str) -> CoreResult<PathBuf> {
    if !valid_id(vault_id) {
        return Err(CoreError::invalid("Invalid vault ID."));
    }
    Ok(directory(data)?.join(format!("{vault_id}.json")))
}
fn aad(vault_id: &str, key_id: &str) -> Vec<u8> {
    format!("apassy-local-request-history-v1\0{vault_id}\0{key_id}").into_bytes()
}

fn read_sealed(data: &Path, vault_id: &str) -> CoreResult<Option<Sealed>> {
    let path = path(data, vault_id)?;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(unavailable()),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_FILE_BYTES {
        return Err(unavailable());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| unavailable())?
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(unavailable());
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| unavailable())
}

/// Used only to limit in-memory migration material; no untrusted header grants
/// authorization or permits discarding an unreadable journal.
pub(super) fn legacy_key_id(data: &Path, vault_id: &str) -> CoreResult<Option<String>> {
    Ok(read_sealed(data, vault_id)?
        .filter(|sealed| sealed.version == 1)
        .map(|sealed| sealed.key_id))
}

fn open_sealed(
    sealed: Sealed,
    vault_id: &str,
    version: u32,
    key_id: &str,
    key: &[u8],
    at: u64,
) -> CoreResult<Journal> {
    if sealed.version != version || sealed.key_id != key_id {
        return Err(unavailable());
    }
    let nonce = decode_b64u(&sealed.nonce).ok_or_else(unavailable)?;
    let ciphertext = decode_b64u(&sealed.ciphertext).ok_or_else(unavailable)?;
    let aad = version_aad(version, vault_id, key_id);
    let plain =
        Zeroizing::new(envelope::open(key, &nonce, &aad, &ciphertext).ok_or_else(unavailable)?);
    let mut journal: Journal = serde_json::from_slice(&plain).map_err(|_| unavailable())?;
    if journal.entries.len() > MAX_ENTRIES
        || journal.entries.iter().any(|e| {
            e.vault_id != vault_id
                || !envelope::valid_qid(&e.qid)
                || e.id != format!("relay:{vault_id}:{}", e.qid)
                || e.source != "relay"
        })
    {
        return Err(unavailable());
    }
    journal.prune(at);
    Ok(journal)
}

fn version_aad(version: u32, vault_id: &str, key_id: &str) -> Vec<u8> {
    if version == 1 {
        aad(vault_id, key_id)
    } else {
        format!("apassy-local-request-history-v2\0{vault_id}\0{key_id}").into_bytes()
    }
}

fn local_key(
    provider: &dyn HistoryKeyProvider,
    vault_id: &str,
    may_create: bool,
) -> CoreResult<Zeroizing<[u8; 32]>> {
    provider
        .key(vault_id, may_create)
        .map_err(|error| match error {
            HistoryKeyError::Missing => CoreError::new(
                "history_key_missing",
                "This device's history key is missing. Existing history was preserved.",
            ),
            HistoryKeyError::Unavailable => CoreError::new(
                "history_storage_unavailable",
                "The device's history key is unavailable. Unlock the device and retry.",
            ),
        })
}

fn local_key_id(key: &[u8]) -> String {
    format!("local-{}", apassy::vault::question_key_id(key))
}

pub(super) fn load_local(
    data: &Path,
    vault_id: &str,
    legacy: Option<(&str, &[u8])>,
    provider: &dyn HistoryKeyProvider,
    at: u64,
) -> CoreResult<Journal> {
    match read_sealed(data, vault_id)? {
        None => {
            let _key = local_key(provider, vault_id, true)?;
            Ok(Journal::default())
        }
        Some(sealed) if sealed.version == 2 => {
            // An existing v2 ciphertext must NEVER cause replacement-key generation.
            let key = local_key(provider, vault_id, false)?;
            open_sealed(
                sealed,
                vault_id,
                2,
                &local_key_id(key.as_slice()),
                key.as_slice(),
                at,
            )
        }
        Some(sealed) if sealed.version == 1 => {
            let (key_id, key) = legacy.filter(|(id, _)| *id == sealed.key_id).ok_or_else(|| {
                CoreError::new("history_migration_blocked", "History needs its previous question key. The encrypted history was preserved.")
            })?;
            let journal = open_sealed(sealed, vault_id, 1, key_id, key, at)?;
            let local = local_key(provider, vault_id, true)?;
            // Before rename, a failure leaves v1 intact; after rename the complete
            // v2 ciphertext remains readable with the already-persisted local key.
            save_version(
                data,
                vault_id,
                2,
                &local_key_id(local.as_slice()),
                local.as_slice(),
                &journal,
            )?;
            Ok(journal)
        }
        Some(_) => Err(unavailable()),
    }
}

pub(super) fn save_local(
    data: &Path,
    vault_id: &str,
    provider: &dyn HistoryKeyProvider,
    journal: &Journal,
) -> CoreResult<()> {
    let key = local_key(provider, vault_id, false)?;
    save_version(
        data,
        vault_id,
        2,
        &local_key_id(key.as_slice()),
        key.as_slice(),
        journal,
    )
}

#[cfg(test)]
fn load(data: &Path, vault_id: &str, key_id: &str, key: &[u8], at: u64) -> CoreResult<Journal> {
    match read_sealed(data, vault_id)? {
        None => Ok(Journal::default()),
        Some(sealed) => open_sealed(sealed, vault_id, 1, key_id, key, at),
    }
}

#[cfg(test)]
fn save(
    data: &Path,
    vault_id: &str,
    key_id: &str,
    key: &[u8],
    journal: &Journal,
) -> CoreResult<()> {
    save_version(data, vault_id, 1, key_id, key, journal)
}

fn save_version(
    data: &Path,
    vault_id: &str,
    version: u32,
    key_id: &str,
    key: &[u8],
    journal: &Journal,
) -> CoreResult<()> {
    if journal.entries.len() > MAX_ENTRIES {
        return Err(unavailable());
    }
    let target = path(data, vault_id)?;
    let dir = directory(data)?;
    let plain = Zeroizing::new(serde_json::to_vec(journal).map_err(|_| unavailable())?);
    let mut nonce = [0; 12];
    getrandom::fill(&mut nonce).map_err(|_| unavailable())?;
    let sealed = envelope::seal(key, &nonce, &version_aad(version, vault_id, key_id), &plain)
        .ok_or_else(unavailable)?;
    let bytes = serde_json::to_vec(&Sealed {
        version,
        key_id: key_id.into(),
        nonce: encode_b64u(&nonce),
        ciphertext: encode_b64u(&sealed),
    })
    .map_err(|_| unavailable())?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(unavailable());
    }
    // Random create_new prevents a stale/symlink temp file from being followed.
    let temp = dir.join(format!(".{vault_id}.{}.tmp", encode_b64u(&nonce)));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|_| unavailable())?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| unavailable())?;
        fs::rename(&temp, target).map_err(|_| unavailable())?;
        fs::File::open(&dir)
            .and_then(|file| file.sync_all())
            .map_err(|_| unavailable())
    })();
    let _ = fs::remove_file(temp);
    result
}

pub(super) fn remove(data: &Path, vault_id: &str) -> CoreResult<()> {
    if !valid_id(vault_id) {
        return Err(CoreError::invalid("Invalid vault ID."));
    }
    // Older installs may never have created the directory.
    if !data.join("request-history").exists() {
        return Ok(());
    }
    let dir = directory(data)?;
    let prefix = format!(".{vault_id}.");
    for entry in fs::read_dir(&dir).map_err(|_| unavailable())? {
        let entry = entry.map_err(|_| unavailable())?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == format!("{vault_id}.json")
            || (name.starts_with(&prefix) && name.ends_with(".tmp"))
        {
            fs::remove_file(entry.path()).map_err(|_| unavailable())?;
        }
    }
    fs::File::open(dir)
        .and_then(|file| file.sync_all())
        .map_err(|_| unavailable())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    const VAULT: &str = "11111111111111111111111111111111";
    const OTHER: &str = "22222222222222222222222222222222";
    const QID: &str = "oKGio6SlpqeoqaqrrK2urw";
    const AT: u64 = 1800000000;
    struct Provider {
        value: Result<[u8; 32], HistoryKeyError>,
        calls: std::sync::Mutex<Vec<bool>>,
    }
    impl Provider {
        fn new(value: Result<[u8; 32], HistoryKeyError>) -> Self {
            Self {
                value,
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }
    }
    impl HistoryKeyProvider for Provider {
        fn key(
            &self,
            _vault_id: &str,
            may_create: bool,
        ) -> Result<Zeroizing<[u8; 32]>, HistoryKeyError> {
            self.calls.lock().unwrap().push(may_create);
            self.value.map(Zeroizing::new)
        }
    }

    #[test]
    fn legacy_fixture_migrates_atomically_and_survives_question_key_changes() {
        let dir = directory_for_test();
        let mut journal = Journal {
            entries: vec![entry()],
        };
        assert!(journal.attempt(QID, &"a".repeat(64), &envelope::Choice::Deny, AT, AT));
        // Exact pre-v2 format: no new field or key provider is needed to create it.
        save(dir.path(), VAULT, "old-question-key", &[7; 32], &journal).unwrap();
        let provider = Provider::new(Ok([41; 32]));
        let migrated = load_local(
            dir.path(),
            VAULT,
            Some(("old-question-key", &[7; 32])),
            &provider,
            AT,
        )
        .unwrap();
        assert_eq!(migrated.entries, journal.entries);
        let sealed = read_sealed(dir.path(), VAULT).unwrap().unwrap();
        assert_eq!(sealed.version, 2);
        assert!(
            !String::from_utf8_lossy(&fs::read(path(dir.path(), VAULT).unwrap()).unwrap())
                .contains("SYNTHETIC_PRIVATE_METADATA")
        );
        let restored = load_local(
            dir.path(),
            VAULT,
            Some(("rotated-key", &[99; 32])),
            &provider,
            AT,
        )
        .unwrap();
        assert_eq!(restored.entries, journal.entries);
        assert!(!restored.permits_answer(QID, &"a".repeat(64), &envelope::Choice::ApproveOnce, AT));
        assert_eq!(*provider.calls.lock().unwrap(), vec![true, false]);
        // Older Requests beta fails closed rather than reading v2 as empty history.
        assert!(load(dir.path(), VAULT, "old-question-key", &[7; 32], AT).is_err());
    }

    #[test]
    fn failed_or_impossible_migration_preserves_v1_bytes_without_reset() {
        let dir = directory_for_test();
        save(
            dir.path(),
            VAULT,
            "old-key",
            &[7; 32],
            &Journal {
                entries: vec![entry()],
            },
        )
        .unwrap();
        let original = fs::read(path(dir.path(), VAULT).unwrap()).unwrap();
        let unavailable = Provider::new(Err(HistoryKeyError::Unavailable));
        assert_eq!(
            load_local(
                dir.path(),
                VAULT,
                Some(("old-key", &[7; 32])),
                &unavailable,
                AT
            )
            .err()
            .unwrap()
            .code,
            "history_storage_unavailable"
        );
        assert_eq!(
            fs::read(path(dir.path(), VAULT).unwrap()).unwrap(),
            original
        );
        let provider = Provider::new(Ok([41; 32]));
        assert_eq!(
            load_local(
                dir.path(),
                VAULT,
                Some(("new-key", &[8; 32])),
                &provider,
                AT
            )
            .err()
            .unwrap()
            .code,
            "history_migration_blocked"
        );
        assert!(provider.calls.lock().unwrap().is_empty());
        assert_eq!(
            fs::read(path(dir.path(), VAULT).unwrap()).unwrap(),
            original
        );
    }

    #[test]
    fn existing_v2_never_recreates_missing_key_and_rejects_wrong_key_or_vault() {
        let dir = directory_for_test();
        let provider = Provider::new(Ok([41; 32]));
        let journal = Journal {
            entries: vec![entry()],
        };
        save_local(dir.path(), VAULT, &provider, &journal).unwrap();
        let original = fs::read(path(dir.path(), VAULT).unwrap()).unwrap();
        let missing = Provider::new(Err(HistoryKeyError::Missing));
        assert_eq!(
            load_local(dir.path(), VAULT, None, &missing, AT)
                .err()
                .unwrap()
                .code,
            "history_key_missing"
        );
        assert_eq!(*missing.calls.lock().unwrap(), vec![false]);
        assert!(load_local(dir.path(), VAULT, None, &Provider::new(Ok([42; 32])), AT).is_err());
        fs::write(path(dir.path(), OTHER).unwrap(), &original).unwrap();
        assert!(load_local(dir.path(), OTHER, None, &provider, AT).is_err());
        assert_eq!(
            fs::read(path(dir.path(), VAULT).unwrap()).unwrap(),
            original
        );
    }

    #[test]
    fn unreadable_journal_never_calls_provider_or_replaces_ciphertext() {
        let dir = directory_for_test();
        let provider = Provider::new(Ok([41; 32]));
        fs::write(path(dir.path(), VAULT).unwrap(), b"damaged ciphertext").unwrap();
        assert!(load_local(dir.path(), VAULT, None, &provider, AT).is_err());
        assert!(provider.calls.lock().unwrap().is_empty());
        assert_eq!(
            fs::read(path(dir.path(), VAULT).unwrap()).unwrap(),
            b"damaged ciphertext"
        );
        fs::remove_file(path(dir.path(), VAULT).unwrap()).unwrap();
        fs::create_dir(path(dir.path(), VAULT).unwrap()).unwrap();
        assert!(load_local(dir.path(), VAULT, None, &provider, AT).is_err());
        assert!(provider.calls.lock().unwrap().is_empty());
    }
    fn directory_for_test() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("request-history")).unwrap();
        fs::set_permissions(
            dir.path().join("request-history"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        dir
    }
    fn entry() -> Entry {
        Entry {
            id: format!("relay:{VAULT}:{QID}"),
            vault_id: VAULT.into(),
            qid: QID.into(),
            source: "relay".into(),
            title: "SYNTHETIC_PRIVATE_METADATA".into(),
            agent: "agent".into(),
            project: Some("project".into()),
            action: "deploy".into(),
            production: true,
            device_name: "Synthetic Mac".into(),
            first_seen_at: AT,
            last_seen_at: AT,
            expires_at: AT + 300,
            selected_kind: None,
            selected_environment: None,
            selected_item_id: None,
            sent_at: None,
            attempted_at: None,
            answer_time: None,
            outcome: None,
            confirmed_kind: None,
            confirmed_at: None,
            confirmed_by: None,
            replaced_by: None,
            digest: "a".repeat(64),
        }
    }
    #[test]
    fn encrypted_roundtrip_wrong_key_vault_binding_and_corruption() {
        let dir = directory_for_test();
        let journal = Journal {
            entries: vec![entry()],
        };
        save(dir.path(), VAULT, "key-one", &[7; 32], &journal).unwrap();
        let bytes = fs::read(path(dir.path(), VAULT).unwrap()).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("SYNTHETIC_PRIVATE_METADATA"));
        assert_eq!(
            load(dir.path(), VAULT, "key-one", &[7; 32], AT)
                .unwrap()
                .entries,
            journal.entries
        );
        assert!(load(dir.path(), VAULT, "key-one", &[8; 32], AT).is_err());
        assert!(load(dir.path(), VAULT, "rotated-key", &[8; 32], AT).is_err());
        fs::write(path(dir.path(), OTHER).unwrap(), &bytes).unwrap();
        assert!(load(dir.path(), OTHER, "key-one", &[7; 32], AT).is_err());
        fs::write(path(dir.path(), VAULT).unwrap(), b"corrupt").unwrap();
        assert!(load(dir.path(), VAULT, "key-one", &[7; 32], AT).is_err());
        assert_eq!(
            fs::read(path(dir.path(), VAULT).unwrap()).unwrap(),
            b"corrupt"
        );
    }
    #[test]
    fn sent_is_not_confirmed_and_reobserving_is_idempotent() {
        let mut journal = Journal::default();
        journal.observe(entry(), None);
        journal.attempt(
            QID,
            &"a".repeat(64),
            &envelope::Choice::ApproveOnce,
            AT + 1,
            AT,
        );
        journal.sent(QID, &"a".repeat(64), AT + 1);
        journal.observe(entry(), None);
        assert_eq!(journal.entries.len(), 1);
        assert_eq!(journal.entries[0].sent_at, Some(AT + 1));
        assert!(journal.entries[0].outcome.is_none());
        journal.observe(
            entry(),
            Some(envelope::Settle {
                v: 1,
                qid: QID.into(),
                outcome: "denied".into(),
                answered_by: None,
                device_name: Some("Other iPhone".into()),
                device_kind: Some("iphone".into()),
                kind: Some("deny".into()),
                at: AT + 2,
                replaced_by: None,
            }),
        );
        assert_eq!(journal.entries[0].outcome.as_deref(), Some("denied"));
        assert_eq!(
            journal.entries[0].selected_kind.as_deref(),
            Some("approve_once")
        );
        let mut changed = entry();
        changed.digest = "b".repeat(64);
        changed.title = "Replacement must not inherit confirmation".into();
        journal.observe(changed, None);
        assert_eq!(journal.entries[0].title, entry().title);
    }
    #[test]
    fn retention_and_bound_are_deterministic_and_clock_rollback_is_conservative() {
        let mut journal = Journal {
            entries: vec![entry()],
        };
        journal.prune(AT - 1);
        assert_eq!(journal.entries.len(), 1);
        journal.entries[0].last_seen_at = AT + RETENTION_DAYS * 86400 + 10;
        journal.prune(AT + RETENTION_DAYS * 86400 + 1);
        assert!(journal.entries.is_empty());
        journal.entries = (0..MAX_ENTRIES + 5)
            .map(|index| {
                let mut e = entry();
                e.id = index.to_string();
                e.first_seen_at += index as u64;
                e
            })
            .collect();
        journal.prune(AT + 2000);
        assert_eq!(journal.entries.len(), MAX_ENTRIES);
        assert_eq!(
            journal.entries[0].first_seen_at,
            AT + MAX_ENTRIES as u64 + 4
        );
    }
    #[test]
    fn live_attempt_survives_1001_newer_observations_and_full_pending_capacity_refuses_another() {
        let mut journal = Journal {
            entries: vec![entry()],
        };
        assert!(journal.attempt(QID, &"a".repeat(64), &envelope::Choice::Deny, AT, AT));
        for index in 0..MAX_ENTRIES + 1 {
            let mut observed = entry();
            observed.qid = encode_b64u(&(index as u128).to_be_bytes());
            observed.id = format!("relay:{VAULT}:{}", observed.qid);
            observed.first_seen_at = AT + 1;
            journal.observe(observed, None);
        }
        journal.prune(AT + 2);
        assert_eq!(journal.entries.len(), MAX_ENTRIES);
        assert_eq!(journal.answered(QID, &"a".repeat(64)), Some("deny"));
        assert!(!journal.permits_answer(QID, &"a".repeat(64), &envelope::Choice::ApproveOnce, AT));
        for entry in &mut journal.entries {
            entry.attempted_at = Some(AT);
            entry.answer_time = Some(AT);
            entry.selected_kind = Some("deny".into());
        }
        let new_qid = encode_b64u(&u128::MAX.to_be_bytes());
        let mut new_entry = entry();
        new_entry.qid = new_qid.clone();
        new_entry.id = format!("relay:{VAULT}:{new_qid}");
        new_entry.first_seen_at = AT + 2;
        journal.observe(new_entry, None);
        assert!(!journal.attempt(
            &new_qid,
            &"a".repeat(64),
            &envelope::Choice::Deny,
            AT + 2,
            AT + 2
        ));
        journal.prune(AT + 2);
        assert_eq!(journal.entries.len(), MAX_ENTRIES);
        assert!(journal.answered(&new_qid, &"a".repeat(64)).is_none());
        // Retrying an existing exact attempt remains possible at capacity.
        assert!(journal.attempt(QID, &"a".repeat(64), &envelope::Choice::Deny, AT + 2, AT));
    }

    #[test]
    fn removal_is_scoped_and_rejects_paths_and_symlinks() {
        let dir = directory_for_test();
        save(dir.path(), VAULT, "key", &[7; 32], &Journal::default()).unwrap();
        save(dir.path(), OTHER, "key", &[7; 32], &Journal::default()).unwrap();
        assert!(path(dir.path(), "../../elsewhere").is_err());
        remove(dir.path(), VAULT).unwrap();
        assert!(!path(dir.path(), VAULT).unwrap().exists());
        assert!(path(dir.path(), OTHER).unwrap().exists());
        std::os::unix::fs::symlink(
            path(dir.path(), OTHER).unwrap(),
            path(dir.path(), VAULT).unwrap(),
        )
        .unwrap();
        assert!(load(dir.path(), VAULT, "key", &[7; 32], AT).is_err());
        remove(dir.path(), VAULT).unwrap();
        assert!(path(dir.path(), OTHER).unwrap().exists());
    }
}
