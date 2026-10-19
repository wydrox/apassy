//! Local, metadata-only relay observations. No keys or plaintext journal leave the core.
//! The caller holds the questions mutex for disk work, so lock/removal cannot race writes.
//! A changed question key deliberately makes the old journal unavailable until cleared.
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
        "History could not be read or saved. Clear this vault's history to start again.",
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

pub(super) fn load(
    data: &Path,
    vault_id: &str,
    key_id: &str,
    key: &[u8],
    at: u64,
) -> CoreResult<Journal> {
    let path = path(data, vault_id)?;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Journal::default()),
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
    let sealed: Sealed = serde_json::from_slice(&bytes).map_err(|_| unavailable())?;
    if sealed.version != 1 || sealed.key_id != key_id {
        return Err(unavailable());
    }
    let nonce = decode_b64u(&sealed.nonce).ok_or_else(unavailable)?;
    let ciphertext = decode_b64u(&sealed.ciphertext).ok_or_else(unavailable)?;
    let plain = Zeroizing::new(
        envelope::open(key, &nonce, &aad(vault_id, key_id), &ciphertext).ok_or_else(unavailable)?,
    );
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

pub(super) fn save(
    data: &Path,
    vault_id: &str,
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
    let sealed =
        envelope::seal(key, &nonce, &aad(vault_id, key_id), &plain).ok_or_else(unavailable)?;
    let bytes = serde_json::to_vec(&Sealed {
        version: 1,
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
