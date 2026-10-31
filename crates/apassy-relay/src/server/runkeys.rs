//! The one-time keys of pending runs, in memory only (docs/SPEC.md, "Host-held item
//! keys").
//!
//! Each pending run has one X25519 key. Its public half goes to the owner's host; its
//! private half never leaves this table and is never written to disk. A release
//! takes the key out, so it is used once. A key is dropped when its run is released,
//! denied, timed out, or invalidated by a revocation. A restart drops them all: a
//! pending run is ended explicitly at startup with a safe retry instruction.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::api::Suggestion;
use crate::hostkeys::{KEY_BYTES, RunKey};
use crate::ids::RunId;

/// The key of one pending run, and the relay's own verdict on the run.
pub struct PendingKey {
    pub key: RunKey,
    pub suggestion: Suggestion,
}

/// The table of run keys.
#[derive(Default)]
pub struct RunKeys {
    inner: Mutex<HashMap<RunId, PendingKey>>,
}

impl RunKeys {
    fn lock(&self) -> MutexGuard<'_, HashMap<RunId, PendingKey>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn insert(&self, run: RunId, key: RunKey, suggestion: Suggestion) {
        self.lock().insert(run, PendingKey { key, suggestion });
    }

    /// The public key and the suggestion of a run, for the host. The private key stays.
    pub fn offer(&self, run: RunId) -> Option<([u8; KEY_BYTES], Suggestion)> {
        self.lock()
            .get(&run)
            .map(|pending| (pending.key.public(), pending.suggestion))
    }

    /// Takes the key out. A second call gets `None`.
    pub fn take(&self, run: RunId) -> Option<PendingKey> {
        self.lock().remove(&run)
    }

    /// Drops the key of a run, if it has one.
    pub fn remove(&self, run: RunId) {
        self.lock().remove(&run);
    }

    /// Drops every key whose run `keep` does not name.
    pub fn retain(&self, keep: impl Fn(RunId) -> bool) {
        self.lock().retain(|run, _| keep(*run));
    }

    pub fn clear(&self) {
        self.lock().clear();
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_offered_until_it_is_taken() {
        let keys = RunKeys::default();
        let key = RunKey::generate().unwrap();
        let public = key.public();
        keys.insert(RunId(4), key, Suggestion::Allow);
        assert_eq!(keys.offer(RunId(4)), Some((public, Suggestion::Allow)));
        assert_eq!(keys.offer(RunId(5)), None);
        assert!(keys.take(RunId(4)).is_some());
        assert!(keys.take(RunId(4)).is_none());
        assert_eq!(keys.offer(RunId(4)), None);
    }

    #[test]
    fn retain_and_clear_drop_keys() {
        let keys = RunKeys::default();
        for id in 1..=3 {
            keys.insert(RunId(id), RunKey::generate().unwrap(), Suggestion::Ask);
        }
        keys.retain(|run| run == RunId(2));
        assert_eq!(keys.len(), 1);
        keys.remove(RunId(2));
        assert!(keys.is_empty());
        keys.insert(RunId(9), RunKey::generate().unwrap(), Suggestion::Ask);
        keys.clear();
        assert!(keys.is_empty());
    }
}
