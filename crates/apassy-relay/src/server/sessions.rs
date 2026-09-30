//! Live proxy sessions, in memory only (docs/SPEC.md, "Session lifecycle").
//!
//! The table is keyed by the hash of the session key. The proxy reads it through
//! `SessionSource`. A restart ends every session. Nothing of a session is written to
//! disk except its id, run id, and expiry. The values of a session are the only
//! readable item values that the relay ever holds: each removal of a session erases
//! them and drops them from the audit masks.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rusqlite::{Connection, params};
use serde_json::json;

use crate::api::SessionView;
use crate::error::{RelayError, RelayResult};
use crate::ids::{RunId, SessionId};
use crate::secret::{TokenHash, TokenKind, new_token, token_hash};
use crate::server::audit::{Audit, RELAY_ACTOR, agent_actor};
use crate::server::env::{self, EnvItem};
use crate::server::store::{Store, db, to_i};
use crate::session::{LiveSession, ProxyEvent, SessionSecret, SessionSource};

struct Entry {
    session: Arc<LiveSession>,
    view: SessionView,
}

/// The table of live sessions.
pub struct SessionTable {
    inner: Mutex<HashMap<TokenHash, Entry>>,
    audit: Arc<Audit>,
    store: Arc<Store>,
    next_id: AtomicU64,
}

impl SessionTable {
    pub fn new(store: Arc<Store>, audit: Arc<Audit>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(HashMap::new()),
            audit,
            store,
            next_id: AtomicU64::new(1),
        })
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<TokenHash, Entry>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Makes a session for a run: the placeholders, the key, the environment. The
    /// returned hash is the handle for `remove_hash`, if the caller must undo it.
    pub fn create(
        &self,
        public_url: &str,
        run_id: RunId,
        agent_id: crate::ids::AgentId,
        member_id: crate::ids::MemberId,
        expires_at: u64,
        items: &[EnvItem],
    ) -> RelayResult<(SessionView, TokenHash)> {
        let key = new_token(TokenKind::Session)?;
        let hash = token_hash(key.expose());
        let mut secrets = Vec::with_capacity(items.len());
        let mut placeholders = Vec::with_capacity(items.len());
        for item in items {
            let placeholder = crate::proxy::mint(&item.value).ok_or_else(|| {
                RelayError::internal("A placeholder cannot be made for an item of this run.")
            })?;
            // Masked before it exists anywhere else.
            self.audit.add_placeholder(&item.env_name, &placeholder);
            self.audit
                .add_session_value(run_id, &item.env_name, &item.value);
            secrets.push(SessionSecret {
                item_id: item.item_id,
                env_name: item.env_name.clone(),
                placeholder: placeholder.clone(),
                value: item.value.clone(),
                hosts: item.hosts.clone(),
            });
            placeholders.push(placeholder);
        }
        let session_id = SessionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let view = env::build(
            public_url,
            &key,
            session_id,
            expires_at,
            items,
            &placeholders,
        );
        let session = Arc::new(LiveSession {
            id: session_id,
            run_id,
            agent_id,
            member_id,
            expires_at,
            secrets,
        });
        self.lock().insert(
            hash,
            Entry {
                session,
                view: view.clone(),
            },
        );
        Ok((view, hash))
    }

    /// Removes one session by its handle, without an audit row.
    pub fn remove_hash(&self, hash: &TokenHash) {
        let removed = self.lock().remove(hash);
        if let Some(entry) = removed {
            self.audit.forget_run(entry.session.run_id);
        }
    }

    /// The environment of the live session of a run, for the agent that asked for it.
    pub fn view_for_run(&self, run_id: RunId, now: u64) -> Option<SessionView> {
        self.lock()
            .values()
            .find(|entry| entry.session.run_id == run_id && entry.session.is_live(now))
            .map(|entry| entry.view.clone())
    }

    /// Removes the sessions that `matches` selects.
    pub fn remove_matching(&self, matches: impl Fn(&LiveSession) -> bool) -> Vec<Arc<LiveSession>> {
        let mut table = self.lock();
        let hashes: Vec<TokenHash> = table
            .iter()
            .filter(|(_, entry)| matches(&entry.session))
            .map(|(hash, _)| *hash)
            .collect();
        let removed: Vec<Arc<LiveSession>> = hashes
            .into_iter()
            .filter_map(|hash| table.remove(&hash))
            .map(|entry| entry.session)
            .collect();
        drop(table);
        for session in &removed {
            self.audit.forget_run(session.run_id);
        }
        removed
    }

    /// Ends the sessions that `matches` selects: removes them, sets their runs to
    /// `ended`, and writes a `session_ended` row for each. Call it inside the same
    /// transaction as the revocation.
    pub fn end_matching(
        &self,
        conn: &Connection,
        now: u64,
        reason: &str,
        matches: impl Fn(&LiveSession) -> bool,
    ) -> RelayResult<usize> {
        let ended = self.remove_matching(matches);
        for session in &ended {
            conn.execute(
                "UPDATE run SET status = 'ended' WHERE id = ?1 AND status = 'ready'",
                params![to_i(session.run_id.0)],
            )
            .map_err(db)?;
            self.audit.write_on(
                conn,
                now,
                RELAY_ACTOR,
                "session_ended",
                Some(session.run_id),
                &json!({"session_id": session.id, "reason": reason}),
            )?;
        }
        Ok(ended.len())
    }

    /// Removes every expired session and returns their run ids.
    pub fn purge_expired(&self, now: u64) -> Vec<RunId> {
        self.remove_matching(|s| !s.is_live(now))
            .into_iter()
            .map(|s| s.run_id)
            .collect()
    }

    /// Drops every session (at stop).
    pub fn clear(&self) {
        let removed: Vec<Entry> = self.lock().drain().map(|(_, entry)| entry).collect();
        for entry in &removed {
            self.audit.forget_run(entry.session.run_id);
        }
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl SessionSource for SessionTable {
    fn find(&self, session_key: &str, now: u64) -> Option<Arc<LiveSession>> {
        if TokenKind::of(session_key) != Some(TokenKind::Session) {
            return None;
        }
        let hash = token_hash(session_key);
        let table = self.lock();
        let entry = table.get(&hash)?;
        entry
            .session
            .is_live(now)
            .then(|| Arc::clone(&entry.session))
    }

    fn record(&self, event: ProxyEvent) {
        let actor = event
            .agent_id
            .map_or_else(|| RELAY_ACTOR.to_string(), |a| agent_actor(a.0));
        let detail = serde_json::to_value(&event).unwrap_or(json!({}));
        let result = self.audit.write(
            &self.store,
            event.at,
            &actor,
            "proxy_request",
            event.run_id,
            &detail,
        );
        if result.is_err() {
            eprintln!("apassy-relay: an audit row for a proxy request could not be written");
        }
    }
}
