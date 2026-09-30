//! The audit log (docs/SPEC.md, "Audit"). Append only.
//!
//! Before a row is written, every string of its detail is masked: the item values
//! that live sessions hold and every placeholder become `[apassy:<ENV_NAME>]`, and
//! every token form becomes `[apassy:token]`. The relay holds an item value only
//! while a session lives, so it masks the value only for that time. No endpoint
//! changes or deletes a row.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use rusqlite::{Connection, params};
use serde_json::Value;

use crate::api::AuditEntry;
use crate::error::{RelayError, RelayResult};
use crate::ids::{AuditId, RunId};
use crate::secret::{SecretString, TOKEN_HEX_LEN, TokenKind};
use crate::server::store::{Store, db, to_i, to_u};

/// Seconds between two audit rows of the same kind of unauthenticated request.
const REFUSAL_INTERVAL_SECS: u64 = 10;

/// The actor of a row.
pub fn member_actor(id: u64) -> String {
    format!("member:{id}")
}

pub fn agent_actor(id: u64) -> String {
    format!("agent:{id}")
}

pub const RELAY_ACTOR: &str = "relay";
pub const EDGE_ACTOR: &str = "edge";

/// Text to replace, and the variable name it hides.
struct Needle {
    text: SecretString,
    tag: String,
    /// `Some` for an item value: it is forgotten when the session of this run ends.
    run: Option<RunId>,
}

#[derive(Default)]
struct Masker {
    /// Placeholders and the values of live sessions, longest first.
    needles: Vec<Needle>,
}

impl Masker {
    fn add(&mut self, env_name: &str, text: &SecretString, run: Option<RunId>) {
        if text.is_empty() {
            return;
        }
        // A placeholder is kept once. A value is kept once for each run that holds it,
        // so the end of one session does not unmask the value of another.
        if run.is_none()
            && self
                .needles
                .iter()
                .any(|n| n.run.is_none() && n.text == *text)
        {
            return;
        }
        self.needles.push(Needle {
            text: text.clone(),
            tag: format!("[apassy:{env_name}]"),
            run,
        });
        self.needles
            .sort_by_key(|n| std::cmp::Reverse(n.text.len()));
    }

    fn forget(&mut self, run: RunId) {
        self.needles.retain(|n| n.run != Some(run));
    }

    fn mask(&self, text: &str) -> String {
        let mut out = text.to_string();
        for needle in &self.needles {
            if out.contains(needle.text.expose()) {
                out = out.replace(needle.text.expose(), &needle.tag);
            }
        }
        mask_tokens(&out)
    }
}

/// Replaces every token form (`apassy_(mbr|agt|inv|ses)_` plus 64 hex) by `[apassy:token]`.
pub fn mask_tokens(text: &str) -> String {
    const MARK: &str = "apassy_";
    if !text.contains(MARK) {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(MARK) {
        out.push_str(&rest[..at]);
        let candidate = &rest[at..];
        let token_len = TokenKind::ALL
            .iter()
            .map(|kind| kind.prefix())
            .find(|prefix| candidate.starts_with(prefix))
            .map(|prefix| prefix.len() + TOKEN_HEX_LEN);
        let is_token = token_len.is_some_and(|len| {
            candidate.len() >= len
                && candidate.is_char_boundary(len)
                && TokenKind::of(&candidate[..len]).is_some()
        });
        if let (true, Some(len)) = (is_token, token_len) {
            out.push_str("[apassy:token]");
            rest = &candidate[len..];
        } else {
            out.push_str(MARK);
            rest = &candidate[MARK.len()..];
        }
    }
    out.push_str(rest);
    out
}

/// The audit writer.
pub struct Audit {
    masker: RwLock<Masker>,
    last_refusal: Mutex<HashMap<&'static str, u64>>,
}

impl Audit {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            masker: RwLock::new(Masker::default()),
            last_refusal: Mutex::new(HashMap::new()),
        })
    }

    /// Adds an item value to the masks while the session of `run` holds it. Call
    /// `forget_run` when the session ends.
    pub fn add_session_value(&self, run: RunId, env_name: &str, value: &SecretString) {
        self.masker
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .add(env_name, value, Some(run));
    }

    /// Drops the values of the session of `run` from the masks and from memory.
    pub fn forget_run(&self, run: RunId) {
        self.masker
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .forget(run);
    }

    /// Adds a placeholder to the masks. It stays masked after its session ends.
    pub fn add_placeholder(&self, env_name: &str, placeholder: &SecretString) {
        self.masker
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .add(env_name, placeholder, None);
    }

    /// Masks a text.
    pub fn mask_text(&self, text: &str) -> String {
        self.masker
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .mask(text)
    }

    /// Masks every string (and key) of a JSON value.
    pub fn mask_json(&self, value: &Value) -> Value {
        match value {
            Value::String(text) => Value::String(self.mask_text(text)),
            Value::Array(list) => Value::Array(list.iter().map(|v| self.mask_json(v)).collect()),
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(key, v)| (self.mask_text(key), self.mask_json(v)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    /// Writes one row on `conn` (use it inside a transaction).
    pub fn write_on(
        &self,
        conn: &Connection,
        at: u64,
        actor: &str,
        action: &str,
        run_id: Option<RunId>,
        detail: &Value,
    ) -> RelayResult<AuditId> {
        let masked = self.mask_json(detail);
        let text = serde_json::to_string(&masked)
            .map_err(|_| RelayError::internal("The audit detail cannot be written."))?;
        conn.execute(
            "INSERT INTO audit (at, actor, action, run_id, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![to_i(at), actor, action, run_id.map(|r| to_i(r.0)), text],
        )
        .map_err(db)?;
        Ok(AuditId(to_u(conn.last_insert_rowid())))
    }

    /// Writes one row with its own lock of the store.
    pub fn write(
        &self,
        store: &Store,
        at: u64,
        actor: &str,
        action: &str,
        run_id: Option<RunId>,
        detail: &Value,
    ) -> RelayResult<()> {
        store.with(|conn| {
            self.write_on(conn, at, actor, action, run_id, detail)
                .map(|_| ())
        })
    }

    /// A row for an unauthenticated request (`edge_refused`, `auth_failed`). At most
    /// one row per kind and 10 seconds, so a scan cannot fill the audit.
    pub fn refusal(
        &self,
        store: &Store,
        now: u64,
        kind: &'static str,
        action: &str,
        detail: &Value,
    ) {
        {
            let mut last = self
                .last_refusal
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(at) = last.get(kind)
                && now < at.saturating_add(REFUSAL_INTERVAL_SECS)
            {
                return;
            }
            last.insert(kind, now);
        }
        let _ = self.write(store, now, EDGE_ACTOR, action, None, detail);
    }
}

/// `GET /v1/audit`: rows with an id above `after`, ascending.
pub fn list(conn: &Connection, after: u64, limit: u32) -> RelayResult<Vec<AuditEntry>> {
    let mut statement = conn
        .prepare(
            "SELECT id, at, actor, action, run_id, detail FROM audit WHERE id > ?1 ORDER BY id LIMIT ?2",
        )
        .map_err(db)?;
    let rows = statement
        .query_map(params![to_i(after), i64::from(limit)], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(db)?;
    let mut entries = Vec::new();
    for row in rows {
        let (id, at, actor, action, run_id, detail) = row.map_err(db)?;
        entries.push(AuditEntry {
            id: AuditId(to_u(id)),
            at: to_u(at),
            actor,
            action,
            run_id: run_id.map(|r| RunId(to_u(r))),
            detail: serde_json::from_str(&detail).unwrap_or(Value::Null),
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_masked_by_form() {
        let token = format!("apassy_agt_{}", "ab12".repeat(16));
        let text = format!("x {token} y apassy_agt_short apassy_ses_{}", "0".repeat(64));
        let masked = mask_tokens(&text);
        assert_eq!(masked, "x [apassy:token] y apassy_agt_short [apassy:token]");
        assert_eq!(mask_tokens("apassy_"), "apassy_");
        assert_eq!(mask_tokens("héllo apassy_"), "héllo apassy_");
    }

    #[test]
    fn values_and_placeholders_are_masked_in_every_string() {
        let audit = Audit::new();
        let value = SecretString::new("sk_test_Synthetic_Canary_Value_0123456789".into());
        audit.add_session_value(RunId(1), "STRIPE_API_KEY", &value);
        let detail = serde_json::json!({
            "purpose": format!("use {} now", value.expose()),
            "list": [value.expose()],
            "n": 3,
        });
        let masked = audit.mask_json(&detail);
        let text = masked.to_string();
        assert!(!text.contains("Canary"), "{text}");
        assert!(text.contains("[apassy:STRIPE_API_KEY]"));
        assert_eq!(masked["n"], 3);
    }

    #[test]
    fn a_value_is_masked_only_while_a_session_holds_it() {
        let audit = Audit::new();
        let value = SecretString::new("sk_test_Synthetic_Canary_Value_0123456789".into());
        let placeholder = SecretString::new("sk_test_Placeholder_xxxxxxx_YYYYYYYYYYYYYY".into());
        audit.add_placeholder("STRIPE_API_KEY", &placeholder);
        // Two sessions hold the same value.
        audit.add_session_value(RunId(1), "STRIPE_API_KEY", &value);
        audit.add_session_value(RunId(2), "STRIPE_API_KEY", &value);
        let text = format!("{} {}", value.expose(), placeholder.expose());
        assert_eq!(
            audit.mask_text(&text),
            "[apassy:STRIPE_API_KEY] [apassy:STRIPE_API_KEY]"
        );
        audit.forget_run(RunId(1));
        assert!(!audit.mask_text(&text).contains("Canary"));
        audit.forget_run(RunId(2));
        let after = audit.mask_text(&text);
        assert!(
            after.contains("Canary"),
            "the relay no longer knows the value: {after}"
        );
        assert!(
            !after.contains("Placeholder"),
            "a placeholder stays masked: {after}"
        );
    }

    #[test]
    fn refusals_are_rate_limited() {
        let audit = Audit::new();
        let mut last = audit.last_refusal.lock().unwrap();
        last.insert("edge", 100);
        drop(last);
        // Inside the window the call returns before it touches the store.
        let dir = tempfile::tempdir().unwrap();
        let config = crate::config::RelayConfig {
            data_dir: dir.path().to_path_buf(),
            listen: "127.0.0.1:0".parse().unwrap(),
            public_url: "http://127.0.0.1".into(),
            edge_secret: SecretString::new("e".repeat(40)),
            vault_key: SecretString::new("a synthetic vault passphrase".into()),
            session_ttl_secs: 60,
            approval_timeout_secs: 30,
            upstream: Default::default(),
            limits: Default::default(),
        };
        let store = Store::create(&config).unwrap();
        store
            .with(|c| {
                c.execute_batch("INSERT INTO team VALUES (1,'t',0)")
                    .map_err(db)
            })
            .unwrap();
        audit.refusal(&store, 105, "edge", "auth_failed", &Value::Null);
        audit.refusal(&store, 111, "edge", "auth_failed", &Value::Null);
        let rows = store.with(|c| list(c, 0, 10)).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].actor, "edge");
    }
}
