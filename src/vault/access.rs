//! The access model of ADR 0012: what an agent can see, and access requests.
//!
//! An agent sees the items that it can use. When the owner lets it see all items, it
//! also gets a catalog: the name, the kind, and the plain fields of each item that is
//! not archived. The catalog never has a secret field, a hidden custom detail, the setup
//! key of a one-time password, or the notes, which often hold a pasted secret. An agent
//! that sees an item can ask for process access to it. The owner decides in the app.

use rusqlite::{OptionalExtension, TransactionBehavior};

use super::agents::{
    MAX_PROJECT_DIR_BYTES, checked_text, from_sql_time, now_unix, require_active_agent,
    require_item, to_sql_time,
};
use super::history::{self, ItemEventKind};
use super::types::{VaultErrorKind, VaultResult, err, kind_from_str};
use super::{Vault, to_public_id, to_sql_id};
use crate::contracts::CredentialKind;

pub const MAX_REQUEST_REASON_BYTES: usize = 500;
/// An agent has at most this many open requests.
pub const MAX_OPEN_REQUESTS: usize = 20;
pub const MAX_CATALOG_ITEMS: usize = 1000;
const MAX_CATALOG_VALUE_CHARS: usize = 200;
/// Custom details of the desktop app are fields named `x_` and the label in hexadecimal.
const DETAIL_PREFIX: &str = "x_";

/// The label of a custom detail field: `x_` and the label in hexadecimal. `None` for
/// another field.
pub fn custom_detail_label(name: &str) -> Option<String> {
    let hex = name.strip_prefix(DETAIL_PREFIX)?;
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(hex.get(index..index + 2)?, 16).ok())
        .collect();
    String::from_utf8(bytes?).ok()
}

/// Whether a stored field holds the setup key of a one-time password, hidden or (as an
/// older Apassy stored it) visible: it is a custom detail with the label of a one-time
/// password, or its value is an explicit `otpauth://totp` link. This is the rule of the
/// owner app. The agent catalog never gets such a value, even from a plain field.
pub(crate) fn is_setup_key_field(name: &str, value: &str) -> bool {
    custom_detail_label(name).is_some_and(|label| crate::otp::is_otp_label(&label))
        || crate::otp::is_totp_uri(value)
}

/// One item as an agent that sees all items gets it. It has no secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    pub item_id: u64,
    pub name: String,
    pub kind: CredentialKind,
    /// Plain fields and visible custom details: (name or label, value).
    pub details: Vec<(String, String)>,
    /// The item has an environment variable, so an agent can ask for process access.
    pub has_variable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestState {
    Open,
    Granted,
    Denied,
}

impl RequestState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Granted => "granted",
            Self::Denied => "denied",
        }
    }

    fn parse(text: &str) -> VaultResult<Self> {
        match text {
            "open" => Ok(Self::Open),
            "granted" => Ok(Self::Granted),
            "denied" => Ok(Self::Denied),
            _ => Err(err(VaultErrorKind::Storage)),
        }
    }
}

/// A request of an agent for process access to one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRequest {
    pub id: u64,
    pub agent_id: u64,
    pub agent_name: String,
    pub item_id: u64,
    pub item_name: String,
    /// The words of the agent. The owner reads them as a claim.
    pub reason: String,
    /// The working directory that the agent named, or empty.
    pub cwd: String,
    pub created_at: u64,
    pub state: RequestState,
}

/// Printable text without control characters, cut at `max` bytes.
fn clean(text: &str, max: usize) -> String {
    let clean: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let clean = clean.trim();
    let mut end = clean.len().min(max);
    while !clean.is_char_boundary(end) {
        end -= 1;
    }
    clean[..end].to_owned()
}

impl Vault {
    /// The agent sees all items without values (ADR 0012).
    pub fn agent_sees_all(&self, agent_id: u64) -> VaultResult<bool> {
        let agent = to_sql_id(agent_id)?;
        let value: Option<i64> = self
            .conn_ref()?
            .query_row(
                "SELECT see_all FROM agent WHERE id = ?1 AND revoked_at IS NULL",
                [agent],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(value == Some(1))
    }

    /// Let an active agent see all items without values, or only the items that it can
    /// use. The desktop app asks for the owner check before it turns this on.
    pub fn set_agent_sees_all(&mut self, agent_id: u64, on: bool) -> VaultResult<()> {
        let agent = to_sql_id(agent_id)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        require_active_agent(&tx, agent)?;
        tx.execute(
            "UPDATE agent SET see_all = ?1 WHERE id = ?2",
            (i64::from(on), agent),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        if !on {
            // An agent that cannot see the items cannot keep asking for them.
            tx.execute(
                "UPDATE access_request SET state = 'denied', decided_at = ?1
                 WHERE agent_id = ?2 AND state = 'open'",
                (to_sql_time(now_unix())?, agent),
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        }
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// Each item that is not archived, by name, with its plain fields. No secret field,
    /// no hidden custom detail (it is a secret field), no passkey field, no setup key of
    /// a one-time password (a visible one too), and no notes.
    pub fn catalog(&self) -> VaultResult<Vec<CatalogEntry>> {
        let conn = self.conn_ref()?;
        let mut items = conn
            .prepare(
                "SELECT item.id, item.title, item.kind,
                     EXISTS (SELECT 1 FROM env_binding WHERE env_binding.item_id = item.id)
                 FROM item
                 WHERE item.id NOT IN (SELECT item_id FROM item_archive)
                 ORDER BY item.title COLLATE NOCASE, item.id
                 LIMIT ?1",
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let limit = i64::try_from(MAX_CATALOG_ITEMS).map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = items
            .query_map([limit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let mut fields = conn
            .prepare(
                "SELECT name, value FROM item_field
                 WHERE item_id = ?1 AND secret = 0 AND substr(name, 1, 8) <> 'passkey_'
                 ORDER BY position",
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let mut catalog = Vec::new();
        for row in rows {
            let (id, name, kind, bound) = row.map_err(|_| err(VaultErrorKind::Storage))?;
            let plain = fields
                .query_map([id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|_| err(VaultErrorKind::Storage))?;
            let mut details = Vec::new();
            for field in plain {
                let (field_name, value) = field.map_err(|_| err(VaultErrorKind::Storage))?;
                if value.trim().is_empty() || is_setup_key_field(&field_name, &value) {
                    continue;
                }
                let label = custom_detail_label(&field_name).unwrap_or(field_name);
                let value: String = value.chars().take(MAX_CATALOG_VALUE_CHARS).collect();
                details.push((label, value));
            }
            catalog.push(CatalogEntry {
                item_id: to_public_id(id)?,
                name,
                kind: kind_from_str(&kind)?,
                details,
                has_variable: bound == 1,
            });
        }
        Ok(catalog)
    }

    /// An agent asks for process access to one item. Returns the request ID and
    /// whether the request is new. An open request for the same item is returned again.
    ///
    /// - `NotFound`: the agent does not see all items, or the item is archived or gone.
    /// - `InvalidInput`: the item has no environment variable, or the reason is empty.
    /// - `AlreadyExists`: the agent has process access to the item.
    /// - `Busy`: the agent has [`MAX_OPEN_REQUESTS`] open requests.
    pub fn request_access(
        &mut self,
        agent_id: u64,
        item_id: u64,
        reason: &str,
        cwd: &str,
    ) -> VaultResult<(u64, bool)> {
        let agent = to_sql_id(agent_id)?;
        let item = to_sql_id(item_id)?;
        let reason = clean(reason, MAX_REQUEST_REASON_BYTES);
        if reason.is_empty() {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let cwd = cwd.trim();
        let cwd = if cwd.is_empty() {
            String::new()
        } else {
            let cwd = checked_text(cwd, MAX_PROJECT_DIR_BYTES)?;
            if !cwd.starts_with('/') {
                return Err(err(VaultErrorKind::InvalidInput));
            }
            cwd.to_owned()
        };
        let at = to_sql_time(now_unix())?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        require_active_agent(&tx, agent)?;
        let sees_all: i64 = tx
            .query_row("SELECT see_all FROM agent WHERE id = ?1", [agent], |row| {
                row.get(0)
            })
            .map_err(|_| err(VaultErrorKind::Storage))?;
        require_item(&tx, item)?;
        let archived: Option<i64> = tx
            .query_row(
                "SELECT item_id FROM item_archive WHERE item_id = ?1",
                [item],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        if sees_all != 1 || archived.is_some() {
            return Err(err(VaultErrorKind::NotFound));
        }
        let bound: Option<i64> = tx
            .query_row(
                "SELECT item_id FROM env_binding WHERE item_id = ?1",
                [item],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        if bound.is_none() {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let granted: Option<i64> = tx
            .query_row(
                "SELECT item_id FROM exec_grant WHERE agent_id = ?1 AND item_id = ?2",
                (agent, item),
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        if granted.is_some() {
            return Err(err(VaultErrorKind::AlreadyExists));
        }
        let open: Option<i64> = tx
            .query_row(
                "SELECT id FROM access_request
                 WHERE agent_id = ?1 AND item_id = ?2 AND state = 'open'",
                (agent, item),
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        if let Some(id) = open {
            return Ok((to_public_id(id)?, false));
        }
        let open_count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM access_request WHERE agent_id = ?1 AND state = 'open'",
                [agent],
                |row| row.get(0),
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        if usize::try_from(open_count).unwrap_or(usize::MAX) >= MAX_OPEN_REQUESTS {
            return Err(err(VaultErrorKind::Busy));
        }
        tx.execute(
            "INSERT INTO access_request (agent_id, item_id, reason, cwd, created_at, state)
             VALUES (?1, ?2, ?3, ?4, ?5, 'open')",
            (agent, item, reason.as_str(), cwd.as_str(), at),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        let id = to_public_id(tx.last_insert_rowid())?;
        let detail = history::agent_name(&tx, agent)?;
        history::record(&tx, item, ItemEventKind::AccessRequested, &detail)?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
        Ok((id, true))
    }

    /// Access requests, newest first. `open_only` leaves out decided ones.
    pub fn access_requests(
        &self,
        open_only: bool,
        limit: usize,
    ) -> VaultResult<Vec<AccessRequest>> {
        self.query_requests(None, open_only, limit)
    }

    /// The requests of one agent, newest first.
    pub fn agent_access_requests(
        &self,
        agent_id: u64,
        limit: usize,
    ) -> VaultResult<Vec<AccessRequest>> {
        self.query_requests(Some(to_sql_id(agent_id)?), false, limit)
    }

    fn query_requests(
        &self,
        agent: Option<i64>,
        open_only: bool,
        limit: usize,
    ) -> VaultResult<Vec<AccessRequest>> {
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(
                "SELECT access_request.id, access_request.agent_id, agent.name,
                     access_request.item_id, item.title, access_request.reason,
                     access_request.cwd, access_request.created_at, access_request.state
                 FROM access_request
                 JOIN agent ON agent.id = access_request.agent_id
                 JOIN item ON item.id = access_request.item_id
                 WHERE (?1 IS NULL OR access_request.agent_id = ?1)
                     AND (?2 = 0 OR access_request.state = 'open')
                 ORDER BY access_request.id DESC
                 LIMIT ?3",
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let limit = i64::try_from(limit).map_err(|_| err(VaultErrorKind::InvalidInput))?;
        let rows = stmt
            .query_map((agent, i64::from(open_only), limit), |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                ))
            })
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let mut requests = Vec::new();
        for row in rows {
            let (id, agent_id, agent_name, item_id, item_name, reason, cwd, at, state) =
                row.map_err(|_| err(VaultErrorKind::Storage))?;
            requests.push(AccessRequest {
                id: to_public_id(id)?,
                agent_id: to_public_id(agent_id)?,
                agent_name,
                item_id: to_public_id(item_id)?,
                item_name,
                reason,
                cwd,
                created_at: from_sql_time(at)?,
                state: RequestState::parse(&state)?,
            });
        }
        Ok(requests)
    }

    /// Deny an open request. It only takes nothing away, so it needs no owner check.
    pub fn deny_access_request(&mut self, request_id: u64) -> VaultResult<()> {
        let id = to_sql_id(request_id)?;
        let at = to_sql_time(now_unix())?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let found: Option<(i64, i64)> = tx
            .query_row(
                "SELECT agent_id, item_id FROM access_request WHERE id = ?1 AND state = 'open'",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let Some((agent, item)) = found else {
            return Err(err(VaultErrorKind::NotFound));
        };
        tx.execute(
            "UPDATE access_request SET state = 'denied', decided_at = ?1 WHERE id = ?2",
            (at, id),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        let detail = history::agent_name(&tx, agent)?;
        history::record(&tx, item, ItemEventKind::AccessDenied, &detail)?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// The agent and the item of an open request.
    pub fn open_request_target(&self, request_id: u64) -> VaultResult<(u64, u64)> {
        let id = to_sql_id(request_id)?;
        let found: Option<(i64, i64)> = self
            .conn_ref()?
            .query_row(
                "SELECT agent_id, item_id FROM access_request WHERE id = ?1 AND state = 'open'",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let (agent, item) = found.ok_or_else(|| err(VaultErrorKind::NotFound))?;
        Ok((to_public_id(agent)?, to_public_id(item)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_detail_labels_decode() {
        assert_eq!(
            custom_detail_label("x_526567696f6e").as_deref(),
            Some("Region")
        );
        assert_eq!(custom_detail_label("username"), None);
        assert_eq!(custom_detail_label("x_5"), None);
        assert_eq!(custom_detail_label("x_zz"), None);
    }

    #[test]
    fn setup_keys_by_label_or_link() {
        const OTP: &str = "x_4f5450"; // "OTP"
        const CODE: &str = "x_4f6e652d74696d6520636f6465"; // "One-time code"
        const REGION: &str = "x_526567696f6e"; // "Region"
        assert!(is_setup_key_field(OTP, "GEZDGNBVGY3TQOJQ"));
        assert!(is_setup_key_field(CODE, "GEZDGNBVGY3TQOJQ"));
        assert!(is_setup_key_field(REGION, " OTPAUTH://TOTP/x?secret=ABC"));
        assert!(is_setup_key_field("website", "otpauth://totp?secret=ABC"));
        assert!(!is_setup_key_field(REGION, "eu-west"));
        assert!(!is_setup_key_field(
            REGION,
            "https://example.test/otpauth-guide"
        ));
        assert!(!is_setup_key_field(REGION, "otpauth://hotp/x?secret=ABC"));
        // Only a custom detail has a label. A field named "otp" is an ordinary field.
        assert!(!is_setup_key_field("otp", "GEZDGNBVGY3TQOJQ"));
    }

    #[test]
    fn reasons_lose_control_characters_and_long_tails() {
        assert_eq!(clean("  a\nb\tc  ", 10), "a b c");
        assert_eq!(clean("ąąą", 3), "ą");
    }
}
