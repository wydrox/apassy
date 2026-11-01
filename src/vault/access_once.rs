//! Local-only lifecycle and durable receipts. Permit authority is deliberately memory-only.
use std::collections::BTreeMap;
use std::time::Duration;

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use super::types::err;
use super::{Vault, VaultErrorKind, VaultResult, to_sql_id};
use crate::questions::access_request::{self as wire, Card, Choice, Receipt, VerifiedCard};

pub(super) const COLUMNS: [&str; 3] = [
    "SELECT id, epoch, card, digest, cancelled, receipt, envelope FROM access_request_v1 LIMIT 0",
    "SELECT id, agent_id, at FROM access_request_creation LIMIT 0",
    "SELECT id, high_water FROM access_request_clock LIMIT 0",
];
pub(super) fn add_schema(tx: &rusqlite::Transaction<'_>) -> VaultResult<()> {
    tx.execute_batch(
        "ALTER TABLE access_request RENAME TO access_request_old;
         DROP INDEX access_request_state;
         CREATE TABLE access_request (
             id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER NOT NULL,
             item_id INTEGER NOT NULL, reason TEXT NOT NULL, cwd TEXT NOT NULL,
             created_at INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN
             ('open','granted','denied','allowed_once','expired','invalidated')), decided_at INTEGER);
         INSERT INTO access_request SELECT * FROM access_request_old;
         DROP TABLE access_request_old;
         CREATE INDEX access_request_state ON access_request(state,id);
         CREATE TABLE access_request_v1 (
             id INTEGER PRIMARY KEY, epoch BLOB NOT NULL, card BLOB NOT NULL,
             digest TEXT NOT NULL, cancelled INTEGER NOT NULL DEFAULT 0,
             receipt BLOB, envelope BLOB);
         CREATE TABLE access_request_creation (
             id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER NOT NULL, at INTEGER NOT NULL);
         CREATE INDEX access_creation_agent ON access_request_creation(agent_id,at);
         CREATE TABLE access_request_clock (id INTEGER PRIMARY KEY CHECK(id=1), high_water INTEGER NOT NULL);
         UPDATE vault_meta SET schema_version=22 WHERE id=1; PRAGMA user_version=22;",
    ).map_err(|_| err(VaultErrorKind::Storage))
}

#[derive(Debug, Default)]
pub(crate) struct Runtime {
    /// None after restart/lock: never reconstructed from a receipt.
    permits: BTreeMap<u64, Permit>,
    deadlines: BTreeMap<u64, Duration>,
}
#[derive(Debug)]
struct Permit {
    consumed: bool,
    cancelled: bool,
    operation: [u8; 32],
}

pub(crate) fn monotonic() -> Duration {
    rustix::time::clock_gettime(rustix::time::ClockId::Monotonic)
        .try_into()
        .unwrap_or(Duration::MAX)
}
pub fn now() -> u64 {
    super::agents::now_unix()
}
fn storage<E>(_: E) -> super::VaultError {
    err(VaultErrorKind::Storage)
}

#[derive(Debug, Clone)]
pub struct AccessRecord {
    pub id: u64,
    pub epoch: [u8; 32],
    pub card: VerifiedCard,
    pub state: String,
    pub cancelled: bool,
    pub receipt: Option<Receipt>,
    pub envelope: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessStatus {
    pub request_id: u64,
    pub state: String,
    pub expires_at: u64,
    pub permit: String,
}

impl Vault {
    /// Versioned, typed field encoding over an explicit list of authorization columns.
    /// See the contract's policy serializer appendix. Tokens enter only the local hash.
    pub fn access_policy_digest(
        &self,
        agent: u64,
        item: u64,
        cwd: &str,
        project: &str,
    ) -> VaultResult<String> {
        let conn = self.conn_ref()?;
        let mut out = b"apassy-access-policy-v1\0".to_vec();
        let field = |out: &mut Vec<u8>, bytes: &[u8]| -> VaultResult<()> {
            out.extend(u32::try_from(bytes.len()).map_err(storage)?.to_be_bytes());
            out.extend(bytes);
            Ok(())
        };
        for bytes in [self.epoch.as_slice(), cwd.as_bytes(), project.as_bytes()] {
            field(&mut out, bytes)?;
        }
        // Fixed order, column order and SQL storage types; no SELECT *, Debug or secret fields.
        for (sql, args) in [
            ("SELECT vault_id FROM sync_meta WHERE id=1", vec![]),
            (
                "SELECT token,token_issued_at,revoked_at,see_all FROM agent WHERE id=?1",
                vec![agent],
            ),
            (
                "SELECT token_lifetime_days FROM vault_meta WHERE id=1",
                vec![],
            ),
            ("SELECT uuid,revision FROM item WHERE id=?1", vec![item]),
            (
                "SELECT env_name,field,placeholder_hosts FROM env_binding WHERE item_id=?1",
                vec![item],
            ),
            (
                "SELECT project,environment,risk,scope,reversibility,provider FROM declaration WHERE item_id=?1",
                vec![item],
            ),
            (
                "SELECT environment,risk,scope,reversibility FROM declaration_source WHERE item_id=?1",
                vec![item],
            ),
            (
                "SELECT always_ask FROM item_policy WHERE item_id=?1",
                vec![item],
            ),
            (
                "SELECT value FROM item_field WHERE item_id=?1 AND name='host' AND secret=0",
                vec![item],
            ),
            (
                "SELECT item_id FROM item_archive WHERE item_id=?1",
                vec![item],
            ),
            (
                "SELECT item_id FROM restore_review WHERE item_id=?1",
                vec![item],
            ),
            (
                "SELECT item_id,kind FROM agent_exception WHERE agent_id=?1 ORDER BY item_id,kind",
                vec![agent],
            ),
            (
                "SELECT item_id,project_dir,mode,any_folder FROM exec_grant WHERE agent_id=?1 ORDER BY item_id",
                vec![agent],
            ),
            (
                "SELECT item_id,operation FROM grant_rule WHERE agent_id=?1 ORDER BY item_id,operation",
                vec![agent],
            ),
            (
                "SELECT uuid,kind,relay_devices,sign_key,answer_key,deleted_at FROM trusted_device ORDER BY uuid",
                vec![],
            ),
            (
                "SELECT team_id,relay_url,device_id,public_key,purposes FROM relay_membership ORDER BY team_id",
                vec![],
            ),
            (
                "SELECT value FROM vault_secret WHERE name='question-key-v1'",
                vec![],
            ),
        ] {
            field(&mut out, sql.as_bytes())?;
            let args: Vec<i64> = args
                .into_iter()
                .map(to_sql_id)
                .collect::<VaultResult<_>>()?;
            let mut stmt = conn.prepare(sql).map_err(storage)?;
            let count = stmt.column_count();
            let mut rows = stmt
                .query(rusqlite::params_from_iter(args))
                .map_err(storage)?;
            while let Some(row) = rows.next().map_err(storage)? {
                out.push(1);
                for i in 0..count {
                    use rusqlite::types::ValueRef;
                    match row.get_ref(i).map_err(storage)? {
                        ValueRef::Null => out.push(0),
                        ValueRef::Integer(n) => {
                            out.push(1);
                            out.extend(n.to_be_bytes());
                        }
                        ValueRef::Text(b) => {
                            out.push(2);
                            field(&mut out, b)?;
                        }
                        ValueRef::Blob(b) => {
                            out.push(3);
                            field(&mut out, b)?;
                        }
                        ValueRef::Real(_) => return Err(err(VaultErrorKind::Storage)),
                    }
                }
            }
            out.push(0);
        }
        Ok(crate::sync::sha256_hex(&out))
    }

    pub fn scoped_access_requests(&self) -> VaultResult<Vec<AccessRecord>> {
        self.query_scoped_access(None)
    }
    fn query_scoped_access(&self, id: Option<u64>) -> VaultResult<Vec<AccessRecord>> {
        let mut stmt = self.conn_ref()?.prepare(
            "SELECT v.id,v.epoch,v.card,v.digest,r.state,v.cancelled,v.receipt,v.envelope
             FROM access_request_v1 v JOIN access_request r ON r.id=v.id WHERE (?1 IS NULL OR v.id=?1) ORDER BY v.id DESC LIMIT 100"
        ).map_err(storage)?;
        let rows = stmt
            .query_map([id.map(to_sql_id).transpose()?], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, bool>(5)?,
                    r.get::<_, Option<Vec<u8>>>(6)?,
                    r.get::<_, Option<Vec<u8>>>(7)?,
                ))
            })
            .map_err(storage)?;
        rows.map(|r| {
            let (id, epoch, body, digest, state, cancelled, receipt, envelope) =
                r.map_err(storage)?;
            let id = u64::try_from(id).map_err(storage)?;
            let card: Card = serde_json::from_slice(&body).map_err(storage)?;
            card.validate().map_err(storage)?;
            Ok(AccessRecord {
                id,
                epoch: epoch.try_into().map_err(storage)?,
                card: VerifiedCard { card, body, digest },
                state,
                cancelled,
                receipt: receipt
                    .map(|b| serde_json::from_slice(&b).map_err(storage))
                    .transpose()?,
                envelope,
            })
        })
        .collect()
    }
    pub fn scoped_access_request(&self, id: u64) -> VaultResult<AccessRecord> {
        // Bounded inventory is enough for the live set; terminal lookup uses its exact id.
        self.query_scoped_access(Some(id))?
            .into_iter()
            .next()
            .ok_or_else(|| err(VaultErrorKind::NotFound))
    }

    /// Called under the shared vault mutex, including budget reservation. The supplied
    /// card is constructed from broker/vault facts, with request_id filled transactionally.
    pub fn create_scoped_access_request(&mut self, mut card: Card) -> VaultResult<(u64, bool)> {
        let agent: u64 = card.agent.id.parse().map_err(storage)?;
        let item: u64 = card.item.local_id.parse().map_err(storage)?;
        if !self.agent_view(agent)?.visible(item) || self.is_archived(item)? {
            return Err(err(VaultErrorKind::NotFound));
        }
        self.expire_scoped_access_requests()?;
        for old in self.scoped_access_requests()? {
            let c = &old.card.card;
            if c.agent.id == card.agent.id
                && (old.state == "open" || self.access_status(agent, old.id)?.permit == "available")
            {
                if c.item == card.item
                    && c.policy_digest == card.policy_digest
                    && c.cwd == card.cwd
                    && c.project == card.project
                    && c.action == card.action
                    && c.hosts == card.hosts
                {
                    return Ok((old.id, false));
                }
                return Err(err(VaultErrorKind::Busy));
            }
        }
        let epoch = self.epoch;
        let at = card.created_at;
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let high: i64 = tx
            .query_row(
                "SELECT high_water FROM access_request_clock WHERE id=1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage)?
            .unwrap_or(0);
        if i64::try_from(at).map_err(storage)? < high {
            return Err(err(VaultErrorKind::Expired));
        }
        let (count,last): (i64,i64) = tx.query_row(
            "SELECT COUNT(*),COALESCE(MAX(at),0) FROM access_request_creation WHERE agent_id=?1 AND at>?2",
            params![to_sql_id(agent)?,super::agents::to_sql_time(at.saturating_sub(3600))?],|r|Ok((r.get(0)?,r.get(1)?))).map_err(storage)?;
        let total: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM access_request_creation WHERE at>?1",
                [super::agents::to_sql_time(at.saturating_sub(3600))?],
                |r| r.get(0),
            )
            .map_err(storage)?;
        let open: i64 = tx.query_row("SELECT COUNT(*) FROM access_request_v1 v JOIN access_request r ON v.id=r.id WHERE r.state='open'",
            [],|r|r.get(0)).map_err(storage)?;
        if count >= 5
            || total >= 20
            || open >= 10
            || (last != 0 && at.saturating_sub(u64::try_from(last).map_err(storage)?) < 30)
        {
            return Err(err(VaultErrorKind::Busy));
        }
        tx.execute("INSERT INTO access_request(agent_id,item_id,reason,cwd,created_at,state) VALUES(?1,?2,?3,?4,?5,'open')",
            params![to_sql_id(agent)?,to_sql_id(item)?,card.reason,card.cwd,super::agents::to_sql_time(at)?]).map_err(storage)?;
        let id = u64::try_from(tx.last_insert_rowid()).map_err(storage)?;
        card.request_id = id.to_string();
        card.validate()
            .map_err(|_| err(VaultErrorKind::InvalidInput))?;
        let body = serde_json::to_vec(&card).map_err(storage)?;
        if body.len() > 20000 {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let digest = wire::hex(&wire::body_digest("card", &body).map_err(storage)?);
        tx.execute(
            "INSERT INTO access_request_v1(id,epoch,card,digest) VALUES(?1,?2,?3,?4)",
            params![to_sql_id(id)?, epoch.as_slice(), body, digest],
        )
        .map_err(storage)?;
        tx.execute(
            "INSERT INTO access_request_creation(agent_id,at) VALUES(?1,?2)",
            params![to_sql_id(agent)?, super::agents::to_sql_time(at)?],
        )
        .map_err(storage)?;
        tx.execute("INSERT INTO access_request_clock(id,high_water) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET high_water=excluded.high_water",
            [super::agents::to_sql_time(at)?]).map_err(storage)?;
        tx.commit().map_err(storage)?;
        self.access_once
            .deadlines
            .insert(id, monotonic().saturating_add(Duration::from_secs(300)));
        Ok((id, true))
    }

    pub fn access_record_live(&self, record: &AccessRecord) -> bool {
        let c = &record.card.card;
        !self.is_locked()
            && record.epoch == self.epoch
            && !record.cancelled
            && now() < c.expires_at
            && now() >= c.created_at
            && self
                .access_once
                .deadlines
                .get(&record.id)
                .is_some_and(|d| monotonic() < *d)
            && self
                .access_once
                .deadlines
                .get(&record.id)
                .is_some_and(|deadline| {
                    let elapsed = monotonic()
                        .saturating_sub(deadline.saturating_sub(Duration::from_secs(300)))
                        .as_secs();
                    now().abs_diff(c.created_at.saturating_add(elapsed)) <= 2
                })
            && self
                .access_policy_digest(
                    c.agent.id.parse().unwrap_or(0),
                    c.item.local_id.parse().unwrap_or(0),
                    &c.cwd,
                    c.project.as_ref().map_or("", |p| p.key.as_str()),
                )
                .is_ok_and(|d| d == c.policy_digest)
    }

    pub fn access_status(&self, agent: u64, id: u64) -> VaultResult<AccessStatus> {
        let r = self.scoped_access_request(id)?;
        if r.card.card.agent.id != agent.to_string() {
            return Err(err(VaultErrorKind::NotFound));
        }
        let live = self.access_record_live(&r);
        let state = if r.state == "open" && !live {
            if now() >= r.card.card.expires_at {
                "expired"
            } else {
                "invalidated"
            }
        } else {
            &r.state
        };
        let permit = match self.access_once.permits.get(&id) {
            Some(p) if p.consumed => "consumed",
            Some(p) if live && !p.cancelled => "available",
            _ => "unavailable",
        };
        Ok(AccessStatus {
            request_id: id,
            state: state.into(),
            expires_at: r.card.card.expires_at,
            permit: permit.into(),
        })
    }
    pub fn cancel_scoped_access_request(&mut self, agent: u64, id: u64) -> VaultResult<()> {
        let r = self.scoped_access_request(id)?;
        if r.card.card.agent.id != agent.to_string() {
            return Err(err(VaultErrorKind::NotFound));
        }
        self.conn_mut()?
            .execute(
                "UPDATE access_request_v1 SET cancelled=1 WHERE id=?1",
                [to_sql_id(id)?],
            )
            .map_err(storage)?;
        if let Some(p) = self.access_once.permits.get_mut(&id) {
            p.cancelled = true;
        }
        self.conn_mut()?.execute("UPDATE access_request SET state='invalidated',decided_at=?2 WHERE id=?1 AND state='open'",
            params![to_sql_id(id)?,super::agents::to_sql_time(now())?]).map_err(storage)?;
        Ok(())
    }
    pub fn expire_scoped_access_requests(&mut self) -> VaultResult<()> {
        for r in self.scoped_access_requests()? {
            if r.state == "open" && !self.access_record_live(&r) {
                let state = if now() >= r.card.card.expires_at {
                    "expired"
                } else {
                    "invalidated"
                };
                self.conn_mut()?.execute("UPDATE access_request SET state=?2,decided_at=?3 WHERE id=?1 AND state='open'",
                    params![to_sql_id(r.id)?,state,super::agents::to_sql_time(now())?]).map_err(storage)?;
            }
        }
        Ok(())
    }

    /// A fresh typed owner proof or a verified signed denial must have been checked by
    /// the caller under this same vault lock. CAS and receipt precede permit installation.
    pub(crate) fn commit_access_answer(
        &mut self,
        id: u64,
        choice: Choice,
        receipt: Receipt,
    ) -> VaultResult<()> {
        let r = self.scoped_access_request(id)?;
        if r.state != "open" {
            return Err(err(VaultErrorKind::Conflict));
        }
        if !self.access_record_live(&r) || !r.card.card.valid_answers.contains(&choice) {
            return Err(err(VaultErrorKind::Expired));
        }
        let state = if choice == Choice::Deny {
            "denied"
        } else {
            "allowed_once"
        };
        let operation = super::fresh_epoch()?;
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if tx
            .execute(
                "UPDATE access_request SET state=?2,decided_at=?3 WHERE id=?1 AND state='open'",
                params![to_sql_id(id)?, state, super::agents::to_sql_time(now())?],
            )
            .map_err(storage)?
            != 1
        {
            return Err(err(VaultErrorKind::Conflict));
        }
        tx.execute(
            "UPDATE access_request_v1 SET receipt=?2 WHERE id=?1",
            params![
                to_sql_id(id)?,
                serde_json::to_vec(&receipt).map_err(storage)?
            ],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        if choice == Choice::AllowOnce {
            self.access_once.permits.insert(
                id,
                Permit {
                    consumed: false,
                    cancelled: false,
                    operation,
                },
            );
        }
        Ok(())
    }

    pub(crate) fn consume_access_once(
        &mut self,
        id: u64,
        agent: u64,
        item: u64,
        cwd: &str,
        project: &str,
        action: wire::Action,
        hosts: &[String],
    ) -> VaultResult<[u8; 32]> {
        let r = self.scoped_access_request(id)?;
        let c = &r.card.card;
        if r.state != "allowed_once"
            || !self.access_record_live(&r)
            || c.agent.id != agent.to_string()
            || c.item.local_id != item.to_string()
            || c.cwd != cwd
            || c.project.as_ref().map(|p| p.key.as_str()) != Some(project)
            || c.action != Some(action)
            || c.hosts != hosts
        {
            return Err(err(VaultErrorKind::NotFound));
        }
        let p = self
            .access_once
            .permits
            .get_mut(&id)
            .ok_or_else(|| err(VaultErrorKind::NotFound))?;
        if p.consumed || p.cancelled {
            return Err(err(VaultErrorKind::NotFound));
        }
        p.consumed = true;
        Ok(p.operation)
    }
    pub(crate) fn access_admission_live(&self, id: u64, operation: &[u8; 32]) -> bool {
        self.access_once
            .permits
            .get(&id)
            .is_some_and(|p| p.consumed && !p.cancelled && &p.operation == operation)
            && self
                .scoped_access_request(id)
                .is_ok_and(|r| self.access_record_live(&r))
    }
    pub fn keep_access_envelope(&mut self, id: u64, envelope: &[u8]) -> VaultResult<()> {
        self.conn_mut()?
            .execute(
                "UPDATE access_request_v1 SET envelope=?2 WHERE id=?1 AND envelope IS NULL",
                params![to_sql_id(id)?, envelope],
            )
            .map_err(storage)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::access_once;
    use crate::broker::approvals::{OwnerAction, OwnerProof};
    use crate::contracts::CredentialKind;
    use crate::vault::{Field, ItemDraft, SecretValue};
    fn fixture() -> (tempfile::TempDir, Vault, u64, u64, u64) {
        let dir = tempfile::tempdir().unwrap();
        let mut v =
            Vault::create(&dir.path().join("synthetic.db"), "synthetic-access-test").unwrap();
        v.unlock("synthetic-access-test").unwrap();
        let item = v
            .add(ItemDraft {
                title: "Synthetic API".into(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: vec![],
                fields: vec![Field {
                    name: "token".into(),
                    value: SecretValue::new("SYNTHETIC-NOT-A-LIVE-KEY-0033".into()),
                    secret: true,
                }],
            })
            .unwrap()
            .id;
        v.set_env_binding(item, "API_TOKEN", "token").unwrap();
        let (a, _) = v.register_agent("Synthetic agent").unwrap();
        v.set_agent_sees_all(a.id, true).unwrap();
        let response = access_once::create(
            &mut v,
            &a,
            item,
            "Read synthetic state.",
            dir.path().to_str(),
            &wire::Scope {
                action: wire::Action::Read,
                hosts: vec!["api.example.test".into()],
            },
        );
        assert!(response.ok, "{response:?}");
        let id = response.result.unwrap()["request_id"].as_u64().unwrap();
        (dir, v, a.id, item, id)
    }
    fn allow(v: &mut Vault, id: u64) {
        let r = v.scoped_access_request(id).unwrap();
        let proof = OwnerProof::issue_for_test(
            OwnerAction::AllowAccessOnce {
                request_id: id,
                digest: r.card.digest.clone(),
            },
            v.epoch(),
            std::time::Instant::now(),
        );
        access_once::local_answer(v, id, Choice::AllowOnce, Some(proof)).unwrap();
    }
    fn consume(v: &mut Vault, id: u64, agent: u64, item: u64) -> VaultResult<[u8; 32]> {
        let c = v.scoped_access_request(id)?.card.card;
        v.consume_access_once(
            id,
            agent,
            item,
            &c.cwd,
            &c.project.unwrap().key,
            wire::Action::Read,
            &c.hosts,
        )
    }
    #[test]
    fn first_answer_and_one_consumer_win_without_durable_authority() {
        let (_d, mut v, agent, item, id) = fixture();
        assert!(access_once::local_answer(&mut v, id, Choice::AllowOnce, None).is_err());
        allow(&mut v, id);
        assert!(v.deny_access_request(id).is_err());
        assert!(
            v.set_exec_grants_for_request(
                agent,
                &[item],
                &super::super::GrantPlace::AnyFolder,
                super::super::ExecMode::Bouncer,
                Some(id)
            )
            .is_err()
        );
        let operation = consume(&mut v, id, agent, item).unwrap();
        assert!(v.access_admission_live(id, &operation));
        assert!(consume(&mut v, id, agent, item).is_err());
        for table in [
            "exec_grant",
            "owner_answer",
            "remembered_pattern",
            "bouncer_scope",
            "agent_exception",
        ] {
            let n: i64 = v
                .conn_ref()
                .unwrap()
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 0, "{table}");
        }
        v.cancel_scoped_access_request(agent, id).unwrap();
        assert!(!v.access_admission_live(id, &operation));
        assert_eq!(v.access_status(agent, id).unwrap().state, "allowed_once");
    }
    #[test]
    fn denial_cancellation_and_other_agents_cannot_create_or_authorize() {
        let (_d, mut v, agent, item, id) = fixture();
        assert!(v.access_status(agent + 1, id).is_err());
        assert!(v.cancel_scoped_access_request(agent + 1, id).is_err());
        access_once::local_answer(&mut v, id, Choice::Deny, None).unwrap();
        assert_eq!(v.access_status(agent, id).unwrap().state, "denied");
        assert!(consume(&mut v, id, agent, item).is_err());
        v.cancel_scoped_access_request(agent, id).unwrap();
        assert_eq!(v.access_status(agent, id).unwrap().state, "denied");
        assert!(v.access_status(agent, id + 1).is_err());
        assert!(v.cancel_scoped_access_request(agent, id + 1).is_err());
        assert_eq!(v.scoped_access_requests().unwrap().len(), 1);
    }
    #[test]
    fn scope_mutations_and_key_or_policy_rotation_fence_admission() {
        let (_d, mut v, agent, item, id) = fixture();
        allow(&mut v, id);
        let c = v.scoped_access_request(id).unwrap().card.card;
        for (a, i, cwd, project, action, hosts) in [
            (
                agent + 1,
                item,
                c.cwd.clone(),
                c.project.as_ref().unwrap().key.clone(),
                wire::Action::Read,
                c.hosts.clone(),
            ),
            (
                agent,
                item + 1,
                c.cwd.clone(),
                c.project.as_ref().unwrap().key.clone(),
                wire::Action::Read,
                c.hosts.clone(),
            ),
            (
                agent,
                item,
                format!("{}/other", c.cwd),
                c.project.as_ref().unwrap().key.clone(),
                wire::Action::Read,
                c.hosts.clone(),
            ),
            (
                agent,
                item,
                c.cwd.clone(),
                "other".into(),
                wire::Action::Read,
                c.hosts.clone(),
            ),
            (
                agent,
                item,
                c.cwd.clone(),
                c.project.as_ref().unwrap().key.clone(),
                wire::Action::Delete,
                c.hosts.clone(),
            ),
            (
                agent,
                item,
                c.cwd.clone(),
                c.project.as_ref().unwrap().key.clone(),
                wire::Action::Read,
                vec!["evil.api.example.test".into()],
            ),
            (
                agent,
                item,
                c.cwd.clone(),
                c.project.as_ref().unwrap().key.clone(),
                wire::Action::Read,
                vec!["api.example.test:8443".into()],
            ),
        ] {
            assert!(
                v.consume_access_once(id, a, i, &cwd, &project, action, &hosts)
                    .is_err()
            );
            assert_eq!(v.access_status(agent, id).unwrap().permit, "available");
        }
        let op = consume(&mut v, id, agent, item).unwrap();
        v.rotate_agent_token(agent).unwrap();
        assert!(!v.access_admission_live(id, &op));
    }
    #[test]
    fn restart_loses_permits_but_keeps_receipts_and_creation_budget() {
        let (dir, mut v, agent, item, id) = fixture();
        allow(&mut v, id);
        let receipt = v.scoped_access_request(id).unwrap().receipt;
        let path = v.path().to_path_buf();
        v.lock().unwrap();
        drop(v);
        let mut v = Vault::open(&path).unwrap();
        v.unlock("synthetic-access-test").unwrap();
        assert_eq!(v.scoped_access_request(id).unwrap().receipt, receipt);
        assert_eq!(v.access_status(agent, id).unwrap().permit, "unavailable");
        assert!(consume(&mut v, id, agent, item).is_err());
        let n: i64 = v
            .conn_ref()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM access_request_creation", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(n, 1);
        assert!(dir.path().exists());
    }
    #[test]
    fn coalescing_and_cancel_do_not_refund_cooldown() {
        let (dir, mut v, agent, item, id) = fixture();
        let a = v
            .list_agents()
            .unwrap()
            .into_iter()
            .find(|a| a.id == agent)
            .unwrap();
        let scope = wire::Scope {
            action: wire::Action::Read,
            hosts: vec!["api.example.test".into()],
        };
        let duplicate = access_once::create(
            &mut v,
            &a,
            item,
            "A changed reason",
            dir.path().to_str(),
            &scope,
        );
        assert!(duplicate.ok);
        assert_eq!(duplicate.result.unwrap()["request_id"], id);
        assert_eq!(
            v.scoped_access_request(id).unwrap().card.card.reason,
            "Read synthetic state."
        );
        v.cancel_scoped_access_request(agent, id).unwrap();
        assert!(!access_once::create(&mut v, &a, item, "Again", dir.path().to_str(), &scope).ok);
    }
    #[test]
    fn exact_ports_and_unknown_destination_forms_fail_closed() {
        let args = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            access_once::exact_run_hosts(&args("curl https://api.example.test:8443/status")),
            Some(vec!["api.example.test:8443".into()])
        );
        assert!(access_once::exact_run_hosts(&args("curl --connect-to api.example.test:443:evil.example.test:443 https://api.example.test")).is_none());
        assert!(
            access_once::exact_run_hosts(&args("psql --host api.example.test --port 5433"))
                .is_none()
        );
    }
}
