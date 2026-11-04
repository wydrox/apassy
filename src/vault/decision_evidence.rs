//! Local retained metadata only. An allowed use records a decision, not successful execution.
use rusqlite::OptionalExtension;

use super::agents::{Declaration, from_sql_time};
use super::history::{EditChange, MAX_ITEM_EVENTS};
use super::policy::{DeclarationSource, DeclarationSources};
use super::types::{VaultError, VaultErrorKind, VaultResult, err};
use super::usage::MAX_ITEM_USE_ROWS;
use super::{Vault, to_sql_id};
use crate::broker::action_kind::ActionKind;
use crate::contracts::CredentialKind;

pub const EVIDENCE_WINDOW_SECS: u64 = 30 * 24 * 3600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceQuery<'a> {
    pub item_id: u64,
    pub agent_id: Option<u64>,
    /// Empty means no use is in the same scope.
    pub project_key: &'a str,
    pub action: ActionKind,
    /// Already normalized by the caller.
    pub hosts: &'a [String],
    pub now: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventAge {
    None,
    At(u64),
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseCount {
    Known(u32),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemDecisionEvidence {
    pub kind: CredentialKind,
    pub provider: Option<String>,
    pub declaration: Option<Declaration>,
    /// Missing row is ambiguous: never fabricate Owner provenance.
    pub declaration_sources: Option<DeclarationSources>,
    pub agent_created_here: bool,
    pub agent_allowed_before: bool,
    pub owner_allowed_same_scope: UseCount,
    pub owner_denied_same_scope: UseCount,
    pub owner_denied_other_scope: UseCount,
    pub last_secret_change: EventAge,
    pub last_access_change: EventAge,
}

fn storage<E>(_: E) -> VaultError {
    err(VaultErrorKind::Storage)
}
fn increment(count: &mut UseCount) {
    *count = match *count {
        UseCount::Known(n) => n.checked_add(1).map_or(UseCount::Unknown, UseCount::Known),
        UseCount::Unknown => UseCount::Unknown,
    };
}

impl Vault {
    /// One consistent, read-only snapshot. Does not read item fields or reveal values.
    pub fn decision_evidence(
        &self,
        query: &EvidenceQuery<'_>,
    ) -> VaultResult<ItemDecisionEvidence> {
        let item = to_sql_id(query.item_id)?;
        let agent = query.agent_id.map(to_sql_id).transpose()?;
        let tx = self.conn_ref()?.unchecked_transaction().map_err(storage)?;
        let kind: String = tx
            .query_row("SELECT kind FROM item WHERE id = ?1", [item], |r| r.get(0))
            .optional()
            .map_err(storage)?
            .ok_or_else(|| err(VaultErrorKind::NotFound))?;
        // declaration() selects only the stored declaration on this same connection/transaction.
        let declaration = self.declaration(query.item_id)?;
        let provider: Option<String> = tx
            .query_row(
                "SELECT provider FROM declaration WHERE item_id = ?1",
                [item],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(storage)?
            .filter(|p: &String| !p.is_empty());
        let sources: Option<[String; 4]> = tx.query_row(
            "SELECT environment, risk, scope, reversibility FROM declaration_source WHERE item_id = ?1",
            [item], |r| Ok([r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?])
        ).optional().map_err(storage)?;
        let declaration_sources = sources
            .map(|s| {
                let parse = |v: &str| {
                    DeclarationSource::parse(v).ok_or_else(|| err(VaultErrorKind::Storage))
                };
                Ok::<_, VaultError>(DeclarationSources {
                    environment: parse(&s[0])?,
                    risk: parse(&s[1])?,
                    scope: parse(&s[2])?,
                    reversibility: parse(&s[3])?,
                })
            })
            .transpose()?;
        let agent_created_here = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM item_origin WHERE item_id = ?1)",
                [item],
                |r| r.get(0),
            )
            .map_err(storage)?;
        let start = query.now.saturating_sub(EVIDENCE_WINDOW_SECS);
        let (total, oldest): (i64, Option<i64>) = tx
            .query_row("SELECT count(*), min(at) FROM item_use", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .map_err(storage)?;
        let incomplete = total >= MAX_ITEM_USE_ROWS
            && oldest
                .map(from_sql_time)
                .transpose()?
                .is_some_and(|t| t > start);
        let initial = if incomplete {
            UseCount::Unknown
        } else {
            UseCount::Known(0)
        };
        let mut result = ItemDecisionEvidence {
            kind: super::kind_from_str(&kind)?,
            provider,
            declaration,
            declaration_sources,
            agent_created_here,
            agent_allowed_before: false,
            owner_allowed_same_scope: initial,
            owner_denied_same_scope: initial,
            owner_denied_other_scope: initial,
            last_secret_change: EventAge::None,
            last_access_change: EventAge::None,
        };
        {
            let mut statement = tx.prepare(
                "SELECT at, agent_id, project_key, action_kind, hosts, outcome, decided_by FROM item_use WHERE item_id = ?1"
            ).map_err(storage)?;
            let mut rows = statement.query([item]).map_err(storage)?;
            while let Some(row) = rows.next().map_err(storage)? {
                let at = from_sql_time(row.get(0).map_err(storage)?)?;
                // Future rows cannot establish prior use or owner evidence.
                if at > query.now {
                    continue;
                }
                let row_agent: Option<i64> = row.get(1).map_err(storage)?;
                let outcome: String = row.get(5).map_err(storage)?;
                if agent.is_some() && row_agent == agent && outcome == "allowed" {
                    result.agent_allowed_before = true;
                }
                let by: String = row.get(6).map_err(storage)?;
                if at < start || by != "owner" || !matches!(outcome.as_str(), "allowed" | "denied")
                {
                    continue;
                }
                let project: String = row.get(2).map_err(storage)?;
                let action: String = row.get(3).map_err(storage)?;
                let hosts: String = row.get(4).map_err(storage)?;
                let hosts: Vec<String> = serde_json::from_str(&hosts).map_err(storage)?;
                let same = agent.is_some()
                    && agent == row_agent
                    && !query.project_key.is_empty()
                    && query.project_key == project
                    && query.action.as_str() == action
                    && query.hosts.iter().all(|host| hosts.contains(host));
                if same && outcome == "allowed" {
                    increment(&mut result.owner_allowed_same_scope);
                }
                if outcome == "denied" {
                    increment(if same {
                        &mut result.owner_denied_same_scope
                    } else {
                        &mut result.owner_denied_other_scope
                    });
                }
            }
        }
        {
            let mut statement = tx
                .prepare("SELECT at, kind, detail FROM item_event WHERE item_id = ?1")
                .map_err(storage)?;
            let mut rows = statement.query([item]).map_err(storage)?;
            let mut count = 0usize;
            let mut oldest = u64::MAX;
            let mut beginning = false;
            let mut secret = None;
            let mut access = None;
            while let Some(row) = rows.next().map_err(storage)? {
                count = count.saturating_add(1);
                let at = from_sql_time(row.get(0).map_err(storage)?)?;
                oldest = oldest.min(at);
                let kind: String = row.get(1).map_err(storage)?;
                beginning |= at <= query.now && matches!(kind.as_str(), "created" | "tracked");
                if at < start || at > query.now {
                    continue;
                }
                if kind == "edited" {
                    let detail: String = row.get(2).map_err(storage)?;
                    if EditChange::parse_detail(&detail)
                        .iter()
                        .any(|c| matches!(c, EditChange::Secret(_)))
                    {
                        secret = Some(secret.map_or(at, |t: u64| t.max(at)));
                    }
                }
                if matches!(
                    kind.as_str(),
                    "access_given"
                        | "access_removed"
                        | "access_denied"
                        | "rule_changed"
                        | "operation_allowed"
                        | "operation_removed"
                        | "restored"
                        | "review_confirmed"
                ) {
                    access = Some(access.map_or(at, |t: u64| t.max(at)));
                }
            }
            // A cap can conceal an older relevant event. Keep both ages unknown, even if a newer
            // retained change exists, as required by the v1 evidence contract.
            if count >= MAX_ITEM_EVENTS && oldest > start && !beginning {
                result.last_secret_change = EventAge::Unknown;
                result.last_access_change = EventAge::Unknown;
            } else {
                result.last_secret_change = secret.map_or(EventAge::None, EventAge::At);
                result.last_access_change = access.map_or(EventAge::None, EventAge::At);
            }
        }
        tx.commit().map_err(storage)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{DeclarationSource, Field, ItemDraft, SecretValue};
    fn fixture() -> (tempfile::TempDir, Vault, u64) {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault =
            Vault::create(&dir.path().join("evidence.db"), "synthetic-evidence-pass").unwrap();
        vault.unlock("synthetic-evidence-pass").unwrap();
        let id = vault
            .add(ItemDraft {
                title: "fixture".into(),
                kind: CredentialKind::Custom,
                notes: String::new(),
                tags: vec![],
                fields: vec![Field {
                    name: "metadata".into(),
                    value: SecretValue::new("fixture metadata".into()),
                    secret: false,
                }],
            })
            .unwrap()
            .id;
        (dir, vault, id)
    }
    fn query<'a>(id: u64) -> EvidenceQuery<'a> {
        EvidenceQuery {
            item_id: id,
            agent_id: Some(7),
            project_key: "p",
            action: ActionKind::Read,
            hosts: &[],
            now: 10_000_000,
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn use_row(
        v: &Vault,
        q: &EvidenceQuery<'_>,
        agent: Option<i64>,
        project: &str,
        action: &str,
        hosts: &str,
        outcome: &str,
        by: &str,
        at: u64,
    ) {
        v.conn_ref().unwrap().execute(
            "INSERT INTO item_use(at,item_id,agent_id,agent_name,project_key,project_label,action_kind,command_summary,hosts,outcome,decided_by)
             VALUES (?1,?2,?3,'fixture',?4,'',?5,'',?6,?7,?8)",
            rusqlite::params![at as i64, q.item_id as i64, agent, project, action, hosts, outcome, by]).unwrap();
    }
    fn event(v: &Vault, id: u64, at: u64, kind: &str, detail: &str) {
        v.conn_ref()
            .unwrap()
            .execute(
                "INSERT INTO item_event(item_id,at,kind,detail) VALUES (?1,?2,?3,?4)",
                rusqlite::params![id as i64, at as i64, kind, detail],
            )
            .unwrap();
    }
    #[test]
    fn provenance_requires_an_actual_source_row_and_origin_is_presence_only() {
        use crate::vault::{Environment, Reversibility, RiskLevel, Scope};
        let (_dir, mut v, id) = fixture();
        let q = query(id);
        let e = v.decision_evidence(&q).unwrap();
        assert_eq!(e.declaration, None);
        assert_eq!(e.declaration_sources, None);
        assert!(!e.agent_created_here);
        v.set_declaration(
            id,
            &Declaration {
                project: "p".into(),
                environment: Environment::Development,
                risk: RiskLevel::Low,
                scope: Scope::ReadOnly,
                reversibility: Reversibility::Reversible,
            },
        )
        .unwrap();
        let e = v.decision_evidence(&q).unwrap();
        assert!(e.declaration.is_some());
        assert_eq!(e.declaration_sources, None);
        let sources = DeclarationSources {
            environment: DeclarationSource::Signal,
            ..DeclarationSources::default()
        };
        v.set_declaration_sources(id, &sources).unwrap();
        v.conn_ref().unwrap().execute("INSERT INTO item_origin(item_id,agent_id,agent_name,project_key,project_label,tool,created_at) VALUES (?1,7,'fixture','p','','save',1)", [id as i64]).unwrap();
        let e = v.decision_evidence(&q).unwrap();
        assert_eq!(e.declaration_sources, Some(sources));
        assert!(e.agent_created_here);
    }
    #[test]
    fn scope_coverage_deciders_time_and_no_agent() {
        let (_dir, v, id) = fixture();
        let hosts = vec!["api.example.test".into()];
        let mut q = query(id);
        q.hosts = &hosts;
        let covered = r#"["api.example.test","extra.example.test"]"#;
        use_row(
            &v,
            &q,
            Some(7),
            "p",
            "read",
            covered,
            "allowed",
            "owner",
            q.now,
        );
        use_row(
            &v,
            &q,
            Some(7),
            "p",
            "read",
            covered,
            "denied",
            "owner",
            q.now,
        );
        for (agent, project, action, hosts) in [
            (Some(8), "p", "read", covered),
            (Some(7), "other", "read", covered),
            (Some(7), "p", "change", covered),
            (Some(7), "p", "read", "[]"),
            (None, "p", "read", covered),
        ] {
            use_row(
                &v, &q, agent, project, action, hosts, "denied", "owner", q.now,
            );
        }
        for by in ["bouncer", "pattern", "answer", "rule"] {
            use_row(&v, &q, Some(7), "p", "read", covered, "allowed", by, q.now);
            use_row(&v, &q, Some(7), "p", "read", covered, "denied", by, q.now);
        }
        for outcome in ["timed_out", "refused"] {
            use_row(
                &v,
                &q,
                Some(7),
                "p",
                "read",
                covered,
                outcome,
                "owner",
                q.now,
            );
        }
        use_row(
            &v,
            &q,
            Some(7),
            "p",
            "read",
            covered,
            "denied",
            "owner",
            q.now + 1,
        );
        use_row(
            &v,
            &q,
            Some(7),
            "p",
            "read",
            covered,
            "denied",
            "owner",
            q.now - EVIDENCE_WINDOW_SECS - 1,
        );
        let e = v.decision_evidence(&q).unwrap();
        assert_eq!(e.owner_allowed_same_scope, UseCount::Known(1));
        assert_eq!(e.owner_denied_same_scope, UseCount::Known(1));
        assert_eq!(e.owner_denied_other_scope, UseCount::Known(5));
        assert!(e.agent_allowed_before);
        q.agent_id = None;
        let e = v.decision_evidence(&q).unwrap();
        assert!(!e.agent_allowed_before);
        assert_eq!(e.owner_allowed_same_scope, UseCount::Known(0));
        q.agent_id = Some(7);
        q.project_key = "";
        assert_eq!(
            v.decision_evidence(&q).unwrap().owner_denied_same_scope,
            UseCount::Known(0)
        );
        q.now += 31 * 86400;
        let e = v.decision_evidence(&q).unwrap();
        assert_eq!(e.owner_denied_other_scope, UseCount::Known(0));
        assert!(
            e.agent_allowed_before,
            "retained use is not limited to the window"
        );
    }
    #[test]
    fn edits_caps_boundaries_and_read_only() {
        let (_dir, v, id) = fixture();
        let q = query(id);
        v.conn_ref()
            .unwrap()
            .execute("DELETE FROM item_event", [])
            .unwrap();
        event(
            &v,
            id,
            q.now - EVIDENCE_WINDOW_SECS,
            "edited",
            "secret:token",
        );
        event(&v, id, q.now, "edited", "title");
        event(&v, id, q.now - 1, "access_given", "");
        event(&v, id, q.now + 1, "edited", "secret:token");
        let snapshot = || {
            let c = v.conn_ref().unwrap();
            (
                c.query_row("SELECT count(*) FROM item_event", [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap(),
                c.query_row("SELECT count(*) FROM item_use", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                c.query_row("SELECT count(*) FROM decision_log", [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap(),
                c.query_row("SELECT revision FROM item WHERE id=?1", [id as i64], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap(),
            )
        };
        let before = snapshot();
        let e = v.decision_evidence(&q).unwrap();
        assert_eq!(
            e.last_secret_change,
            EventAge::At(q.now - EVIDENCE_WINDOW_SECS)
        );
        assert_eq!(e.last_access_change, EventAge::At(q.now - 1));
        assert_eq!(snapshot(), before);
        v.conn_ref()
            .unwrap()
            .execute("DELETE FROM item_event", [])
            .unwrap();
        for _ in 0..MAX_ITEM_EVENTS {
            event(&v, id, q.now, "edited", "title");
        }
        let e = v.decision_evidence(&q).unwrap();
        assert_eq!(e.last_secret_change, EventAge::Unknown);
        assert_eq!(e.last_access_change, EventAge::Unknown);
        v.conn_ref()
            .unwrap()
            .execute(
                "UPDATE item_event SET kind='tracked' WHERE id=(SELECT min(id) FROM item_event)",
                [],
            )
            .unwrap();
        assert_eq!(
            v.decision_evidence(&q).unwrap().last_secret_change,
            EventAge::None
        );
    }
    #[test]
    fn global_use_cap_and_overflow_are_unknown() {
        let (_dir, v, id) = fixture();
        let q = query(id);
        v.conn_ref().unwrap().execute(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < ?1)
             INSERT INTO item_use(at,item_id,agent_id,agent_name,project_key,project_label,action_kind,command_summary,hosts,outcome,decided_by)
             SELECT ?2,?3,7,'fixture','p','','read','','[]','allowed','owner' FROM n",
            rusqlite::params![MAX_ITEM_USE_ROWS, q.now as i64, id as i64]).unwrap();
        assert_eq!(
            v.decision_evidence(&q).unwrap().owner_allowed_same_scope,
            UseCount::Unknown
        );
        v.conn_ref()
            .unwrap()
            .execute(
                "UPDATE item_use SET at=?1 WHERE id=(SELECT min(id) FROM item_use)",
                [(q.now - EVIDENCE_WINDOW_SECS) as i64],
            )
            .unwrap();
        assert_eq!(
            v.decision_evidence(&q).unwrap().owner_allowed_same_scope,
            UseCount::Known(50_000)
        );
        let mut n = UseCount::Known(u32::MAX);
        increment(&mut n);
        assert_eq!(n, UseCount::Unknown);
        assert_eq!(
            v.decision_evidence(&EvidenceQuery {
                item_id: id + 999,
                ..q
            })
            .unwrap_err()
            .kind(),
            VaultErrorKind::NotFound
        );
    }
    #[test]
    fn future_rows_never_establish_prior_use_and_window_start_is_inclusive() {
        let (_dir, v, id) = fixture();
        let mut q = query(id);
        use_row(
            &v,
            &q,
            Some(7),
            "p",
            "read",
            "[]",
            "allowed",
            "pattern",
            q.now + 1,
        );
        let e = v.decision_evidence(&q).unwrap();
        assert!(!e.agent_allowed_before);
        assert_eq!(e.owner_allowed_same_scope, UseCount::Known(0));
        use_row(
            &v,
            &q,
            Some(7),
            "p",
            "read",
            "[]",
            "allowed",
            "owner",
            q.now - EVIDENCE_WINDOW_SECS,
        );
        assert_eq!(
            v.decision_evidence(&q).unwrap().owner_allowed_same_scope,
            UseCount::Known(1)
        );
        q.now = 0;
        event(&v, id, 0, "access_removed", "");
        assert_eq!(
            v.decision_evidence(&q).unwrap().last_access_change,
            EventAge::At(0)
        );
        q.now = u64::MAX;
        assert_eq!(
            v.decision_evidence(&q).unwrap().owner_allowed_same_scope,
            UseCount::Known(0)
        );
    }
}
