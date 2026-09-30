//! The `/v1` endpoints for people and agents (docs/SPEC.md, "HTTP API").
//!
//! Each function does one endpoint: it takes the checked principal and the parsed
//! request, and returns the `result` of the envelope. The relay has no readable value
//! of an item: it stores a uid and a sealed text, and no view has a field for either.

use apassy::broker::proxy::HostRule;
use apassy::vault::{Environment, Reversibility, RiskLevel, Scope, checked_env_name, providers};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::{Value, json};

use crate::api::{
    AccessItem, AccessView, AgentCreate, AgentView, CollectionCreate, CollectionView, Created,
    GrantCreate, GrantView, InviteRequest, InviteView, IssuedRef, ItemCreated, ItemView,
    JoinRequest, MeView, MemberView, NewItem, Policy, PolicyMode, PrincipalKind, Role,
};
use crate::error::{RelayError, RelayResult, codes};
use crate::hostkeys;
use crate::ids::{AgentId, CollectionId, GrantId, InviteId, ItemId, MemberId};
use crate::secret::{TokenKind, new_token, token_hash};
use crate::server::Core;
use crate::server::approvals::invalidate_pending;
use crate::server::audit::{self, member_actor};
use crate::server::auth::{AgentAuth, MemberAuth, parse_role, role_text};
use crate::server::env::{RESERVED_NAMES, base_var, provider_vars};
use crate::server::store::{
    ItemRow, db, has_grant, is_unique_violation, load_live_items, team_name, to_i, to_u,
};

const DEFAULT_INVITE_HOURS: u32 = 72;
const MAX_INVITE_HOURS: u32 = 168;
const DEFAULT_AGENT_DAYS: u32 = 30;
const MAX_AGENT_DAYS: u32 = 365;
const MAX_ITEM_HOSTS: usize = 16;

fn to_json<T: Serialize>(value: &T) -> RelayResult<Value> {
    serde_json::to_value(value).map_err(|_| RelayError::internal("A result cannot be written."))
}

fn created(id: u64) -> RelayResult<Value> {
    to_json(&Created { id })
}

/// A name for a collection, item, or agent: 1 to 64 bytes, no control character.
fn checked_label(text: &str, what: &str) -> RelayResult<String> {
    let text = text.trim();
    if text.is_empty()
        || text.len() > crate::api::MAX_NAME_BYTES
        || text.chars().any(char::is_control)
    {
        return Err(RelayError::invalid(format!(
            "The {what} name is 1 to 64 bytes with no control character."
        )));
    }
    Ok(text.to_string())
}

/// A member name: 1 to 64 bytes of letters, digits, and `.-_`.
pub fn checked_member_name(text: &str) -> RelayResult<&str> {
    let ok = !text.is_empty()
        && text.len() <= crate::api::MAX_NAME_BYTES
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if ok {
        Ok(text)
    } else {
        Err(RelayError::invalid(
            "A member name is 1 to 64 bytes of letters, digits, dot, dash, and underscore.",
        ))
    }
}

// ---- Me, join, invites, members ----

pub fn me(core: &Core, who: &crate::server::auth::Principal) -> RelayResult<Value> {
    let team = core.store.with(team_name)?;
    let member = who.member();
    let view = match who {
        crate::server::auth::Principal::Member(_) => MeView {
            team,
            kind: PrincipalKind::Member,
            member_id: member.id,
            member_name: member.name.clone(),
            role: member.role,
            agent_id: None,
            agent_name: None,
            expires_at: None,
        },
        crate::server::auth::Principal::Agent(agent) => MeView {
            team,
            kind: PrincipalKind::Agent,
            member_id: member.id,
            member_name: member.name.clone(),
            role: member.role,
            agent_id: Some(agent.id),
            agent_name: Some(agent.name.clone()),
            expires_at: Some(agent.expires_at),
        },
    };
    to_json(&view)
}

fn invite_invalid() -> RelayError {
    RelayError::new(
        codes::INVITE_INVALID,
        "The invite code is not valid, was used, or expired.",
    )
}

pub fn join(core: &Core, request: &JoinRequest, now: u64) -> RelayResult<Value> {
    let name = checked_member_name(&request.name)?.to_string();
    let code = request.code.expose();
    if TokenKind::of(code) != Some(TokenKind::Invite) {
        return Err(invite_invalid());
    }
    let code_hash = token_hash(code);
    let token = new_token(TokenKind::Member)?;
    let member_hash = token_hash(token.expose());
    let (member_id, role, invite_id) = core.store.tx(|tx| {
        let invite: Option<(i64, String)> = tx
            .query_row(
                "SELECT id, role FROM invite WHERE code_hash = ?1 AND used_by IS NULL AND expires_at > ?2",
                params![code_hash.0.as_slice(), to_i(now)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(db)?;
        let (invite_id, role) = invite.ok_or_else(invite_invalid)?;
        let inserted = tx.execute(
            "INSERT INTO member (name, role, token_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![name, role, member_hash.0.as_slice(), to_i(now)],
        );
        match inserted {
            Ok(_) => {}
            Err(error) if is_unique_violation(&error) => {
                return Err(RelayError::new(
                    codes::CONFLICT,
                    "A member with this name exists.",
                ));
            }
            Err(error) => return Err(db(error)),
        }
        let member_id = tx.last_insert_rowid();
        tx.execute(
            "UPDATE invite SET used_by = ?1, used_at = ?2 WHERE id = ?3",
            params![member_id, to_i(now), invite_id],
        )
        .map_err(db)?;
        core.audit.write_on(
            tx,
            now,
            &member_actor(to_u(member_id)),
            "member_joined",
            None,
            &json!({"name": name, "role": role, "invite_id": to_u(invite_id)}),
        )?;
        Ok((to_u(member_id), role, to_u(invite_id)))
    })?;
    let _ = (role, invite_id);
    to_json(&IssuedRef {
        id: member_id,
        secret: token.expose(),
        expires_at: None,
    })
}

pub fn invite_create(
    core: &Core,
    by: &MemberAuth,
    request: &InviteRequest,
    now: u64,
) -> RelayResult<Value> {
    if request.role == Role::Owner {
        return Err(RelayError::invalid(
            "An invite is for a manager or a member.",
        ));
    }
    if request.role == Role::Manager && by.role != Role::Owner {
        return Err(RelayError::forbidden("Only the owner invites a manager."));
    }
    let hours = request.expires_hours.unwrap_or(DEFAULT_INVITE_HOURS);
    if !(1..=MAX_INVITE_HOURS).contains(&hours) {
        return Err(RelayError::invalid("An invite lives 1 to 168 hours."));
    }
    let code = new_token(TokenKind::Invite)?;
    let hash = token_hash(code.expose());
    let expires_at = now + u64::from(hours) * 3600;
    let id = core.store.tx(|tx| {
        tx.execute(
            "INSERT INTO invite (code_hash, role, created_by, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                hash.0.as_slice(),
                role_text(request.role),
                to_i(by.id.0),
                to_i(now),
                to_i(expires_at)
            ],
        )
        .map_err(db)?;
        let id = to_u(tx.last_insert_rowid());
        core.audit.write_on(
            tx,
            now,
            &member_actor(by.id.0),
            "invite_created",
            None,
            &json!({"invite_id": id, "role": role_text(request.role), "expires_at": expires_at}),
        )?;
        Ok(id)
    })?;
    to_json(&IssuedRef {
        id,
        secret: code.expose(),
        expires_at: Some(expires_at),
    })
}

pub fn invite_list(core: &Core) -> RelayResult<Value> {
    core.store.with(|conn| {
        let mut statement = conn
            .prepare("SELECT id, role, created_at, expires_at, used_by FROM invite ORDER BY id")
            .map_err(db)?;
        let rows = statement
            .query_map([], |row| {
                Ok(InviteView {
                    id: InviteId(to_u(row.get(0)?)),
                    role: parse_role(&row.get::<_, String>(1)?),
                    created_at: to_u(row.get(2)?),
                    expires_at: to_u(row.get(3)?),
                    used_by: row.get::<_, Option<i64>>(4)?.map(|v| MemberId(to_u(v))),
                })
            })
            .map_err(db)?;
        let list: Vec<InviteView> = rows.collect::<Result<_, _>>().map_err(db)?;
        to_json(&list)
    })
}

pub fn member_list(core: &Core) -> RelayResult<Value> {
    core.store.with(|conn| {
        let mut statement = conn
            .prepare("SELECT id, name, role, created_at, revoked_at FROM member ORDER BY id")
            .map_err(db)?;
        let rows = statement
            .query_map([], |row| {
                Ok(MemberView {
                    id: MemberId(to_u(row.get(0)?)),
                    name: row.get(1)?,
                    role: parse_role(&row.get::<_, String>(2)?),
                    created_at: to_u(row.get(3)?),
                    revoked: row.get::<_, Option<i64>>(4)?.is_some(),
                })
            })
            .map_err(db)?;
        let list: Vec<MemberView> = rows.collect::<Result<_, _>>().map_err(db)?;
        to_json(&list)
    })
}

pub fn member_revoke(
    core: &Core,
    owner: &MemberAuth,
    id: MemberId,
    now: u64,
) -> RelayResult<Value> {
    if id == owner.id {
        return Err(RelayError::forbidden("The owner cannot revoke themselves."));
    }
    core.store.tx(|tx| {
        let changed = tx
            .execute(
                "UPDATE member SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
                params![to_i(id.0), to_i(now)],
            )
            .map_err(db)?;
        if changed == 0 {
            return Err(RelayError::not_found("member"));
        }
        tx.execute(
            "UPDATE agent SET revoked_at = ?2 WHERE member_id = ?1 AND revoked_at IS NULL",
            params![to_i(id.0), to_i(now)],
        )
        .map_err(db)?;
        tx.execute(
            "UPDATE access_grant SET revoked_at = ?2 WHERE member_id = ?1 AND revoked_at IS NULL",
            params![to_i(id.0), to_i(now)],
        )
        .map_err(db)?;
        // The pending runs of this member are denied, and their keys are dropped.
        invalidate_pending(
            core,
            tx,
            now,
            &member_actor(owner.id.0),
            "member_revoked",
            |run| run.member_id == id,
        )?;
        core.sessions
            .end_matching(tx, now, "member_revoked", |s| s.member_id == id)?;
        core.audit.write_on(
            tx,
            now,
            &member_actor(owner.id.0),
            "member_revoked",
            None,
            &json!({"member_id": id}),
        )?;
        Ok(())
    })?;
    core.notify.notify();
    created(id.0)
}

// ---- Collections ----

fn checked_policy(core: &Core, policy: Policy) -> RelayResult<Policy> {
    let mut rule = policy
        .rule
        .normalized()
        .map_err(|_| RelayError::invalid("The rule of the policy is not valid."))?;
    // The instruction is free text that agents can read back: no value or token in it.
    rule.instruction = core.audit.mask_text(&rule.instruction);
    Ok(Policy {
        mode: policy.mode,
        rule,
    })
}

fn policy_json(policy: &Policy) -> RelayResult<String> {
    serde_json::to_string(policy).map_err(|_| RelayError::internal("A policy cannot be written."))
}

pub fn collection_create(
    core: &Core,
    by: &MemberAuth,
    request: CollectionCreate,
    now: u64,
) -> RelayResult<Value> {
    let name = core
        .audit
        .mask_text(&checked_label(&request.name, "collection")?);
    let policy = checked_policy(core, request.policy)?;
    let text = policy_json(&policy)?;
    let id = core.store.tx(|tx| {
        match tx.execute(
            "INSERT INTO collection (name, policy, created_at) VALUES (?1, ?2, ?3)",
            params![name, text, to_i(now)],
        ) {
            Ok(_) => {}
            Err(error) if is_unique_violation(&error) => {
                return Err(RelayError::new(
                    codes::CONFLICT,
                    "A collection with this name exists.",
                ));
            }
            Err(error) => return Err(db(error)),
        }
        let id = to_u(tx.last_insert_rowid());
        core.audit.write_on(
            tx,
            now,
            &member_actor(by.id.0),
            "collection_created",
            None,
            &json!({"collection_id": id, "name": name, "policy": policy}),
        )?;
        Ok(id)
    })?;
    created(id)
}

fn collection_view(conn: &Connection, id: CollectionId) -> RelayResult<Option<CollectionView>> {
    conn.query_row(
        "SELECT c.id, c.name, c.policy, c.created_at, \
         (SELECT count(*) FROM item i WHERE i.collection_id = c.id AND i.archived_at IS NULL) \
         FROM collection c WHERE c.id = ?1",
        params![to_i(id.0)],
        collection_from_row,
    )
    .optional()
    .map_err(db)
}

fn collection_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CollectionView> {
    let policy: String = row.get(2)?;
    Ok(CollectionView {
        id: CollectionId(to_u(row.get(0)?)),
        name: row.get(1)?,
        policy: serde_json::from_str(&policy).unwrap_or_default(),
        item_count: to_u(row.get(4)?),
        created_at: to_u(row.get(3)?),
    })
}

pub fn collection_list(core: &Core, who: &MemberAuth) -> RelayResult<Value> {
    core.store.with(|conn| {
        let mut statement = conn
            .prepare(
                "SELECT c.id, c.name, c.policy, c.created_at, \
                 (SELECT count(*) FROM item i WHERE i.collection_id = c.id AND i.archived_at IS NULL) \
                 FROM collection c ORDER BY c.id",
            )
            .map_err(db)?;
        let all: Vec<CollectionView> = statement
            .query_map([], collection_from_row)
            .map_err(db)?
            .collect::<Result<_, _>>()
            .map_err(db)?;
        let mut visible = Vec::new();
        for view in all {
            if who.role.is_approver() || has_grant(conn, who.id, view.id)? {
                visible.push(view);
            }
        }
        to_json(&visible)
    })
}

pub fn policy_put(
    core: &Core,
    by: &MemberAuth,
    id: CollectionId,
    policy: Policy,
    now: u64,
) -> RelayResult<Value> {
    let policy = checked_policy(core, policy)?;
    let text = policy_json(&policy)?;
    let view = core.store.tx(|tx| {
        let changed = tx
            .execute(
                "UPDATE collection SET policy = ?2 WHERE id = ?1",
                params![to_i(id.0), text],
            )
            .map_err(db)?;
        if changed == 0 {
            return Err(RelayError::not_found("collection"));
        }
        core.audit.write_on(
            tx,
            now,
            &member_actor(by.id.0),
            "policy_changed",
            None,
            &json!({"collection_id": id, "policy": policy}),
        )?;
        collection_view(tx, id)?.ok_or_else(|| RelayError::not_found("collection"))
    })?;
    to_json(&view)
}

// ---- Items ----

fn item_view(item: &ItemRow) -> ItemView {
    ItemView {
        id: item.id,
        collection_id: item.collection_id,
        collection: item.collection.clone(),
        name: item.name.clone(),
        env_name: item.env_name.clone(),
        provider: item.provider.clone(),
        hosts: item.hosts.clone(),
        environment: item.environment.clone(),
        risk: item.risk.clone(),
        scope: item.scope.clone(),
        reversibility: item.reversibility.clone(),
        created_at: item.created_at,
    }
}

fn declared<T>(
    text: Option<&String>,
    default: &str,
    parse: impl Fn(&str) -> apassy::vault::VaultResult<T>,
    what: &str,
) -> RelayResult<String> {
    let text = text.map_or(default, String::as_str);
    parse(text)
        .map(|_| text.to_string())
        .map_err(|_| RelayError::invalid(format!("The {what} is not one of the known values.")))
}

pub fn item_create(core: &Core, by: &MemberAuth, request: NewItem, now: u64) -> RelayResult<Value> {
    let name = checked_label(&request.name, "item")?;
    let env_name = checked_env_name(&request.env_name)
        .map_err(|_| RelayError::invalid("The variable name is not allowed."))?
        .to_string();
    if RESERVED_NAMES.contains(&env_name.as_str()) {
        return Err(RelayError::invalid(
            "The variable name is one that the relay sets itself.",
        ));
    }
    // The relay cannot read the value: the CLI checked it and sealed it. The relay
    // checks the shape of what it stores.
    if !hostkeys::is_uid(&request.uid) {
        return Err(RelayError::invalid(
            "The uid is 32 lowercase hex characters.",
        ));
    }
    let sealed = hostkeys::decode_b64(&request.sealed, hostkeys::MAX_SEALED_BYTES)
        .ok()
        .filter(|bytes| bytes.len() >= hostkeys::MIN_SEALED_BYTES)
        .ok_or_else(|| {
            RelayError::invalid("The sealed value is base64url text of 12 + 16 + 1 to 4096 bytes.")
        })?;
    let provider = match request.provider.as_deref() {
        None | Some("") => None,
        Some(id) => {
            providers::find(id).ok_or_else(|| RelayError::invalid("The provider is not known."))?;
            Some(id.to_string())
        }
    };
    let host_texts: Vec<String> = if request.hosts.is_empty() {
        provider
            .as_deref()
            .map(|id| providers::known_hosts(id).to_vec())
            .unwrap_or_default()
    } else {
        request.hosts.clone()
    };
    if host_texts.is_empty() {
        return Err(RelayError::invalid("A relay item needs at least one host."));
    }
    let mut hosts: Vec<String> = Vec::new();
    let mut broad_hosts: Vec<String> = Vec::new();
    let provider_hosts = provider.as_deref().map_or(&[][..], providers::known_hosts);
    for text in &host_texts {
        let rule = HostRule::parse(text).map_err(RelayError::invalid)?;
        let shown = rule.to_string();
        if hosts.contains(&shown) {
            continue;
        }
        if let Some(why) = broad_host(rule.host(), provider_hosts) {
            if !request.allow_broad_host {
                return Err(RelayError::new(
                    codes::BROAD_HOST,
                    format!(
                        "The host {shown} is {why}. A host covers every subdomain too, and other people may own some of them. Give the exact API host, such as api.example.com, or allow a broad host on purpose (apassy-team item add --allow-broad-host)."
                    ),
                ));
            }
            broad_hosts.push(shown.clone());
        }
        hosts.push(shown);
    }
    if hosts.len() > MAX_ITEM_HOSTS {
        return Err(RelayError::invalid("An item has at most 16 hosts."));
    }
    let environment = declared(
        Some(&request.environment),
        "",
        Environment::parse,
        "environment",
    )?;
    let risk = declared(request.risk.as_ref(), "high", RiskLevel::parse, "risk")?;
    let scope = declared(request.scope.as_ref(), "admin", Scope::parse, "scope")?;
    let reversibility = declared(
        request.reversibility.as_ref(),
        "irreversible",
        Reversibility::parse,
        "reversibility",
    )?;
    let hosts_text = serde_json::to_string(&hosts)
        .map_err(|_| RelayError::internal("The hosts cannot be written."))?;
    let id = core.store.tx(|tx| {
        let name = core.audit.mask_text(&name);
        let exists: i64 = tx
            .query_row(
                "SELECT count(*) FROM collection WHERE id = ?1",
                params![to_i(request.collection_id.0)],
                |row| row.get(0),
            )
            .map_err(db)?;
        if exists == 0 {
            return Err(RelayError::not_found("collection"));
        }
        let uid_used: i64 = tx
            .query_row(
                "SELECT count(*) FROM item WHERE uid = ?1",
                params![request.uid],
                |row| row.get(0),
            )
            .map_err(db)?;
        if uid_used > 0 {
            return Err(RelayError::new(
                codes::CONFLICT,
                "An item with this uid exists.",
            ));
        }
        match tx.execute(
            "INSERT INTO item (collection_id, name, env_name, uid, sealed, provider, hosts, \
             environment, risk, scope, reversibility, created_by, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                to_i(request.collection_id.0),
                name,
                env_name,
                request.uid,
                sealed,
                provider,
                hosts_text,
                environment,
                risk,
                scope,
                reversibility,
                to_i(by.id.0),
                to_i(now)
            ],
        ) {
            Ok(_) => {}
            Err(error) if is_unique_violation(&error) => {
                return Err(RelayError::new(
                    codes::CONFLICT,
                    "This collection has an item with this variable name.",
                ));
            }
            Err(error) => return Err(db(error)),
        }
        let id = to_u(tx.last_insert_rowid());
        core.audit.write_on(
            tx,
            now,
            &member_actor(by.id.0),
            "item_added",
            None,
            &json!({
                "item_id": id, "collection_id": request.collection_id, "name": name,
                "env_name": env_name, "provider": provider, "hosts": hosts,
                "environment": environment, "broad_hosts": broad_hosts
            }),
        )?;
        Ok(id)
    })?;
    to_json(&ItemCreated { id, hosts })
}

/// Why a host is broad, or `None`. A host rule covers the host and every subdomain.
/// - A public suffix (`com`, `herokuapp.com`, `github.io`, `s3.amazonaws.com`) has
///   subdomains of many owners. It is always broad.
/// - A whole domain under a public (ICANN) suffix (`example.com`, `example.co.uk`)
///   has subdomains that other teams or customers may own. A known host of the
///   provider of the item is not broad in this way: the provider owns it. A domain
///   under a private suffix (`myapp.herokuapp.com`) belongs to one customer.
///
/// The public suffix list is compiled in (`psl`).
pub fn broad_host(host: &str, provider_hosts: &[String]) -> Option<&'static str> {
    let bytes = host.as_bytes();
    if psl::suffix(bytes).is_some_and(|suffix| suffix.as_bytes() == bytes) {
        return Some("a public suffix");
    }
    let whole = psl::domain(bytes).is_some_and(|domain| {
        domain.as_bytes() == bytes && domain.suffix().typ() != Some(psl::Type::Private)
    });
    if whole && !provider_hosts.iter().any(|known| known == host) {
        return Some("a whole domain");
    }
    None
}

pub fn item_list(
    core: &Core,
    who: &MemberAuth,
    collection: Option<CollectionId>,
) -> RelayResult<Value> {
    core.store.with(|conn| {
        let items = load_live_items(conn, collection)?;
        let mut views = Vec::new();
        for item in &items {
            if who.role.is_approver() || has_grant(conn, who.id, item.collection_id)? {
                views.push(item_view(item));
            }
        }
        to_json(&views)
    })
}

pub fn item_archive(core: &Core, by: &MemberAuth, id: ItemId, now: u64) -> RelayResult<Value> {
    core.store.tx(|tx| {
        let changed = tx
            .execute(
                "UPDATE item SET archived_at = ?2 WHERE id = ?1 AND archived_at IS NULL",
                params![to_i(id.0), to_i(now)],
            )
            .map_err(db)?;
        if changed == 0 {
            return Err(RelayError::not_found("item"));
        }
        invalidate_pending(
            core,
            tx,
            now,
            &member_actor(by.id.0),
            "item_archived",
            |run| run.items.contains(&id),
        )?;
        core.sessions.end_matching(tx, now, "item_archived", |s| {
            s.secrets.iter().any(|secret| secret.item_id == id)
        })?;
        core.audit.write_on(
            tx,
            now,
            &member_actor(by.id.0),
            "item_archived",
            None,
            &json!({"item_id": id}),
        )?;
        Ok(())
    })?;
    core.notify.notify();
    created(id.0)
}

// ---- Grants ----

pub fn grant_create(
    core: &Core,
    by: &MemberAuth,
    request: &GrantCreate,
    now: u64,
) -> RelayResult<Value> {
    let id = core.store.tx(|tx| {
        let collection = collection_view(tx, request.collection_id)?
            .ok_or_else(|| RelayError::not_found("collection"))?;
        let member_live: i64 = tx
            .query_row(
                "SELECT count(*) FROM member WHERE id = ?1 AND revoked_at IS NULL",
                params![to_i(request.member_id.0)],
                |row| row.get(0),
            )
            .map_err(db)?;
        if member_live == 0 {
            return Err(RelayError::not_found("member"));
        }
        match tx.execute(
            "INSERT INTO access_grant (collection_id, member_id, created_by, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                to_i(collection.id.0),
                to_i(request.member_id.0),
                to_i(by.id.0),
                to_i(now)
            ],
        ) {
            Ok(_) => {}
            Err(error) if is_unique_violation(&error) => {
                return Err(RelayError::new(
                    codes::CONFLICT,
                    "The member already has a grant for this collection.",
                ));
            }
            Err(error) => return Err(db(error)),
        }
        let id = to_u(tx.last_insert_rowid());
        core.audit.write_on(
            tx,
            now,
            &member_actor(by.id.0),
            "grant_created",
            None,
            &json!({"grant_id": id, "collection_id": collection.id, "member_id": request.member_id}),
        )?;
        Ok(id)
    })?;
    created(id)
}

pub fn grant_list(core: &Core) -> RelayResult<Value> {
    core.store.with(|conn| {
        let mut statement = conn
            .prepare(
                "SELECT g.id, g.collection_id, c.name, g.member_id, m.name, g.created_at \
                 FROM access_grant g JOIN collection c ON c.id = g.collection_id \
                 JOIN member m ON m.id = g.member_id WHERE g.revoked_at IS NULL ORDER BY g.id",
            )
            .map_err(db)?;
        let rows = statement
            .query_map([], |row| {
                Ok(GrantView {
                    id: GrantId(to_u(row.get(0)?)),
                    collection_id: CollectionId(to_u(row.get(1)?)),
                    collection: row.get(2)?,
                    member_id: MemberId(to_u(row.get(3)?)),
                    member: row.get(4)?,
                    created_at: to_u(row.get(5)?),
                })
            })
            .map_err(db)?;
        let list: Vec<GrantView> = rows.collect::<Result<_, _>>().map_err(db)?;
        to_json(&list)
    })
}

pub fn grant_revoke(core: &Core, by: &MemberAuth, id: GrantId, now: u64) -> RelayResult<Value> {
    core.store.tx(|tx| {
        let grant: Option<(i64, i64)> = tx
            .query_row(
                "SELECT collection_id, member_id FROM access_grant WHERE id = ?1 AND revoked_at IS NULL",
                params![to_i(id.0)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(db)?;
        let (collection, member) = grant.ok_or_else(|| RelayError::not_found("grant"))?;
        tx.execute(
            "UPDATE access_grant SET revoked_at = ?2 WHERE id = ?1",
            params![to_i(id.0), to_i(now)],
        )
        .map_err(db)?;
        let member = MemberId(to_u(member));
        let items: std::collections::HashSet<ItemId> = {
            let mut statement = tx
                .prepare("SELECT id FROM item WHERE collection_id = ?1")
                .map_err(db)?;
            statement
                .query_map(params![collection], |row| Ok(ItemId(to_u(row.get(0)?))))
                .map_err(db)?
                .collect::<Result<_, _>>()
                .map_err(db)?
        };
        invalidate_pending(
            core,
            tx,
            now,
            &member_actor(by.id.0),
            "grant_revoked",
            |run| run.member_id == member && run.items.iter().any(|item| items.contains(item)),
        )?;
        core.sessions.end_matching(tx, now, "grant_revoked", |s| {
            s.member_id == member && s.secrets.iter().any(|secret| items.contains(&secret.item_id))
        })?;
        core.audit.write_on(
            tx,
            now,
            &member_actor(by.id.0),
            "grant_revoked",
            None,
            &json!({"grant_id": id, "collection_id": to_u(collection), "member_id": member}),
        )?;
        Ok(())
    })?;
    core.notify.notify();
    created(id.0)
}

// ---- Agents ----

pub fn agent_create(
    core: &Core,
    by: &MemberAuth,
    request: &AgentCreate,
    now: u64,
) -> RelayResult<Value> {
    let name = core
        .audit
        .mask_text(&checked_label(&request.name, "agent")?);
    let days = request.days.unwrap_or(DEFAULT_AGENT_DAYS);
    if !(1..=MAX_AGENT_DAYS).contains(&days) {
        return Err(RelayError::invalid("An agent token lives 1 to 365 days."));
    }
    let token = new_token(TokenKind::Agent)?;
    let hash = token_hash(token.expose());
    let expires_at = now + u64::from(days) * 86_400;
    let id = core.store.tx(|tx| {
        tx.execute(
            "INSERT INTO agent (member_id, name, token_hash, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                to_i(by.id.0),
                name,
                hash.0.as_slice(),
                to_i(now),
                to_i(expires_at)
            ],
        )
        .map_err(db)?;
        let id = to_u(tx.last_insert_rowid());
        core.audit.write_on(
            tx,
            now,
            &member_actor(by.id.0),
            "agent_created",
            None,
            &json!({"agent_id": id, "name": name, "expires_at": expires_at}),
        )?;
        Ok(id)
    })?;
    to_json(&IssuedRef {
        id,
        secret: token.expose(),
        expires_at: Some(expires_at),
    })
}

pub fn agent_list(core: &Core, who: &MemberAuth) -> RelayResult<Value> {
    core.store.with(|conn| {
        let mut statement = conn
            .prepare(
                "SELECT id, member_id, name, created_at, expires_at, revoked_at FROM agent \
                 WHERE (?1 = 1 OR member_id = ?2) ORDER BY id",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(
                params![i64::from(who.role.is_approver()), to_i(who.id.0)],
                |row| {
                    Ok(AgentView {
                        id: AgentId(to_u(row.get(0)?)),
                        member_id: MemberId(to_u(row.get(1)?)),
                        name: row.get(2)?,
                        created_at: to_u(row.get(3)?),
                        expires_at: to_u(row.get(4)?),
                        revoked: row.get::<_, Option<i64>>(5)?.is_some(),
                    })
                },
            )
            .map_err(db)?;
        let list: Vec<AgentView> = rows.collect::<Result<_, _>>().map_err(db)?;
        to_json(&list)
    })
}

pub fn agent_revoke(core: &Core, by: &MemberAuth, id: AgentId, now: u64) -> RelayResult<Value> {
    core.store.tx(|tx| {
        let owner: Option<i64> = tx
            .query_row(
                "SELECT member_id FROM agent WHERE id = ?1 AND revoked_at IS NULL",
                params![to_i(id.0)],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        let owner = owner.ok_or_else(|| RelayError::not_found("agent"))?;
        if !by.role.is_approver() && to_u(owner) != by.id.0 {
            return Err(RelayError::not_found("agent"));
        }
        tx.execute(
            "UPDATE agent SET revoked_at = ?2 WHERE id = ?1",
            params![to_i(id.0), to_i(now)],
        )
        .map_err(db)?;
        invalidate_pending(
            core,
            tx,
            now,
            &member_actor(by.id.0),
            "agent_revoked",
            |run| run.agent_id == id,
        )?;
        core.sessions
            .end_matching(tx, now, "agent_revoked", |s| s.agent_id == id)?;
        core.audit.write_on(
            tx,
            now,
            &member_actor(by.id.0),
            "agent_revoked",
            None,
            &json!({"agent_id": id}),
        )?;
        Ok(())
    })?;
    core.notify.notify();
    created(id.0)
}

// ---- Audit and access ----

pub fn audit_list(core: &Core, after: u64, limit: u32) -> RelayResult<Value> {
    let entries = core.store.with(|conn| audit::list(conn, after, limit))?;
    to_json(&entries)
}

fn approval_text(item: &ItemRow) -> String {
    if item.environment == "production" {
        "Every run with this production credential waits for the owner's host, which asks the owner."
            .to_string()
    } else if item.policy.mode == PolicyMode::Ask {
        "Every run waits for the owner's host, which asks the owner (the policy of the collection)."
            .to_string()
    } else {
        "A known safe command is released by the owner's host when the run has the user's request. Any other command waits for the owner at the host."
            .to_string()
    }
}

pub fn access(core: &Core, agent: &AgentAuth) -> RelayResult<Value> {
    core.store.with(|conn| {
        let mut items = Vec::new();
        for item in load_live_items(conn, None)? {
            if !has_grant(conn, agent.member.id, item.collection_id)? {
                continue;
            }
            let hosts: Vec<HostRule> = item
                .hosts
                .iter()
                .filter_map(|h| HostRule::parse(h).ok())
                .collect();
            let mut vars = vec![base_var(&item.env_name)];
            vars.extend(provider_vars(&hosts).into_iter().map(str::to_string));
            items.push(AccessItem {
                item_id: item.id,
                item_name: item.name.clone(),
                collection: item.collection.clone(),
                env_name: item.env_name.clone(),
                hosts: item.hosts.clone(),
                environment: item.environment.clone(),
                base_url_vars: vars,
                approval: approval_text(&item),
                rule: item.policy.rule.clone(),
            });
        }
        let note = if items.is_empty() {
            "No collection is granted to your member yet. Ask the owner for a grant."
        } else {
            "Ask for a run with the exact command, the purpose, and the user's request. The relay swaps placeholders for values in auth positions only."
        };
        to_json(&AccessView {
            agent_id: agent.id,
            agent: agent.name.clone(),
            member: agent.member.name.clone(),
            items,
            note: note.to_string(),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broad_hosts_are_public_suffixes_and_whole_domains() {
        for host in [
            "com",
            "herokuapp.com",
            "azurewebsites.net",
            "github.io",
            "workers.dev",
            "s3.amazonaws.com",
            "co.uk",
            "localhost",
        ] {
            assert_eq!(broad_host(host, &[]), Some("a public suffix"), "{host}");
        }
        for host in [
            "example.com",
            "amazonaws.com",
            "example.co.uk",
            "stripe.com",
        ] {
            assert_eq!(broad_host(host, &[]), Some("a whole domain"), "{host}");
        }
        for host in [
            "api.example.com",
            "api.stripe.com",
            "myapp.herokuapp.com",
            "mybucket.s3.amazonaws.com",
            "api.example.co.uk",
            "other.example.test",
        ] {
            assert_eq!(broad_host(host, &[]), None, "{host}");
        }
        // A known host of the provider of the item is not broad as a whole domain.
        let aws = providers::known_hosts("aws");
        assert!(aws.iter().any(|h| h == "amazonaws.com"));
        assert_eq!(broad_host("amazonaws.com", aws), None);
        assert_eq!(
            broad_host("amazonaws.com", providers::known_hosts("stripe")),
            Some("a whole domain")
        );
        // A public suffix stays broad even when a provider lists it.
        let listed = ["github.io".to_owned()];
        assert_eq!(broad_host("github.io", &listed), Some("a public suffix"));
    }

    #[test]
    fn provider_default_hosts_that_are_broad() {
        let catalog = [
            "anthropic",
            "aws",
            "cloudflare",
            "datadog",
            "gcp",
            "github",
            "neon",
            "netlify",
            "openai",
            "planetscale",
            "resend",
            "sendgrid",
            "sentry",
            "stripe",
            "supabase",
            "twilio",
            "vercel",
        ];
        let mut suffixes = Vec::new();
        for id in catalog {
            let known = providers::known_hosts(id);
            for host in known {
                if broad_host(host, known).is_some() {
                    suffixes.push(host.clone());
                }
            }
        }
        // Each project of Supabase is a subdomain of supabase.co, and googleapis.com
        // hosts customer content: both are on the public suffix list. Such an item
        // needs the exact host (`<project>.supabase.co`) or `allow_broad_host`.
        assert_eq!(suffixes, vec!["googleapis.com", "supabase.co"]);
    }
}
