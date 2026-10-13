//! A join or a new device waits for a person to compare the safety words.

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::{Value, json};

use crate::api::{
    ConfirmRequest, Created, JoinConfirmed, JoinRequest, JoinView, LinkCancel, LinkCreatedRef,
    LinkRequest, LinkView, Pending, Role,
};
use crate::device;
use crate::device::{decode_public_key, safety_words};
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::{CollectionId, DeviceId, MemberId};
use crate::secret::{TokenKind, new_token, parse_token, token_hash};
use crate::server::Core;
use crate::server::admin::checked_member_name;
use crate::server::audit::{EDGE_ACTOR, member_actor};
use crate::server::auth::{MemberAuth, parse_role};
use crate::server::devices::{checked_label, view};
use crate::server::store::{db, team_name, to_i, to_u};

const JOIN_SECS: u64 = 72 * 3600;
const LINK_SECS: u64 = 600;
/// How long an expired or refused device link stays, and how many such links stay.
const LINK_KEEP_SECS: u64 = 7 * 86_400;
const LINK_KEEP_ROWS: i64 = 100;
const MAX_DEVICES: i64 = 10;

fn json_value<T: Serialize>(value: &T) -> RelayResult<Value> {
    serde_json::to_value(value).map_err(|_| RelayError::internal("A result cannot be written."))
}

fn conflict(message: &str) -> RelayError {
    RelayError::new(codes::CONFLICT, message)
}

fn invite_invalid() -> RelayError {
    RelayError::new(
        codes::INVITE_INVALID,
        "The invite code is not valid, was used, or expired. If you did not use it, tell the person who invited you.",
    )
}

fn link_invalid() -> RelayError {
    RelayError::forbidden("The link code is not valid, was used, or expired.")
}

fn checked_key(text: &str) -> RelayResult<Vec<u8>> {
    decode_public_key(text)
        .map(|key| key.to_vec())
        .map_err(|_| RelayError::invalid("The device public key is not valid."))
}

fn check_code(
    core: &Core,
    code: &str,
    kind: TokenKind,
    invalid: fn() -> RelayError,
) -> RelayResult<()> {
    let parsed = parse_token(code).ok_or_else(invalid)?;
    if parsed.kind != kind || parsed.team.as_ref() != Some(&core.team) {
        return Err(invalid());
    }
    Ok(())
}

fn key_free(conn: &Connection, key: &[u8]) -> RelayResult<()> {
    let taken: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM device WHERE public_key = ?1 AND revoked_at IS NULL)",
            params![key],
            |row| row.get(0),
        )
        .map_err(db)?;
    if taken {
        return Err(conflict("This public key belongs to a live device."));
    }
    Ok(())
}

fn check_device_count(conn: &Connection, member: MemberId) -> RelayResult<()> {
    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM device WHERE member_id = ?1 AND revoked_at IS NULL",
            params![to_i(member.0)],
            |row| row.get(0),
        )
        .map_err(db)?;
    if count >= MAX_DEVICES {
        return Err(conflict("A member can have at most 10 live devices."));
    }
    Ok(())
}

/// Read the caller's role again under the mutation transaction.
fn approver(conn: &Connection, by: &MemberAuth) -> RelayResult<Role> {
    let role: Option<String> = conn
        .query_row(
            "SELECT role FROM member WHERE id = ?1 AND revoked_at IS NULL",
            params![to_i(by.id.0)],
            |row| row.get(0),
        )
        .optional()
        .map_err(db)?;
    let role = parse_role(&role.ok_or_else(RelayError::unauthenticated)?);
    if !role.is_approver() {
        return Err(RelayError::forbidden(
            "Only an owner or a manager can do this.",
        ));
    }
    Ok(role)
}

/// Device-only endpoints never accept a member token. Recheck both live rows.
fn own_device(conn: &Connection, by: &MemberAuth) -> RelayResult<(DeviceId, String)> {
    let device = by.device.as_ref().ok_or_else(RelayError::unauthenticated)?;
    conn.query_row(
        "SELECT m.kind FROM device d JOIN member m ON m.id = d.member_id \
         WHERE d.id = ?1 AND m.id = ?2 AND d.revoked_at IS NULL AND m.revoked_at IS NULL",
        params![to_i(device.id.0), to_i(by.id.0)],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(db)?
    .map(|kind| (device.id, kind))
    .ok_or_else(RelayError::unauthenticated)
}

struct Invite {
    id: i64,
    role: String,
    name: Option<String>,
    grants: String,
    shared: bool,
    maker_name: String,
    maker_role: String,
    maker_revoked: bool,
    expires: u64,
    used: bool,
    revoked: bool,
}

fn invite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Invite> {
    Ok(Invite {
        id: row.get(0)?,
        role: row.get(1)?,
        name: row.get(2)?,
        grants: row.get(3)?,
        shared: row.get(4)?,
        maker_name: row.get(6)?,
        maker_role: row.get(7)?,
        maker_revoked: row.get::<_, Option<i64>>(8)?.is_some(),
        expires: to_u(row.get(9)?),
        used: row.get::<_, Option<i64>>(10)?.is_some(),
        revoked: row.get::<_, Option<i64>>(11)?.is_some(),
    })
}

const INVITE_COLUMNS: &str = "i.id, i.role, i.name, i.grants, i.shared, i.created_by, \
    m.name, m.role, m.revoked_at, i.expires_at, i.used_at, i.revoked_at";

fn maker_valid(invite: &Invite) -> bool {
    !invite.maker_revoked
        && !invite.revoked
        && match parse_role(&invite.role) {
            Role::Owner | Role::Manager => parse_role(&invite.maker_role) == Role::Owner,
            Role::Member => parse_role(&invite.maker_role).is_approver(),
        }
        && (!invite.shared || parse_role(&invite.role) == Role::Member)
}

fn pending(
    core: &Core,
    conn: &Connection,
    id: u64,
    safety: String,
    expires_at: u64,
    by: String,
) -> RelayResult<Value> {
    json_value(&Pending {
        id,
        team_id: core.team.clone(),
        team: team_name(conn)?,
        safety,
        expires_at,
        by,
    })
}

pub fn join(core: &Core, request: &JoinRequest, now: u64) -> RelayResult<Value> {
    let (device_name, public_key) = request
        .device_name
        .as_deref()
        .zip(request.public_key.as_deref())
        .ok_or_else(|| {
            RelayError::invalid(format!(
                "This apassy-team is too old: update it (curl -fsSL {}/install.sh ...)",
                core.config.public_url
            ))
        })?;
    let device_name = checked_label(device_name)?;
    let key = checked_key(public_key)?;
    let code = request.code.expose();
    check_code(core, code, TokenKind::Invite, invite_invalid)?;
    let hash = token_hash(code);
    let mut reused = None;
    let result = core.store.tx(|tx| {
        let invite = tx.query_row(&format!("SELECT {INVITE_COLUMNS} FROM invite i JOIN member m ON m.id = i.created_by WHERE i.code_hash = ?1"),
            params![hash.0.as_slice()], invite_row).optional().map_err(db)?.ok_or_else(invite_invalid)?;
        if invite.used {
            let old: Option<(i64, Vec<u8>, String, i64, String)> = tx.query_row(
                "SELECT id, public_key, safety, expires_at, state FROM join_request WHERE invite_id = ?1 ORDER BY id LIMIT 1",
                params![invite.id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))
                .optional().map_err(db)?;
            if let Some((id, old_key, safety, expires, state)) = old {
                if old_key != key { reused = Some(to_u(invite.id)); }
                else if state == "pending" && to_u(expires) > now && maker_valid(&invite) {
                    return Ok(pending(core, tx, to_u(id), safety, to_u(expires), invite.maker_name));
                }
            } else { reused = Some(to_u(invite.id)); }
            return Err(invite_invalid());
        }
        if invite.expires <= now || !maker_valid(&invite) { return Err(invite_invalid()); }
        let name = checked_member_name(invite.name.as_deref().or(request.name.as_deref()).unwrap_or_default())?;
        let used: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM member WHERE name = ?1 AND revoked_at IS NULL) \
             OR EXISTS(SELECT 1 FROM join_request WHERE name = ?1 AND state = 'pending' AND expires_at > ?2)",
            params![name, to_i(now)], |row| row.get(0)).map_err(db)?;
        if used { return Err(conflict("A live member or a pending join has this name.")); }
        key_free(tx, &key)?;
        let members: i64 = tx.query_row("SELECT count(*) FROM member WHERE revoked_at IS NULL", [], |row| row.get(0)).map_err(db)?;
        if to_u(members) >= core.limits().members {
            return Ok(Err(core.limit_error_on(tx, now, "members")?));
        }
        let safety = safety_words(&core.team, code, &key);
        let expires = now.saturating_add(JOIN_SECS);
        tx.execute("INSERT INTO join_request (invite_id, name, device_name, public_key, safety, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![invite.id, name, device_name, key, safety, to_i(now), to_i(expires)]).map_err(db)?;
        let id = to_u(tx.last_insert_rowid());
        tx.execute("UPDATE invite SET used_at = ?1 WHERE id = ?2", params![to_i(now), invite.id]).map_err(db)?;
        Ok(pending(core, tx, id, safety, expires, invite.maker_name))
    });
    if let Some(id) = reused {
        core.audit.refusal(
            &core.store,
            now,
            "invite_reused",
            "invite_reused",
            &json!({"invite_id": id}),
        );
    }
    result?
}

pub fn list(core: &Core, now: u64) -> RelayResult<Value> {
    core.store.with(|conn| {
        let mut statement = conn.prepare(
            "SELECT j.id, j.name, j.device_name, i.role, i.shared, i.grants, m.name, j.created_at, j.expires_at \
             FROM join_request j JOIN invite i ON i.id = j.invite_id JOIN member m ON m.id = i.created_by \
             WHERE j.state = 'pending' AND j.expires_at > ?1 ORDER BY j.created_at, j.id").map_err(db)?;
        let rows = statement.query_map(params![to_i(now)], |row| Ok((JoinView {
            id: to_u(row.get(0)?), name: row.get(1)?, device_name: row.get(2)?, role: parse_role(&row.get::<_, String>(3)?),
            shared: row.get(4)?, grants: vec![], invited_by: row.get(6)?, created_at: to_u(row.get(7)?), expires_at: to_u(row.get(8)?),
        }, row.get::<_, String>(5)?))).map_err(db)?;
        let mut result = Vec::new();
        for row in rows {
            let (mut join, grants) = row.map_err(db)?;
            for id in grant_ids(&grants)? {
                let name: Option<String> = conn.query_row("SELECT name FROM collection WHERE id = ?1", params![to_i(id.0)], |row| row.get(0)).optional().map_err(db)?;
                if let Some(name) = name { join.grants.push(name); }
            }
            result.push(join);
        }
        json_value(&result)
    })
}

fn grant_ids(text: &str) -> RelayResult<Vec<CollectionId>> {
    serde_json::from_str(text)
        .map_err(|_| RelayError::internal("The invite grants cannot be read."))
}

pub fn confirm(
    core: &Core,
    by: &MemberAuth,
    id: u64,
    request: &ConfirmRequest,
    now: u64,
) -> RelayResult<Value> {
    core.store.tx(|tx| {
        let caller_role = approver(tx, by)?;
        type PendingJoinRow = (i64, String, String, Vec<u8>, String, String, i64);
        let join: Option<PendingJoinRow> = tx.query_row(
            "SELECT invite_id, name, device_name, public_key, safety, state, expires_at FROM join_request WHERE id = ?1",
            params![to_i(id)], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)))
            .optional().map_err(db)?;
        let (invite_id, name, device_name, key, safety, state, expires) = join.ok_or_else(|| RelayError::not_found("join"))?;
        if state != "pending" || to_u(expires) <= now { return Err(conflict("The join does not wait for confirmation.")); }
        let invite = tx.query_row(&format!("SELECT {INVITE_COLUMNS} FROM invite i JOIN member m ON m.id = i.created_by WHERE i.id = ?1"),
            params![invite_id], invite_row).map_err(db)?;
        if parse_role(&invite.role) != Role::Member && caller_role != Role::Owner {
            return Err(RelayError::forbidden("Only an owner can confirm an owner or manager join."));
        }
        if !maker_valid(&invite) { return Err(invite_invalid()); }
        if !device::same_safety(&request.safety, &safety) { return Err(conflict("The safety words do not match.")); }
        let used: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM member WHERE name = ?1 AND revoked_at IS NULL)", params![name], |row| row.get(0)).map_err(db)?;
        if used { return Err(conflict("A live member has this name.")); }
        key_free(tx, &key)?;
        let members: i64 = tx.query_row("SELECT count(*) FROM member WHERE revoked_at IS NULL", [], |row| row.get(0)).map_err(db)?;
        if to_u(members) >= core.limits().members { return Ok(Err(core.limit_error_on(tx, now, "members")?)); }
        tx.execute("INSERT INTO member (name, role, kind, token_hash, created_at) VALUES (?1, ?2, ?3, NULL, ?4)",
            params![name, invite.role, if invite.shared { "shared" } else { "person" }, to_i(now)]).map_err(db)?;
        let member = MemberId(to_u(tx.last_insert_rowid()));
        let device = add_device(tx, member, &device_name, &key, now)?;
        for collection in grant_ids(&invite.grants)? {
            tx.execute("INSERT INTO access_grant (collection_id, member_id, created_by, created_at) \
                SELECT id, ?1, ?2, ?3 FROM collection WHERE id = ?4",
                params![to_i(member.0), to_i(by.id.0), to_i(now), to_i(collection.0)]).map_err(db)?;
        }
        tx.execute("UPDATE invite SET used_by = ?1 WHERE id = ?2", params![to_i(member.0), invite_id]).map_err(db)?;
        tx.execute("UPDATE join_request SET state = 'confirmed', decided_by = ?1, decided_at = ?2, member_id = ?3, device_id = ?4 WHERE id = ?5",
            params![to_i(by.id.0), to_i(now), to_i(member.0), to_i(device.0), to_i(id)]).map_err(db)?;
        core.audit.write_on(tx, now, &member_actor(by.id.0), "member_joined", None,
            &json!({"member_id": member, "name": name, "role": invite.role, "invite_id": invite_id, "shared": invite.shared}))?;
        if parse_role(&invite.role) == Role::Owner {
            crate::server::devices::end_host_bootstrap_on(tx, &core.audit, now)?;
        }
        audit_device(core, tx, by, device, false, now)?;
        Ok(json_value(&JoinConfirmed { member_id: member, device_id: device }))
    })?
}

fn add_device(
    conn: &Connection,
    member: MemberId,
    name: &str,
    key: &[u8],
    now: u64,
) -> RelayResult<DeviceId> {
    check_device_count(conn, member)?;
    key_free(conn, key)?;
    conn.execute("INSERT INTO device (member_id, name, public_key, key_holder, created_at) VALUES (?1, ?2, ?3, 0, ?4)",
        params![to_i(member.0), name, key, to_i(now)]).map_err(db)?;
    Ok(DeviceId(to_u(conn.last_insert_rowid())))
}

fn audit_device(
    core: &Core,
    conn: &Connection,
    by: &MemberAuth,
    device: DeviceId,
    owner: bool,
    now: u64,
) -> RelayResult<()> {
    let added = view(conn, device, None)?;
    let detail = json!({"member_id": added.member_id, "device_id": device, "name": added.name});
    core.audit.write_on(
        conn,
        now,
        &member_actor(by.id.0),
        "device_added",
        None,
        &detail,
    )?;
    if owner {
        core.audit.write_on(
            conn,
            now,
            &member_actor(by.id.0),
            "owner_device_added",
            None,
            &detail,
        )?;
    }
    Ok(())
}

pub fn refuse(core: &Core, by: &MemberAuth, id: u64, now: u64) -> RelayResult<Value> {
    core.store.tx(|tx| {
        approver(tx, by)?;
        let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM join_request WHERE id = ?1)", params![to_i(id)], |row| row.get(0)).map_err(db)?;
        if !exists { return Err(RelayError::not_found("join")); }
        let changed = tx.execute("UPDATE join_request SET state = 'refused', decided_by = ?1, decided_at = ?2 WHERE id = ?3 AND state = 'pending' AND expires_at > ?2",
            params![to_i(by.id.0), to_i(now), to_i(id)]).map_err(db)?;
        if changed == 0 { return Err(conflict("The join does not wait for confirmation.")); }
        core.audit.write_on(tx, now, &member_actor(by.id.0), "join_refused", None, &json!({"join_id": id}))?;
        json_value(&Created { id })
    })
}

pub fn links_create(core: &Core, by: &MemberAuth, now: u64) -> RelayResult<Value> {
    let code = new_token(TokenKind::Link, &core.team)?;
    let hash = token_hash(code.expose());
    let expires = now.saturating_add(LINK_SECS);
    core.store.tx(|tx| {
        let (device, kind) = own_device(tx, by)?;
        if kind != "person" { return Err(RelayError::forbidden("A shared member cannot make a device link.")); }
        check_device_count(tx, by.id)?;
        tx.execute("INSERT INTO device_link (member_id, code_hash, made_by_device, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![to_i(by.id.0), hash.0.as_slice(), to_i(device.0), to_i(now), to_i(expires)]).map_err(db)?;
        json_value(&LinkCreatedRef { secret: code.expose(), expires_at: expires })
    })
}

struct Link {
    id: u64,
    member: MemberId,
    member_name: String,
    member_role: Role,
    expires: u64,
    state: String,
    key: Option<Vec<u8>>,
    safety: Option<String>,
    name: Option<String>,
}

const LINK_COLUMNS: &str = "l.id, l.member_id, m.name, m.role, l.expires_at, l.state, l.public_key, l.safety, l.device_name";
const LIVE_LINK: &str = "FROM device_link l JOIN member m ON m.id = l.member_id \
    JOIN device d ON d.id = l.made_by_device \
    WHERE m.revoked_at IS NULL AND d.revoked_at IS NULL AND d.member_id = m.id";

fn link_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Link> {
    Ok(Link {
        id: to_u(row.get(0)?),
        member: MemberId(to_u(row.get(1)?)),
        member_name: row.get(2)?,
        member_role: parse_role(&row.get::<_, String>(3)?),
        expires: to_u(row.get(4)?),
        state: row.get(5)?,
        key: row.get(6)?,
        safety: row.get(7)?,
        name: row.get(8)?,
    })
}

pub fn link(core: &Core, request: &LinkRequest, now: u64) -> RelayResult<Value> {
    let name = checked_label(&request.device_name)?;
    let key = checked_key(&request.public_key)?;
    let code = request.code.expose();
    check_code(core, code, TokenKind::Link, link_invalid)?;
    let hash = token_hash(code);
    core.store.tx(|tx| {
        let link = tx.query_row(&format!("SELECT {LINK_COLUMNS} {LIVE_LINK} AND l.code_hash = ?1"),
            params![hash.0.as_slice()], link_row).optional().map_err(db)?.ok_or_else(link_invalid)?;
        if link.expires <= now { return Err(link_invalid()); }
        if link.state == "pending" && link.key.as_deref() == Some(key.as_slice()) {
            return pending(core, tx, link.id, link.safety.unwrap_or_default(), link.expires, link.member_name);
        }
        if link.state != "open" { return Err(link_invalid()); }
        key_free(tx, &key)?;
        check_device_count(tx, link.member)?;
        let safety = safety_words(&core.team, code, &key);
        let expires = now.saturating_add(LINK_SECS);
        tx.execute("UPDATE device_link SET device_name = ?1, public_key = ?2, safety = ?3, requested_at = ?4, expires_at = ?5, state = 'pending' WHERE id = ?6",
            params![name, key, safety, to_i(now), to_i(expires), to_i(link.id)]).map_err(db)?;
        pending(core, tx, link.id, safety, expires, link.member_name)
    })
}

/// `POST /v1/devices/link/cancel`: the new device takes back its pending link before a
/// confirmation, with the code it sent and its key. A retry after a cancel answers the
/// same; a link that was confirmed is 409, and the device then removes itself with a
/// token.
pub fn link_cancel(core: &Core, request: &LinkCancel, now: u64) -> RelayResult<Value> {
    let key = checked_key(&request.public_key)?;
    let code = request.code.expose();
    check_code(core, code, TokenKind::Link, link_invalid)?;
    let hash = token_hash(code);
    core.store.tx(|tx| {
        let link: Option<(i64, String, Option<Vec<u8>>, i64)> = tx
            .query_row(
                "SELECT id, state, public_key, expires_at FROM device_link WHERE code_hash = ?1",
                params![hash.0.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(db)?;
        let (id, state, link_key, expires) = link.ok_or_else(link_invalid)?;
        if link_key.as_deref() != Some(key.as_slice()) {
            return Err(link_invalid());
        }
        let id = to_u(id);
        match state.as_str() {
            "pending" if to_u(expires) > now => {
                tx.execute(
                    "UPDATE device_link SET state = 'refused', decided_at = ?1 WHERE id = ?2",
                    params![to_i(now), to_i(id)],
                )
                .map_err(db)?;
                core.audit.write_on(
                    tx,
                    now,
                    EDGE_ACTOR,
                    "device_link_cancelled",
                    None,
                    &json!({"link_id": id}),
                )?;
                json_value(&Created { id })
            }
            "pending" | "refused" | "expired" => json_value(&Created { id }),
            "confirmed" => Err(conflict(
                "The other device confirmed this link. Sign in and remove this device.",
            )),
            _ => Err(link_invalid()),
        }
    })
}

pub fn links_list(core: &Core, by: &MemberAuth, now: u64) -> RelayResult<Value> {
    core.store.with(|conn| {
        own_device(conn, by)?;
        let mut statement = conn.prepare("SELECT id, device_name, requested_at, expires_at, public_key FROM device_link \
            WHERE member_id = ?1 AND state = 'pending' AND expires_at > ?2 ORDER BY requested_at, id").map_err(db)?;
        let rows = statement.query_map(params![to_i(by.id.0), to_i(now)], |row| Ok(LinkView {
            id: to_u(row.get(0)?), device_name: row.get(1)?, created_at: to_u(row.get(2)?), expires_at: to_u(row.get(3)?),
            public_key: crate::hostkeys::encode_b64(&row.get::<_, Option<Vec<u8>>>(4)?.unwrap_or_default()),
        })).map_err(db)?;
        json_value(&rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db)?)
    })
}

fn own_link(conn: &Connection, by: &MemberAuth, id: u64, now: u64) -> RelayResult<Link> {
    own_device(conn, by)?;
    let link = conn
        .query_row(
            &format!("SELECT {LINK_COLUMNS} {LIVE_LINK} AND l.id = ?1 AND l.member_id = ?2"),
            params![to_i(id), to_i(by.id.0)],
            link_row,
        )
        .optional()
        .map_err(db)?
        .ok_or_else(|| RelayError::not_found("link"))?;
    if link.state != "pending" || link.expires <= now {
        return Err(conflict("The link does not wait for confirmation."));
    }
    Ok(link)
}

pub fn links_confirm(
    core: &Core,
    by: &MemberAuth,
    id: u64,
    request: &ConfirmRequest,
    now: u64,
) -> RelayResult<Value> {
    core.store.tx(|tx| {
        let link = own_link(tx, by, id, now)?;
        if !link.safety.as_deref().is_some_and(|words| device::same_safety(&request.safety, words)) { return Err(conflict("The safety words do not match.")); }
        let name = link.name.ok_or_else(|| RelayError::internal("The link has no device name."))?;
        let key = link.key.ok_or_else(|| RelayError::internal("The link has no public key."))?;
        let device = add_device(tx, by.id, &name, &key, now)?;
        tx.execute("UPDATE device_link SET state = 'confirmed', decided_at = ?1, device_id = ?2 WHERE id = ?3",
            params![to_i(now), to_i(device.0), to_i(id)]).map_err(db)?;
        audit_device(core, tx, by, device, link.member_role == Role::Owner, now)?;
        json_value(&view(tx, device, by.device.as_ref().map(|d| d.id))?)
    })
}

pub fn links_refuse(core: &Core, by: &MemberAuth, id: u64, now: u64) -> RelayResult<Value> {
    core.store.tx(|tx| {
        own_link(tx, by, id, now)?;
        tx.execute(
            "UPDATE device_link SET state = 'refused', decided_at = ?1 WHERE id = ?2",
            params![to_i(now), to_i(id)],
        )
        .map_err(db)?;
        core.audit.write_on(
            tx,
            now,
            &member_actor(by.id.0),
            "device_link_refused",
            None,
            &json!({"link_id": id}),
        )?;
        json_value(&Created { id })
    })
}

/// Called by the team's five-second maintenance pass. A device link that expired or was
/// refused stays `LINK_KEEP_SECS` for the record (a sign-in of its key reads
/// `join_refused`), and at most `LINK_KEEP_ROWS` of them stay at all; then the row goes.
/// A link makes no audit row, so these rows are the only trace, and they stay bounded.
pub fn expire(core: &Core, now: u64) -> RelayResult<()> {
    core.store.tx(|tx| {
        tx.execute("UPDATE join_request SET state = 'expired', decided_at = ?1 WHERE state = 'pending' AND expires_at <= ?1", params![to_i(now)]).map_err(db)?;
        tx.execute("UPDATE device_link SET state = 'expired', decided_at = ?1 WHERE state IN ('open', 'pending') AND expires_at <= ?1", params![to_i(now)]).map_err(db)?;
        tx.execute(
            "DELETE FROM device_link WHERE state IN ('expired', 'refused') AND (decided_at <= ?1 \
             OR id NOT IN (SELECT id FROM device_link WHERE state IN ('expired', 'refused') \
             ORDER BY id DESC LIMIT ?2))",
            params![to_i(now.saturating_sub(LINK_KEEP_SECS)), LINK_KEEP_ROWS],
        )
        .map_err(db)?;
        Ok(())
    })
}
