//! Device sign-in, enrollment, revocation, and host authorization (SPEC section 23).

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, PoisonError};

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use crate::api::{
    AccessGrantedRef, Challenge, ChallengeRequest, DeviceEnroll, DeviceView, Role, TokenRequest,
};
use crate::device;
use crate::error::{RelayError, RelayResult, codes};
use crate::hostkeys::decode_b64;
use crate::ids::{AgentId, DeviceId, MemberId};
use crate::secret::{TokenHash, TokenKind, new_token, token_hash};
use crate::server::Core;
use crate::server::approvals::invalidate_pending;
use crate::server::audit::{Audit, RELAY_ACTOR, member_actor};
use crate::server::auth::{MemberAuth, device_member};
use crate::server::store::{db, to_i, to_u};

#[derive(Default)]
struct State {
    nonces: HashMap<String, (DeviceId, u64)>,
    nonce_order: VecDeque<String>,
    // This table deliberately contains no role, member, public key, or bearer token.
    access: HashMap<TokenHash, (DeviceId, u64)>,
    access_order: VecDeque<TokenHash>,
}

impl State {
    fn purge(&mut self, now: u64) {
        self.nonces.retain(|_, (_, expiry)| *expiry > now);
        self.access.retain(|_, (_, expiry)| *expiry > now);
        self.compact();
    }

    fn compact(&mut self) {
        self.nonce_order
            .retain(|nonce| self.nonces.contains_key(nonce));
        self.access_order
            .retain(|hash| self.access.contains_key(hash));
    }
}

#[derive(Default)]
pub struct DeviceAuthState(Mutex<State>);

impl DeviceAuthState {
    pub fn clear(&self) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = State::default();
    }

    pub(crate) fn resolve(&self, token: &str, now: u64) -> RelayResult<DeviceId> {
        let state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        match state.access.get(&token_hash(token)) {
            Some((id, expiry)) if *expiry > now => Ok(*id),
            Some(_) => Err(RelayError::new(
                codes::TOKEN_EXPIRED,
                "The access token expired. Sign in again.",
            )),
            None => Err(RelayError::unauthenticated()),
        }
    }
}

pub fn drop_tokens(core: &Core, devices: &[DeviceId]) {
    let mut state = core
        .device_auth
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    state.access.retain(|_, (id, _)| !devices.contains(id));
    state.nonces.retain(|_, (id, _)| !devices.contains(id));
    state.compact();
}

/// How often a device's `last_seen_at` is written outside sign-in, at most.
pub const SEEN_EVERY_SECS: u64 = 60;

/// Sets `last_seen_at` of a device that used the relay, at most once per
/// `SEEN_EVERY_SECS`, so frequent calls (sync long polls) write little. A time ahead of
/// `now` (the clock went back) is replaced too.
pub fn mark_seen(conn: &Connection, id: DeviceId, now: u64) -> RelayResult<()> {
    conn.execute(
        "UPDATE device SET last_seen_at = ?2 WHERE id = ?1 \
         AND (last_seen_at IS NULL OR last_seen_at <= ?3 OR last_seen_at > ?2)",
        params![
            to_i(id.0),
            to_i(now),
            to_i(now.saturating_sub(SEEN_EVERY_SECS))
        ],
    )
    .map_err(db)?;
    Ok(())
}

pub fn checked_label(text: &str) -> RelayResult<String> {
    let text = text.trim();
    if text.is_empty()
        || text.len() > crate::api::MAX_NAME_BYTES
        || text.chars().any(char::is_control)
    {
        return Err(RelayError::invalid(
            "The device name is 1 to 64 bytes with no control character.",
        ));
    }
    Ok(text.to_owned())
}

fn json_value(value: &impl serde::Serialize) -> RelayResult<Value> {
    serde_json::to_value(value).map_err(|_| RelayError::internal("The response cannot be encoded."))
}

pub fn view(conn: &Connection, id: DeviceId, current: Option<DeviceId>) -> RelayResult<DeviceView> {
    conn.query_row(
        "SELECT d.member_id, m.name, d.name, d.key_holder, d.created_at, d.last_seen_at, d.public_key \
         FROM device d JOIN member m ON m.id = d.member_id \
         WHERE d.id = ?1 AND d.revoked_at IS NULL AND m.revoked_at IS NULL",
        params![to_i(id.0)],
        |row| {
            Ok(DeviceView {
                id,
                member_id: MemberId(to_u(row.get(0)?)),
                member_name: row.get(1)?,
                name: row.get(2)?,
                key_holder: row.get(3)?,
                created_at: to_u(row.get(4)?),
                last_seen_at: row.get::<_, Option<i64>>(5)?.map(to_u),
                current: current == Some(id),
                public_key: crate::hostkeys::encode_b64(&row.get::<_, Vec<u8>>(6)?),
            })
        },
    )
    .optional()
    .map_err(db)?
    .ok_or_else(|| RelayError::not_found("device"))
}

pub fn challenge(core: &Core, request: &ChallengeRequest, now: u64) -> RelayResult<Value> {
    if request.team_id != core.team || core.stopping() {
        return Err(RelayError::unauthenticated());
    }
    let public = device::decode_public_key(&request.public_key)
        .map_err(|_| RelayError::unauthenticated())?;
    core.store.with(|conn| {
        // Read-time expiry makes the answer independent of the five-second sweep.
        expire_waits(conn, now)?;
        let id = conn.query_row(
            "SELECT d.id FROM device d JOIN member m ON m.id = d.member_id \
             WHERE d.public_key = ?1 AND d.revoked_at IS NULL AND m.revoked_at IS NULL",
            params![public.as_slice()], |row| Ok(DeviceId(to_u(row.get(0)?))),
        ).optional().map_err(db)?;
        let Some(id) = id else {
            let pending: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM join_request WHERE public_key = ?1 AND state = 'pending' \
                 UNION ALL SELECT 1 FROM device_link WHERE public_key = ?1 AND state = 'pending')",
                params![public.as_slice()], |row| row.get(0),
            ).map_err(db)?;
            if pending { return Err(RelayError::new(codes::JOIN_PENDING, "The device waits for confirmation.")); }
            let refused: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM join_request WHERE public_key = ?1 AND state IN ('refused','expired') \
                 UNION ALL SELECT 1 FROM device_link WHERE public_key = ?1 AND state IN ('refused','expired'))",
                params![public.as_slice()], |row| row.get(0),
            ).map_err(db)?;
            return Err(if refused { RelayError::new(codes::JOIN_REFUSED, "The device request was refused or expired.") } else { RelayError::unauthenticated() });
        };
        let nonce = device::new_nonce().map_err(|_| RelayError::internal("The system has no random source."))?;
        let expires_at = now.saturating_add(60);
        let mut state = core.device_auth.0.lock().unwrap_or_else(PoisonError::into_inner);
        state.purge(now);
        let oldest = if state.nonces.values().filter(|(d, _)| *d == id).count() >= 4 {
            state.nonce_order.iter().find(|n| state.nonces.get(*n).is_some_and(|(d, _)| *d == id)).cloned()
        } else { None };
        if state.nonces.len() >= 1000 {
            return Err(RelayError::new(codes::BUSY, "The sign-in challenge table is full. Try again later."));
        }
        if let Some(oldest) = oldest { state.nonces.remove(&oldest); state.compact(); }
        state.nonce_order.push_back(nonce.clone());
        state.nonces.insert(nonce.clone(), (id, expires_at));
        json_value(&Challenge { nonce, expires_at, origin: core.config.public_url.clone() })
    })
}

pub fn token(core: &Core, request: &TokenRequest, now: u64) -> RelayResult<Value> {
    // Consume before any validation, including the key encoding and team check.
    let challenge = {
        let mut state = core
            .device_auth
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let challenge = state.nonces.remove(&request.nonce);
        state.compact();
        challenge
    };
    let result = (|| {
        let (id, expiry) = challenge.ok_or_else(RelayError::unauthenticated)?;
        if expiry <= now || request.team_id != core.team || core.stopping() {
            return Err(RelayError::unauthenticated());
        }
        let public = device::decode_public_key(&request.public_key)
            .map_err(|_| RelayError::unauthenticated())?;
        let signature = decode_b64(&request.signature, device::MAX_SIGNATURE_BYTES)
            .map_err(|_| RelayError::unauthenticated())?;
        core.store.tx(|conn| {
            let member = device_member(conn, id)?;
            let stored: Vec<u8> = conn.query_row("SELECT public_key FROM device WHERE id = ?1", params![to_i(id.0)], |row| row.get(0)).map_err(db)?;
            if stored != public || !device::verify(&public, &device::sign_in_message(&core.config.public_url, &core.team, &request.public_key, &request.nonce), &signature) {
                return Err(RelayError::unauthenticated());
            }
            let team: String = conn.query_row("SELECT name FROM team WHERE id = 1", [], |row| row.get(0)).map_err(db)?;
            let access = new_token(TokenKind::Access, &core.team)?;
            let expires_at = now.saturating_add(900);
            conn.execute("UPDATE device SET last_seen_at = ?2 WHERE id = ?1", params![to_i(id.0), to_i(now)]).map_err(db)?;
            let recent: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM audit WHERE action = 'device_signed_in' AND at > ?1 AND json_extract(detail, '$.device_id') = ?2)",
                params![to_i(now.saturating_sub(3600)), to_i(id.0)], |row| row.get(0),
            ).map_err(db)?;
            if !recent {
                core.audit.write_on(conn, now, &member_actor(member.id.0), "device_signed_in", None, &json!({"device_id": id}))?;
            }
            let response = json_value(&AccessGrantedRef {
                token: access.expose(), expires_at, team_id: &core.team, team: &team,
                member_id: member.id, member_name: &member.name, role: member.role,
                device_id: id, key_holder: member.device.is_some_and(|d| d.key_holder),
            })?;
            let mut state = core.device_auth.0.lock().unwrap_or_else(PoisonError::into_inner);
            state.purge(now);
            if state.access.values().filter(|(d, _)| *d == id).count() >= 8
                && let Some(oldest) = state.access_order.iter().find(|h| state.access.get(*h).is_some_and(|(d, _)| *d == id)).copied() {
                state.access.remove(&oldest);
                state.compact();
            }
            let hash = token_hash(access.expose());
            state.access.insert(hash, (id, expires_at));
            state.access_order.push_back(hash);
            Ok(response)
        })
    })();
    if result
        .as_ref()
        .is_err_and(|e| e.code == codes::UNAUTHENTICATED)
    {
        core.audit.refusal(
            &core.store,
            now,
            "device_sign_in",
            "device_sign_in_refused",
            &json!({}),
        );
    }
    result
}

pub fn enroll(
    core: &Core,
    by: &MemberAuth,
    request: &DeviceEnroll,
    now: u64,
) -> RelayResult<Value> {
    if by.device.is_some() {
        return Err(RelayError::unauthenticated());
    }
    let name = checked_label(&request.name)?;
    let public = device::decode_public_key(&request.public_key)
        .map_err(|_| RelayError::invalid("The device public key is not valid."))?;
    core.store.tx(|conn| {
        let (role, has_token): (String, bool) = conn.query_row("SELECT role, token_hash IS NOT NULL FROM member WHERE id = ?1 AND revoked_at IS NULL", params![to_i(by.id.0)], |row| Ok((row.get(0)?, row.get(1)?))).optional().map_err(db)?.ok_or_else(RelayError::unauthenticated)?;
        let conflict: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM device WHERE revoked_at IS NULL AND (member_id = ?1 OR public_key = ?2))", params![to_i(by.id.0), public.as_slice()], |row| row.get(0)).map_err(db)?;
        if conflict { return Err(RelayError::new(codes::CONFLICT, "The member has a device or the public key is in use.")); }
        if !has_token { return Err(RelayError::unauthenticated()); }
        let holder: bool = conn.query_row("SELECT NOT EXISTS(SELECT 1 FROM device d JOIN member m ON m.id = d.member_id WHERE d.key_holder = 1 AND d.revoked_at IS NULL AND m.revoked_at IS NULL) AND (SELECT count(*) FROM member WHERE role = 'owner' AND revoked_at IS NULL) = 1", [], |row| row.get(0)).map_err(db)?;
        conn.execute("INSERT INTO device (member_id, name, public_key, key_holder, created_at) VALUES (?1,?2,?3,?4,?5)", params![to_i(by.id.0), name, public.as_slice(), role == "owner" && holder, to_i(now)]).map_err(db)?;
        let id = DeviceId(to_u(conn.last_insert_rowid()));
        if role == "owner" {
            end_host_bootstrap_on(conn, &core.audit, now)?;
        }
        conn.execute("UPDATE member SET token_hash = NULL WHERE id = ?1", params![to_i(by.id.0)]).map_err(db)?;
        conn.execute("UPDATE agent SET device_id = ?2 WHERE member_id = ?1 AND device_id IS NULL", params![to_i(by.id.0), to_i(id.0)]).map_err(db)?;
        core.audit.write_on(conn, now, &member_actor(by.id.0), "member_enrolled", None, &json!({"member_id": by.id, "device_id": id, "name": name}))?;
        json_value(&view(conn, id, None)?)
    })
}

pub fn list(core: &Core, by: &MemberAuth) -> RelayResult<Value> {
    core.store.with(|conn| {
        let mut statement = conn.prepare("SELECT d.id FROM device d JOIN member m ON m.id = d.member_id WHERE d.revoked_at IS NULL AND m.revoked_at IS NULL AND (?1 OR d.member_id = ?2) ORDER BY d.id").map_err(db)?;
        let ids = statement.query_map(params![by.role == Role::Owner, to_i(by.id.0)], |row| Ok(DeviceId(to_u(row.get(0)?)))).map_err(db)?.collect::<Result<Vec<_>, _>>().map_err(db)?;
        let views = ids.into_iter().map(|id| view(conn, id, by.device.map(|d| d.id))).collect::<RelayResult<Vec<_>>>()?;
        json_value(&views)
    })
}

pub fn revoke(core: &Core, by: &MemberAuth, id: DeviceId, now: u64) -> RelayResult<Value> {
    let was_holder = core.store.tx(|conn| {
        let target = view(conn, id, None)?;
        if by.role != Role::Owner && target.member_id != by.id { return Err(RelayError::not_found("device")); }
        // No change may leave the team without an owner who can sign in (review).
        if !crate::server::admin::owner_can_sign_in_after(conn, now, None, Some(id))? {
            return Err(RelayError::new(codes::CONFLICT, "This would leave no owner who can sign in: the last device of the last owner cannot be revoked."));
        }
        let agents = {
            let mut statement = conn.prepare("SELECT id FROM agent WHERE device_id = ?1").map_err(db)?;
            statement.query_map(params![to_i(id.0)], |row| Ok(AgentId(to_u(row.get(0)?)))).map_err(db)?.collect::<Result<Vec<_>, _>>().map_err(db)?
        };
        conn.execute("UPDATE device SET revoked_at = ?2 WHERE id = ?1", params![to_i(id.0), to_i(now)]).map_err(db)?;
        // A removed device gets no more pushes (docs/SPEC.md section 25.2).
        conn.execute("DELETE FROM push_token WHERE device_id = ?1", params![to_i(id.0)]).map_err(db)?;
        conn.execute("UPDATE agent SET revoked_at = ?2 WHERE device_id = ?1 AND revoked_at IS NULL", params![to_i(id.0), to_i(now)]).map_err(db)?;
        conn.execute("UPDATE device_link SET state = 'expired', decided_at = ?2 WHERE made_by_device = ?1 AND state IN ('open','pending')", params![to_i(id.0), to_i(now)]).map_err(db)?;
        invalidate_pending(core, conn, now, &member_actor(by.id.0), "device_revoked", |run| agents.contains(&run.agent_id))?;
        core.sessions.end_matching(conn, now, "device_revoked", |s| agents.contains(&s.agent_id))?;
        core.audit.write_on(conn, now, &member_actor(by.id.0), "device_revoked", None, &json!({"device_id": id, "name": target.name, "key_holder": target.key_holder}))?;
        Ok(target.key_holder)
    })?;
    drop_tokens(core, &[id]);
    core.notify.notify();
    let mut result = json!({"id": id});
    if was_holder {
        result["message"] =
            json!("The team has no key holder. An owner device must claim the keys.");
    }
    Ok(result)
}

pub fn key_holder(core: &Core, by: &MemberAuth, id: DeviceId, now: u64) -> RelayResult<Value> {
    let caller = by.device.ok_or_else(|| {
        RelayError::new(
            codes::NOT_KEY_HOLDER,
            "Use an owner device to move or claim the keys.",
        )
    })?;
    core.store.tx(|conn| {
        let member = device_member(conn, caller.id)?;
        if member.role != Role::Owner { return Err(RelayError::forbidden("Only an owner can move or claim the keys.")); }
        let holder: Option<i64> = conn.query_row("SELECT d.id FROM device d JOIN member m ON m.id = d.member_id WHERE d.key_holder = 1 AND d.revoked_at IS NULL AND m.revoked_at IS NULL AND m.role = 'owner'", [], |row| row.get(0)).optional().map_err(db)?;
        if holder.map(to_u).is_some_and(|holder| holder != caller.id.0) || (holder.is_none() && id != caller.id) {
            return Err(RelayError::new(codes::NOT_KEY_HOLDER, "Only the key holder can move the keys. Without a key holder, an owner device can claim only its own flag."));
        }
        let target = device_member(conn, id).map_err(|e| if e.code == codes::UNAUTHENTICATED { RelayError::not_found("device") } else { e })?;
        if target.role != Role::Owner { return Err(RelayError::forbidden("The key holder must be an owner device.")); }
        conn.execute("UPDATE device SET key_holder = 0 WHERE key_holder = 1", []).map_err(db)?;
        conn.execute("UPDATE device SET key_holder = 1 WHERE id = ?1", params![to_i(id.0)]).map_err(db)?;
        let action = if holder.is_some() { "key_holder_moved" } else { "key_holder_claimed" };
        core.audit.write_on(conn, now, &member_actor(member.id.0), action, None, &json!({"device_id": id, "previous_device_id": holder.map(to_u)}))?;
        json_value(&view(conn, id, Some(caller.id))?)
    })
}

/// Permanently closes member-token host access when an owner gets a device.
/// Call in the transaction that adds that device or promotes its member.
pub fn end_host_bootstrap_on(conn: &Connection, audit: &Audit, now: u64) -> RelayResult<()> {
    let closed: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM audit WHERE action = 'host_bootstrap_ended')",
            [],
            |row| row.get(0),
        )
        .map_err(db)?;
    if !closed {
        audit.write_on(
            conn,
            now,
            RELAY_ACTOR,
            "host_bootstrap_ended",
            None,
            &json!({}),
        )?;
    }
    Ok(())
}

pub fn authorize_host(core: &Core, by: &MemberAuth) -> RelayResult<()> {
    core.store.with(|conn| {
        if let Some(device) = by.device {
            let member = device_member(conn, device.id)?;
            if member.role != Role::Owner { return Err(RelayError::forbidden("Only an owner can use the host endpoints.")); }
            if member.device.is_some_and(|d| d.key_holder) { return Ok(()); }
        } else {
            let owner: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM member WHERE id = ?1 AND role = 'owner' AND revoked_at IS NULL)", params![to_i(by.id.0)], |row| row.get(0)).map_err(db)?;
            if !owner { return Err(RelayError::forbidden("Only an owner can use the host endpoints.")); }
            // A revoked owner device also closes the bootstrap path permanently.
            let owner_device: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM audit WHERE action = 'host_bootstrap_ended') OR EXISTS(SELECT 1 FROM device d JOIN member m ON m.id = d.member_id WHERE m.role = 'owner')", [], |row| row.get(0)).map_err(db)?;
            if !owner_device { return Ok(()); }
        }
        Err(RelayError::new(codes::NOT_KEY_HOLDER, "Only the key-holder device can use the host endpoints."))
    })
}

fn expire_waits(conn: &Connection, now: u64) -> RelayResult<()> {
    conn.execute("UPDATE join_request SET state = 'expired', decided_at = ?1 WHERE state = 'pending' AND expires_at <= ?1", params![to_i(now)]).map_err(db)?;
    conn.execute("UPDATE device_link SET state = 'expired', decided_at = ?1 WHERE state IN ('open','pending') AND expires_at <= ?1", params![to_i(now)]).map_err(db)?;
    Ok(())
}

pub fn maintenance(core: &Core, now: u64) -> RelayResult<()> {
    core.device_auth
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .purge(now);
    core.store.with(|conn| expire_waits(conn, now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelayConfig;
    use crate::device::DeviceKey;
    use crate::secret::SecretString;
    use crate::server::{Relay, hub::Hub};
    use std::sync::{Arc, atomic::AtomicBool};

    fn fixture() -> (tempfile::TempDir, Arc<Core>, SecretString) {
        let dir = tempfile::tempdir().unwrap();
        let config = RelayConfig {
            data_dir: dir.path().join("data"),
            listen: "127.0.0.1:0".parse().unwrap(),
            public_url: "https://relay.example.test".into(),
            edge_secret: SecretString::new("e".repeat(40)),
            master_key: SecretString::new("synthetic unit test vault key".into()),
            session_ttl_secs: 60,
            approval_timeout_secs: 30,
            upstream: Default::default(),
            limits: Default::default(),
            backup_dir: dir.path().join("backups"),
            push: None,
            questions_to_approvers: false,
        };
        let owner = Relay::init(&config, "team", "owner").unwrap();
        let hub = Hub::open(config, Arc::new(AtomicBool::new(false))).unwrap();
        let core = hub.for_token(owner.expose()).unwrap();
        (dir, core, owner)
    }

    #[test]
    fn the_team_nonce_cap_preserves_other_keys_and_allows_own_replacement() {
        let (_dir, core, _) = fixture();
        let keys: Vec<_> = (0..251).map(|_| DeviceKey::generate().unwrap()).collect();
        // This fixture exercises the nonce limit directly. Join/link flows have HTTP tests.
        core.store.tx(|conn| {
            for (index, key) in keys.iter().enumerate() {
                conn.execute("INSERT INTO device(member_id,name,public_key,created_at) VALUES(1,?1,?2,0)", params![format!("device{index}"), key.public_key().as_slice()]).map_err(db)?;
            }
            Ok(())
        }).unwrap();
        let now = crate::now_unix();
        let mut first = String::new();
        for (index, key) in keys[..250].iter().enumerate() {
            for slot in 0..4 {
                let made = challenge(
                    &core,
                    &ChallengeRequest {
                        team_id: core.team.clone(),
                        public_key: key.public_key_b64(),
                    },
                    now,
                )
                .unwrap();
                if index == 0 && slot == 0 {
                    first = made["nonce"].as_str().unwrap().to_owned();
                }
            }
        }
        let before = core.device_auth.0.lock().unwrap().nonces.clone();
        assert_eq!(before.len(), 1000);
        let request = ChallengeRequest {
            team_id: core.team.clone(),
            public_key: keys[250].public_key_b64(),
        };
        assert_eq!(
            challenge(&core, &request, now).unwrap_err().code,
            codes::BUSY
        );
        assert_eq!(core.device_auth.0.lock().unwrap().nonces, before);
        let full_key_request = ChallengeRequest {
            team_id: core.team.clone(),
            public_key: keys[0].public_key_b64(),
        };
        assert_eq!(
            challenge(&core, &full_key_request, now).unwrap_err().code,
            codes::BUSY
        );
        let after = core.device_auth.0.lock().unwrap().nonces.clone();
        assert_eq!(after, before);
        assert!(after.contains_key(&first));
        // Exact expiry frees every nonce and lets a different key enter.
        challenge(&core, &request, now + 60).unwrap();
        assert_eq!(core.device_auth.0.lock().unwrap().nonces.len(), 1);
    }

    #[test]
    fn owner_role_changes_do_not_reopen_member_token_host_access() {
        let (_dir, core, bearer) = fixture();
        let now = crate::now_unix();
        let owner = crate::server::auth::authenticate_core(&core, bearer.expose(), now)
            .unwrap()
            .member()
            .clone();
        authorize_host(&core, &owner).unwrap();
        let key = DeviceKey::generate().unwrap();
        enroll(
            &core,
            &owner,
            &DeviceEnroll {
                name: "owner device".into(),
                public_key: key.public_key_b64(),
            },
            now,
        )
        .unwrap();
        let other = core.store.tx(|conn| {
            conn.execute("INSERT INTO member(name,role,token_hash,created_at) VALUES('other','owner',?1,0)", params![vec![2u8; 32]]).map_err(db)?;
            let id = MemberId(to_u(conn.last_insert_rowid()));
            conn.execute("UPDATE device SET revoked_at = ?1", params![to_i(now)]).map_err(db)?;
            conn.execute("UPDATE member SET role = 'member' WHERE id = 1", []).map_err(db)?;
            Ok(MemberAuth { id, name: "other".into(), role: Role::Owner, device: None })
        }).unwrap();
        assert_eq!(
            authorize_host(&core, &other).unwrap_err().code,
            codes::NOT_KEY_HOLDER
        );
    }

    /// SPEC 23.5 and 24.4: the sync calls mark a device as seen, at most once a minute.
    #[test]
    fn sync_calls_mark_the_device_seen_once_a_minute() {
        use crate::api::ReceiptRequest;
        use crate::server::auth::DeviceAuth;
        use crate::server::sync::{self, PushRequest};
        use sha2::{Digest, Sha256};

        let (_dir, core, bearer) = fixture();
        let t0 = crate::now_unix();
        let owner = crate::server::auth::authenticate_core(&core, bearer.expose(), t0)
            .unwrap()
            .member()
            .clone();
        let key = DeviceKey::generate().unwrap();
        let made = enroll(
            &core,
            &owner,
            &DeviceEnroll {
                name: "Mac".into(),
                public_key: key.public_key_b64(),
            },
            t0,
        )
        .unwrap();
        let id = DeviceId(made["id"].as_u64().unwrap());
        let mac = MemberAuth {
            device: Some(DeviceAuth {
                id,
                key_holder: true,
            }),
            ..owner
        };
        let last_seen = || {
            core.store
                .with(|conn| {
                    conn.query_row(
                        "SELECT last_seen_at FROM device WHERE id = ?1",
                        params![to_i(id.0)],
                        |row| row.get::<_, Option<i64>>(0),
                    )
                    .map_err(db)
                })
                .unwrap()
                .map(to_u)
        };
        assert_eq!(last_seen(), None);

        // A head poll marks it; a receipt within the minute does not write again.
        sync::head(&core, &mac, 0, 0, t0).unwrap();
        assert_eq!(last_seen(), Some(t0));
        sync::receipt(&core, &mac, &ReceiptRequest { version: 0 }, t0 + 59).unwrap();
        assert_eq!(last_seen(), Some(t0));
        sync::receipt(&core, &mac, &ReceiptRequest { version: 0 }, t0 + 60).unwrap();
        assert_eq!(last_seen(), Some(t0 + 60));

        // A push marks it.
        let body = b"synthetic snapshot";
        let text = format!(
            "apassy-relay-sync-head-v1\n0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77 1 {} {}\n{} {}/{} 1790000000",
            crate::sync_head::hex(&Sha256::digest(body)),
            body.len(),
            "0".repeat(64),
            core.team.as_str(),
            id.0
        );
        let signature = crate::hostkeys::encode_b64(&key.sign(text.as_bytes()).unwrap());
        let headers = [
            ("If-Match", "\"0\"".to_owned()),
            ("Content-Length", body.len().to_string()),
            (
                crate::sync_head::HEAD_HEADER,
                crate::hostkeys::encode_b64(text.as_bytes()),
            ),
            (crate::sync_head::SIGNATURE_HEADER, signature),
        ];
        let push = PushRequest::from_headers(|name| {
            headers
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.clone())
        })
        .unwrap();
        let reauth = || Ok(mac.clone());
        sync::push(&core, &mac, &push, &mut &body[..], &reauth, t0 + 130).unwrap();
        assert_eq!(last_seen(), Some(t0 + 130));

        // A download marks it, and a long poll within the minute does not.
        drop(sync::open_snapshot(&core, &mac, 1, t0 + 200).unwrap());
        assert_eq!(last_seen(), Some(t0 + 200));
        sync::head(&core, &mac, 0, 0, t0 + 210).unwrap();
        assert_eq!(last_seen(), Some(t0 + 200));
        // The device list shows it.
        let listed = list(&core, &mac).unwrap();
        assert_eq!(listed[0]["last_seen_at"], t0 + 200);
    }

    #[test]
    fn enrollment_rechecks_conflicts_after_authentication() {
        let (_dir, core, bearer) = fixture();
        let now = crate::now_unix();
        let owner = crate::server::auth::authenticate_core(&core, bearer.expose(), now)
            .unwrap()
            .member()
            .clone();
        let key = DeviceKey::generate().unwrap();
        let request = DeviceEnroll {
            name: "owner device".into(),
            public_key: key.public_key_b64(),
        };
        enroll(&core, &owner, &request, now).unwrap();
        assert_eq!(
            enroll(&core, &owner, &request, now).unwrap_err().code,
            codes::CONFLICT
        );
        // A different member cannot enroll the same live public key.
        let second = core.store.tx(|conn| {
            conn.execute("INSERT INTO member(name,role,token_hash,created_at) VALUES('member','member',?1,0)", params![vec![1u8; 32]]).map_err(db)?;
            Ok(MemberAuth { id: MemberId(to_u(conn.last_insert_rowid())), name: "member".into(), role: Role::Member, device: None })
        }).unwrap();
        assert_eq!(
            enroll(&core, &second, &request, now).unwrap_err().code,
            codes::CONFLICT
        );
    }
}
