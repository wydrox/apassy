//! Connect groups: Family and Team (ADR 0037 stage 7, unit C3; connect-billing-v1 section
//! 6; docs/SPEC.md section 36).
//!
//! A group is made by the Stripe webhook when a Family or Team subscription is bound
//! (`server::billing`), with the buying account as its active `owner`. Everything else is
//! here: one-use invites of 7 days (`apassy_gin_<group id>_<64 hex>`, only the SHA-256 is
//! stored), the join of an account as `pending`, the confirmation by the owner or an admin
//! (the people or seats of the subscription follow through billing, `409 seat_limit` above
//! the plan's maximum), the removal of a member, and the `Groups` seam of the accounts:
//! the group in `GET /v1/account`, the shared-store check of a device of another account,
//! and the refusal to delete an owner's account while it has confirmed members.
//!
//! Roles: Family has one organizer (`owner`) and `member`s, no admins. Team has `owner`,
//! `admin`s, and `member`s. The owner and admins invite and confirm; only the owner invites
//! or removes an admin; a member may remove itself; the owner cannot be removed. A pending
//! member has no entitlement: billing gives a plan only to active members.

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::api::AccountGroup;
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::TeamId;
use crate::secret::is_connect_id;
use crate::server::account::{AccountCaller, Groups};
use crate::server::auth::Need;
use crate::server::hub::{Hub, StoreRemoval};
use crate::server::store::{Store, db, to_i, to_u};

/// An invite lives 7 days.
pub const INVITE_SECS: u64 = 7 * 86_400;
/// Open invites of one group at most (`403 account_limit`).
pub const MAX_OPEN_INVITES: u64 = 20;
/// The form of an invite code: `apassy_gin_` + group id + `_` + 64 hex.
pub const INVITE_PREFIX: &str = "apassy_gin_";

// ---- Routes. ----

/// The group endpoints under `/v1/account/group` (connect-billing-v1 section 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupEndpoint {
    View,
    Invite,
    Join,
    Confirm(String),
    Remove(String),
    Seats,
}

/// The need and endpoint of a path below `/v1/account/group` (`rest` is the segments after
/// `group`). 404 for an unknown path, 405 for another method.
pub fn route(method: &str, rest: &[&str]) -> RelayResult<(Need, GroupEndpoint)> {
    let not_found = || RelayError::new(codes::NOT_FOUND, "No such path.");
    let pick = |wanted: &str, endpoint: GroupEndpoint| {
        if method == wanted {
            Ok((Need::Account, endpoint))
        } else {
            Err(RelayError::new(
                codes::METHOD_NOT_ALLOWED,
                "This path does not allow this method.",
            ))
        }
    };
    match rest {
        [] => pick("GET", GroupEndpoint::View),
        ["invites"] => pick("POST", GroupEndpoint::Invite),
        ["join"] => pick("POST", GroupEndpoint::Join),
        ["seats"] => pick("POST", GroupEndpoint::Seats),
        ["members", account, "confirm"] if is_connect_id(account, "acc_") => {
            pick("POST", GroupEndpoint::Confirm((*account).to_string()))
        }
        ["members", account] if is_connect_id(account, "acc_") => {
            pick("DELETE", GroupEndpoint::Remove((*account).to_string()))
        }
        _ => Err(not_found()),
    }
}

// ---- Wire types. ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteRequest {
    /// `member` or (Team only, owner only) `admin`.
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteAnswer {
    pub invite_id: u64,
    pub url: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinAnswer {
    pub group_id: String,
    pub kind: String,
    pub state: String,
    pub owner_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberView {
    pub account_id: String,
    pub name: String,
    pub role: String,
    pub state: String,
    pub joined_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupView {
    pub group_id: String,
    pub kind: String,
    pub role: String,
    pub owner_account: String,
    pub included: u32,
    pub quantity: Option<u64>,
    pub members: Vec<MemberView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovedAnswer {
    pub account_id: String,
    pub removed_from_stores: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyBody {}

// ---- Errors. ----

fn not_in_group() -> RelayError {
    RelayError::new(
        codes::NOT_IN_GROUP,
        "This account is not in that family or team.",
    )
}

fn forbidden(message: &str) -> RelayError {
    RelayError::forbidden(message)
}

fn conflict(message: &str) -> RelayError {
    RelayError::new(codes::CONFLICT, message)
}

fn plan_required() -> RelayError {
    RelayError::new(
        codes::PLAN_REQUIRED,
        "This account is not on Apassy Connect.",
    )
}

fn strict<T: for<'de> Deserialize<'de>>(body: &[u8]) -> RelayResult<T> {
    serde_json::from_slice(body)
        .map_err(|_| RelayError::invalid("The request body does not match the contract."))
}

fn to_value<T: Serialize>(value: &T) -> RelayResult<Value> {
    serde_json::to_value(value).map_err(|_| RelayError::internal("The answer cannot be written."))
}

// ---- Rows. ----

/// The group of an account, from `group_member` and `"group"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub group_id: String,
    pub kind: String,
    pub owner: String,
    pub role: String,
    pub state: String,
}

impl Member {
    fn active(&self) -> bool {
        self.state == "active"
    }

    fn manages(&self) -> bool {
        self.active() && (self.role == "owner" || self.role == "admin")
    }
}

/// The membership of `account`, pending or active.
pub fn membership(conn: &Connection, account: &str) -> RelayResult<Option<Member>> {
    conn.query_row(
        "SELECT m.group_id, g.kind, g.owner_account, m.role, m.state FROM group_member m \
         JOIN \"group\" g ON g.id = m.group_id WHERE m.account_id = ?1",
        params![account],
        |row| {
            Ok(Member {
                group_id: row.get(0)?,
                kind: row.get(1)?,
                owner: row.get(2)?,
                role: row.get(3)?,
                state: row.get(4)?,
            })
        },
    )
    .optional()
    .map_err(db)
}

fn member_view(conn: &Connection, group: &str, account: &str) -> RelayResult<MemberView> {
    conn.query_row(
        "SELECT m.account_id, a.name, m.role, m.state, m.joined_at FROM group_member m \
         JOIN account a ON a.id = m.account_id WHERE m.group_id = ?1 AND m.account_id = ?2",
        params![group, account],
        member_from_row,
    )
    .optional()
    .map_err(db)?
    .ok_or_else(|| RelayError::not_found("member"))
}

fn member_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemberView> {
    Ok(MemberView {
        account_id: row.get(0)?,
        name: row.get(1)?,
        role: row.get(2)?,
        state: row.get(3)?,
        joined_at: row.get::<_, Option<i64>>(4)?.map(to_u),
    })
}

/// The other accounts of a group (every state), `account` left out.
fn other_accounts(conn: &Connection, group: &str, account: &str) -> RelayResult<Vec<String>> {
    let mut statement = conn
        .prepare(
            "SELECT account_id FROM group_member WHERE group_id = ?1 AND account_id <> ?2 \
             ORDER BY account_id",
        )
        .map_err(db)?;
    statement
        .query_map(params![group, account], |row| row.get(0))
        .map_err(db)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db)
}

fn active_count(conn: &Connection, group: &str) -> RelayResult<u64> {
    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM group_member WHERE group_id = ?1 AND state = 'active'",
            params![group],
            |row| row.get(0),
        )
        .map_err(db)?;
    Ok(to_u(count))
}

fn included_of(kind: &str) -> u32 {
    if kind == "family" { 4 } else { 1 }
}

fn code_hash(code: &str) -> Vec<u8> {
    Sha256::digest(code.as_bytes()).to_vec()
}

/// The group id of a well-formed invite code, or `None`.
fn parse_code(code: &str) -> Option<&str> {
    let rest = code.strip_prefix(INVITE_PREFIX)?;
    let (group, secret) = rest.split_at_checked(14)?;
    let secret = secret.strip_prefix('_')?;
    (is_connect_id(group, "grp_")
        && secret.len() == 64
        && secret
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(group)
}

fn new_code(group: &str) -> RelayResult<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| RelayError::internal("No randomness."))?;
    Ok(format!(
        "{INVITE_PREFIX}{group}_{}",
        crate::sync_head::hex(&bytes)
    ))
}

// ---- Dispatch. ----

/// One group endpoint for the caller of an account token.
pub fn dispatch(
    hub: &Hub,
    caller: &AccountCaller,
    endpoint: &GroupEndpoint,
    body: &[u8],
    now: u64,
) -> RelayResult<Value> {
    match endpoint {
        GroupEndpoint::View => to_value(&view(hub, caller, now)?),
        GroupEndpoint::Invite => to_value(&invite(hub, caller, &strict(body)?, now)?),
        GroupEndpoint::Join => to_value(&join(hub, caller, &strict(body)?, now)?),
        GroupEndpoint::Confirm(account) => {
            strict::<EmptyBody>(body)?;
            to_value(&confirm(hub, caller, account, now)?)
        }
        GroupEndpoint::Remove(account) => {
            if !body.iter().all(u8::is_ascii_whitespace) {
                strict::<EmptyBody>(body)?;
            }
            to_value(&remove(hub, caller, account, now)?)
        }
        GroupEndpoint::Seats => to_value(&crate::server::account::billing(hub)?.change_seats(
            &caller.account,
            body,
            now,
        )?),
    }
}

/// The plan of the group itself: its subscription of the group's kind with the best
/// state (connect-billing-v1 section 8). Not the owner's own plan: an owner who switched
/// to Personal has a plan, its family has none.
fn group_plan(
    hub: &Hub,
    group: &str,
    now: u64,
) -> RelayResult<Option<crate::server::billing::GroupPlan>> {
    match crate::server::account::billing(hub) {
        Ok(billing) => billing.group_plan(group, now),
        Err(_) => Ok(None),
    }
}

/// Whether the group's plan is entitled now.
fn group_entitled(hub: &Hub, group: &str, now: u64) -> RelayResult<bool> {
    Ok(group_plan(hub, group, now)?.is_some_and(|plan| plan.state.entitled))
}

/// `GET /v1/account/group`: the `GroupView`. A pending member sees the owner and itself.
fn view(hub: &Hub, caller: &AccountCaller, now: u64) -> RelayResult<GroupView> {
    let member = hub
        .directory
        .store
        .with(|conn| membership(conn, &caller.account))?
        .ok_or_else(|| RelayError::not_found("group"))?;
    let quantity = match crate::server::account::billing(hub) {
        Ok(billing) => billing
            .group_quantity(&member.group_id, now)?
            .map(u64::from),
        Err(_) => None,
    };
    hub.directory.store.with(|conn| {
        let mut statement = conn
            .prepare(
                "SELECT m.account_id, a.name, m.role, m.state, m.joined_at FROM group_member m \
                 JOIN account a ON a.id = m.account_id WHERE m.group_id = ?1 \
                 ORDER BY m.role = 'owner' DESC, m.created_at, m.account_id",
            )
            .map_err(db)?;
        let mut members = statement
            .query_map(params![member.group_id], member_from_row)
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)?;
        if !member.active() {
            members.retain(|m| m.role == "owner" || m.account_id == caller.account);
        }
        Ok(GroupView {
            group_id: member.group_id.clone(),
            kind: member.kind.clone(),
            role: member.role.clone(),
            owner_account: member.owner.clone(),
            included: included_of(&member.kind),
            quantity,
            members,
        })
    })
}

/// `POST /v1/account/group/invites`: by the owner or an admin of an entitled group.
fn invite(
    hub: &Hub,
    caller: &AccountCaller,
    request: &InviteRequest,
    now: u64,
) -> RelayResult<InviteAnswer> {
    let member = hub
        .directory
        .store
        .with(|conn| membership(conn, &caller.account))?
        .filter(Member::active)
        .ok_or_else(not_in_group)?;
    if !member.manages() {
        return Err(forbidden("The owner or an admin invites."));
    }
    match request.role.as_str() {
        "member" => {}
        "admin" if member.kind == "family" => return Err(forbidden("A family has no admins.")),
        "admin" if member.role != "owner" => {
            return Err(forbidden("Only the owner invites an admin."));
        }
        "admin" => {}
        _ => return Err(RelayError::invalid("The role is member or admin.")),
    }
    if !group_entitled(hub, &member.group_id, now)? {
        return Err(plan_required());
    }
    let code = new_code(&member.group_id)?;
    let expires_at = now + INVITE_SECS;
    let invite_id = hub.directory.store.tx(|tx| {
        let open: i64 = tx
            .query_row(
                "SELECT count(*) FROM group_invite WHERE group_id = ?1 AND used_at IS NULL \
                 AND expires_at > ?2",
                params![member.group_id, to_i(now)],
                |row| row.get(0),
            )
            .map_err(db)?;
        if to_u(open) >= MAX_OPEN_INVITES {
            return Err(RelayError::new(
                codes::ACCOUNT_LIMIT,
                "This group has 20 open invites.",
            ));
        }
        tx.execute(
            "INSERT INTO group_invite (group_id, code_hash, role, created_by, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                member.group_id,
                code_hash(&code),
                request.role,
                caller.account,
                to_i(now),
                to_i(expires_at)
            ],
        )
        .map_err(db)?;
        let id = tx.last_insert_rowid();
        hub.directory.audit.write_on(
            tx,
            now,
            &format!("account:{}", caller.account),
            "group_invite_made",
            None,
            &json!({"group_id": member.group_id, "invite_id": id, "role": request.role}),
        )?;
        Ok(to_u(id))
    })?;
    Ok(InviteAnswer {
        invite_id,
        url: format!(
            "{}/connect/join#{code}",
            hub.config.connect.site_url.trim_end_matches('/')
        ),
        expires_at,
    })
}

/// `POST /v1/account/group/join`: the invited account joins as `pending`. A used,
/// expired, or unknown code is 403; an account in a group or with an entitled plan of its
/// own is 409. The same code again by the account that used it answers the same.
fn join(
    hub: &Hub,
    caller: &AccountCaller,
    request: &JoinRequest,
    now: u64,
) -> RelayResult<JoinAnswer> {
    let group = parse_code(&request.code)
        .ok_or_else(|| RelayError::invalid("The invite code is not valid."))?
        .to_string();
    let invalid = || forbidden("The invite is not valid, used, or expired.");
    let hash = code_hash(&request.code);
    // A repeat after a lost answer.
    let repeat = hub.directory.store.with(|conn| {
        let used_by: Option<Option<String>> = conn
            .query_row(
                "SELECT used_by FROM group_invite WHERE code_hash = ?1 AND group_id = ?2",
                params![hash, group],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        Ok(
            used_by.flatten().as_deref() == Some(caller.account.as_str())
                && membership(conn, &caller.account)?
                    .is_some_and(|m| m.group_id == group && !m.active()),
        )
    })?;
    if !repeat {
        if hub
            .directory
            .store
            .with(|conn| membership(conn, &caller.account))?
            .is_some()
        {
            return Err(conflict("This account is in a family or team already."));
        }
        if hub
            .accounts
            .plans()
            .plan(&hub.directory.store, &caller.account, now)?
            .entitled
        {
            return Err(conflict(
                "This account has a plan of its own. End it before it joins a family or team.",
            ));
        }
        hub.directory.store.tx(|tx| {
            let row: Option<(i64, String, Option<i64>, i64)> = tx
                .query_row(
                    "SELECT id, role, used_at, expires_at FROM group_invite \
                     WHERE code_hash = ?1 AND group_id = ?2",
                    params![hash, group],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(db)?;
            let Some((id, role, None, expires_at)) = row else {
                return Err(invalid());
            };
            if to_u(expires_at) <= now {
                return Err(invalid());
            }
            if membership(tx, &caller.account)?.is_some() {
                return Err(conflict("This account is in a family or team already."));
            }
            tx.execute(
                "UPDATE group_invite SET used_at = ?2, used_by = ?3 WHERE id = ?1",
                params![id, to_i(now), caller.account],
            )
            .map_err(db)?;
            tx.execute(
                "INSERT INTO group_member (group_id, account_id, role, state, created_at) \
                 VALUES (?1, ?2, ?3, 'pending', ?4)",
                params![group, caller.account, role, to_i(now)],
            )
            .map_err(db)?;
            tx.execute(
                "UPDATE account SET group_id = ?2 WHERE id = ?1",
                params![caller.account, group],
            )
            .map_err(db)?;
            hub.directory.audit.write_on(
                tx,
                now,
                &format!("account:{}", caller.account),
                "group_joined",
                None,
                &json!({"group_id": group, "invite_id": id, "state": "pending"}),
            )
        })?;
        // A checkout the account opened before it joined ends at Stripe: a plan bought
        // now could not bind to a group of its own.
        // The join is made: a session that cannot be ended now is logged, and a
        // subscription it makes later is recorded for the operator when it cannot bind.
        if let Ok(billing) = crate::server::account::billing(hub)
            && billing.end_open_checkout(&caller.account, now).is_err()
        {
            billing.log(&format!(
                "the open checkout of {} could not be ended after its join",
                caller.account
            ));
        }
    }
    hub.directory.store.with(|conn| {
        let (kind, owner_name): (String, String) = conn
            .query_row(
                "SELECT g.kind, a.name FROM \"group\" g JOIN account a ON a.id = g.owner_account \
                 WHERE g.id = ?1",
                params![group],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(db)?;
        Ok(JoinAnswer {
            group_id: group.clone(),
            kind,
            state: "pending".to_string(),
            owner_name,
        })
    })
}

/// `POST /v1/account/group/members/{account}/confirm`: the owner or an admin makes a
/// pending member active. Under the lock of the group (`Billing::with_group_lock`), in
/// this order: the group's plan must be entitled; the active members are counted with the
/// new one (`409 seat_limit` above the plan's maximum); the member becomes active; when
/// the count exceeds the quantity at Stripe (the stored one, or one Stripe accepted from
/// Connect since), billing asks Stripe for the count, and when Stripe refuses the member
/// is pending again. Stripe's webhook then applies the quantity.
fn confirm(hub: &Hub, caller: &AccountCaller, target: &str, now: u64) -> RelayResult<MemberView> {
    let member = hub
        .directory
        .store
        .with(|conn| membership(conn, &caller.account))?
        .filter(Member::active)
        .ok_or_else(not_in_group)?;
    if !member.manages() {
        return Err(forbidden("The owner or an admin confirms a member."));
    }
    let other = hub
        .directory
        .store
        .with(|conn| membership(conn, target))?
        .filter(|m| m.group_id == member.group_id)
        .ok_or_else(|| RelayError::not_found("member"))?;
    if other.active() {
        return hub
            .directory
            .store
            .with(|conn| member_view(conn, &member.group_id, target));
    }
    let billing = crate::server::account::billing(hub).map_err(|_| plan_required())?;
    billing.with_group_lock(&member.group_id, |locked| {
        let plan = billing
            .group_plan(&member.group_id, now)?
            .filter(|plan| plan.state.entitled)
            .ok_or_else(plan_required)?;
        let active = hub
            .directory
            .store
            .with(|conn| active_count(conn, &member.group_id))?;
        let wanted = u32::try_from(active + 1).unwrap_or(u32::MAX);
        crate::server::billing::check_count(plan.plan, wanted)?;
        let activated = hub.directory.store.tx(|tx| {
            let changed = tx
                .execute(
                    "UPDATE group_member SET state = 'active', joined_at = ?3 \
                     WHERE group_id = ?1 AND account_id = ?2 AND state = 'pending'",
                    params![member.group_id, target, to_i(now)],
                )
                .map_err(db)?;
            if changed == 1 {
                hub.directory.audit.write_on(
                    tx,
                    now,
                    &format!("account:{}", caller.account),
                    "group_member_confirmed",
                    None,
                    &json!({"group_id": member.group_id, "account_id": target}),
                )?;
            }
            Ok(changed == 1)
        })?;
        if activated
            && wanted > plan.quantity
            && let Err(error) = billing.request_quantity_locked(locked, wanted, now)
        {
            hub.directory.store.tx(|tx| {
                let changed = tx
                    .execute(
                        "UPDATE group_member SET state = 'pending', joined_at = NULL \
                         WHERE group_id = ?1 AND account_id = ?2 AND state = 'active'",
                        params![member.group_id, target],
                    )
                    .map_err(db)?;
                if changed == 1 {
                    hub.directory.audit.write_on(
                        tx,
                        now,
                        &format!("account:{}", caller.account),
                        "group_member_confirm_undone",
                        None,
                        &json!({"group_id": member.group_id, "account_id": target,
                                "code": error.code}),
                    )?;
                }
                Ok(())
            })?;
            return Err(error);
        }
        hub.directory
            .store
            .with(|conn| member_view(conn, &member.group_id, target))
    })
}

/// `DELETE /v1/account/group/members/{account}`: the owner or an admin removes a member
/// (only the owner an admin), or a member removes itself; the owner cannot be removed. The
/// removed account keeps a free account; its devices leave the stores of the group's
/// other accounts, theirs leave its stores, and the tunnel grants between it and the group
/// end. The membership and the store rows go in one transaction, with a waiting removal
/// for each store file; the files take them after the commit, at their next open, or at a
/// maintenance pass.
fn remove(hub: &Hub, caller: &AccountCaller, target: &str, now: u64) -> RelayResult<RemovedAnswer> {
    let member = hub
        .directory
        .store
        .with(|conn| membership(conn, &caller.account))?
        .ok_or_else(not_in_group)?;
    let other = if target == caller.account {
        if member.role == "owner" {
            return Err(forbidden("The owner cannot leave its own family or team."));
        }
        member.clone()
    } else {
        if !member.manages() {
            return Err(if member.active() {
                forbidden("The owner or an admin removes a member.")
            } else {
                not_in_group()
            });
        }
        let other = hub
            .directory
            .store
            .with(|conn| membership(conn, target))?
            .filter(|m| m.group_id == member.group_id)
            .ok_or_else(|| RelayError::not_found("member"))?;
        if other.role == "owner" {
            return Err(forbidden("The owner cannot be removed."));
        }
        if other.role == "admin" && member.role != "owner" {
            return Err(forbidden("Only the owner removes an admin."));
        }
        other
    };
    let others = hub
        .directory
        .store
        .with(|conn| other_accounts(conn, &other.group_id, target))?;
    crate::server::billing_store::tunnel_grants_end(hub, target, &others, now)?;
    let (removals, removed_from_stores) = hub.directory.store.tx(|tx| {
        let (removals, removed_from_stores) = queue_group_store_removals(tx, target, &others, now)?;
        tx.execute(
            "DELETE FROM group_member WHERE group_id = ?1 AND account_id = ?2",
            params![other.group_id, target],
        )
        .map_err(db)?;
        tx.execute(
            "UPDATE account SET group_id = NULL WHERE id = ?1",
            params![target],
        )
        .map_err(db)?;
        hub.directory.audit.write_on(
            tx,
            now,
            &format!("account:{}", caller.account),
            "group_member_removed",
            None,
            &json!({"group_id": other.group_id, "account_id": target,
                    "removed_from_stores": removed_from_stores}),
        )?;
        Ok((removals, removed_from_stores))
    })?;
    hub.apply_removals(&removals, now);
    Ok(RemovedAnswer {
        account_id: target.to_string(),
        removed_from_stores,
    })
}

/// The devices of `account` leave the vault stores of `others`, and the devices of
/// `others` leave the stores of `account`, inside the transaction `tx` of the removal: the
/// store rows go with a waiting removal for each store file
/// (`hub::queue_store_removal`). Answers the removals and how many device rows of
/// `account` left.
fn queue_group_store_removals(
    tx: &Connection,
    account: &str,
    others: &[String],
    now: u64,
) -> RelayResult<(Vec<StoreRemoval>, u64)> {
    let rows: Vec<(String, String, String, String, i64)> = {
        let mut statement = tx
            .prepare(
                "SELECT s.team_id, t.account_id, s.device_id, s.account_id, s.store_device \
                 FROM account_store_device s JOIN team t ON t.id = s.team_id \
                 WHERE t.kind = 'account' AND (s.account_id = ?1 OR t.account_id = ?1) \
                 ORDER BY s.team_id, s.store_device",
            )
            .map_err(db)?;
        statement
            .query_map(params![account], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)?
    };
    let mut removals = Vec::new();
    let mut left = 0;
    for (team, owner, device, device_account, store_device) in rows {
        let theirs = device_account == account && others.contains(&owner);
        let ours = owner == account && others.contains(&device_account);
        if !(theirs || ours) {
            continue;
        }
        let Some(team) = TeamId::parse(&team) else {
            continue;
        };
        let removal = StoreRemoval {
            team,
            device,
            store_device: to_u(store_device),
        };
        crate::server::hub::queue_store_removal(tx, &removal, now)?;
        removals.push(removal);
        if theirs {
            left += 1;
        }
    }
    Ok((removals, left))
}

/// The group rows of an account that is deleted (in the transaction of `DELETE
/// /v1/account`): its membership goes; for an owner (who has no confirmed members, or the
/// deletion was refused) the group, its pending members, and its invites go too.
pub(crate) fn forget_account(conn: &Connection, account: &str) -> RelayResult<()> {
    for sql in [
        "UPDATE account SET group_id = NULL WHERE group_id IN \
         (SELECT id FROM \"group\" WHERE owner_account = ?1)",
        "DELETE FROM group_invite WHERE group_id IN \
         (SELECT id FROM \"group\" WHERE owner_account = ?1)",
        "DELETE FROM group_member WHERE group_id IN \
         (SELECT id FROM \"group\" WHERE owner_account = ?1)",
        "DELETE FROM \"group\" WHERE owner_account = ?1",
        "DELETE FROM group_member WHERE account_id = ?1",
    ] {
        conn.execute(sql, params![account]).map_err(db)?;
    }
    Ok(())
}

// ---- The seam of the accounts. ----

/// The `Groups` seam of the accounts, on the directory tables.
pub struct DirectoryGroups;

impl Groups for DirectoryGroups {
    fn group_of(
        &self,
        directory: &Store,
        account: &str,
        _now: u64,
    ) -> RelayResult<Option<AccountGroup>> {
        Ok(directory
            .with(|conn| membership(conn, account))?
            .map(|member| AccountGroup {
                group_id: member.group_id,
                kind: member.kind,
                role: member.role,
                state: member.state,
            }))
    }

    /// Both accounts are active members of one group.
    fn share_group(
        &self,
        directory: &Store,
        account: &str,
        other: &str,
        _now: u64,
    ) -> RelayResult<bool> {
        directory.with(|conn| {
            let (Some(a), Some(b)) = (membership(conn, account)?, membership(conn, other)?) else {
                return Ok(false);
            };
            Ok(a.active() && b.active() && a.group_id == b.group_id)
        })
    }

    /// An owner with confirmed members.
    fn blocks_deletion(&self, directory: &Store, account: &str, _now: u64) -> RelayResult<bool> {
        directory.with(|conn| {
            let Some(member) = membership(conn, account)? else {
                return Ok(false);
            };
            Ok(member.role == "owner" && active_count(conn, &member.group_id)? > 1)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_and_codes() {
        assert_eq!(route("GET", &[]).unwrap().1, GroupEndpoint::View);
        assert_eq!(
            route("POST", &["invites"]).unwrap().1,
            GroupEndpoint::Invite
        );
        assert_eq!(
            route("POST", &["members", "acc_k7m2q4x3ca", "confirm"])
                .unwrap()
                .1,
            GroupEndpoint::Confirm("acc_k7m2q4x3ca".into())
        );
        assert_eq!(
            route("DELETE", &["members", "acc_k7m2q4x3ca"]).unwrap().1,
            GroupEndpoint::Remove("acc_k7m2q4x3ca".into())
        );
        assert_eq!(
            route("GET", &["seats"]).unwrap_err().code,
            codes::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            route("DELETE", &["members", "acc_X"]).unwrap_err().code,
            codes::NOT_FOUND
        );
        let code = new_code("grp_k7m2q4x3ca").unwrap();
        assert_eq!(parse_code(&code), Some("grp_k7m2q4x3ca"));
        assert_eq!(code.len(), INVITE_PREFIX.len() + 14 + 1 + 64);
        assert_eq!(parse_code("apassy_gin_grp_k7m2q4x3ca_00"), None);
        assert_eq!(
            parse_code(&code.replace("apassy_gin_", "apassy_gim_")),
            None
        );
        assert_eq!(parse_code(&format!("{code}0")), None);
    }
}
