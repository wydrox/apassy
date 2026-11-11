//! The directory of the relay: `relay.db` (ADR 0019, docs/SPEC.md "Teams").
//!
//! One SQLCipher file, keyed with the master key. It holds the teams (public id, name,
//! kind, state, and the random key of each team file), the one-time team codes of the
//! operator, the hashes of the device keys that made Connect teams (section 26), and the
//! audit of the relay: operator actions, and refused requests that name no known team.
//! Since version 1004 it also holds the OAuth state of an embedded node (docs/SPEC.md
//! section 31): registered clients, connect requests, and refresh tokens, with codes and
//! refresh tokens as hashes only. Since version 1005 each team code has a kind:
//! `operator` (`apassy-relay admin team-code`) or `node` (`apassy pair` on a node, ten
//! minutes, docs/SPEC.md section 32). It holds no people, no items, and no runs: those are
//! in the file of each team.

use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::api::TeamKind;
use crate::config::RelayConfig;
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::TeamId;
use crate::secret::{SecretString, TokenKind, new_team_code, parse_token, token_hash};
use crate::server::audit::Audit;
use crate::server::store::{Store, db, to_i, to_u};

/// `PRAGMA user_version` of the directory. Far from the team versions, so one file is
/// never taken for the other. Since 1006 it holds the accounts of Apassy Connect
/// (`MIGRATE_ACCOUNTS`). The step of the accounts is this one constant: a parallel plan
/// that lands a directory step first renumbers it to the next free version.
pub const DIRECTORY_VERSION: i64 = 1006;
/// The version before the accounts step.
pub const BEFORE_ACCOUNTS_VERSION: i64 = DIRECTORY_VERSION - 1;

/// The schema of version 1005, without its version line: a new file runs it and then
/// `MIGRATE_ACCOUNTS`, so a new file and a migrated one have the same schema text.
const SCHEMA_1005: &str = "
CREATE TABLE team (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, file_key TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('active','suspended')),
  legacy INTEGER NOT NULL DEFAULT 0 CHECK (legacy IN (0, 1)),
  created_at INTEGER NOT NULL, suspended_at INTEGER, limits TEXT,
  kind TEXT NOT NULL DEFAULT 'operator' CHECK (kind IN ('operator','connect')),
  suspend_reason TEXT);
CREATE UNIQUE INDEX team_legacy ON team(legacy) WHERE legacy = 1;
CREATE TABLE team_code (
  id INTEGER PRIMARY KEY, code_hash BLOB NOT NULL UNIQUE, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, used_at INTEGER, team_id TEXT);
CREATE TABLE audit (
  id INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  run_id INTEGER, detail TEXT NOT NULL);
CREATE TABLE connect_key (
  key_hash BLOB PRIMARY KEY, team_id TEXT, created_at INTEGER NOT NULL);
CREATE INDEX connect_key_created ON connect_key(created_at);
CREATE TABLE oauth_client (
  client_id TEXT PRIMARY KEY, client_name TEXT, redirect_uris TEXT NOT NULL,
  created_at INTEGER NOT NULL, used_at INTEGER);
CREATE INDEX oauth_client_created ON oauth_client(created_at);
CREATE TABLE connect_request (
  id TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, state TEXT,
  code_challenge TEXT NOT NULL, match_code TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','allowed','denied','expired','redeemed')),
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, decided_at INTEGER,
  team_id TEXT, agent_id INTEGER, code_hash BLOB UNIQUE, code_expires_at INTEGER);
CREATE INDEX connect_request_client ON connect_request(client_id);
CREATE TABLE oauth_refresh (
  token_hash BLOB PRIMARY KEY, family TEXT NOT NULL, client_id TEXT NOT NULL,
  team_id TEXT NOT NULL, agent_id INTEGER NOT NULL, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, used_at INTEGER, revoked_at INTEGER);
CREATE INDEX oauth_refresh_family ON oauth_refresh(family);
CREATE INDEX oauth_refresh_agent ON oauth_refresh(team_id, agent_id);
ALTER TABLE team_code ADD COLUMN kind TEXT NOT NULL DEFAULT 'operator' CHECK (kind IN ('operator','node'));
";

/// Version 1005 to `DIRECTORY_VERSION` (docs/SPEC.md section 33, connect-account-v1
/// section 12, plan s7 decision 1): Apassy Connect, additive for every row of 1005, in one
/// transaction. Every table of stage 7 is here, so billing (C2), groups (C3), and the
/// tunnel (C4) need no step of their own:
///
/// - `team` gains the kind `account` (a vault store, one relay-sync team for each vault)
///   and `account_id`, `vault_id`. SQLite cannot widen a CHECK in place, so the table is
///   rebuilt with the same rows; the index `team_legacy` is made again.
/// - `account` (with the public recovery key and the last recovery, for its retry),
///   `account_id_used` (every account id that an account ever had, written with the
///   account and never deleted: an id is used once, so no later account meets the
///   billing, tunnel, or key rows of an earlier one),
///   `account_device` (with the device that added it, `added_by`; none for a root),
///   `account_list` (the signed device list of each account: one row for each entry,
///   from the root at version 1, with the device name it signs and its signature; a
///   recovery starts it again), `account_key` (the SHA-256
///   of every key that was ever
///   a device of an account, and that account: one key makes at most one account, also
///   after a deletion), `account_link`, `account_join`, `account_store_device` (which
///   account device is which device of which store), `account_store_removal` (removals
///   from a store file that wait for its open or a retry), `brain_event` (the I-4 outbox
///   of the bouncer brain).
/// - `account_list` also holds the entries that name another account (section 16: `peer`
///   with the pinned root, `share` and `join` with the store, and their ends), and
///   `account_peer_link`, `account_peer_join` hold the hashes of share codes and their
///   answers (pruned a day after they end).
/// - `"group"`, `group_member`, `group_invite` (C3); `stripe_customer`,
///   `stripe_subscription`, `stripe_event`, `billing_problem` (Stripe objects Connect
///   could not apply, for the operator), `billing_clock` (the clock of the deletion
///   pass) (C2); `tunnel_node`, `tunnel_grant`,
///   `tunnel_usage` (C4); `entitlement_key` (kids and public keys only).
///
/// Nothing here is secret: public keys, names, ids, hashes, and Stripe ids. Tokens, link
/// codes, recovery codes, and the signing key are never stored.
const MIGRATE_ACCOUNTS: &str = "
CREATE TABLE team_accounts (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, file_key TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('active','suspended')),
  legacy INTEGER NOT NULL DEFAULT 0 CHECK (legacy IN (0, 1)),
  created_at INTEGER NOT NULL, suspended_at INTEGER, limits TEXT,
  kind TEXT NOT NULL DEFAULT 'operator' CHECK (kind IN ('operator','connect','account')),
  suspend_reason TEXT, account_id TEXT, vault_id TEXT,
  CHECK ((kind = 'account') = (account_id IS NOT NULL AND vault_id IS NOT NULL)));
INSERT INTO team_accounts (id, name, file_key, state, legacy, created_at, suspended_at, limits, kind, suspend_reason)
  SELECT id, name, file_key, state, legacy, created_at, suspended_at, limits, kind, suspend_reason FROM team;
DROP TABLE team;
ALTER TABLE team_accounts RENAME TO team;
CREATE UNIQUE INDEX team_legacy ON team(legacy) WHERE legacy = 1;
CREATE UNIQUE INDEX team_vault ON team(account_id, vault_id) WHERE kind = 'account';
CREATE TABLE account (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL,
  recovery_key BLOB NOT NULL, create_hash BLOB NOT NULL, email TEXT, group_id TEXT,
  recover_hash BLOB, recovered_at INTEGER, recover_device TEXT, recover_deleted INTEGER);
CREATE INDEX account_created ON account(created_at);
CREATE TABLE account_id_used (id TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
CREATE TABLE account_device (
  id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  name TEXT NOT NULL, platform TEXT NOT NULL CHECK (platform IN ('mac','iphone','linux')),
  public_key BLOB NOT NULL UNIQUE, created_at INTEGER NOT NULL, last_seen_at INTEGER,
  revoked_at INTEGER, added_by TEXT);
CREATE INDEX account_device_account ON account_device(account_id);
CREATE TABLE account_list (
  account_id TEXT NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  op TEXT NOT NULL CHECK (op IN ('root','add','remove','peer','unpeer','share','unshare','join','leave')),
  key BLOB, link_hash TEXT, name TEXT, by_key BLOB NOT NULL, signature BLOB NOT NULL,
  hash TEXT NOT NULL, created_at INTEGER NOT NULL, peer_account TEXT, peer_root BLOB, team_id TEXT,
  PRIMARY KEY (account_id, version),
  CHECK ((op IN ('root','add','remove')) = (key IS NOT NULL AND peer_account IS NULL)));
CREATE INDEX account_list_peer ON account_list(account_id, peer_account) WHERE peer_account IS NOT NULL;
CREATE INDEX account_list_team ON account_list(team_id) WHERE team_id IS NOT NULL;
CREATE TABLE account_key (
  key_hash BLOB PRIMARY KEY, created_at INTEGER NOT NULL, account_id TEXT);
CREATE TABLE account_store_removal (
  team_id TEXT NOT NULL, store_device INTEGER NOT NULL, device_id TEXT NOT NULL,
  created_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_at INTEGER NOT NULL,
  PRIMARY KEY (team_id, store_device));
CREATE INDEX account_store_removal_next ON account_store_removal(next_at);
CREATE TABLE account_link (
  id INTEGER PRIMARY KEY, account_id TEXT NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL REFERENCES account_device(id) ON DELETE CASCADE,
  link_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  used_at INTEGER);
CREATE INDEX account_link_device ON account_link(device_id);
CREATE TABLE account_join (
  id INTEGER PRIMARY KEY, link_id INTEGER NOT NULL REFERENCES account_link(id) ON DELETE CASCADE,
  account_id TEXT NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  name TEXT NOT NULL, platform TEXT NOT NULL CHECK (platform IN ('mac','iphone','linux')),
  public_key BLOB NOT NULL, signature BLOB NOT NULL, body_hash BLOB NOT NULL UNIQUE,
  state TEXT NOT NULL CHECK (state IN ('pending','confirmed','refused','cancelled','expired')),
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, decided_at INTEGER,
  device_id TEXT);
CREATE INDEX account_join_key ON account_join(public_key);
CREATE TABLE account_store_device (
  team_id TEXT NOT NULL, device_id TEXT NOT NULL, account_id TEXT NOT NULL,
  store_device INTEGER NOT NULL, added_at INTEGER NOT NULL, PRIMARY KEY (team_id, device_id));
CREATE INDEX account_store_device_device ON account_store_device(device_id);
CREATE INDEX account_store_device_account ON account_store_device(account_id);
CREATE TABLE brain_event (
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('revoke','forget')),
  subject TEXT NOT NULL, created_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
  next_at INTEGER NOT NULL, done_at INTEGER);
CREATE INDEX brain_event_next ON brain_event(next_at) WHERE done_at IS NULL;
CREATE TABLE \"group\" (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('family','team')),
  owner_account TEXT NOT NULL, subscription_id TEXT, created_at INTEGER NOT NULL);
CREATE TABLE group_member (
  group_id TEXT NOT NULL, account_id TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('owner','admin','member')),
  state TEXT NOT NULL CHECK (state IN ('pending','active')),
  created_at INTEGER NOT NULL, joined_at INTEGER, PRIMARY KEY (group_id, account_id));
CREATE TABLE group_invite (
  id INTEGER PRIMARY KEY, group_id TEXT NOT NULL, code_hash BLOB NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('admin','member')), created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER, used_by TEXT);
CREATE TABLE stripe_customer (
  customer_id TEXT PRIMARY KEY, account_id TEXT NOT NULL UNIQUE, email TEXT,
  created_at INTEGER NOT NULL, checkout_session TEXT, checkout_request TEXT,
  checkout_expires_at INTEGER);
CREATE TABLE stripe_subscription (
  subscription_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, item_id TEXT,
  account_id TEXT, group_id TEXT, lookup_key TEXT, quantity INTEGER, status TEXT NOT NULL,
  current_period_end INTEGER, cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
  first_failure_at INTEGER, ended_at INTEGER, event_created INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL, last_invoice_created INTEGER NOT NULL DEFAULT 0,
  stores_deleted_at INTEGER, requested_quantity INTEGER, requested_at INTEGER,
  kind_left_at INTEGER, checked_at INTEGER);
CREATE INDEX stripe_subscription_account ON stripe_subscription(account_id);
CREATE INDEX stripe_subscription_group ON stripe_subscription(group_id);
CREATE TABLE stripe_event (
  id TEXT PRIMARY KEY, type TEXT NOT NULL, received_at INTEGER NOT NULL);
CREATE INDEX stripe_event_received ON stripe_event(received_at);
CREATE TABLE billing_problem (
  id INTEGER PRIMARY KEY, object_id TEXT NOT NULL UNIQUE, account_id TEXT, customer_id TEXT,
  event_id TEXT, reason TEXT NOT NULL, first_at INTEGER NOT NULL, last_at INTEGER NOT NULL,
  events INTEGER NOT NULL DEFAULT 1, resolved_at INTEGER);
CREATE TABLE billing_clock (
  id INTEGER PRIMARY KEY CHECK (id = 1), last_pass_at INTEGER, stripe_time INTEGER,
  held_since INTEGER);
CREATE TABLE tunnel_node (
  id TEXT PRIMARY KEY, account_id TEXT NOT NULL, device_id TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL, pin TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX tunnel_node_account ON tunnel_node(account_id);
CREATE TABLE tunnel_grant (
  id TEXT PRIMARY KEY, node_id TEXT NOT NULL, account_id TEXT NOT NULL,
  granted_by TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE (node_id, account_id));
CREATE INDEX tunnel_grant_account ON tunnel_grant(account_id);
CREATE TABLE tunnel_usage (
  account_id TEXT NOT NULL, month TEXT NOT NULL, dials INTEGER NOT NULL DEFAULT 0,
  streams INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (account_id, month));
CREATE TABLE entitlement_key (
  kid TEXT PRIMARY KEY, public_key BLOB NOT NULL, created_at INTEGER NOT NULL,
  last_signed_at INTEGER);
CREATE TABLE account_peer_link (
  id INTEGER PRIMARY KEY, account_id TEXT NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL REFERENCES account_device(id) ON DELETE CASCADE,
  peer_account TEXT NOT NULL, link_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, used_at INTEGER);
CREATE INDEX account_peer_link_device ON account_peer_link(device_id);
CREATE TABLE account_peer_join (
  id INTEGER PRIMARY KEY, link_id INTEGER NOT NULL REFERENCES account_peer_link(id) ON DELETE CASCADE,
  account_id TEXT NOT NULL, device_id TEXT NOT NULL, public_key BLOB NOT NULL,
  signature BLOB NOT NULL, body_hash BLOB NOT NULL UNIQUE,
  state TEXT NOT NULL CHECK (state IN ('pending','confirmed','refused','cancelled','expired')),
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, decided_at INTEGER);
CREATE INDEX account_peer_join_account ON account_peer_join(account_id);
";

/// The SQL of a new directory: `SCHEMA_1005`, then `MIGRATE_ACCOUNTS`, then the version.
fn schema() -> String {
    format!("{SCHEMA_1005}{MIGRATE_ACCOUNTS}PRAGMA user_version = {DIRECTORY_VERSION};")
}

/// `DIRECTORY_VERSION` back to 1005 (`downgrade_to_1005`, docs/OPERATIONS.md section 26.3):
/// the vault stores go from `team` (an image of 1005 cannot read the kind `account`); the
/// caller deletes their files after the commit. Every other table and column stays: the
/// image of 1005 never reads them, and the next open of this version keeps them.
const DOWNGRADE_1005: &str = "
DELETE FROM account_store_device;
DELETE FROM account_store_removal;
DELETE FROM team WHERE kind = 'account';
PRAGMA user_version = 1005;
";

/// Version 1004 to 1005 (docs/SPEC.md section 32.6): the kind of a team code, additive.
/// Every existing code is `operator`. The same text as the last table line of `SCHEMA`,
/// so a migrated file has the schema of a new one. A file that `downgrade_to_1004` took
/// back has the column already: it stays (`migrate_1005`).
const KIND_1005: &str = "
ALTER TABLE team_code ADD COLUMN kind TEXT NOT NULL DEFAULT 'operator' CHECK (kind IN ('operator','node'));
";

/// Version 1005 back to 1004 (`downgrade_to_1004`, docs/OPERATIONS.md section 25.3): the
/// unused node codes go, so the image of 1004 cannot take one for an operator code; the
/// column stays, and that image never reads it.
const DOWNGRADE_1004: &str = "
DELETE FROM team_code WHERE kind = 'node' AND used_at IS NULL;
PRAGMA user_version = 1004;
";

/// Version 1003 to 1004 (docs/SPEC.md section 31.8): additive, in one transaction. The
/// OAuth state of an embedded node; the hosted relay keeps the tables empty.
const MIGRATE_1004: &str = "
CREATE TABLE oauth_client (
  client_id TEXT PRIMARY KEY, client_name TEXT, redirect_uris TEXT NOT NULL,
  created_at INTEGER NOT NULL, used_at INTEGER);
CREATE INDEX oauth_client_created ON oauth_client(created_at);
CREATE TABLE connect_request (
  id TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, state TEXT,
  code_challenge TEXT NOT NULL, match_code TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','allowed','denied','expired','redeemed')),
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, decided_at INTEGER,
  team_id TEXT, agent_id INTEGER, code_hash BLOB UNIQUE, code_expires_at INTEGER);
CREATE INDEX connect_request_client ON connect_request(client_id);
CREATE TABLE oauth_refresh (
  token_hash BLOB PRIMARY KEY, family TEXT NOT NULL, client_id TEXT NOT NULL,
  team_id TEXT NOT NULL, agent_id INTEGER NOT NULL, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, used_at INTEGER, revoked_at INTEGER);
CREATE INDEX oauth_refresh_family ON oauth_refresh(family);
CREATE INDEX oauth_refresh_agent ON oauth_refresh(team_id, agent_id);
PRAGMA user_version = 1004;
";

/// Version 1004 back to 1003 (`downgrade_to_1003`, docs/OPERATIONS.md section 24): the
/// OAuth tables go, in one transaction. Every other table is as 1003 made it.
const DOWNGRADE_1003: &str = "
DROP TABLE oauth_refresh;
DROP TABLE connect_request;
DROP TABLE oauth_client;
PRAGMA user_version = 1003;
";

/// Version 1002 to 1003 (docs/SPEC.md section 26): additive, in one transaction. Every
/// existing team becomes `operator`.
const MIGRATE_1003: &str = "
ALTER TABLE team ADD COLUMN kind TEXT NOT NULL DEFAULT 'operator' CHECK (kind IN ('operator','connect'));
ALTER TABLE team ADD COLUMN suspend_reason TEXT;
CREATE TABLE connect_key (
  key_hash BLOB PRIMARY KEY, team_id TEXT, created_at INTEGER NOT NULL);
CREATE INDEX connect_key_created ON connect_key(created_at);
PRAGMA user_version = 1003;
";

/// `suspend_reason` of a team that `admin connect-sweep` suspended. A later sweep
/// deletes only such teams.
pub const IDLE_REASON: &str = "idle";

/// The actor of an operator action, in the directory and in the team's own audit.
pub const OPERATOR_ACTOR: &str = "operator";

/// The longest life of a team code, in hours.
pub const MAX_TEAM_CODE_HOURS: u64 = 720;

/// The longest life of a node pairing code, in minutes (node-pairing-v1 section 6).
pub const MAX_NODE_CODE_MINUTES: u64 = 10;

/// The kind of a team code (`team_code.kind`, directory 1005).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeKind {
    /// Made by the operator (`apassy-relay admin team-code`): works on any relay.
    Operator,
    /// A node pairing code (`apassy pair`, node-pairing-v1 section 6): one use, at most
    /// ten minutes, and only on a node (a relay with a tailnet listener).
    Node,
}

impl CodeKind {
    pub fn text(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Node => "node",
        }
    }

    fn from_text(text: &str) -> Option<Self> {
        match text {
            "operator" => Some(Self::Operator),
            "node" => Some(Self::Node),
            _ => None,
        }
    }
}

/// `migrate_1005` on a transaction: the column, when it is not there, and the version.
fn migrate_1005(conn: &Connection) -> RelayResult<()> {
    if !crate::server::store::has_column(conn, "team_code", "kind")? {
        conn.execute_batch(KIND_1005).map_err(db)?;
    }
    conn.pragma_update(None, "user_version", 1005).map_err(db)
}

/// The accounts step on a transaction: `MIGRATE_ACCOUNTS` when `team` has no
/// `account_id` yet, and the version. A file that `downgrade_to_1005` took back has every
/// table of the step already (it removed only the vault store rows): they stay.
fn migrate_accounts(conn: &Connection) -> RelayResult<()> {
    if crate::server::store::has_column(conn, "team", "account_id")? {
        refuse_earlier_accounts_step(conn)?;
    } else {
        conn.execute_batch(MIGRATE_ACCOUNTS).map_err(db)?;
    }
    conn.pragma_update(None, "user_version", DIRECTORY_VERSION)
        .map_err(db)
}

/// The tables of the accounts step from an earlier, unreleased build of it (no
/// `account_list.name`: the device lists whose entries sign no device name; no
/// `account_list.team_id`: the lists without the entries of section 16; no
/// `account_id_used`; no `account_join.signature`): this build does not read them, and
/// does not change them.
fn refuse_earlier_accounts_step(conn: &Connection) -> RelayResult<()> {
    let used: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'account_id_used')",
            [],
            |row| row.get(0),
        )
        .map_err(db)?;
    if used
        && crate::server::store::has_column(conn, "account_list", "name")?
        && crate::server::store::has_column(conn, "account_list", "team_id")?
        && crate::server::store::has_column(conn, "account_join", "signature")?
    {
        return Ok(());
    }
    Err(RelayError::internal(
        "relay.db holds the accounts tables of an earlier, unreleased build of directory 1006 (no account_list.name, account_list.team_id, account_id_used, or account_join.signature). This build cannot open it: restore relay.db from the backup taken before that build, or start that build's image again.",
    ))
}

/// Opens `relay.db` as `Directory::open` does: a plain file in `connect` mode
/// (`Store::open_plain`), else keyed with the master key. The downgrade commands use it too.
fn open_directory_file(config: &RelayConfig) -> RelayResult<Store> {
    if config.connect.plain_files() {
        Store::open_plain(&config.directory_path(), config)
    } else {
        Store::open_at(&config.directory_path(), &config.master_key)
    }
}

/// The downgrades below directory 1006 delete the vault stores of the accounts (paid
/// stores of Apassy Connect, with their snapshots). They do it only when the operator
/// says so (`--delete-vault-stores`); otherwise a directory with vault stores is refused
/// and nothing changes.
fn refuse_vault_stores(store: &Store, delete_vault_stores: bool) -> RelayResult<()> {
    if delete_vault_stores {
        return Ok(());
    }
    let stores: i64 = store.with(|conn| {
        conn.query_row(
            "SELECT count(*) FROM team WHERE kind = 'account'",
            [],
            |row| row.get(0),
        )
        .map_err(db)
    })?;
    if stores > 0 {
        return Err(RelayError::new(
            codes::CONFLICT,
            format!(
                "relay.db holds {stores} vault stores of Apassy Connect accounts, and this downgrade deletes them with their snapshots. Run it again with --delete-vault-stores to delete them. Nothing was changed."
            ),
        ));
    }
    Ok(())
}

/// Removes the vault stores from `team` inside a downgrade's transaction and returns
/// their ids; the caller deletes their files after the commit.
fn drop_vault_store_rows(conn: &Connection) -> RelayResult<Vec<TeamId>> {
    let mut statement = conn
        .prepare("SELECT id FROM team WHERE kind = 'account' ORDER BY id")
        .map_err(db)?;
    let ids = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(db)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db)?;
    conn.execute_batch(DOWNGRADE_1005).map_err(db)?;
    Ok(ids.iter().filter_map(|id| TeamId::parse(id)).collect())
}

/// The effective resource limits of one team.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TeamLimits {
    pub members: u64,
    pub items: u64,
    pub agents: u64,
    pub runs_per_hour: u64,
    pub pending_runs: u64,
    pub agent_requests: u64,
    /// The largest vault snapshot, in bytes (docs/SPEC.md section 24).
    pub sync_bytes: u64,
    /// Snapshot pushes in the last 3600 seconds.
    pub sync_pushes_per_hour: u64,
    /// Snapshot pushes and downloads of the team at once.
    pub sync_transfers: u64,
    /// Questions with the state `open` (docs/SPEC.md section 25).
    pub open_questions: u64,
    /// Questions posted in the last 3600 seconds.
    pub questions_per_hour: u64,
    /// The bytes of question and answer ciphertext the team's file holds at once.
    pub question_bytes: u64,
    /// `open_questions` and `questions_per_hour` of one member, and of one device.
    pub member_open_questions: u64,
    pub member_questions_per_hour: u64,
    pub device_open_questions: u64,
    pub device_questions_per_hour: u64,
    /// The bytes of feed ciphertext the team's file holds at once (docs/SPEC.md
    /// section 27): its own budget, apart from `question_bytes`.
    pub feed_bytes: u64,
    /// Feed actions posted in the last 3600 seconds.
    pub feed_actions_per_hour: u64,
}

/// The fields of `TeamLimits` that the image before questions (`sync-*`, 84a57fa) does
/// not know: it reads the stored JSON with `deny_unknown_fields`. `stored_json` leaves
/// them out while they equal their default, so a rollback can still read the column.
pub const QUESTION_LIMIT_FIELDS: [&str; 7] = [
    "open_questions",
    "questions_per_hour",
    "question_bytes",
    "member_open_questions",
    "member_questions_per_hour",
    "device_open_questions",
    "device_questions_per_hour",
];

/// The fields of `TeamLimits` that the image before feeds (schema 5, `connect-*`) does not
/// know. `stored_json` leaves them out while they equal the preset of the team's kind
/// (`TeamLimits::for_kind`), and `from_stored` fills them from that preset, so the
/// `connect` preset's 1 MiB is never stored and a rollback can still read the column.
pub const FEED_LIMIT_FIELDS: [&str; 2] = ["feed_bytes", "feed_actions_per_hour"];

impl Default for TeamLimits {
    fn default() -> Self {
        Self {
            members: 50,
            items: 500,
            agents: 100,
            runs_per_hour: 1000,
            pending_runs: 50,
            agent_requests: 56,
            sync_bytes: 67_108_864,
            sync_pushes_per_hour: 600,
            sync_transfers: 2,
            open_questions: 20,
            questions_per_hour: 300,
            question_bytes: 8_388_608,
            member_open_questions: 15,
            member_questions_per_hour: 225,
            device_open_questions: 10,
            device_questions_per_hour: 150,
            feed_bytes: 4 * 1_048_576,
            feed_actions_per_hour: 60,
        }
    }
}

/// Only the fields supplied by the operator change.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TeamLimitsUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agents: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runs_per_hour: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_runs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_requests: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_pushes_per_hour: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_transfers: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_questions: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub questions_per_hour: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub question_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_open_questions: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_questions_per_hour: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_open_questions: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_questions_per_hour: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feed_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feed_actions_per_hour: Option<u64>,
}

impl TeamLimits {
    /// The limits of a new Connect team (docs/SPEC.md section 26): one member, no items
    /// and no agents (so no runs and no proxy), no vault sync (`plan_required`), 30
    /// snapshot pushes an hour, 2 MiB of questions, and 1 MiB of feeds. The other fields
    /// are the defaults. Devices are 10 per member, as in every team.
    pub fn connect() -> Self {
        Self::connect_with(0)
    }

    /// [`Self::connect`] with the vault sync size `sync_bytes` of the relay's setting
    /// `APASSY_RELAY_CONNECT_SYNC_BYTES` (docs/SPEC.md section 26.4): 0 is no vault sync,
    /// else the largest snapshot. `sync_bytes` is stored in every limits column, so an
    /// image before this setting reads it; `FEED_LIMIT_FIELDS` keep their rule.
    pub fn connect_with(sync_bytes: u64) -> Self {
        Self {
            members: 1,
            items: 0,
            agents: 0,
            sync_bytes,
            sync_pushes_per_hour: CONNECT_SYNC_PUSHES_PER_HOUR,
            question_bytes: CONNECT_QUESTION_BYTES,
            feed_bytes: CONNECT_FEED_BYTES,
            ..Self::default()
        }
    }

    /// Whether these are the limits a Connect team starts with on a relay whose setting
    /// is `sync_bytes`: [`Self::connect`], or [`Self::connect_with`] of the setting. A
    /// team with other limits got them from the operator (a plan); the idle sweep leaves
    /// it alone. The presets from before `CONNECT_SYNC_PUSHES_PER_HOUR` (600 pushes an
    /// hour, the default) count too, so the teams made before it stay in the sweep.
    pub fn is_connect_preset(&self, sync_bytes: u64) -> bool {
        let earlier = |limits: Self| Self {
            sync_pushes_per_hour: Self::default().sync_pushes_per_hour,
            ..limits
        };
        [Self::connect(), Self::connect_with(sync_bytes)]
            .into_iter()
            .any(|preset| *self == preset || *self == earlier(preset))
    }

    /// The limits of the personal team of an embedded node (docs/SPEC.md section 30.2):
    /// 20 agents, 120 runs an hour, 10 pending runs, and 16 agent requests at once, since
    /// its agents reach it from the internet. The other fields are the defaults.
    pub fn personal() -> Self {
        Self {
            agents: 20,
            runs_per_hour: 120,
            pending_runs: 10,
            agent_requests: 16,
            ..Self::default()
        }
    }

    /// The largest file of a team of `kind` (`Store::set_max_bytes`), or `None` for no
    /// cap. A Connect team: its `question_bytes` and `feed_bytes`, plus
    /// `CONNECT_FILE_SLACK` for its rows and audit, plus room for the items and members
    /// that a plan may give it, plus `CONNECT_SYNC_FILE_BYTES` for the sync heads when
    /// it has vault sync (the snapshots are files of their own). An operator team has no cap: the operator made it with a
    /// code and watches it.
    pub fn file_bytes(&self, kind: TeamKind) -> Option<u64> {
        match kind {
            TeamKind::Operator => None,
            // A vault store holds devices, heads, receipts, and its audit; the snapshots
            // are files of their own.
            TeamKind::Account => Some(
                CONNECT_FILE_SLACK
                    .saturating_add(CONNECT_SYNC_FILE_BYTES)
                    .saturating_add(
                        self.members
                            .saturating_sub(1)
                            .saturating_mul(MEMBER_FILE_BYTES),
                    ),
            ),
            TeamKind::Connect => Some(
                self.question_bytes
                    .saturating_add(self.feed_bytes)
                    .saturating_add(CONNECT_FILE_SLACK)
                    .saturating_add(self.items.saturating_mul(ITEM_FILE_BYTES))
                    .saturating_add(
                        self.members
                            .saturating_sub(1)
                            .saturating_mul(MEMBER_FILE_BYTES),
                    )
                    .saturating_add(if self.sync_bytes == 0 {
                        0
                    } else {
                        CONNECT_SYNC_FILE_BYTES
                    }),
            ),
        }
    }

    /// The limits a new team of this kind starts with.
    pub fn for_kind(kind: TeamKind) -> Self {
        match kind {
            TeamKind::Operator => Self::default(),
            TeamKind::Connect => Self::connect(),
            TeamKind::Account => Self::account(1),
        }
    }

    /// The limits of a vault store (connect-account-v1 section 8) for `members` accounts:
    /// 64 MiB snapshots, `ACCOUNT_SYNC_PUSHES_PER_HOUR`, no items, no agents (so no runs
    /// and no proxy), and the smallest question and feed budgets (a store serves no
    /// questions and no feed: `http` refuses those routes for it). Devices are 10 for
    /// each member, as in every team. A shared store (C3) gets more members.
    pub fn account(members: u64) -> Self {
        Self {
            members: members.clamp(1, 1_000_000),
            items: 0,
            agents: 0,
            sync_bytes: crate::sync_head::MAX_SNAPSHOT_BYTES,
            sync_pushes_per_hour: ACCOUNT_SYNC_PUSHES_PER_HOUR,
            question_bytes: MIN_QUESTION_BYTES,
            feed_bytes: MIN_FEED_BYTES,
            ..Self::default()
        }
    }

    pub fn validate(&self) -> RelayResult<()> {
        for (field, value) in [
            ("members", self.members),
            ("runs_per_hour", self.runs_per_hour),
            ("pending_runs", self.pending_runs),
            ("sync_pushes_per_hour", self.sync_pushes_per_hour),
            ("questions_per_hour", self.questions_per_hour),
            ("member_questions_per_hour", self.member_questions_per_hour),
            ("device_questions_per_hour", self.device_questions_per_hour),
            ("feed_actions_per_hour", self.feed_actions_per_hour),
        ] {
            if !(1..=1_000_000).contains(&value) {
                return Err(RelayError::invalid(format!(
                    "{field} must be 1 to 1000000."
                )));
            }
        }
        // 0 items or 0 agents: the team has none (a Connect team).
        for (field, value) in [("items", self.items), ("agents", self.agents)] {
            if value > 1_000_000 {
                return Err(RelayError::invalid(format!(
                    "{field} must be 0 to 1000000."
                )));
            }
        }
        if !(1..=224).contains(&self.agent_requests) {
            return Err(RelayError::invalid("agent_requests must be 1 to 224."));
        }
        // 0: no vault sync on the relay; a push is 403 `plan_required` (section 26).
        if self.sync_bytes != 0
            && !(1_048_576..=crate::sync_head::MAX_SNAPSHOT_BYTES).contains(&self.sync_bytes)
        {
            return Err(RelayError::invalid(
                "sync_bytes must be 0 (no vault sync) or 1048576 to 67108864.",
            ));
        }
        if !(1..=8).contains(&self.sync_transfers) {
            return Err(RelayError::invalid("sync_transfers must be 1 to 8."));
        }
        for (field, value) in [
            ("open_questions", self.open_questions),
            ("member_open_questions", self.member_open_questions),
            ("device_open_questions", self.device_open_questions),
        ] {
            if !(1..=1000).contains(&value) {
                return Err(RelayError::invalid(format!("{field} must be 1 to 1000.")));
            }
        }
        if !(MIN_QUESTION_BYTES..=MAX_QUESTION_BYTES).contains(&self.question_bytes) {
            return Err(RelayError::invalid(format!(
                "question_bytes must be {MIN_QUESTION_BYTES} to {MAX_QUESTION_BYTES}."
            )));
        }
        if !(MIN_FEED_BYTES..=MAX_FEED_BYTES).contains(&self.feed_bytes) {
            return Err(RelayError::invalid(format!(
                "feed_bytes must be {MIN_FEED_BYTES} to {MAX_FEED_BYTES}."
            )));
        }
        Ok(())
    }

    pub fn apply(self, update: TeamLimitsUpdate) -> RelayResult<Self> {
        let limits = Self {
            members: update.members.unwrap_or(self.members),
            items: update.items.unwrap_or(self.items),
            agents: update.agents.unwrap_or(self.agents),
            runs_per_hour: update.runs_per_hour.unwrap_or(self.runs_per_hour),
            pending_runs: update.pending_runs.unwrap_or(self.pending_runs),
            agent_requests: update.agent_requests.unwrap_or(self.agent_requests),
            sync_bytes: update.sync_bytes.unwrap_or(self.sync_bytes),
            sync_pushes_per_hour: update
                .sync_pushes_per_hour
                .unwrap_or(self.sync_pushes_per_hour),
            sync_transfers: update.sync_transfers.unwrap_or(self.sync_transfers),
            open_questions: update.open_questions.unwrap_or(self.open_questions),
            questions_per_hour: update.questions_per_hour.unwrap_or(self.questions_per_hour),
            question_bytes: update.question_bytes.unwrap_or(self.question_bytes),
            member_open_questions: update
                .member_open_questions
                .unwrap_or(self.member_open_questions),
            member_questions_per_hour: update
                .member_questions_per_hour
                .unwrap_or(self.member_questions_per_hour),
            device_open_questions: update
                .device_open_questions
                .unwrap_or(self.device_open_questions),
            device_questions_per_hour: update
                .device_questions_per_hour
                .unwrap_or(self.device_questions_per_hour),
            feed_bytes: update.feed_bytes.unwrap_or(self.feed_bytes),
            feed_actions_per_hour: update
                .feed_actions_per_hour
                .unwrap_or(self.feed_actions_per_hour),
        };
        limits.validate()?;
        Ok(limits)
    }

    /// The text of the `limits` column of a team of `kind`: every field, except a field
    /// of `QUESTION_LIMIT_FIELDS` that equals its default and a field of
    /// `FEED_LIMIT_FIELDS` that equals the preset of `kind`. The images before questions
    /// and before feeds refuse unknown fields, so with those limits at their default
    /// they still read the column after a rollback (docs/OPERATIONS.md sections 19.3
    /// and 21.3).
    pub fn stored_json(&self, kind: TeamKind) -> RelayResult<String> {
        let unwritable = || RelayError::internal("The limits cannot be written.");
        let mut value = serde_json::to_value(self).map_err(|_| unwritable())?;
        let defaults = serde_json::to_value(Self::default()).map_err(|_| unwritable())?;
        let preset = serde_json::to_value(Self::for_kind(kind)).map_err(|_| unwritable())?;
        if let Some(fields) = value.as_object_mut() {
            for name in QUESTION_LIMIT_FIELDS {
                if fields.get(name) == defaults.get(name) {
                    fields.remove(name);
                }
            }
            for name in FEED_LIMIT_FIELDS {
                if fields.get(name) == preset.get(name) {
                    fields.remove(name);
                }
            }
        }
        serde_json::to_string(&value).map_err(|_| unwritable())
    }

    /// The limits of a team of `kind` from the text of its `limits` column (`None`: the
    /// defaults). A field that is not there takes its default, and a field of
    /// `FEED_LIMIT_FIELDS` the preset of `kind`, as `stored_json` left it out.
    pub fn from_stored(text: Option<&str>, kind: TeamKind) -> Option<Self> {
        let mut value: serde_json::Value = match text {
            Some(text) => serde_json::from_str(text).ok()?,
            None => serde_json::json!({}),
        };
        let preset = serde_json::to_value(Self::for_kind(kind)).ok()?;
        let fields = value.as_object_mut()?;
        for name in FEED_LIMIT_FIELDS {
            if !fields.contains_key(name) {
                fields.insert(name.to_string(), preset.get(name)?.clone());
            }
        }
        serde_json::from_value(value).ok()
    }
}

/// The range of `question_bytes`: 1 MiB to 256 MiB.
pub const MIN_QUESTION_BYTES: u64 = 1_048_576;
pub const MAX_QUESTION_BYTES: u64 = 268_435_456;
/// `question_bytes` of a new Connect team: 2 MiB.
pub const CONNECT_QUESTION_BYTES: u64 = 2_097_152;
/// The range of `feed_bytes`: 1 MiB to 64 MiB (docs/SPEC.md section 27).
pub const MIN_FEED_BYTES: u64 = 1_048_576;
pub const MAX_FEED_BYTES: u64 = 67_108_864;
/// `feed_bytes` of a new Connect team: 1 MiB, about four full feeds.
pub const CONNECT_FEED_BYTES: u64 = 1_048_576;
/// The file of a Connect team beyond its `question_bytes`: its team, member, device,
/// and link rows, the question metadata, and its audit (`TeamLimits::file_bytes`).
pub const CONNECT_FILE_SLACK: u64 = 8 * 1_048_576;
/// Room in a Connect team's file for each item and each member beyond the first that a
/// plan gives it: an item holds up to 4 KiB sealed, a member its devices and its audit.
pub const ITEM_FILE_BYTES: u64 = 16 * 1024;
/// Room in a Connect team's file for vault sync (`sync_bytes` above 0): up to
/// `sync::KEPT_HEADS` (10000) signed heads of about 600 bytes each with their index, the
/// receipts, and the audit rows of the pushes. The snapshots are files in
/// `teams/<team id>.sync/`, at most two of `sync_bytes` each.
pub const CONNECT_SYNC_FILE_BYTES: u64 = 16 * 1_048_576;
/// `sync_pushes_per_hour` of a vault store: 120, a push every 30 seconds from the devices
/// of a vault together.
pub const ACCOUNT_SYNC_PUSHES_PER_HOUR: u64 = 120;
/// `sync_pushes_per_hour` of a new Connect team: 30, a push every two minutes, which a
/// vault that one person changes does not reach (docs/SPEC.md section 26.4).
pub const CONNECT_SYNC_PUSHES_PER_HOUR: u64 = 30;
/// The snapshot bytes that one Connect team may push in 3600 seconds: 512 MiB, eight
/// full pushes of the largest `sync_bytes`. Over it: 429 `rate_limited` with
/// `Retry-After` (docs/SPEC.md section 24.3 check 4). Not a stored limit: a plan that
/// needs more makes the team an operator team.
pub const CONNECT_SYNC_BYTES_PER_HOUR: u64 = 512 * 1_048_576;
pub const MEMBER_FILE_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamState {
    Active,
    Suspended,
}

impl TeamState {
    pub fn text(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }
}

/// One team of the directory, with the key of its file.
pub struct TeamRow {
    pub id: TeamId,
    pub name: String,
    pub file_key: SecretString,
    pub state: TeamState,
    /// The team migrated from a relay before teams. Its old member and agent tokens
    /// have no team id; the relay sends them here.
    pub legacy: bool,
    pub created_at: u64,
    pub suspended_at: Option<u64>,
    pub limits: TeamLimits,
    pub kind: TeamKind,
    /// `IDLE_REASON` when `admin connect-sweep` suspended the team.
    pub suspend_reason: Option<String>,
    /// A vault store (`TeamKind::Account`): the account that made it, and its vault id.
    pub account_id: Option<String>,
    pub vault_id: Option<String>,
}

/// Every team of the directory on `conn`, oldest first.
pub fn read_teams(conn: &Connection) -> RelayResult<Vec<TeamRow>> {
    let mut statement = conn
        .prepare(&format!(
            "SELECT {TEAM_COLUMNS} FROM team ORDER BY created_at, id"
        ))
        .map_err(db)?;
    let rows = statement.query_map([], team_from_row).map_err(db)?;
    rows.map(|row| row.map_err(db)).collect()
}

fn team_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TeamRow> {
    let id: String = row.get(0)?;
    let state: String = row.get(3)?;
    let text: Option<String> = row.get(7)?;
    let kind = match row.get::<_, String>(8)?.as_str() {
        "operator" => TeamKind::Operator,
        "connect" => TeamKind::Connect,
        "account" => TeamKind::Account,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let limits =
        TeamLimits::from_stored(text.as_deref(), kind).ok_or(rusqlite::Error::InvalidQuery)?;
    limits
        .validate()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(TeamRow {
        id: TeamId::parse(&id).ok_or(rusqlite::Error::InvalidQuery)?,
        name: row.get(1)?,
        file_key: SecretString::new(row.get(2)?),
        state: if state == "active" {
            TeamState::Active
        } else {
            TeamState::Suspended
        },
        legacy: row.get::<_, i64>(4)? == 1,
        created_at: to_u(row.get(5)?),
        suspended_at: row.get::<_, Option<i64>>(6)?.map(to_u),
        limits,
        kind,
        suspend_reason: row.get(9)?,
        account_id: row.get(10)?,
        vault_id: row.get(11)?,
    })
}

const TEAM_COLUMNS: &str = "id, name, file_key, state, legacy, created_at, suspended_at, limits, kind, suspend_reason, account_id, vault_id";

/// The directory: its file, and the audit writer of the relay.
pub struct Directory {
    pub store: Arc<Store>,
    pub audit: Arc<Audit>,
}

impl Directory {
    /// Creates `relay.db`. Refuses when it exists.
    pub fn create(config: &RelayConfig) -> RelayResult<Self> {
        if config.connect.plain_files() {
            // `connect` mode: a plain file, nothing in it is secret (ADR 0037 stage 7).
            let store = Store::create_plain(&config.directory_path(), config, &schema())
                .map_err(already_exists)?;
            return Ok(Self {
                store: Arc::new(store),
                audit: Audit::new(),
            });
        }
        Self::create_at(&config.directory_path(), &config.master_key)
    }

    /// Creates a directory file at `path` (`migrate` writes it under another name and
    /// renames it last). Refuses when it exists.
    pub fn create_at(path: &std::path::Path, master_key: &SecretString) -> RelayResult<Self> {
        let store = Store::create_at(path, master_key, &schema()).map_err(already_exists)?;
        Ok(Self {
            store: Arc::new(store),
            audit: Audit::new(),
        })
    }

    /// Opens `relay.db` and checks its version. 1001 to 1005 move to `DIRECTORY_VERSION`
    /// in one transaction; a failure leaves the file at its version. In `connect` mode the
    /// file is plain (`Store::open_plain`).
    pub fn open(config: &RelayConfig) -> RelayResult<Self> {
        let store = open_directory_file(config)?;
        match store.user_version()? {
            DIRECTORY_VERSION => store.with(refuse_earlier_accounts_step)?,
            version @ (1001..=BEFORE_ACCOUNTS_VERSION) => store.tx(|tx| {
                if version == 1001 {
                    tx.execute_batch("ALTER TABLE team ADD COLUMN limits TEXT;")
                        .map_err(db)?;
                }
                if version <= 1002 {
                    tx.execute_batch(MIGRATE_1003).map_err(db)?;
                }
                if version <= 1003 {
                    tx.execute_batch(MIGRATE_1004).map_err(db)?;
                }
                if version <= 1004 {
                    migrate_1005(tx)?;
                }
                migrate_accounts(tx)
            })?,
            _ => {
                return Err(RelayError::internal(
                    "relay.db is not the directory of a relay, or has an unknown version.",
                ));
            }
        }
        Ok(Self {
            store: Arc::new(store),
            audit: Audit::new(),
        })
    }

    /// `apassy-relay downgrade-directory-1003` (docs/OPERATIONS.md section 24): with the
    /// relay stopped (it takes `relay.lock`), a directory of version 1004 or 1005 goes back
    /// to 1003 in place, for an image before OAuth: first the step of `downgrade_to_1004`
    /// (unused node codes go), then the OAuth tables go: registered clients, connect
    /// requests, and refresh tokens. An access token that was issued stays valid in its
    /// team file until it ends (at most `oauth::ACCESS_TOKEN_SECS`), and no client can
    /// refresh it. A file of version 1003 is left as it is. Returns the version before and
    /// after.
    /// A directory of `DIRECTORY_VERSION` with vault stores is refused, with no change, unless
    /// `delete_vault_stores` (`--delete-vault-stores`): the step deletes them.
    pub fn downgrade_to_1003(
        config: &RelayConfig,
        delete_vault_stores: bool,
    ) -> RelayResult<(i64, i64)> {
        config.refuse_connect_mode("`apassy-relay downgrade-directory-1003`")?;
        let _lock = crate::server::hub::lock_data_dir(config)?;
        let store = open_directory_file(config)?;
        let from = store.user_version()?;
        if from == DIRECTORY_VERSION {
            refuse_vault_stores(&store, delete_vault_stores)?;
        }
        let stores = match from {
            DIRECTORY_VERSION => store.tx(|tx| {
                let stores = drop_vault_store_rows(tx)?;
                tx.execute_batch(DOWNGRADE_1004).map_err(db)?;
                tx.execute_batch(DOWNGRADE_1003).map_err(db)?;
                Ok(stores)
            })?,
            1005 => store.tx(|tx| {
                tx.execute_batch(DOWNGRADE_1004).map_err(db)?;
                tx.execute_batch(DOWNGRADE_1003).map_err(db)?;
                Ok(Vec::new())
            })?,
            1004 => store.tx(|tx| {
                tx.execute_batch(DOWNGRADE_1003).map_err(db)?;
                Ok(Vec::new())
            })?,
            1003 => Vec::new(),
            _ => {
                return Err(RelayError::internal(format!(
                    "relay.db is not a directory of version 1003 to {DIRECTORY_VERSION}."
                )));
            }
        };
        remove_vault_store_files(config, &stores);
        Ok((from, store.user_version()?))
    }

    /// `apassy-relay downgrade-directory-1004` (docs/OPERATIONS.md section 25.3): with the
    /// relay stopped (it takes `relay.lock`), a directory of version 1005 goes back to 1004
    /// in place, for the image before node pairing codes. The unused node codes go (the
    /// image of 1004 would take one for an operator code); used ones stay as history, and
    /// the `kind` column stays: that image never reads it, and the next open of 1005 keeps
    /// it. A file of version 1004 is left as it is. Returns the version before and after.
    /// A directory of `DIRECTORY_VERSION` with vault stores is refused, with no change, unless
    /// `delete_vault_stores` (`--delete-vault-stores`): the step deletes them.
    pub fn downgrade_to_1004(
        config: &RelayConfig,
        delete_vault_stores: bool,
    ) -> RelayResult<(i64, i64)> {
        config.refuse_connect_mode("`apassy-relay downgrade-directory-1004`")?;
        let _lock = crate::server::hub::lock_data_dir(config)?;
        let store = open_directory_file(config)?;
        let from = store.user_version()?;
        if from == DIRECTORY_VERSION {
            refuse_vault_stores(&store, delete_vault_stores)?;
        }
        let stores = match from {
            DIRECTORY_VERSION => store.tx(|tx| {
                let stores = drop_vault_store_rows(tx)?;
                tx.execute_batch(DOWNGRADE_1004).map_err(db)?;
                Ok(stores)
            })?,
            1005 => store.tx(|tx| {
                tx.execute_batch(DOWNGRADE_1004).map_err(db)?;
                Ok(Vec::new())
            })?,
            1004 => Vec::new(),
            _ => {
                return Err(RelayError::internal(format!(
                    "relay.db is not a directory of version 1004 to {DIRECTORY_VERSION}."
                )));
            }
        };
        remove_vault_store_files(config, &stores);
        Ok((from, store.user_version()?))
    }

    /// `apassy-relay downgrade-directory-1005` (docs/OPERATIONS.md section 26.3): with the
    /// relay stopped (it takes `relay.lock`), a directory of `DIRECTORY_VERSION` goes back
    /// to 1005 in place, for the image before Apassy Connect accounts. The vault stores go
    /// (their rows and their files: snapshots, heads, and receipts; each Mac pushes its
    /// vault again after the next upgrade, M3); the accounts, their devices, and every other
    /// table of the step stay, unread by that image, and the next open of this version keeps
    /// them. A file of version 1005 is left as it is. Returns the version before and after,
    /// and the vault stores removed. The only complete way back is the backup of the deploy.
    /// A directory of `DIRECTORY_VERSION` with vault stores is refused, with no change, unless
    /// `delete_vault_stores` (`--delete-vault-stores`): the step deletes them.
    pub fn downgrade_to_1005(
        config: &RelayConfig,
        delete_vault_stores: bool,
    ) -> RelayResult<(i64, i64, usize)> {
        config.refuse_connect_mode("`apassy-relay downgrade-directory-1005`")?;
        let _lock = crate::server::hub::lock_data_dir(config)?;
        let store = open_directory_file(config)?;
        let from = store.user_version()?;
        if from == DIRECTORY_VERSION {
            refuse_vault_stores(&store, delete_vault_stores)?;
        }
        let stores = match from {
            DIRECTORY_VERSION => store.tx(|tx| drop_vault_store_rows(tx))?,
            1005 => Vec::new(),
            _ => {
                return Err(RelayError::internal(format!(
                    "relay.db is not a directory of version 1005 or {DIRECTORY_VERSION}."
                )));
            }
        };
        remove_vault_store_files(config, &stores);
        Ok((from, store.user_version()?, stores.len()))
    }

    /// Every team, oldest first.
    pub fn teams(&self) -> RelayResult<Vec<TeamRow>> {
        self.store.with(read_teams)
    }

    /// One team by id.
    pub fn team(&self, id: &TeamId) -> RelayResult<Option<TeamRow>> {
        self.store.with(|conn| team_by_id(conn, id))
    }

    /// Sets the state of a team, and writes an operator row. `reason` is kept with a
    /// suspension (`IDLE_REASON`); a resume clears it.
    pub fn set_state(
        &self,
        id: &TeamId,
        state: TeamState,
        reason: Option<&str>,
        now: u64,
    ) -> RelayResult<()> {
        let reason = reason.filter(|_| state == TeamState::Suspended);
        self.store.tx(|tx| {
            let changed = tx
                .execute(
                    "UPDATE team SET state = ?1, suspended_at = ?2, suspend_reason = ?3 WHERE id = ?4",
                    params![
                        state.text(),
                        (state == TeamState::Suspended).then_some(to_i(now)),
                        reason,
                        id.as_str()
                    ],
                )
                .map_err(db)?;
            if changed == 0 {
                return Err(RelayError::not_found("team"));
            }
            let action = match state {
                TeamState::Active => "team_resumed",
                TeamState::Suspended => "team_suspended",
            };
            let detail = match reason {
                Some(reason) => serde_json::json!({"team_id": id, "reason": reason}),
                None => serde_json::json!({"team_id": id}),
            };
            self.audit
                .write_on(tx, now, OPERATOR_ACTOR, action, None, &detail)?;
            Ok(())
        })
    }

    /// Removes a team from the directory: its row and the key of its file. The caller
    /// deletes the file. The `connect_key` row of a Connect team stays, as used; with
    /// `free_connect_key` its hash becomes random bytes, so the device key that made the
    /// team may make a new one, and the row still counts for the daily cap. Returns
    /// whether a key was freed.
    pub fn remove(&self, id: &TeamId, free_connect_key: bool, now: u64) -> RelayResult<bool> {
        self.store.tx(|tx| {
            let changed = tx
                .execute("DELETE FROM team WHERE id = ?1", params![id.as_str()])
                .map_err(db)?;
            if changed == 0 {
                return Err(RelayError::not_found("team"));
            }
            // The key of a deleted Connect team stays used, but no longer names the team.
            let freed = if free_connect_key {
                tx.execute(
                    "UPDATE connect_key SET key_hash = randomblob(32), team_id = NULL \
                     WHERE team_id = ?1",
                    params![id.as_str()],
                )
            } else {
                tx.execute(
                    "UPDATE connect_key SET team_id = NULL WHERE team_id = ?1",
                    params![id.as_str()],
                )
                .map(|_| 0)
            }
            .map_err(db)?;
            let detail = if free_connect_key {
                serde_json::json!({"team_id": id, "connect_key_freed": freed > 0})
            } else {
                serde_json::json!({"team_id": id})
            };
            self.audit
                .write_on(tx, now, OPERATOR_ACTOR, "team_deleted", None, &detail)?;
            Ok(freed > 0)
        })
    }

    /// A new one-time team code of the operator. Returns the code (shown once) and its
    /// expiry.
    pub fn new_team_code(&self, hours: u64, now: u64) -> RelayResult<(SecretString, u64)> {
        if !(1..=MAX_TEAM_CODE_HOURS).contains(&hours) {
            return Err(RelayError::invalid(format!(
                "A team code lives 1 to {MAX_TEAM_CODE_HOURS} hours."
            )));
        }
        self.insert_code(CodeKind::Operator, now + hours * 3600, now)
    }

    /// A new node pairing code (node-pairing-v1 section 6): a team code of kind `node`,
    /// one use, for 1 to `MAX_NODE_CODE_MINUTES` minutes. It makes a team only on a node
    /// (`Hub::create_team`). Returns the code (shown once) and its expiry. The row of the
    /// relay audit is `node_code_created {code_id, expires_at}`.
    pub fn new_node_code(&self, minutes: u64, now: u64) -> RelayResult<(SecretString, u64)> {
        if !(1..=MAX_NODE_CODE_MINUTES).contains(&minutes) {
            return Err(RelayError::invalid(format!(
                "A node pairing code lives 1 to {MAX_NODE_CODE_MINUTES} minutes."
            )));
        }
        self.insert_code(CodeKind::Node, now + minutes * 60, now)
    }

    fn insert_code(
        &self,
        kind: CodeKind,
        expires_at: u64,
        now: u64,
    ) -> RelayResult<(SecretString, u64)> {
        let code = new_team_code()?;
        self.store.tx(|tx| {
            tx.execute(
                "INSERT INTO team_code (code_hash, created_at, expires_at, kind) VALUES (?1, ?2, ?3, ?4)",
                params![
                    token_hash(code.expose()).0.as_slice(),
                    to_i(now),
                    to_i(expires_at),
                    kind.text()
                ],
            )
            .map_err(db)?;
            let id = to_u(tx.last_insert_rowid());
            let action = match kind {
                CodeKind::Operator => "team_code_created",
                CodeKind::Node => "node_code_created",
            };
            self.audit.write_on(
                tx,
                now,
                OPERATOR_ACTOR,
                action,
                None,
                &serde_json::json!({"code_id": id, "expires_at": expires_at}),
            )?;
            Ok(())
        })?;
        Ok((code, expires_at))
    }
}

/// The error of a directory file that exists already.
fn already_exists(error: RelayError) -> RelayError {
    if error.code == codes::CONFLICT {
        RelayError::new(
            codes::CONFLICT,
            "The relay already exists. Refusing to create it again.",
        )
    } else {
        error
    }
}

/// Deletes the files of the vault stores that a downgrade removed from `team`. A file
/// that cannot be deleted is logged: without its row no key opens it, and the next start
/// of the old image removes it as an orphan (`hub::sweep_orphans`).
fn remove_vault_store_files(config: &RelayConfig, stores: &[TeamId]) {
    for id in stores {
        if crate::server::hub::remove_team_file(config, id).is_err() {
            eprintln!("apassy-relay: the file of vault store {id} could not be deleted");
        }
    }
}

/// One team by id, on a connection.
pub fn team_by_id(conn: &Connection, id: &TeamId) -> RelayResult<Option<TeamRow>> {
    conn.query_row(
        &format!("SELECT {TEAM_COLUMNS} FROM team WHERE id = ?1"),
        params![id.as_str()],
        team_from_row,
    )
    .optional()
    .map_err(db)
}

/// The error for a team code that is wrong, used, or expired. One message for all.
pub fn team_code_invalid() -> RelayError {
    RelayError::new(
        codes::INVITE_INVALID,
        "The team code is not valid, was used, or expired.",
    )
}

/// The id and kind of a live team code, inside a transaction. Refuses a wrong, used, or
/// expired code. Check it before any work for a new team. The caller refuses a `node`
/// code on a relay that is not a node (`Hub::create_team`).
pub fn find_team_code(conn: &Connection, code: &str, now: u64) -> RelayResult<(u64, CodeKind)> {
    if parse_token(code).is_none_or(|parsed| parsed.kind != TokenKind::TeamCode) {
        return Err(team_code_invalid());
    }
    let row: Option<(i64, String)> = conn
        .query_row(
            "SELECT id, kind FROM team_code WHERE code_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
            params![token_hash(code).0.as_slice(), to_i(now)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(db)?;
    let (id, kind) = row.ok_or_else(team_code_invalid)?;
    let kind = CodeKind::from_text(&kind).ok_or_else(team_code_invalid)?;
    Ok((to_u(id), kind))
}

/// Marks a team code used for `team`, inside the transaction of `find_team_code`.
pub fn mark_team_code_used(conn: &Connection, id: u64, team: &TeamId, now: u64) -> RelayResult<()> {
    conn.execute(
        "UPDATE team_code SET used_at = ?1, team_id = ?2 WHERE id = ?3 AND used_at IS NULL",
        params![to_i(now), team.as_str(), to_i(id)],
    )
    .map_err(db)
    .and_then(|changed| {
        if changed == 1 {
            Ok(())
        } else {
            Err(team_code_invalid())
        }
    })
}

/// Adds a team row of kind `operator` with the default limits, inside a transaction.
pub fn insert_team(
    conn: &Connection,
    id: &TeamId,
    name: &str,
    file_key: &SecretString,
    legacy: bool,
    now: u64,
) -> RelayResult<()> {
    conn.execute(
        "INSERT INTO team (id, name, file_key, state, legacy, created_at) VALUES (?1, ?2, ?3, 'active', ?4, ?5)",
        params![id.as_str(), name, file_key.expose(), i64::from(legacy), to_i(now)],
    )
    .map_err(db)?;
    Ok(())
}

/// Adds the row of a new Connect team with the `connect` limits, inside a transaction.
pub fn insert_connect_team(
    conn: &Connection,
    id: &TeamId,
    name: &str,
    file_key: &SecretString,
    limits: &TeamLimits,
    now: u64,
) -> RelayResult<()> {
    let limits = limits.stored_json(TeamKind::Connect)?;
    conn.execute(
        "INSERT INTO team (id, name, file_key, state, legacy, created_at, limits, kind) VALUES (?1, ?2, ?3, 'active', 0, ?4, ?5, 'connect')",
        params![id.as_str(), name, file_key.expose(), to_i(now), limits],
    )
    .map_err(db)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
/// Adds the row of a new vault store (kind `account`) of `account` for `vault_id`, inside
/// a transaction.
pub fn insert_vault_store(
    conn: &Connection,
    id: &TeamId,
    name: &str,
    file_key: &SecretString,
    limits: &TeamLimits,
    account: &str,
    vault_id: &str,
    now: u64,
) -> RelayResult<()> {
    let limits = limits.stored_json(TeamKind::Account)?;
    conn.execute(
        "INSERT INTO team (id, name, file_key, state, legacy, created_at, limits, kind, account_id, vault_id) \
         VALUES (?1, ?2, ?3, 'active', 0, ?4, ?5, 'account', ?6, ?7)",
        params![id.as_str(), name, file_key.expose(), to_i(now), limits, account, vault_id],
    )
    .map_err(db)?;
    Ok(())
}

/// The hash under which `connect_key` keeps a device public key (65 bytes).
pub fn connect_key_hash(public_key: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(public_key).into()
}

/// The error for a public key that made a Connect team before. The same for every such
/// key: it names no team.
pub fn connect_key_used() -> RelayError {
    RelayError::new(
        codes::CONNECT_KEY_USED,
        "This key cannot create another team. Recover an active team with a fresh Connect challenge, or use a new key.",
    )
}

/// Checks a new Connect team against `connect_key`, inside the transaction that adds
/// it: the key made no team before (409 `connect_key_used`), and the relay made fewer
/// than `per_day` Connect teams in the last 24 hours (503 `busy`). Rows of
/// `connect_key` stay after their team is deleted (with `team_id` NULL), so both checks
/// count them.
pub fn check_connect_key(
    conn: &Connection,
    key_hash: &[u8; 32],
    per_day: u64,
    now: u64,
) -> RelayResult<()> {
    let used: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM connect_key WHERE key_hash = ?1",
            params![key_hash.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(db)?;
    if used.is_some() {
        return Err(connect_key_used());
    }
    let today: i64 = conn
        .query_row(
            "SELECT count(*) FROM connect_key WHERE created_at > ?1",
            params![to_i(now.saturating_sub(86_400))],
            |row| row.get(0),
        )
        .map_err(db)?;
    if to_u(today) >= per_day {
        return Err(connect_busy());
    }
    Ok(())
}

/// Checks that the relay holds fewer than `max` Connect teams, active or suspended
/// (`APASSY_RELAY_CONNECT_TEAMS_MAX`), inside the transaction that adds one: else 503
/// `busy` (`connect_full`).
pub fn check_connect_room(conn: &Connection, max: u64) -> RelayResult<()> {
    let held: i64 = conn
        .query_row(
            "SELECT count(*) FROM team WHERE kind = 'connect'",
            [],
            |row| row.get(0),
        )
        .map_err(db)?;
    if to_u(held) >= max {
        return Err(connect_full());
    }
    Ok(())
}

/// 503 `busy` of `POST /v1/connect` when the relay holds `connect_teams_max` Connect
/// teams. The same code as the daily cap; the message tells them apart for a person.
pub fn connect_full() -> RelayError {
    RelayError::new(
        codes::BUSY,
        "The relay has no room for new teams now. Try again later.",
    )
}

/// 503 `busy` of `POST /v1/connect`: the relay-wide daily cap is reached, or Connect is
/// off (`APASSY_RELAY_CONNECT_TEAMS_PER_DAY=0`).
pub fn connect_busy() -> RelayError {
    RelayError::new(
        codes::BUSY,
        "The relay makes no new teams now. Try again later.",
    )
}

/// Records the key of a new Connect team, inside the transaction that adds it.
pub fn insert_connect_key(
    conn: &Connection,
    key_hash: &[u8; 32],
    team: &TeamId,
    now: u64,
) -> RelayResult<()> {
    conn.execute(
        "INSERT INTO connect_key (key_hash, team_id, created_at) VALUES (?1, ?2, ?3)",
        params![key_hash.as_slice(), team.as_str(), to_i(now)],
    )
    .map_err(db)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: &std::path::Path) -> RelayConfig {
        RelayConfig::from_lookup(|name| match name {
            "APASSY_RELAY_DATA" => Some(dir.to_string_lossy().into_owned()),
            "APASSY_RELAY_PUBLIC_URL" => Some("https://relay.example.test".to_string()),
            "APASSY_RELAY_EDGE_SECRET" => Some("test-edge-secret-32-bytes-minimum".to_string()),
            "APASSY_RELAY_KEY" => Some("test-master-key-16-bytes-minimum".to_string()),
            _ => None,
        })
        .unwrap()
    }

    #[test]
    fn limits_defaults_partial_json_and_validation() {
        let defaults = TeamLimits::default();
        assert_eq!(
            serde_json::to_value(defaults).unwrap(),
            serde_json::json!({
                "members": 50, "items": 500, "agents": 100,
                "runs_per_hour": 1000, "pending_runs": 50, "agent_requests": 56,
                "sync_bytes": 67108864, "sync_pushes_per_hour": 600, "sync_transfers": 2,
                "open_questions": 20, "questions_per_hour": 300,
                "question_bytes": 8388608,
                "member_open_questions": 15, "member_questions_per_hour": 225,
                "device_open_questions": 10, "device_questions_per_hour": 150,
                "feed_bytes": 4194304, "feed_actions_per_hour": 60,
            })
        );
        assert_eq!(serde_json::from_str::<TeamLimits>("{}").unwrap(), defaults);
        let partial: TeamLimits = serde_json::from_str(r#"{"members":7}"#).unwrap();
        assert_eq!(partial.members, 7);
        assert_eq!(partial.items, defaults.items);
        let update: TeamLimitsUpdate = serde_json::from_str(r#"{"agent_requests":224}"#).unwrap();
        assert_eq!(defaults.apply(update).unwrap().agent_requests, 224);
        assert_eq!(
            serde_json::to_string(&update).unwrap(),
            r#"{"agent_requests":224}"#
        );
        assert!(serde_json::from_str::<TeamLimitsUpdate>(r#"{"unknown":1}"#).is_err());
        assert!(serde_json::from_str::<TeamLimitsUpdate>(r#"{"members":-1}"#).is_err());
        assert!(serde_json::from_str::<TeamLimitsUpdate>(r#"{"members":1.5}"#).is_err());
        for field in [
            "members",
            "items",
            "agents",
            "runs_per_hour",
            "pending_runs",
        ] {
            let zero_ok = matches!(field, "items" | "agents");
            let update =
                serde_json::from_value::<TeamLimitsUpdate>(serde_json::json!({field: 0})).unwrap();
            assert_eq!(defaults.apply(update).is_ok(), zero_ok, "{field}=0");
            let update =
                serde_json::from_value::<TeamLimitsUpdate>(serde_json::json!({field: 1_000_001}))
                    .unwrap();
            assert!(defaults.apply(update).is_err(), "{field}=1000001");
            for value in [1, 1_000_000] {
                let update =
                    serde_json::from_value::<TeamLimitsUpdate>(serde_json::json!({field: value}))
                        .unwrap();
                assert!(defaults.apply(update).is_ok(), "{field}={value}");
            }
        }
        for value in [0, 225] {
            assert!(
                defaults
                    .apply(TeamLimitsUpdate {
                        agent_requests: Some(value),
                        ..Default::default()
                    })
                    .is_err()
            );
        }
        let questions = |open: u64, per_hour: u64| {
            defaults.apply(TeamLimitsUpdate {
                open_questions: Some(open),
                questions_per_hour: Some(per_hour),
                ..Default::default()
            })
        };
        assert!(questions(1, 1).is_ok());
        assert!(questions(1000, 1_000_000).is_ok());
        assert!(questions(0, 300).is_err());
        assert!(questions(1001, 300).is_err());
        assert!(questions(20, 0).is_err());
        assert!(questions(20, 1_000_001).is_err());
        for (field, low, high) in [
            ("member_open_questions", 1, 1000),
            ("device_open_questions", 1, 1000),
            ("member_questions_per_hour", 1, 1_000_000),
            ("device_questions_per_hour", 1, 1_000_000),
            ("question_bytes", MIN_QUESTION_BYTES, MAX_QUESTION_BYTES),
            ("feed_bytes", MIN_FEED_BYTES, MAX_FEED_BYTES),
            ("feed_actions_per_hour", 1, 1_000_000),
        ] {
            let set = |value: u64| {
                defaults.apply(
                    serde_json::from_value::<TeamLimitsUpdate>(serde_json::json!({field: value}))
                        .unwrap(),
                )
            };
            assert!(set(low).is_ok() && set(high).is_ok(), "{field}");
            assert!(set(low - 1).is_err() && set(high + 1).is_err(), "{field}");
        }
        // sync_bytes: 0 (no vault sync) or 1 MiB to 64 MiB.
        let sync = |value: u64| {
            defaults.apply(TeamLimitsUpdate {
                sync_bytes: Some(value),
                ..Default::default()
            })
        };
        assert!(sync(0).is_ok() && sync(1_048_576).is_ok() && sync(67_108_864).is_ok());
        assert!(sync(1).is_err() && sync(1_048_575).is_err() && sync(67_108_865).is_err());
        // A stored row from before questions reads the question defaults.
        let old: TeamLimits = serde_json::from_str(r#"{"members":7,"sync_transfers":3}"#).unwrap();
        assert_eq!((old.open_questions, old.questions_per_hour), (20, 300));
    }

    /// `TeamLimits` of the image before questions (84a57fa), field for field: it reads
    /// the `limits` column with `deny_unknown_fields`.
    #[derive(Debug, Deserialize)]
    #[serde(default, deny_unknown_fields)]
    #[allow(dead_code)]
    struct OldTeamLimits {
        members: u64,
        items: u64,
        agents: u64,
        runs_per_hour: u64,
        pending_runs: u64,
        agent_requests: u64,
        sync_bytes: u64,
        sync_pushes_per_hour: u64,
        sync_transfers: u64,
    }

    impl Default for OldTeamLimits {
        fn default() -> Self {
            Self {
                members: 50,
                items: 500,
                agents: 100,
                runs_per_hour: 1000,
                pending_runs: 50,
                agent_requests: 56,
                sync_bytes: 67_108_864,
                sync_pushes_per_hour: 600,
                sync_transfers: 2,
            }
        }
    }

    #[test]
    fn stored_limits_with_default_question_limits_read_in_the_old_image() {
        let defaults = TeamLimits::default();
        let text = defaults.stored_json(TeamKind::Operator).unwrap();
        serde_json::from_str::<OldTeamLimits>(&text).unwrap();
        assert_eq!(serde_json::from_str::<TeamLimits>(&text).unwrap(), defaults);
        // A changed limit of the old image stays readable too.
        let changed = defaults
            .apply(TeamLimitsUpdate {
                members: Some(7),
                sync_transfers: Some(3),
                ..Default::default()
            })
            .unwrap();
        let text = changed.stored_json(TeamKind::Operator).unwrap();
        let old = serde_json::from_str::<OldTeamLimits>(&text).unwrap();
        assert_eq!((old.members, old.sync_transfers), (7, 3));
        assert_eq!(serde_json::from_str::<TeamLimits>(&text).unwrap(), changed);
        // Each question limit changed from its default is written, and the old image
        // refuses the column: the rollback restores relay.db (OPERATIONS 19.3).
        for field in QUESTION_LIMIT_FIELDS {
            let value = match field {
                "question_bytes" => MIN_QUESTION_BYTES,
                _ => 1,
            };
            let update =
                serde_json::from_value::<TeamLimitsUpdate>(serde_json::json!({field: value}))
                    .unwrap();
            let limits = defaults.apply(update).unwrap();
            let text = limits.stored_json(TeamKind::Operator).unwrap();
            assert!(text.contains(field), "{field}");
            assert!(
                serde_json::from_str::<OldTeamLimits>(&text).is_err(),
                "{field}"
            );
            assert_eq!(serde_json::from_str::<TeamLimits>(&text).unwrap(), limits);
        }
        // The operator still sees every field.
        assert_eq!(
            serde_json::to_value(defaults)
                .unwrap()
                .as_object()
                .unwrap()
                .len(),
            18
        );
    }

    /// `TeamLimits` of the image before feeds (schema 5, `connect-*`), field for field.
    #[derive(Debug, Deserialize)]
    #[serde(default, deny_unknown_fields)]
    #[allow(dead_code)]
    struct SchemaFiveLimits {
        members: u64,
        items: u64,
        agents: u64,
        runs_per_hour: u64,
        pending_runs: u64,
        agent_requests: u64,
        sync_bytes: u64,
        sync_pushes_per_hour: u64,
        sync_transfers: u64,
        open_questions: u64,
        questions_per_hour: u64,
        question_bytes: u64,
        member_open_questions: u64,
        member_questions_per_hour: u64,
        device_open_questions: u64,
        device_questions_per_hour: u64,
    }

    impl Default for SchemaFiveLimits {
        fn default() -> Self {
            let d = TeamLimits::default();
            Self {
                members: d.members,
                items: d.items,
                agents: d.agents,
                runs_per_hour: d.runs_per_hour,
                pending_runs: d.pending_runs,
                agent_requests: d.agent_requests,
                sync_bytes: d.sync_bytes,
                sync_pushes_per_hour: d.sync_pushes_per_hour,
                sync_transfers: d.sync_transfers,
                open_questions: d.open_questions,
                questions_per_hour: d.questions_per_hour,
                question_bytes: d.question_bytes,
                member_open_questions: d.member_open_questions,
                member_questions_per_hour: d.member_questions_per_hour,
                device_open_questions: d.device_open_questions,
                device_questions_per_hour: d.device_questions_per_hour,
            }
        }
    }

    #[test]
    fn feed_limits_at_the_preset_of_the_kind_read_in_the_schema_5_image() {
        for kind in [TeamKind::Operator, TeamKind::Connect] {
            let preset = TeamLimits::for_kind(kind);
            let text = preset.stored_json(kind).unwrap();
            assert!(!text.contains("feed_"), "{text}");
            serde_json::from_str::<SchemaFiveLimits>(&text).unwrap();
            assert_eq!(TeamLimits::from_stored(Some(&text), kind).unwrap(), preset);
            // Each feed limit away from the preset is written, and the old image refuses
            // the column: the rollback restores relay.db (OPERATIONS 21.3).
            for field in FEED_LIMIT_FIELDS {
                let value = match (field, kind) {
                    ("feed_bytes", TeamKind::Connect) => 2 * MIN_FEED_BYTES,
                    ("feed_bytes", TeamKind::Operator) => MIN_FEED_BYTES,
                    _ => 7,
                };
                let update =
                    serde_json::from_value::<TeamLimitsUpdate>(serde_json::json!({field: value}))
                        .unwrap();
                let limits = preset.apply(update).unwrap();
                let text = limits.stored_json(kind).unwrap();
                assert!(text.contains(field), "{field}");
                assert!(
                    serde_json::from_str::<SchemaFiveLimits>(&text).is_err(),
                    "{field}"
                );
                assert_eq!(TeamLimits::from_stored(Some(&text), kind).unwrap(), limits);
            }
        }
        // A column of the schema 5 image reads the preset of its kind: a Connect team's
        // 1 MiB, an operator team's 4 MiB. No column: the defaults.
        let connect_text =
            r#"{"members":1,"items":0,"agents":0,"sync_bytes":0,"question_bytes":2097152}"#;
        let connect = TeamLimits::from_stored(Some(connect_text), TeamKind::Connect).unwrap();
        // That image wrote no push count: the default of then, still a Connect preset.
        assert_eq!(
            connect,
            TeamLimits {
                sync_pushes_per_hour: 600,
                ..TeamLimits::connect()
            }
        );
        assert!(connect.is_connect_preset(0));
        assert_eq!(connect.feed_bytes, CONNECT_FEED_BYTES);
        let operator =
            TeamLimits::from_stored(Some(r#"{"members":7}"#), TeamKind::Operator).unwrap();
        assert_eq!((operator.members, operator.feed_bytes), (7, 4 * 1_048_576));
        assert_eq!(
            TeamLimits::from_stored(None, TeamKind::Operator).unwrap(),
            TeamLimits::default()
        );
        assert!(TeamLimits::from_stored(Some(r#"{"feeds":1}"#), TeamKind::Operator).is_none());
        assert!(TeamLimits::from_stored(Some("[]"), TeamKind::Operator).is_none());
    }

    /// The directory of the image before Connect teams (version 1002), as it made it.
    const SCHEMA_1002: &str = "
CREATE TABLE team (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, file_key TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('active','suspended')),
  legacy INTEGER NOT NULL DEFAULT 0 CHECK (legacy IN (0, 1)),
  created_at INTEGER NOT NULL, suspended_at INTEGER, limits TEXT);
CREATE UNIQUE INDEX team_legacy ON team(legacy) WHERE legacy = 1;
CREATE TABLE team_code (
  id INTEGER PRIMARY KEY, code_hash BLOB NOT NULL UNIQUE, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, used_at INTEGER, team_id TEXT);
CREATE TABLE audit (
  id INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  run_id INTEGER, detail TEXT NOT NULL);
PRAGMA user_version = 1002;
";

    #[test]
    fn connect_limits_preset() {
        let connect = TeamLimits::connect();
        connect.validate().unwrap();
        assert_eq!(
            (
                connect.members,
                connect.items,
                connect.agents,
                connect.sync_bytes
            ),
            (1, 0, 0, 0)
        );
        assert_eq!(connect.question_bytes, 2 * 1024 * 1024);
        assert_eq!(connect.feed_bytes, 1024 * 1024);
        let defaults = TeamLimits::default();
        assert_eq!(
            TeamLimits {
                members: defaults.members,
                items: defaults.items,
                agents: defaults.agents,
                sync_bytes: defaults.sync_bytes,
                sync_pushes_per_hour: defaults.sync_pushes_per_hour,
                question_bytes: defaults.question_bytes,
                feed_bytes: defaults.feed_bytes,
                ..connect
            },
            defaults
        );
        assert_eq!(connect.sync_pushes_per_hour, CONNECT_SYNC_PUSHES_PER_HOUR);
        // The file cap grows by the feed budget: 2 + 1 + 8 MiB.
        assert_eq!(connect.file_bytes(TeamKind::Connect), Some(11 * 1_048_576));
        assert_eq!(defaults.file_bytes(TeamKind::Operator), None);
        assert_eq!(TeamLimits::for_kind(TeamKind::Operator), defaults);
        assert_eq!(TeamLimits::for_kind(TeamKind::Connect), connect);
        let text = connect.stored_json(TeamKind::Connect).unwrap();
        assert!(!text.contains("feed_bytes"), "{text}");
        assert_eq!(
            TeamLimits::from_stored(Some(&text), TeamKind::Connect).unwrap(),
            connect
        );
        // The operator can still raise every field of a Connect team.
        let raised = connect
            .apply(TeamLimitsUpdate {
                sync_bytes: Some(67_108_864),
                members: Some(5),
                ..Default::default()
            })
            .unwrap();
        assert_eq!((raised.sync_bytes, raised.members), (67_108_864, 5));
    }

    #[test]
    fn connect_with_sync_bytes_stores_them_and_keeps_the_rollback_rule() {
        let synced = TeamLimits::connect_with(67_108_864);
        synced.validate().unwrap();
        assert_eq!(
            TeamLimits {
                sync_bytes: 0,
                ..synced
            },
            TeamLimits::connect()
        );
        // `sync_bytes` is a field of every image's limits; the feed fields stay out.
        let text = synced.stored_json(TeamKind::Connect).unwrap();
        assert!(text.contains(r#""sync_bytes":67108864"#), "{text}");
        for name in FEED_LIMIT_FIELDS {
            assert!(!text.contains(name), "{text}");
        }
        assert_eq!(
            TeamLimits::from_stored(Some(&text), TeamKind::Connect).unwrap(),
            synced
        );
        // Room for the sync heads, only with vault sync: 11 + 16 MiB.
        assert_eq!(synced.file_bytes(TeamKind::Connect), Some(27 * 1_048_576));
        // Both are presets of a relay with the setting; a raised team is not.
        assert!(synced.is_connect_preset(67_108_864));
        assert!(TeamLimits::connect().is_connect_preset(67_108_864));
        assert!(!synced.is_connect_preset(0));
        let raised = synced
            .apply(TeamLimitsUpdate {
                members: Some(5),
                ..Default::default()
            })
            .unwrap();
        assert!(!raised.is_connect_preset(67_108_864));
        // A value between 0 and 1 MiB is not a limit.
        assert!(TeamLimits::connect_with(1024).validate().is_err());
        // B-M2: 30 pushes an hour; a team made before with 600 is still a preset, any
        // other count is the operator's.
        assert_eq!(synced.sync_pushes_per_hour, CONNECT_SYNC_PUSHES_PER_HOUR);
        assert_eq!(TeamLimits::connect().sync_pushes_per_hour, 30);
        for earlier in [TeamLimits::connect(), synced] {
            let before = TeamLimits {
                sync_pushes_per_hour: 600,
                ..earlier
            };
            assert!(before.is_connect_preset(67_108_864));
            let lifted = TeamLimits {
                sync_pushes_per_hour: 120,
                ..earlier
            };
            assert!(!lifted.is_connect_preset(67_108_864));
        }
    }

    #[test]
    fn directory_migrates_1002_to_1005_and_keeps_teams_as_operator() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path());
        let store =
            Store::create_at(&config.directory_path(), &config.master_key, SCHEMA_1002).unwrap();
        let first = TeamId::parse("t_abcdefgh23").unwrap();
        let second = TeamId::parse("t_bcdefgh234").unwrap();
        let key = SecretString::new("test-team-file-key".to_string());
        store
            .with(|conn| {
                insert_team(conn, &first, "First", &key, true, 42)?;
                insert_team(conn, &second, "Second", &key, false, 43)?;
                conn.execute(
                    "UPDATE team SET state = 'suspended', suspended_at = 50, limits = ?1 WHERE id = ?2",
                    params![r#"{"members":7}"#, second.as_str()],
                )
                .map_err(db)?;
                Ok(())
            })
            .unwrap();
        drop(store);

        let directory = Directory::open(&config).unwrap();
        assert_eq!(directory.store.user_version().unwrap(), DIRECTORY_VERSION);
        let rows = directory.teams().unwrap();
        assert_eq!(rows.len(), 2);
        let first_row = directory.team(&first).unwrap().unwrap();
        assert_eq!(
            (
                first_row.name.as_str(),
                first_row.legacy,
                first_row.kind,
                first_row.created_at
            ),
            ("First", true, TeamKind::Operator, 42)
        );
        assert_eq!(first_row.file_key, key);
        assert_eq!(first_row.limits, TeamLimits::default());
        let second_row = directory.team(&second).unwrap().unwrap();
        assert_eq!(second_row.kind, TeamKind::Operator);
        assert_eq!(second_row.state, TeamState::Suspended);
        assert_eq!(second_row.suspended_at, Some(50));
        assert_eq!(second_row.suspend_reason, None);
        assert_eq!(second_row.limits.members, 7);
        // The new table is there and empty.
        directory
            .store
            .with(|conn| {
                check_connect_key(conn, &connect_key_hash(&[4; 65]), 1, 100)?;
                Ok(())
            })
            .unwrap();
        drop(directory);
        // A second open is a no-op.
        assert_eq!(Directory::open(&config).unwrap().teams().unwrap().len(), 2);
    }

    #[test]
    fn connect_keys_are_one_use_and_capped_per_day() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path());
        let directory = Directory::create(&config).unwrap();
        let team = TeamId::parse("t_abcdefgh23").unwrap();
        let key = SecretString::new("test-team-file-key".to_string());
        let one = connect_key_hash(&[4; 65]);
        let two = connect_key_hash(&[5; 65]);
        let three = connect_key_hash(&[6; 65]);
        directory
            .store
            .tx(|tx| {
                check_connect_key(tx, &one, 2, 1000)?;
                insert_connect_team(tx, &team, "Mac", &key, &TeamLimits::connect(), 1000)?;
                insert_connect_key(tx, &one, &team, 1000)
            })
            .unwrap();
        let row = directory.team(&team).unwrap().unwrap();
        assert_eq!(row.kind, TeamKind::Connect);
        assert_eq!(row.limits, TeamLimits::connect());
        directory
            .store
            .with(|conn| {
                assert_eq!(
                    check_connect_key(conn, &one, 100, 1001).unwrap_err().code,
                    codes::CONNECT_KEY_USED
                );
                // The key stays used after a day, and after its team is gone.
                conn.execute("DELETE FROM team", []).map_err(db)?;
                assert_eq!(
                    check_connect_key(conn, &one, 100, 1_000_000)
                        .unwrap_err()
                        .code,
                    codes::CONNECT_KEY_USED
                );
                insert_connect_key(conn, &two, &team, 2000)?;
                // Two in 24 hours: the third waits until the first is a day old.
                assert_eq!(
                    check_connect_key(conn, &three, 2, 2001).unwrap_err().code,
                    codes::BUSY
                );
                check_connect_key(conn, &three, 2, 1000 + 86_400)?;
                check_connect_key(conn, &three, 3, 2001)?;
                // 0 turns Connect off.
                assert_eq!(
                    check_connect_key(conn, &three, 0, 1_000_000)
                        .unwrap_err()
                        .code,
                    codes::BUSY
                );
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn directory_migrates_1001_and_defaults_null_or_partial_limits() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path());
        let old_schema = SCHEMA_1002
            .replace(", limits TEXT", "")
            .replace("user_version = 1002", "user_version = 1001");
        let store =
            Store::create_at(&config.directory_path(), &config.master_key, &old_schema).unwrap();
        let id = TeamId::parse("t_abcdefgh23").unwrap();
        let key = SecretString::new("test-team-file-key".to_string());
        store
            .with(|conn| insert_team(conn, &id, "Team", &key, false, 42))
            .unwrap();
        drop(store);

        let directory = Directory::open(&config).unwrap();
        assert_eq!(directory.store.user_version().unwrap(), DIRECTORY_VERSION);
        let row = directory.team(&id).unwrap().unwrap();
        assert_eq!(row.name, "Team");
        assert_eq!(row.created_at, 42);
        assert_eq!(row.file_key, key);
        assert_eq!(row.limits, TeamLimits::default());
        assert_eq!(row.kind, TeamKind::Operator);
        directory
            .store
            .with(|conn| {
                conn.execute("UPDATE team SET limits = ?1", [r#"{"members":7}"#])
                    .map_err(db)?;
                Ok(())
            })
            .unwrap();
        let row = directory.team(&id).unwrap().unwrap();
        assert_eq!(row.limits.members, 7);
        assert_eq!(row.limits.items, 500);
        drop(directory);
        assert_eq!(
            Directory::open(&config)
                .unwrap()
                .team(&id)
                .unwrap()
                .unwrap()
                .limits
                .members,
            7
        );
    }

    #[test]
    fn new_directory_uses_1005_and_refuses_unknown_versions() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path());
        let directory = Directory::create(&config).unwrap();
        assert_eq!(directory.store.user_version().unwrap(), DIRECTORY_VERSION);
        assert_eq!(DIRECTORY_VERSION, 1006);
        directory
            .store
            .with(|conn| conn.pragma_update(None, "user_version", 1007).map_err(db))
            .unwrap();
        drop(directory);
        assert!(Directory::open(&config).is_err());
        assert_eq!(
            Store::open_at(&config.directory_path(), &config.master_key)
                .unwrap()
                .user_version()
                .unwrap(),
            1007
        );
    }

    /// The tables, indexes, and their SQL of a directory file, by name.
    fn schema_of(config: &RelayConfig) -> Vec<(String, String)> {
        Store::open_at(&config.directory_path(), &config.master_key)
            .unwrap()
            .with(|conn| {
                let mut statement = conn
                    .prepare(
                        "SELECT name, coalesce(sql, '') FROM sqlite_master \
                         WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
                    )
                    .map_err(db)?;
                let rows = statement
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                    .map_err(db)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db)
            })
            .unwrap()
    }

    #[test]
    fn directory_moves_from_1003_to_1005_and_back() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path());
        let fresh = {
            Directory::create(&config).unwrap();
            schema_of(&config)
        };
        for table in ["oauth_client", "connect_request", "oauth_refresh"] {
            assert!(fresh.iter().any(|(name, _)| name == table), "{table}");
        }
        let team = TeamId::parse("t_abcdefgh23").unwrap();
        let key = SecretString::new("test-team-file-key".to_string());
        Store::open_at(&config.directory_path(), &config.master_key)
            .unwrap()
            .with(|conn| {
                insert_team(conn, &team, "First", &key, false, 42)?;
                conn.execute(
                    "INSERT INTO oauth_client (client_id, client_name, redirect_uris, created_at) \
                     VALUES ('c_1', 'Grok Bot', '[\"https://x.example/cb\"]', 42)",
                    [],
                )
                .map_err(db)?;
                Ok(())
            })
            .unwrap();
        // Down: the OAuth tables go, the team stays, and a second run changes nothing.
        assert_eq!(
            Directory::downgrade_to_1003(&config, false).unwrap(),
            (DIRECTORY_VERSION, 1003)
        );
        assert_eq!(
            Directory::downgrade_to_1003(&config, false).unwrap(),
            (1003, 1003)
        );
        let down = schema_of(&config);
        assert!(
            down.iter().all(
                |(name, _)| !name.starts_with("oauth_") && !name.starts_with("connect_request")
            )
        );
        assert!(down.iter().any(|(name, _)| name == "connect_key"));
        // Up again at the next open, with the schema of a new file.
        let directory = Directory::open(&config).unwrap();
        assert_eq!(directory.store.user_version().unwrap(), DIRECTORY_VERSION);
        assert_eq!(directory.teams().unwrap().len(), 1);
        drop(directory);
        assert_eq!(schema_of(&config), fresh);
        // A file of another version is refused, and stays.
        Store::open_at(&config.directory_path(), &config.master_key)
            .unwrap()
            .with(|conn| conn.pragma_update(None, "user_version", 1002).map_err(db))
            .unwrap();
        assert!(Directory::downgrade_to_1003(&config, false).is_err());
    }

    #[test]
    fn failed_migration_does_not_advance_version() {
        // A 1004 file that claims an older version: its migration fails (the columns or
        // tables are there), and the version stays.
        for version in [1001, 1002, 1003] {
            let dir = tempfile::tempdir().unwrap();
            let config = config(dir.path());
            let directory = Directory::create(&config).unwrap();
            directory
                .store
                .with(|conn| {
                    conn.pragma_update(None, "user_version", version)
                        .map_err(db)
                })
                .unwrap();
            drop(directory);
            assert!(Directory::open(&config).is_err());
            assert_eq!(
                Store::open_at(&config.directory_path(), &config.master_key)
                    .unwrap()
                    .user_version()
                    .unwrap(),
                version
            );
        }
    }

    #[test]
    fn directory_moves_from_1004_to_1005_and_back_and_keeps_the_codes() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path());
        let fresh = {
            Directory::create(&config).unwrap();
            schema_of(&config)
        };
        let directory = Directory::open(&config).unwrap();
        let now = 1_790_000_000;
        let (operator, _) = directory.new_team_code(1, now).unwrap();
        let (node, node_expires) = directory.new_node_code(10, now).unwrap();
        assert_eq!(node_expires, now + 600);
        let (used_node, _) = directory.new_node_code(1, now).unwrap();
        let team = TeamId::parse("t_abcdefgh23").unwrap();
        directory
            .store
            .tx(|tx| {
                let (id, kind) = find_team_code(tx, used_node.expose(), now)?;
                assert_eq!(kind, CodeKind::Node);
                mark_team_code_used(tx, id, &team, now)
            })
            .unwrap();
        directory
            .store
            .with(|conn| {
                assert_eq!(
                    find_team_code(conn, operator.expose(), now)?.1,
                    CodeKind::Operator
                );
                assert_eq!(find_team_code(conn, node.expose(), now)?.1, CodeKind::Node);
                // A node code ends after its minutes.
                assert_eq!(
                    find_team_code(conn, node.expose(), node_expires)
                        .unwrap_err()
                        .code,
                    codes::INVITE_INVALID
                );
                Ok(())
            })
            .unwrap();
        // The bounds of a node code: 1 to 10 minutes.
        for minutes in [0, 11, 60] {
            assert_eq!(
                directory.new_node_code(minutes, now).unwrap_err().code,
                codes::INVALID_REQUEST
            );
        }
        let audit: Vec<String> = directory
            .store
            .with(|conn| {
                let mut statement = conn
                    .prepare("SELECT action FROM audit ORDER BY id")
                    .map_err(db)?;
                let rows = statement.query_map([], |row| row.get(0)).map_err(db)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db)
            })
            .unwrap();
        assert_eq!(
            audit,
            [
                "team_code_created",
                "node_code_created",
                "node_code_created"
            ]
        );
        drop(directory);
        // Down: the unused node code goes; the operator code and the used node code stay.
        assert_eq!(
            Directory::downgrade_to_1004(&config, false).unwrap(),
            (DIRECTORY_VERSION, 1004)
        );
        assert_eq!(
            Directory::downgrade_to_1004(&config, false).unwrap(),
            (1004, 1004)
        );
        let kinds: Vec<(String, bool)> =
            Store::open_at(&config.directory_path(), &config.master_key)
                .unwrap()
                .with(|conn| {
                    let mut statement = conn
                        .prepare("SELECT kind, used_at IS NOT NULL FROM team_code ORDER BY id")
                        .map_err(db)?;
                    let rows = statement
                        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                        .map_err(db)?;
                    rows.collect::<Result<Vec<_>, _>>().map_err(db)
                })
                .unwrap();
        assert_eq!(
            kinds,
            [("operator".to_string(), false), ("node".to_string(), true)]
        );
        // Up again at the next open, with the schema of a new file.
        let directory = Directory::open(&config).unwrap();
        assert_eq!(directory.store.user_version().unwrap(), DIRECTORY_VERSION);
        drop(directory);
        assert_eq!(schema_of(&config), fresh);
        // A file of another version is refused by the step to 1004, and stays.
        Store::open_at(&config.directory_path(), &config.master_key)
            .unwrap()
            .with(|conn| conn.pragma_update(None, "user_version", 1003).map_err(db))
            .unwrap();
        assert!(Directory::downgrade_to_1004(&config, false).is_err());
    }

    #[test]
    fn directory_moves_from_1005_to_the_accounts_step_and_back() {
        let fresh_dir = tempfile::tempdir().unwrap();
        let fresh = {
            let config = config(fresh_dir.path());
            Directory::create(&config).unwrap();
            schema_of(&config)
        };
        for table in [
            "account",
            "account_device",
            "account_list",
            "account_key",
            "account_link",
            "account_join",
            "account_store_device",
            "brain_event",
            "group",
            "group_member",
            "group_invite",
            "stripe_customer",
            "stripe_subscription",
            "stripe_event",
            "tunnel_node",
            "tunnel_grant",
            "tunnel_usage",
            "entitlement_key",
            "team_vault",
            "team_legacy",
        ] {
            assert!(fresh.iter().any(|(name, _)| name == table), "{table}");
        }
        // A file of 1005, as the image before made it, with an operator and a Connect team.
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path());
        let key = SecretString::new("test-team-file-key".to_string());
        let operator = TeamId::parse("t_abcdefgh23").unwrap();
        let connect = TeamId::parse("t_bcdefgh234").unwrap();
        let store = Store::create_at(
            &config.directory_path(),
            &config.master_key,
            &format!("{SCHEMA_1005}PRAGMA user_version = 1005;"),
        )
        .unwrap();
        store
            .with(|conn| {
                insert_team(conn, &operator, "First", &key, true, 42)?;
                insert_connect_team(conn, &connect, "Second", &key, &TeamLimits::connect(), 43)
            })
            .unwrap();
        drop(store);
        let directory = Directory::open(&config).unwrap();
        assert_eq!(directory.store.user_version().unwrap(), DIRECTORY_VERSION);
        let rows = directory.teams().unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| (row.id.clone(), row.kind, row.legacy, row.file_key.clone()))
                .collect::<Vec<_>>(),
            [
                (operator.clone(), TeamKind::Operator, true, key.clone()),
                (connect.clone(), TeamKind::Connect, false, key.clone())
            ]
        );
        assert_eq!(rows[1].limits, TeamLimits::connect());
        // A vault store row, and the CHECK of its account and vault ids.
        let store_id = TeamId::parse("t_cdefgh2345").unwrap();
        directory
            .store
            .with(|conn| {
                insert_vault_store(
                    conn,
                    &store_id,
                    "Personal",
                    &key,
                    &TeamLimits::account(1),
                    "acc_k7m2q4x3ca",
                    "0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77",
                    44,
                )
            })
            .unwrap();
        let row = directory.team(&store_id).unwrap().unwrap();
        assert_eq!(
            (row.kind, row.account_id.as_deref(), row.limits),
            (
                TeamKind::Account,
                Some("acc_k7m2q4x3ca"),
                TeamLimits::account(1)
            )
        );
        assert!(
            directory
                .store
                .with(|conn| conn
                    .execute(
                        "UPDATE team SET account_id = NULL WHERE id = ?1",
                        params![store_id.as_str()]
                    )
                    .map_err(db))
                .is_err()
        );
        drop(directory);
        assert_eq!(schema_of(&config), fresh);
        // Without `--delete-vault-stores` the vault store stays and nothing changes.
        let refused = Directory::downgrade_to_1005(&config, false).unwrap_err();
        assert!(
            refused.message.contains("--delete-vault-stores"),
            "{refused:?}"
        );
        assert_eq!(schema_of(&config), fresh);
        // Down: the vault store goes, the other teams stay; a second run changes nothing.
        assert_eq!(
            Directory::downgrade_to_1005(&config, true).unwrap(),
            (DIRECTORY_VERSION, 1005, 1)
        );
        assert_eq!(
            Directory::downgrade_to_1005(&config, false).unwrap(),
            (1005, 1005, 0)
        );
        let left: Vec<String> = Store::open_at(&config.directory_path(), &config.master_key)
            .unwrap()
            .with(|conn| {
                let mut statement = conn
                    .prepare("SELECT id FROM team ORDER BY id")
                    .map_err(db)?;
                let rows = statement.query_map([], |row| row.get(0)).map_err(db)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db)
            })
            .unwrap();
        assert_eq!(left, [operator.to_string(), connect.to_string()]);
        // Up again at the next open, with the schema of a new file.
        let directory = Directory::open(&config).unwrap();
        assert_eq!(directory.store.user_version().unwrap(), DIRECTORY_VERSION);
        drop(directory);
        assert_eq!(schema_of(&config), fresh);
        // Another version is refused by the step to 1005, and stays.
        Store::open_at(&config.directory_path(), &config.master_key)
            .unwrap()
            .with(|conn| conn.pragma_update(None, "user_version", 1004).map_err(db))
            .unwrap();
        assert!(Directory::downgrade_to_1005(&config, false).is_err());
    }

    #[test]
    fn a_1004_file_moves_to_1005_with_operator_codes() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path());
        let directory = Directory::create(&config).unwrap();
        let (code, _) = directory.new_team_code(1, 100).unwrap();
        // The directory of version 1004: no kind column.
        directory
            .store
            .with(|conn| {
                conn.execute_batch(
                    "ALTER TABLE team_code DROP COLUMN kind; PRAGMA user_version = 1004;",
                )
                .map_err(db)
            })
            .unwrap();
        drop(directory);
        let directory = Directory::open(&config).unwrap();
        assert_eq!(directory.store.user_version().unwrap(), DIRECTORY_VERSION);
        directory
            .store
            .with(|conn| {
                assert_eq!(
                    find_team_code(conn, code.expose(), 100)?.1,
                    CodeKind::Operator
                );
                Ok(())
            })
            .unwrap();
    }
}
