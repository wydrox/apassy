//! Schema version 28: the pinned trust of a relay membership (contract node-pairing-v1
//! section 9, docs/design/implementation-plan-s2-s3.md unit N3).
//!
//! - `relay_membership.pin`: the pin of a node relay, the b64u SHA-256 of its
//!   certificate (43 characters). `NULL` for a hosted relay (system trust) and for every
//!   row before 28. A membership with a pin connects to its relay only with that pin.
//! - `relay_membership.alt`: the alternative destinations of a node relay, a JSON list of
//!   `host:port` texts in the order to try them (at most four). `NULL` for none.
//! - `cloud_node.tailnet_on`, `tailnet_port`, `node_origin`, `push_gateway` (plan unit
//!   N4): the tailnet route of the Mac's node. Off by default; the port `NULL` is 8444;
//!   the origin is the last node origin that the node served (`https://<Tailscale
//!   IPv4>:<port>`), so a changed origin is seen; the gateway `NULL` is the default push
//!   gateway. `cloud_node` is a local table too.
//!
//! Only a new pairing of the team sets them (`Vault::set_membership_trust`). The table is
//! local ([`super::merge::LOCAL_TABLES`]): a pushed copy carries none of its rows, so the
//! columns change nothing of sync.
//!
//! Schema 28 follows [`PREVIOUS_SCHEMA_VERSION`] (27, the Bouncer figures): a vault of an
//! earlier schema runs the steps before it and then this one, in one migration. A merge
//! takes a synced copy of schema 16 to the previous schema as before. A device of the
//! previous schema or earlier refuses a copy of schema 28 (`UnsupportedSchema`).
//!
//! The number lives in [`NODE_TRUST_SCHEMA_VERSION`] only, so a release coordinator that
//! renumbers this step changes that constant and [`PREVIOUS_SCHEMA_VERSION`].

use rusqlite::Transaction;

use super::types::{VaultErrorKind, VaultResult, err};
use super::verify_expected_columns_in;

/// The schema version of the pinned trust of a membership.
pub(super) const NODE_TRUST_SCHEMA_VERSION: i64 = 28;
/// The newest schema before this one in the migration chain.
pub(super) const PREVIOUS_SCHEMA_VERSION: i64 = super::schema27::STATS_SCHEMA_VERSION;

const _: () = assert!(PREVIOUS_SCHEMA_VERSION < NODE_TRUST_SCHEMA_VERSION);

/// The longest stored list of alternatives: four entries of a 253-character name, a
/// port, and the JSON around them.
pub(super) const MAX_ALT_JSON_BYTES: usize = 1100;

/// The columns of schema 28.
const SCHEMA_V28_SQL: &str = "
ALTER TABLE relay_membership ADD COLUMN pin TEXT CHECK (pin IS NULL OR length(pin) = 43);
ALTER TABLE relay_membership ADD COLUMN alt TEXT
    CHECK (alt IS NULL OR length(alt) BETWEEN 2 AND 1100);
ALTER TABLE cloud_node ADD COLUMN tailnet_on INTEGER NOT NULL DEFAULT 0
    CHECK (tailnet_on IN (0, 1));
ALTER TABLE cloud_node ADD COLUMN tailnet_port INTEGER
    CHECK (tailnet_port IS NULL OR tailnet_port BETWEEN 1024 AND 65535);
ALTER TABLE cloud_node ADD COLUMN node_origin TEXT
    CHECK (node_origin IS NULL OR length(node_origin) BETWEEN 12 AND 300);
ALTER TABLE cloud_node ADD COLUMN push_gateway TEXT
    CHECK (push_gateway IS NULL OR length(push_gateway) BETWEEN 9 AND 300);
";

/// What `verify_expected_columns_in` reads for schema 28 and later.
pub(super) const COLUMNS: [&str; 2] = [
    "SELECT pin, alt FROM relay_membership LIMIT 0",
    "SELECT tailnet_on, tailnet_port, node_origin, push_gateway FROM cloud_node LIMIT 0",
];

/// The version marks of `version` in `vault_meta` and in the header.
fn marks_sql(version: i64) -> String {
    format!(
        "UPDATE vault_meta SET schema_version = {version} WHERE id = 1;
         PRAGMA user_version = {version};"
    )
}

/// Add schema version 28 in the migration or create transaction. Then the columns of
/// schema 28 are checked in the same transaction.
pub(super) fn add_schema_v28(tx: &Transaction<'_>) -> VaultResult<()> {
    tx.execute_batch(SCHEMA_V28_SQL)
        .map_err(|_| err(VaultErrorKind::Storage))?;
    tx.execute_batch(&marks_sql(NODE_TRUST_SCHEMA_VERSION))
        .map_err(|_| err(VaultErrorKind::Storage))?;
    verify_expected_columns_in(tx, "main", NODE_TRUST_SCHEMA_VERSION)
}

/// The way back to the previous schema, for test fixtures and for the rollback notes. A
/// build of schema 27 has no use for the columns: its memberships are hosted, and a
/// membership of a node then fails to connect (the node's certificate is in no trust
/// store) until this build opens the vault again. The pin of such a row is gone with the
/// column, so that membership needs a new pairing.
#[cfg(test)]
pub(super) fn downgrade_sql() -> String {
    let mut sql = "
ALTER TABLE cloud_node DROP COLUMN push_gateway;
ALTER TABLE cloud_node DROP COLUMN node_origin;
ALTER TABLE cloud_node DROP COLUMN tailnet_port;
ALTER TABLE cloud_node DROP COLUMN tailnet_on;
ALTER TABLE relay_membership DROP COLUMN alt;
ALTER TABLE relay_membership DROP COLUMN pin;
"
    .to_owned();
    sql.push_str(&marks_sql(PREVIOUS_SCHEMA_VERSION));
    sql
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use rusqlite::Connection;

    use super::*;
    use crate::sync::DeviceKey;
    use crate::vault::{
        MembershipPurpose, OPEN_EXISTING, RelayMembership, Vault, apply_key, close_conn,
    };

    const PASS: &str = "synthetic-schema28-pass";
    const PIN: &str = "u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE";
    const TEAM: &str = "t_7k2m5q4x3c";

    fn version(conn: &Connection) -> i64 {
        conn.query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap()
    }

    fn meta_version(conn: &Connection) -> i64 {
        conn.query_row(
            "SELECT schema_version FROM vault_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn raw(path: &std::path::Path) -> Connection {
        let conn = Connection::open_with_flags(path, OPEN_EXISTING).unwrap();
        apply_key(&conn, PASS).unwrap();
        conn
    }

    fn has_columns(conn: &Connection) -> bool {
        conn.prepare("SELECT pin, alt FROM relay_membership")
            .is_ok()
    }

    fn membership(relay_url: &str) -> RelayMembership {
        let key = DeviceKey::generate().unwrap();
        RelayMembership {
            team_id: TEAM.to_owned(),
            relay_url: relay_url.to_owned(),
            device_id: 3,
            public_key: key.public_key().to_vec(),
            key_pkcs8: key.pkcs8().unwrap().clone(),
            purposes: BTreeSet::from([MembershipPurpose::Questions]),
            created_at: 0,
            pin: None,
            alt: Vec::new(),
        }
    }

    /// A vault of the previous schema with one hosted membership.
    fn previous_file(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let path = dir.path().join("v27.db");
        let mut vault = Vault::create(&path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault
            .add_relay_membership(&membership("https://relay.example.test"))
            .unwrap();
        vault.lock().unwrap();
        drop(vault);
        let conn = raw(&path);
        // Schema 29 (`schema29.rs`) first, then this one.
        conn.execute_batch(&crate::vault::schema27::downgrade_to_27_sql())
            .unwrap();
        assert_eq!(version(&conn), PREVIOUS_SCHEMA_VERSION);
        assert_eq!(meta_version(&conn), PREVIOUS_SCHEMA_VERSION);
        assert!(!has_columns(&conn));
        close_conn(conn).unwrap();
        path
    }

    #[test]
    fn a_previous_vault_moves_to_28_and_its_memberships_have_no_pin() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = previous_file(&dir);
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        let conn = vault.conn_ref().unwrap();
        assert_eq!(version(conn), crate::vault::SCHEMA_VERSION);
        assert_eq!(meta_version(conn), crate::vault::SCHEMA_VERSION);
        assert!(has_columns(conn));
        let kept = vault.relay_membership(TEAM).unwrap().unwrap();
        assert_eq!(kept.relay_url, "https://relay.example.test");
        assert_eq!(kept.pin, None);
        assert!(kept.alt.is_empty());
        // A pin of another length and an empty list are refused by the table too.
        let conn = vault.conn_ref().unwrap();
        for bad in [
            "UPDATE relay_membership SET pin = 'short'",
            "UPDATE relay_membership SET alt = ''",
        ] {
            assert!(conn.execute(bad, []).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_failed_migration_keeps_the_previous_schema() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = previous_file(&dir);
        let mut conn = raw(&path);
        let tx = conn.transaction().unwrap();
        add_schema_v28(&tx).unwrap();
        // Roll back, as a failure of a later step does.
        drop(tx);
        assert_eq!(version(&conn), PREVIOUS_SCHEMA_VERSION);
        assert_eq!(meta_version(&conn), PREVIOUS_SCHEMA_VERSION);
        assert!(!has_columns(&conn));
        close_conn(conn).unwrap();
    }

    #[test]
    fn the_way_back_keeps_the_membership_and_the_next_unlock_moves_to_28_again() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("v28.db");
        let mut vault = Vault::create(&path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault
            .add_relay_membership(&membership("https://100.64.0.7:8444"))
            .unwrap();
        let alt = vec!["apassy-mini.tail0123.ts.net:8444".to_owned()];
        vault.set_membership_trust(TEAM, Some(PIN), &alt).unwrap();
        let stored = vault.relay_membership(TEAM).unwrap().unwrap();
        assert_eq!(stored.pin.as_deref(), Some(PIN));
        assert_eq!(stored.alt, alt);
        vault.lock().unwrap();
        drop(vault);

        let conn = raw(&path);
        conn.execute_batch(&crate::vault::schema27::downgrade_to_27_sql())
            .unwrap();
        assert_eq!(version(&conn), PREVIOUS_SCHEMA_VERSION);
        let rows: i64 = conn
            .query_row("SELECT count(*) FROM relay_membership", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 1, "the membership stays without its pin");
        close_conn(conn).unwrap();

        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        assert_eq!(
            version(vault.conn_ref().unwrap()),
            crate::vault::SCHEMA_VERSION
        );
        let back = vault.relay_membership(TEAM).unwrap().unwrap();
        assert_eq!(back.pin, None, "a new pairing sets the pin again");
        assert!(back.alt.is_empty());
    }

    #[test]
    fn copies_of_the_previous_schema_merge_and_a_new_vault_has_the_columns() {
        for version in [16, 25, PREVIOUS_SCHEMA_VERSION, NODE_TRUST_SCHEMA_VERSION] {
            assert!(
                crate::vault::merge::is_mergeable_schema(version),
                "{version}"
            );
        }
        assert!(!crate::vault::merge::is_mergeable_schema(
            crate::vault::SCHEMA_VERSION + 1
        ));
        const { assert!(NODE_TRUST_SCHEMA_VERSION <= crate::vault::SCHEMA_VERSION) };
        assert!(crate::vault::merge::LOCAL_TABLES.contains(&"relay_membership"));

        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("new.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let conn = vault.conn_ref().unwrap();
        assert_eq!(version(conn), crate::vault::SCHEMA_VERSION);
        assert!(has_columns(conn));
    }
}
