#![cfg(feature = "vault")]

//! Sync copies of schema 16 (before passkeys) on Macs of schema 17: adoption on a new
//! Mac, a new passphrase, the folder, and the relay. Synthetic values only.
//!
//! Schema 17 adds no table and no column: a passkey is an item field with a reserved
//! `passkey_` name. So a copy of schema 17 without passkey fields is the copy that the
//! app of schema 16 pushed, except the two version marks and the content digest. The
//! fixture changes the marks and stores a new digest. The digest is a copy of the
//! app's algorithm (`content_digest` in `src/vault/sync.rs`); each fixture first checks
//! the copy against the digest that the app stored.
//!
//! The merge itself (the reserved names, a mixed file, a header-only change) is in
//! `vault::merge::schema16_tests`.

#[path = "common/fake_relay.rs"]
mod fake_relay;

/// The fake relay reads the app's sync module under this name.
use apassy::sync as relay_api;

use std::fs;
use std::path::{Path, PathBuf};

use apassy::contracts::CredentialKind;
use apassy::sync::{
    DeviceKey, FolderSync, HeadFields, JoinedDevice, PendingJoin, RelayConfig, RelaySync,
    SignedHead, SyncConfig, sha256_hex,
};
use apassy::vault::{Field, ItemDraft, SecretValue, SyncScope, Vault, VaultErrorKind};
use fake_relay::{FakeRelay, StoredHead};
use ring::digest;
use rusqlite::Connection;
use rusqlite::types::ValueRef;
use tempfile::TempDir;

const PASS: &str = "synthetic-upgrade-pass";
const NEW_PASS: &str = "synthetic-upgrade-new-pass";
const WRONG: &str = "synthetic-upgrade-wrong";
const CURRENT: i64 = 17;
const OLD: i64 = 16;

// ---- Fixture: a copy of schema 16 ----

/// The content digest of a sync copy: the algorithm of `content_digest` in
/// `src/vault/sync.rs` ("apassy-sync-content-v1"), over `main`.
fn content_digest(conn: &Connection) -> [u8; 32] {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(b"apassy-sync-content-v1\0");
    let mut tables = Vec::new();
    {
        let mut stmt = conn
            .prepare("SELECT type, name, tbl_name, sql FROM main.sqlite_schema ORDER BY type, name")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            ctx.update(b"S");
            for index in 0..4 {
                hash_value(&mut ctx, row.get_ref(index).unwrap());
            }
            let kind: String = row.get(0).unwrap();
            let name: String = row.get(1).unwrap();
            if kind == "table" && name != "sync_meta" {
                tables.push(name);
            }
        }
    }
    for table in tables {
        ctx.update(b"T");
        hash_value(&mut ctx, ValueRef::Text(table.as_bytes()));
        let sql = format!(
            "SELECT * FROM main.\"{}\" ORDER BY rowid",
            table.replace('"', "\"\"")
        );
        let mut stmt = conn.prepare(&sql).unwrap();
        let columns = stmt.column_count();
        let mut rows = stmt.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            ctx.update(b"R");
            for index in 0..columns {
                hash_value(&mut ctx, row.get_ref(index).unwrap());
            }
        }
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

fn hash_value(ctx: &mut digest::Context, value: ValueRef<'_>) {
    let len = |bytes: &[u8]| (bytes.len() as u64).to_be_bytes();
    match value {
        ValueRef::Null => ctx.update(b"n"),
        ValueRef::Integer(n) => {
            ctx.update(b"i");
            ctx.update(&n.to_be_bytes());
        }
        ValueRef::Real(x) => {
            ctx.update(b"r");
            ctx.update(&x.to_bits().to_be_bytes());
        }
        ValueRef::Text(bytes) => {
            ctx.update(b"t");
            ctx.update(&len(bytes));
            ctx.update(bytes);
        }
        ValueRef::Blob(bytes) => {
            ctx.update(b"b");
            ctx.update(&len(bytes));
            ctx.update(bytes);
        }
    }
}

fn open_raw(path: &Path, passphrase: &str) -> Connection {
    let conn = Connection::open(path).unwrap();
    conn.pragma_update(None, "key", passphrase).unwrap();
    conn
}

/// The version in the header and in `vault_meta` of the closed file at `path`.
fn versions(path: &Path, passphrase: &str) -> (i64, i64) {
    let conn = open_raw(path, passphrase);
    let header = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    let meta = conn
        .query_row(
            "SELECT schema_version FROM vault_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    conn.close().map_err(|(_, e)| e).unwrap();
    (header, meta)
}

/// Give the closed sync copy at `path` (schema 17, written by the app) the version
/// marks of `version`. `digest`: store the content digest of the changed rows, as the
/// push of that app does; else the old digest stays. The copy must have no passkey
/// field, and the stored digest must be the one of this copy of the algorithm.
fn set_schema(path: &Path, passphrase: &str, version: i64, digest: bool) {
    let conn = open_raw(path, passphrase);
    let marks: (i64, i64) = conn
        .query_row(
            "SELECT (SELECT user_version FROM pragma_user_version), schema_version
             FROM vault_meta WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        marks,
        (CURRENT, CURRENT),
        "the app writes the current schema"
    );
    let passkeys: i64 = conn
        .query_row(
            "SELECT count(*) FROM item_field WHERE substr(name, 1, 8) = 'passkey_'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(passkeys, 0, "a schema 16 copy has no passkey field");
    let stored: Vec<u8> = conn
        .query_row(
            "SELECT content_digest FROM sync_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        stored,
        content_digest(&conn),
        "the test digest is the algorithm of the app"
    );
    conn.execute_batch(&format!(
        "UPDATE vault_meta SET schema_version = {version} WHERE id = 1;
         PRAGMA user_version = {version};"
    ))
    .unwrap();
    if digest {
        let new = content_digest(&conn);
        assert_ne!(new.as_slice(), stored.as_slice(), "vault_meta is content");
        conn.execute(
            "UPDATE sync_meta SET content_digest = ?1 WHERE id = 1",
            [new.as_slice()],
        )
        .unwrap();
    }
    conn.close().map_err(|(_, e)| e).unwrap();
    assert_eq!(versions(path, passphrase), (version, version));
}

fn sha(path: &Path) -> String {
    apassy::sync::file_sha256(path).unwrap()
}

fn item(title: &str, token: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![
            Field {
                name: "service".to_owned(),
                value: SecretValue::new("synthetic-service".to_owned()),
                secret: false,
            },
            Field {
                name: "token".to_owned(),
                value: SecretValue::new(token.to_owned()),
                secret: true,
            },
        ],
    }
}

fn titles(vault: &Vault) -> Vec<String> {
    let mut titles: Vec<String> = vault
        .search("")
        .unwrap()
        .into_iter()
        .map(|summary| summary.title)
        .collect();
    titles.sort();
    titles
}

fn token(vault: &Vault, title: &str) -> String {
    let found = vault.search("").unwrap();
    let matches: Vec<_> = found.iter().filter(|item| item.title == title).collect();
    assert_eq!(matches.len(), 1, "one item {title}");
    vault
        .reveal(matches[0].id, "token")
        .unwrap()
        .expose()
        .to_owned()
}

fn content(vault: &Vault) -> [u8; 32] {
    vault.sync_content(&SyncScope::vault()).unwrap()
}

/// Mac A with two items, unlocked, and a sync copy of it with schema 16 marks.
fn mac_a_and_old_copy(root: &Path) -> (Vault, PathBuf) {
    let mut a = Vault::create(&root.join("a.db"), PASS).unwrap();
    a.unlock(PASS).unwrap();
    a.add(item("Alpha", "SYNTH-alpha")).unwrap();
    a.add(item("Beta", "SYNTH-beta")).unwrap();
    let copy = root.join("old-copy.apassy");
    a.write_sync_copy(&copy, "Mac A").unwrap();
    set_schema(&copy, PASS, OLD, true);
    (a, copy)
}

// ---- Vault: adopt and new passphrase ----

#[test]
fn a_new_mac_adopts_a_schema16_copy_without_a_change_to_the_copy() {
    let root = TempDir::new().unwrap();
    let (mut a, copy) = mac_a_and_old_copy(root.path());
    let before = sha(&copy);
    let identity = Vault::inspect_sync_copy(&copy, PASS).unwrap();
    assert_eq!(identity.vault_id, a.sync_identity().unwrap().vault_id);

    let (mut b, adopted) = Vault::adopt_sync_copy(&copy, &root.path().join("b.db"), PASS).unwrap();
    assert_eq!(adopted.schema, OLD);
    assert!(adopted.outdated());
    assert_eq!(adopted.identity, identity);
    assert_eq!(sha(&copy), before, "the source copy does not change");
    assert_eq!(versions(&copy, PASS), (OLD, OLD));
    b.unlock(PASS).unwrap();
    // The migration adds no edit: the same records, the same synced content.
    assert_eq!(adopted.content, content(&a));
    assert_eq!(content(&b), content(&a));
    assert_eq!(titles(&b), ["Alpha", "Beta"]);
    assert_eq!(token(&b, "Beta"), "SYNTH-beta");
    b.lock().unwrap();
    assert_eq!(versions(b.path(), PASS), (CURRENT, CURRENT));
    b.unlock(PASS).unwrap();

    // The copy of B is the current schema; A takes it with no change and no conflict.
    let b_copy = root.path().join("b-copy.apassy");
    b.write_sync_copy(&b_copy, "Mac B").unwrap();
    assert_eq!(versions(&b_copy, PASS), (CURRENT, CURRENT));
    let report = a.merge_from(&b_copy, &SyncScope::vault()).unwrap();
    assert!(!report.changed_local());
    assert!(report.conflicts.is_empty());
    assert!(!report.remote_outdated());
    assert_eq!(report.remote_schema, CURRENT);
    // The old copy again: nothing to take, but it is outdated.
    let report = a.merge_from(&copy, &SyncScope::vault()).unwrap();
    assert!(!report.changed_local());
    assert!(report.remote_outdated());
    assert_eq!(titles(&a), ["Alpha", "Beta"]);
    assert!(a.conflict_copies().unwrap().is_empty());
    assert_eq!(sha(&copy), before);
}

#[test]
fn schema16_adoption_keeps_the_key_digest_and_schema_checks() {
    let root = TempDir::new().unwrap();
    let (mut a, copy) = mac_a_and_old_copy(root.path());
    let refuse = |source: &Path, passphrase: &str, kind: VaultErrorKind| {
        let before = sha(source);
        assert_eq!(
            Vault::inspect_sync_copy(source, passphrase)
                .unwrap_err()
                .kind(),
            kind
        );
        let dest = root.path().join("refused.db");
        let failed = Vault::adopt_sync_copy(source, &dest, passphrase).map(|_| ());
        assert_eq!(failed.unwrap_err().kind(), kind);
        assert!(!dest.exists(), "a refused copy makes no vault file");
        assert_eq!(sha(source), before, "the source does not change");
    };

    refuse(&copy, WRONG, VaultErrorKind::WrongKeyOrCorrupt);

    // The marks of schema 16 without the digest of a push.
    let stale = root.path().join("stale.apassy");
    a.write_sync_copy(&stale, "Mac A").unwrap();
    set_schema(&stale, PASS, OLD, false);
    refuse(&stale, PASS, VaultErrorKind::WrongKeyOrCorrupt);

    // A later and an earlier schema, each with a valid digest.
    for version in [CURRENT + 1, OLD - 1] {
        let path = root.path().join(format!("v{version}.apassy"));
        a.write_sync_copy(&path, "Mac A").unwrap();
        set_schema(&path, PASS, version, true);
        refuse(&path, PASS, VaultErrorKind::UnsupportedSchema);
    }

    // The schema 16 copy still adopts after the refusals.
    let (_, adopted) = Vault::adopt_sync_copy(&copy, &root.path().join("b.db"), PASS).unwrap();
    assert!(adopted.outdated());
}

#[test]
fn a_new_passphrase_comes_from_a_schema16_copy() {
    let root = TempDir::new().unwrap();
    let mut a = Vault::create(&root.path().join("a.db"), PASS).unwrap();
    a.unlock(PASS).unwrap();
    a.add(item("Alpha", "SYNTH-alpha")).unwrap();
    let seed = root.path().join("seed.apassy");
    a.write_sync_copy(&seed, "Mac A").unwrap();
    let (mut old, _) = Vault::adopt_sync_copy(&seed, &root.path().join("old.db"), PASS).unwrap();
    old.unlock(PASS).unwrap();
    old.change_passphrase(PASS, NEW_PASS).unwrap();
    old.unlock(NEW_PASS).unwrap();
    let copy = root.path().join("old-push.apassy");
    old.write_sync_copy(&copy, "Old Mac").unwrap();
    set_schema(&copy, NEW_PASS, OLD, true);
    let before = sha(&copy);

    let wrong = a.take_passphrase_of_copy_report(&copy, WRONG).unwrap_err();
    assert!(!wrong.rekeyed);
    Vault::verify_passphrase_at(a.path(), PASS).unwrap();
    a.take_passphrase_of_copy(&copy, NEW_PASS).unwrap();
    assert!(!a.is_locked());
    Vault::verify_passphrase_at(a.path(), NEW_PASS).unwrap();
    assert!(Vault::verify_passphrase_at(a.path(), PASS).is_err());
    assert_eq!(sha(&copy), before);
    assert_eq!(token(&a, "Alpha"), "SYNTH-alpha");
}

// ---- Folder sync ----

fn folder_sync(root: &Path, mac: &str, vault_path: &Path, folder: &Path) -> FolderSync {
    let data = root.join(mac);
    fs::create_dir_all(&data).unwrap();
    FolderSync::new(SyncConfig::in_data_dir(&data, vault_path, folder, "vault"))
}

#[test]
fn folder_sync_adopts_a_schema16_file_and_a_new_passphrase_replaces_it() {
    let root = TempDir::new().unwrap();
    let folder = root.path().join("Dropbox").join("Apassy");
    fs::create_dir_all(&folder).unwrap();
    let mut a = Vault::create(&root.path().join("a.db"), PASS).unwrap();
    a.unlock(PASS).unwrap();
    a.add(item("Alpha", "SYNTH-alpha")).unwrap();
    let sync_a = folder_sync(root.path(), "a-data", a.path(), &folder);
    let name = sync_a.enable(&mut a, "Personal").unwrap().file_name;
    let file = folder.join(&name);
    // An old Mac pushed this file: schema 16.
    set_schema(&file, PASS, OLD, true);
    let before = sha(&file);

    // A new Mac adopts it.
    let c_path = root.path().join("c.db");
    let sync_c = folder_sync(root.path(), "c-data", &c_path, &folder);
    let (mut c, report) = sync_c.adopt(&name, PASS).unwrap();
    assert_eq!(
        report.identity.vault_id,
        a.sync_identity().unwrap().vault_id
    );
    assert_eq!(sha(&file), before, "adoption reads the file only");
    c.unlock(PASS).unwrap();
    assert_eq!(content(&c), content(&a));
    assert!(sync_c.sync(&mut c).unwrap().pushed);
    assert_eq!(versions(&file, PASS), (CURRENT, CURRENT));
    assert!(!sync_c.sync(&mut c).unwrap().pushed);
    // An edit on the new Mac goes up with the current schema.
    c.add(item("Gamma", "SYNTH-gamma")).unwrap();
    assert!(sync_c.sync(&mut c).unwrap().pushed);
    assert_eq!(versions(&file, PASS), (CURRENT, CURRENT));
    let outcome = sync_a.sync(&mut a).unwrap();
    let merge = outcome.merge.unwrap();
    assert_eq!((merge.inserted, merge.updated), (1, 0));
    assert!(!merge.remote_outdated());
    assert!(!outcome.pushed);

    // The old Mac changes the passphrase and pushes schema 16 again.
    let (mut old, _) = Vault::adopt_sync_copy(&file, &root.path().join("old.db"), PASS).unwrap();
    old.unlock(PASS).unwrap();
    old.change_passphrase(PASS, NEW_PASS).unwrap();
    old.unlock(NEW_PASS).unwrap();
    let push = root.path().join("old-push.apassy");
    old.write_sync_copy(&push, "Old Mac").unwrap();
    set_schema(&push, NEW_PASS, OLD, true);
    fs::rename(&push, &file).unwrap();
    assert!(
        sync_a.sync(&mut a).is_err(),
        "the key of A does not open it"
    );
    let outcome = sync_a.take_new_passphrase(&mut a, NEW_PASS).unwrap();
    let merge = outcome.merge.unwrap();
    assert!(!merge.changed_local());
    assert!(merge.remote_outdated());
    assert!(outcome.pushed, "the same content, but an earlier schema");
    assert_eq!(versions(&file, NEW_PASS), (CURRENT, CURRENT));
    assert_eq!(titles(&a), ["Alpha", "Gamma"]);
    let again = sync_a.sync(&mut a).unwrap();
    assert!(again.merge.is_none());
    assert!(!again.pushed);
}

// ---- Relay ----

struct Mac {
    data: PathBuf,
    vault_path: PathBuf,
    sync: RelaySync,
}

fn mac(root: &TempDir, name: &str, url: &str) -> Mac {
    let data = root.path().join(name).join("Apassy");
    fs::create_dir_all(&data).unwrap();
    let vault_path = data.join("vault.db");
    Mac {
        sync: RelaySync::new(RelayConfig::in_data_dir(&data, &vault_path, url, "vault")),
        data,
        vault_path,
    }
}

fn join(a: &Mac, vault_a: &Vault, device_name: &str) -> JoinedDevice {
    let code = a.sync.create_link(vault_a).unwrap();
    let pending = PendingJoin::request(&code.link, "", device_name).unwrap();
    assert!(pending.poll().unwrap().is_none());
    let links = a.sync.pending_links(vault_a, Some(&code)).unwrap();
    a.sync.confirm_link(vault_a, &links[0]).unwrap();
    pending.poll().unwrap().unwrap()
}

/// Mac A made the team; Mac B, the old Mac, joined. Both are unlocked.
struct Team {
    root: TempDir,
    relay: FakeRelay,
    a: Mac,
    vault_a: Vault,
    vault_b: Vault,
}

fn team() -> Team {
    let root = TempDir::new().unwrap();
    let relay = FakeRelay::start();
    let a = mac(&root, "a", &relay.url);
    let b = mac(&root, "b", &relay.url);
    let mut vault_a = Vault::create(&a.vault_path, PASS).unwrap();
    vault_a.unlock(PASS).unwrap();
    vault_a.add(item("Alpha", "SYNTH-alpha")).unwrap();
    a.sync
        .create_team(
            &mut vault_a,
            "Personal",
            &relay.team_code(),
            "Synthetic MacBook",
        )
        .unwrap();
    let joined = join(&a, &vault_a, "Synthetic old Mac");
    let download = joined.download(&b.data.join("sync")).unwrap();
    let (mut vault_b, _) = b.sync.adopt(&joined, &download, PASS).unwrap();
    vault_b.unlock(PASS).unwrap();
    Team {
        root,
        relay,
        a,
        vault_a,
        vault_b,
    }
}

/// The old Mac pushes its vault as a schema 16 copy: the next version, signed with its
/// device key.
fn old_mac_push(team: &mut Team) {
    let path = team.root.path().join("old-push.apassy");
    team.vault_b.write_sync_copy(&path, "Old Mac").unwrap();
    set_schema(&path, PASS, OLD, true);
    let bytes = fs::read(&path).unwrap();
    let heads = team.relay.heads();
    let last = heads.last().unwrap();
    let row = team.vault_b.relay_device().unwrap().unwrap();
    let key = DeviceKey::from_pkcs8(row.key_pkcs8).unwrap();
    let fields = HeadFields {
        version: last.version + 1,
        previous: last.hash(),
        snapshot_sha256: sha256_hex(&bytes),
        size: bytes.len() as u64,
        device_id: row.device_id,
        ..HeadFields::parse(&last.text).unwrap()
    };
    let signed = SignedHead::sign(fields, &key).unwrap();
    team.relay.replace_from(vec![(
        StoredHead {
            version: last.version + 1,
            text: signed.text,
            signature: signed.signature,
            device_id: row.device_id,
        },
        bytes,
    )]);
}

#[test]
fn a_schema16_relay_copy_is_replaced_also_with_the_same_content_and_after_a_failed_push() {
    let mut t = team();
    old_mac_push(&mut t);
    assert_eq!(t.relay.version(), 2);
    let puts = t.relay.count("PUT /v1/sync/snapshot");

    // The first push fails: the next sync pushes without a new download.
    t.relay.fail_next("PUT /v1/sync/snapshot", 1, 500);
    assert!(t.a.sync.sync(&mut t.vault_a).is_err());
    assert_eq!(t.relay.version(), 2);
    assert!(
        t.a.sync.local_changed(&t.vault_a).unwrap(),
        "an upgrade waits"
    );
    let downloads = t.relay.count("GET /v1/sync/snapshot");
    let outcome = t.a.sync.sync(&mut t.vault_a).unwrap();
    assert!(outcome.pushed, "the same content, but an earlier schema");
    assert!(outcome.merge.is_none());
    assert_eq!(t.relay.count("GET /v1/sync/snapshot"), downloads);
    assert_eq!(t.relay.version(), 3);
    assert!(t.relay.count("PUT /v1/sync/snapshot") > puts);
    let again = t.a.sync.sync(&mut t.vault_a).unwrap();
    assert!(!again.pushed);
    assert!(again.merge.is_none());

    // Another Mac of schema 17 reads version 3 with the current schema.
    let c = mac(&t.root, "c", &t.relay.url);
    let joined = join(&t.a, &t.vault_a, "Synthetic Mac mini");
    let download = joined.download(&c.data.join("sync")).unwrap();
    let (mut vault_c, _) = c.sync.adopt(&joined, &download, PASS).unwrap();
    vault_c.unlock(PASS).unwrap();
    assert_eq!(titles(&vault_c), ["Alpha"]);
    assert_eq!(content(&vault_c), content(&t.vault_a));
    let outcome = c.sync.sync(&mut vault_c).unwrap();
    assert!(!outcome.pushed, "a current copy needs no upgrade");
    assert_eq!(t.relay.version(), 3);
}

#[test]
fn a_schema16_relay_copy_merges_an_edit_and_the_schema_in_the_report() {
    let mut t = team();
    let alpha = t.vault_b.search("").unwrap()[0].clone();
    t.vault_b
        .update(
            alpha.id,
            alpha.revision,
            item("Alpha", "SYNTH-alpha-old-mac"),
        )
        .unwrap();
    old_mac_push(&mut t);
    let outcome = t.a.sync.sync(&mut t.vault_a).unwrap();
    let merge = outcome.merge.unwrap();
    assert_eq!((merge.inserted, merge.updated), (0, 1));
    assert!(merge.conflicts.is_empty());
    assert_eq!(merge.remote_schema, OLD);
    assert!(merge.remote_outdated());
    assert!(outcome.pushed);
    assert_eq!(t.relay.version(), 3);
    assert_eq!(token(&t.vault_a, "Alpha"), "SYNTH-alpha-old-mac");
    assert!(t.vault_a.conflict_copies().unwrap().is_empty());
}

#[test]
fn a_new_mac_adopts_a_schema16_relay_copy_and_its_first_sync_upgrades_it() {
    let mut t = team();
    old_mac_push(&mut t);
    let c = mac(&t.root, "c", &t.relay.url);
    let joined = join(&t.a, &t.vault_a, "Synthetic Mac mini");
    let download = joined.download(&c.data.join("sync")).unwrap();
    // A wrong passphrase makes no file; the download stays for the next try.
    assert!(c.sync.adopt(&joined, &download, WRONG).is_err());
    assert!(!c.vault_path.exists());
    let (mut vault_c, report) = c.sync.adopt(&joined, &download, PASS).unwrap();
    assert_eq!(
        report.identity.vault_id,
        t.vault_a.sync_identity().unwrap().vault_id
    );
    vault_c.unlock(PASS).unwrap();
    assert_eq!(titles(&vault_c), ["Alpha"]);
    assert_eq!(content(&vault_c), content(&t.vault_b));

    let downloads = t.relay.count("GET /v1/sync/snapshot");
    let outcome = c.sync.sync(&mut vault_c).unwrap();
    assert!(outcome.pushed, "the adopted copy was outdated");
    assert!(outcome.merge.is_none());
    assert_eq!(t.relay.count("GET /v1/sync/snapshot"), downloads);
    assert_eq!(t.relay.version(), 3);
    assert!(!c.sync.sync(&mut vault_c).unwrap().pushed);

    // Mac A merges version 3: the current schema, the same records.
    let outcome = t.a.sync.sync(&mut t.vault_a).unwrap();
    let merge = outcome.merge.unwrap();
    assert_eq!(merge.remote_schema, CURRENT);
    assert!(!merge.changed_local());
    assert!(!outcome.pushed);
}
