#![cfg(feature = "vault")]

//! Sync of a vault through a folder (ADR 0014, docs/operations/sync.md). Synthetic
//! values only.
//!
//! A temporary folder stands in for iCloud Drive or Dropbox, and each "Mac" is a
//! separate data folder with its own local vault file. So the tests run on Linux and
//! macOS, and never touch a real synced folder. The sync service itself (upload,
//! download, eviction) is simulated with file operations.

use std::fs;
use std::path::{Path, PathBuf};

use apassy::contracts::CredentialKind;
use apassy::sync::{
    FileStatus, FolderSync, PUSH_SUFFIX, SyncConfig, SyncError, detect_folders_in, device_name,
    file_name_for, icloud_folder, list_folder_vaults,
};
use apassy::vault::{
    ActivityDecision, EnvDelivery, Field, ItemDraft, LOCAL_TABLES, NewActivity, SYNCED_TABLES,
    SecretValue, SyncScope, Vault, VaultErrorKind,
};
use tempfile::TempDir;

const PASS: &str = "synthetic-sync-pass";
const NEW_PASS: &str = "synthetic-sync-pass-new";
const WRONG: &str = "synthetic-sync-wrong";
const FILE: &str = "Personal.apassy";
const PAGE_SIZE: usize = 4096;

/// A temporary synced folder (`<root>/Dropbox/Apassy`, not created yet).
struct World {
    root: TempDir,
    folder: PathBuf,
}

fn world() -> World {
    let root = TempDir::new().expect("temp dir");
    let service = root.path().join("Dropbox");
    fs::create_dir_all(&service).expect("sync service folder");
    let folder = service.join("Apassy");
    World { root, folder }
}

/// One Mac: a data folder, its local vault path, and its sync engine.
struct Mac {
    data: PathBuf,
    vault_path: PathBuf,
    sync: FolderSync,
}

impl World {
    fn mac(&self, name: &str) -> Mac {
        let data = self.root.path().join(name).join("Apassy");
        fs::create_dir_all(&data).expect("data dir");
        let vault_path = data.join("vault.db");
        let config = SyncConfig::in_data_dir(&data, &vault_path, &self.folder, "vault");
        Mac {
            data,
            vault_path,
            sync: FolderSync::new(config),
        }
    }

    fn file(&self) -> PathBuf {
        self.folder.join(FILE)
    }
}

impl Mac {
    fn create(&self, passphrase: &str) -> Vault {
        let mut vault = Vault::create(&self.vault_path, passphrase).expect("create");
        vault.unlock(passphrase).expect("unlock");
        vault
    }

    fn status(&self) -> FileStatus {
        self.sync.status().expect("status").status
    }
}

fn item(title: &str, token: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![Field {
            name: "token".to_owned(),
            value: SecretValue::new(token.to_owned()),
            secret: true,
        }],
    }
}

fn titles(vault: &Vault) -> Vec<String> {
    let mut titles: Vec<String> = vault
        .search("")
        .expect("search")
        .into_iter()
        .map(|summary| summary.title)
        .collect();
    titles.sort();
    titles
}

fn id_of(vault: &Vault, title: &str) -> u64 {
    vault
        .search("")
        .expect("search")
        .into_iter()
        .find(|summary| summary.title == title)
        .map(|summary| summary.id)
        .unwrap_or_else(|| panic!("no credential {title}"))
}

fn token_of(vault: &Vault, title: &str) -> String {
    vault
        .reveal(id_of(vault, title), "token")
        .expect("reveal")
        .expose()
        .to_owned()
}

fn edit(vault: &mut Vault, title: &str, token: &str) {
    let id = id_of(vault, title);
    let revision = vault.details(id).expect("details").summary.revision;
    vault
        .update(id, revision, item(title, token))
        .expect("update");
}

/// Mac A with "Personal" in the folder (first push), and Mac B adopted from it. Both
/// unlocked.
fn two_macs(world: &World) -> (Mac, Vault, Mac, Vault) {
    let a = world.mac("mac-a");
    let mut vault_a = a.create(PASS);
    vault_a.add(item("Alpha", "SYNTH-alpha-1")).expect("add");
    let report = a.sync.enable(&mut vault_a, "Personal").expect("enable");
    assert_eq!(report.file_name, FILE);
    assert!(!report.linked);
    let b = world.mac("mac-b");
    let (mut vault_b, _) = b.sync.adopt(FILE, PASS).expect("adopt");
    vault_b.unlock(PASS).expect("unlock b");
    (a, vault_a, b, vault_b)
}

/// Open a synced file with the passphrase through a private copy, for a look inside.
fn peek(path: &Path, passphrase: &str) -> (TempDir, rusqlite::Connection) {
    let dir = TempDir::new().expect("temp");
    let copy = dir.path().join("peek.db");
    fs::copy(path, &copy).expect("copy");
    let conn = rusqlite::Connection::open(&copy).expect("open");
    conn.pragma_update(None, "key", passphrase).expect("key");
    (dir, conn)
}

fn count(conn: &rusqlite::Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |row| row.get(0)).expect("count")
}

#[test]
fn two_macs_editing_different_credentials_merge_without_a_conflict() {
    let world = world();
    let (a, mut vault_a, b, mut vault_b) = two_macs(&world);
    assert_eq!(titles(&vault_b), vec!["Alpha"]);
    assert_eq!(token_of(&vault_b, "Alpha"), "SYNTH-alpha-1");

    vault_a.add(item("From A", "SYNTH-a")).expect("add");
    vault_b.add(item("From B", "SYNTH-b")).expect("add");
    edit(&mut vault_b, "Alpha", "SYNTH-alpha-2");

    // A pushes first; B merges A's file, then pushes the merged result.
    assert!(a.sync.sync(&mut vault_a).expect("sync a").pushed);
    let outcome = b.sync.sync(&mut vault_b).expect("sync b");
    let merge = outcome.merge.expect("B merged the file of A");
    assert_eq!(merge.inserted, 1);
    assert!(merge.conflicts.is_empty(), "{merge:?}");
    assert!(outcome.pushed);
    assert_eq!(titles(&vault_b), vec!["Alpha", "From A", "From B"]);

    // A merges B's push and has everything; nothing is left to push.
    assert_eq!(a.status(), FileStatus::Changed);
    let outcome = a.sync.sync(&mut vault_a).expect("sync a again");
    assert!(outcome.merge.expect("merge").conflicts.is_empty());
    assert!(!outcome.pushed, "A has nothing new");
    assert_eq!(titles(&vault_a), vec!["Alpha", "From A", "From B"]);
    assert_eq!(token_of(&vault_a, "Alpha"), "SYNTH-alpha-2");
    assert_eq!(a.status(), FileStatus::UpToDate);
    assert!(!a.sync.local_changed(&vault_a).expect("changed"));
    // B syncs again: up to date both ways.
    let outcome = b.sync.sync(&mut vault_b).expect("sync b again");
    assert!(outcome.merge.is_none() && !outcome.pushed, "{outcome:?}");
    assert_eq!(
        vault_a.sync_content(&SyncScope::vault()).expect("content"),
        vault_b.sync_content(&SyncScope::vault()).expect("content")
    );
}

#[test]
fn the_same_credential_edited_on_both_sides_gives_a_conflict_copy() {
    let world = world();
    let (a, mut vault_a, b, mut vault_b) = two_macs(&world);
    edit(&mut vault_a, "Alpha", "SYNTH-from-a");
    edit(&mut vault_b, "Alpha", "SYNTH-from-b");
    a.sync.sync(&mut vault_a).expect("sync a");
    // B changed the same credential later, so B's version wins; A's version stays as an
    // archived copy.
    let merge = b
        .sync
        .sync(&mut vault_b)
        .expect("sync b")
        .merge
        .expect("merge");
    assert_eq!(merge.conflicts.len(), 1, "{merge:?}");
    let conflict = &merge.conflicts[0];
    assert_eq!(conflict.title, "Alpha");
    assert!(
        conflict.copy_title.starts_with("Alpha (conflict copy, "),
        "{conflict:?}"
    );
    assert_eq!(token_of(&vault_b, "Alpha"), "SYNTH-from-b");
    assert_eq!(token_of(&vault_b, &conflict.copy_title), "SYNTH-from-a");
    let copy = id_of(&vault_b, &conflict.copy_title);
    assert!(
        vault_b.is_archived(copy).expect("archived"),
        "the copy is archived"
    );

    // A merges B's push: the same result, and only one copy.
    let merge = a
        .sync
        .sync(&mut vault_a)
        .expect("sync a")
        .merge
        .expect("merge");
    assert!(
        merge.conflicts.is_empty(),
        "A sees no new conflict: {merge:?}"
    );
    assert_eq!(titles(&vault_a), titles(&vault_b));
    assert_eq!(titles(&vault_a).len(), 2);
    assert_eq!(token_of(&vault_a, "Alpha"), "SYNTH-from-b");
    assert_eq!(
        vault_a.sync_content(&SyncScope::vault()).expect("content"),
        vault_b.sync_content(&SyncScope::vault()).expect("content")
    );
}

#[test]
fn concurrent_edits_converge_when_both_see_the_conflict() {
    // Both Macs edit the same credential and both merge before either sees the other's
    // copy of the conflict: each makes the copy, and the copies are the same record.
    let world = world();
    let (a, mut vault_a, b, mut vault_b) = two_macs(&world);
    let base = fs::read(world.file()).expect("base");
    edit(&mut vault_a, "Alpha", "SYNTH-a2");
    a.sync.sync(&mut vault_a).expect("sync a");
    let from_a = fs::read(world.file()).expect("a");
    edit(&mut vault_b, "Alpha", "SYNTH-b2");
    // B pushes over the old file (it has not seen A's push yet).
    fs::write(world.file(), &base).expect("not delivered");
    b.sync.sync(&mut vault_b).expect("sync b");
    // Now each side merges the other's version.
    fs::write(world.file(), &from_a).expect("A's version");
    let merge_b = b
        .sync
        .sync(&mut vault_b)
        .expect("b merges a")
        .merge
        .expect("merge");
    assert_eq!(merge_b.conflicts.len(), 1);
    let merge_a = a
        .sync
        .sync(&mut vault_a)
        .expect("a merges b")
        .merge
        .expect("merge");
    assert!(merge_a.conflicts.len() <= 1);
    b.sync.sync(&mut vault_b).expect("b again");
    a.sync.sync(&mut vault_a).expect("a again");
    assert_eq!(titles(&vault_a), titles(&vault_b));
    assert_eq!(titles(&vault_a).len(), 2, "{:?}", titles(&vault_a));
}

#[test]
fn deletes_propagate_and_a_tombstone_beats_an_old_copy() {
    let world = world();
    let (a, mut vault_a, b, mut vault_b) = two_macs(&world);
    vault_a.add(item("Beta", "SYNTH-beta")).expect("add");
    a.sync.sync(&mut vault_a).expect("sync a");
    b.sync.sync(&mut vault_b).expect("sync b");
    assert_eq!(titles(&vault_b), vec!["Alpha", "Beta"]);
    let with_beta = fs::read(world.file()).expect("with beta");

    // B deletes Beta; A merges the delete.
    let beta = id_of(&vault_b, "Beta");
    let revision = vault_b.details(beta).expect("details").summary.revision;
    vault_b.delete(beta, revision).expect("delete");
    b.sync.sync(&mut vault_b).expect("sync b");
    let merge = a
        .sync
        .sync(&mut vault_a)
        .expect("sync a")
        .merge
        .expect("merge");
    assert_eq!(merge.deleted, 1);
    assert_eq!(titles(&vault_a), vec!["Alpha"]);

    // Someone puts the copy with Beta back: the tombstone wins.
    fs::write(world.file(), &with_beta).expect("old copy");
    let merge = a
        .sync
        .sync(&mut vault_a)
        .expect("sync a")
        .merge
        .expect("merge");
    assert_eq!(merge.inserted, 0, "{merge:?}");
    assert_eq!(titles(&vault_a), vec!["Alpha"]);
    let merge = b.sync.sync(&mut vault_b).expect("sync b").merge;
    assert!(merge.is_none_or(|merge| merge.inserted == 0));
    assert_eq!(titles(&vault_b), vec!["Alpha"]);
}

#[test]
fn an_old_copy_no_longer_undoes_anything() {
    let world = world();
    let (a, mut vault_a, b, mut vault_b) = two_macs(&world);
    let old = fs::read(world.file()).expect("old");
    edit(&mut vault_a, "Alpha", "SYNTH-newer");
    vault_a.add(item("Gamma", "SYNTH-gamma")).expect("add");
    a.sync.sync(&mut vault_a).expect("sync a");
    b.sync.sync(&mut vault_b).expect("sync b");
    assert_eq!(token_of(&vault_b, "Alpha"), "SYNTH-newer");

    fs::write(world.file(), &old).expect("rollback");
    assert_eq!(b.status(), FileStatus::Changed);
    let outcome = b.sync.sync(&mut vault_b).expect("sync b");
    let merge = outcome.merge.expect("merge");
    assert_eq!((merge.updated, merge.deleted), (0, 0), "{merge:?}");
    assert!(
        merge.conflicts.is_empty(),
        "an old copy makes no conflict copy"
    );
    assert_eq!(token_of(&vault_b, "Alpha"), "SYNTH-newer");
    assert_eq!(titles(&vault_b), vec!["Alpha", "Gamma"]);
    assert!(outcome.pushed, "B puts the newer content back");
    let merge = a.sync.sync(&mut vault_a).expect("sync a").merge;
    assert!(merge.is_none_or(|merge| !merge.changed_local()));
    assert_eq!(token_of(&vault_a, "Alpha"), "SYNTH-newer");
}

#[test]
fn agent_side_data_never_syncs_and_is_stripped_from_the_pushed_copy() {
    let world = world();
    let a = world.mac("mac-a");
    let mut vault_a = a.create(PASS);
    let alpha = vault_a.add(item("Alpha", "SYNTH-alpha")).expect("add");
    vault_a
        .set_destination(alpha.id, "reporting-api-v0", "http://127.0.0.1:8787")
        .expect("destination");
    vault_a
        .set_env_binding_with(
            alpha.id,
            "ALPHA_TOKEN",
            "token",
            &EnvDelivery::Placeholder(vec!["api.alpha.invalid".to_owned()]),
        )
        .expect("variable");
    let (agent, token) = vault_a.register_agent("Mac A agent").expect("agent");
    vault_a
        .set_grant(agent.id, alpha.id, "get_sales_summary", true)
        .expect("grant");
    vault_a
        .record_activity(&NewActivity {
            agent_id: Some(agent.id),
            agent_name: "Mac A agent".to_owned(),
            item_id: Some(alpha.id),
            operation: "get_sales_summary".to_owned(),
            decision: ActivityDecision::Allow,
            reason: "SYNTH reason".to_owned(),
        })
        .expect("activity");
    vault_a.set_token_lifetime_days(90).expect("lifetime");
    let _ = vault_a.reveal(alpha.id, "token").expect("reveal");
    a.sync.enable(&mut vault_a, "Personal").expect("enable");

    // Inside the pushed copy: the credential and its settings, no local row.
    let (_dir, conn) = peek(&world.file(), PASS);
    for table in LOCAL_TABLES {
        assert_eq!(
            count(&conn, &format!("SELECT count(*) FROM {table}")),
            0,
            "{table} must be empty in the pushed copy"
        );
    }
    assert_eq!(count(&conn, "SELECT count(*) FROM item"), 1);
    assert_eq!(count(&conn, "SELECT count(*) FROM env_binding"), 1);
    assert_eq!(count(&conn, "SELECT count(*) FROM destination"), 1);
    assert_eq!(
        count(&conn, "SELECT token_lifetime_days FROM vault_meta"),
        30
    );
    assert_eq!(
        count(
            &conn,
            "SELECT count(*) FROM item_event WHERE kind IN ('revealed', 'operation_allowed')"
        ),
        0,
        "local history stays"
    );
    assert!(
        count(
            &conn,
            "SELECT count(*) FROM item_event WHERE kind = 'created'"
        ) >= 1
    );
    // Every table of the copy is classified.
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table'")
        .expect("tables");
    let names: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .expect("rows")
        .collect::<Result<_, _>>()
        .expect("names");
    for name in names {
        assert!(
            SYNCED_TABLES.contains(&name.as_str()) || LOCAL_TABLES.contains(&name.as_str()),
            "{name}"
        );
    }
    drop(stmt);
    drop(conn);

    // Mac B gets the credential with its settings, and no agent.
    let b = world.mac("mac-b");
    let (mut vault_b, _) = b.sync.adopt(FILE, PASS).expect("adopt");
    vault_b.unlock(PASS).expect("unlock");
    assert!(vault_b.list_agents().expect("agents").is_empty());
    assert!(vault_b.authenticate_agent(token.expose()).is_err());
    assert!(vault_b.recent_activity(10).expect("activity").is_empty());
    assert_eq!(vault_b.token_lifetime_days().expect("lifetime"), 30);
    let alpha_b = id_of(&vault_b, "Alpha");
    let binding = vault_b
        .env_binding(alpha_b)
        .expect("binding")
        .expect("some");
    assert_eq!(binding.env_name, "ALPHA_TOKEN");
    assert_eq!(
        binding.delivery,
        EnvDelivery::Placeholder(vec!["api.alpha.invalid".to_owned()])
    );
    assert_eq!(
        vault_b
            .destination(alpha_b)
            .expect("destination")
            .expect("some")
            .base_url,
        "http://127.0.0.1:8787"
    );
    // B registers its own agent; a sync keeps both sides' agents apart.
    vault_b.register_agent("Mac B agent").expect("agent b");
    vault_b.add(item("From B", "SYNTH-b")).expect("add");
    b.sync.sync(&mut vault_b).expect("sync b");
    a.sync.sync(&mut vault_a).expect("sync a");
    let names: Vec<String> = vault_a
        .list_agents()
        .expect("agents")
        .into_iter()
        .map(|agent| agent.name)
        .collect();
    assert_eq!(names, vec!["Mac A agent"]);
    assert!(vault_a.authenticate_agent(token.expose()).is_ok());
    assert!(
        vault_a
            .has_grant(agent.id, alpha.id, "get_sales_summary")
            .expect("grant"),
        "a merge keeps the local grant"
    );
    assert_eq!(vault_a.token_lifetime_days().expect("lifetime"), 90);
}

#[test]
fn activity_alone_does_not_count_as_a_change() {
    let world = world();
    let a = world.mac("mac-a");
    let mut vault_a = a.create(PASS);
    let alpha = vault_a.add(item("Alpha", "SYNTH-alpha")).expect("add");
    a.sync.enable(&mut vault_a, "Personal").expect("enable");
    assert!(!a.sync.local_changed(&vault_a).expect("changed"));
    let (agent, _) = vault_a.register_agent("Agent").expect("agent");
    vault_a
        .record_activity(&NewActivity {
            agent_id: Some(agent.id),
            agent_name: "Agent".to_owned(),
            item_id: Some(alpha.id),
            operation: "run".to_owned(),
            decision: ActivityDecision::Deny,
            reason: "SYNTH".to_owned(),
        })
        .expect("activity");
    let _ = vault_a.reveal(alpha.id, "token").expect("reveal");
    assert!(
        !a.sync.local_changed(&vault_a).expect("changed"),
        "activity, a reveal, and an agent are not synced content"
    );
    let before = fs::read(world.file()).expect("file");
    let outcome = a.sync.sync(&mut vault_a).expect("sync");
    assert!(!outcome.pushed);
    assert_eq!(fs::read(world.file()).expect("file"), before);

    vault_a.set_archived(alpha.id, true).expect("archive");
    assert!(a.sync.local_changed(&vault_a).expect("changed"));
    assert!(a.sync.sync(&mut vault_a).expect("sync").pushed);
}

#[test]
fn attach_uses_the_key_and_a_new_passphrase_on_another_mac_needs_the_prompt() {
    let world = world();
    let (a, mut vault_a, b, mut vault_b) = two_macs(&world);
    // The copy opens with the key of the open vault: no passphrase in normal use.
    let identity = vault_b
        .check_sync_copy(&world.file(), &SyncScope::vault())
        .expect("same key");
    assert_eq!(
        identity.vault_id,
        vault_a.sync_identity().expect("id").vault_id
    );

    // Mac A changes the passphrase and pushes.
    vault_a.change_passphrase(PASS, NEW_PASS).expect("change");
    vault_a
        .add(item("After change", "SYNTH-after"))
        .expect("add");
    a.sync.sync(&mut vault_a).expect("sync a");
    assert_eq!(
        vault_b
            .check_sync_copy(&world.file(), &SyncScope::vault())
            .unwrap_err()
            .kind(),
        VaultErrorKind::WrongKeyOrCorrupt
    );
    vault_b.add(item("On B", "SYNTH-on-b")).expect("add");
    assert_eq!(
        b.sync.sync(&mut vault_b).unwrap_err(),
        SyncError::NeedsPassphrase
    );
    // A wrong passphrase changes nothing.
    assert_eq!(
        b.sync.take_new_passphrase(&mut vault_b, WRONG).unwrap_err(),
        SyncError::Vault(VaultErrorKind::WrongKeyOrCorrupt)
    );
    assert!(!vault_b.is_locked());
    // The new passphrase: rekey, merge, push.
    let outcome = b
        .sync
        .take_new_passphrase(&mut vault_b, NEW_PASS)
        .expect("new passphrase");
    assert!(outcome.pushed);
    assert_eq!(titles(&vault_b), vec!["After change", "Alpha", "On B"]);
    vault_b.lock().expect("lock");
    assert_eq!(
        vault_b.unlock(PASS).unwrap_err().kind(),
        VaultErrorKind::WrongKeyOrCorrupt
    );
    vault_b
        .unlock(NEW_PASS)
        .expect("the new passphrase opens B");
    a.sync.sync(&mut vault_a).expect("sync a");
    assert_eq!(titles(&vault_a), vec!["After change", "Alpha", "On B"]);
}

#[test]
fn adopt_on_a_new_mac_and_a_wrong_passphrase_makes_no_file() {
    let world = world();
    let a = world.mac("mac-a");
    let mut vault_a = a.create(PASS);
    vault_a.add(item("Alpha", "SYNTH-alpha")).expect("add");
    a.sync.enable(&mut vault_a, "Personal").expect("enable");
    let listed = list_folder_vaults(&world.folder).expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, FILE);
    assert!(listed[0].downloaded);

    let c = world.mac("mac-c");
    assert_eq!(
        c.sync.adopt(FILE, WRONG).unwrap_err(),
        SyncError::Vault(VaultErrorKind::WrongKeyOrCorrupt)
    );
    assert!(!c.vault_path.exists());
    let (mut vault_c, report) = c.sync.adopt(FILE, PASS).expect("adopt");
    assert_eq!(report.identity.pushed_by, device_name());
    assert!(vault_c.is_locked());
    assert_eq!(c.status(), FileStatus::UpToDate);
    vault_c.unlock(PASS).expect("unlock");
    assert_eq!(titles(&vault_c), vec!["Alpha"]);
    assert!(!c.sync.local_changed(&vault_c).expect("changed"));
    // Each vault file has its own device ID.
    assert_ne!(
        vault_c.sync_device_id().expect("device"),
        vault_a.sync_device_id().expect("device")
    );
    // An edit on A after the adopt merges into C without a conflict.
    edit(&mut vault_a, "Alpha", "SYNTH-alpha-2");
    a.sync.sync(&mut vault_a).expect("sync a");
    let merge = c
        .sync
        .sync(&mut vault_c)
        .expect("sync c")
        .merge
        .expect("merge");
    assert!(merge.conflicts.is_empty());
    assert_eq!(token_of(&vault_c, "Alpha"), "SYNTH-alpha-2");
    assert_eq!(
        c.sync.adopt(FILE, PASS).unwrap_err(),
        SyncError::AlreadyEnabled
    );
}

#[test]
fn a_small_team_shares_one_folder_and_keeps_its_own_agents() {
    let world = world();
    let owner = world.mac("owner");
    let mut vault_o = owner.create(PASS);
    vault_o
        .add(item("Shared API", "SYNTH-shared"))
        .expect("add");
    owner.sync.enable(&mut vault_o, "Team").expect("enable");
    let team_file = "Team.apassy";
    let ana = world.mac("ana");
    let (mut vault_ana, _) = ana.sync.adopt(team_file, PASS).expect("adopt ana");
    vault_ana.unlock(PASS).expect("unlock");
    let ben = world.mac("ben");
    let (mut vault_ben, _) = ben.sync.adopt(team_file, PASS).expect("adopt ben");
    vault_ben.unlock(PASS).expect("unlock");

    vault_o.register_agent("Owner agent").expect("agent");
    vault_ana.register_agent("Ana agent").expect("agent");
    vault_ben.register_agent("Ben agent").expect("agent");
    vault_ana.add(item("Ana key", "SYNTH-ana")).expect("add");
    vault_ben.add(item("Ben key", "SYNTH-ben")).expect("add");
    edit(&mut vault_o, "Shared API", "SYNTH-shared-2");

    for _ in 0..2 {
        owner.sync.sync(&mut vault_o).expect("owner");
        ana.sync.sync(&mut vault_ana).expect("ana");
        ben.sync.sync(&mut vault_ben).expect("ben");
    }
    let expected = vec!["Ana key", "Ben key", "Shared API"];
    for (who, vault) in [
        ("owner", &vault_o),
        ("ana", &vault_ana),
        ("ben", &vault_ben),
    ] {
        assert_eq!(titles(vault), expected, "{who}");
        assert_eq!(token_of(vault, "Shared API"), "SYNTH-shared-2", "{who}");
        assert_eq!(vault.list_agents().expect("agents").len(), 1, "{who}");
    }
    assert_eq!(
        vault_ana.list_agents().expect("agents")[0].name,
        "Ana agent"
    );
}

#[test]
fn a_folder_outside_icloud_is_made_and_an_unreachable_one_is_calm() {
    let world = world();
    let a = world.mac("mac-a");
    let mut vault_a = a.create(PASS);
    assert!(!world.folder.exists());
    a.sync.enable(&mut vault_a, "Personal").expect("enable");
    assert!(world.file().is_file(), "enable made the Apassy folder");
    assert!(
        !world.folder.join(format!("{FILE}{PUSH_SUFFIX}")).exists(),
        "no temporary file stays"
    );
    assert_eq!(
        fs::read_dir(&world.folder).expect("dir").count(),
        1,
        "only the synced file is in the folder"
    );
    // The folder goes away (the drive is not mounted).
    let away = world.root.path().join("away");
    fs::rename(world.root.path().join("Dropbox"), &away).expect("unmount");
    assert_eq!(a.status(), FileStatus::FolderUnavailable);
    vault_a.add(item("Offline", "SYNTH-offline")).expect("add");
    assert_eq!(
        a.sync.sync(&mut vault_a).unwrap_err(),
        SyncError::FolderUnavailable
    );
    fs::rename(&away, world.root.path().join("Dropbox")).expect("mount");
    assert!(a.sync.sync(&mut vault_a).expect("sync").pushed);
    assert_eq!(a.status(), FileStatus::UpToDate);

    // An evicted iCloud file waits for the download.
    fs::rename(world.file(), world.root.path().join("aside")).expect("evict");
    fs::write(world.folder.join(format!(".{FILE}.icloud")), b"placeholder").expect("placeholder");
    assert_eq!(a.status(), FileStatus::NotDownloaded);
    assert_eq!(
        a.sync.sync(&mut vault_a).unwrap_err(),
        SyncError::NotDownloaded
    );
    assert!(a.sync.request_download().is_ok());
    // The file is gone: a sync writes it again.
    fs::remove_file(world.folder.join(format!(".{FILE}.icloud"))).expect("rm");
    assert_eq!(a.status(), FileStatus::Missing);
    assert!(a.sync.sync(&mut vault_a).expect("sync").pushed);
}

#[test]
fn enable_picks_a_free_name_and_links_the_same_vault() {
    let world = world();
    let a = world.mac("mac-a");
    let mut vault_x = a.create(PASS);
    vault_x.add(item("X", "SYNTH-x")).expect("add");
    assert_eq!(
        a.sync
            .enable(&mut vault_x, "Personal")
            .expect("enable")
            .file_name,
        FILE
    );
    assert_eq!(
        a.sync.enable(&mut vault_x, "Personal").unwrap_err(),
        SyncError::AlreadyEnabled
    );
    // Another vault, even with the same passphrase, does not open with this key.
    let c = world.mac("mac-c");
    let mut vault_y = c.create(PASS);
    assert_eq!(
        c.sync
            .enable(&mut vault_y, "Personal")
            .expect("enable")
            .file_name,
        "Personal-2.apassy"
    );
    // Off and on again: the same vault links and merges.
    assert!(a.sync.disable().expect("disable"));
    assert!(world.file().is_file(), "disable keeps the synced file");
    vault_x.add(item("X2", "SYNTH-x2")).expect("add");
    let report = a
        .sync
        .enable(&mut vault_x, "Personal")
        .expect("enable again");
    assert!(report.linked);
    assert_eq!(report.file_name, FILE);
    assert!(report.outcome.pushed);
    let (_dir, conn) = peek(&world.file(), PASS);
    assert_eq!(count(&conn, "SELECT count(*) FROM item"), 2);
}

#[test]
fn a_damaged_or_foreign_file_is_refused_and_can_be_replaced() {
    let world = world();
    let (a, mut vault_a, b, mut vault_b) = two_macs(&world);
    let old = fs::read(world.file()).expect("old");
    edit(&mut vault_a, "Alpha", "SYNTH-alpha-2");
    a.sync.sync(&mut vault_a).expect("sync a");
    let new = fs::read(world.file()).expect("new");
    assert_eq!(old.len(), new.len(), "the same page count");

    // One page of the new copy, every other page of the old copy: each page HMAC holds,
    // and the content digest refuses the mixed file.
    let sync_page = {
        let (_dir, conn) = peek(&world.file(), PASS);
        let root: i64 = conn
            .query_row(
                "SELECT rootpage FROM sqlite_schema WHERE name = 'sync_meta'",
                [],
                |row| row.get(0),
            )
            .expect("root page");
        usize::try_from(root).expect("page")
    };
    let mut mixed = old.clone();
    let start = (sync_page - 1) * PAGE_SIZE;
    mixed[start..start + PAGE_SIZE].copy_from_slice(&new[start..start + PAGE_SIZE]);
    fs::write(world.file(), &mixed).expect("mixed");
    Vault::verify_passphrase_at(&world.file(), PASS).expect("valid pages");
    assert_eq!(b.sync.sync(&mut vault_b).unwrap_err(), SyncError::Damaged);
    assert_eq!(titles(&vault_b), vec!["Alpha"], "nothing merged");
    // Last resort: replace the damaged file with this Mac's vault.
    assert!(
        b.sync
            .replace_synced_file(&mut vault_b)
            .expect("replace")
            .pushed
    );
    a.sync.sync(&mut vault_a).expect("sync a");
    assert_eq!(
        token_of(&vault_a, "Alpha"),
        "SYNTH-alpha-2",
        "A keeps its newer edit"
    );

    // Another vault at the file name.
    let d = world.mac("mac-d");
    let mut other = d.create(PASS);
    let report = d.sync.enable(&mut other, "Other").expect("enable");
    fs::copy(world.folder.join(&report.file_name), world.file()).expect("replace");
    assert_eq!(
        a.sync.sync(&mut vault_a).unwrap_err(),
        SyncError::NeedsPassphrase,
        "a file of another vault does not open with this key"
    );
}

#[test]
fn companion_files_refuse_the_push() {
    let world = world();
    let a = world.mac("mac-a");
    let mut vault_a = a.create(PASS);
    a.sync.enable(&mut vault_a, "Personal").expect("enable");
    vault_a.add(item("Alpha", "SYNTH-alpha")).expect("add");
    let before = fs::read(world.file()).expect("file");
    for suffix in ["-journal", "-wal", "-shm"] {
        let companion = PathBuf::from(format!("{}{suffix}", a.vault_path.display()));
        fs::write(&companion, b"").expect("companion");
        assert_eq!(
            a.sync.sync(&mut vault_a).unwrap_err(),
            SyncError::Vault(VaultErrorKind::InvalidInput),
            "{suffix}"
        );
        fs::remove_file(&companion).expect("rm");
        assert_eq!(fs::read(world.file()).expect("file"), before);
    }
    assert!(a.sync.sync(&mut vault_a).expect("sync").pushed);
    assert!(
        fs::read_dir(a.data.join("sync"))
            .expect("work dir")
            .all(|entry| !entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .starts_with('.')),
        "no work copy stays"
    );
}

#[test]
fn status_reports_duplicates_and_names() {
    let world = world();
    let a = world.mac("mac-a");
    let mut vault_a = a.create(PASS);
    assert_eq!(a.sync.status().unwrap_err(), SyncError::NotEnabled);
    a.sync.enable(&mut vault_a, "Personal").expect("enable");
    fs::copy(world.file(), world.folder.join("Personal 2.apassy")).expect("dup");
    let report = a.sync.status().expect("status");
    assert_eq!(report.status, FileStatus::UpToDate);
    assert_eq!(report.duplicates, vec!["Personal 2.apassy".to_owned()]);
    assert_eq!(file_name_for("Work 2"), "Work-2.apassy");
    assert!(!device_name().is_empty());
    let state = a.sync.state().expect("state").expect("some");
    assert_eq!(state.vault_path.as_deref(), Some(vault_a.path()));
    let home = TempDir::new().expect("home");
    assert!(detect_folders_in(home.path()).is_empty());
    let dir = icloud_folder();
    if cfg!(target_os = "macos") && std::env::var_os("HOME").is_some() {
        assert!(
            dir.expect("iCloud path")
                .ends_with("Library/Mobile Documents/com~apple~CloudDocs/Apassy")
        );
    } else if !cfg!(target_os = "macos") {
        assert_eq!(dir, None);
    }
}

#[test]
fn an_edit_that_the_delete_did_not_see_keeps_the_credential() {
    let world = world();
    let (a, mut vault_a, b, mut vault_b) = two_macs(&world);
    let alpha = id_of(&vault_a, "Alpha");
    let revision = vault_a.details(alpha).expect("details").summary.revision;
    vault_a.delete(alpha, revision).expect("delete");
    a.sync.sync(&mut vault_a).expect("sync a");
    // B edits Alpha before it sees the delete: the edit wins, nothing is lost.
    edit(&mut vault_b, "Alpha", "SYNTH-kept");
    let merge = b
        .sync
        .sync(&mut vault_b)
        .expect("sync b")
        .merge
        .expect("merge");
    assert_eq!(merge.deleted, 0);
    assert_eq!(token_of(&vault_b, "Alpha"), "SYNTH-kept");
    let merge = a
        .sync
        .sync(&mut vault_a)
        .expect("sync a")
        .merge
        .expect("merge");
    assert_eq!(merge.inserted, 1, "the edited credential comes back");
    assert_eq!(token_of(&vault_a, "Alpha"), "SYNTH-kept");
}

#[test]
fn a_variable_name_that_is_taken_here_is_left_out_and_reported() {
    let world = world();
    let (a, mut vault_a, b, mut vault_b) = two_macs(&world);
    let on_a = vault_a.add(item("Gh A", "SYNTH-gh-a")).expect("add");
    vault_a
        .set_env_binding_with(on_a.id, "GITHUB_TOKEN", "token", &EnvDelivery::Value)
        .expect("variable");
    let on_b = vault_b.add(item("Gh B", "SYNTH-gh-b")).expect("add");
    vault_b
        .set_env_binding_with(on_b.id, "GITHUB_TOKEN", "token", &EnvDelivery::Value)
        .expect("variable");
    a.sync.sync(&mut vault_a).expect("sync a");
    let merge = b
        .sync
        .sync(&mut vault_b)
        .expect("sync b")
        .merge
        .expect("merge");
    assert_eq!(merge.skipped_variables, vec!["GITHUB_TOKEN".to_owned()]);
    let gh_a = id_of(&vault_b, "Gh A");
    assert!(vault_b.env_binding(gh_a).expect("binding").is_none());
    assert_eq!(
        vault_b
            .env_binding(on_b.id)
            .expect("binding")
            .expect("some")
            .env_name,
        "GITHUB_TOKEN"
    );
}
