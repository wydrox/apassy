#![cfg(feature = "vault")]

//! iCloud sync engine (ADR 0014, docs/operations/icloud.md). Synthetic values only.
//!
//! A temporary folder stands in for iCloud Drive (`<tmp>/Mobile Documents/
//! com~apple~CloudDocs`), and each "Mac" is a separate data folder with its own local
//! vault file. So the tests run on Linux and macOS, and never touch the real iCloud
//! Drive. iCloud itself (upload, download, eviction) is simulated with file operations.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use apassy::cloud::{
    CloudError, CloudSync, SyncConfig, SyncStatus, cloud_file_name_for, default_cloud_dir,
    device_name, list_cloud_vaults,
};
use apassy::contracts::CredentialKind;
use apassy::vault::{Field, INCOMING_SUFFIX, ItemDraft, SecretValue, Vault, VaultErrorKind};
use tempfile::TempDir;

const PASS: &str = "synthetic-icloud-pass";
const WRONG: &str = "synthetic-icloud-wrong";
const OTHER_PASS: &str = "synthetic-icloud-other";
const CLOUD_NAME: &str = "Personal.apassy";
const PAGE_SIZE: usize = 4096;

/// A fake iCloud Drive and the Apassy folder in it (not created yet).
struct World {
    root: TempDir,
    icloud: PathBuf,
    cloud_dir: PathBuf,
}

fn world() -> World {
    let root = TempDir::new().expect("temp dir");
    let icloud = root
        .path()
        .join("Mobile Documents")
        .join("com~apple~CloudDocs");
    fs::create_dir_all(&icloud).expect("icloud root");
    let cloud_dir = icloud.join("Apassy");
    World {
        root,
        icloud,
        cloud_dir,
    }
}

/// One Mac: a data folder, the path of its local vault, and its sync engine.
struct Mac {
    data: PathBuf,
    vault_path: PathBuf,
    sync: CloudSync,
}

impl World {
    fn mac(&self, name: &str) -> Mac {
        let data = self.root.path().join(name).join("Apassy");
        fs::create_dir_all(&data).expect("data dir");
        let vault_path = data.join("vault.db");
        let config = SyncConfig::in_data_dir(&data, &vault_path, &self.cloud_dir, "vault");
        Mac {
            data,
            vault_path,
            sync: CloudSync::new(config),
        }
    }

    fn cloud_file(&self) -> PathBuf {
        self.cloud_dir.join(CLOUD_NAME)
    }
}

impl Mac {
    fn create(&self, passphrase: &str) -> Vault {
        let mut vault = Vault::create(&self.vault_path, passphrase).expect("create");
        vault.unlock(passphrase).expect("unlock");
        vault
    }

    fn conflicts(&self) -> PathBuf {
        self.data.join("conflicts")
    }

    fn state_path(&self) -> PathBuf {
        self.sync.config().state_path.clone()
    }

    fn status(&self) -> SyncStatus {
        self.sync.status().expect("status").status
    }
}

fn item(title: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![Field {
            name: "token".to_owned(),
            value: SecretValue::new(format!("SYNTH-SECRET-{title}")),
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

/// Open a vault file that is not in use (a cloud or conflict copy) through a private
/// copy, and return its titles.
fn titles_of_copy(path: &Path, passphrase: &str) -> Vec<String> {
    let dir = TempDir::new().expect("temp dir");
    let copy = dir.path().join("copy.apassy");
    fs::copy(path, &copy).expect("copy");
    let mut vault = Vault::open(&copy).expect("open copy");
    vault.unlock(passphrase).expect("unlock copy");
    titles(&vault)
}

fn names_in(dir: &Path) -> Vec<String> {
    let Ok(read) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = read
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("utf-8")
        })
        .collect();
    names.sort();
    names
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).expect("metadata").permissions().mode() & 0o777
}

/// Mac A with a vault, sync on (first push), and Mac B adopted from iCloud. Both are
/// unlocked and in sync.
fn two_macs(world: &World) -> (Mac, Vault, Mac, Vault) {
    let a = world.mac("mac-a");
    let mut vault_a = a.create(PASS);
    vault_a.add(item("Alpha")).expect("add");
    let report = a
        .sync
        .enable(&mut vault_a, PASS, "Personal")
        .expect("enable");
    assert_eq!(report.cloud_file_name, CLOUD_NAME);
    let b = world.mac("mac-b");
    let (mut vault_b, _) = b.sync.adopt(CLOUD_NAME, PASS).expect("adopt");
    vault_b.unlock(PASS).expect("unlock b");
    (a, vault_a, b, vault_b)
}

#[test]
fn push_then_pull_round_trip_on_a_second_mac() {
    let world = world();
    let a = world.mac("mac-a");
    let mut vault_a = a.create(PASS);
    let first = vault_a.add(item("Alpha")).expect("add");
    vault_a.add(item("Bravo")).expect("add");
    vault_a
        .set_destination(first.id, "reporting-api-v0", "http://127.0.0.1:8787")
        .expect("destination");
    let (agent, token) = vault_a.register_agent("Sync agent").expect("agent");
    vault_a
        .set_grant(agent.id, first.id, "get_sales_summary", true)
        .expect("grant");

    // Enable: the first push. The vault stays unlocked.
    let report = a
        .sync
        .enable(&mut vault_a, PASS, "Personal")
        .expect("enable");
    assert_eq!(report.cloud_file_name, CLOUD_NAME);
    assert!(report.pushed);
    assert_eq!(report.status, SyncStatus::InSync);
    assert_eq!(report.generation, 1);
    assert!(!vault_a.is_locked(), "a push keeps the vault unlocked");
    assert_eq!(
        names_in(&world.cloud_dir),
        vec![CLOUD_NAME.to_owned()],
        "no temporary file stays in iCloud"
    );
    assert_eq!(mode_of(&world.cloud_file()), 0o600);
    assert_eq!(a.status(), SyncStatus::InSync);

    // The copy made while the vault was unlocked opens with the passphrase and has the
    // same items and the new sync record.
    assert_eq!(titles_of_copy(&world.cloud_file(), PASS), titles(&vault_a));
    let record = vault_a.sync_identity().expect("record");
    assert_eq!(record.generation, 1);
    assert_eq!(record.pushed_by, device_name());
    assert!(record.pushed_at.is_some());
    let inspected = Vault::inspect_sync_copy(&world.cloud_file(), PASS).expect("inspect");
    assert_eq!(inspected, record);

    // A new Mac lists and adopts the vault.
    let listed = list_cloud_vaults(&world.cloud_dir).expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, CLOUD_NAME);
    assert!(listed[0].downloaded);
    assert_eq!(listed[0].duplicate_of, None);
    let b = world.mac("mac-b");
    let (mut vault_b, adopted) = b.sync.adopt(CLOUD_NAME, PASS).expect("adopt");
    assert!(vault_b.is_locked());
    assert_eq!(adopted.generation, 1);
    assert_eq!(adopted.pushed_by, device_name());
    assert_eq!(b.status(), SyncStatus::InSync);
    vault_b.unlock(PASS).expect("unlock b");
    assert_eq!(titles(&vault_b), titles(&vault_a));
    // Unlike a restore, the agent, its token, and its grant stay.
    assert_eq!(
        vault_b
            .authenticate_agent(token.expose())
            .expect("token works")
            .id,
        agent.id
    );
    assert!(
        vault_b
            .has_grant(agent.id, first.id, "get_sales_summary")
            .expect("grant")
    );
    assert!(vault_b.items_needing_review().expect("review").is_empty());

    // Mac B changes the vault and pushes.
    vault_b.add(item("Charlie")).expect("add");
    assert_eq!(b.status(), SyncStatus::PushNeeded);
    let pushed = b.sync.push(&mut vault_b).expect("push");
    assert!(pushed.copied);
    assert_eq!(pushed.generation, 2);
    assert_eq!(b.status(), SyncStatus::InSync);
    let again = b.sync.push(&mut vault_b).expect("push again");
    assert!(!again.copied, "nothing to push");

    // Mac A gets the change.
    assert_eq!(a.status(), SyncStatus::PullAvailable);
    vault_a.lock().expect("lock");
    let pulled = a.sync.pull(&mut vault_a, PASS).expect("pull");
    assert!(pulled.copied);
    assert_eq!(pulled.generation, 2);
    assert_eq!(pulled.conflict_copy, None);
    assert!(
        !Path::new(&format!("{}{INCOMING_SUFFIX}", a.vault_path.display())).exists(),
        "the incoming copy is gone"
    );
    assert_eq!(a.status(), SyncStatus::InSync);
    assert!(
        !a.sync.pull(&mut vault_a, PASS).expect("pull again").copied,
        "nothing to pull"
    );
    vault_a.unlock(PASS).expect("unlock a");
    assert_eq!(titles(&vault_a), vec!["Alpha", "Bravo", "Charlie"]);
    assert_eq!(vault_a.sync_identity().expect("record").generation, 2);
    assert!(vault_a.authenticate_agent(token.expose()).is_ok());
}

#[test]
fn status_reports_each_state() {
    let world = world();
    let a = world.mac("mac-a");
    let mut vault_a = a.create(PASS);
    assert_eq!(a.sync.status().unwrap_err(), CloudError::NotEnabled);
    vault_a.add(item("Alpha")).expect("add");
    a.sync
        .enable(&mut vault_a, PASS, "Personal")
        .expect("enable");
    assert_eq!(a.status(), SyncStatus::InSync);

    vault_a.add(item("Bravo")).expect("add");
    assert_eq!(a.status(), SyncStatus::PushNeeded);
    a.sync.push(&mut vault_a).expect("push");
    assert_eq!(a.status(), SyncStatus::InSync);

    let b = world.mac("mac-b");
    let (mut vault_b, _) = b.sync.adopt(CLOUD_NAME, PASS).expect("adopt");
    vault_b.unlock(PASS).expect("unlock");
    vault_b.add(item("Charlie")).expect("add");
    b.sync.push(&mut vault_b).expect("push");
    assert_eq!(a.status(), SyncStatus::PullAvailable);

    vault_a.add(item("Delta")).expect("add");
    assert_eq!(a.status(), SyncStatus::Conflict);

    // Evicted before macOS 14: only the placeholder `.<name>.icloud` is there.
    let aside = world.root.path().join("aside.apassy");
    fs::rename(world.cloud_file(), &aside).expect("evict");
    fs::write(
        world.cloud_dir.join(format!(".{CLOUD_NAME}.icloud")),
        b"synthetic placeholder",
    )
    .expect("placeholder");
    let report = a.sync.status().expect("status");
    assert_eq!(report.status, SyncStatus::NotDownloaded);
    assert_eq!(report.cloud_path, world.cloud_file());
    assert!(a.sync.request_download().is_ok());

    // The cloud file is gone.
    fs::remove_file(world.cloud_dir.join(format!(".{CLOUD_NAME}.icloud"))).expect("rm");
    assert_eq!(a.status(), SyncStatus::CloudMissing);
    // The Apassy folder is gone.
    fs::remove_dir_all(&world.cloud_dir).expect("rm folder");
    assert_eq!(a.status(), SyncStatus::CloudMissing);
    // iCloud Drive is gone (signed out).
    let signed_out = world.root.path().join("signed-out");
    fs::rename(&world.icloud, &signed_out).expect("sign out");
    assert_eq!(a.status(), SyncStatus::Unavailable);
    assert_eq!(
        a.sync.push(&mut vault_a).unwrap_err(),
        CloudError::Unavailable
    );
    assert_eq!(
        list_cloud_vaults(&world.cloud_dir).unwrap_err(),
        CloudError::Unavailable
    );

    // Back online without the file: a push writes the folder and the file again.
    fs::rename(&signed_out, &world.icloud).expect("sign in");
    let pushed = a.sync.push(&mut vault_a).expect("push again");
    assert!(pushed.copied);
    assert_eq!(a.status(), SyncStatus::InSync);
    assert_eq!(
        titles_of_copy(&world.cloud_file(), PASS),
        vec!["Alpha", "Bravo", "Delta"]
    );
}

#[test]
fn pull_refuses_an_older_copy() {
    let world = world();
    let (a, mut vault_a, b, mut vault_b) = two_macs(&world);
    let generation_1 = fs::read(world.cloud_file()).expect("read");
    vault_a.add(item("Bravo")).expect("add");
    a.sync.push(&mut vault_a).expect("push");
    vault_b.lock().expect("lock");
    b.sync.pull(&mut vault_b, PASS).expect("pull generation 2");

    // Someone puts the copy of generation 1 back in iCloud.
    fs::write(world.cloud_file(), &generation_1).expect("replace");
    assert_eq!(b.status(), SyncStatus::PullAvailable);
    let before = fs::read(&b.vault_path).expect("local");
    let rollback = CloudError::Rollback {
        cloud_generation: 1,
        synced_generation: 2,
    };
    assert_eq!(b.sync.pull(&mut vault_b, PASS).unwrap_err(), rollback);
    assert_eq!(b.sync.use_icloud(&mut vault_b, PASS).unwrap_err(), rollback);
    assert_eq!(fs::read(&b.vault_path).expect("local"), before);
    assert!(names_in(&b.conflicts()).is_empty(), "no conflict copy");
    assert!(!Path::new(&format!("{}{INCOMING_SUFFIX}", b.vault_path.display())).exists());
    let text = rollback.to_string();
    assert!(text.contains("older"), "{text}");

    // "Keep this Mac" puts the newer copy back, above the old generation.
    vault_b.unlock(PASS).expect("unlock");
    let kept = b.sync.keep_this_mac(&mut vault_b, PASS).expect("keep");
    assert_eq!(kept.generation, 3);
    assert!(kept.conflict_copy.is_some(), "the old copy is saved");
    assert_eq!(b.status(), SyncStatus::InSync);
}

#[test]
fn equal_generation_with_other_content_needs_the_owner() {
    // Two Macs push from the same copy before iCloud delivers the other push.
    let world = world();
    let (_a, _vault_a, b, mut vault_b) = two_macs(&world);
    let c = world.mac("mac-c");
    let (mut vault_c, _) = c.sync.adopt(CLOUD_NAME, PASS).expect("adopt c");
    vault_c.unlock(PASS).expect("unlock c");
    let generation_1 = fs::read(world.cloud_file()).expect("read");

    vault_c.add(item("From C")).expect("add");
    assert_eq!(c.sync.push(&mut vault_c).expect("push c").generation, 2);
    let from_c = fs::read(world.cloud_file()).expect("read");

    // Mac B has not seen the push of C yet.
    fs::write(world.cloud_file(), &generation_1).expect("not delivered");
    vault_b.add(item("From B")).expect("add");
    assert_eq!(b.sync.push(&mut vault_b).expect("push b").generation, 2);

    // iCloud keeps the version of C.
    fs::write(world.cloud_file(), &from_c).expect("delivered");
    assert_eq!(b.status(), SyncStatus::PullAvailable);
    vault_b.lock().expect("lock");
    let same = CloudError::Rollback {
        cloud_generation: 2,
        synced_generation: 2,
    };
    assert_eq!(b.sync.pull(&mut vault_b, PASS).unwrap_err(), same);
    assert!(same.to_string().contains("other content"));

    // The owner chooses the iCloud copy. The copy of this Mac is saved first.
    let outcome = b.sync.use_icloud(&mut vault_b, PASS).expect("use icloud");
    let saved = outcome.conflict_copy.expect("conflict copy");
    assert!(saved.starts_with(b.conflicts()));
    let saved_name = saved.file_name().unwrap().to_str().unwrap().to_owned();
    assert!(
        saved_name.starts_with("Personal-this-mac-") && saved_name.ends_with(".apassy"),
        "{saved_name}"
    );
    assert_eq!(mode_of(&saved), 0o600);
    assert_eq!(mode_of(&b.conflicts()), 0o700);
    assert!(titles_of_copy(&saved, PASS).contains(&"From B".to_owned()));
    vault_b.unlock(PASS).expect("unlock");
    assert!(titles(&vault_b).contains(&"From C".to_owned()));
    assert!(!titles(&vault_b).contains(&"From B".to_owned()));
    assert_eq!(b.status(), SyncStatus::InSync);
}

#[test]
fn conflict_keep_this_mac_saves_the_icloud_copy_then_pushes() {
    let world = world();
    let (a, mut vault_a, b, mut vault_b) = two_macs(&world);
    vault_b.add(item("From B")).expect("add");
    b.sync.push(&mut vault_b).expect("push b");
    vault_a.add(item("From A")).expect("add");
    assert_eq!(a.status(), SyncStatus::Conflict);
    assert_eq!(
        a.sync.push(&mut vault_a).unwrap_err(),
        CloudError::CloudChanged
    );
    vault_a.lock().expect("lock");
    assert_eq!(
        a.sync.pull(&mut vault_a, PASS).unwrap_err(),
        CloudError::LocalChanged
    );
    vault_a.unlock(PASS).expect("unlock");

    // A wrong passphrase changes nothing.
    let cloud_before = fs::read(world.cloud_file()).expect("cloud");
    assert_eq!(
        a.sync.keep_this_mac(&mut vault_a, WRONG).unwrap_err(),
        CloudError::Vault(VaultErrorKind::WrongKeyOrCorrupt)
    );
    assert_eq!(fs::read(world.cloud_file()).expect("cloud"), cloud_before);
    assert!(names_in(&a.conflicts()).is_empty());

    let outcome = a.sync.keep_this_mac(&mut vault_a, PASS).expect("keep");
    assert!(!vault_a.is_locked());
    assert_eq!(
        outcome.generation, 3,
        "above the generation of the iCloud copy"
    );
    let saved = outcome.conflict_copy.expect("conflict copy");
    let saved_name = saved.file_name().unwrap().to_str().unwrap().to_owned();
    assert!(saved_name.starts_with("Personal-icloud-"), "{saved_name}");
    assert_eq!(fs::read(&saved).expect("saved"), cloud_before);
    assert!(titles_of_copy(&saved, PASS).contains(&"From B".to_owned()));
    assert_eq!(a.status(), SyncStatus::InSync);

    // Mac B accepts the new copy: its generation is higher.
    assert_eq!(b.status(), SyncStatus::PullAvailable);
    vault_b.lock().expect("lock");
    assert_eq!(b.sync.pull(&mut vault_b, PASS).expect("pull").generation, 3);
    vault_b.unlock(PASS).expect("unlock");
    assert_eq!(titles(&vault_b), vec!["Alpha", "From A"]);
}

#[test]
fn conflict_use_icloud_saves_this_mac_then_pulls() {
    let world = world();
    let (a, mut vault_a, b, mut vault_b) = two_macs(&world);
    vault_b.add(item("From B")).expect("add");
    b.sync.push(&mut vault_b).expect("push b");
    vault_a.add(item("From A")).expect("add");
    assert_eq!(a.status(), SyncStatus::Conflict);
    assert_eq!(
        a.sync.use_icloud(&mut vault_a, PASS).unwrap_err(),
        CloudError::NotLocked
    );
    vault_a.lock().expect("lock");
    let local_before = fs::read(&a.vault_path).expect("local");

    let outcome = a.sync.use_icloud(&mut vault_a, PASS).expect("use icloud");
    assert_eq!(outcome.generation, 2);
    let saved = outcome.conflict_copy.expect("conflict copy");
    assert_eq!(fs::read(&saved).expect("saved"), local_before);
    assert!(titles_of_copy(&saved, PASS).contains(&"From A".to_owned()));
    vault_a.unlock(PASS).expect("unlock");
    assert_eq!(titles(&vault_a), vec!["Alpha", "From B"]);
    assert_eq!(a.status(), SyncStatus::InSync);
    assert_eq!(b.status(), SyncStatus::InSync);
}

#[test]
fn wrong_passphrase_leaves_the_local_file_untouched() {
    let world = world();
    let (a, mut vault_a, b, mut vault_b) = two_macs(&world);
    vault_b.add(item("From B")).expect("add");
    b.sync.push(&mut vault_b).expect("push b");
    vault_a.lock().expect("lock");
    let local_before = fs::read(&a.vault_path).expect("local");
    let state_before = fs::read(a.state_path()).expect("state");
    for result in [
        a.sync.pull(&mut vault_a, WRONG),
        a.sync.use_icloud(&mut vault_a, WRONG),
    ] {
        assert_eq!(
            result.unwrap_err(),
            CloudError::Vault(VaultErrorKind::WrongKeyOrCorrupt)
        );
        assert_eq!(fs::read(&a.vault_path).expect("local"), local_before);
        assert_eq!(fs::read(a.state_path()).expect("state"), state_before);
        assert!(!Path::new(&format!("{}{INCOMING_SUFFIX}", a.vault_path.display())).exists());
        assert!(names_in(&a.conflicts()).is_empty());
    }
    // The right passphrase works after the failures.
    a.sync.pull(&mut vault_a, PASS).expect("pull");

    // Adopt with a wrong passphrase makes no vault file.
    let c = world.mac("mac-c");
    assert_eq!(
        c.sync.adopt(CLOUD_NAME, WRONG).unwrap_err(),
        CloudError::Vault(VaultErrorKind::WrongKeyOrCorrupt)
    );
    assert!(!c.vault_path.exists());
    assert!(c.sync.state().expect("state").is_none());
}

#[test]
fn companion_files_refuse_the_push_and_the_pull() {
    let world = world();
    let (a, mut vault_a, b, mut vault_b) = two_macs(&world);
    vault_a.add(item("Bravo")).expect("add");
    let cloud_before = fs::read(world.cloud_file()).expect("cloud");
    for suffix in ["-journal", "-wal", "-shm"] {
        let companion = PathBuf::from(format!("{}{suffix}", a.vault_path.display()));
        fs::write(&companion, b"").expect("companion");
        assert_eq!(
            a.sync.push(&mut vault_a).unwrap_err(),
            CloudError::Vault(VaultErrorKind::InvalidInput),
            "{suffix}"
        );
        fs::remove_file(&companion).expect("rm");
        assert_eq!(fs::read(world.cloud_file()).expect("cloud"), cloud_before);
        assert_eq!(names_in(&world.cloud_dir), vec![CLOUD_NAME.to_owned()]);
    }
    a.sync.push(&mut vault_a).expect("push");

    // A pull refuses a journal next to the local vault: SQLite would apply it to the
    // new file.
    vault_b.lock().expect("lock");
    let journal = PathBuf::from(format!("{}-journal", b.vault_path.display()));
    fs::write(&journal, b"").expect("journal");
    let local_before = fs::read(&b.vault_path).expect("local");
    assert_eq!(
        b.sync.pull(&mut vault_b, PASS).unwrap_err(),
        CloudError::Vault(VaultErrorKind::InvalidInput)
    );
    assert_eq!(fs::read(&b.vault_path).expect("local"), local_before);
    fs::remove_file(&journal).expect("rm");
    b.sync.pull(&mut vault_b, PASS).expect("pull");
}

#[test]
fn evicted_cloud_file_is_not_downloaded() {
    let world = world();
    let (a, mut vault_a, b, mut vault_b) = two_macs(&world);
    fs::rename(world.cloud_file(), world.root.path().join("aside")).expect("evict");
    fs::write(
        world.cloud_dir.join(format!(".{CLOUD_NAME}.icloud")),
        b"synthetic placeholder",
    )
    .expect("placeholder");
    assert_eq!(a.status(), SyncStatus::NotDownloaded);
    vault_a.add(item("Bravo")).expect("add");
    assert_eq!(
        a.sync.push(&mut vault_a).unwrap_err(),
        CloudError::NotDownloaded
    );
    vault_b.lock().expect("lock");
    assert_eq!(
        b.sync.pull(&mut vault_b, PASS).unwrap_err(),
        CloudError::NotDownloaded
    );
    let listed = list_cloud_vaults(&world.cloud_dir).expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, CLOUD_NAME);
    assert!(!listed[0].downloaded);
    let c = world.mac("mac-c");
    assert_eq!(
        c.sync.adopt(CLOUD_NAME, PASS).unwrap_err(),
        CloudError::NotDownloaded
    );
    assert!(!c.vault_path.exists());
}

#[test]
fn icloud_duplicates_are_reported() {
    let world = world();
    let a = world.mac("mac-a");
    let mut vault_a = a.create(PASS);
    a.sync
        .enable(&mut vault_a, PASS, "Personal")
        .expect("enable");
    fs::copy(
        world.cloud_file(),
        world.cloud_dir.join("Personal 2.apassy"),
    )
    .expect("dup");
    fs::write(
        world.cloud_dir.join(".Personal 3.apassy.icloud"),
        b"synthetic placeholder",
    )
    .expect("evicted dup");
    fs::write(world.cloud_dir.join("Other.apassy"), b"other").expect("other");
    fs::write(world.cloud_dir.join(".Other.apassy.push.nosync"), b"tmp").expect("tmp");
    fs::write(world.cloud_dir.join("notes.txt"), b"not a vault").expect("txt");

    let report = a.sync.status().expect("status");
    assert_eq!(report.status, SyncStatus::InSync);
    assert_eq!(
        report.duplicates,
        vec![
            "Personal 2.apassy".to_owned(),
            "Personal 3.apassy".to_owned()
        ]
    );

    let listed = list_cloud_vaults(&world.cloud_dir).expect("list");
    let summary: Vec<(&str, bool, Option<&str>)> = listed
        .iter()
        .map(|entry| {
            (
                entry.name.as_str(),
                entry.downloaded,
                entry.duplicate_of.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            ("Other.apassy", true, None),
            ("Personal 2.apassy", true, Some(CLOUD_NAME)),
            ("Personal 3.apassy", false, Some(CLOUD_NAME)),
            (CLOUD_NAME, true, None),
        ]
    );
}

#[test]
fn enable_picks_a_free_name_and_links_the_same_vault() {
    let world = world();
    let a = world.mac("mac-a");
    let mut vault_x = a.create(PASS);
    vault_x.add(item("X")).expect("add");
    assert_eq!(
        a.sync.enable(&mut vault_x, WRONG, "Personal").unwrap_err(),
        CloudError::Vault(VaultErrorKind::WrongKeyOrCorrupt)
    );
    assert!(!world.cloud_dir.exists() || names_in(&world.cloud_dir).is_empty());
    let first = a
        .sync
        .enable(&mut vault_x, PASS, "Personal")
        .expect("enable");
    assert_eq!(first.cloud_file_name, CLOUD_NAME);
    assert_eq!(
        a.sync.enable(&mut vault_x, PASS, "Personal").unwrap_err(),
        CloudError::AlreadyEnabled
    );

    // Another vault with another passphrase: the file does not open, so it is not this
    // vault.
    let c = world.mac("mac-c");
    let mut vault_y = c.create(OTHER_PASS);
    let y = c
        .sync
        .enable(&mut vault_y, OTHER_PASS, "Personal")
        .expect("enable y");
    assert_eq!(y.cloud_file_name, "Personal-2.apassy");
    assert!(y.pushed);

    // Another vault with the same passphrase: the file opens, but the vault id differs.
    let d = world.mac("mac-d");
    let mut vault_z = d.create(PASS);
    let z = d
        .sync
        .enable(&mut vault_z, PASS, "Personal")
        .expect("enable z");
    assert_eq!(z.cloud_file_name, "Personal-3.apassy");

    // Turn off and on again: the same vault id links to the same file without a push.
    let cloud_before = fs::read(world.cloud_file()).expect("cloud");
    assert!(a.sync.disable().expect("disable"));
    assert!(!a.sync.disable().expect("disable again"));
    assert_eq!(a.sync.status().unwrap_err(), CloudError::NotEnabled);
    assert!(world.cloud_file().exists(), "disable keeps the cloud file");
    let linked = a
        .sync
        .enable(&mut vault_x, PASS, "Personal")
        .expect("enable again");
    assert_eq!(linked.cloud_file_name, CLOUD_NAME);
    assert!(!linked.pushed);
    assert_eq!(linked.status, SyncStatus::InSync);
    assert_eq!(fs::read(world.cloud_file()).expect("cloud"), cloud_before);

    // A change while sync was off: the link is a conflict for the owner.
    a.sync.disable().expect("disable");
    vault_x.add(item("X2")).expect("add");
    let linked = a
        .sync
        .enable(&mut vault_x, PASS, "Personal")
        .expect("enable again");
    assert!(!linked.pushed);
    assert_eq!(linked.status, SyncStatus::Conflict);
    assert_eq!(a.status(), SyncStatus::Conflict);
    a.sync.keep_this_mac(&mut vault_x, PASS).expect("keep");
    assert_eq!(a.status(), SyncStatus::InSync);
    assert_eq!(titles_of_copy(&world.cloud_file(), PASS), vec!["X", "X2"]);
}

#[test]
fn pull_refuses_another_vault_at_the_cloud_name() {
    let world = world();
    let (a, mut vault_a, _b, _vault_b) = two_macs(&world);
    let d = world.mac("mac-d");
    let mut other = d.create(PASS);
    let report = d.sync.enable(&mut other, PASS, "Other").expect("enable");
    fs::copy(
        world.cloud_dir.join(&report.cloud_file_name),
        world.cloud_file(),
    )
    .expect("replace");
    assert_eq!(
        a.sync.keep_this_mac(&mut vault_a, PASS).unwrap_err(),
        CloudError::DifferentVault
    );
    vault_a.lock().expect("lock");
    let before = fs::read(&a.vault_path).expect("local");
    assert_eq!(
        a.sync.pull(&mut vault_a, PASS).unwrap_err(),
        CloudError::DifferentVault
    );
    assert_eq!(fs::read(&a.vault_path).expect("local"), before);
}

/// SQLCipher authenticates each page, not the file. All copies of a vault share the
/// key, so a page of an older copy still passes its HMAC in a newer copy. The content
/// digest of the sync record refuses such a mixed file.
#[test]
fn a_copy_that_mixes_pages_of_two_pushes_is_refused() {
    let world = world();
    let (a, mut vault_a, b, mut vault_b) = two_macs(&world);
    let old = fs::read(world.cloud_file()).expect("generation 1");
    let alpha = vault_a.search("Alpha").expect("search")[0].clone();
    vault_a
        .update(alpha.id, alpha.revision, item("Alphb"))
        .expect("update");
    a.sync.push(&mut vault_a).expect("push");
    let new = fs::read(world.cloud_file()).expect("generation 2");
    assert_eq!(old.len(), new.len(), "the same page count");

    // The page of the sync record comes from the new copy, every other page from the
    // old copy.
    let sync_page = {
        let dir = TempDir::new().expect("temp");
        let copy = dir.path().join("probe.db");
        fs::write(&copy, &new).expect("write");
        let conn = rusqlite::Connection::open(&copy).expect("open");
        conn.pragma_update(None, "key", PASS).expect("key");
        let root: i64 = conn
            .query_row(
                "SELECT rootpage FROM sqlite_schema WHERE name = 'sync_meta'",
                [],
                |row| row.get(0),
            )
            .expect("root page");
        conn.close().map_err(|(_, err)| err).expect("close");
        usize::try_from(root).expect("page")
    };
    let mut mixed = old.clone();
    let start = (sync_page - 1) * PAGE_SIZE;
    mixed[start..start + PAGE_SIZE].copy_from_slice(&new[start..start + PAGE_SIZE]);
    fs::write(world.cloud_file(), &mixed).expect("mixed");

    // SQLCipher and SQLite accept the mixed file: every page HMAC and the structure are
    // valid.
    Vault::verify_passphrase_at(&world.cloud_file(), PASS).expect("valid pages");
    // The sync check refuses it.
    assert_eq!(
        Vault::inspect_sync_copy(&world.cloud_file(), PASS)
            .unwrap_err()
            .kind(),
        VaultErrorKind::WrongKeyOrCorrupt
    );
    assert_eq!(b.status(), SyncStatus::PullAvailable);
    vault_b.lock().expect("lock");
    let before = fs::read(&b.vault_path).expect("local");
    assert_eq!(
        b.sync.pull(&mut vault_b, PASS).unwrap_err(),
        CloudError::Vault(VaultErrorKind::WrongKeyOrCorrupt)
    );
    assert_eq!(fs::read(&b.vault_path).expect("local"), before);
}

#[test]
fn locks_paths_and_state_are_checked() {
    let world = world();
    let (a, mut vault_a, b, mut vault_b) = two_macs(&world);
    assert_eq!(
        a.sync.pull(&mut vault_a, PASS).unwrap_err(),
        CloudError::NotLocked
    );
    vault_a.lock().expect("lock");
    assert_eq!(
        a.sync.push(&mut vault_a).unwrap_err(),
        CloudError::Vault(VaultErrorKind::Locked)
    );
    // The sync engine of Mac A refuses the vault of Mac B.
    assert_eq!(
        a.sync.push(&mut vault_b).unwrap_err(),
        CloudError::WrongVault
    );

    // The state file: mode 0600, the cloud name, a SHA-256, no temporary file.
    let state_path = b.state_path();
    assert_eq!(mode_of(&state_path), 0o600);
    let state = b.sync.state().expect("read").expect("some");
    assert_eq!(state.cloud_file_name, CLOUD_NAME);
    assert_eq!(state.last_generation, 1);
    assert_eq!(state.last_sha256.as_deref().map(str::len), Some(64));
    assert_eq!(
        vault_b.sync_identity().expect("record").vault_id,
        state.vault_id
    );
    assert_eq!(
        names_in(state_path.parent().expect("dir")),
        vec!["vault.json".to_owned()]
    );

    // A damaged state file is an error, not "off".
    fs::write(&state_path, b"{ not json").expect("damage");
    assert_eq!(b.sync.status().unwrap_err(), CloudError::State);
    assert_eq!(b.sync.push(&mut vault_b).unwrap_err(), CloudError::State);
}

#[test]
fn cloud_names_and_defaults() {
    assert_eq!(cloud_file_name_for("Work 2"), "Work-2.apassy");
    assert!(!device_name().is_empty());
    let dir = default_cloud_dir();
    if cfg!(target_os = "macos") && std::env::var_os("HOME").is_some() {
        let dir = dir.expect("the iCloud Drive folder on macOS");
        assert!(
            dir.ends_with("Library/Mobile Documents/com~apple~CloudDocs/Apassy"),
            "{dir:?}"
        );
    } else if !cfg!(target_os = "macos") {
        assert_eq!(dir, None, "no iCloud Drive outside macOS");
    }
}

#[test]
fn adopt_accepts_a_vault_file_put_in_icloud_by_hand() {
    // A vault that was never pushed has generation 0 and no content digest.
    let world = world();
    let d = world.mac("mac-d");
    let mut vault = d.create(PASS);
    vault.add(item("By hand")).expect("add");
    drop(vault);
    fs::create_dir_all(&world.cloud_dir).expect("folder");
    fs::copy(&d.vault_path, world.cloud_dir.join("Manual.apassy")).expect("copy");

    let e = world.mac("mac-e");
    assert_eq!(
        e.sync.adopt(".Manual.apassy", PASS).unwrap_err(),
        CloudError::InvalidName
    );
    let (mut adopted, outcome) = e.sync.adopt("Manual.apassy", PASS).expect("adopt");
    assert_eq!(outcome.generation, 0);
    assert!(outcome.pushed_by.is_empty());
    assert_eq!(e.status(), SyncStatus::InSync);
    adopted.unlock(PASS).expect("unlock");
    assert_eq!(titles(&adopted), vec!["By hand"]);
    // The first push from the new Mac makes generation 1.
    adopted.add(item("Later")).expect("add");
    assert_eq!(e.sync.push(&mut adopted).expect("push").generation, 1);
    assert_eq!(
        e.sync.adopt("Manual.apassy", PASS).unwrap_err(),
        CloudError::AlreadyEnabled
    );
}
