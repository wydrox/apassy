//! The phone and Mac exchange the same encrypted snapshot format. The tests stand
//! in for Swift file coordination; no test calls an iCloud service.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use apassy::contracts::CredentialKind;
use apassy::vault::{Field, ItemDraft, SecretValue, SyncScope, Vault};
use apassy_core::Core;
use serde_json::{Value, json};
use tempfile::TempDir;

const PASS: &str = "synthetic-icloud-passphrase";
const NEW_PASS: &str = "synthetic-new-icloud-passphrase";

fn core(path: &Path, role: &str) -> Core {
    Core::new(&json!({"data_dir": path, "role": role, "device_name": "Test iPhone"}).to_string())
        .unwrap()
}

fn call(core: &Core, request: Value) -> Value {
    let answer: Value = serde_json::from_str(&core.call(&request.to_string())).unwrap();
    assert_eq!(answer["ok"], true, "{answer}");
    answer["result"].clone()
}

fn fails(core: &Core, request: Value) -> String {
    let answer: Value = serde_json::from_str(&core.call(&request.to_string())).unwrap();
    assert_eq!(answer["ok"], false, "{answer}");
    answer["error"]["code"].as_str().unwrap().to_owned()
}

fn draft(title: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::ApiKey,
        notes: String::new(),
        tags: vec![],
        fields: vec![
            Field {
                name: "service".into(),
                value: SecretValue::new("example".into()),
                secret: false,
            },
            Field {
                name: "token".into(),
                value: SecretValue::new("synthetic-secret".into()),
                secret: true,
            },
        ],
    }
}

fn phone_draft(title: &str) -> Value {
    json!({"title": title, "kind": "api_key", "fields": [
        {"name":"service", "value":"example", "secret":false},
        {"name":"token", "value":"synthetic-phone-secret", "secret":true}
    ]})
}

struct Fixture {
    root: TempDir,
    dir: PathBuf,
    phone: Core,
    mac: Vault,
    id: String,
    serial: usize,
}

impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        let dir = root.path().join("phone");
        let phone = core(&dir, "app");
        let mut mac = Vault::create(&root.path().join("mac.apassy"), PASS).unwrap();
        mac.unlock(PASS).unwrap();
        let id = mac.sync_identity().unwrap().vault_id;
        Self {
            root,
            dir,
            phone,
            mac,
            id,
            serial: 0,
        }
    }

    fn paths(&mut self) -> (PathBuf, PathBuf) {
        self.serial += 1;
        let folder = self
            .dir
            .join("icloud-transfer")
            .join(format!("transfer-{}", self.serial));
        fs::create_dir(&folder).unwrap();
        (folder.join("input.apassy"), folder.join("output.apassy"))
    }

    fn import(&mut self) -> PathBuf {
        let (input, _) = self.paths();
        self.mac.write_sync_copy(&input, "Test Mac").unwrap();
        let result = call(
            &self.phone,
            json!({"op":"icloud_import", "name":"Personal", "passphrase":PASS, "input_path":input}),
        );
        assert_eq!(result["vault"]["id"], self.id);
        assert_eq!(result["vault"]["sync_source"], "icloud");
        input
    }

    fn prepare(&self, input: &Path, output: &Path) -> Value {
        call(
            &self.phone,
            json!({"op":"icloud_sync_prepare", "vault_id":self.id, "input_path":input, "output_path":output}),
        )
    }

    fn complete(&self, prepared: &Value) -> Value {
        call(
            &self.phone,
            json!({"op":"icloud_sync_complete", "vault_id":self.id, "token":prepared["token"]}),
        )["status"]
            .clone()
    }

    fn save(&self, title: &str) -> Value {
        call(&self.phone, json!({"op":"save", "item":phone_draft(title)}))
    }

    fn titles(&self) -> Vec<String> {
        call(&self.phone, json!({"op":"items"}))["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["title"].as_str().unwrap().to_owned())
            .collect()
    }
}

#[test]
fn import_checks_key_preserves_identity_and_strips_raw_mac_local_data() {
    let mut f = Fixture::new();
    f.mac.add(draft("Mac credential")).unwrap();
    f.mac.register_agent("Mac-only agent").unwrap();
    let (input, _) = f.paths();
    // A raw vault with generation zero can contain agents and local events.
    f.mac.backup(&input).unwrap();
    f.mac.unlock(PASS).unwrap();
    assert_eq!(
        Vault::inspect_sync_copy(&input, PASS).unwrap().generation,
        0
    );
    assert_eq!(
        fails(
            &f.phone,
            json!({"op":"icloud_import", "name":"Personal", "passphrase":"synthetic-wrong-passphrase", "input_path":input})
        ),
        "wrong_passphrase"
    );
    assert!(
        call(&f.phone, json!({"op":"info"}))["vaults"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    call(
        &f.phone,
        json!({"op":"icloud_import", "name":"Personal", "passphrase":PASS, "input_path":input}),
    );
    assert_eq!(f.titles(), ["Mac credential"]);
    let status = call(&f.phone, json!({"op":"sync_status"}));
    assert_eq!(status["status"]["enabled"], true);
    assert_eq!(status["status"]["state"], "never");
    assert_eq!(
        fails(&f.phone, json!({"op":"sync"})),
        "coordination_required"
    );
    assert_eq!(
        fails(
            &f.phone,
            json!({"op":"icloud_import", "name":"Again", "passphrase":PASS, "input_path":input})
        ),
        "invalid_input"
    );
    assert_eq!(call(&f.phone, json!({"op":"info"}))["unlocked"], true);
    f.phone.shutdown();
    let mut imported = Vault::open(&f.dir.join("vaults").join(format!("{}.apassy", f.id))).unwrap();
    imported.unlock(PASS).unwrap();
    assert_eq!(imported.sync_identity().unwrap().vault_id, f.id);
    assert!(imported.list_agents().unwrap().is_empty());
    assert_ne!(
        imported.sync_device_id().unwrap(),
        f.mac.sync_device_id().unwrap()
    );
}

#[test]
fn snapshots_merge_mac_and_phone_edits_conflicts_and_deletions() {
    let mut f = Fixture::new();
    let item = f.mac.add(draft("Original")).unwrap();
    f.import();
    // Both devices change the same record after import.
    f.mac
        .update(item.id, item.revision, draft("Mac version"))
        .unwrap();
    call(
        &f.phone,
        json!({"op":"save", "id":item.id, "revision":item.revision, "item":phone_draft("Phone version")}),
    );
    f.save("Phone only");
    f.mac.add(draft("Mac only")).unwrap();
    let (input, output) = f.paths();
    f.mac.write_sync_copy(&input, "Test Mac").unwrap();
    let prepared = f.prepare(&input, &output);
    assert_eq!(prepared["write_required"], true);
    assert_eq!(prepared["rekeyed"], false);
    assert_eq!(
        prepared["input_sha256"],
        apassy::sync::file_sha256(&input).unwrap()
    );
    assert_eq!(
        prepared["output_sha256"],
        apassy::sync::file_sha256(&output).unwrap()
    );
    assert_eq!(
        call(&f.phone, json!({"op":"sync_status"}))["status"]["state"],
        "pending"
    );
    assert!(f.titles().contains(&"Mac only".to_owned()));
    let complete = f.complete(&prepared);
    assert_eq!(complete["state"], "ok");
    assert_eq!(complete["merged"]["conflicts"], 1);
    f.mac.merge_from(&output, &SyncScope::vault()).unwrap();
    assert!(
        f.mac
            .search("")
            .unwrap()
            .iter()
            .any(|item| item.title == "Phone only")
    );
    let archived = call(&f.phone, json!({"op":"items", "archived":"all"}));
    assert!(archived.to_string().contains("conflict copy"));
    // The Mac deletes one item and the phone deletes a different item.
    let mac_only = f
        .mac
        .search("")
        .unwrap()
        .into_iter()
        .find(|item| item.title == "Mac only")
        .unwrap();
    f.mac.delete(mac_only.id, mac_only.revision).unwrap();
    let phone_only = call(&f.phone, json!({"op":"items"}))["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["title"] == "Phone only")
        .unwrap()
        .clone();
    call(
        &f.phone,
        json!({"op":"delete", "id":phone_only["id"], "revision":phone_only["revision"]}),
    );
    let (input, output) = f.paths();
    f.mac.write_sync_copy(&input, "Test Mac").unwrap();
    let prepared = f.prepare(&input, &output);
    assert_eq!(f.complete(&prepared)["state"], "ok");
    f.mac.merge_from(&output, &SyncScope::vault()).unwrap();
    assert!(
        !f.titles()
            .iter()
            .any(|title| title == "Mac only" || title == "Phone only")
    );
    assert!(
        !f.mac
            .search("")
            .unwrap()
            .iter()
            .any(|item| item.title == "Mac only" || item.title == "Phone only")
    );
    // The same content needs no new encrypted export.
    let (input, output) = f.paths();
    f.mac.write_sync_copy(&input, "Test Mac").unwrap();
    let prepared = f.prepare(&input, &output);
    assert_eq!(prepared["write_required"], false);
    assert!(prepared["output_sha256"].is_null());
    assert!(!output.exists());
    assert_eq!(f.complete(&prepared)["state"], "ok");
}

#[test]
fn completion_tokens_are_one_use_bound_to_session_and_do_not_hide_new_edits() {
    let mut f = Fixture::new();
    f.import();
    f.save("First change");
    let (input, output) = f.paths();
    f.mac.write_sync_copy(&input, "Test Mac").unwrap();
    let prepared = f.prepare(&input, &output);
    f.save("Newer change");
    assert_eq!(f.complete(&prepared)["state"], "pending");
    assert_eq!(
        fails(
            &f.phone,
            json!({"op":"icloud_sync_complete", "vault_id":f.id, "token":prepared["token"]})
        ),
        "cancelled"
    );
    let (_, output2) = f.paths();
    let prepared2 = f.prepare(&input, &output2);
    let (_, output3) = f.paths();
    let prepared3 = f.prepare(&input, &output3);
    assert_eq!(
        fails(
            &f.phone,
            json!({"op":"icloud_sync_complete", "vault_id":f.id, "token":prepared2["token"]})
        ),
        "invalid_input"
    );
    call(&f.phone, json!({"op":"lock"}));
    call(&f.phone, json!({"op":"unlock", "passphrase":PASS}));
    assert_eq!(
        fails(
            &f.phone,
            json!({"op":"icloud_sync_complete", "vault_id":f.id, "token":prepared3["token"]})
        ),
        "cancelled"
    );
    let (_, output4) = f.paths();
    let prepared4 = f.prepare(&input, &output4);
    call(&f.phone, json!({"op":"select", "vault_id":f.id}));
    call(&f.phone, json!({"op":"unlock", "passphrase":PASS}));
    assert_eq!(
        fails(
            &f.phone,
            json!({"op":"icloud_sync_complete", "vault_id":f.id, "token":prepared4["token"]})
        ),
        "cancelled"
    );
}

#[test]
fn wrong_identity_and_new_passphrase_never_replace_local_items() {
    let mut f = Fixture::new();
    f.mac.add(draft("Original")).unwrap();
    f.import();
    f.save("Phone change");
    let (other_path, output) = f.paths();
    let mut other = Vault::create(&f.root.path().join("other.apassy"), PASS).unwrap();
    other.unlock(PASS).unwrap();
    other.add(draft("Wrong vault")).unwrap();
    other.write_sync_copy(&other_path, "Other Mac").unwrap();
    assert_eq!(
        fails(
            &f.phone,
            json!({"op":"icloud_sync_prepare", "vault_id":f.id, "input_path":other_path, "output_path":output})
        ),
        "needs_passphrase"
    );
    assert!(!output.exists());
    assert_eq!(f.titles(), ["Original", "Phone change"]);
    assert_eq!(
        fails(
            &f.phone,
            json!({"op":"icloud_sync_prepare", "vault_id":f.id, "input_path":other_path, "output_path":output, "passphrase":PASS})
        ),
        "damaged"
    );
    // A remote rekey does not discard the phone's local edits.
    f.mac.change_passphrase(PASS, NEW_PASS).unwrap();
    f.mac.unlock(NEW_PASS).unwrap();
    f.mac.add(draft("Mac after rekey")).unwrap();
    let (input, output) = f.paths();
    f.mac.write_sync_copy(&input, "Test Mac").unwrap();
    assert_eq!(
        fails(
            &f.phone,
            json!({"op":"icloud_sync_prepare", "vault_id":f.id, "input_path":input, "output_path":output})
        ),
        "needs_passphrase"
    );
    call(
        &f.phone,
        json!({"op":"unlock", "passphrase":PASS, "keep":true}),
    );
    let prepared = call(
        &f.phone,
        json!({"op":"icloud_sync_prepare", "vault_id":f.id, "input_path":input, "output_path":output, "passphrase":NEW_PASS}),
    );
    assert_eq!(prepared["rekeyed"], true);
    assert_eq!(prepared["write_required"], true);
    assert_eq!(f.complete(&prepared)["state"], "ok");
    f.mac.merge_from(&output, &SyncScope::vault()).unwrap();
    assert!(
        f.mac
            .search("")
            .unwrap()
            .iter()
            .any(|item| item.title == "Phone change")
    );
    call(&f.phone, json!({"op":"suspend"}));
    assert_eq!(call(&f.phone, json!({"op":"resume"}))["unlocked"], true);
    assert_eq!(
        call(
            &f.phone,
            json!({"op":"check_passphrase", "passphrase":PASS})
        )["ok"],
        false
    );
    assert_eq!(
        call(
            &f.phone,
            json!({"op":"check_passphrase", "passphrase":NEW_PASS})
        )["ok"],
        true
    );
}

#[test]
fn transfer_paths_roles_and_size_have_strict_bounds() {
    let mut f = Fixture::new();
    let input = f.import();
    let (_, output) = f.paths();
    let outside = f.root.path().join("outside.apassy");
    fs::copy(&input, &outside).unwrap();
    assert_eq!(
        fails(
            &f.phone,
            json!({"op":"icloud_sync_prepare", "vault_id":f.id, "input_path":outside, "output_path":output})
        ),
        "invalid_input"
    );
    assert_eq!(
        fails(
            &f.phone,
            json!({"op":"icloud_sync_prepare", "vault_id":f.id, "input_path":input, "output_path":outside})
        ),
        "invalid_input"
    );
    assert_eq!(
        fails(
            &f.phone,
            json!({"op":"icloud_sync_prepare", "vault_id":f.id, "input_path":input, "output_path":input})
        ),
        "invalid_input"
    );
    let link = output.with_file_name("link.apassy");
    std::os::unix::fs::symlink(&input, &link).unwrap();
    assert_eq!(
        fails(
            &f.phone,
            json!({"op":"icloud_sync_prepare", "vault_id":f.id, "input_path":link, "output_path":output})
        ),
        "invalid_input"
    );
    let dir_link = f.dir.join("icloud-transfer").join("linked-folder");
    std::os::unix::fs::symlink(input.parent().unwrap(), &dir_link).unwrap();
    assert_eq!(
        fails(
            &f.phone,
            json!({"op":"icloud_sync_prepare", "vault_id":f.id, "input_path":dir_link.join("input.apassy"), "output_path":output})
        ),
        "invalid_input"
    );
    let hard = output.with_file_name("hard.apassy");
    fs::hard_link(&input, &hard).unwrap();
    assert_eq!(
        fails(
            &f.phone,
            json!({"op":"icloud_sync_prepare", "vault_id":f.id, "input_path":hard, "output_path":output})
        ),
        "invalid_input"
    );
    fs::remove_file(hard).unwrap();
    let large = output.with_file_name("large.apassy");
    fs::File::create(&large)
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();
    assert_eq!(
        fails(
            &f.phone,
            json!({"op":"icloud_sync_prepare", "vault_id":f.id, "input_path":large, "output_path":output})
        ),
        "too_large"
    );
    fs::write(input.with_file_name("input.apassy-wal"), b"synthetic WAL").unwrap();
    assert_eq!(
        fails(
            &f.phone,
            json!({"op":"icloud_sync_prepare", "vault_id":f.id, "input_path":input, "output_path":output})
        ),
        "invalid_input"
    );
    let autofill = core(&f.dir, "autofill");
    for op in [
        "icloud_import",
        "icloud_sync_prepare",
        "icloud_sync_complete",
    ] {
        assert_eq!(fails(&autofill, json!({"op":op})), "not_allowed");
    }
}

#[test]
fn old_registry_files_still_load_and_icloud_source_survives_restart_and_remove() {
    let mut f = Fixture::new();
    let input = f.import();
    f.phone.shutdown();
    let restarted = core(&f.dir, "app");
    assert_eq!(
        call(&restarted, json!({"op":"info"}))["vaults"][0]["sync_source"],
        "icloud"
    );
    assert_eq!(
        call(&restarted, json!({"op":"sync_status"}))["status"]["enabled"],
        true
    );
    call(&restarted, json!({"op":"remove_vault", "vault_id":f.id}));
    assert!(
        input.exists(),
        "core never removes provider or caller-owned transfer files"
    );
    assert!(
        !f.dir
            .join("vaults")
            .join(format!("{}.apassy", f.id))
            .exists()
    );
    let local = call(
        &restarted,
        json!({"op":"create_local_vault", "name":"Local", "passphrase":PASS}),
    );
    restarted.shutdown();
    let registry = f.dir.join("phone.json");
    let mut old: Value = serde_json::from_slice(&fs::read(&registry).unwrap()).unwrap();
    old["vaults"][0]
        .as_object_mut()
        .unwrap()
        .remove("sync_source");
    fs::write(&registry, serde_json::to_vec(&old).unwrap()).unwrap();
    let legacy = core(&f.dir, "app");
    assert_eq!(
        call(&legacy, json!({"op":"info"}))["selected"],
        local["vault"]["id"]
    );
    assert_eq!(
        call(&legacy, json!({"op":"sync_status"}))["status"]["enabled"],
        false
    );
}

#[test]
fn a_lock_during_import_prevents_a_late_selection_or_unlock() {
    let f = Fixture::new();
    let input = f.dir.join("icloud-transfer").join("import.apassy");
    let mut mac = f.mac;
    mac.write_sync_copy(&input, "Test Mac").unwrap();
    let phone = Arc::new(f.phone);
    let worker_core = Arc::clone(&phone);
    let worker = std::thread::spawn(move || {
        fails(
            &worker_core,
            json!({"op":"icloud_import", "input_path":input, "name":"Personal", "passphrase":PASS}),
        )
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let started = fs::read_dir(f.dir.join("icloud-transfer"))
            .unwrap()
            .any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".core-")
            });
        if started {
            break;
        }
        assert!(Instant::now() < deadline, "import did not start");
        std::thread::sleep(Duration::from_millis(1));
    }
    call(&phone, json!({"op":"lock"}));
    assert_eq!(worker.join().unwrap(), "cancelled");
    let info = call(&phone, json!({"op":"info"}));
    assert_eq!(info["unlocked"], false);
    assert!(info["vaults"].as_array().unwrap().is_empty());
    assert!(
        !f.dir
            .join("vaults")
            .join(format!("{}.apassy", f.id))
            .exists()
    );
}

#[test]
fn repeated_single_item_merges_advance_status_version() {
    let mut f = Fixture::new();
    let item = f.mac.add(draft("Initial")).unwrap();
    f.import();
    let mut version = 0;
    let mut revision = item.revision;
    for title in ["Remote edit one", "Remote edit two"] {
        revision = f
            .mac
            .update(item.id, revision, draft(title))
            .unwrap()
            .revision;
        let (input, output) = f.paths();
        f.mac.write_sync_copy(&input, "Test Mac").unwrap();
        let prepared = f.prepare(&input, &output);
        let status = f.complete(&prepared);
        assert_eq!(status["merged"]["updated"], 1);
        let next = status["version"].as_u64().unwrap();
        assert!(
            next > version,
            "equal merge counts must still refresh the app"
        );
        version = next;
        assert_eq!(f.titles(), [title]);
    }
}

#[test]
fn an_output_failure_after_rekey_reports_the_accepted_passphrase() {
    use std::os::unix::fs::PermissionsExt;
    let mut f = Fixture::new();
    f.import();
    f.save("Phone change");
    f.mac.change_passphrase(PASS, NEW_PASS).unwrap();
    f.mac.unlock(NEW_PASS).unwrap();
    let (input, output) = f.paths();
    f.mac.write_sync_copy(&input, "Test Mac").unwrap();
    let parent = output.parent().unwrap();
    fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
    let probe = parent.join("permission-probe");
    if fs::write(&probe, b"probe").is_ok() {
        // A privileged test process bypasses filesystem permissions.
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        eprintln!("permission failure check unavailable for this privileged process");
        return;
    }
    let answer: Value = serde_json::from_str(
        &f.phone.call(
            &json!({
                "op":"icloud_sync_prepare", "vault_id":f.id, "input_path":input,
                "output_path":output, "passphrase":NEW_PASS
            })
            .to_string(),
        ),
    )
    .unwrap();
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(answer["ok"], false, "{answer}");
    assert_eq!(answer["error"]["rekeyed"], true, "{answer}");
    assert_eq!(
        call(
            &f.phone,
            json!({"op":"check_passphrase", "passphrase":NEW_PASS})
        )["ok"],
        true
    );
    assert_eq!(
        call(
            &f.phone,
            json!({"op":"check_passphrase", "passphrase":PASS})
        )["ok"],
        false
    );
}

#[test]
fn startup_recovers_only_owned_unregistered_import_files() {
    use std::os::unix::fs::MetadataExt;
    let mut f = Fixture::new();
    let file = f.dir.join("vaults").join(format!("{}.apassy", f.id));
    f.mac.backup(&file).unwrap();
    f.mac.unlock(PASS).unwrap();
    let marker = f
        .dir
        .join("sync")
        .join(format!("icloud-import-{}.json", f.id));
    // An interrupted marker from an older implementation must not block imports.
    fs::write(&marker, b"{\"id\":").unwrap();
    let malformed = core(&f.dir, "app");
    assert!(!marker.exists());
    assert!(
        file.exists(),
        "an invalid marker cannot authorize removal of a vault"
    );
    malformed.shutdown();
    let record = |path: &Path| {
        let meta = fs::metadata(path).unwrap();
        json!({"id":f.id, "device":meta.dev(), "inode":meta.ino()})
    };
    fs::write(&marker, serde_json::to_vec(&record(&file)).unwrap()).unwrap();
    let recovered = core(&f.dir, "app");
    assert!(!file.exists());
    assert!(!marker.exists());
    recovered.shutdown();
    // Recovery frees the name so an ordinary import can succeed.
    f.import();
    f.phone.shutdown();
    let meta = fs::metadata(&file).unwrap();
    fs::write(
        &marker,
        serde_json::to_vec(&json!({"id":f.id, "device":meta.dev(), "inode":meta.ino()})).unwrap(),
    )
    .unwrap();
    let registered = core(&f.dir, "app");
    assert!(file.exists(), "a registered vault always survives recovery");
    assert!(!marker.exists());
    registered.shutdown();
    // A changed file at an unregistered name is not the marker's file.
    fs::remove_file(f.dir.join("phone.json")).unwrap();
    fs::write(
        &marker,
        serde_json::to_vec(
            &json!({"id":f.id, "device":meta.dev(), "inode":meta.ino().wrapping_add(1)}),
        )
        .unwrap(),
    )
    .unwrap();
    let changed = core(&f.dir, "app");
    assert!(file.exists(), "a marker cannot remove a different inode");
    changed.shutdown();
}

#[test]
fn concurrent_imports_never_remove_the_successful_import() {
    let mut f = Fixture::new();
    let (input, _) = f.paths();
    f.mac.write_sync_copy(&input, "Test Mac").unwrap();
    let phone = Arc::new(f.phone);
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let workers: Vec<_> = (0..2).map(|_| {
        let phone = Arc::clone(&phone);
        let barrier = Arc::clone(&barrier);
        let input = input.clone();
        std::thread::spawn(move || {
            barrier.wait();
            serde_json::from_str::<Value>(&phone.call(&json!({"op":"icloud_import", "input_path":input, "name":"Personal", "passphrase":PASS}).to_string())).unwrap()
        })
    }).collect();
    barrier.wait();
    let answers: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(
        answers.iter().filter(|answer| answer["ok"] == true).count(),
        1,
        "{answers:?}"
    );
    assert_eq!(
        call(&phone, json!({"op":"info"}))["vaults"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    phone.shutdown();
    let restarted = core(&f.dir, "app");
    call(&restarted, json!({"op":"unlock", "passphrase":PASS}));
}

// ---- A snapshot of schema 16 (before passkeys) ----

/// The content digest of a sync copy: the algorithm of `content_digest` in
/// `src/vault/sync.rs` ("apassy-sync-content-v1"). [`set_schema`] checks it first against
/// the digest that the app stored.
fn content_digest(conn: &rusqlite::Connection) -> [u8; 32] {
    use rusqlite::types::ValueRef;
    fn put(ctx: &mut ring::digest::Context, value: ValueRef<'_>) {
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
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
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
                put(&mut ctx, row.get_ref(index).unwrap());
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
        put(&mut ctx, ValueRef::Text(table.as_bytes()));
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
                put(&mut ctx, row.get_ref(index).unwrap());
            }
        }
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// The version in the header and in `vault_meta` of the closed file at `path`.
fn schema_marks(path: &Path) -> (i64, i64) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.pragma_update(None, "key", PASS).unwrap();
    let marks = conn
        .query_row(
            "SELECT (SELECT user_version FROM pragma_user_version), schema_version
             FROM vault_meta WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    conn.close().map_err(|(_, e)| e).unwrap();
    marks
}

/// Give the closed Mac snapshot at `path` the version marks of `version` and the
/// content digest of the changed rows, as the push of that app does. Schema 17 adds no
/// table or column (a passkey is an item field with a reserved name), so a snapshot
/// without passkey fields is then the snapshot of the app of schema 16.
fn set_schema(path: &Path, version: i64) {
    assert_eq!(schema_marks(path), (17, 17));
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.pragma_update(None, "key", PASS).unwrap();
    let passkeys: i64 = conn
        .query_row(
            "SELECT count(*) FROM item_field WHERE substr(name, 1, 8) = 'passkey_'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(passkeys, 0, "a schema 16 snapshot has no passkey field");
    let stored: Vec<u8> = conn
        .query_row(
            "SELECT content_digest FROM sync_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored, content_digest(&conn), "the algorithm of the app");
    conn.execute_batch(&format!(
        "UPDATE vault_meta SET schema_version = {version} WHERE id = 1;
         PRAGMA user_version = {version};"
    ))
    .unwrap();
    let digest = content_digest(&conn);
    conn.execute(
        "UPDATE sync_meta SET content_digest = ?1 WHERE id = 1",
        [digest.as_slice()],
    )
    .unwrap();
    conn.close().map_err(|(_, e)| e).unwrap();
    assert_eq!(schema_marks(path), (version, version));
}

/// The Mac writes a snapshot and an app of schema 16 is the writer.
fn old_snapshot(f: &mut Fixture) -> (PathBuf, PathBuf) {
    let (input, output) = f.paths();
    f.mac.write_sync_copy(&input, "Old Mac").unwrap();
    set_schema(&input, 16);
    (input, output)
}

#[test]
fn a_schema16_snapshot_imports_and_the_next_sync_writes_schema17_with_no_edit() {
    let mut f = Fixture::new();
    f.mac.add(draft("Mac credential")).unwrap();

    // A later schema and a wrong passphrase make no vault on the phone.
    let (future, _) = f.paths();
    f.mac.write_sync_copy(&future, "Newer Mac").unwrap();
    set_schema(&future, 18);
    let import = |input: &Path, passphrase: &str| json!({"op":"icloud_import", "name":"Personal", "passphrase":passphrase, "input_path":input});
    assert_eq!(fails(&f.phone, import(&future, PASS)), "unsupported_schema");
    let (input, _) = old_snapshot(&mut f);
    let input_sha = apassy::sync::file_sha256(&input).unwrap();
    assert_eq!(
        fails(&f.phone, import(&input, "synthetic-wrong-passphrase")),
        "wrong_passphrase"
    );
    assert!(
        call(&f.phone, json!({"op":"info"}))["vaults"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let result = call(&f.phone, import(&input, PASS));
    assert_eq!(result["vault"]["id"], f.id);
    assert_eq!(f.titles(), ["Mac credential"]);
    assert_eq!(apassy::sync::file_sha256(&input).unwrap(), input_sha);
    assert_eq!(schema_marks(&input), (16, 16));

    // The same file, no edit: the phone writes the current schema once.
    let (_, output) = f.paths();
    let prepared = f.prepare(&input, &output);
    assert_eq!(prepared["write_required"], true);
    assert_eq!(prepared["input_sha256"], input_sha);
    assert_eq!(
        prepared["output_sha256"],
        apassy::sync::file_sha256(&output).unwrap()
    );
    assert_eq!(apassy::sync::file_sha256(&input).unwrap(), input_sha);
    assert_eq!(schema_marks(&input), (16, 16));
    assert_eq!(schema_marks(&output), (17, 17));
    let complete = f.complete(&prepared);
    assert_eq!(complete["state"], "ok");
    assert_eq!(complete["merged"]["inserted"], 0);
    assert_eq!(complete["merged"]["updated"], 0);
    assert_eq!(complete["merged"]["conflicts"], 0);

    // The Mac and a new Mac take the output: no duplicate, no conflict.
    let report = f.mac.merge_from(&output, &SyncScope::vault()).unwrap();
    assert_eq!(report.remote_schema, 17);
    assert!(!report.remote_outdated());
    assert!(!report.changed_local());
    assert!(report.conflicts.is_empty());
    let (mut new_mac, adopted) =
        Vault::adopt_sync_copy(&output, &f.root.path().join("new-mac.apassy"), PASS).unwrap();
    assert!(!adopted.outdated());
    new_mac.unlock(PASS).unwrap();
    for vault in [&f.mac, &new_mac] {
        let titles: Vec<String> = vault
            .search("")
            .unwrap()
            .into_iter()
            .map(|item| item.title)
            .collect();
        assert_eq!(titles, ["Mac credential"]);
        assert!(vault.conflict_copies().unwrap().is_empty());
    }
    assert_eq!(
        new_mac.sync_content(&SyncScope::vault()).unwrap(),
        f.mac.sync_content(&SyncScope::vault()).unwrap()
    );

    // An edit on each side and a schema 16 snapshot again: one merge, no duplicate.
    f.save("Phone item");
    f.mac.add(draft("Mac item")).unwrap();
    let (input, output) = old_snapshot(&mut f);
    let input_sha = apassy::sync::file_sha256(&input).unwrap();
    let prepared = f.prepare(&input, &output);
    assert_eq!(prepared["write_required"], true);
    assert_eq!(apassy::sync::file_sha256(&input).unwrap(), input_sha);
    let complete = f.complete(&prepared);
    assert_eq!(complete["state"], "ok");
    assert_eq!(complete["merged"]["inserted"], 1);
    assert_eq!(complete["merged"]["conflicts"], 0);
    let report = f.mac.merge_from(&output, &SyncScope::vault()).unwrap();
    assert_eq!(report.inserted, 1);
    assert!(report.conflicts.is_empty());
    let mut titles = f.titles();
    titles.sort();
    assert_eq!(titles, ["Mac credential", "Mac item", "Phone item"]);
    assert_eq!(f.mac.search("").unwrap().len(), 3);

    // A current snapshot with the same content needs no new export.
    let (input, output) = f.paths();
    f.mac.write_sync_copy(&input, "Test Mac").unwrap();
    let prepared = f.prepare(&input, &output);
    assert_eq!(prepared["write_required"], false);
    assert!(!output.exists());
}
