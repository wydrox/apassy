#![cfg(feature = "vault")]

//! Sync of a vault through the Apassy relay (ADR 0022, contract relay-sync-v1). Synthetic
//! values only.
//!
//! An in-process fake relay (`tests/common/fake_relay.rs`) stands in for the relay on
//! 127.0.0.1 with plain HTTP, which the app allows only for a loopback address. Each
//! "Mac" is a separate data folder with its own local vault file and device key.

#[path = "common/fake_relay.rs"]
mod fake_relay;

/// The fake relay reads the app's sync module under this name.
use apassy::sync as relay_api;

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apassy::contracts::CredentialKind;
use apassy::sync::{
    DeviceKey, HeadFields, JoinedDevice, LinkCode, PendingJoin, RelayConfig, RelayRefusal,
    RelaySync, SignedHead, SyncError, SyncTransport, TransportKind, decode_b64u, head_hash,
    safety_words, sha256_hex, sign_in_message,
};
use apassy::vault::{Field, ItemDraft, SecretValue, Vault, VaultErrorKind};
use fake_relay::{FakeRelay, StoredHead};
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use tempfile::TempDir;

const PASS: &str = "synthetic-relay-pass";
const WRONG: &str = "synthetic-relay-wrong";

/// One Mac: a data folder, its local vault path, and its relay sync.
struct Mac {
    data: PathBuf,
    vault_path: PathBuf,
    sync: RelaySync,
}

fn mac(root: &TempDir, name: &str, url: &str) -> Mac {
    let data = root.path().join(name).join("Apassy");
    fs::create_dir_all(&data).expect("data dir");
    let vault_path = data.join("vault.db");
    Mac {
        sync: RelaySync::new(RelayConfig::in_data_dir(&data, &vault_path, url, "vault")),
        data,
        vault_path,
    }
}

impl Mac {
    fn create(&self) -> Vault {
        let mut vault = Vault::create(&self.vault_path, PASS).expect("create");
        vault.unlock(PASS).expect("unlock");
        vault
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

/// Mac A with a vault on the relay (a new team), and Mac B that joined with a link and
/// adopted the vault. Both vaults are unlocked.
struct Pair {
    _root: TempDir,
    relay: FakeRelay,
    a: Mac,
    b: Mac,
    vault_a: Vault,
    vault_b: Vault,
}

fn join(relay: &FakeRelay, a: &Mac, vault_a: &Vault) -> JoinedDevice {
    let code = a.sync.create_link(vault_a).expect("link");
    assert!(
        code.link
            .starts_with(&format!("{}/link#apassy_lnk_", relay.url))
    );
    let pending = PendingJoin::request(&code.link, "", "Synthetic Mac mini").expect("request");
    assert!(
        pending.poll().expect("poll").is_none(),
        "waits for the confirmation"
    );
    let links = a.sync.pending_links(vault_a, Some(&code)).expect("links");
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].device_name, "Synthetic Mac mini");
    assert_eq!(
        links[0].safety.as_deref(),
        Some(pending.safety.as_str()),
        "both Macs show the same words"
    );
    a.sync.confirm_link(vault_a, &links[0]).expect("confirm");
    pending.poll().expect("poll").expect("confirmed")
}

fn pair() -> Pair {
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    let a = mac(&root, "a", &relay.url);
    let b = mac(&root, "b", &relay.url);
    let mut vault_a = a.create();
    vault_a.add(item("Alpha", "SYNTH-alpha")).expect("add");
    let report = a
        .sync
        .create_team(
            &mut vault_a,
            "Personal",
            &relay.team_code(),
            "Synthetic MacBook",
        )
        .expect("create team");
    assert!(report.outcome.pushed);
    assert_eq!(relay.version(), 1);
    let joined = join(&relay, &a, &vault_a);
    let download = joined.download(&b.data.join("sync")).expect("download");
    let (mut vault_b, _) = b.sync.adopt(&joined, &download, PASS).expect("adopt");
    vault_b.unlock(PASS).expect("unlock");
    Pair {
        _root: root,
        relay,
        a,
        b,
        vault_a,
        vault_b,
    }
}

#[test]
fn a_new_team_pushes_version_1_and_stores_the_link_after_the_push() {
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    let a = mac(&root, "a", &relay.url);
    let mut vault = a.create();
    vault.add(item("Alpha", "SYNTH-alpha")).expect("add");
    let identity = vault.sync_identity().expect("identity");

    // A wrong team code changes nothing on this Mac.
    let bad = format!("apassy_tcd_{}", "0".repeat(64));
    assert_eq!(
        a.sync
            .create_team(&mut vault, "Personal", &bad, "Synthetic MacBook")
            .unwrap_err(),
        SyncError::Relay(RelayRefusal::InviteInvalid)
    );
    assert!(vault.relay_device().expect("row").is_none());
    assert!(a.sync.state().expect("state").is_none());

    let report = a
        .sync
        .create_team(
            &mut vault,
            "  Personal  ",
            &relay.team_code(),
            "Synthetic MacBook",
        )
        .expect("create team");
    assert_eq!(report.team, "Personal");
    assert_eq!(report.link.url, relay.url);
    assert!(report.outcome.pushed);
    let head = &relay.heads()[0];
    let fields = HeadFields::parse(&head.text).expect("head");
    assert_eq!(fields.version, 1);
    assert_eq!(fields.vault_id, identity.vault_id);
    assert_eq!(fields.previous, "0".repeat(64));
    assert_eq!(fields.team_id, report.link.team_id);
    assert_eq!(fields.device_id, report.link.device_id);

    let row = vault.relay_device().expect("row").expect("a row");
    assert_eq!(row.team_id, report.link.team_id);
    assert_eq!(row.device_id, report.link.device_id);
    let state = a.sync.state().expect("state").expect("on");
    assert_eq!(state.transport, TransportKind::Relay);
    assert_eq!(state.format, 3);
    assert_eq!(state.last_remote_version, 1);
    assert_eq!(
        state.last_head_sha256.as_deref(),
        Some(head.hash().as_str())
    );
    assert_eq!(
        a.sync
            .create_team(&mut vault, "Personal", &relay.team_code(), "Mac")
            .unwrap_err(),
        SyncError::AlreadyEnabled
    );

    // A sync with nothing new sends no push.
    let outcome = a.sync.sync(&mut vault).expect("sync");
    assert!(!outcome.pushed);
    assert!(outcome.merge.is_none());
    assert_eq!(relay.count("PUT /v1/sync/snapshot"), 1);
}

#[test]
fn push_and_pull_between_two_macs() {
    let Pair {
        _root,
        relay,
        a,
        b,
        mut vault_a,
        mut vault_b,
        ..
    } = pair();
    assert_eq!(titles(&vault_b), ["Alpha"]);
    assert_eq!(relay.devices().len(), 2);
    let state_b = b.sync.state().expect("state").expect("on");
    assert_eq!(state_b.last_remote_version, 1);
    assert!(vault_b.relay_device().expect("row").is_some());
    let row_a = vault_a.relay_device().expect("row").expect("row");
    let row_b = vault_b.relay_device().expect("row").expect("row");
    assert_ne!(row_a.device_id, row_b.device_id);
    assert_ne!(row_a.public_key, row_b.public_key);

    vault_b.add(item("Beta", "SYNTH-beta")).expect("add");
    assert!(b.sync.local_changed(&vault_b).expect("changed"));
    let outcome = b.sync.sync(&mut vault_b).expect("push");
    assert!(outcome.pushed);
    assert_eq!(relay.version(), 2);
    let pulled = a.sync.sync(&mut vault_a).expect("pull");
    assert!(!pulled.pushed);
    assert_eq!(pulled.merge.expect("merge").inserted, 1);
    assert_eq!(titles(&vault_a), ["Alpha", "Beta"]);
    assert_eq!(a.sync.state().unwrap().unwrap().last_remote_version, 2);

    // The pushed copy never carries the device key of a Mac.
    let snapshot_heads = relay.heads();
    assert_eq!(snapshot_heads.len(), 2);
    assert_eq!(
        HeadFields::parse(&snapshot_heads[1].text).unwrap().previous,
        snapshot_heads[0].hash(),
        "the chain links"
    );
}

#[test]
fn a_wrong_passphrase_at_adoption_makes_no_file_and_the_download_stays() {
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    let a = mac(&root, "a", &relay.url);
    let b = mac(&root, "b", &relay.url);
    let mut vault_a = a.create();
    vault_a.add(item("Alpha", "SYNTH-alpha")).expect("add");
    a.sync
        .create_team(&mut vault_a, "Personal", &relay.team_code(), "Mac")
        .expect("team");
    let joined = join(&relay, &a, &vault_a);
    let download = joined.download(&b.data.join("sync")).expect("download");
    assert_eq!(download.version(), 1);
    assert_eq!(
        b.sync.adopt(&joined, &download, WRONG).unwrap_err(),
        SyncError::Vault(VaultErrorKind::WrongKeyOrCorrupt)
    );
    assert!(!b.vault_path.exists());
    assert!(b.sync.state().expect("state").is_none());
    let (vault_b, report) = b.sync.adopt(&joined, &download, PASS).expect("again");
    assert!(vault_b.is_locked());
    assert_eq!(
        report.link.team_id,
        vault_a.relay_device().unwrap().unwrap().team_id
    );
    assert_eq!(report.link.device_id, joined.device_id());
}

#[test]
fn a_412_merges_and_pushes_again_and_nothing_is_lost() {
    let Pair {
        _root,
        relay,
        a,
        b,
        vault_a,
        mut vault_b,
        ..
    } = pair();
    let vault_a = Arc::new(Mutex::new(vault_a));
    vault_a
        .lock()
        .unwrap()
        .add(item("From A", "SYNTH-a"))
        .expect("add");
    vault_b.add(item("From B", "SYNTH-b")).expect("add");

    // Mac A pushes while the push of Mac B is on its way: both push at version 1.
    let other = a.sync.clone();
    let other_vault = Arc::clone(&vault_a);
    relay.on_next_put(move || {
        let outcome = other
            .sync(&mut other_vault.lock().unwrap())
            .expect("Mac A pushes first");
        assert!(outcome.pushed);
    });
    let outcome = b.sync.sync(&mut vault_b).expect("merge and push again");
    assert!(outcome.pushed);
    assert_eq!(outcome.merge.expect("merge of A").inserted, 1);
    assert_eq!(
        relay.count("PUT /v1/sync/snapshot"),
        1 + 3,
        "A, B refused, B again"
    );
    assert_eq!(relay.version(), 3);
    assert_eq!(titles(&vault_b), ["Alpha", "From A", "From B"]);

    let mut vault_a = vault_a.lock().unwrap();
    a.sync.sync(&mut vault_a).expect("pull");
    assert_eq!(titles(&vault_a), ["Alpha", "From A", "From B"]);
    assert_eq!(
        vault_a
            .reveal(
                vault_a
                    .search("From B")
                    .unwrap()
                    .first()
                    .expect("From B")
                    .id,
                "token"
            )
            .unwrap()
            .expose(),
        "SYNTH-b"
    );
}

#[test]
fn three_lost_rounds_leave_the_change_for_the_next_sync() {
    let Pair {
        _root,
        relay,
        a,
        b,
        vault_a,
        mut vault_b,
        ..
    } = pair();
    let vault_a = Arc::new(Mutex::new(vault_a));
    vault_b.add(item("From B", "SYNTH-b")).expect("add");
    // Before each push of B, A pushes a change and arms the next hook: B loses three
    // rounds in a row.
    fn arm(relay: Arc<FakeRelay>, sync: RelaySync, vault: Arc<Mutex<Vault>>, left: u32) {
        let next_relay = Arc::clone(&relay);
        relay.on_next_put(move || {
            {
                let mut open = vault.lock().unwrap();
                open.add(item(&format!("A {left}"), "SYNTH-a"))
                    .expect("add");
                sync.sync(&mut open).expect("A pushes");
            }
            if left > 1 {
                arm(next_relay, sync, vault, left - 1);
            }
        });
    }
    let relay = Arc::new(relay);
    arm(Arc::clone(&relay), a.sync.clone(), Arc::clone(&vault_a), 3);
    assert_eq!(b.sync.sync(&mut vault_b).unwrap_err(), SyncError::RelayBusy);
    assert!(
        b.sync.local_changed(&vault_b).expect("changed"),
        "the change stays"
    );
    let outcome = b.sync.sync(&mut vault_b).expect("next sync");
    assert!(outcome.pushed);
    let mut vault_a = vault_a.lock().unwrap();
    a.sync.sync(&mut vault_a).expect("pull");
    assert_eq!(
        titles(&vault_a),
        ["A 1", "A 2", "A 3", "Alpha", "From B"],
        "nothing is lost"
    );
}

/// The forged head of version `version` after `previous`, signed with `key`.
fn forged(
    key: &DeviceKey,
    template: &HeadFields,
    version: u64,
    previous: &str,
    bytes: &[u8],
) -> (StoredHead, Vec<u8>) {
    let fields = HeadFields {
        version,
        previous: previous.to_owned(),
        snapshot_sha256: sha256_hex(bytes),
        size: bytes.len() as u64,
        ..template.clone()
    };
    let signed = SignedHead::sign(fields, key).expect("sign");
    (
        StoredHead {
            version,
            text: signed.text,
            signature: signed.signature,
            device_id: template.device_id,
        },
        bytes.to_vec(),
    )
}

fn key_of(vault: &Vault) -> DeviceKey {
    DeviceKey::from_pkcs8(vault.relay_device().unwrap().unwrap().key_pkcs8).expect("key")
}

#[test]
fn a_stale_copy_is_refused() {
    let Pair {
        _root,
        relay,
        b,
        mut vault_b,
        ..
    } = pair();
    vault_b.add(item("Beta", "SYNTH-beta")).expect("add");
    b.sync.sync(&mut vault_b).expect("push version 2");
    // The relay comes back from an older backup.
    relay.roll_back_to(1);
    let downloads = relay.count("GET /v1/sync/snapshot");
    assert_eq!(b.sync.sync(&mut vault_b).unwrap_err(), SyncError::StaleCopy);
    assert_eq!(
        relay.count("GET /v1/sync/snapshot"),
        downloads,
        "no download, no merge"
    );
    assert_eq!(titles(&vault_b), ["Alpha", "Beta"]);
}

#[test]
fn the_same_version_with_another_head_is_refused() {
    let Pair {
        _root,
        relay,
        b,
        mut vault_b,
        ..
    } = pair();
    vault_b.add(item("Beta", "SYNTH-beta")).expect("add");
    b.sync.sync(&mut vault_b).expect("push version 2");
    let template = HeadFields::parse(&relay.heads()[1].text).unwrap();
    let first = relay.heads()[0].hash();
    relay.replace_from(vec![forged(
        &key_of(&vault_b),
        &template,
        2,
        &first,
        b"forged",
    )]);
    assert_eq!(b.sync.sync(&mut vault_b).unwrap_err(), SyncError::StaleCopy);
}

#[test]
fn a_forked_chain_is_refused() {
    let Pair {
        _root,
        relay,
        a,
        b,
        mut vault_a,
        mut vault_b,
        ..
    } = pair();
    vault_b.add(item("Beta", "SYNTH-beta")).expect("add");
    b.sync.sync(&mut vault_b).expect("push version 2");
    a.sync.sync(&mut vault_a).expect("A sees version 2");
    // The relay serves A a version 3 on a fork of version 2 that A never saw. Even
    // signed by a real device of the team, it does not include A's anchor.
    let template = HeadFields::parse(&relay.heads()[1].text).unwrap();
    let first = relay.heads()[0].hash();
    let key = key_of(&vault_b);
    let two = forged(&key, &template, 2, &first, b"forged two");
    let three = forged(&key, &template, 3, &two.0.hash(), b"forged three");
    relay.replace_from(vec![two, three]);
    let downloads = relay.count("GET /v1/sync/snapshot");
    assert_eq!(
        a.sync.sync(&mut vault_a).unwrap_err(),
        SyncError::ForkedCopy
    );
    assert_eq!(
        relay.count("GET /v1/sync/snapshot"),
        downloads,
        "no download, no merge"
    );
    assert_eq!(titles(&vault_a), ["Alpha", "Beta"]);

    // A head signed by a key that is not a device of the team is damaged.
    let stranger = DeviceKey::generate().expect("key");
    let three = forged(
        &stranger,
        &template,
        3,
        &relay.heads()[1].hash(),
        b"stranger",
    );
    relay.replace_from(vec![three]);
    assert_eq!(b.sync.sync(&mut vault_b).unwrap_err(), SyncError::Damaged);
}

#[test]
fn oversized_snapshots_are_refused() {
    // The app refuses to push a copy over its limit: no PUT.
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    let small = mac(&root, "small", &relay.url);
    let sync = small.sync.clone().with_snapshot_limit(1024);
    let mut vault = small.create();
    assert_eq!(
        sync.create_team(&mut vault, "Personal", &relay.team_code(), "Mac")
            .unwrap_err(),
        SyncError::TooLarge
    );
    assert_eq!(relay.count("PUT /v1/sync/snapshot"), 0);
    assert!(vault.relay_device().expect("row").is_none());
    assert!(sync.state().expect("state").is_none());

    // The relay refuses a copy over its `sync_bytes` with 413.
    let Pair {
        _root,
        relay,
        b,
        mut vault_b,
        a,
        ..
    } = pair();
    relay.set_max_bytes(1024);
    vault_b.add(item("Beta", "SYNTH-beta")).expect("add");
    assert_eq!(b.sync.sync(&mut vault_b).unwrap_err(), SyncError::TooLarge);
    assert_eq!(relay.version(), 1);

    // A head larger than the limit of this Mac is refused before the download.
    relay.set_max_bytes(fake_relay::SYNC_BYTES);
    b.sync.sync(&mut vault_b).expect("push");
    let mut vault_a = Vault::open(&a.vault_path).expect("open");
    vault_a.unlock(PASS).expect("unlock");
    let limited = a.sync.clone().with_snapshot_limit(1024);
    let downloads = relay.count("GET /v1/sync/snapshot");
    assert_eq!(limited.sync(&mut vault_a).unwrap_err(), SyncError::TooLarge);
    assert_eq!(relay.count("GET /v1/sync/snapshot"), downloads);
}

#[test]
fn loopback_http_is_allowed_and_plain_http_elsewhere_is_refused() {
    let root = TempDir::new().expect("temp dir");
    for (index, url) in [
        "http://relay.example.test:8080",
        "http://10.0.0.1:8787",
        "http://127.0.0.1",
        "https://relay.example.test/v1",
    ]
    .into_iter()
    .enumerate()
    {
        let remote = mac(&root, &format!("m{index}"), url);
        let mut vault = remote.create();
        let code = format!("apassy_tcd_{}", "0".repeat(64));
        assert_eq!(
            remote
                .sync
                .create_team(&mut vault, "Personal", &code, "Mac")
                .unwrap_err(),
            SyncError::InvalidRelayAddress,
            "{url}"
        );
    }
    // The pair of every other test runs on http://127.0.0.1:<port>.
    let relay = FakeRelay::start();
    assert!(relay.url.starts_with("http://127.0.0.1:"));
    // A relay that calls itself by another address is refused at sign-in.
    let lying = mac(&root, "lying", &relay.url);
    let mut vault = lying.create();
    relay.set_origin("https://elsewhere.example.test");
    assert_eq!(
        lying
            .sync
            .create_team(&mut vault, "Personal", &relay.team_code(), "Mac")
            .unwrap_err(),
        SyncError::OriginMismatch
    );
}

#[test]
fn a_removed_mac_is_told_and_keeps_its_vault() {
    let Pair {
        _root,
        relay,
        a,
        b,
        vault_a,
        mut vault_b,
        ..
    } = pair();
    let devices = a.sync.devices(&vault_a).expect("devices");
    assert_eq!(devices.len(), 2);
    let other = devices.iter().find(|device| !device.current).expect("B");
    assert_eq!(other.name, "Synthetic Mac mini");
    a.sync.remove_device(&vault_a, other.id).expect("remove");
    assert_eq!(relay.devices().len(), 1);
    vault_b.add(item("Beta", "SYNTH-beta")).expect("add");
    assert_eq!(
        b.sync.sync(&mut vault_b).unwrap_err(),
        SyncError::RemovedFromRelay
    );
    assert_eq!(titles(&vault_b), ["Alpha", "Beta"]);
    // Turning relay sync off removes the row and the state; the relay keeps the copy.
    assert!(b.sync.disable(Some(&mut vault_b)).expect("off"));
    assert!(vault_b.relay_device().expect("row").is_none());
    assert!(b.sync.state().expect("state").is_none());
    assert_eq!(relay.version(), 1);
}

/// A removed Mac signs in once, learns that it was removed, and then asks the relay no
/// more before its next try, 15 minutes later: not at the next sync, not at a long
/// poll, not after a lock. Another vault goes on, and turning relay sync off ends the
/// state.
#[test]
fn a_removed_mac_signs_in_no_more_until_it_turns_sync_off() {
    let Pair {
        _root,
        relay,
        a,
        b,
        mut vault_a,
        mut vault_b,
        ..
    } = pair();
    let b_id = vault_b.relay_device().unwrap().unwrap().device_id;
    a.sync.remove_device(&vault_a, b_id).expect("remove B");
    assert!(!b.sync.is_removed());
    let challenges = relay.count("POST /v1/auth/challenge");
    assert_eq!(
        b.sync.sync(&mut vault_b).unwrap_err(),
        SyncError::RemovedFromRelay
    );
    assert!(b.sync.is_removed());
    assert_eq!(
        relay.count("POST /v1/auth/challenge"),
        challenges + 1,
        "one sign-in learns it"
    );
    let asked = relay.log().len();
    assert_eq!(
        b.sync.sync(&mut vault_b).unwrap_err(),
        SyncError::RemovedFromRelay
    );
    assert_eq!(
        b.sync.poll(Duration::from_secs(1)).unwrap_err(),
        SyncError::RemovedFromRelay
    );
    assert_eq!(
        b.sync.devices(&vault_b).unwrap_err(),
        SyncError::RemovedFromRelay
    );
    // A lock drops the key; the next unlock does not sign in again.
    b.sync.forget();
    assert!(b.sync.is_removed());
    assert_eq!(
        b.sync.sync(&mut vault_b).unwrap_err(),
        SyncError::RemovedFromRelay
    );
    assert_eq!(relay.log().len(), asked, "{:?}", relay.log());
    // Mac A and its vault go on.
    vault_a.add(item("Gamma", "SYNTH-gamma")).expect("add");
    assert!(a.sync.sync(&mut vault_a).expect("A syncs").pushed);
    // Turning relay sync off ends it.
    assert!(b.sync.disable(Some(&mut vault_b)).expect("off"));
    assert!(!b.sync.is_removed());
}

/// "Join from another Mac" for a vault whose relay copy has another passphrase: the
/// join asks for it, and a wrong one changes nothing. The relay copy is the copy of the
/// team, so the joining Mac takes its passphrase, also when the joining Mac is the stale
/// one (Mac A changed a leaked passphrase while B had relay sync off). Mac A then syncs
/// on, with no passphrase step.
#[test]
fn a_join_under_another_passphrase_takes_the_passphrase_of_the_copy() {
    const NEW: &str = "synthetic-relay-new-pass";
    let Pair {
        _root,
        relay,
        a,
        b,
        mut vault_a,
        mut vault_b,
    } = pair();
    assert!(b.sync.disable(Some(&mut vault_b)).expect("off"));
    vault_b.add(item("Only on B", "SYNTH-only-b")).expect("add");
    // Mac A changes the passphrase, and its next push is under the new one.
    vault_a.change_passphrase(PASS, NEW).expect("change");
    vault_a.add(item("Only on A", "SYNTH-only-a")).expect("add");
    assert!(a.sync.sync(&mut vault_a).expect("A pushes").pushed);
    assert_eq!(relay.version(), 2);

    let joined = join(&relay, &a, &vault_a);
    assert_eq!(
        b.sync.enable_joined(&mut vault_b, &joined).unwrap_err(),
        SyncError::NeedsPassphrase
    );
    assert!(
        b.sync.state().expect("state").is_none(),
        "nothing turned on"
    );
    assert_eq!(
        b.sync
            .enable_joined_with_passphrase(&mut vault_b, &joined, WRONG)
            .unwrap_err(),
        SyncError::Vault(VaultErrorKind::WrongKeyOrCorrupt)
    );
    assert!(
        b.sync.state().expect("state").is_none(),
        "nothing turned on"
    );
    assert!(vault_b.relay_device().expect("row").is_none());
    Vault::verify_passphrase_at(&b.vault_path, PASS).expect("B keeps its passphrase");
    assert_eq!(relay.version(), 2);

    let report = b
        .sync
        .enable_joined_with_passphrase(&mut vault_b, &joined, NEW)
        .expect("the passphrase of the copy");
    assert!(report.outcome.pushed);
    assert!(report.outcome.merge.is_some());
    assert_eq!(relay.version(), 3);
    assert_eq!(titles(&vault_b), ["Alpha", "Only on A", "Only on B"]);
    assert!(b.sync.state().expect("state").is_some());
    assert!(vault_b.relay_device().expect("row").is_some());
    vault_b.lock().expect("lock");
    assert_eq!(
        vault_b.unlock(PASS).unwrap_err().kind(),
        VaultErrorKind::WrongKeyOrCorrupt,
        "the old passphrase does not come back"
    );
    vault_b
        .unlock(NEW)
        .expect("B takes the passphrase of the copy");

    // Mac A goes on with its passphrase: no passphrase step.
    a.sync.sync(&mut vault_a).expect("A syncs");
    assert_eq!(titles(&vault_a), ["Alpha", "Only on A", "Only on B"]);
    vault_a.lock().expect("lock");
    vault_a.unlock(NEW).expect("A keeps the new passphrase");
}

/// A relay that is suspended or stops answers a challenge with `401`, as for a removed
/// device. The Mac shows "Removed from the relay" and signs in no more for a while, then
/// asks once more, and syncs again when the relay knows it.
#[test]
fn a_refused_challenge_is_asked_again_later_and_sync_comes_back() {
    let Pair {
        _root,
        relay,
        b,
        mut vault_b,
        ..
    } = pair();
    let sync = RelaySync::new(RelayConfig::in_data_dir(
        &b.data,
        &b.vault_path,
        &relay.url,
        "vault",
    ))
    .with_removed_probe(Duration::from_millis(400));
    relay.fail_next("POST /v1/auth/challenge", 1, 401);
    assert_eq!(
        sync.sync(&mut vault_b).unwrap_err(),
        SyncError::RemovedFromRelay
    );
    assert!(sync.is_removed());
    let challenges = relay.count("POST /v1/auth/challenge");
    assert_eq!(
        sync.sync(&mut vault_b).unwrap_err(),
        SyncError::RemovedFromRelay
    );
    assert_eq!(
        relay.count("POST /v1/auth/challenge"),
        challenges,
        "no sign-in before its time"
    );
    let until = sync.removed_until().expect("the next try");
    while Instant::now() < until {
        std::thread::sleep(Duration::from_millis(20));
    }
    vault_b.add(item("Beta", "SYNTH-beta")).expect("add");
    assert!(sync.sync(&mut vault_b).expect("the relay knows B").pushed);
    assert!(!sync.is_removed());
    assert_eq!(relay.count("POST /v1/auth/challenge"), challenges + 1);
}

/// "Turn off" asks the relay to remove the device also when the relay refused it a
/// moment ago: the refusal can be a suspended relay, and the device must not stay live
/// on the relay when its key leaves the vault.
#[test]
fn turn_off_asks_the_relay_after_a_refusal() {
    let Pair {
        _root,
        relay,
        b,
        mut vault_b,
        ..
    } = pair();
    let b_id = vault_b.relay_device().unwrap().unwrap().device_id;
    b.sync.forget();
    relay.fail_next("POST /v1/auth/challenge", 1, 401);
    assert_eq!(
        b.sync.sync(&mut vault_b).unwrap_err(),
        SyncError::RemovedFromRelay
    );
    assert!(b.sync.is_removed());
    b.sync
        .remove_device(&vault_b, b_id)
        .expect("the relay hears it");
    assert!(!relay.devices().contains(&b_id));
}

/// A `401` to the token call is a sign-in that failed (contract section 5), not a
/// removal: the next sync signs in again.
#[test]
fn a_refused_token_is_no_removal() {
    let Pair {
        _root,
        relay,
        b,
        mut vault_b,
        ..
    } = pair();
    b.sync.forget();
    relay.fail_next("POST /v1/auth/token", 1, 401);
    let error = b.sync.sync(&mut vault_b).unwrap_err();
    assert_ne!(error, SyncError::RemovedFromRelay);
    assert!(!b.sync.is_removed());
    b.sync.sync(&mut vault_b).expect("the next sync signs in");
}

#[test]
fn a_refused_link_ends_the_join() {
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    let a = mac(&root, "a", &relay.url);
    let mut vault_a = a.create();
    a.sync
        .create_team(&mut vault_a, "Personal", &relay.team_code(), "Mac")
        .expect("team");
    let code = a.sync.create_link(&vault_a).expect("link");
    let bare = code.code.as_str().to_owned();
    let pending = PendingJoin::request(&bare, &relay.url, "Other").expect("bare code");
    // A link without the code on this Mac can only be refused.
    let unknown = a.sync.pending_links(&vault_a, None).expect("links");
    assert_eq!(unknown[0].safety, None);
    a.sync.refuse_link(&vault_a, unknown[0].id).expect("refuse");
    assert_eq!(
        pending.poll().unwrap_err(),
        SyncError::Relay(RelayRefusal::JoinRefused)
    );
    // A used code does not work again.
    assert_eq!(
        PendingJoin::request(&bare, &relay.url, "Third").unwrap_err(),
        SyncError::Relay(RelayRefusal::Forbidden)
    );
}

#[test]
fn the_long_poll_hears_a_push_of_another_mac() {
    let Pair {
        _root,
        relay: _relay,
        a,
        b,
        mut vault_a,
        mut vault_b,
    } = pair();
    // The key is in memory after a sync of the unlocked vault.
    b.sync.sync(&mut vault_b).expect("sync");
    assert!(b.sync.has_session());
    let start = Instant::now();
    assert!(
        !b.sync
            .wait_for_change(Duration::from_secs(1))
            .expect("no change")
    );
    assert!(start.elapsed() >= Duration::from_millis(900));

    vault_a.add(item("Gamma", "SYNTH-gamma")).expect("add");
    let waiter = {
        let sync = b.sync.clone();
        std::thread::spawn(move || {
            let start = Instant::now();
            (
                sync.wait_for_change(Duration::from_secs(20)),
                start.elapsed(),
            )
        })
    };
    std::thread::sleep(Duration::from_millis(300));
    a.sync.sync(&mut vault_a).expect("push");
    let (changed, waited) = waiter.join().expect("waiter");
    assert!(changed.expect("poll"));
    assert!(waited < Duration::from_secs(5), "{waited:?}");
    b.sync.sync(&mut vault_b).expect("pull");
    assert!(titles(&vault_b).contains(&"Gamma".to_owned()));

    // A lock drops the key: the waiter has nothing to wait with.
    b.sync.forget();
    assert_eq!(
        b.sync.wait_for_change(Duration::from_secs(1)).unwrap_err(),
        SyncError::Vault(VaultErrorKind::Locked)
    );
    // The transport says the same through the trait.
    let transport = b.sync.relay_transport(&vault_b).expect("transport");
    let seen = b.sync.state().unwrap().unwrap().last_remote_version;
    assert!(
        !transport
            .wait_for_change(seen, Duration::ZERO)
            .expect("poll")
    );
    assert!(
        transport
            .wait_for_change(seen - 1, Duration::ZERO)
            .expect("poll")
    );
}

/// Contract section 15, on the side of this suite: the vector heads hash and verify with
/// `ring` directly, the sign-in message verifies, and the safety words match.
#[test]
fn the_contract_vectors_verify_with_ring() {
    let public = decode_b64u(
        "BOpHkB5VvTHXawpUXZxgu44Q97I2bzq9G_uI6tFM9mj8De047e1fNWI8MIERDsaxhBC0ih1DPfXaM4mdBbExjrA",
    )
    .expect("key");
    let head_1 = "apassy-relay-sync-head-v1\n0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77 1 5b77343bd881a4f425bde1ec9979946ec1add11de02010d4c63159977bac4de8 18\n0000000000000000000000000000000000000000000000000000000000000000 t_7k2m5q4x3c/2 1790000000";
    assert_eq!(
        head_hash(head_1),
        "d562a4c9951ac36b211ed9786a6897f16870639c54df9d168c56c39d4ce387d9"
    );
    let head_2 = "apassy-relay-sync-head-v1\n0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77 2 7dd91ab21b30df12a943c507d6e7d808f6ea2608faa3239aa7fed621ecae241a 20\nd562a4c9951ac36b211ed9786a6897f16870639c54df9d168c56c39d4ce387d9 t_7k2m5q4x3c/2 1790000060";
    assert_eq!(
        head_hash(head_2),
        "2a3d34a3454acf98a897115ed30e8ea195852d7e943c780974c1f2489810cc3c"
    );
    let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public);
    for (text, signature) in [
        (
            head_1,
            "MEUCIHD6Ih2lhM6u-hBJFTF2urGCw1UeM8vL3oM2mIDm0MvgAiEAxXcwrQRcPb0WAAgj4tylCij4Qxlbu7jISfCuxGIJDHA",
        ),
        (
            head_2,
            "MEUCIQDpxvOaoLg8rz7vXW0U0xd6lGyttG8CeaRV76DrHTChYgIgIpwTtg1Z-BqkmTw1uDnO8FHS_YddNgbMPCWJP8KKa-g",
        ),
    ] {
        let signature = decode_b64u(signature).expect("signature");
        assert!(key.verify(text.as_bytes(), &signature).is_ok());
        assert!(
            HeadFields::parse(text).is_some(),
            "the app parses the vector"
        );
        assert!(
            key.verify(text.replacen(" 1790", " 1791", 1).as_bytes(), &signature)
                .is_err()
        );
    }
    let message = sign_in_message(
        "https://relay.example.test",
        "t_7k2m5q4x3c",
        "BOpHkB5VvTHXawpUXZxgu44Q97I2bzq9G_uI6tFM9mj8De047e1fNWI8MIERDsaxhBC0ih1DPfXaM4mdBbExjrA",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    );
    assert_eq!(
        sha256_hex(&message),
        "43722057f746ba2b1759952943e9532ad49c68496c11a6f1bef65709c20e7aaa"
    );
    let signature = decode_b64u(
        "MEUCIAyr22ugUYumzN6x8ktWI1ruvFmEVjktZGhAfa7dRmeXAiEAiHEWtFJmR5giJlad5O0jy9dVkHD3IAKRM3TZRXzwJEY",
    )
    .expect("signature");
    assert!(key.verify(&message, &signature).is_ok());
    assert_eq!(
        safety_words(
            "t_7k2m5q4x3c",
            &format!("apassy_lnk_t_7k2m5q4x3c_{}", "ab".repeat(32)),
            &public
        ),
        "tulip arrow"
    );
}

/// A third Mac that joins the pair with a link and adopts the vault, unlocked.
fn third_mac(relay: &FakeRelay, root: &TempDir, a: &Mac, vault_a: &Vault) -> (Mac, Vault) {
    let c = mac(root, "c", &relay.url);
    let joined = join(relay, a, vault_a);
    let download = joined.download(&c.data.join("sync")).expect("download");
    let (mut vault_c, _) = c.sync.adopt(&joined, &download, PASS).expect("adopt");
    vault_c.unlock(PASS).expect("unlock");
    (c, vault_c)
}

/// ADR 0022, contract section 13 check 3: removing the Mac that signed the current head
/// (or a head inside the chain) does not stop the others. Its heads still verify for
/// the versions it pushed while it was a member; it cannot push again.
#[test]
fn removing_the_mac_that_signed_the_head_keeps_sync_working() {
    let Pair {
        _root,
        relay,
        a,
        b,
        mut vault_a,
        mut vault_b,
    } = pair();
    let (c, mut vault_c) = third_mac(&relay, &_root, &a, &vault_a);
    vault_b.add(item("Beta", "SYNTH-beta")).expect("add");
    b.sync.sync(&mut vault_b).expect("B pushes version 2");
    // A sees version 2 now; C stays at version 1.
    a.sync.sync(&mut vault_a).expect("A pulls version 2");
    let b_id = vault_b.relay_device().unwrap().unwrap().device_id;
    // The owner removes B ("Devices…" > Remove, or B turns relay sync off).
    a.sync.remove_device(&vault_a, b_id).expect("remove B");
    assert!(!relay.devices().contains(&b_id));

    // A's next change goes on top of the head that B signed.
    vault_a.add(item("Gamma", "SYNTH-gamma")).expect("add");
    let outcome = a.sync.sync(&mut vault_a).expect("A pushes over B's head");
    assert!(outcome.pushed);
    assert_eq!(relay.version(), 3);

    // C, after a lock, reads the chain [v2 by B, v3 by A] from its anchor at version 1.
    c.sync.forget();
    let outcome = c.sync.sync(&mut vault_c).expect("C pulls through B's head");
    assert!(outcome.merge.is_some());
    assert_eq!(titles(&vault_c), ["Alpha", "Beta", "Gamma"]);

    // A removed Mac cannot push.
    vault_b.add(item("Delta", "SYNTH-delta")).expect("add");
    assert_eq!(
        b.sync.sync(&mut vault_b).unwrap_err(),
        SyncError::RemovedFromRelay
    );
    assert_eq!(relay.version(), 3);
}

/// The head of `version` after `previous`, signed by `key` as device `device_id`, for
/// `bytes`.
fn head_of(
    key: &DeviceKey,
    template: &HeadFields,
    device_id: u64,
    version: u64,
    previous: &str,
    bytes: &[u8],
) -> (StoredHead, Vec<u8>) {
    let fields = HeadFields {
        device_id,
        ..template.clone()
    };
    let (mut head, bytes) = forged(key, &fields, version, previous, bytes);
    head.device_id = device_id;
    (head, bytes)
}

/// Contract section 9: the relay answers the oldest 1000 heads after `since`. A Mac
/// more than 1000 versions behind reads the chain in pages and catches up, with no
/// false fork.
#[test]
fn a_mac_far_behind_reads_the_chain_in_pages() {
    let Pair {
        _root,
        relay,
        a,
        mut vault_a,
        mut vault_b,
        ..
    } = pair();
    // B's real copy with a new item is the newest version; 1100 heads of B lead to it.
    vault_b.add(item("Far", "SYNTH-far")).expect("add");
    let copy_path = _root.path().join("b-copy");
    vault_b
        .write_sync_copy(&copy_path, "Synthetic Mac mini")
        .expect("copy");
    let newest = fs::read(&copy_path).expect("copy bytes");
    let row = vault_b.relay_device().unwrap().unwrap();
    let key = key_of(&vault_b);
    let template = HeadFields::parse(&relay.heads()[0].text).unwrap();
    let mut previous = relay.heads()[0].hash();
    let mut heads = Vec::new();
    for version in 2..=1101u64 {
        let bytes = if version == 1101 {
            newest.clone()
        } else {
            format!("filler {version}").into_bytes()
        };
        let head = head_of(&key, &template, row.device_id, version, &previous, &bytes);
        previous = head.0.hash();
        heads.push(head);
    }
    relay.replace_from(heads);
    let pages = relay.count("GET /v1/sync/head");
    let outcome = a.sync.sync(&mut vault_a).expect("A catches up");
    assert!(outcome.merge.is_some());
    assert!(titles(&vault_a).contains(&"Far".to_owned()));
    assert_eq!(a.sync.state().unwrap().unwrap().last_remote_version, 1101);
    assert!(
        relay.count("GET /v1/sync/head") >= pages + 2,
        "two pages: versions 2 to 1001, then 1002 to 1101"
    );
}

/// "Received by <Mac>": a Mac that merged a pulled version tells the relay.
#[test]
fn a_merged_version_is_acknowledged() {
    let Pair {
        _root,
        relay,
        a,
        b,
        mut vault_a,
        mut vault_b,
    } = pair();
    let b_id = vault_b.relay_device().unwrap().unwrap().device_id;
    assert_eq!(
        relay.receipts().get(&b_id),
        Some(&1),
        "the adoption of version 1"
    );
    vault_b.add(item("Beta", "SYNTH-beta")).expect("add");
    b.sync.sync(&mut vault_b).expect("push version 2");
    a.sync.sync(&mut vault_a).expect("pull version 2");
    let a_id = vault_a.relay_device().unwrap().unwrap().device_id;
    assert_eq!(relay.receipts().get(&a_id), Some(&2));
    let receipts = a.sync.receipts(&vault_a).expect("receipts");
    assert!(
        receipts
            .iter()
            .any(|receipt| receipt.device_id == a_id && receipt.version == 2)
    );
}

/// Contract sections 5 and 11: a lock ends a long poll in flight at once, and the
/// dropped session signs in no more.
#[test]
fn a_lock_ends_the_long_poll_at_once() {
    let Pair {
        _root,
        relay: _relay,
        b,
        mut vault_b,
        ..
    } = pair();
    b.sync.sync(&mut vault_b).expect("sync");
    let waiter = {
        let sync = b.sync.clone();
        std::thread::spawn(move || {
            let start = Instant::now();
            (sync.poll(Duration::from_secs(20)), start.elapsed())
        })
    };
    std::thread::sleep(Duration::from_millis(400));
    b.sync.forget();
    let (polled, waited) = waiter.join().expect("waiter");
    assert_eq!(
        polled.unwrap_err(),
        SyncError::Vault(VaultErrorKind::Locked)
    );
    assert!(waited < Duration::from_secs(3), "{waited:?}");
}

/// Contract section 3: a `429` waits `Retry-After`. Until then no call reaches the
/// relay.
#[test]
fn a_429_waits_retry_after() {
    let Pair {
        _root,
        relay,
        b,
        mut vault_b,
        ..
    } = pair();
    relay.fail_next("GET /v1/sync/head", 1, 429);
    // The pair's B has no session in memory any more after a lock.
    b.sync.forget();
    assert_eq!(
        b.sync.sync(&mut vault_b).unwrap_err(),
        SyncError::Relay(RelayRefusal::RateLimited)
    );
    let calls = relay.log().len();
    assert_eq!(
        b.sync.sync(&mut vault_b).unwrap_err(),
        SyncError::Relay(RelayRefusal::RateLimited)
    );
    assert_eq!(relay.log().len(), calls, "no request before Retry-After");
    std::thread::sleep(Duration::from_millis(2100));
    b.sync.sync(&mut vault_b).expect("after Retry-After");
}

/// Contract section 7.2 step 4: a failure that passes by itself (no network, a busy
/// relay) keeps the join waiting, with a growing wait; a refusal ends it.
#[test]
fn a_transient_error_keeps_a_join_waiting() {
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    let a = mac(&root, "a", &relay.url);
    let mut vault_a = a.create();
    a.sync
        .create_team(&mut vault_a, "Personal", &relay.team_code(), "Mac")
        .expect("team");
    let code = a.sync.create_link(&vault_a).expect("link");
    let pending = PendingJoin::request(&code.link, "", "Synthetic Mac mini").expect("request");
    relay.fail_next("POST /v1/auth/challenge", 1, 502);
    assert!(pending.poll().expect("a network error waits").is_none());
    let links = a.sync.pending_links(&vault_a, Some(&code)).expect("links");
    a.sync.confirm_link(&vault_a, &links[0]).expect("confirm");
    // The next poll waits 2 seconds before it asks the relay again.
    let challenges = relay.count("POST /v1/auth/challenge");
    assert!(pending.poll().expect("backing off").is_none());
    assert_eq!(relay.count("POST /v1/auth/challenge"), challenges);
    std::thread::sleep(Duration::from_millis(2100));
    assert!(pending.poll().expect("poll").is_some(), "confirmed");
}

/// Contract section 7.2 step 7: the new Mac cancels before the confirmation; the first
/// Mac no longer shows it. After a confirmation, a cancel removes the new device.
#[test]
fn a_pending_join_can_be_cancelled() {
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    let a = mac(&root, "a", &relay.url);
    let mut vault_a = a.create();
    a.sync
        .create_team(&mut vault_a, "Personal", &relay.team_code(), "Mac")
        .expect("team");
    let code = a.sync.create_link(&vault_a).expect("link");
    let pending = PendingJoin::request(&code.link, "", "Synthetic Mac mini").expect("request");
    assert_eq!(relay.pending_links(), 1);
    pending.cancel().expect("cancel");
    assert_eq!(relay.pending_links(), 0);
    assert!(
        a.sync
            .pending_links(&vault_a, Some(&code))
            .expect("links")
            .is_empty()
    );

    // The other Mac confirmed first: the cancel removes the new device.
    let code = a.sync.create_link(&vault_a).expect("link");
    let pending = PendingJoin::request(&code.link, "", "Synthetic iMac").expect("request");
    let links = a.sync.pending_links(&vault_a, Some(&code)).expect("links");
    a.sync.confirm_link(&vault_a, &links[0]).expect("confirm");
    assert_eq!(relay.devices().len(), 2);
    pending.cancel().expect("cancel after the confirmation");
    assert_eq!(relay.devices().len(), 1);
}

/// A damaged relay copy is not downloaded again for each sync, and "Replace with this
/// Mac's vault" pushes over it; the other Mac then syncs, and nothing is lost.
#[test]
fn a_damaged_relay_copy_is_replaced_with_this_macs_vault() {
    let Pair {
        _root,
        relay,
        a,
        b,
        mut vault_a,
        mut vault_b,
    } = pair();
    vault_b.add(item("Beta", "SYNTH-beta")).expect("add");
    b.sync.sync(&mut vault_b).expect("push version 2");
    relay.corrupt_snapshot(2);
    assert_eq!(a.sync.sync(&mut vault_a).unwrap_err(), SyncError::Damaged);
    let downloads = relay.count("GET /v1/sync/snapshot");
    assert_eq!(a.sync.sync(&mut vault_a).unwrap_err(), SyncError::Damaged);
    assert_eq!(
        relay.count("GET /v1/sync/snapshot"),
        downloads,
        "the same damaged copy is not downloaded again"
    );

    vault_a.add(item("From A", "SYNTH-a")).expect("add");
    let outcome = a.sync.replace_relay_copy(&mut vault_a).expect("replace");
    assert!(outcome.pushed);
    assert_eq!(relay.version(), 3);
    assert!(!a.sync.local_changed(&vault_a).expect("changed"));
    // B links version 3 to its anchor at version 2, merges it, and keeps Beta.
    b.sync.sync(&mut vault_b).expect("B syncs");
    assert_eq!(titles(&vault_b), ["Alpha", "Beta", "From A"]);
    a.sync.sync(&mut vault_a).expect("A pulls B's push");
    assert_eq!(titles(&vault_a), ["Alpha", "Beta", "From A"]);
}

/// A copy with a new passphrase from another Mac is downloaded once: the next syncs
/// say so without a new download, until the owner gives the new passphrase.
#[test]
fn a_copy_with_a_new_passphrase_is_downloaded_once() {
    let Pair {
        _root,
        relay,
        a,
        b,
        mut vault_a,
        mut vault_b,
    } = pair();
    const NEW: &str = "synthetic-relay-new-pass";
    vault_a
        .change_passphrase(PASS, NEW)
        .expect("new passphrase");
    vault_a.add(item("Beta", "SYNTH-beta")).expect("add");
    a.sync.sync(&mut vault_a).expect("push version 2");
    assert_eq!(
        b.sync.sync(&mut vault_b).unwrap_err(),
        SyncError::NeedsPassphrase
    );
    let downloads = relay.count("GET /v1/sync/snapshot");
    for _ in 0..3 {
        assert_eq!(
            b.sync.sync(&mut vault_b).unwrap_err(),
            SyncError::NeedsPassphrase
        );
    }
    assert_eq!(relay.count("GET /v1/sync/snapshot"), downloads);
    b.sync
        .take_new_passphrase(&mut vault_b, NEW)
        .expect("the owner gives it")
        .expect("and the sync after it");
    assert_eq!(titles(&vault_b), ["Alpha", "Beta"]);
    assert_eq!(
        relay.count("GET /v1/sync/snapshot"),
        downloads + 1,
        "the check and the merge use one download"
    );
}

/// A sync that fails after the new passphrase is taken says so: the vault uses the new
/// passphrase already, and the sync tries again later.
#[test]
fn a_failed_sync_after_a_new_passphrase_keeps_the_new_passphrase() {
    let Pair {
        _root,
        relay,
        a,
        b,
        mut vault_a,
        mut vault_b,
    } = pair();
    const NEW: &str = "synthetic-relay-new-pass";
    vault_a
        .change_passphrase(PASS, NEW)
        .expect("new passphrase");
    vault_a.add(item("Beta", "SYNTH-beta")).expect("add");
    a.sync.sync(&mut vault_a).expect("push version 2");
    assert_eq!(
        b.sync.sync(&mut vault_b).unwrap_err(),
        SyncError::NeedsPassphrase
    );
    relay.delay("GET /v1/sync/snapshot", Duration::from_millis(1200));
    let taken = std::thread::scope(|scope| {
        let relay = &relay;
        scope.spawn(move || {
            // During the download for the check: the next head request fails.
            std::thread::sleep(Duration::from_millis(600));
            relay.fail_next("GET /v1/sync/head", 1, 500);
        });
        b.sync.take_new_passphrase(&mut vault_b, NEW)
    });
    let synced = taken.expect("the vault takes the new passphrase");
    assert_eq!(synced.unwrap_err(), SyncError::Relay(RelayRefusal::Error));
    vault_b.lock().expect("lock");
    assert!(vault_b.unlock(PASS).is_err(), "the old passphrase is gone");
    vault_b.unlock(NEW).expect("the new passphrase opens it");
    b.sync.sync(&mut vault_b).expect("the next sync merges");
    assert_eq!(titles(&vault_b), ["Alpha", "Beta"]);
}

/// A copy that this Mac cannot read for a reason that does not pass by itself (here:
/// a newer schema from a Mac with a newer Apassy) is downloaded once, not at every
/// sync.
#[test]
fn a_copy_with_a_newer_schema_is_downloaded_once() {
    let Pair {
        _root,
        relay,
        a,
        b: _b,
        mut vault_a,
        mut vault_b,
    } = pair();
    let copy = _root.path().join("newer-copy");
    vault_b
        .write_sync_copy(&copy, "Synthetic Mac mini")
        .expect("copy");
    {
        let conn = rusqlite::Connection::open(&copy).expect("open copy");
        conn.execute_batch(&format!("PRAGMA key = '{PASS}'"))
            .expect("key");
        let schema: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("schema");
        conn.execute_batch(&format!("PRAGMA user_version = {}", schema + 1))
            .expect("newer schema");
    }
    let bytes = fs::read(&copy).expect("read copy");
    let first = relay.heads()[0].clone();
    let template = HeadFields {
        device_id: vault_b.relay_device().unwrap().unwrap().device_id,
        ..HeadFields::parse(&first.text).unwrap()
    };
    relay.replace_from(vec![forged(
        &key_of(&vault_b),
        &template,
        2,
        &first.hash(),
        &bytes,
    )]);
    let downloads = relay.count("GET /v1/sync/snapshot");
    for _ in 0..4 {
        assert_eq!(
            a.sync.sync(&mut vault_a).unwrap_err(),
            SyncError::Vault(VaultErrorKind::UnsupportedSchema)
        );
    }
    assert_eq!(relay.count("GET /v1/sync/snapshot"), downloads + 1);
}

/// A relay restored from a backup, with one Mac in the team: that Mac refuses the
/// older copy, and "Use the relay copy" goes on with the same device. Nothing is lost.
#[test]
fn a_lone_mac_uses_the_relay_copy_after_a_relay_rollback() {
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    let a = mac(&root, "a", &relay.url);
    let mut vault = a.create();
    vault.add(item("Alpha", "SYNTH-alpha")).expect("add");
    a.sync
        .create_team(&mut vault, "Personal", &relay.team_code(), "Mac")
        .expect("team");
    vault.add(item("Beta", "SYNTH-beta")).expect("add");
    a.sync.sync(&mut vault).expect("push version 2");
    relay.roll_back_to(1);
    vault.add(item("Gamma", "SYNTH-gamma")).expect("add");
    assert_eq!(a.sync.sync(&mut vault).unwrap_err(), SyncError::StaleCopy);
    assert!(
        SyncError::StaleCopy
            .to_string()
            .contains("“Use the relay copy…”"),
        "the text names the way out"
    );
    let outcome = a
        .sync
        .use_relay_copy(&mut vault)
        .expect("use the relay copy");
    assert!(outcome.pushed);
    assert_eq!(relay.version(), 2);
    assert_eq!(relay.devices().len(), 1, "the device stays");
    a.sync.sync(&mut vault).expect("syncs again");
    assert_eq!(titles(&vault), ["Alpha", "Beta", "Gamma"]);
    let other = mac(&root, "other", &relay.url);
    let joined = join(&relay, &a, &vault);
    let download = joined.download(&other.data.join("sync")).expect("download");
    let (mut copy, _) = other.sync.adopt(&joined, &download, PASS).expect("adopt");
    copy.unlock(PASS).expect("unlock");
    assert_eq!(titles(&copy), ["Alpha", "Beta", "Gamma"]);
}

/// The receipts are read from the version that this Mac saw: the answer has no chain of
/// older heads.
#[test]
fn receipts_ask_from_the_version_this_mac_saw() {
    let Pair {
        _root,
        relay,
        a,
        mut vault_a,
        ..
    } = pair();
    for n in 0..3 {
        vault_a
            .add(item(&format!("Item {n}"), "SYNTH-x"))
            .expect("add");
        a.sync.sync(&mut vault_a).expect("push");
    }
    let before = relay.log().len();
    a.sync.receipts(&vault_a).expect("receipts");
    let asked: Vec<String> = relay.log()[before..]
        .iter()
        .filter(|line| line.starts_with("GET /v1/sync/head"))
        .cloned()
        .collect();
    assert_eq!(asked.len(), 1, "{asked:?}");
    let state = a.sync.state().unwrap().unwrap();
    assert_eq!(state.last_remote_version, 4);
    assert_eq!(relay.last_since(), Some(4));
}

/// A lock ends a download in flight at once (`forget`), and the sync ends as locked.
/// "Turn off" then gets the guard of the vault at once.
#[test]
fn a_lock_ends_a_transfer_at_once() {
    let Pair {
        _root,
        relay,
        a,
        b,
        mut vault_a,
        vault_b,
    } = pair();
    vault_a.add(item("Gamma", "SYNTH-gamma")).expect("add");
    a.sync.sync(&mut vault_a).expect("push version 2");
    relay.delay("GET /v1/sync/snapshot", Duration::from_secs(3));
    let downloads = relay.count("GET /v1/sync/snapshot");
    let slot = Mutex::new(Some(vault_b));
    let (synced, took, waited) = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let started = Instant::now();
            (b.sync.sync_shared(&slot, |_| true), started.elapsed())
        });
        while relay.count("GET /v1/sync/snapshot") == downloads {
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(200));
        slot.lock().unwrap().as_mut().unwrap().lock().expect("lock");
        let started = Instant::now();
        drop(b.sync.stop_runs());
        let waited = started.elapsed();
        let (synced, took) = worker.join().expect("worker");
        (synced, took, waited)
    });
    assert_eq!(
        synced.unwrap_err(),
        SyncError::Vault(VaultErrorKind::Locked)
    );
    assert!(took < Duration::from_millis(2000), "the sync took {took:?}");
    assert!(
        waited < Duration::from_millis(1000),
        "turn off waited {waited:?}"
    );
}

/// The step before a lock or a backup does not run beside another sync of the vault:
/// it skips its push (`Running`) at once, the other sync keeps its download, and one
/// change makes one push.
#[test]
fn the_step_before_a_lock_skips_while_another_sync_runs() {
    let Pair {
        _root,
        relay,
        a,
        b,
        mut vault_a,
        mut vault_b,
    } = pair();
    vault_a.add(item("Eps", "SYNTH-eps")).expect("add");
    a.sync.sync(&mut vault_a).expect("push version 2");
    vault_b.add(item("Zeta", "SYNTH-zeta")).expect("add");
    relay.delay("GET /v1/sync/snapshot", Duration::from_millis(1500));
    let puts = relay.count("PUT /v1/sync/snapshot");
    let downloads = relay.count("GET /v1/sync/snapshot");
    let slot = Mutex::new(Some(vault_b));
    let (synced, skipped, waited) = std::thread::scope(|scope| {
        let worker = scope.spawn(|| b.sync.sync_shared(&slot, |_| true));
        while relay.count("GET /v1/sync/snapshot") == downloads {
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut held = slot.lock().unwrap();
        let started = Instant::now();
        let skipped = b
            .sync
            .sync_within(held.as_mut().unwrap(), Duration::from_secs(10));
        let waited = started.elapsed();
        drop(held);
        (worker.join().expect("worker"), skipped, waited)
    });
    assert_eq!(skipped.unwrap_err(), SyncError::Running);
    assert!(waited < Duration::from_millis(200), "{waited:?}");
    assert!(synced.expect("the other sync").pushed);
    assert_eq!(relay.count("PUT /v1/sync/snapshot"), puts + 1);
    let vault_b = slot.into_inner().unwrap().unwrap();
    assert_eq!(titles(&vault_b), ["Alpha", "Eps", "Zeta"]);
}

/// The relay calls of the step before a lock end within its limit, also when the relay
/// is slow.
#[test]
fn the_step_before_a_lock_ends_within_its_limit() {
    let Pair {
        _root,
        relay,
        a,
        mut vault_a,
        ..
    } = pair();
    vault_a.add(item("Slow", "SYNTH-slow")).expect("add");
    relay.delay("PUT /v1/sync/snapshot", Duration::from_secs(5));
    let started = Instant::now();
    let pushed = a.sync.sync_within(&mut vault_a, Duration::from_millis(800));
    let took = started.elapsed();
    assert_eq!(pushed.unwrap_err(), SyncError::RelayUnreachable);
    assert!(took < Duration::from_millis(2500), "{took:?}");
    assert!(
        a.sync.local_changed(&vault_a).expect("changed"),
        "the change waits"
    );
}

/// A pending link that the relay made before the code that this Mac holds is of an
/// older code: it gets no safety words, so it can only be refused (contract section
/// 7.1).
#[test]
fn a_link_older_than_the_held_code_gets_no_words() {
    let Pair {
        _root,
        relay: _relay,
        a,
        vault_a,
        ..
    } = pair();
    let code = a.sync.create_link(&vault_a).expect("link");
    let _pending = PendingJoin::request(&code.link, "", "Synthetic iMac").expect("request");
    let links = a.sync.pending_links(&vault_a, Some(&code)).expect("links");
    assert!(links[0].safety.is_some(), "a link of the held code");
    // A code that the relay made an hour after this link.
    let later = LinkCode {
        code: code.code.clone(),
        link: code.link.clone(),
        expires_at: code.expires_at + 3600,
    };
    let links = a.sync.pending_links(&vault_a, Some(&later)).expect("links");
    assert_eq!(links.len(), 1);
    assert!(links[0].safety.is_none(), "an older link is refused only");
}

/// A relay restored from a backup that predates a passphrase change: "Use the relay
/// copy" needs the passphrase of that copy. The forgotten anchor stays, so the
/// passphrase step starts from the copy as it is now. That passphrase only opens the
/// copy for the merge: the vault keeps the passphrase of this Mac, and the merged vault
/// goes up under it. Nothing is lost, and the old passphrase does not come back.
#[test]
fn a_relay_rollback_before_a_passphrase_change_keeps_the_passphrase_of_this_mac() {
    const NEW: &str = "synthetic-relay-new-pass";
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    let a = mac(&root, "a", &relay.url);
    let mut vault = a.create();
    vault.add(item("Alpha", "SYNTH-alpha")).expect("add");
    a.sync
        .create_team(&mut vault, "Personal", &relay.team_code(), "Mac")
        .expect("team");
    vault.change_passphrase(PASS, NEW).expect("change");
    vault.add(item("Beta", "SYNTH-beta")).expect("add");
    a.sync.sync(&mut vault).expect("push version 2");
    relay.roll_back_to(1);
    assert_eq!(a.sync.sync(&mut vault).unwrap_err(), SyncError::StaleCopy);
    assert!(!a.sync.keeps_passphrase(), "an anchor: a passphrase change");
    assert_eq!(
        a.sync.use_relay_copy(&mut vault).unwrap_err(),
        SyncError::NeedsPassphrase
    );
    let state = a.sync.state().expect("state").expect("on");
    assert_eq!(
        (state.last_remote_version, state.last_head_sha256),
        (0, None),
        "the forgotten anchor stays"
    );
    assert!(
        a.sync.keeps_passphrase(),
        "no anchor: the copy may be older"
    );
    assert_eq!(
        a.sync.sync(&mut vault).unwrap_err(),
        SyncError::NeedsPassphrase,
        "the copy needs its passphrase; it is not refused as older"
    );
    assert_eq!(
        a.sync.take_new_passphrase(&mut vault, NEW).unwrap_err(),
        SyncError::Vault(VaultErrorKind::WrongKeyOrCorrupt),
        "the passphrase of this Mac does not open the older copy"
    );
    let synced = a
        .sync
        .take_new_passphrase(&mut vault, PASS)
        .expect("the passphrase of the copy");
    assert!(synced.expect("the sync after it").pushed);
    assert_eq!(relay.version(), 2);
    assert!(!a.sync.keeps_passphrase(), "the anchor is back");
    vault.add(item("Gamma", "SYNTH-gamma")).expect("add");
    a.sync
        .sync(&mut vault)
        .expect("syncs again under the passphrase of this Mac");
    assert_eq!(relay.version(), 3);
    assert_eq!(titles(&vault), ["Alpha", "Beta", "Gamma"]);
    vault.lock().expect("lock");
    assert_eq!(
        vault.unlock(PASS).unwrap_err().kind(),
        VaultErrorKind::WrongKeyOrCorrupt,
        "the old passphrase does not come back"
    );
    vault
        .unlock(NEW)
        .expect("the vault keeps the passphrase of this Mac");

    // A second Mac adopts the copy that went up with the passphrase of this Mac.
    let b = mac(&root, "b", &relay.url);
    let joined = join(&relay, &a, &vault);
    let download = joined.download(&b.data.join("sync")).expect("download");
    assert!(b.sync.adopt(&joined, &download, PASS).is_err());
    let (mut vault_b, _) = b.sync.adopt(&joined, &download, NEW).expect("adopt");
    vault_b.unlock(NEW).expect("unlock");
    assert_eq!(titles(&vault_b), ["Alpha", "Beta", "Gamma"]);
}

/// A relay address that takes TCP connections and never answers: a TLS handshake waits
/// for the server hello.
fn silent_tls_relay() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming().flatten() {
            held.push(stream);
        }
    });
    format!("https://127.0.0.1:{port}")
}

/// A vault with a relay device of `url` and a relay state, as after "Turn on".
fn relay_vault(dir: &std::path::Path, url: &str) -> (Mutex<Option<Vault>>, RelaySync) {
    let vault_path = dir.join("vault.db");
    let mut vault = Vault::create(&vault_path, PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    let key = DeviceKey::generate().expect("key");
    vault
        .set_relay_device(&apassy::vault::RelayDevice {
            relay_url: url.to_owned(),
            team_id: "t_7k2m5q4x3c".to_owned(),
            device_id: 2,
            public_key: key.public_key().to_vec(),
            key_pkcs8: key.pkcs8().expect("pkcs8").clone(),
            created_at: 0,
        })
        .expect("relay row");
    let config = RelayConfig::in_data_dir(dir, &vault_path, url, "relay");
    fs::create_dir_all(&config.work_dir).expect("work dir");
    let state = serde_json::json!({
        "format": 3, "transport": "relay", "file_name": "",
        "vault_id": vault.sync_identity().expect("identity").vault_id,
        "last_file_sha256": null, "last_content": null, "last_sync_at": null,
        "relay_url": url, "team_id": "t_7k2m5q4x3c", "device_id": 2,
    });
    fs::write(&config.state_path, state.to_string()).expect("state");
    let sync = RelaySync::new(config);
    assert!(sync.state().expect("state").is_some());
    (Mutex::new(Some(vault)), sync)
}

/// A lock while a sync is in its TLS handshake with a relay that never answers: the
/// sync ends at once, and "Turn off" (`stop_runs`, on the window thread) does not wait
/// for the relay.
#[test]
fn a_lock_during_the_tls_handshake_ends_the_sync_at_once() {
    let dir = TempDir::new().expect("temp dir");
    let url = silent_tls_relay();
    let (slot, sync) = relay_vault(dir.path(), &url);
    let (result, took, waited) = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let started = Instant::now();
            (sync.sync_shared(&slot, |_| true), started.elapsed())
        });
        std::thread::sleep(Duration::from_millis(500));
        assert!(sync.has_session(), "the sync has the key");
        sync.forget();
        let started = Instant::now();
        drop(sync.stop_runs());
        let waited = started.elapsed();
        let (result, took) = worker.join().expect("worker");
        (result, took, waited)
    });
    assert_eq!(
        result.unwrap_err(),
        SyncError::Vault(VaultErrorKind::Locked)
    );
    assert!(
        waited < Duration::from_secs(2),
        "turn off waited {waited:?}"
    );
    assert!(took < Duration::from_secs(3), "the sync took {took:?}");
}

/// "Turn off" pauses the sync of the vault while its device leaves the team: the sync
/// that runs ends, a sync that waits for it does not start, and nothing is pushed. After
/// `resume` the vault syncs again.
#[test]
fn a_sync_that_waits_during_a_pause_does_not_run() {
    let Pair {
        _root,
        relay,
        a,
        b,
        mut vault_a,
        mut vault_b,
    } = pair();
    vault_b.add(item("Beta", "SYNTH-beta")).expect("add");
    vault_a.add(item("Gamma", "SYNTH-gamma")).expect("add");
    a.sync.sync(&mut vault_a).expect("push version 2");
    relay.delay("GET /v1/sync/snapshot", Duration::from_secs(2));
    let downloads = relay.count("GET /v1/sync/snapshot");
    let slot = Mutex::new(Some(vault_b));
    let (owner, worker, puts) = std::thread::scope(|scope| {
        let owner = scope.spawn(|| b.sync.sync_shared(&slot, |_| true));
        while relay.count("GET /v1/sync/snapshot") == downloads {
            std::thread::sleep(Duration::from_millis(20));
        }
        let worker = scope.spawn(|| b.sync.sync_shared(&slot, |_| true));
        std::thread::sleep(Duration::from_millis(200));
        let puts = relay.count("PUT /v1/sync/snapshot");
        b.sync.pause();
        (
            owner.join().expect("owner"),
            worker.join().expect("worker"),
            puts,
        )
    });
    let locked = SyncError::Vault(VaultErrorKind::Locked);
    assert_eq!(owner.unwrap_err(), locked);
    assert_eq!(worker.unwrap_err(), locked, "the waiting sync did not run");
    assert_eq!(relay.count("PUT /v1/sync/snapshot"), puts, "nothing pushed");
    assert!(!b.sync.has_session(), "the key is not in memory");
    b.sync.resume();
    let mut vault_b = slot.into_inner().unwrap().unwrap();
    assert!(b.sync.sync(&mut vault_b).expect("syncs again").pushed);
    assert_eq!(titles(&vault_b), ["Alpha", "Beta", "Gamma"]);
}

/// The work files that a crash or a quit in a transfer left (copies of the vault under
/// the passphrase of that time) go at the next sync.
#[test]
fn a_work_file_that_a_crash_left_goes_at_the_next_sync() {
    let Pair {
        _root,
        relay: _relay,
        a,
        mut vault_a,
        ..
    } = pair();
    let work = a.sync.config().work_dir.clone();
    let left: Vec<PathBuf> = ["merge", "push", "passphrase"]
        .iter()
        .map(|purpose| work.join(format!(".vault.relay.{purpose}")))
        .collect();
    for path in &left {
        fs::write(path, vec![7u8; 4096]).expect("leftover");
    }
    vault_a.add(item("Delta", "SYNTH-delta")).expect("add");
    a.sync.sync(&mut vault_a).expect("sync");
    for path in &left {
        assert!(!path.exists(), "{} stays", path.display());
    }
    let names: Vec<String> = fs::read_dir(&work)
        .expect("work dir")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.contains(".relay."))
        .collect();
    assert!(names.is_empty(), "{names:?}");
}

/// The relay reads the token again after the body of a push, so an upload needs a token
/// that lasts to the end of the transfer: with less left, the Mac signs in first. A sync
/// without a push keeps the token.
#[test]
fn an_upload_signs_in_again_when_the_token_ends_before_the_transfer_could() {
    let Pair {
        _root,
        relay,
        a,
        mut vault_a,
        ..
    } = pair();
    // Less than the ten minutes that a transfer may take.
    relay.set_token_lifetime(400);
    a.sync.forget();
    a.sync.sync(&mut vault_a).expect("a sync without a push");
    let sign_ins = relay.count("POST /v1/auth/token");
    a.sync.sync(&mut vault_a).expect("a sync without a push");
    assert_eq!(
        relay.count("POST /v1/auth/token"),
        sign_ins,
        "the token stays"
    );
    vault_a.add(item("Epsilon", "SYNTH-epsilon")).expect("add");
    assert!(a.sync.sync(&mut vault_a).expect("push").pushed);
    assert_eq!(
        relay.count("POST /v1/auth/token"),
        sign_ins + 1,
        "a new token for the upload"
    );
}
