#![cfg(feature = "vault")]

//! Sync of a vault through the Apassy relay (ADR 0022, contract relay-sync-v1). Synthetic
//! values only.
//!
//! An in-process fake relay (`tests/common/fake_relay.rs`) stands in for the relay on
//! 127.0.0.1 with plain HTTP, which the app allows only for a loopback address. Each
//! "Mac" is a separate data folder with its own local vault file and device key.

use crate::common::fake_relay;

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
        concat!("both ", apassy::computers!(), " show the same words")
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
    // "Received by <Mac>": a Mac that merged a pulled version tells the relay.
    let b_id = row_b.device_id;
    assert_eq!(
        relay.receipts().get(&b_id),
        Some(&1),
        "the adoption of version 1"
    );

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
    let a_id = row_a.device_id;
    assert_eq!(
        relay.receipts().get(&a_id),
        Some(&2),
        "the merge of the pulled version 2"
    );
    let receipts = a.sync.receipts(&vault_a).expect("receipts");
    assert!(
        receipts
            .iter()
            .any(|receipt| receipt.device_id == a_id && receipt.version == 2),
        "the receipts list the merge of version 2"
    );

    // The pushed copy never carries the device key of a Mac.
    let snapshot_heads = relay.heads();
    assert_eq!(snapshot_heads.len(), 2);
    assert_eq!(
        HeadFields::parse(&snapshot_heads[1].text).unwrap().previous,
        snapshot_heads[0].hash(),
        "the chain links"
    );

    // The receipts are read from the version that this Mac saw: the answer has no
    // chain of older heads.
    for n in 0..2 {
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
    assert_eq!(asked.len(), 1, "one head read for the receipts: {asked:?}");
    let state = a.sync.state().unwrap().unwrap();
    assert_eq!(state.last_remote_version, 4);
    assert_eq!(
        relay.last_since(),
        Some(4),
        concat!(
            "the receipts ask from the version this ",
            apassy::computer!(),
            " saw"
        )
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

/// A push that loses one round to a push of the other Mac merges and pushes again, and
/// nothing is lost; three lost rounds in a row leave the change for the next sync.
#[test]
fn a_412_merges_and_pushes_again_and_three_lost_rounds_leave_the_change() {
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

    // One lost round (412): it merges and pushes again, and nothing is lost.
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
    {
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

    // Three lost rounds in a row: the change stays for the next sync.
    vault_b.add(item("From B late", "SYNTH-b")).expect("add");
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
    assert_eq!(
        b.sync.sync(&mut vault_b).unwrap_err(),
        SyncError::RelayBusy,
        "three lost rounds"
    );
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
        [
            "A 1",
            "A 2",
            "A 3",
            "Alpha",
            "From A",
            "From B",
            "From B late"
        ],
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
    assert_eq!(
        pending.first_retry_wait(),
        Duration::from_secs(2),
        "a join of the app waits 2 s after the first failure"
    );
    // The test waits a shorter first wait.
    let pending = pending.with_first_retry_wait(Duration::from_millis(1_200));
    relay.fail_next("POST /v1/auth/challenge", 1, 502);
    assert!(pending.poll().expect("a network error waits").is_none());
    let links = a.sync.pending_links(&vault_a, Some(&code)).expect("links");
    a.sync.confirm_link(&vault_a, &links[0]).expect("confirm");
    // The next poll waits before it asks the relay again.
    let challenges = relay.count("POST /v1/auth/challenge");
    assert!(pending.poll().expect("backing off").is_none());
    assert_eq!(relay.count("POST /v1/auth/challenge"), challenges);
    std::thread::sleep(Duration::from_millis(1_250));
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
    let download = relay.hold("GET /v1/sync/snapshot", Duration::from_millis(1200));
    let taken = std::thread::scope(|scope| {
        let relay = &relay;
        let download = &download;
        scope.spawn(move || {
            // During the download for the check: the next head request fails.
            download.wait_entered();
            relay.fail_next("GET /v1/sync/head", 1, 500);
            download.release();
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
        crate::common::key_raw(&conn, PASS).expect("key");
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
        concat!(
            "the passphrase of this ",
            apassy::computer!(),
            " does not open the older copy"
        )
    );
    let synced = a
        .sync
        .take_new_passphrase(&mut vault, PASS)
        .expect("the passphrase of the copy");
    assert!(synced.expect("the sync after it").pushed);
    assert_eq!(relay.version(), 2);
    assert!(!a.sync.keeps_passphrase(), "the anchor is back");
    vault.add(item("Gamma", "SYNTH-gamma")).expect("add");
    a.sync.sync(&mut vault).expect(concat!(
        "syncs again under the passphrase of this ",
        apassy::computer!()
    ));
    assert_eq!(relay.version(), 3);
    assert_eq!(titles(&vault), ["Alpha", "Beta", "Gamma"]);
    vault.lock().expect("lock");
    assert_eq!(
        vault.unlock(PASS).unwrap_err().kind(),
        VaultErrorKind::WrongKeyOrCorrupt,
        "the old passphrase does not come back"
    );
    vault.unlock(NEW).expect(concat!(
        "the vault keeps the passphrase of this ",
        apassy::computer!()
    ));

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
            account_key: false,
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
    let download = relay.hold("GET /v1/sync/snapshot", Duration::from_secs(2));
    let slot = Mutex::new(Some(vault_b));
    let (owner, worker, puts) = std::thread::scope(|scope| {
        let owner = scope.spawn(|| b.sync.sync_shared(&slot, |_| true));
        download.wait_entered();
        let worker = scope.spawn(|| b.sync.sync_shared(&slot, |_| true));
        std::thread::sleep(Duration::from_millis(200));
        let puts = relay.count("PUT /v1/sync/snapshot");
        b.sync.pause();
        download.release();
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

// ---- A new relay copy without a team code (plans section 4.1, plan s7 unit S0). ----

/// A Mac whose vault asks through a questions-only Connect team (ADR 0032), as the
/// questions sheet makes it. Returns the team id.
fn questions_through_connect(relay: &FakeRelay, vault: &mut Vault) -> String {
    use apassy::relay::connect::{create_connect, prepare_connect};
    let pending =
        prepare_connect(vault, &relay.url, "Personal", "Synthetic MacBook").expect("prepare");
    let membership = create_connect(&pending).expect("connect");
    vault.keep_connect_result(&membership).expect("keep");
    apassy::relay::membership::adopt_questions_team(vault, &membership, "Synthetic MacBook")
        .expect("adopt");
    membership.team_id
}

fn purposes(vault: &Vault, team: &str) -> Vec<apassy::vault::MembershipPurpose> {
    vault
        .relay_membership(team)
        .expect("row")
        .expect("membership")
        .purposes
        .into_iter()
        .collect()
}

#[test]
fn a_new_relay_copy_without_a_code_pushes_version_one() {
    use apassy::vault::MembershipPurpose;
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    // The hosted relay's setting until Apassy Connect starts.
    relay.set_connect_sync_bytes(fake_relay::SYNC_BYTES);
    let a = mac(&root, "a", &relay.url);
    let mut vault = a.create();
    vault.add(item("Alpha", "SYNTH-alpha")).expect("add");
    let identity = vault.sync_identity().expect("identity");

    let report = a
        .sync
        .create_team_codeless(&mut vault, "  Personal  ", "Synthetic MacBook")
        .expect("codeless relay copy");
    assert_eq!(report.team, "Personal");
    assert!(report.outcome.pushed);
    // One Connect team, no team code, and version 1 of this vault in it.
    assert_eq!(relay.connect_teams(), vec![report.link.team_id.clone()]);
    assert_eq!(relay.count("POST /v1/connect"), 1);
    assert_eq!(relay.count("POST /v1/teams"), 0);
    assert!(
        !relay
            .request_bodies()
            .iter()
            .any(|body| body.contains("apassy_tcd_"))
    );
    assert_eq!(relay.version(), 1);
    let fields = HeadFields::parse(&relay.heads()[0].text).expect("head");
    assert_eq!(fields.vault_id, identity.vault_id);
    assert_eq!(fields.team_id, report.link.team_id);
    assert_eq!(fields.device_id, report.link.device_id);
    // The membership is for sync only; the attempt keeps the team for a retry.
    let row = vault.relay_device().expect("row").expect("a row");
    assert_eq!(row.team_id, report.link.team_id);
    assert_eq!(
        purposes(&vault, &report.link.team_id),
        vec![MembershipPurpose::Sync]
    );
    assert_eq!(
        vault
            .pending_connect()
            .expect("pending")
            .expect("kept")
            .created,
        Some((report.link.team_id.clone(), report.link.device_id))
    );
    let state = a.sync.state().expect("state").expect("on");
    assert_eq!(state.last_remote_version, 1);
    assert_eq!(
        a.sync
            .create_team_codeless(&mut vault, "Personal", "Mac")
            .unwrap_err(),
        apassy::relay::connect::ConnectError::Sync(SyncError::AlreadyEnabled)
    );
    // The questions then use the same team, with no relay call.
    let calls = relay.log().len();
    apassy::relay::membership::enable_questions(&mut vault, "Synthetic MacBook")
        .expect("questions");
    assert_eq!(relay.log().len(), calls);
    assert_eq!(
        purposes(&vault, &report.link.team_id),
        vec![MembershipPurpose::Sync, MembershipPurpose::Questions]
    );
}

#[test]
fn a_new_relay_copy_without_a_code_reuses_the_questions_team_of_the_vault() {
    use apassy::relay::connect::ConnectError;
    use apassy::vault::MembershipPurpose;
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    let a = mac(&root, "a", &relay.url);
    let mut vault = a.create();
    vault.add(item("Alpha", "SYNTH-alpha")).expect("add");
    // The questions team was made before the relay's sync setting: `sync_bytes` 0.
    let team = questions_through_connect(&relay, &mut vault);
    relay.set_connect_sync_bytes(fake_relay::SYNC_BYTES);
    assert_eq!(
        a.sync
            .create_team_codeless(&mut vault, "Personal", "Synthetic MacBook")
            .unwrap_err(),
        ConnectError::Sync(SyncError::Relay(RelayRefusal::PlanRequired))
    );
    // Nothing turned on, no second team, the questions as they were.
    assert!(a.sync.state().expect("state").is_none());
    assert!(vault.relay_device().expect("row").is_none());
    assert_eq!(relay.version(), 0);
    assert_eq!(relay.connect_teams(), vec![team.clone()]);
    assert_eq!(purposes(&vault, &team), vec![MembershipPurpose::Questions]);

    // The operator gives the team the size (`admin limits --sync-bytes`): the same team
    // takes the copy, with no new Connect call.
    relay.set_team_sync_bytes(&team, fake_relay::SYNC_BYTES);
    let report = a
        .sync
        .create_team_codeless(&mut vault, "Personal", "Synthetic MacBook")
        .expect("codeless relay copy");
    assert_eq!(report.link.team_id, team);
    assert_eq!(relay.count("POST /v1/connect"), 1);
    assert_eq!(relay.connect_teams(), vec![team.clone()]);
    assert_eq!(relay.version(), 1);
    assert_eq!(
        purposes(&vault, &team),
        vec![MembershipPurpose::Sync, MembershipPurpose::Questions]
    );
    let questions = apassy::relay::membership::questions_membership(&vault)
        .expect("row")
        .expect("questions stay on");
    assert_eq!(questions.team_id, team);
    assert_eq!(
        vault.relay_device().expect("row").expect("sync").public_key,
        questions.public_key
    );
}

#[test]
fn a_new_relay_copy_without_a_code_a_lost_answer_recovers_the_same_team() {
    use apassy::relay::connect::ConnectError;
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    relay.set_connect_sync_bytes(fake_relay::SYNC_BYTES);
    relay.support_connect_recovery();
    let a = mac(&root, "a", &relay.url);
    let mut vault = a.create();
    // The relay makes the team, and both answers are lost on the network.
    relay.lose_next_answers("POST /v1/connect", 2);
    assert_eq!(
        a.sync
            .create_team_codeless(&mut vault, "Personal", "Synthetic MacBook")
            .unwrap_err(),
        ConnectError::Offline
    );
    assert!(a.sync.state().expect("state").is_none());
    let made = relay.connect_teams();
    assert_eq!(made.len(), 1);
    let saved = vault.pending_connect().expect("pending").expect("kept");
    assert!(saved.created.is_none());
    // After a lock, the next try recovers the team of the saved key (F06).
    vault.lock().expect("lock");
    vault.unlock(PASS).expect("unlock");
    let report = a
        .sync
        .create_team_codeless(&mut vault, "Personal", "Synthetic MacBook")
        .expect("recovered");
    assert_eq!(vec![report.link.team_id.clone()], made);
    assert_eq!(relay.connect_teams(), made);
    assert!(
        relay
            .request_bodies()
            .iter()
            .any(|body| body.contains("recovery_nonce"))
    );
    assert_eq!(relay.version(), 1);
    let kept = vault.pending_connect().expect("pending").expect("kept");
    assert_eq!(kept.key_pkcs8, saved.key_pkcs8);
    assert_eq!(
        kept.created.map(|(team, _)| team),
        Some(report.link.team_id)
    );
}

#[test]
fn a_new_relay_copy_without_a_code_joins_the_team_that_another_mac_holds() {
    use apassy::relay::connect::ConnectError;
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    relay.set_connect_sync_bytes(fake_relay::SYNC_BYTES);
    let a = mac(&root, "a", &relay.url);
    let mut vault = a.create();
    // The vault names a questions team that this Mac is not in.
    vault.set_questions_team("t_abcdefgh23").expect("team");
    assert_eq!(
        a.sync
            .create_team_codeless(&mut vault, "Personal", "Synthetic MacBook")
            .unwrap_err(),
        ConnectError::JoinOtherMac
    );
    assert!(relay.log().is_empty(), "no relay call");
    assert!(vault.pending_connect().expect("pending").is_none());
    assert!(
        ConnectError::JoinOtherMac
            .to_string()
            .contains(concat!("Join from another ", apassy::computer!()))
    );
}

// ---- Sync through Apassy Connect (plan s7 unit M3, connect-account-v1 section 8). ----
//
// The fake Connect keeps its vault stores as teams of a fake relay
// (`FakeConnect::with_relay`): the app signs in, pushes, and pulls at the Connect origin,
// and the relay checks every head with `ring` against the keys of the store, which are
// the account device keys. Each "Mac" has its own key store (the Keychain in the app)
// and account file.

mod connect_sync {
    use super::{Mac, PASS, item, mac, titles};
    use crate::common::fake_connect::FakeConnect;
    use crate::common::fake_relay::{FakeRelay, StoredHead};

    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use apassy::broker::SharedVault;
    use apassy::broker::approvals::{OwnerCheck, OwnerGate};
    use apassy::connect::{
        AccountSigner, ConnectAccount, ConnectClient, ConnectError, JoinPoll, JoinRequest,
        MemoryKeyStore, account_file, signer_policy,
    };
    use apassy::sync::{
        HeadFields, MoveStep, RelayConfig, RelayRefusal, RelaySync, StoreError, StorePlan,
        SyncError, is_plan_refusal, sha256_hex,
    };
    use apassy::vault::Vault;
    use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};

    /// A head by a key that the policy of `sync` does not hold: the sync first waits for a
    /// fresh device list ("Checking the device list"), and changes nothing; with a list
    /// fetched after that (`note_device_list`) the refusal of the next sync is returned.
    fn refused_after_a_fresh_list(sync: &RelaySync, vault: &mut Vault) -> SyncError {
        assert_eq!(sync.sync(vault).unwrap_err(), SyncError::ChecksDeviceList);
        sync.note_device_list(std::time::Instant::now());
        sync.sync(vault).unwrap_err()
    }
    use serde_json::json;
    use tempfile::TempDir;

    /// The fake Connect with its relay of stores.
    struct Cloud {
        root: TempDir,
        relay: Arc<FakeRelay>,
        connect: FakeConnect,
    }

    fn cloud() -> Cloud {
        let relay = Arc::new(FakeRelay::start());
        let connect = FakeConnect::with_relay(Arc::clone(&relay) as _);
        Cloud {
            root: TempDir::new().expect("temp dir"),
            relay,
            connect,
        }
    }

    /// A Mac with a Connect account: its relay sync for the Connect origin, its key
    /// store, its account file.
    struct ConnectMac {
        mac: Mac,
        keys: MemoryKeyStore,
        account_path: PathBuf,
    }

    fn connect_mac(cloud: &Cloud, name: &str) -> ConnectMac {
        let mac = mac(&cloud.root, name, &cloud.connect.url);
        let account_path = account_file(&mac.data);
        ConnectMac {
            mac,
            keys: MemoryKeyStore::new(),
            account_path,
        }
    }

    fn client(cloud: &Cloud) -> ConnectClient {
        ConnectClient::new(&cloud.connect.url).expect("client")
    }

    /// A new account on `mac`, entitled when `entitled`.
    fn new_account(cloud: &Cloud, mac: &ConnectMac, name: &str, entitled: bool) -> ConnectAccount {
        let (account, _recovery) = ConnectAccount::create(
            client(cloud),
            &mac.keys,
            &mac.account_path,
            name,
            "Synthetic MacBook",
        )
        .expect("create account");
        if entitled {
            cloud.connect.entitle(&account.state().account_id);
        }
        account
    }

    /// An unlocked vault and its owner gate, for the owner checks.
    struct Owner {
        _dir: TempDir,
        shared: SharedVault,
        gate: OwnerGate,
    }

    fn owner() -> Owner {
        let dir = TempDir::new().expect("dir");
        let mut vault = Vault::create(&dir.path().join("owner.db"), PASS).expect("vault");
        vault.unlock(PASS).expect("unlock");
        let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
        let gate = OwnerGate::new(Arc::clone(&shared), None);
        Owner {
            _dir: dir,
            shared,
            gate,
        }
    }

    impl Owner {
        fn proof(
            &self,
            action: apassy::broker::approvals::OwnerAction,
        ) -> (apassy::broker::approvals::OwnerProof, [u8; 32]) {
            let proof = self
                .gate
                .authorize(action, OwnerCheck::passphrase(PASS))
                .expect("owner check");
            let epoch = self.shared.lock().unwrap().as_ref().expect("vault").epoch();
            (proof, epoch)
        }
    }

    /// `b` joins the account of `account` (on another Mac) with the safety words and a
    /// fresh owner check, as Settings › Connect does.
    fn join_account(
        cloud: &Cloud,
        account: &mut ConnectAccount,
        b: &ConnectMac,
        name: &str,
    ) -> ConnectAccount {
        let owner = owner();
        let link = account.start_link().expect("link");
        let mut request =
            JoinRequest::start(client(cloud), &b.keys, &b.account_path, link.code(), name)
                .expect("join");
        assert!(matches!(request.poll().expect("poll"), JoinPoll::Waiting));
        let pending = account.pending_joins(&link).expect("pending");
        let (proof, epoch) = owner.proof(pending[0].owner_action(&account.state().account_id));
        account
            .confirm_join(&link, &pending[0], proof, &epoch)
            .expect("confirm");
        match request.poll().expect("poll") {
            JoinPoll::Confirmed(joined) => *joined,
            other => panic!("not confirmed: {other:?}"),
        }
    }

    fn verifies(public_key: &[u8], text: &str, signature: &[u8]) -> bool {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
            .verify(text.as_bytes(), signature)
            .is_ok()
    }

    /// A vault of `a` that each of `others` holds too (the same vault id and
    /// passphrase, as a vault that synced through a folder before): all unlocked, `a`'s
    /// first.
    fn shared_vaults(a: &Mac, others: &[&Mac]) -> Vec<Vault> {
        let mut vault = a.create();
        vault.add(item("Alpha", "SYNTH-alpha")).expect("add");
        drop(vault);
        let open = |path: &std::path::Path| {
            let mut vault = Vault::open(path).expect("open");
            vault.unlock(PASS).expect("unlock");
            vault
        };
        let mut vaults = vec![open(&a.vault_path)];
        for other in others {
            fs::copy(&a.vault_path, &other.vault_path).expect("copy");
            vaults.push(open(&other.vault_path));
        }
        vaults
    }

    fn shared_vault(a: &Mac, b: &Mac) -> (Vault, Vault) {
        let mut vaults = shared_vaults(a, &[b]);
        let b = vaults.pop().expect("b");
        (vaults.pop().expect("a"), b)
    }

    #[test]
    fn enabling_on_connect_pushes_version_one_under_the_account_key() {
        let cloud = cloud();
        let a = connect_mac(&cloud, "a");
        let mut account = new_account(&cloud, &a, "Rafal", true);
        let signer = account.signer().expect("signer");
        let mut vault = a.mac.create();
        vault.add(item("Alpha", "SYNTH-alpha")).expect("add");
        let vault_id = vault.sync_identity().expect("identity").vault_id;

        let report = a
            .mac
            .sync
            .enable_on_connect(&mut vault, &mut account, "Personal")
            .expect("enable on Connect");
        assert!(report.enable.outcome.pushed);
        let team = report.team_id.clone();
        assert_eq!(
            cloud
                .connect
                .store_of(&account.state().account_id, &vault_id)
                .as_deref(),
            Some(team.as_str()),
            "POST /v1/account/vaults made the store"
        );
        assert_eq!(cloud.relay.version_of(&team), 1);
        // The head of version 1 is signed with the account key, and the relay took it.
        let heads = cloud.relay.heads_of(&team);
        assert_eq!(heads.len(), 1);
        let head = &heads[0];
        assert!(verifies(signer.public_key(), &head.text, &head.signature));
        assert!(head.text.contains(&vault_id));
        let devices = cloud.relay.team_devices(&team);
        assert_eq!(devices.len(), 1);
        assert_eq!(
            devices[0].1,
            signer.public_key(),
            "the store device is the account key"
        );
        // The vault keeps an account row with no private key.
        let row = vault
            .relay_device()
            .expect("row")
            .expect("relay sync is on");
        assert!(row.uses_account_key());
        assert!(row.key_pkcs8.is_empty());
        assert_eq!(row.team_id, team);
        assert_eq!(row.relay_url, cloud.connect.url);
        // The relay-sync-v1 wire: the team sign-in and the push at the Connect origin.
        let log = cloud.connect.log();
        assert!(log.iter().any(|line| line == "POST /v1/account/vaults"));
        assert!(log.iter().any(|line| line == "POST /v1/auth/token"));
        assert!(log.iter().any(|line| line == "PUT /v1/sync/snapshot"));
        // A later change goes up as version 2, signed by the same key.
        vault.add(item("Beta", "SYNTH-beta")).expect("add");
        assert!(a.mac.sync.sync(&mut vault).expect("sync").pushed);
        assert_eq!(cloud.relay.version_of(&team), 2);
        let heads = cloud.relay.heads_of(&team);
        assert!(verifies(
            signer.public_key(),
            &heads[1].text,
            &heads[1].signature
        ));

        // An account without a plan gets no store, and nothing turns on.
        let c = connect_mac(&cloud, "c");
        let mut free = new_account(&cloud, &c, "Free", false);
        let mut other = c.mac.create();
        let refused = c
            .mac
            .sync
            .enable_on_connect(&mut other, &mut free, "Personal")
            .unwrap_err();
        assert_eq!(refused, StoreError::Connect(ConnectError::PlanRequired));
        assert!(c.mac.sync.state().expect("state").is_none());
        assert!(other.relay_device().expect("row").is_none());
    }

    #[test]
    fn a_second_mac_of_the_account_joins_without_a_link_code_and_merges() {
        let cloud = cloud();
        let a = connect_mac(&cloud, "a");
        let b = connect_mac(&cloud, "b");
        let mut account_a = new_account(&cloud, &a, "Rafal", true);
        let mut account_b = join_account(&cloud, &mut account_a, &b, "Synthetic Mac mini");
        let c = connect_mac(&cloud, "c");
        let mut vaults = shared_vaults(&a.mac, &[&b.mac, &c.mac]);
        let mut vault_c = vaults.pop().expect("c");
        let mut vault_b = vaults.pop().expect("b");
        let mut vault_a = vaults.pop().expect("a");
        vault_b.add(item("Beta", "SYNTH-beta")).expect("add");

        let report = a
            .mac
            .sync
            .enable_on_connect(&mut vault_a, &mut account_a, "Personal")
            .expect("enable on A");
        assert_eq!(
            report.registered,
            vec!["Synthetic Mac mini".to_owned()],
            "A registers the other Mac of the account"
        );
        assert!(report.not_registered.is_empty());
        let team = report.team_id;
        assert!(
            cloud
                .connect
                .store_devices(&team)
                .contains(&account_b.state().device_id)
        );

        // B turns on the same way: no link code, a merge, and a push.
        let report = b
            .mac
            .sync
            .enable_on_connect(&mut vault_b, &mut account_b, "Personal")
            .expect("enable on B");
        assert_eq!(report.team_id, team, "the same store");
        assert!(report.enable.outcome.merge.is_some(), "B merged A's copy");
        assert!(report.enable.outcome.pushed, "B pushed the merged vault");
        assert_eq!(titles(&vault_b), vec!["Alpha", "Beta"]);
        assert_eq!(cloud.relay.version_of(&team), 2);
        let log = cloud.connect.log();
        assert!(
            !log.iter()
                .any(|line| line.starts_with("POST /v1/devices/link")),
            "no device link: {log:?}"
        );
        assert!(
            vault_b
                .relay_device()
                .expect("row")
                .expect("on")
                .uses_account_key()
        );
        // A pulls B's change.
        a.mac.sync.sync(&mut vault_a).expect("sync A");
        assert_eq!(titles(&vault_a), vec!["Alpha", "Beta"]);

        // A Mac that joined the account later is not in the store until a Mac in it adds
        // it; then it turns on without a link code too.
        let mut account_c = join_account(&cloud, &mut account_a, &c, "Synthetic iMac");
        let early = c
            .mac
            .sync
            .enable_on_connect(&mut vault_c, &mut account_c, "Personal")
            .unwrap_err();
        assert_eq!(early, StoreError::NotInStore);
        assert_eq!(
            a.mac
                .sync
                .register_account_devices(&mut account_a)
                .expect("register"),
            vec!["Synthetic iMac".to_owned()]
        );
        c.mac
            .sync
            .enable_on_connect(&mut vault_c, &mut account_c, "Personal")
            .expect("enable on C");
        assert_eq!(titles(&vault_c), vec!["Alpha", "Beta"]);
    }

    /// A head after `last` that `signer` signs with `device_id` as its store device: what
    /// a hostile relay serves.
    fn forged_after(
        last: &StoredHead,
        device_id: u64,
        signer: &AccountSigner,
    ) -> (StoredHead, Vec<u8>) {
        let bytes = b"synthetic copy".to_vec();
        let fields = HeadFields {
            version: last.version + 1,
            previous: last.hash(),
            snapshot_sha256: sha256_hex(&bytes),
            size: bytes.len() as u64,
            device_id,
            ..HeadFields::parse(&last.text).expect("head")
        };
        let signed = signer.sign_head(fields).expect("sign");
        (
            StoredHead {
                version: last.version + 1,
                text: signed.text,
                signature: signed.signature,
                device_id,
            },
            bytes,
        )
    }

    /// The heads of a vault store come only from the trust store of this Mac: a key that
    /// Connect lists as a store device signs nothing, though Connect says the account is an
    /// active member of a family, both in a store of this account alone and in one that
    /// Connect marks shared (with a device of a member's account in it). The member's own
    /// device signs nothing here either: no step pinned the root of its account.
    #[test]
    fn a_key_that_connect_lists_in_a_store_signs_nothing_also_in_an_active_group() {
        for shared in [false, true] {
            let cloud = cloud();
            let a = connect_mac(&cloud, "a");
            let m = connect_mac(&cloud, "m");
            let mut account_a = new_account(&cloud, &a, "Rafal", true);
            let account_m = new_account(&cloud, &m, "Ola", false);
            let owner_id = account_a.state().account_id.clone();
            cloud.connect.make_group(&owner_id, "family");
            cloud
                .connect
                .add_member(&owner_id, &account_m.state().account_id);
            let mut vault_a = a.mac.create();
            vault_a.add(item("Family", "SYNTH-family")).expect("add");
            let team = a
                .mac
                .sync
                .enable_on_connect(&mut vault_a, &mut account_a, "Family")
                .expect("enable")
                .team_id;
            let view = account_a.view().expect("view");
            assert_eq!(
                view.group.as_ref().map(|group| group.state.as_str()),
                Some("active")
            );
            let member = shared.then(|| {
                cloud
                    .connect
                    .list_in_store(&team, &account_m.state().device_id)
            });
            if shared {
                let stores = account_a.vault_stores().expect("stores");
                assert!(stores[0].shared, "Connect marks the store shared");
            }
            // The relay's own key, listed as a device of the store.
            let first = cloud.relay.heads_of(&team)[0].clone();
            let relay_key = AccountSigner::open_or_create(&MemoryKeyStore::new()).unwrap();
            let number = cloud
                .relay
                .add_store_device(&team, "Mac Studio", relay_key.public_key());
            cloud
                .relay
                .replace_store_from(&team, vec![forged_after(&first, number, &relay_key)]);
            assert_eq!(
                refused_after_a_fresh_list(&a.mac.sync, &mut vault_a),
                SyncError::Damaged,
                "shared: {shared}"
            );
            assert_eq!(titles(&vault_a), vec!["Family"]);
            if let Some(member) = member {
                // The member's device, which Connect lists in the store: refused too.
                cloud.relay.replace_store_from(
                    &team,
                    vec![forged_after(&first, member, &account_m.signer().unwrap())],
                );
                assert_eq!(
                    refused_after_a_fresh_list(&a.mac.sync, &mut vault_a),
                    SyncError::Damaged
                );
            }
            // The policy of this Mac holds its own key only.
            let policy = signer_policy(account_a.state());
            assert_eq!(
                policy.accepted,
                vec![account_a.signer().unwrap().public_key().to_vec()]
            );
            assert!(policy.left.is_empty());
        }
    }

    /// A device that left the account: the store does not get stuck on the head it pushed
    /// before it left (the version that this Mac merged), and no later version that it
    /// signs is taken.
    #[test]
    fn a_device_that_left_keeps_its_merged_head_and_signs_no_later_one() {
        let cloud = cloud();
        let a = connect_mac(&cloud, "a");
        let b = connect_mac(&cloud, "b");
        let mut account_a = new_account(&cloud, &a, "Rafal", true);
        let mut account_b = join_account(&cloud, &mut account_a, &b, "Synthetic Mac mini");
        let (mut vault_a, mut vault_b) = shared_vault(&a.mac, &b.mac);
        let team = a
            .mac
            .sync
            .enable_on_connect(&mut vault_a, &mut account_a, "Personal")
            .expect("enable on A")
            .team_id;
        vault_b.add(item("Beta", "SYNTH-beta")).expect("add");
        b.mac
            .sync
            .enable_on_connect(&mut vault_b, &mut account_b, "Personal")
            .expect("enable on B");
        assert_eq!(cloud.relay.version_of(&team), 2);
        a.mac
            .sync
            .sync(&mut vault_a)
            .expect("A merges B's version 2");
        assert_eq!(titles(&vault_a), vec!["Alpha", "Beta"]);

        // A removes B with a signed entry, and its relay sync takes the new policy, as the
        // window does after each refresh.
        let owner = owner();
        let target = account_a
            .view()
            .unwrap()
            .devices
            .into_iter()
            .find(|device| device.device_id == account_b.state().device_id)
            .unwrap();
        let (proof, epoch) = owner.proof(account_a.revoke_action(&target));
        account_a.revoke(&target, proof, &epoch).expect("revoke");
        a.mac
            .sync
            .set_account_signers(Some(signer_policy(account_a.state())));
        // The current head is still B's version 2: the store goes on, and A signs a head
        // of its own over it with the same content.
        assert!(a.mac.sync.sync(&mut vault_a).expect("not stuck").pushed);
        assert_eq!(cloud.relay.version_of(&team), 3);
        // A later version that B signs (a relay that still takes it): not taken.
        let heads = cloud.relay.heads_of(&team);
        let b_number = HeadFields::parse(&heads[1].text).unwrap().device_id;
        cloud.relay.replace_store_from(
            &team,
            vec![forged_after(
                &heads[2],
                b_number,
                &account_b.signer().unwrap(),
            )],
        );
        assert_eq!(
            a.mac.sync.sync(&mut vault_a).unwrap_err(),
            SyncError::WaitsForAccountDevice
        );
        assert_eq!(titles(&vault_a), vec!["Alpha", "Beta"]);
    }

    /// Revoke the device `device_id` from `account` with a fresh owner check, as Settings ›
    /// Connect does.
    fn revoke_device(account: &mut ConnectAccount, device_id: &str) {
        let owner = owner();
        let target = account
            .view()
            .expect("view")
            .devices
            .into_iter()
            .find(|device| device.device_id == device_id)
            .expect("the device");
        let (proof, epoch) = owner.proof(account.revoke_action(&target));
        account.revoke(&target, proof, &epoch).expect("revoke");
    }

    /// A head after `last` signed by `signer` as store device `device_id`, over a real
    /// sync copy of `vault`: a copy that merges.
    fn copy_after(
        last: &StoredHead,
        device_id: u64,
        signer: &AccountSigner,
        vault: &mut Vault,
        work: &std::path::Path,
    ) -> (StoredHead, Vec<u8>) {
        let path = work.join(format!("forged-{}", last.version + 1));
        let copy = vault.write_sync_copy(&path, "Synthetic").expect("copy");
        let bytes = fs::read(&path).expect("read copy");
        fs::remove_file(&path).expect("remove copy");
        let fields = HeadFields {
            version: last.version + 1,
            previous: last.hash(),
            snapshot_sha256: sha256_hex(&bytes),
            size: bytes.len() as u64,
            device_id,
            ..HeadFields::parse(&last.text).expect("head")
        };
        let hex: String = copy.sha256.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(sha256_hex(&bytes), hex);
        let signed = signer.sign_head(fields).expect("sign");
        (
            StoredHead {
                version: last.version + 1,
                text: signed.text,
                signature: signed.signature,
                device_id,
            },
            bytes,
        )
    }

    /// The device that signed the head of version `version` of `team`, by its store number.
    fn signer_of(cloud: &Cloud, team: &str, version: u64) -> u64 {
        let heads = cloud.relay.heads_of(team);
        let head = heads
            .iter()
            .find(|head| head.version == version)
            .expect("head");
        HeadFields::parse(&head.text).expect("fields").device_id
    }

    /// A second device of the same account gets the vault from the account's store with no
    /// link and no local copy: the join, the download, the adoption, and later syncs, with
    /// the policy of its own account file from the first request on. A removal reaches its
    /// running session through the policy slot of its relay sync, as the window sets it.
    #[test]
    fn a_second_device_gets_the_vault_from_the_store_and_follows_removals() {
        let cloud = cloud();
        let a = connect_mac(&cloud, "a");
        let b = connect_mac(&cloud, "b");
        let c = connect_mac(&cloud, "c");
        let mut account_a = new_account(&cloud, &a, "Rafal", true);
        let mut account_b = join_account(&cloud, &mut account_a, &b, "Synthetic Mac mini");
        let mut account_c = join_account(&cloud, &mut account_a, &c, "Synthetic iMac");
        let (mut vault_a, mut vault_c) = shared_vault(&a.mac, &c.mac);
        let team = a
            .mac
            .sync
            .enable_on_connect(&mut vault_a, &mut account_a, "Personal")
            .expect("enable on A")
            .team_id;
        c.mac
            .sync
            .enable_on_connect(&mut vault_c, &mut account_c, "Personal")
            .expect("enable on C");

        // B has no copy of the vault: it takes the copy of the store that lists it.
        let store = account_b
            .vault_stores()
            .expect("stores")
            .into_iter()
            .find(|store| store.team_id == team)
            .expect("B is in the store");
        let joined = RelaySync::joined_from_store(&mut account_b, &store).expect("joined");
        let download = joined.download(&b.mac.data.join("sync")).expect("download");
        let (vault, _) = b.mac.sync.adopt(&joined, &download, PASS).expect("adopt");
        drop((vault, download, joined));
        // The window hands the key and the policy to the relay sync of the new vault.
        b.mac
            .sync
            .set_account_signer(Some(account_b.signer().expect("signer")));
        b.mac
            .sync
            .set_account_signers(Some(signer_policy(account_b.state())));
        let mut vault_b = Vault::open(&b.mac.vault_path).expect("open");
        vault_b.unlock(PASS).expect("unlock");
        assert_eq!(titles(&vault_b), vec!["Alpha"]);
        assert!(
            vault_b
                .relay_device()
                .expect("row")
                .expect("on")
                .uses_account_key()
        );

        // Later syncs: A's change reaches B, and B's reaches A.
        vault_a.add(item("Beta", "SYNTH-beta")).expect("add");
        assert!(a.mac.sync.sync(&mut vault_a).expect("A").pushed);
        b.mac.sync.sync(&mut vault_b).expect("B merges A");
        assert_eq!(titles(&vault_b), vec!["Alpha", "Beta"]);
        vault_b.add(item("Gamma", "SYNTH-gamma")).expect("add");
        assert!(b.mac.sync.sync(&mut vault_b).expect("B").pushed);
        a.mac.sync.sync(&mut vault_a).expect("A merges B");
        assert_eq!(titles(&vault_a), vec!["Alpha", "Beta", "Gamma"]);

        // A removes C; B learns it at its next view, and its running session takes the
        // new policy from the slot: a later head of C is not merged.
        revoke_device(&mut account_a, &account_c.state().device_id.clone());
        account_b.view().expect("B views the account");
        b.mac
            .sync
            .set_account_signers(Some(signer_policy(account_b.state())));
        let heads = cloud.relay.heads_of(&team);
        let last = heads.last().expect("head").clone();
        let c_key = account_c.signer().expect("signer").public_key().to_vec();
        let c_number = cloud
            .relay
            .team_devices(&team)
            .into_iter()
            .find(|(_, key)| *key == c_key)
            .map(|(number, _)| number)
            .expect("C is a device of the store at the relay");
        vault_c.add(item("Delta", "SYNTH-delta")).expect("add");
        let forged = copy_after(
            &last,
            c_number,
            &account_c.signer().expect("signer"),
            &mut vault_c,
            &c.mac.data,
        );
        cloud.relay.replace_store_from(&team, vec![forged]);
        assert!(
            b.mac.sync.sync(&mut vault_b).is_err(),
            "a head of a device that left is not merged by the running session"
        );
        assert_eq!(titles(&vault_b), vec!["Alpha", "Beta", "Gamma"]);
    }

    /// A store that holds a device of another account, with no share of it that this
    /// device verified (connect-account-v1 section 16), is refused before anything is
    /// asked or made.
    #[test]
    fn a_store_of_another_account_is_refused_before_any_request() {
        let cloud = cloud();
        let a = connect_mac(&cloud, "a");
        let m = connect_mac(&cloud, "m");
        let mut account_a = new_account(&cloud, &a, "Rafal", true);
        let mut account_m = new_account(&cloud, &m, "Ola", false);
        let owner_id = account_a.state().account_id.clone();
        cloud.connect.make_group(&owner_id, "family");
        cloud
            .connect
            .add_member(&owner_id, &account_m.state().account_id);
        let mut vault_a = a.mac.create();
        vault_a.add(item("Family", "SYNTH-family")).expect("add");
        let team = a
            .mac
            .sync
            .enable_on_connect(&mut vault_a, &mut account_a, "Family")
            .expect("enable")
            .team_id;
        cloud
            .connect
            .list_in_store(&team, &account_m.state().device_id);
        let store = account_m
            .vault_stores()
            .expect("stores")
            .into_iter()
            .find(|store| store.team_id == team)
            .expect("the store lists the member's device");
        let before = cloud.connect.log().len();
        let refused = RelaySync::joined_from_store(&mut account_m, &store);
        let text = refused
            .as_ref()
            .err()
            .map(ToString::to_string)
            .unwrap_or_default();
        assert_eq!(
            text,
            "This vault is shared with another account, and this device has not verified the share yet. Open Settings › Connect, then try again.",
            "refused with its own text"
        );
        assert_eq!(cloud.connect.log().len(), before, "nothing was asked");
        assert!(!m.mac.vault_path.exists());
    }

    /// Three devices of one account; B is behind when C pushes, and C then leaves. B waits
    /// with a text of its own (never "damaged"), and so does a new device with no anchor.
    /// A, whose own anchor head is C's, pushes a head of its own over it at its next sync
    /// (the same content), so B and the new device take the copy again.
    #[test]
    fn a_device_behind_a_head_of_a_device_that_left_waits_and_a_live_device_signs_over_it() {
        let cloud = cloud();
        let a = connect_mac(&cloud, "a");
        let b = connect_mac(&cloud, "b");
        let c = connect_mac(&cloud, "c");
        let d = connect_mac(&cloud, "d");
        let mut account_a = new_account(&cloud, &a, "Rafal", true);
        let mut account_b = join_account(&cloud, &mut account_a, &b, "Synthetic Mac mini");
        let mut account_c = join_account(&cloud, &mut account_a, &c, "Synthetic iMac");
        let mut vaults = shared_vaults(&a.mac, &[&b.mac, &c.mac]);
        let mut vault_c = vaults.pop().expect("c");
        let mut vault_b = vaults.pop().expect("b");
        let mut vault_a = vaults.pop().expect("a");
        let team = a
            .mac
            .sync
            .enable_on_connect(&mut vault_a, &mut account_a, "Personal")
            .expect("enable on A")
            .team_id;
        b.mac
            .sync
            .enable_on_connect(&mut vault_b, &mut account_b, "Personal")
            .expect("enable on B");
        c.mac
            .sync
            .enable_on_connect(&mut vault_c, &mut account_c, "Personal")
            .expect("enable on C");
        // C pushes; A merges it; B is behind.
        vault_c.add(item("Gamma", "SYNTH-gamma")).expect("add");
        assert!(c.mac.sync.sync(&mut vault_c).expect("C").pushed);
        let c_version = cloud.relay.version_of(&team);
        a.mac.sync.sync(&mut vault_a).expect("A merges C");
        assert_eq!(titles(&vault_a), vec!["Alpha", "Gamma"]);

        // C leaves the account.
        revoke_device(&mut account_a, &account_c.state().device_id.clone());
        a.mac
            .sync
            .set_account_signers(Some(signer_policy(account_a.state())));
        account_b.view().expect("B views");
        b.mac
            .sync
            .set_account_signers(Some(signer_policy(account_b.state())));
        // A device that joins now, with no anchor.
        let mut account_d = join_account(&cloud, &mut account_a, &d, "Synthetic MacBook Air");
        a.mac
            .sync
            .register_account_devices(&mut account_a)
            .expect("register D");
        let waiting = "waiting for another device of this account to sync";
        let behind = b.mac.sync.sync(&mut vault_b).unwrap_err();
        assert!(
            behind.to_string().to_lowercase().contains(waiting),
            "B waits: {behind}"
        );
        assert_ne!(behind, SyncError::Damaged);
        let store = account_d
            .vault_stores()
            .expect("stores")
            .into_iter()
            .find(|store| store.team_id == team)
            .expect("D is in the store");
        let joined_d = RelaySync::joined_from_store(&mut account_d, &store).expect("joined");
        let early = joined_d.download(&d.mac.data.join("sync")).map(|_| ());
        assert!(
            early
                .unwrap_err()
                .to_string()
                .to_lowercase()
                .contains(waiting),
            "a device with no anchor waits too"
        );

        // A's next sync: its own anchor head is C's, so it pushes a head of its own over
        // it with the same content.
        let outcome = a.mac.sync.sync(&mut vault_a).expect("A");
        assert!(outcome.pushed, "A signs over the head of C");
        assert_eq!(cloud.relay.version_of(&team), c_version + 1);
        assert_ne!(
            signer_of(&cloud, &team, c_version + 1),
            signer_of(&cloud, &team, c_version)
        );
        // Nothing more to push after that.
        assert!(!a.mac.sync.sync(&mut vault_a).expect("A again").pushed);
        // B takes the copy now: C's head is vouched for by A's head after it.
        b.mac.sync.sync(&mut vault_b).expect("B goes on");
        assert_eq!(titles(&vault_b), vec!["Alpha", "Gamma"]);
        // The new device downloads and adopts it.
        let download = joined_d
            .download(&d.mac.data.join("sync"))
            .expect("D downloads");
        let (vault_d, _) = d.mac.sync.adopt(&joined_d, &download, PASS).expect("adopt");
        drop(vault_d);
    }

    /// A live device changed the vault after the head of a device that left: a device that
    /// is behind both takes the chain (the head of the live device vouches for the one
    /// before it), so its copy is not forked.
    #[test]
    fn a_head_of_a_device_that_left_inside_the_chain_is_vouched_for_by_a_live_head() {
        let cloud = cloud();
        let a = connect_mac(&cloud, "a");
        let b = connect_mac(&cloud, "b");
        let c = connect_mac(&cloud, "c");
        let mut account_a = new_account(&cloud, &a, "Rafal", true);
        let mut account_b = join_account(&cloud, &mut account_a, &b, "Synthetic Mac mini");
        let mut account_c = join_account(&cloud, &mut account_a, &c, "Synthetic iMac");
        let mut vaults = shared_vaults(&a.mac, &[&b.mac, &c.mac]);
        let mut vault_c = vaults.pop().expect("c");
        let mut vault_b = vaults.pop().expect("b");
        let mut vault_a = vaults.pop().expect("a");
        for (mac, vault, account) in [
            (&a, &mut vault_a, &mut account_a),
            (&b, &mut vault_b, &mut account_b),
            (&c, &mut vault_c, &mut account_c),
        ] {
            mac.mac
                .sync
                .enable_on_connect(vault, account, "Personal")
                .expect("enable");
        }
        vault_c.add(item("Gamma", "SYNTH-gamma")).expect("add");
        assert!(c.mac.sync.sync(&mut vault_c).expect("C").pushed);
        a.mac.sync.sync(&mut vault_a).expect("A merges C");
        revoke_device(&mut account_a, &account_c.state().device_id.clone());
        a.mac
            .sync
            .set_account_signers(Some(signer_policy(account_a.state())));
        vault_a.add(item("Delta", "SYNTH-delta")).expect("add");
        assert!(a.mac.sync.sync(&mut vault_a).expect("A").pushed);
        account_b.view().expect("B views");
        b.mac
            .sync
            .set_account_signers(Some(signer_policy(account_b.state())));
        b.mac.sync.sync(&mut vault_b).expect("not forked");
        assert_eq!(titles(&vault_b), vec!["Alpha", "Delta", "Gamma"]);
    }

    /// A vault store has no device link: the relay refuses to make one (its devices come
    /// from the account), so no Mac joins a store with a link, of this account or of
    /// another. A member of a family has no way into a store of another account: no store
    /// lists its device, and one that Connect marks shared is refused before any request
    /// (`a_store_of_another_account_is_refused_before_any_request`). Against a service that
    /// hides that flag only the signer policy refuses: the heads of a device of another
    /// account are not merged
    /// (`a_device_of_another_account_in_a_store_not_marked_shared_signs_nothing`).
    #[test]
    fn a_vault_store_has_no_device_link() {
        let cloud = cloud();
        let a = connect_mac(&cloud, "a");
        let m = connect_mac(&cloud, "m");
        let mut account_a = new_account(&cloud, &a, "Rafal", true);
        let mut account_m = new_account(&cloud, &m, "Ola", false);
        let owner_id = account_a.state().account_id.clone();
        cloud.connect.make_group(&owner_id, "family");
        cloud
            .connect
            .add_member(&owner_id, &account_m.state().account_id);
        let mut vault_a = a.mac.create();
        vault_a.add(item("Family", "SYNTH-family")).expect("add");
        let team = a
            .mac
            .sync
            .enable_on_connect(&mut vault_a, &mut account_a, "Family")
            .expect("enable")
            .team_id;
        assert!(account_m.vault_stores().expect("stores").is_empty());
        assert!(
            a.mac.sync.create_link(&vault_a).is_err(),
            "the relay makes no device link for a vault store"
        );
        assert_eq!(cloud.relay.team_devices(&team).len(), 1);
    }

    /// A vault of Mac A on the old (hosted) relay with a team code, and the relay sync
    /// of the same vault for the Connect origin.
    struct Moving {
        cloud: Cloud,
        old: FakeRelay,
        a: Mac,
        keys: MemoryKeyStore,
        account: ConnectAccount,
        to_connect: RelaySync,
        vault: Vault,
    }

    fn moving() -> Moving {
        let cloud = cloud();
        let old = FakeRelay::start();
        let a = mac(&cloud.root, "a", &old.url);
        let mut vault = a.create();
        vault.add(item("Alpha", "SYNTH-alpha")).expect("add");
        a.sync
            .create_team(
                &mut vault,
                "Personal",
                &old.team_code(),
                "Synthetic MacBook",
            )
            .expect("team");
        assert_eq!(old.version(), 1);
        let keys = MemoryKeyStore::new();
        let (account, _) = ConnectAccount::create(
            client(&cloud),
            &keys,
            &account_file(&a.data),
            "Rafal",
            "Synthetic MacBook",
        )
        .expect("account");
        cloud.connect.entitle(&account.state().account_id);
        let to_connect = RelaySync::new(RelayConfig::in_data_dir(
            &a.data,
            &a.vault_path,
            &cloud.connect.url,
            "vault.connect",
        ));
        Moving {
            cloud,
            old,
            a,
            keys,
            account,
            to_connect,
            vault,
        }
    }

    #[test]
    fn moving_the_relay_copy_pushes_to_connect_first_and_deletes_the_old_copy_second() {
        let Moving {
            cloud,
            old,
            a,
            keys: _keys,
            mut account,
            to_connect,
            vault,
        } = moving();
        let vault_id = vault.sync_identity().expect("identity").vault_id;
        let account_id = account.state().account_id.clone();
        // Hold the delete of the old copy and look at both relays at that moment.
        let hold = old.hold("DELETE /v1/sync", Duration::from_secs(20));
        let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
        let path = a.vault_path.clone();
        let mover = {
            let shared = Arc::clone(&shared);
            let from = a.sync.clone();
            let to = to_connect.clone();
            std::thread::spawn(move || {
                let canonical = fs::canonicalize(&path).expect("path");
                let result = from.move_to_connect_shared(
                    &to,
                    &shared,
                    move |vault| vault.path() == canonical,
                    &mut account,
                    "Personal",
                );
                (result, account)
            })
        };
        hold.wait_entered();
        let team = cloud
            .connect
            .store_of(&account_id, &vault_id)
            .expect("the store is there before the delete");
        assert_eq!(
            cloud.relay.version_of(&team),
            1,
            "Connect has the copy first"
        );
        assert_eq!(old.version(), 1, "the old copy is still there");
        assert_eq!(
            a.sync.pending_move().map(|record| record.step),
            Some(MoveStep::Pushed)
        );
        hold.release();
        let (result, _account) = mover.join().expect("thread");
        let report = result.expect("moved");
        assert_eq!(report.team_id, team);
        assert_eq!(old.version(), 0, "the old copy is deleted second");
        assert!(a.sync.pending_move().is_none(), "the record goes");
        assert!(
            a.sync.state().expect("state").is_none(),
            "the old sync is off"
        );
        assert!(to_connect.state().expect("state").is_some());
        let guard = shared.lock().unwrap();
        let vault = guard.as_ref().expect("vault");
        let row = vault.relay_device().expect("row").expect("on");
        assert!(row.uses_account_key());
        assert_eq!(row.team_id, team);
        assert_eq!(titles(vault), vec!["Alpha"]);
    }

    #[test]
    fn a_failure_between_the_steps_of_a_move_leaves_both_copies_with_a_clear_state() {
        let Moving {
            cloud,
            old,
            a,
            keys: _keys,
            mut account,
            to_connect,
            mut vault,
        } = moving();
        let vault_id = vault.sync_identity().expect("identity").vault_id;
        let account_id = account.state().account_id.clone();
        old.fail_next("DELETE /v1/sync", 1, 403);
        let failure = a
            .sync
            .move_to_connect(&to_connect, &mut vault, &mut account, "Personal")
            .unwrap_err();
        assert_eq!(failure.step, Some(MoveStep::Pushed));
        assert!(failure.to_string().contains("Both copies are kept"));
        let team = cloud
            .connect
            .store_of(&account_id, &vault_id)
            .expect("store");
        assert_eq!(cloud.relay.version_of(&team), 1, "the Connect copy");
        assert_eq!(old.version(), 1, "the old copy");
        assert_eq!(
            a.sync.pending_move().map(|record| record.step),
            Some(MoveStep::Pushed)
        );
        // The vault still syncs with the old relay, and nothing is lost.
        assert!(
            !vault
                .relay_device()
                .expect("row")
                .expect("on")
                .uses_account_key()
        );
        vault.add(item("Beta", "SYNTH-beta")).expect("add");
        assert!(a.sync.sync(&mut vault).expect("sync").pushed);
        assert_eq!(old.version(), 2);

        // The same call again goes on: Connect gets the change, then the old copy goes.
        let report = a
            .sync
            .move_to_connect(&to_connect, &mut vault, &mut account, "Personal")
            .expect("retry");
        assert_eq!(report.team_id, team);
        assert_eq!(old.version(), 0);
        assert!(a.sync.pending_move().is_none());
        assert!(
            cloud.relay.version_of(&team) >= 2,
            "the change went to Connect"
        );
        assert_eq!(titles(&vault), vec!["Alpha", "Beta"]);

        // Undo after a failed delete: the Connect copy goes, the relay copy stays.
        let Moving {
            cloud,
            old,
            a,
            keys: _keys,
            mut account,
            to_connect,
            mut vault,
        } = moving();
        old.fail_next("DELETE /v1/sync", 1, 403);
        let failure = a
            .sync
            .move_to_connect(&to_connect, &mut vault, &mut account, "Personal")
            .unwrap_err();
        assert_eq!(failure.step, Some(MoveStep::Pushed));
        let record = a.sync.pending_move().expect("record");
        let owner = owner();
        let (proof, epoch) =
            owner.proof(ConnectAccount::delete_vault_store_action(&record.team_id));
        a.sync.undo_move(&mut account, proof, &epoch).expect("undo");
        assert!(
            !cloud.relay.has_team(&record.team_id),
            "the Connect copy is gone"
        );
        assert_eq!(old.version(), 1, "the relay copy stays");
        assert!(a.sync.pending_move().is_none());
        assert!(a.sync.sync(&mut vault).is_ok(), "the old sync goes on");
    }

    #[test]
    fn a_read_only_plan_shows_the_state_and_keeps_pulls() {
        let cloud = cloud();
        let a = connect_mac(&cloud, "a");
        let b = connect_mac(&cloud, "b");
        let mut account_a = new_account(&cloud, &a, "Rafal", true);
        let mut account_b = join_account(&cloud, &mut account_a, &b, "Synthetic Mac mini");
        let (mut vault_a, mut vault_b) = shared_vault(&a.mac, &b.mac);
        let team = a
            .mac
            .sync
            .enable_on_connect(&mut vault_a, &mut account_a, "Personal")
            .expect("enable A")
            .team_id;
        b.mac
            .sync
            .enable_on_connect(&mut vault_b, &mut account_b, "Personal")
            .expect("enable B");
        vault_a.add(item("Gamma", "SYNTH-gamma")).expect("add");
        assert!(a.mac.sync.sync(&mut vault_a).expect("sync").pushed);
        let version = cloud.relay.version_of(&team);

        // The plan ends: read-only for 30 days.
        let until = 1_900_000_000;
        cloud.connect.set_plan(
            &account_a.state().account_id,
            json!({"plan": "personal", "status": "read_only", "entitled": false,
                   "interval": "month", "quantity": 1, "renews_at": null,
                   "ends_at": 1_897_400_000, "grace_until": null,
                   "read_only_until": until, "delete_at": 1_905_200_000, "group_id": null}),
        );
        let plan = StorePlan::from_view(&account_b.plan().expect("plan"));
        assert_eq!(plan, StorePlan::ReadOnly { until: Some(until) });
        assert!(!plan.pushes());

        // B pulls A's change, and its own change stays on B: the push is refused.
        vault_b.add(item("Delta", "SYNTH-delta")).expect("add");
        let refused = b.mac.sync.sync(&mut vault_b).unwrap_err();
        assert_eq!(refused, SyncError::Relay(RelayRefusal::PlanRequired));
        assert!(is_plan_refusal(refused));
        assert_eq!(titles(&vault_b), vec!["Alpha", "Delta", "Gamma"]);
        assert_eq!(cloud.relay.version_of(&team), version, "no push");
        // The next pull still works and keeps the change.
        assert_eq!(
            b.mac.sync.sync(&mut vault_b).unwrap_err(),
            SyncError::Relay(RelayRefusal::PlanRequired)
        );
        assert!(b.mac.sync.local_changed(&vault_b).expect("changed"));
        assert_eq!(titles(&vault_b), vec!["Alpha", "Delta", "Gamma"]);
    }

    /// Two devices of one account: B pushes last, then A removes it before A merged that
    /// head. A waits, and the core keeps the details of the head for the window: B's key
    /// (which A's verified list names), the version, the hash, and B's time.
    struct LeftLast {
        cloud: Cloud,
        a: ConnectMac,
        account_a: ConnectAccount,
        account_b: ConnectAccount,
        vault_a: Vault,
        team: String,
    }

    fn b_pushed_last_and_left() -> LeftLast {
        let cloud = cloud();
        let a = connect_mac(&cloud, "a");
        let b = connect_mac(&cloud, "b");
        let mut account_a = new_account(&cloud, &a, "Rafal", true);
        let mut account_b = join_account(&cloud, &mut account_a, &b, "Synthetic Mac mini");
        let (mut vault_a, mut vault_b) = shared_vault(&a.mac, &b.mac);
        let team = a
            .mac
            .sync
            .enable_on_connect(&mut vault_a, &mut account_a, "Personal")
            .expect("enable on A")
            .team_id;
        b.mac
            .sync
            .enable_on_connect(&mut vault_b, &mut account_b, "Personal")
            .expect("enable on B");
        // B pushes last; A has not merged it.
        vault_b.add(item("Beta", "SYNTH-beta")).expect("add");
        assert!(b.mac.sync.sync(&mut vault_b).expect("B").pushed);
        revoke_device(&mut account_a, &account_b.state().device_id.clone());
        a.mac
            .sync
            .set_account_signers(Some(signer_policy(account_a.state())));
        LeftLast {
            cloud,
            a,
            account_a,
            account_b,
            vault_a,
            team,
        }
    }

    impl LeftLast {
        /// A waits on B's last head; the details name it.
        fn waits(&mut self) -> apassy::sync::DepartedHead {
            assert_eq!(
                self.a.mac.sync.sync(&mut self.vault_a).unwrap_err(),
                SyncError::WaitsForAccountDevice
            );
            let head = self.a.mac.sync.waiting_head().expect("the waiting head");
            let last = self
                .cloud
                .relay
                .heads_of(&self.team)
                .last()
                .cloned()
                .unwrap();
            let fields = HeadFields::parse(&last.text).expect("fields");
            assert_eq!(head.version, last.version);
            assert_eq!(head.head_hash, last.hash());
            assert_eq!(head.time, fields.time);
            assert_eq!(head.device_id, fields.device_id);
            let b_key = self.account_b.signer().unwrap().public_key().to_vec();
            assert_eq!(head.key, b_key);
            // The signed name of the removed device, from the list verified from version 1.
            self.account_a.view().expect("view");
            assert_eq!(
                self.account_a
                    .verified_list()
                    .and_then(|list| list.removed_name(&head.key)),
                Some("Synthetic Mac mini")
            );
            head
        }
    }

    /// "Use the Copy That … Left…": A takes B's last head once, merges it, and signs a head
    /// of its own over it; the next sync is a plain one.
    #[test]
    fn the_owner_takes_the_copy_that_a_removed_device_left_once() {
        let mut left = b_pushed_last_and_left();
        let head = left.waits();
        let version = left.cloud.relay.version_of(&left.team);
        let outcome = left
            .a
            .mac
            .sync
            .use_departed_copy(&mut left.vault_a, &head)
            .expect("the owner takes the copy");
        assert!(outcome.merge.is_some(), "B's copy merged");
        assert!(outcome.pushed, "A signs over it");
        assert_eq!(titles(&left.vault_a), vec!["Alpha", "Beta"]);
        assert_eq!(left.cloud.relay.version_of(&left.team), version + 1);
        assert_ne!(
            signer_of(&left.cloud, &left.team, version + 1),
            signer_of(&left.cloud, &left.team, version)
        );
        assert_eq!(left.a.mac.sync.waiting_head(), None, "nothing waits");
        let again = left
            .a
            .mac
            .sync
            .sync(&mut left.vault_a)
            .expect("a plain sync");
        assert!(!again.pushed);
        assert!(again.merge.is_none());
    }

    /// The step re-checks the relay copy: a later head of the removed device is not the one
    /// that the owner saw, so it is not taken, and the details name the new head.
    #[test]
    fn a_head_that_changed_meanwhile_is_not_taken() {
        let mut left = b_pushed_last_and_left();
        let head = left.waits();
        let last = left
            .cloud
            .relay
            .heads_of(&left.team)
            .last()
            .cloned()
            .unwrap();
        left.cloud.relay.replace_store_from(
            &left.team,
            vec![forged_after(
                &last,
                head.device_id,
                &left.account_b.signer().unwrap(),
            )],
        );
        assert_eq!(
            left.a
                .mac
                .sync
                .use_departed_copy(&mut left.vault_a, &head)
                .unwrap_err(),
            SyncError::WaitsForAccountDevice
        );
        assert_eq!(titles(&left.vault_a), vec!["Alpha"]);
        let now = left.a.mac.sync.waiting_head().expect("the new head");
        assert_eq!(now.version, head.version + 1);
        assert_ne!(now.head_hash, head.head_hash);
        // Another signer than the one that the owner saw is not taken either.
        let mut other = now.clone();
        other.key = left.account_a.signer().unwrap().public_key().to_vec();
        assert_eq!(
            left.a
                .mac
                .sync
                .use_departed_copy(&mut left.vault_a, &other)
                .unwrap_err(),
            SyncError::Damaged,
            "a key that did not leave the list is refused"
        );
    }

    /// "Replace It with This Mac's Copy…": A pushes its own copy over B's last head; the
    /// next sync is a plain one.
    #[test]
    fn the_owner_replaces_the_copy_that_a_removed_device_left() {
        let mut left = b_pushed_last_and_left();
        left.waits();
        let version = left.cloud.relay.version_of(&left.team);
        let outcome = left
            .a
            .mac
            .sync
            .replace_relay_copy(&mut left.vault_a)
            .expect("replace");
        assert!(outcome.pushed);
        assert_eq!(left.cloud.relay.version_of(&left.team), version + 1);
        assert_eq!(titles(&left.vault_a), vec!["Alpha"], "no merge");
        let again = left
            .a
            .mac
            .sync
            .sync(&mut left.vault_a)
            .expect("a plain sync");
        assert!(!again.pushed);
        assert_eq!(left.a.mac.sync.waiting_head(), None);
    }

    /// A new device with no anchor waits on the head that a removed device left too; the
    /// owner takes it once at the download, the adoption makes it the anchor, and the first
    /// sync signs a head of the new device over it. The device was removed before the new
    /// device joined: its signed name comes from the list verified from version 1.
    #[test]
    fn a_new_device_takes_the_copy_that_a_removed_device_left() {
        let mut left = b_pushed_last_and_left();
        let d = connect_mac(&left.cloud, "d");
        let mut account_d = join_account(&left.cloud, &mut left.account_a, &d, "Synthetic iMac");
        left.a
            .mac
            .sync
            .register_account_devices(&mut left.account_a)
            .expect("register D");
        left.a
            .mac
            .sync
            .set_account_signers(Some(signer_policy(left.account_a.state())));
        let store = account_d
            .vault_stores()
            .expect("stores")
            .into_iter()
            .find(|store| store.team_id == left.team)
            .expect("D is in the store");
        let joined = RelaySync::joined_from_store(&mut account_d, &store).expect("joined");
        let work = d.mac.data.join("sync");
        assert_eq!(
            joined.download(&work).unwrap_err(),
            SyncError::WaitsForAccountDevice
        );
        let head = joined.waiting_head().expect("the waiting head");
        assert_eq!(head.version, left.cloud.relay.version_of(&left.team));
        assert_eq!(
            account_d
                .verified_list()
                .and_then(|list| list.removed_name(&head.key)),
            Some("Synthetic Mac mini")
        );
        let download = joined.download_departed(&work, &head).expect("download");
        let (vault, _) = d.mac.sync.adopt(&joined, &download, PASS).expect("adopt");
        drop((vault, download, joined));
        d.mac
            .sync
            .set_account_signer(Some(account_d.signer().expect("signer")));
        d.mac
            .sync
            .set_account_signers(Some(signer_policy(account_d.state())));
        let mut vault_d = Vault::open(&d.mac.vault_path).expect("open");
        vault_d.unlock(PASS).expect("unlock");
        assert_eq!(titles(&vault_d), vec!["Alpha", "Beta"]);
        assert!(
            d.mac.sync.sync(&mut vault_d).expect("D").pushed,
            "D signs over the head that B left"
        );
        assert!(!d.mac.sync.sync(&mut vault_d).expect("D again").pushed);
        // A, which was behind, takes the copy now as usual.
        left.a.mac.sync.sync(&mut left.vault_a).expect("A goes on");
        assert_eq!(titles(&left.vault_a), vec!["Alpha", "Beta"]);
        // A later head of the removed device (a store that still lists it) waits again:
        // the owner took one head, not the device.
        let b_signer = left.account_b.signer().expect("B's key");
        let b_number = left
            .cloud
            .relay
            .team_devices(&left.team)
            .into_iter()
            .find(|(_, key)| key.as_slice() == b_signer.public_key())
            .map(|(number, _)| number)
            .expect("B in the store");
        let last = left
            .cloud
            .relay
            .heads_of(&left.team)
            .last()
            .cloned()
            .unwrap();
        let later = forged_after(&last, b_number, &b_signer);
        left.cloud.relay.replace_store_from(&left.team, vec![later]);
        assert_eq!(
            d.mac.sync.sync(&mut vault_d).unwrap_err(),
            SyncError::WaitsForAccountDevice,
            "a later head of the removed device waits again"
        );
        assert_eq!(titles(&vault_d), vec!["Alpha", "Beta"]);
    }

    /// A new device that takes the copy that a removed device left checks the chain below
    /// that head as at any first download: an entry by a key that the device list never
    /// held is refused, and nothing is downloaded.
    #[test]
    fn a_new_device_checks_the_chain_below_the_copy_that_a_removed_device_left() {
        let mut left = b_pushed_last_and_left();
        let heads = left.cloud.relay.heads_of(&left.team);
        let below = heads[heads.len() - 2].clone();
        let stranger = AccountSigner::open_or_create(&MemoryKeyStore::new()).unwrap();
        let stranger_number =
            left.cloud
                .relay
                .add_store_device(&left.team, "Mac Studio", stranger.public_key());
        let b_signer = left.account_b.signer().expect("B's key");
        let b_number = left
            .cloud
            .relay
            .team_devices(&left.team)
            .into_iter()
            .find(|(_, key)| key.as_slice() == b_signer.public_key())
            .map(|(number, _)| number)
            .expect("B in the store");
        let entry = forged_after(&below, stranger_number, &stranger);
        let top = forged_after(&entry.0, b_number, &b_signer);
        left.cloud
            .relay
            .replace_store_from(&left.team, vec![entry, top]);
        let d = connect_mac(&left.cloud, "d");
        let mut account_d = join_account(&left.cloud, &mut left.account_a, &d, "Synthetic iMac");
        left.a
            .mac
            .sync
            .register_account_devices(&mut left.account_a)
            .expect("register D");
        let store = account_d
            .vault_stores()
            .expect("stores")
            .into_iter()
            .find(|store| store.team_id == left.team)
            .expect("D is in the store");
        let joined = RelaySync::joined_from_store(&mut account_d, &store).expect("joined");
        let work = d.mac.data.join("sync");
        assert_eq!(
            joined.download(&work).unwrap_err(),
            SyncError::WaitsForAccountDevice
        );
        let head = joined.waiting_head().expect("the waiting head");
        assert_eq!(
            joined.download_departed(&work, &head).unwrap_err(),
            SyncError::Damaged,
            "the chain below the head holds a key that was never a device"
        );
    }

    /// A head by a key that the device list never held stays refused: no waiting head is
    /// kept, and the core refuses to take it, for a vault and at a download.
    #[test]
    fn a_head_by_a_key_never_in_the_list_cannot_be_taken() {
        let cloud = cloud();
        let a = connect_mac(&cloud, "a");
        let mut account_a = new_account(&cloud, &a, "Rafal", true);
        let mut vault_a = a.mac.create();
        vault_a.add(item("Alpha", "SYNTH-alpha")).expect("add");
        let team = a
            .mac
            .sync
            .enable_on_connect(&mut vault_a, &mut account_a, "Personal")
            .expect("enable")
            .team_id;
        let first = cloud.relay.heads_of(&team)[0].clone();
        let stranger = AccountSigner::open_or_create(&MemoryKeyStore::new()).unwrap();
        let number = cloud
            .relay
            .add_store_device(&team, "Mac Studio", stranger.public_key());
        let (forged, bytes) = forged_after(&first, number, &stranger);
        let hash = forged.hash();
        cloud.relay.replace_store_from(&team, vec![(forged, bytes)]);
        assert_eq!(
            refused_after_a_fresh_list(&a.mac.sync, &mut vault_a),
            SyncError::Damaged
        );
        assert_eq!(a.mac.sync.waiting_head(), None, "nothing to offer");
        let attempt = apassy::sync::DepartedHead {
            key: stranger.public_key().to_vec(),
            device_id: number,
            version: 2,
            head_hash: hash,
            time: 0,
        };
        assert_eq!(
            a.mac
                .sync
                .use_departed_copy(&mut vault_a, &attempt)
                .unwrap_err(),
            SyncError::Damaged
        );
        assert_eq!(titles(&vault_a), vec!["Alpha"]);
        assert_eq!(cloud.relay.version_of(&team), 2, "nothing pushed");
        // A new device of the account refuses it at the download too.
        let d = connect_mac(&cloud, "d");
        let mut account_d = join_account(&cloud, &mut account_a, &d, "Synthetic iMac");
        a.mac
            .sync
            .register_account_devices(&mut account_a)
            .expect("register D");
        let store = account_d
            .vault_stores()
            .expect("stores")
            .into_iter()
            .find(|store| store.team_id == team)
            .expect("D is in the store");
        let joined = RelaySync::joined_from_store(&mut account_d, &store).expect("joined");
        let work = d.mac.data.join("sync");
        assert_eq!(joined.download(&work).unwrap_err(), SyncError::Damaged);
        assert_eq!(joined.waiting_head(), None);
        assert_eq!(
            joined.download_departed(&work, &attempt).unwrap_err(),
            SyncError::Damaged
        );
    }

    /// Three devices of one account; A's relay sync has the policy of before C joined. A
    /// chain entry of C below a head of B is not a fork: A checks the device list first,
    /// and merges the chain once the fresh list holds C, with no offer.
    #[test]
    fn a_chain_entry_by_a_device_of_a_fresh_list_merges_after_the_refresh() {
        let cloud = cloud();
        let a = connect_mac(&cloud, "a");
        let b = connect_mac(&cloud, "b");
        let c = connect_mac(&cloud, "c");
        let mut account_a = new_account(&cloud, &a, "Rafal", true);
        let mut account_b = join_account(&cloud, &mut account_a, &b, "Synthetic Mac mini");
        let mut vaults = shared_vaults(&a.mac, &[&b.mac, &c.mac]);
        let mut vault_c = vaults.pop().expect("c");
        let mut vault_b = vaults.pop().expect("b");
        let mut vault_a = vaults.pop().expect("a");
        a.mac
            .sync
            .enable_on_connect(&mut vault_a, &mut account_a, "Personal")
            .expect("enable on A");
        b.mac
            .sync
            .enable_on_connect(&mut vault_b, &mut account_b, "Personal")
            .expect("enable on B");
        a.mac.sync.sync(&mut vault_a).expect("A");
        // C joins through B; A's relay sync keeps the policy it had.
        let mut account_c = join_account(&cloud, &mut account_b, &c, "Synthetic iMac");
        b.mac
            .sync
            .set_account_signers(Some(signer_policy(account_b.state())));
        b.mac
            .sync
            .register_account_devices(&mut account_b)
            .expect("register C");
        c.mac
            .sync
            .enable_on_connect(&mut vault_c, &mut account_c, "Personal")
            .expect("enable on C");
        vault_c.add(item("Gamma", "SYNTH-gamma")).expect("add");
        assert!(c.mac.sync.sync(&mut vault_c).expect("C").pushed);
        b.mac.sync.sync(&mut vault_b).expect("B merges C");
        vault_b.add(item("Beta", "SYNTH-beta")).expect("add");
        assert!(b.mac.sync.sync(&mut vault_b).expect("B").pushed);

        assert_eq!(
            a.mac.sync.sync(&mut vault_a).unwrap_err(),
            SyncError::ChecksDeviceList,
            "not a forked copy"
        );
        assert_eq!(
            a.mac.sync.sync(&mut vault_a).unwrap_err(),
            SyncError::ChecksDeviceList,
            "no fresh list yet"
        );
        assert_eq!(titles(&vault_a), vec!["Alpha"]);
        // The window's refresh: the fresh list holds C.
        account_a.view().expect("A views the account");
        a.mac
            .sync
            .set_account_signers(Some(signer_policy(account_a.state())));
        a.mac.sync.note_device_list(std::time::Instant::now());
        a.mac
            .sync
            .sync(&mut vault_a)
            .expect("merged after the refresh");
        assert_eq!(titles(&vault_a), vec!["Alpha", "Beta", "Gamma"]);
    }

    /// A chain entry by a key that no device list holds: A checks the device list first;
    /// a fresh list still refuses it, and only then is the copy refused, with "Use the
    /// relay copy…" as the way on, which takes the head of a device of the account.
    #[test]
    fn a_chain_entry_by_an_unknown_key_is_refused_after_a_fresh_list() {
        let cloud = cloud();
        let a = connect_mac(&cloud, "a");
        let b = connect_mac(&cloud, "b");
        let mut account_a = new_account(&cloud, &a, "Rafal", true);
        let mut account_b = join_account(&cloud, &mut account_a, &b, "Synthetic Mac mini");
        let (mut vault_a, mut vault_b) = shared_vault(&a.mac, &b.mac);
        let team = a
            .mac
            .sync
            .enable_on_connect(&mut vault_a, &mut account_a, "Personal")
            .expect("enable on A")
            .team_id;
        b.mac
            .sync
            .enable_on_connect(&mut vault_b, &mut account_b, "Personal")
            .expect("enable on B");
        a.mac.sync.sync(&mut vault_a).expect("A");
        let last = cloud.relay.heads_of(&team).last().cloned().unwrap();
        let stranger = AccountSigner::open_or_create(&MemoryKeyStore::new()).unwrap();
        let number = cloud
            .relay
            .add_store_device(&team, "Mac Studio", stranger.public_key());
        let entry = forged_after(&last, number, &stranger);
        let b_key = account_b.signer().unwrap().public_key().to_vec();
        let b_number = cloud
            .relay
            .team_devices(&team)
            .into_iter()
            .find(|(_, key)| *key == b_key)
            .map(|(number, _)| number)
            .expect("B is a device of the store");
        vault_b.add(item("Beta", "SYNTH-beta")).expect("add");
        let head = copy_after(
            &entry.0,
            b_number,
            &account_b.signer().unwrap(),
            &mut vault_b,
            &b.mac.data,
        );
        cloud.relay.replace_store_from(&team, vec![entry, head]);

        let asked_before = std::time::Instant::now();
        assert_eq!(
            a.mac.sync.sync(&mut vault_a).unwrap_err(),
            SyncError::ChecksDeviceList
        );
        assert!(a.mac.sync.checking_since().is_some());
        // A list asked of Connect before the refusal ends nothing.
        a.mac.sync.note_device_list(asked_before);
        assert_eq!(
            a.mac.sync.sync(&mut vault_a).unwrap_err(),
            SyncError::ChecksDeviceList,
            "a list older than the refusal"
        );
        account_a.view().expect("A views the account");
        a.mac
            .sync
            .set_account_signers(Some(signer_policy(account_a.state())));
        a.mac.sync.note_device_list(std::time::Instant::now());
        assert_eq!(
            a.mac.sync.sync(&mut vault_a).unwrap_err(),
            SyncError::UnknownSigner,
            "the fresh list still refuses it"
        );
        assert_eq!(titles(&vault_a), vec!["Alpha"]);
        a.mac
            .sync
            .use_relay_copy(&mut vault_a)
            .expect("the owner uses the relay copy");
        assert_eq!(titles(&vault_a), vec!["Alpha", "Beta"]);
    }

    /// A store that Connect does not mark shared, with a device of another account among
    /// its signers at the relay: the signer policy of this Mac refuses its heads, so nothing
    /// is merged. Against a service that hides the flag only the policy refuses.
    #[test]
    fn a_device_of_another_account_in_a_store_not_marked_shared_signs_nothing() {
        let cloud = cloud();
        let a = connect_mac(&cloud, "a");
        let m = connect_mac(&cloud, "m");
        let mut account_a = new_account(&cloud, &a, "Rafal", true);
        let mut account_m = new_account(&cloud, &m, "Ola", false);
        let owner_id = account_a.state().account_id.clone();
        cloud.connect.make_group(&owner_id, "family");
        cloud
            .connect
            .add_member(&owner_id, &account_m.state().account_id);
        let mut vault_a = a.mac.create();
        vault_a.add(item("Family", "SYNTH-family")).expect("add");
        let team = a
            .mac
            .sync
            .enable_on_connect(&mut vault_a, &mut account_a, "Family")
            .expect("enable")
            .team_id;
        // The member's device is a signer of the store at the relay; Connect lists nothing
        // of it, and does not mark the store shared.
        let member_key = account_m.signer().unwrap();
        let number = cloud
            .relay
            .add_store_device(&team, "Synthetic iMac", member_key.public_key());
        let stores = account_a.vault_stores().expect("stores");
        let store = stores
            .iter()
            .find(|store| store.team_id == team)
            .expect("the store");
        assert!(!store.shared, "Connect does not mark it shared");
        let first = cloud.relay.heads_of(&team)[0].clone();
        let copy_path = m.mac.data.join("copy-of-a.db");
        fs::copy(&a.mac.vault_path, &copy_path).expect("copy");
        let mut copy = Vault::open(&copy_path).expect("open");
        copy.unlock(PASS).expect("unlock");
        copy.add(item("From the member", "SYNTH-member"))
            .expect("add");
        let forged = copy_after(&first, number, &member_key, &mut copy, &m.mac.data);
        drop(copy);
        cloud.relay.replace_store_from(&team, vec![forged]);
        assert_eq!(
            refused_after_a_fresh_list(&a.mac.sync, &mut vault_a),
            SyncError::Damaged
        );
        assert_eq!(titles(&vault_a), vec!["Family"], "nothing merged");
        assert!(
            !account_m
                .vault_stores()
                .expect("stores")
                .iter()
                .any(|s| s.team_id == team)
        );
    }
}
