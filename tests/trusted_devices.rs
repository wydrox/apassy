#![cfg(feature = "vault")]

//! Trusted devices, relay memberships, and item homes across sync copies (schema 19,
//! stage 5 plan §A1). Synthetic values only.
//!
//! Trusted devices sync row by row: the later version wins, and a removal wins over any
//! edit. Relay memberships are local and never leave the Mac. The home of a mirror is a
//! child row of its credential and syncs with it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use apassy::contracts::CredentialKind;
use apassy::vault::{
    Field, ItemDraft, ItemHome, MembershipPurpose, RelayMembership, SecretValue, SyncScope,
    TrustedDeviceKind, Vault, VaultErrorKind,
};
use tempfile::TempDir;
use zeroize::Zeroizing;

const PASS: &str = "synthetic-trusted-sync-pass";

fn point(fill: u8) -> Vec<u8> {
    let mut key = vec![0x04];
    key.extend_from_slice(&[fill; 64]);
    key
}

fn item(title: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![Field {
            name: "token".to_owned(),
            value: SecretValue::new(format!("SYNTH-{title}")),
            secret: true,
        }],
    }
}

/// Mac A and Mac B, unlocked, with one vault.
struct World {
    dir: TempDir,
    a: Vault,
    b: Vault,
    pushes: usize,
}

impl World {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let mut a = Vault::create(&dir.path().join("a.db"), PASS).unwrap();
        a.unlock(PASS).unwrap();
        a.add(item("Alpha")).unwrap();
        let seed = dir.path().join("seed.apassy");
        a.write_sync_copy(&seed, "Mac A").unwrap();
        let (mut b, _) = Vault::adopt_sync_copy(&seed, &dir.path().join("b.db"), PASS).unwrap();
        b.unlock(PASS).unwrap();
        Self {
            dir,
            a,
            b,
            pushes: 0,
        }
    }

    fn copy_of(&mut self, from_a: bool) -> PathBuf {
        self.pushes += 1;
        let path = self.dir.path().join(format!("push-{}.apassy", self.pushes));
        if from_a {
            self.a.write_sync_copy(&path, "Mac A").unwrap();
        } else {
            self.b.write_sync_copy(&path, "Mac B").unwrap();
        }
        path
    }

    /// A takes the copy of B, then B takes the copy of A: both agree.
    fn sync_both(&mut self) {
        let from_b = self.copy_of(false);
        self.a.merge_from(&from_b, &SyncScope::vault()).unwrap();
        let from_a = self.copy_of(true);
        self.b.merge_from(&from_a, &SyncScope::vault()).unwrap();
        assert_eq!(
            self.a.sync_content(&SyncScope::vault()).unwrap(),
            self.b.sync_content(&SyncScope::vault()).unwrap()
        );
        assert_eq!(
            self.a.trusted_devices().unwrap(),
            self.b.trusted_devices().unwrap()
        );
    }
}

fn names(vault: &Vault) -> Vec<(String, String)> {
    vault
        .trusted_devices()
        .unwrap()
        .into_iter()
        .map(|device| (device.uuid, device.name))
        .collect()
}

fn id_of(vault: &Vault, title: &str) -> u64 {
    vault
        .search("")
        .unwrap()
        .into_iter()
        .find(|item| item.title == title)
        .unwrap()
        .id
}

/// The rows of `trusted_device` in the closed or open file at `path` with a removal.
fn removed_rows(path: &Path) -> i64 {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.pragma_update(None, "key", PASS).unwrap();
    let count = conn
        .query_row(
            "SELECT count(*) FROM trusted_device WHERE deleted_at IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    conn.close().map_err(|(_, e)| e).unwrap();
    count
}

#[test]
fn trusted_devices_merge_last_writer_wins_and_tombstone_wins() {
    let mut w = World::new();
    // Each device registers itself on its own Mac.
    w.a.register_trusted_device(
        "device-mac-a",
        "Synthetic MacBook",
        TrustedDeviceKind::Mac,
        &point(1),
        None,
    )
    .unwrap();
    w.b.register_trusted_device(
        "device-iphone",
        "Synthetic iPhone",
        TrustedDeviceKind::Iphone,
        &point(2),
        Some(&point(3)),
    )
    .unwrap();
    let before_any_removal = w.copy_of(false);
    w.sync_both();
    let mut both = names(&w.a);
    both.sort();
    assert_eq!(
        both,
        [
            ("device-iphone".to_owned(), "Synthetic iPhone".to_owned()),
            ("device-mac-a".to_owned(), "Synthetic MacBook".to_owned()),
        ]
    );
    let phone = w.a.trusted_device("device-iphone").unwrap().unwrap();
    assert_eq!(phone.answer_key, Some(point(3)));
    assert_eq!(phone.kind, TrustedDeviceKind::Iphone);

    // Last writer wins: both Macs rename the Mac device; the later name stays on both.
    w.a.register_trusted_device(
        "device-mac-a",
        "Name from A",
        TrustedDeviceKind::Mac,
        &point(1),
        None,
    )
    .unwrap();
    sleep(Duration::from_millis(5));
    w.b.register_trusted_device(
        "device-mac-a",
        "Name from B",
        TrustedDeviceKind::Mac,
        &point(4),
        None,
    )
    .unwrap();
    w.sync_both();
    let mac = w.a.trusted_device("device-mac-a").unwrap().unwrap();
    assert_eq!(mac.name, "Name from B");
    assert_eq!(mac.sign_key, point(4));
    assert_eq!(mac.updated_by, w.b.sync_device_id().unwrap());

    // The device numbers of each relay team travel with the row.
    w.a.set_trusted_device_relay_id("device-mac-a", "t_notify0001", 1)
        .unwrap();
    w.a.set_trusted_device_relay_id("device-mac-a", "t_shared0001", 3)
        .unwrap();
    w.b.set_trusted_device_relay_id("device-iphone", "t_notify0001", 2)
        .unwrap();
    w.sync_both();
    for (team, id, uuid) in [
        ("t_notify0001", 1, "device-mac-a"),
        ("t_shared0001", 3, "device-mac-a"),
        ("t_notify0001", 2, "device-iphone"),
    ] {
        for vault in [&w.a, &w.b] {
            let found = vault.trusted_device_by_relay_id(team, id).unwrap().unwrap();
            assert_eq!(found.uuid, uuid);
        }
    }
    assert_eq!(
        w.b.trusted_device("device-mac-a").unwrap().unwrap().name,
        "Name from B",
        "the later version carries the rename and the numbers"
    );

    // The removal wins over an edit, also over a later edit on the other Mac.
    assert!(w.a.remove_trusted_device("device-iphone").unwrap());
    sleep(Duration::from_millis(5));
    w.b.register_trusted_device(
        "device-iphone",
        "Renamed later",
        TrustedDeviceKind::Iphone,
        &point(5),
        Some(&point(6)),
    )
    .unwrap();
    let removal = w.copy_of(true);
    w.sync_both();
    for vault in [&w.a, &w.b] {
        assert_eq!(vault.trusted_device("device-iphone").unwrap(), None);
        assert_eq!(
            names(vault),
            [("device-mac-a".to_owned(), "Name from B".to_owned())]
        );
    }
    assert_eq!(removed_rows(&removal), 1, "the removal travels as a row");
    for vault in [&w.a, &w.b] {
        assert_eq!(
            vault.trusted_device_by_relay_id("t_notify0001", 2).unwrap(),
            None,
            "a removed device answers for no relay number"
        );
    }
    // A removed device cannot register again, on either Mac.
    for vault in [&mut w.a, &mut w.b] {
        assert_eq!(
            vault
                .register_trusted_device(
                    "device-iphone",
                    "Synthetic iPhone",
                    TrustedDeviceKind::Iphone,
                    &point(2),
                    None,
                )
                .unwrap_err()
                .kind(),
            VaultErrorKind::AlreadyExists
        );
    }
    // An old copy from before the removal does not bring the device back.
    let report =
        w.a.merge_from(&before_any_removal, &SyncScope::vault())
            .unwrap();
    assert_eq!(report.folders, 0);
    assert_eq!(w.a.trusted_device("device-iphone").unwrap(), None);
    assert_eq!(w.a.trusted_devices().unwrap().len(), 1);
}

#[test]
fn relay_memberships_stay_on_their_mac() {
    let mut w = World::new();
    w.a.add_relay_membership(&RelayMembership {
        team_id: "t_q0000000aa".to_owned(),
        relay_url: "https://relay.example.test".to_owned(),
        device_id: 4,
        public_key: point(8),
        key_pkcs8: Zeroizing::new(vec![0x3c; 138]),
        purposes: BTreeSet::from([MembershipPurpose::Questions]),
        created_at: 0,
    })
    .unwrap();
    let copy = w.copy_of(true);
    let conn = rusqlite::Connection::open(&copy).unwrap();
    conn.pragma_update(None, "key", PASS).unwrap();
    let rows: i64 = conn
        .query_row("SELECT count(*) FROM relay_membership", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(rows, 0, "a pushed copy carries no key of this Mac");
    conn.close().map_err(|(_, e)| e).unwrap();
    w.b.merge_from(&copy, &SyncScope::vault()).unwrap();
    assert!(w.b.relay_memberships().unwrap().is_empty());
    assert_eq!(w.a.relay_memberships().unwrap().len(), 1);
    // A Mac that adopts a raw vault file (never pushed) does not get its keys either.
    let solo_path = w.dir.path().join("solo.db");
    let mut solo = Vault::create(&solo_path, PASS).unwrap();
    solo.unlock(PASS).unwrap();
    solo.add_relay_membership(&RelayMembership {
        team_id: "t_q0000000bb".to_owned(),
        relay_url: "https://relay.example.test".to_owned(),
        device_id: 5,
        public_key: point(9),
        key_pkcs8: Zeroizing::new(vec![0x3d; 138]),
        purposes: BTreeSet::from([MembershipPurpose::Sync]),
        created_at: 0,
    })
    .unwrap();
    assert!(solo.relay_device().unwrap().is_some());
    drop(solo);
    let (mut c, _) = Vault::adopt_sync_copy(&solo_path, &w.dir.path().join("c.db"), PASS).unwrap();
    c.unlock(PASS).unwrap();
    assert!(c.relay_memberships().unwrap().is_empty());
    assert!(c.relay_device().unwrap().is_none());
}

#[test]
fn an_item_home_syncs_with_its_credential_and_not_with_a_conflict_copy() {
    let mut w = World::new();
    let home = ItemHome {
        shared_vault_uuid: "a1".repeat(16),
        home_uuid: "b2".repeat(16),
    };
    let alpha_a = id_of(&w.a, "Alpha");
    w.a.set_item_home(alpha_a, &home).unwrap();
    w.sync_both();
    let alpha_b = id_of(&w.b, "Alpha");
    assert_eq!(w.b.item_home(alpha_b).unwrap(), Some(home.clone()));

    // Both Macs change the mirror: one conflict copy, and only the credential is the
    // mirror.
    let edit = |vault: &mut Vault, id: u64, title: &str| {
        let revision = vault.details(id).unwrap().summary.revision;
        let mut draft = item("Alpha");
        draft.notes = title.to_owned();
        vault.update(id, revision, draft).unwrap();
    };
    edit(&mut w.a, alpha_a, "from A");
    sleep(Duration::from_millis(5));
    edit(&mut w.b, alpha_b, "from B");
    let from_b = w.copy_of(false);
    let report = w.a.merge_from(&from_b, &SyncScope::vault()).unwrap();
    assert_eq!(report.conflicts.len(), 1);
    let homes: Vec<Option<ItemHome>> =
        w.a.search("")
            .unwrap()
            .into_iter()
            .map(|summary| w.a.item_home(summary.id).unwrap())
            .collect();
    assert_eq!(homes.iter().filter(|h| h.is_some()).count(), 1, "{homes:?}");
    assert_eq!(w.a.item_home(alpha_a).unwrap(), Some(home));

    // Clearing the home is a change of the credential that syncs.
    assert!(w.a.clear_item_home(alpha_a).unwrap());
    let from_a = w.copy_of(true);
    w.b.merge_from(&from_a, &SyncScope::vault()).unwrap();
    assert_eq!(w.b.item_home(alpha_b).unwrap(), None);
}
