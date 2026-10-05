#![cfg(feature = "vault")]

//! The device store of the iPhone companion (ADR 0020, vault schema 15): the setting,
//! the certificate, and the paired devices. A device is added only with an owner proof
//! for `OwnerAction::PairCompanion`. All data is synthetic.

#[path = "support/companion.rs"]
mod companion_support;

use std::sync::Arc;

use apassy::broker::approvals::{OwnerAction, OwnerCheck, ProofRefusal};
use apassy::companion::crypto::certificate_pin;
use apassy::vault::{
    AddDeviceError, CompanionSetting, DEFAULT_COMPANION_PORT, MAX_COMPANION_DEVICES, Vault,
    VaultErrorKind,
};
use companion_support::{DEVICE, PASS, PhoneKey, fixture};
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};

fn other_id(index: usize) -> String {
    format!("{index:032x}")
}

#[test]
fn the_companion_is_off_on_the_default_port_and_has_nothing() {
    let fx = fixture();
    fx.with(|vault| {
        assert_eq!(
            vault.companion_setting().expect("setting"),
            CompanionSetting {
                enabled: false,
                port: 48620
            }
        );
        assert_eq!(DEFAULT_COMPANION_PORT, 48620);
        assert!(vault.companion_devices().expect("devices").is_empty());
        assert!(
            vault
                .companion_certificate()
                .expect("certificate")
                .is_none()
        );
        assert!(vault.companion_device(DEVICE).expect("device").is_none());
        assert!(vault.companion_device_keys(DEVICE).expect("keys").is_none());
    });
}

#[test]
fn the_setting_and_the_port_change_without_a_proof_and_stay() {
    let fx = fixture();
    fx.with(|vault| {
        vault.set_companion_enabled(true).expect("on");
        vault.set_companion_port(50_000).expect("port");
        assert_eq!(
            vault.companion_setting().expect("setting"),
            CompanionSetting {
                enabled: true,
                port: 50_000
            }
        );
        // Below 1024 is refused and changes nothing.
        for port in [0, 80, 1023] {
            assert_eq!(
                vault.set_companion_port(port).unwrap_err().kind(),
                VaultErrorKind::InvalidInput
            );
        }
        vault.set_companion_port(1024).expect("lowest port");
        vault.set_companion_port(65_535).expect("highest port");
        vault.set_companion_enabled(false).expect("off");
        vault.set_companion_enabled(true).expect("on");
        // A lock and an unlock keep the setting.
        vault.lock().expect("lock");
        assert_eq!(
            vault.companion_setting().unwrap_err().kind(),
            VaultErrorKind::Locked
        );
        assert_eq!(
            vault.set_companion_enabled(false).unwrap_err().kind(),
            VaultErrorKind::Locked
        );
        vault.unlock(PASS).expect("unlock");
        assert_eq!(
            vault.companion_setting().expect("setting"),
            CompanionSetting {
                enabled: true,
                port: 65_535
            }
        );
    });
}

#[test]
fn the_certificate_is_made_once_and_is_a_usable_p256_key() {
    let fx = fixture();
    let (first, second) = fx.with(|vault| {
        let first = vault.ensure_companion_certificate().expect("first");
        let second = vault.ensure_companion_certificate().expect("second");
        assert_eq!(
            vault
                .companion_certificate()
                .expect("read")
                .expect("some")
                .der,
            first.der
        );
        (first, second)
    });
    assert_eq!(first.der, second.der);
    assert_eq!(first.key.as_slice(), second.key.as_slice());
    // DER: a SEQUENCE. The key parses as ECDSA P-256 in PKCS#8.
    assert_eq!(first.der[0], 0x30);
    let rng = ring::rand::SystemRandom::new();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &first.key, &rng)
        .expect("the key is an ECDSA P-256 PKCS#8 key");
    // The listener can serve it: rustls accepts the certificate with its key, and checks
    // that they belong together.
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(first.key.to_vec());
    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(first.der.clone())],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key),
        )
        .expect("the certificate and the key match");
    // The pin is the hash of the DER.
    assert_eq!(certificate_pin(&first.der).len(), 43);
    // Debug shows no key.
    let debug = format!("{first:?}");
    assert!(debug.contains("[redacted]"));
    // Another vault makes another certificate.
    let other = fixture();
    let other_cert = other.with(|vault| vault.ensure_companion_certificate().expect("cert"));
    assert_ne!(other_cert.der, first.der);
    assert_ne!(other_cert.key.as_slice(), first.key.as_slice());
    // The certificate stays across a lock and an unlock.
    fx.with(|vault| {
        vault.lock().expect("lock");
        vault.unlock(PASS).expect("unlock");
        assert_eq!(
            vault
                .companion_certificate()
                .expect("read")
                .expect("some")
                .der,
            first.der
        );
    });
}

#[test]
fn a_device_is_added_with_a_proof_and_listed_with_its_keys() {
    let fx = fixture();
    let (request, approval) = (PhoneKey::generate(), PhoneKey::generate());
    let device = fx
        .pair(DEVICE, "Test iPhone", &request.public(), &approval.public())
        .expect("pair");
    assert_eq!(device.device_id, DEVICE);
    assert_eq!(device.name, "Test iPhone");
    assert_eq!(device.last_seen_at, None);
    assert!(device.paired_at > 1_700_000_000);
    fx.with(|vault| {
        let listed = vault.companion_devices().expect("devices");
        assert_eq!(listed, vec![device.clone()]);
        assert_eq!(
            vault.companion_device(DEVICE).expect("device"),
            Some(device.clone())
        );
        let keys = vault
            .companion_device_keys(DEVICE)
            .expect("keys")
            .expect("paired");
        assert_eq!(keys.request_key, request.public());
        assert_eq!(keys.approval_key, approval.public());
        assert!(
            vault
                .companion_device_keys(&other_id(1))
                .expect("keys")
                .is_none()
        );
        // The last-seen time.
        assert!(
            vault
                .touch_companion_device(DEVICE, 1_790_000_123)
                .expect("touch")
        );
        assert_eq!(
            vault
                .companion_device(DEVICE)
                .expect("device")
                .expect("paired")
                .last_seen_at,
            Some(1_790_000_123)
        );
        assert!(
            !vault
                .touch_companion_device(&other_id(1), 5)
                .expect("touch")
        );
        // The device stays across a lock and an unlock.
        vault.lock().expect("lock");
        vault.unlock(PASS).expect("unlock");
        assert_eq!(vault.companion_devices().expect("devices").len(), 1);
    });
}

#[test]
fn a_proof_for_another_action_or_other_values_adds_nothing() {
    let fx = fixture();
    let (request, approval) = (PhoneKey::generate(), PhoneKey::generate());
    let (rk, ak) = (request.public(), approval.public());
    let add = |proof, id: &str, name: &str, request_key: &[u8], approval_key: &[u8]| {
        fx.with(|vault| vault.add_companion_device(proof, id, name, request_key, approval_key))
    };
    // A proof for another owner action.
    let reveal = fx
        .gate
        .authorize(
            OwnerAction::Reveal { item_id: 1 },
            OwnerCheck::passphrase(PASS),
        )
        .expect("proof");
    assert!(matches!(
        add(reveal, DEVICE, "Test iPhone", &rk, &ak),
        Err(AddDeviceError::Proof(ProofRefusal::WrongAction))
    ));
    // A proof for another device ID, name, request key, or approval key.
    let for_other_id = fx.pair_proof(&other_id(7), "Test iPhone", &rk, &ak);
    assert!(matches!(
        add(for_other_id, DEVICE, "Test iPhone", &rk, &ak),
        Err(AddDeviceError::Proof(ProofRefusal::WrongAction))
    ));
    let for_other_name = fx.pair_proof(DEVICE, "Other name", &rk, &ak);
    assert!(matches!(
        add(for_other_name, DEVICE, "Test iPhone", &rk, &ak),
        Err(AddDeviceError::Proof(ProofRefusal::WrongAction))
    ));
    let for_swapped_keys = fx.pair_proof(DEVICE, "Test iPhone", &ak, &rk);
    assert!(matches!(
        add(for_swapped_keys, DEVICE, "Test iPhone", &rk, &ak),
        Err(AddDeviceError::Proof(ProofRefusal::WrongAction))
    ));
    let attacker = PhoneKey::generate();
    let for_attacker_key = fx.pair_proof(DEVICE, "Test iPhone", &rk, &attacker.public());
    assert!(matches!(
        add(for_attacker_key, DEVICE, "Test iPhone", &rk, &ak),
        Err(AddDeviceError::Proof(ProofRefusal::WrongAction))
    ));
    fx.with(|vault| assert!(vault.companion_devices().expect("devices").is_empty()));
}

#[test]
fn a_proof_from_another_vault_session_adds_nothing() {
    let fx = fixture();
    let (request, approval) = (PhoneKey::generate(), PhoneKey::generate());
    let proof = fx.pair_proof(DEVICE, "Test iPhone", &request.public(), &approval.public());
    // A lock and an unlock end the session of the proof.
    fx.with(|vault| {
        vault.lock().expect("lock");
        vault.unlock(PASS).expect("unlock");
    });
    let result = fx.with(|vault| {
        vault.add_companion_device(
            proof,
            DEVICE,
            "Test iPhone",
            &request.public(),
            &approval.public(),
        )
    });
    assert!(matches!(
        result,
        Err(AddDeviceError::Proof(ProofRefusal::OtherSession))
    ));
    assert!(result.unwrap_err().message().contains("Confirm again"));
    fx.with(|vault| assert!(vault.companion_devices().expect("devices").is_empty()));
}

#[test]
fn a_locked_vault_adds_nothing() {
    let fx = fixture();
    let (request, approval) = (PhoneKey::generate(), PhoneKey::generate());
    let proof = fx.pair_proof(DEVICE, "Test iPhone", &request.public(), &approval.public());
    let result = fx.with(|vault| {
        vault.lock().expect("lock");
        vault.add_companion_device(
            proof,
            DEVICE,
            "Test iPhone",
            &request.public(),
            &approval.public(),
        )
    });
    match result {
        Err(AddDeviceError::Vault(error)) => assert_eq!(error.kind(), VaultErrorKind::Locked),
        other => panic!("expected a locked vault, got {other:?}"),
    }
}

#[test]
fn a_bad_device_id_name_or_key_is_refused_also_with_a_proof() {
    let fx = fixture();
    let (request, approval) = (PhoneKey::generate(), PhoneKey::generate());
    let (rk, ak) = (request.public(), approval.public());
    let cases: Vec<(String, String, Vec<u8>, Vec<u8>)> = vec![
        (
            "D4C0FFEE00000000000000000000BEEF".to_owned(),
            "Test iPhone".to_owned(),
            rk.clone(),
            ak.clone(),
        ),
        (
            DEVICE[..31].to_owned(),
            "Test iPhone".to_owned(),
            rk.clone(),
            ak.clone(),
        ),
        (
            DEVICE.to_owned(),
            " Test iPhone".to_owned(),
            rk.clone(),
            ak.clone(),
        ),
        (
            DEVICE.to_owned(),
            "Test\niPhone".to_owned(),
            rk.clone(),
            ak.clone(),
        ),
        (DEVICE.to_owned(), String::new(), rk.clone(), ak.clone()),
        (DEVICE.to_owned(), "n".repeat(41), rk.clone(), ak.clone()),
        // Unicode `White_Space` at an end, and a scalar count over 40 in bytes and
        // scalars (contract section 2).
        (
            DEVICE.to_owned(),
            "\u{a0}Test iPhone".to_owned(),
            rk.clone(),
            ak.clone(),
        ),
        (
            DEVICE.to_owned(),
            "Test iPhone\u{3000}".to_owned(),
            rk.clone(),
            ak.clone(),
        ),
        (
            DEVICE.to_owned(),
            "\u{1f600}".repeat(41),
            rk.clone(),
            ak.clone(),
        ),
        (
            DEVICE.to_owned(),
            "Test\u{9f}iPhone".to_owned(),
            rk.clone(),
            ak.clone(),
        ),
        (
            DEVICE.to_owned(),
            "Test iPhone".to_owned(),
            rk[..64].to_vec(),
            ak.clone(),
        ),
        (DEVICE.to_owned(), "Test iPhone".to_owned(), rk.clone(), {
            let mut key = ak.clone();
            key[0] = 0x02;
            key
        }),
    ];
    for (id, name, request_key, approval_key) in cases {
        let proof = fx.pair_proof(&id, &name, &request_key, &approval_key);
        let result = fx.with(|vault| {
            vault.add_companion_device(proof, &id, &name, &request_key, &approval_key)
        });
        assert!(
            matches!(result, Err(AddDeviceError::Invalid)),
            "{id:?} {name:?}"
        );
    }
    fx.with(|vault| assert!(vault.companion_devices().expect("devices").is_empty()));
}

#[test]
fn a_device_id_is_paired_once() {
    let fx = fixture();
    let (request, approval) = (PhoneKey::generate(), PhoneKey::generate());
    fx.pair(DEVICE, "Test iPhone", &request.public(), &approval.public())
        .expect("pair");
    let again = PhoneKey::generate();
    let result = fx.pair(DEVICE, "Attacker", &again.public(), &again.public());
    assert!(matches!(result, Err(AddDeviceError::AlreadyPaired)));
    // The first device keeps its keys.
    fx.with(|vault| {
        let keys = vault
            .companion_device_keys(DEVICE)
            .expect("keys")
            .expect("paired");
        assert_eq!(keys.approval_key, approval.public());
        assert_eq!(vault.companion_devices().expect("devices").len(), 1);
    });
}

#[test]
fn at_most_five_devices() {
    let fx = fixture();
    assert_eq!(MAX_COMPANION_DEVICES, 5);
    let key = PhoneKey::generate();
    for index in 0..MAX_COMPANION_DEVICES {
        fx.pair(
            &other_id(index),
            &format!("Phone {index}"),
            &key.public(),
            &key.public(),
        )
        .expect("pair");
    }
    let sixth = fx.pair(&other_id(99), "Phone 99", &key.public(), &key.public());
    match sixth {
        Err(error @ AddDeviceError::TooManyDevices) => {
            assert!(error.message().contains("at most 5 devices"));
        }
        other => panic!("expected the limit, got {other:?}"),
    }
    fx.with(|vault| {
        assert_eq!(vault.companion_devices().expect("devices").len(), 5);
        // Removing one makes room.
        assert!(vault.remove_companion_device(&other_id(2)).expect("remove"));
    });
    fx.pair(&other_id(99), "Phone 99", &key.public(), &key.public())
        .expect("the sixth device fits after a removal");
    fx.with(|vault| {
        let names: Vec<String> = vault
            .companion_devices()
            .expect("devices")
            .into_iter()
            .map(|device| device.name)
            .collect();
        assert_eq!(names.len(), 5);
        assert!(!names.contains(&"Phone 2".to_owned()));
        assert!(names.contains(&"Phone 99".to_owned()));
    });
}

#[test]
fn removing_a_device_needs_no_proof_and_removes_only_that_device() {
    let fx = fixture();
    let key = PhoneKey::generate();
    fx.pair(&other_id(1), "One", &key.public(), &key.public())
        .expect("pair");
    fx.pair(&other_id(2), "Two", &key.public(), &key.public())
        .expect("pair");
    fx.with(|vault| {
        assert!(vault.remove_companion_device(&other_id(1)).expect("remove"));
        assert!(!vault.remove_companion_device(&other_id(1)).expect("again"));
        assert!(
            vault
                .companion_device_keys(&other_id(1))
                .expect("keys")
                .is_none()
        );
        assert!(
            vault
                .companion_device_keys(&other_id(2))
                .expect("keys")
                .is_some()
        );
    });
}

#[test]
fn reset_removes_every_device_and_the_certificate_and_keeps_the_setting() {
    let fx = fixture();
    let key = PhoneKey::generate();
    let before = fx.with(|vault| {
        vault.set_companion_enabled(true).expect("on");
        vault.set_companion_port(50_001).expect("port");
        vault.ensure_companion_certificate().expect("certificate")
    });
    fx.pair(&other_id(1), "One", &key.public(), &key.public())
        .expect("pair");
    fx.pair(&other_id(2), "Two", &key.public(), &key.public())
        .expect("pair");
    fx.with(|vault| {
        vault.reset_companion_pairing().expect("reset");
        assert!(vault.companion_devices().expect("devices").is_empty());
        assert!(
            vault
                .companion_certificate()
                .expect("certificate")
                .is_none()
        );
        assert_eq!(
            vault.companion_setting().expect("setting"),
            CompanionSetting {
                enabled: true,
                port: 50_001
            }
        );
        // The next certificate is another one, so a phone with the old pin cannot connect.
        let after = vault
            .ensure_companion_certificate()
            .expect("new certificate");
        assert_ne!(after.der, before.der);
        // A reset with nothing to reset works.
        vault.reset_companion_pairing().expect("reset again");
        vault.reset_companion_pairing().expect("and again");
    });
}

#[test]
fn a_restore_removes_the_devices_and_the_certificate_and_turns_the_setting_off() {
    let fx = fixture();
    let key = PhoneKey::generate();
    let before = fx.with(|vault| {
        vault.set_companion_enabled(true).expect("on");
        vault.set_companion_port(50_002).expect("port");
        vault.ensure_companion_certificate().expect("certificate")
    });
    fx.pair(&other_id(1), "One", &key.public(), &key.public())
        .expect("pair");
    let backup = fx.dir.path().join("backup.db");
    fx.with(|vault| vault.backup(&backup).expect("backup"));
    // The backup has the device: opening it as it is, without a restore, shows it.
    let mut plain = Vault::open(&backup).expect("open the backup");
    plain.unlock(PASS).expect("unlock");
    assert_eq!(plain.companion_devices().expect("devices").len(), 1);
    assert!(
        plain
            .companion_certificate()
            .expect("certificate")
            .is_some()
    );
    drop(plain);
    // A restore revokes them.
    let mut restored =
        Vault::restore(&backup, &fx.dir.path().join("restored.db"), PASS).expect("restore");
    restored.unlock(PASS).expect("unlock");
    assert!(restored.companion_devices().expect("devices").is_empty());
    assert!(
        restored
            .companion_certificate()
            .expect("certificate")
            .is_none()
    );
    assert_eq!(
        restored.companion_setting().expect("setting"),
        CompanionSetting {
            enabled: false,
            port: 50_002
        }
    );
    assert!(
        restored
            .companion_device_keys(&other_id(1))
            .expect("keys")
            .is_none()
    );
    // The restored vault makes its own certificate.
    let new_cert = restored
        .ensure_companion_certificate()
        .expect("certificate");
    assert_eq!(new_cert.der[0], 0x30);
    assert_ne!(
        new_cert.der, before.der,
        "a restore makes a new listener identity"
    );
}

#[test]
fn the_vault_file_does_not_hold_the_certificate_key_in_plaintext() {
    let fx = fixture();
    let cert = fx.with(|vault| vault.ensure_companion_certificate().expect("certificate"));
    fx.with(|vault| vault.lock().expect("lock"));
    let path = fx.dir.path().join("companion.db");
    let file = std::fs::read(path).expect("read the vault file");
    let needle = &cert.key[cert.key.len() - 32..];
    assert!(
        !file.windows(needle.len()).any(|window| window == needle),
        "the SQLCipher file is encrypted"
    );
}

#[test]
fn sync_export_removes_companion_keys_and_merge_keeps_each_mac_pairing() {
    use apassy::broker::approvals::OwnerGate;
    use apassy::vault::SyncScope;
    use companion_support::Fixture;
    use std::sync::Mutex;

    let mac_a = fixture();
    let key_a = PhoneKey::generate();
    mac_a
        .pair(DEVICE, "Phone A", &key_a.public(), &key_a.public())
        .unwrap();
    let cert_a = mac_a.with(|v| {
        v.set_companion_enabled(true).unwrap();
        v.set_companion_port(50_101).unwrap();
        v.ensure_companion_certificate().unwrap()
    });
    // A generation zero backup can also be adopted or merged.
    let raw_seed = mac_a.dir.path().join("raw-seed.db");
    mac_a.with(|v| {
        v.backup(&raw_seed).unwrap();
        v.unlock(PASS).unwrap();
    });
    let pushed = mac_a.dir.path().join("pushed.db");
    mac_a.with(|v| v.write_sync_copy(&pushed, "Mac A").unwrap());
    let conn = rusqlite::Connection::open(&pushed).unwrap();
    conn.pragma_update(None, "key", PASS).unwrap();
    for table in ["companion_device", "companion_certificate"] {
        let rows: i64 = conn
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0, "no {table} in a synced file");
    }
    let setting: (i64, i64, i64) = conn
        .query_row("SELECT id, enabled, port FROM companion_setting", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!(setting, (1, 0, i64::from(DEFAULT_COMPANION_PORT)));
    conn.close().map_err(|(_, e)| e).unwrap();
    Vault::inspect_sync_copy(&pushed, PASS).expect("stripped copy digest and schema are valid");
    let dir_b = tempfile::TempDir::new().unwrap();
    let (mut vault_b, _) =
        Vault::adopt_sync_copy(&pushed, &dir_b.path().join("b.db"), PASS).unwrap();
    vault_b.unlock(PASS).unwrap();
    assert_eq!(
        vault_b.companion_setting().unwrap(),
        CompanionSetting {
            enabled: false,
            port: DEFAULT_COMPANION_PORT
        }
    );
    assert!(vault_b.companion_devices().unwrap().is_empty());
    assert!(vault_b.companion_certificate().unwrap().is_none());
    drop(vault_b);
    let (mut vault_b, _) =
        Vault::adopt_sync_copy(&raw_seed, &dir_b.path().join("raw-b.db"), PASS).unwrap();
    vault_b.unlock(PASS).unwrap();
    let shared = Arc::new(Mutex::new(Some(vault_b)));
    let mac_b = Fixture {
        dir: dir_b,
        gate: OwnerGate::new(Arc::clone(&shared), None),
        shared,
    };
    let key_b = PhoneKey::generate();
    mac_b
        .pair(&other_id(2), "Phone B", &key_b.public(), &key_b.public())
        .unwrap();
    let cert_b = mac_b.with(|v| {
        v.set_companion_enabled(true).unwrap();
        v.set_companion_port(50_102).unwrap();
        v.ensure_companion_certificate().unwrap()
    });
    assert_ne!(cert_a.der, cert_b.der);
    let backup_b = mac_b.dir.path().join("b-backup.db");
    mac_b.with(|v| {
        v.backup(&backup_b).unwrap();
        v.unlock(PASS).unwrap();
    });
    // A merge reads the record tables only, even when the source includes local keys.
    mac_a.with(|v| {
        v.merge_from(&backup_b, &SyncScope::vault()).unwrap();
        assert_eq!(
            v.companion_setting().unwrap(),
            CompanionSetting {
                enabled: true,
                port: 50_101
            }
        );
        assert_eq!(v.companion_devices().unwrap()[0].device_id, DEVICE);
        assert_eq!(v.companion_devices().unwrap().len(), 1);
        assert_eq!(v.companion_certificate().unwrap().unwrap().der, cert_a.der);
    });
    mac_b.with(|v| {
        assert_eq!(v.companion_devices().unwrap()[0].device_id, other_id(2));
        assert_eq!(v.companion_certificate().unwrap().unwrap().der, cert_b.der);
    });
}

#[test]
fn adopting_a_raw_generation_zero_vault_does_not_copy_companion_trust() {
    let mac_a = fixture();
    let key = PhoneKey::generate();
    mac_a
        .pair(DEVICE, "Raw source phone", &key.public(), &key.public())
        .unwrap();
    let certificate = mac_a.with(|v| {
        v.set_companion_enabled(true).unwrap();
        v.set_companion_port(50_103).unwrap();
        assert_eq!(v.sync_identity().unwrap().generation, 0);
        v.ensure_companion_certificate().unwrap()
    });
    let raw = mac_a.dir.path().join("raw.db");
    mac_a.with(|v| {
        v.backup(&raw).unwrap();
        v.unlock(PASS).unwrap();
    });
    Vault::inspect_sync_copy(&raw, PASS).expect("a generation zero vault is an allowed source");
    let (mut adopted, _) =
        Vault::adopt_sync_copy(&raw, &mac_a.dir.path().join("adopted.db"), PASS).unwrap();
    adopted.unlock(PASS).unwrap();
    assert!(adopted.companion_devices().unwrap().is_empty());
    assert!(adopted.companion_certificate().unwrap().is_none());
    assert_eq!(
        adopted.companion_setting().unwrap(),
        CompanionSetting {
            enabled: false,
            port: DEFAULT_COMPANION_PORT
        }
    );
    assert_ne!(
        adopted.ensure_companion_certificate().unwrap().der,
        certificate.der
    );
    mac_a.with(|v| {
        assert_eq!(v.companion_devices().unwrap()[0].device_id, DEVICE);
        assert_eq!(
            v.companion_setting().unwrap(),
            CompanionSetting {
                enabled: true,
                port: 50_103
            }
        );
        assert_eq!(
            v.companion_certificate().unwrap().unwrap().der,
            certificate.der
        );
    });
}
