#![cfg(feature = "vault")]
//! No real vault, Keychain or external relay. Every request goes to a local fake.
use crate::common::fake_relay::FakeRelay;
use apassy::questions::{QuestionsClient, device_link::link_device_name};
use apassy::relay::connect::{ConnectError, create_connect, prepare_connect};
use apassy::relay::membership::{
    adopt_questions_team, questions_membership, register_linked_device,
};
use apassy::relay::pairing::{HANDOFF_KEY_ID, PairingChannel};
use apassy::sync::{DeviceKey, PendingJoin};
use apassy::vault::{MembershipPurpose, Vault};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
const PASS: &str = "synthetic-connect-passphrase";
fn vault(dir: &TempDir) -> Vault {
    let mut vault = Vault::create(&dir.path().join("test.apassy"), PASS).unwrap();
    vault.unlock(PASS).unwrap();
    vault
}

#[test]
fn connect_persists_before_network_and_adopts_only_questions_after_restart() {
    let relay = FakeRelay::start();
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let pending = prepare_connect(&mut vault, &relay.url, "Personal", "Test Mac").unwrap();
    assert!(relay.log().is_empty());
    assert!(vault.relay_memberships().unwrap().is_empty());
    vault.lock().unwrap();
    vault.unlock(PASS).unwrap();
    let retry = prepare_connect(&mut vault, &relay.url, "Changed name", "Another name").unwrap();
    assert_eq!(pending.key_pkcs8, retry.key_pkcs8);
    assert_eq!(retry.team_name, "Personal");
    let export = dir.path().join("export.apassy");
    vault.write_sync_copy(&export, "Synthetic Mac").unwrap();
    let (mut copy, _) =
        Vault::adopt_sync_copy(&export, &dir.path().join("adopted.apassy"), PASS).unwrap();
    copy.unlock(PASS).unwrap();
    assert!(
        copy.pending_connect().unwrap().is_none(),
        "a synced/adopted copy never carries another device's pending key"
    );
    let membership = create_connect(&retry).unwrap();
    vault.keep_connect_result(&membership).unwrap();
    adopt_questions_team(&mut vault, &membership, "Test Mac").unwrap();
    assert!(
        vault.relay_device().unwrap().is_none(),
        "Connect never enables paid vault sync"
    );
    assert_eq!(
        membership.purposes.iter().copied().collect::<Vec<_>>(),
        vec![MembershipPurpose::Questions]
    );
    assert!(questions_membership(&vault).unwrap().is_some());
    assert!(vault.question_key().unwrap().is_some());
    assert_eq!(vault.trusted_devices().unwrap().len(), 1);
    let count = relay.log().len();
    let again = create_connect(&vault.pending_connect().unwrap().unwrap()).unwrap();
    assert_eq!(again.team_id, membership.team_id);
    assert_eq!(
        relay.log().len(),
        count,
        "a saved response needs no second creation"
    );
    let bodies = relay.request_bodies().join("\n");
    assert!(!bodies.contains("apassy_tcd_"));
    assert!(
        !bodies.contains("recovery_nonce"),
        "legacy create omits the new field entirely"
    );
    assert!(!bodies.contains("key_pkcs8"));
}

#[test]
fn lost_response_on_live_058_keeps_the_key_and_explains_recovery_is_unavailable() {
    let relay = FakeRelay::start();
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let pending = prepare_connect(&mut vault, &relay.url, "Free", "Mac").unwrap();
    relay.lose_next_answers("POST /v1/connect", 1);
    assert_eq!(create_connect(&pending).unwrap_err(), ConnectError::KeyUsed);
    vault.lock().unwrap();
    vault.unlock(PASS).unwrap();
    let retry = prepare_connect(&mut vault, &relay.url, "Free", "Mac").unwrap();
    assert_eq!(pending.key_pkcs8, retry.key_pkcs8);
    assert_eq!(create_connect(&retry).unwrap_err(), ConnectError::KeyUsed);
    assert!(questions_membership(&vault).unwrap().is_none());
    assert!(
        ConnectError::KeyUsed
            .to_string()
            .contains("Your key is saved")
    );
}

#[test]
fn lost_response_recovers_with_fresh_possession_proof_when_f06_becomes_available() {
    let relay = FakeRelay::start();
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let pending = prepare_connect(&mut vault, &relay.url, "Free", "Mac").unwrap();
    relay.lose_next_answers("POST /v1/connect", 1);
    assert_eq!(create_connect(&pending).unwrap_err(), ConnectError::KeyUsed);
    // Same saved attempt, relay upgraded, app restarted: no rotation and no new team.
    relay.support_connect_recovery();
    vault.lock().unwrap();
    vault.unlock(PASS).unwrap();
    let retry = vault.pending_connect().unwrap().unwrap();
    let membership = create_connect(&retry).unwrap();
    assert_eq!(pending.key_pkcs8, membership.key_pkcs8);
    let bodies = relay.request_bodies();
    assert!(bodies.iter().any(|body| body.contains("recovery_nonce")));
    vault.keep_connect_result(&membership).unwrap();
    adopt_questions_team(&mut vault, &membership, "Mac").unwrap();
}

#[test]
fn confirmed_join_hands_keys_only_to_the_confirmed_device_and_preserves_revocation() {
    let relay = FakeRelay::start();
    let dir = TempDir::new().unwrap();
    let mut mac = vault(&dir);
    let staged = prepare_connect(&mut mac, &relay.url, "Free", "Mac").unwrap();
    let membership = create_connect(&staged).unwrap();
    mac.keep_connect_result(&membership).unwrap();
    adopt_questions_team(&mut mac, &membership, "Mac").unwrap();
    let client = QuestionsClient::from_membership(&membership).unwrap();
    let code = client.create_link().unwrap();
    let channel = PairingChannel::generate().unwrap();
    let qr = channel.link(&code.link);
    let (raw, phone_channel) = PairingChannel::parse(&qr).unwrap();
    assert_eq!(raw, code.link.as_str());
    let answer = DeviceKey::generate().unwrap();
    let name = link_device_name("Test iPhone", answer.public_key()).unwrap();
    let phone = PendingJoin::request(raw, &relay.url, &name).unwrap();
    assert!(phone.poll().unwrap().is_none());
    let waiting = client.pending_links(Some(&code)).unwrap();
    let link = waiting.iter().find(|l| l.id == phone.link_id).unwrap();
    assert_eq!(link.safety.as_deref(), Some(phone.safety.as_str()));
    let device = client.confirm_link(link).unwrap();
    let trusted = register_linked_device(
        &mut mac,
        &membership.team_id,
        device.id,
        &link.device_name,
        &link.public_key,
    )
    .unwrap()
    .unwrap();
    let sealed = channel
        .seal(&mac, &membership.team_id, &link.public_key)
        .unwrap();
    assert_eq!(sealed.key_id, HANDOFF_KEY_ID);
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;
    channel.send(&client, expiry, &sealed).unwrap();
    let joined = phone.poll().unwrap().unwrap();
    let phone_client = QuestionsClient::from_member(joined.member());
    let handoff = phone_channel
        .receive(&phone_client, &membership.team_id, &link.public_key)
        .unwrap()
        .unwrap();
    assert_eq!(
        handoff.question_key.as_slice(),
        mac.question_key().unwrap().unwrap().bytes()
    );
    assert!(handoff.devices.iter().any(|d| d.uuid == trusted.uuid && d.answer_key.as_deref() == Some(answer.public_key())));
    // A different recipient or QR capability cannot open this handoff.
    assert!(
        phone_channel
            .receive(&phone_client, &membership.team_id, answer.public_key())
            .unwrap()
            .is_none()
    );
    assert!(
        PairingChannel::generate()
            .unwrap()
            .receive(&phone_client, &membership.team_id, &link.public_key)
            .unwrap()
            .is_none()
    );
    // Use a local encrypted copy of this same vault to model the iCloud import; no relay snapshot.
    let copy = dir.path().join("phone.apassy");
    mac.lock().unwrap();
    let (mut iphone, _) = Vault::adopt_sync_copy(mac.path(), &copy, PASS).unwrap();
    mac.unlock(PASS).unwrap();
    iphone.unlock(PASS).unwrap();
    let phone_membership = apassy::vault::RelayMembership {
        team_id: membership.team_id.clone(),
        relay_url: relay.url.clone(),
        device_id: device.id,
        public_key: link.public_key.clone(),
        key_pkcs8: joined.key_pkcs8().unwrap(),
        purposes: std::collections::BTreeSet::from([MembershipPurpose::Questions]),
        created_at: 0,
    };
    iphone
        .adopt_question_handoff(&handoff, &phone_membership, answer.public_key(), None)
        .unwrap();
    iphone.remove_trusted_device(&trusted.uuid).unwrap();
    assert!(
        iphone
            .adopt_question_handoff(&handoff, &phone_membership, answer.public_key(), None)
            .is_err()
    );
    mac.remove_trusted_device(&trusted.uuid).unwrap();
    assert!(
        channel
            .seal(&mac, &membership.team_id, &link.public_key)
            .is_err()
    );
}

#[test]
fn a_short_edge_rate_limit_reports_retry_after_and_keeps_the_same_key() {
    let relay = FakeRelay::start();
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let pending = prepare_connect(&mut vault, &relay.url, "Free", "Mac").unwrap();
    relay.fail_next("POST /v1/connect", 1, 429);
    assert_eq!(
        create_connect(&pending).unwrap_err(),
        ConnectError::TryLater(2)
    );
    assert_eq!(
        vault.pending_connect().unwrap().unwrap().key_pkcs8,
        pending.key_pkcs8
    );
    assert!(ConnectError::TryLater(2).to_string().contains("2 seconds"));
    assert!(
        ConnectError::TryLater(2)
            .to_string()
            .contains("will be reused")
    );
}
