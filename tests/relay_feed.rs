#![cfg(feature = "vault")]

//! The feed of the agents through the relay (contract relay-feed-v1). Synthetic values
//! only; no network beyond the in-process fake relay on 127.0.0.1.
//!
//! A Mac has the vault and a notifications-only questions team; its questions waiter
//! publishes the feed of its agents. An "iPhone" joins the team with a link, reads and
//! opens the feed with the contract's AAD, and sends removals of exceptions back, signed
//! with the P-256 answer key of the contract test vectors (Face ID) or its relay key.

use crate::common::fake_relay;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use apassy::broker::action_kind::ActionKind;
use apassy::broker::approvals::{
    ApprovalQueue, OwnerAction, OwnerAuthError, OwnerCheck, OwnerGate, verify_remote_action,
};
use apassy::contracts::CredentialKind;
use apassy::questions::device_link::link_device_name;
use apassy::questions::envelope::{Sealed, new_qid};
use apassy::questions::feed::{
    ActionBody, Feed, FeedActionUse, FeedAgent, FeedException, FeedMac, FeedUse, FeedWeek,
    RemovalAction, SettleBody, Target, UNSUPPORTED, action_aad, build_feed, feed_aad, names_digest,
    names_here, names_hold, names_in_vault, open_action, settle_aad, still_shown,
};
use apassy::questions::{FeedActionRecord, QuestionsClient, QuestionsConfig, QuestionsWorker};
use apassy::relay::membership::{
    adopt_questions_team, new_questions_team, register_linked_device, this_device,
};
use apassy::sync::{DeviceKey, PendingJoin, decode_b64u};
use apassy::vault::exceptions::{AgentException, ExceptionKind};
use apassy::vault::usage::{NewItemUse, UseDecidedBy, UseOutcome};
use apassy::vault::{
    ActivityDecision, Field, ItemDraft, QuestionKey, SecretValue, TrustedDevice, TrustedDeviceKind,
    Vault,
};
use fake_relay::FakeRelay;
use tempfile::TempDir;

const PASS: &str = "synthetic-feed-pass";
const SHOP_SECRET: &str = "SYNTH-shop-database-secret";
const API_SECRET: &str = "SYNTH-api-token-secret";
const LATE_SECRET: &str = "SYNTH-value-set-after-the-use";
const NOTE_SECRET: &str = "SYNTH-secret-in-the-item-notes";
const PROJECT_KEY: &str = "/Users/synthetic/private-path/synthetic-shop/.git";
const HOST: &str = "secret-host.synthetic.example";
const TEAM: &str = "t_7k2m5q4x3c";
const MAC_UUID: &str = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d";
const PHONE_UUID: &str = "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b";
const SHOP_UUID: &str = "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c";
const API_UUID: &str = "8d2a4c6e1f3b4d5a9c7e0b2d4f6a8c1e";
const ACTION_ID: &str = "sLGys7S1tre4ubq7vL2-vw";
const ANSWER_PRIVATE: &str = "bb684f0551ffd30d7040500bc8fa0d83efd5dbde18ea1e253f098b6ddfca5f1b";
const ANSWER_PUBLIC: &str =
    "BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts";
/// The device key of relay-sync-v1 section 15.
const SYNC_PRIVATE: &str = "4f2d9c6e1b3a7d8f0c5e2a9b7f4d1c3e6a8b0d2f4c6e8a1b3d5f7a9c0e2b4d6f";
const SYNC_PUBLIC: &str =
    "BOpHkB5VvTHXawpUXZxgu44Q97I2bzq9G_uI6tFM9mj8De047e1fNWI8MIERDsaxhBC0ih1DPfXaM4mdBbExjrA";
const SIGNATURE: &str = "MEUCIQCOrTEXw3oKicPKbs27qpgbvM95jFR7lYdT06KKIVWa-wIgT3NaBhBSf5jHK8K-zhPQ0hBmo181UGMB1WMeAjoHBRk";

type SharedVault = Arc<Mutex<Option<Vault>>>;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn sha256(bytes: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

fn contract_key() -> QuestionKey {
    let mut bytes = [0u8; 32];
    for (at, byte) in bytes.iter_mut().enumerate() {
        *byte = at as u8;
    }
    QuestionKey::from_bytes(bytes)
}

fn answer_key() -> DeviceKey {
    DeviceKey::from_raw(&unhex(ANSWER_PRIVATE), &decode_b64u(ANSWER_PUBLIC).unwrap())
        .expect("the answer key of the contract")
}

fn sync_key() -> DeviceKey {
    DeviceKey::from_raw(&unhex(SYNC_PRIVATE), &decode_b64u(SYNC_PUBLIC).unwrap())
        .expect("the device key of relay-sync-v1")
}

fn verifies(key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, key)
        .verify(message, signature)
        .is_ok()
}

fn nonce(first: u8) -> [u8; 12] {
    std::array::from_fn(|at| first + at as u8)
}

// ---- The contract test vectors (section 17). ----

fn vector_feed() -> Feed {
    Feed {
        v: 1,
        mac: FeedMac {
            device: MAC_UUID.to_owned(),
            name: "MacBook Pro".to_owned(),
        },
        seq: 1_790_000_040,
        generated_at: 1_790_000_040,
        truncated: false,
        week: FeedWeek {
            by_you: 3,
            automatic: 128,
        },
        agents: vec![FeedAgent {
            id: "4".to_owned(),
            name: "Claude Code".to_owned(),
            host: "claude".to_owned(),
            place: "mac".to_owned(),
            revoked: false,
            token_expires_at: 1_797_776_000,
            last_use_at: Some(1_790_000_010),
            uses_this_week: 12,
            projects: vec!["synthetic-shop".to_owned()],
            note: "Deploys only from the main branch.".to_owned(),
            restricted: false,
            actions: vec![FeedActionUse {
                action: "deploy".to_owned(),
                allowed: 2,
                not_allowed: 1,
                projects: vec!["synthetic-shop".to_owned()],
            }],
            exceptions: vec![FeedException {
                item: Some(SHOP_UUID.to_owned()),
                item_title: "Shop database".to_owned(),
                kind: "never".to_owned(),
                created_at: 1_789_990_000,
            }],
            recent: vec![FeedUse {
                at: 1_790_000_010,
                item: Some(API_UUID.to_owned()),
                item_title: "API token".to_owned(),
                action: "deploy".to_owned(),
                project: "synthetic-shop".to_owned(),
                command: "npm run deploy -- --token [apassy:secret]".to_owned(),
                outcome: "allowed".to_owned(),
                decided_by: "owner".to_owned(),
                answered_on: "Test iPhone".to_owned(),
            }],
        }],
    }
}

fn vector_removal() -> RemovalAction {
    RemovalAction {
        by: PHONE_UUID.to_owned(),
        to: MAC_UUID.to_owned(),
        team_id: TEAM.to_owned(),
        action_id: ACTION_ID.to_owned(),
        agent_id: 4,
        item_uuid: SHOP_UUID.to_owned(),
        kind: ExceptionKind::Never,
        created_at: 1_789_990_000,
        feed_seq: 1_790_000_040,
        time: 1_790_000_060,
        names: None,
    }
}

fn vector_phone(sign_key: &[u8], answer_key: &[u8]) -> TrustedDevice {
    TrustedDevice {
        uuid: PHONE_UUID.to_owned(),
        name: "Test iPhone".to_owned(),
        kind: TrustedDeviceKind::Iphone,
        relay_devices: BTreeMap::from([(TEAM.to_owned(), 3)]),
        sign_key: sign_key.to_vec(),
        answer_key: Some(answer_key.to_vec()),
        created_at: 1_789_000_000,
        updated_at: 0,
        updated_by: String::new(),
    }
}

#[test]
fn the_contract_test_vectors_reproduce_exactly() {
    let key = contract_key();
    assert_eq!(key.key_id(), "630dcd2966c43366");

    // 17.1 The feed.
    let feed = vector_feed();
    let plaintext = feed.to_plaintext();
    assert_eq!(plaintext.len(), 919);
    assert_eq!(
        sha256(&plaintext),
        "5a47ba132d8e33ffd68237f2c8f5332fbf27c15f39fe14e06b9fc33415b34785"
    );
    assert_eq!(Feed::parse(&plaintext), Some(feed.clone()));
    let aad = feed_aad(TEAM, 2, 1_790_000_040, &key.key_id());
    assert_eq!(aad.len(), 62);
    assert_eq!(
        hex(&aad),
        "6170617373792d666565642d7631006665656400745f376b326d357134783363003200313739303030303034300036333064636432393636633433333636"
    );
    let sealed = Sealed::with_nonce(&key, &nonce(0x30), &aad, &plaintext);
    assert_eq!(sealed.nonce, "MDEyMzQ1Njc4OTo7");
    let ciphertext = decode_b64u(&sealed.ciphertext).unwrap();
    assert_eq!(ciphertext.len(), 935);
    assert_eq!(
        sha256(&ciphertext),
        "f79d190efe856940ca7f53b5909c8e2d35d85035d3646551fd15fb70ddbca2a6"
    );
    assert_eq!(
        hex(&ciphertext[ciphertext.len() - 16..]),
        "b0d6de4e7c01d3b980b2c6b4fd344af9"
    );
    assert_eq!(
        sealed.open(&key, &aad).unwrap().as_slice(),
        plaintext.as_slice()
    );
    // 17.5: not with device 3, seq − 1, another team or key id, or the part `action`.
    for other in [
        feed_aad(TEAM, 3, 1_790_000_040, &key.key_id()),
        feed_aad(TEAM, 2, 1_790_000_039, &key.key_id()),
        feed_aad("t_0000000000", 2, 1_790_000_040, &key.key_id()),
        feed_aad(TEAM, 2, 1_790_000_040, "0000000000000000"),
        action_aad(TEAM, ACTION_ID, &key.key_id(), 3, 2),
    ] {
        assert!(sealed.open(&key, &other).is_none());
    }

    // 17.2 The action string and its signature.
    let removal = vector_removal();
    let text = removal.string().unwrap();
    assert_eq!(
        text,
        "apassy-feed-action-v1\n6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b\n0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d\nt_7k2m5q4x3c\nsLGys7S1tre4ubq7vL2-vw\nremove_exception:4:3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c:never:1789990000\n1790000040\n1790000060"
    );
    assert_eq!(text.len(), 222);
    assert_eq!(
        sha256(text.as_bytes()),
        "4555d68b3fbe31ad493893152aa08eb21342feb0dbf69e91247748a6ae81ad6d"
    );
    let signature = decode_b64u(SIGNATURE).unwrap();
    assert_eq!(signature.len(), 71);
    let answer_public = decode_b64u(ANSWER_PUBLIC).unwrap();
    let sync_public = decode_b64u(SYNC_PUBLIC).unwrap();
    assert!(verifies(&answer_public, text.as_bytes(), &signature));
    assert!(!verifies(
        &answer_public,
        text.replace(":never:", ":only:").as_bytes(),
        &signature
    ));
    assert!(!verifies(
        &answer_public,
        text.replace(MAC_UUID, "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4e")
            .as_bytes(),
        &signature
    ));
    assert!(!verifies(&sync_public, text.as_bytes(), &signature));
    let fresh = answer_key().sign(text.as_bytes()).unwrap();
    assert_ne!(fresh, signature, "a new signature differs");
    assert!(verifies(&answer_public, text.as_bytes(), &fresh));

    // 17.3 The action envelope.
    let body = ActionBody::new(&removal, &signature);
    let action = body.to_plaintext().unwrap();
    assert_eq!(
        String::from_utf8(action.to_vec()).unwrap(),
        format!(
            r#"{{"v":1,"action_id":"{ACTION_ID}","by":"{PHONE_UUID}","to":"{MAC_UUID}","kind":"remove_exception","agent":"4","item":"{SHOP_UUID}","exception":{{"kind":"never","created_at":1789990000}},"feed_seq":1790000040,"time":1790000060,"signature":"{SIGNATURE}"}}"#
        )
    );
    assert_eq!(action.len(), 415);
    assert_eq!(
        sha256(&action),
        "22af11dac5c7a34b5ff375255a687d57b616f3307301bce022a82a7a9c74aa26"
    );
    assert_eq!(ActionBody::parse(&action), Some(body.clone()));
    let aad = action_aad(TEAM, ACTION_ID, &key.key_id(), 3, 2);
    assert_eq!(aad.len(), 78);
    assert_eq!(
        hex(&aad),
        "6170617373792d666565642d763100616374696f6e00745f376b326d35713478336300734c4779733753317472653475627137764c322d7677003633306463643239363663343333363600330032"
    );
    let sealed_action = Sealed::with_nonce(&key, &nonce(0x40), &aad, &action);
    assert_eq!(sealed_action.nonce, "QEFCQ0RFRkdISUpL");
    let ciphertext = decode_b64u(&sealed_action.ciphertext).unwrap();
    assert_eq!(ciphertext.len(), 431);
    assert_eq!(
        sha256(&ciphertext),
        "d804b41435c71360d58e728b82f8715e5d586507b8f11d8f844b12789e887da4"
    );
    assert_eq!(
        hex(&ciphertext),
        "83760aa3487bc22339ac8269d48132a4d0ee593a37b006168d3b816a9e555f5e85d1e847500750db7c180d6b483697bcdb715aafcf15bd4ae9a322086a5f574cff551c3b7e2b861220235deaf24a170fee3da44fc9dfc2429f05c30f367eb216a95dbb391fe5384e66eaf6e93fd854db8fc1d6ceb0b2ab28d979941a463e3768ea501aefb6d699f22d9a1c02c99bfdddfd7c80e2a4cf67d726f759e70e92ee1a4208141f7e524fc951c2e256158fef5c05ebac29bccb949f0d5556311192fd84701066f8b6b1d160cd5a3a0d8cc0a9ac8028785ec8b7f216dd8b58da9aa4a5dbcee3f9aabbbecac7b127969d3df50afe36f1d0d31be580dd9f514a3e33856ce732838b014148ce97e02fc74e40468740e5e304915e362fbcbade163190a3845c06a2b25cb91d5ccdd2534702f1734ac5004cb2ffea57d02891e4598b18e8e8dff089421dc6281a499aa50cc1fe34af67febb3b82bd7f1469eb985b95abab8765c81a6b139417516b56ff72c9b7bd24575eb2b1468d23810569791d4e37bd9703d98cd84eae14fd96d574a4c4985e08d904f2870a7262bc57c9c46488df3340b9c35b116c3068090c9df1df08e407c7"
    );
    // Not with the target 5 instead of 2, or the sender 4 instead of 3.
    assert!(
        sealed_action
            .open(&key, &action_aad(TEAM, ACTION_ID, &key.key_id(), 3, 5))
            .is_none()
    );
    assert!(
        sealed_action
            .open(&key, &action_aad(TEAM, ACTION_ID, &key.key_id(), 4, 2))
            .is_none()
    );

    // 17.4 The settle.
    let settle = SettleBody {
        v: 1,
        action_id: ACTION_ID.to_owned(),
        outcome: "applied".to_owned(),
        reason: String::new(),
        feed_seq: Some(1_790_000_070),
        at: 1_790_000_061,
    };
    let settle_plain = settle.to_plaintext().unwrap();
    assert_eq!(
        String::from_utf8(settle_plain.to_vec()).unwrap(),
        r#"{"v":1,"action_id":"sLGys7S1tre4ubq7vL2-vw","outcome":"applied","reason":"","feed_seq":1790000070,"at":1790000061}"#
    );
    assert_eq!(settle_plain.len(), 114);
    let aad = settle_aad(TEAM, ACTION_ID, &key.key_id(), "applied");
    assert_eq!(aad.len(), 82);
    assert_eq!(
        hex(&aad),
        "6170617373792d666565642d763100736574746c6500745f376b326d35713478336300734c4779733753317472653475627137764c322d76770036333064636432393636633433333636006170706c696564"
    );
    let sealed_settle = Sealed::with_nonce(&key, &nonce(0x50), &aad, &settle_plain);
    assert_eq!(sealed_settle.nonce, "UFFSU1RVVldYWVpb");
    assert_eq!(
        hex(&decode_b64u(&sealed_settle.ciphertext).unwrap()),
        "45c1455083097076570a95408f49b1f62de9b76b09a5c47982c1f3b5c77807a3639e5ecf86f3776b677093db298da725bfe2853c8688b69ad7b4a7832e77d73b1ac2ecd226b7cb5a4afdf3983e7e2acf4d006065b984d08880aaa87d41d13ec7fb54c8e0c1f5a9e420b91c0814b97d13b6e076ff2594ee2ba2c7d39ddfaea96b2a1c"
    );
    assert_eq!(
        SettleBody::parse(&sealed_settle.open(&key, &aad).unwrap()),
        Some(settle)
    );
    assert!(
        sealed_settle
            .open(&key, &settle_aad(TEAM, ACTION_ID, &key.key_id(), "refused"))
            .is_none()
    );

    // 17.5 The target: the publisher of 17.1 with the row (4, Shop database, never,
    // 1789990000) and its last seq 1790000040.
    let phone = vector_phone(&sync_public, &answer_public);
    let record = FeedActionRecord {
        action_id: ACTION_ID.to_owned(),
        seq: 9,
        from_device_id: 3,
        key_id: sealed_action.key_id.clone(),
        nonce: sealed_action.nonce.clone(),
        ciphertext: sealed_action.ciphertext.clone(),
        created_at: 1_790_000_060,
        expires_at: 1_790_000_360,
    };
    let mac = TrustedDevice {
        uuid: MAC_UUID.to_owned(),
        name: "MacBook Pro".to_owned(),
        kind: TrustedDeviceKind::Mac,
        relay_devices: BTreeMap::from([(TEAM.to_owned(), 2)]),
        sign_key: vec![4; 65],
        answer_key: None,
        created_at: 1_789_000_000,
        updated_at: 0,
        updated_by: String::new(),
    };
    let target = Target {
        team_id: TEAM.to_owned(),
        me: mac,
        device_id: 2,
    };
    let devices = vec![phone.clone()];
    let shop_item = 1;
    let row = |created_at| AgentException {
        agent_id: 4,
        item_id: shop_item,
        kind: ExceptionKind::Never,
        created_at,
    };
    for clock in [1_790_000_000, 1_790_000_060, 1_790_000_120] {
        let opened = open_action(&record, &target, Some(&key), &devices, clock).expect("it opens");
        assert_eq!(opened.removal, removal);
        assert_eq!(opened.signature, signature);
        assert_eq!(
            verify_remote_action(&phone, &opened.removal, &opened.signature, clock),
            Ok(())
        );
        assert_eq!(
            still_shown(
                &opened.removal,
                shop_item,
                &[row(1_789_990_000)],
                1_790_000_040
            ),
            Ok(())
        );
    }
    // Too old at 1790000121.
    let late = open_action(&record, &target, Some(&key), &devices, 1_790_000_121).unwrap_err();
    assert_eq!((late.outcome.as_str(), late.reason), ("refused", "too old"));
    assert_eq!(
        verify_remote_action(&phone, &removal, &signature, 1_790_000_121),
        Err(OwnerAuthError::RemoteStale)
    );
    // The row made again at 1789990001; a target whose last seq is 1790000039.
    let changed = still_shown(&removal, shop_item, &[row(1_789_990_001)], 1_790_000_040);
    assert_eq!(changed.unwrap_err().outcome.as_str(), "stale");
    let unseen = still_shown(&removal, shop_item, &[row(1_789_990_000)], 1_790_000_039);
    assert_eq!(unseen.unwrap_err().outcome.as_str(), "stale");
    // Another answer key; the iPhone's sign_key.
    let other = DeviceKey::generate().unwrap();
    assert_eq!(
        verify_remote_action(
            &vector_phone(&sync_public, other.public_key()),
            &removal,
            &signature,
            1_790_000_060
        ),
        Err(OwnerAuthError::RemoteRejected)
    );
    let by_sign_key = sync_key().sign(text.as_bytes()).unwrap();
    assert_eq!(
        verify_remote_action(&phone, &removal, &by_sign_key, 1_790_000_060),
        Err(OwnerAuthError::RemoteRejected)
    );
    // The same action to another Mac does not open, and does not name it.
    let mut elsewhere = target.clone();
    elsewhere.device_id = 5;
    assert_eq!(
        open_action(&record, &elsewhere, Some(&key), &devices, 1_790_000_060)
            .unwrap_err()
            .reason,
        "it could not be read"
    );
    let mut other_mac = target.clone();
    other_mac.me.uuid = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4e".to_owned();
    assert_eq!(
        open_action(&record, &other_mac, Some(&key), &devices, 1_790_000_060)
            .unwrap_err()
            .reason,
        "it is for another Mac"
    );
    // A sender that is a Mac, or whose device number in the team is another one.
    let mut as_mac = phone.clone();
    as_mac.kind = TrustedDeviceKind::Mac;
    let mut renumbered = phone.clone();
    renumbered.relay_devices.insert(TEAM.to_owned(), 7);
    for devices in [vec![], vec![as_mac], vec![renumbered]] {
        assert_eq!(
            open_action(&record, &target, Some(&key), &devices, 1_790_000_060)
                .unwrap_err()
                .reason,
            "the device is not an iPhone of this vault"
        );
    }
}

/// The v2 signature of section 17.6, by the answer key.
const SIGNATURE_V2: &str = "MEUCIDZe_XeIFZkGUQjDaJg3Z5bviGeoqBIc-8R8aaFyCBGXAiEA7dTFzS2hkSFmp8wVG1jQTJR3DqpJlwzqEPofgU_SbBs";

/// Section 17.6: the feed of 17.1 with the mark of v2, the names, the action string of
/// v2, its signature, and its envelope.
#[test]
fn the_v2_vectors_reproduce_exactly() {
    let key = contract_key();
    // The feed of a Mac that checks the names: 17.1 and one line feed.
    let mut plaintext = vector_feed().to_plaintext().to_vec();
    plaintext.push(b'\n');
    assert_eq!(plaintext.len(), 920);
    assert_eq!(
        sha256(&plaintext),
        "140fa142ad88453b65e512ad2715f425c0800b73f445d2faeeee896d220c42a7"
    );
    assert!(Feed::checks_names(&plaintext));
    assert!(!Feed::checks_names(&vector_feed().to_plaintext()));
    assert_eq!(Feed::parse(&plaintext), Some(vector_feed()));
    let aad = feed_aad(TEAM, 2, 1_790_000_040, &key.key_id());
    let sealed = Sealed::with_nonce(&key, &nonce(0x30), &aad, &plaintext);
    let ciphertext = decode_b64u(&sealed.ciphertext).unwrap();
    assert_eq!(ciphertext.len(), 936);
    assert_eq!(
        sha256(&ciphertext),
        "86535f0d4be458344a31ac492dd860cae9698a5b3116bff239eddebb8c98d23e"
    );

    // The names: the agent, the credential, the Mac, joined with one zero byte.
    let joined = b"Claude Code\0Shop database\0MacBook Pro";
    assert_eq!(
        hex(joined),
        "436c6175646520436f64650053686f70206461746162617365004d6163426f6f6b2050726f"
    );
    let digest = names_digest("Claude Code", "Shop database", "MacBook Pro");
    assert_eq!(
        digest,
        "8ef3d4125ebeb2d11adc19a4430a543178783fddd3c75dd1c20d2f9e2e9205c6"
    );
    assert_eq!(sha256(joined), digest);
    assert_eq!(
        names_here("Claude Code", "Shop database", "MacBook Pro"),
        vec![digest.clone()]
    );

    // The action string of v2: the tag of v2, lines 2 to 8 of 17.2, and the names.
    let mut removal = vector_removal();
    removal.names = Some(digest.clone());
    let text = removal.string().unwrap();
    assert_eq!(
        text,
        "apassy-feed-action-v2\n6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b\n0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d\nt_7k2m5q4x3c\nsLGys7S1tre4ubq7vL2-vw\nremove_exception:4:3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c:never:1789990000\n1790000040\n1790000060\nnames:8ef3d4125ebeb2d11adc19a4430a543178783fddd3c75dd1c20d2f9e2e9205c6"
    );
    assert_eq!(text.len(), 293);
    assert_eq!(
        sha256(text.as_bytes()),
        "faee55b8a1050aac2b18711bdc15869dd35f454293319bd516044e56a941345c"
    );
    let signature = decode_b64u(SIGNATURE_V2).unwrap();
    assert_eq!(signature.len(), 71);
    let answer_public = decode_b64u(ANSWER_PUBLIC).unwrap();
    assert!(verifies(&answer_public, text.as_bytes(), &signature));
    // The v1 signature of 17.2 is not one of v2, and the v2 one is not of v1, of other
    // names, or of the device key.
    let v1 = vector_removal().string().unwrap();
    assert!(!verifies(
        &answer_public,
        text.as_bytes(),
        &decode_b64u(SIGNATURE).unwrap()
    ));
    assert!(!verifies(&answer_public, v1.as_bytes(), &signature));
    let mut other_names = removal.clone();
    other_names.names = Some(names_digest("Scratch Bot", "Shop database", "MacBook Pro"));
    assert!(!verifies(
        &answer_public,
        other_names.string().unwrap().as_bytes(),
        &signature
    ));
    assert!(!verifies(
        &decode_b64u(SYNC_PUBLIC).unwrap(),
        text.as_bytes(),
        &signature
    ));
    let now = 1_790_000_060;
    let phone = vector_phone(&decode_b64u(SYNC_PUBLIC).unwrap(), &answer_public);
    assert_eq!(
        verify_remote_action(&phone, &removal, &signature, now),
        Ok(())
    );
    assert_eq!(
        verify_remote_action(&phone, &other_names, &signature, now),
        Err(OwnerAuthError::RemoteRejected)
    );

    // The action envelope of v2: `v` 2 and `names` before the signature.
    let body = ActionBody::new(&removal, &signature);
    let action = body.to_plaintext().unwrap();
    assert_eq!(
        String::from_utf8(action.to_vec()).unwrap(),
        format!(
            r#"{{"v":2,"action_id":"{ACTION_ID}","by":"{PHONE_UUID}","to":"{MAC_UUID}","kind":"remove_exception","agent":"4","item":"{SHOP_UUID}","exception":{{"kind":"never","created_at":1789990000}},"feed_seq":1790000040,"time":1790000060,"names":"{digest}","signature":"{SIGNATURE_V2}"}}"#
        )
    );
    assert_eq!(action.len(), 490);
    assert_eq!(
        sha256(&action),
        "cde8c71bb7e7b61061fab82ec31a26718d0470539c5ccf6333d6bab1106b53c1"
    );
    assert_eq!(ActionBody::parse(&action), Some(body));
    let aad = action_aad(TEAM, ACTION_ID, &key.key_id(), 3, 2);
    let sealed_action = Sealed::with_nonce(&key, &nonce(0x40), &aad, &action);
    let ciphertext = decode_b64u(&sealed_action.ciphertext).unwrap();
    assert_eq!(ciphertext.len(), 506);
    assert_eq!(
        sha256(&ciphertext),
        "6b66949004172f5791d6f9e42f60a2d70f0ff1cac2a76c8fc5732eae53403e44"
    );

    // The target opens it and gets the names; the names of its rows match.
    let record = FeedActionRecord {
        action_id: ACTION_ID.to_owned(),
        seq: 9,
        from_device_id: 3,
        key_id: sealed_action.key_id.clone(),
        nonce: sealed_action.nonce.clone(),
        ciphertext: sealed_action.ciphertext.clone(),
        created_at: 1_790_000_060,
        expires_at: 1_790_000_360,
    };
    let target = Target {
        team_id: TEAM.to_owned(),
        me: TrustedDevice {
            uuid: MAC_UUID.to_owned(),
            name: "MacBook Pro".to_owned(),
            kind: TrustedDeviceKind::Mac,
            relay_devices: BTreeMap::from([(TEAM.to_owned(), 2)]),
            sign_key: vec![4; 65],
            answer_key: None,
            created_at: 1_789_000_000,
            updated_at: 0,
            updated_by: String::new(),
        },
        device_id: 2,
    };
    let opened = open_action(&record, &target, Some(&key), &[phone], now).expect("it opens");
    assert_eq!(opened.removal, removal);
    assert_eq!(opened.removal.names.as_deref(), Some(digest.as_str()));
}

// ---- A Mac, its waiter, and an iPhone with the fake relay. ----

fn secret_item(title: &str, token: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::ApiKey,
        notes: format!("Synthetic notes: {NOTE_SECRET}"),
        tags: Vec::new(),
        fields: vec![Field {
            name: "token".to_owned(),
            value: SecretValue::new(token.to_owned()),
            secret: true,
        }],
    }
}

fn config() -> QuestionsConfig {
    QuestionsConfig {
        question_wait: Duration::from_secs(300),
        tick: Duration::from_millis(50),
        device_name: "Synthetic MacBook".to_owned(),
        feed: true,
        feed_every: Duration::from_secs(1),
        feed_beat: Duration::from_secs(600),
    }
}

struct World {
    _root: TempDir,
    relay: FakeRelay,
    shared: SharedVault,
    membership: apassy::vault::RelayMembership,
    worker: Option<QuestionsWorker>,
    agent: u64,
    token: String,
    items: [u64; 2],
}

/// An iPhone of the team: its relay client, its row, and its answer key.
struct Phone {
    client: QuestionsClient,
    uuid: String,
    answer: DeviceKey,
    /// The question key that the iPhone holds through the vault.
    key: QuestionKey,
    /// The name of the Mac's row in the iPhone's copy of the vault.
    mac_name: String,
}

fn world() -> World {
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    relay.set_feed_every(Duration::from_millis(900));
    let mut vault = Vault::create(&root.path().join("feed.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    let membership = new_questions_team(
        &relay.url,
        &relay.team_code(),
        "Personal",
        "Synthetic MacBook",
    )
    .expect("team");
    adopt_questions_team(&mut vault, &membership, "Synthetic MacBook").expect("adopt");
    let shop = vault
        .add(secret_item("Shop database", SHOP_SECRET))
        .unwrap()
        .id;
    let api = vault.add(secret_item("API token", API_SECRET)).unwrap().id;
    let (agent, token) = vault.register_agent("Claude Code").unwrap();
    World {
        _root: root,
        relay,
        shared: Arc::new(Mutex::new(Some(vault))),
        membership,
        worker: None,
        agent: agent.id,
        token: token.expose().to_owned(),
        items: [shop, api],
    }
}

impl World {
    fn with<T>(&self, f: impl FnOnce(&mut Vault) -> T) -> T {
        f(self.shared.lock().unwrap().as_mut().unwrap())
    }

    fn start(&mut self, config: QuestionsConfig) {
        self.worker = Some(QuestionsWorker::start(
            Arc::new(ApprovalQueue::new()),
            Arc::clone(&self.shared),
            OwnerGate::new(Arc::clone(&self.shared), None),
            config,
        ));
    }

    fn me(&self) -> TrustedDevice {
        self.with(|vault| {
            this_device(vault, &self.membership)
                .unwrap()
                .expect("this Mac")
        })
    }

    fn team(&self) -> &str {
        &self.membership.team_id
    }

    fn mac_id(&self) -> u64 {
        self.membership.device_id
    }

    /// An iPhone joins the team with a link that carries its answer key; the Mac writes
    /// its row from the link.
    fn phone(&self, name: &str, answer: DeviceKey) -> Phone {
        let client = QuestionsClient::from_membership(&self.membership).unwrap();
        let code = client.create_link().expect("link");
        let link_name = link_device_name(name, answer.public_key()).unwrap();
        let pending = PendingJoin::request_with_key(
            &code.link,
            "",
            &link_name,
            DeviceKey::generate().unwrap(),
        )
        .expect("join");
        let links = client.pending_links(Some(&code)).expect("links");
        let device = client.confirm_link(&links[0]).expect("confirm");
        let joined = pending.poll().expect("poll").expect("confirmed");
        let row = self.with(|vault| {
            register_linked_device(
                vault,
                self.team(),
                device.id,
                &links[0].device_name,
                &links[0].public_key,
            )
            .unwrap()
            .expect("an iPhone row")
        });
        Phone {
            client: QuestionsClient::from_member(joined.member()),
            uuid: row.uuid,
            answer,
            key: self.key(),
            mac_name: self.me().name,
        }
    }

    fn key(&self) -> QuestionKey {
        self.with(|vault| vault.question_key().unwrap().unwrap())
    }

    fn feed_puts(&self) -> usize {
        self.relay.count("PUT /v1/feed")
    }

    fn uses(&self, command: &str, item: u64, at_project: &str) {
        self.with(|vault| {
            vault
                .record_item_use(&NewItemUse {
                    item_id: item,
                    agent_id: Some(self.agent),
                    agent_name: "Claude Code".to_owned(),
                    project_key: PROJECT_KEY.to_owned(),
                    project_label: at_project.to_owned(),
                    action: ActionKind::Deploy,
                    command_summary: command.to_owned(),
                    hosts: vec![HOST.to_owned()],
                    outcome: UseOutcome::Allowed,
                    decided_by: UseDecidedBy::Owner,
                    answered_on: "Test iPhone".to_owned(),
                    decision_log_id: None,
                })
                .unwrap();
        });
    }

    fn exceptions(&self) -> Vec<AgentException> {
        self.with(|vault| vault.agent_exceptions(self.agent).unwrap())
    }

    fn activity(&self) -> Vec<String> {
        self.with(|vault| {
            vault
                .recent_activity(100)
                .unwrap()
                .into_iter()
                .filter(|row| row.operation == apassy::questions::feed::ACTIVITY_OPERATION)
                .map(|row| row.reason)
                .collect()
        })
    }
}

fn wait_until<T>(what: &str, mut probe: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(found) = probe() {
            return found;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "waited for {what}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

impl Phone {
    /// The newest feed of the Mac `mac_id`, opened with the contract's AAD and checked
    /// as a reader does (section 7.4 steps 1 to 3).
    fn feed(&self, world: &World, mac_id: u64) -> Option<Feed> {
        let key = &self.key;
        let list = self.client.feeds(0, Duration::ZERO).ok()?;
        let record = list.feeds.iter().find(|feed| feed.device_id == mac_id)?;
        assert!(list.present.contains(&mac_id));
        let aad = feed_aad(world.team(), record.device_id, record.seq, &record.key_id);
        // A feed that does not open keeps the last good one (section 7.4 step 1).
        let plaintext = record.sealed().open(key, &aad)?;
        let feed = Feed::parse(&plaintext).expect("the feed has the contract form");
        assert_eq!(feed.seq, record.seq);
        Some(feed)
    }

    fn wait_feed(&self, world: &World, what: &str, wanted: impl Fn(&Feed) -> bool) -> Feed {
        wait_until(what, || {
            self.feed(world, world.mac_id()).filter(|feed| wanted(feed))
        })
    }

    /// Sign `removal` with `sign` and post it, sealed for the Mac `to_device`.
    fn send(
        &self,
        world: &World,
        removal: &RemovalAction,
        to_device: u64,
        sign: impl Fn(&[u8]) -> Vec<u8>,
    ) {
        let signature = sign(removal.string().unwrap().as_bytes());
        let body = ActionBody::new(removal, &signature);
        let key = &self.key;
        let from = self.client.device_id().unwrap();
        let aad = action_aad(
            world.team(),
            &removal.action_id,
            &key.key_id(),
            from,
            to_device,
        );
        let sealed = Sealed::new(key, &aad, &body.to_plaintext().unwrap()).unwrap();
        self.client
            .post_feed_action(&removal.action_id, to_device, &sealed)
            .expect("the relay takes the action");
    }

    /// The removal of the exception `exception` of the first agent of `feed`, as a new
    /// iPhone sends it (v2, section 9.3): it signs the names it showed, the agent's and the
    /// title from the feed (this iPhone holds no copy of the item), and the Mac's from its
    /// row.
    fn removal(&self, world: &World, feed: &Feed, exception: &FeedException) -> RemovalAction {
        let mut removal = self.removal_v1(world, feed, exception);
        removal.names = Some(names_digest(
            &feed.agents[0].name,
            &exception.item_title,
            &self.mac_name,
        ));
        removal
    }

    /// The same removal as an iPhone of 0.5.2 sends it: v1, ids only.
    fn removal_v1(&self, world: &World, feed: &Feed, exception: &FeedException) -> RemovalAction {
        RemovalAction {
            by: self.uuid.clone(),
            to: feed.mac.device.clone(),
            team_id: world.team().to_owned(),
            action_id: new_qid().unwrap(),
            agent_id: feed.agents[0].id.parse().unwrap(),
            item_uuid: exception.item.clone().unwrap(),
            kind: ExceptionKind::parse(&exception.kind).unwrap(),
            created_at: exception.created_at,
            feed_seq: feed.seq,
            time: now(),
            names: None,
        }
    }

    /// The settle of `action_id`, opened: its clear outcome and its body.
    fn settle(&self, world: &World, action_id: &str) -> (String, SettleBody) {
        let key = &self.key;
        wait_until("the settle", || {
            let status = self
                .client
                .feed_action_status(action_id, Duration::from_secs(2))
                .ok()?;
            if status.state != "settled" {
                return None;
            }
            let outcome = status.outcome.clone().expect("a clear outcome");
            let sealed = status.settle.as_ref().expect("a settle").sealed();
            let aad = settle_aad(world.team(), action_id, &sealed.key_id, &outcome);
            let body = SettleBody::parse(&sealed.open(key, &aad).expect("the settle opens"))
                .expect("the settle has the contract form");
            assert_eq!(body.outcome, outcome);
            assert_eq!(body.action_id, action_id);
            Some((outcome, body))
        })
    }
}

/// The plaintext of the Mac's current feed, as the relay holds it.
fn stored_plaintext(world: &World) -> String {
    let (seq, key_id, nonce, ciphertext) = world.relay.feed_of(world.mac_id()).expect("a feed");
    let sealed = Sealed {
        key_id: key_id.clone(),
        nonce,
        ciphertext,
    };
    let aad = feed_aad(world.team(), world.mac_id(), seq, &key_id);
    String::from_utf8(sealed.open(&world.key(), &aad).unwrap().to_vec()).unwrap()
}

#[test]
fn the_feed_holds_no_secret_values() {
    let mut world = world();
    let [shop, api] = world.items;
    world.uses(
        &format!("npm run deploy -- --token {SHOP_SECRET} --late {LATE_SECRET}"),
        shop,
        "synthetic-shop",
    );
    world.uses(
        &format!("curl -H 'Bearer {API_SECRET}'"),
        api,
        "synthetic-shop",
    );
    world.with(|vault| {
        vault
            .add_agent_exception(world.agent, shop, ExceptionKind::AlwaysAsk)
            .unwrap();
        vault
            .set_agent_note(world.agent, "Deploys only from the main branch.")
            .unwrap();
        // A value set after the use was written: the feed masks it at publish time.
        let revision = vault.details(shop).unwrap().summary.revision;
        let mut draft = secret_item("Shop database", SHOP_SECRET);
        draft.fields.push(Field {
            name: "late".to_owned(),
            value: SecretValue::new(LATE_SECRET.to_owned()),
            secret: true,
        });
        vault.update(shop, revision, draft).unwrap();
    });
    let me = world.me();
    let built = world.with(|vault| build_feed(vault, &me, 1, now()).unwrap());
    let plaintext = String::from_utf8(built.to_plaintext().to_vec()).unwrap();
    let token = world.token.clone();
    let forbidden = [
        SHOP_SECRET,
        API_SECRET,
        LATE_SECRET,
        NOTE_SECRET,
        PROJECT_KEY,
        HOST,
        token.as_str(),
    ];
    for secret in forbidden {
        assert!(!plaintext.contains(secret), "{secret} in {plaintext}");
    }
    let recent = &built.agents[0].recent;
    assert_eq!(recent[0].command, "curl -H 'Bearer [apassy:secret]'");
    assert_eq!(
        recent[1].command,
        "npm run deploy -- --token [apassy:secret] --late [apassy:secret]"
    );
    assert_eq!(recent[1].project, "synthetic-shop");

    // The feed that the Mac publishes holds none of them either, and no body that the
    // relay got does.
    world.start(config());
    let phone = world.phone("Test iPhone", answer_key());
    let feed = phone.wait_feed(&world, "a feed", |feed| !feed.agents.is_empty());
    assert_eq!(feed.agents[0].recent, *recent);
    let published = stored_plaintext(&world);
    for secret in forbidden {
        assert!(
            !published.contains(secret),
            "{secret} in the published feed"
        );
        for body in world.relay.request_bodies() {
            assert!(!body.contains(secret), "{secret} in a request body");
        }
    }
}

#[cfg(feature = "desktop")]
#[test]
fn the_feed_shows_what_the_agents_page_shows() {
    use apassy::desktop::owner_store::OwnerSession;
    let root = TempDir::new().unwrap();
    let mut session = OwnerSession::new();
    session
        .create_file(&root.path().join("page.db"), PASS)
        .unwrap();
    session.unlock(PASS).unwrap();
    let shared = session.shared_vault();
    let (agent, shop, api) = {
        let mut guard = shared.lock().unwrap();
        let vault = guard.as_mut().unwrap();
        let shop = vault
            .add(secret_item("Shop database", SHOP_SECRET))
            .unwrap()
            .id;
        let api = vault.add(secret_item("API token", API_SECRET)).unwrap().id;
        let agent = vault.register_agent("Claude Code").unwrap().0.id;
        for (item, action, project, outcome) in [
            (
                shop,
                ActionKind::Deploy,
                "synthetic-shop",
                UseOutcome::Allowed,
            ),
            (api, ActionKind::Read, "synthetic-shop", UseOutcome::Allowed),
            (shop, ActionKind::Deploy, "acme-billing", UseOutcome::Denied),
            (api, ActionKind::Change, "", UseOutcome::TimedOut),
            (
                shop,
                ActionKind::Delete,
                "acme-billing",
                UseOutcome::Refused,
            ),
            (api, ActionKind::Read, "synthetic-shop", UseOutcome::Allowed),
            (
                shop,
                ActionKind::Deploy,
                "synthetic-shop",
                UseOutcome::Allowed,
            ),
        ] {
            vault
                .record_item_use(&NewItemUse {
                    item_id: item,
                    agent_id: Some(agent),
                    agent_name: "Claude Code".to_owned(),
                    project_key: format!("/synthetic/{project}/.git"),
                    project_label: project.to_owned(),
                    action,
                    command_summary: format!("synthetic {}", action.as_str()),
                    hosts: Vec::new(),
                    outcome,
                    decided_by: UseDecidedBy::Bouncer,
                    answered_on: String::new(),
                    decision_log_id: None,
                })
                .unwrap();
        }
        vault
            .add_agent_exception(agent, shop, ExceptionKind::Never)
            .unwrap();
        vault
            .add_agent_exception(agent, api, ExceptionKind::Only)
            .unwrap();
        vault.set_agent_note(agent, "Synthetic note.").unwrap();
        (agent, shop, api)
    };
    let page = session.agent_overview(agent).unwrap();
    let week = session.week_counts().unwrap();
    let me = TrustedDevice {
        uuid: MAC_UUID.to_owned(),
        name: "Synthetic MacBook".to_owned(),
        kind: TrustedDeviceKind::Mac,
        relay_devices: BTreeMap::new(),
        sign_key: vec![4; 65],
        answer_key: None,
        created_at: 0,
        updated_at: 0,
        updated_by: String::new(),
    };
    let (feed, uuids) = {
        let guard = shared.lock().unwrap();
        let vault = guard.as_ref().unwrap();
        (
            build_feed(vault, &me, 7, now()).unwrap(),
            [
                vault.item_uuid(shop).unwrap().unwrap(),
                vault.item_uuid(api).unwrap().unwrap(),
            ],
        )
    };
    assert_eq!(feed.week.by_you, week.by_you);
    assert_eq!(feed.week.automatic, week.automatic);
    let shown = &feed.agents[0];
    assert_eq!(shown.id, agent.to_string());
    assert_eq!(shown.uses_this_week, page.uses_this_week as u64);
    assert_eq!(shown.projects, page.projects);
    assert_eq!(shown.note, page.note);
    assert_eq!(shown.restricted, page.restricted);
    assert!(shown.restricted);
    let actions: Vec<(String, u64, u64, Vec<String>)> = page
        .actions
        .iter()
        .map(|action| {
            (
                action.action.as_str().to_owned(),
                action.allowed as u64,
                action.not_allowed as u64,
                action.projects.clone(),
            )
        })
        .collect();
    let sent: Vec<(String, u64, u64, Vec<String>)> = shown
        .actions
        .iter()
        .map(|action| {
            (
                action.action.clone(),
                action.allowed,
                action.not_allowed,
                action.projects.clone(),
            )
        })
        .collect();
    assert_eq!(sent, actions);
    // The same exceptions, named by the item UUID, never by the numeric id.
    let mut on_page: Vec<(String, String, u64)> = page
        .exceptions
        .iter()
        .map(|row| {
            let uuid = if row.exception.item_id == shop {
                &uuids[0]
            } else {
                &uuids[1]
            };
            (
                uuid.clone(),
                row.exception.kind.as_str().to_owned(),
                row.exception.created_at,
            )
        })
        .collect();
    let mut in_feed: Vec<(String, String, u64)> = shown
        .exceptions
        .iter()
        .map(|exception| {
            (
                exception.item.clone().unwrap(),
                exception.kind.clone(),
                exception.created_at,
            )
        })
        .collect();
    on_page.sort();
    in_feed.sort();
    assert_eq!(in_feed, on_page);
    assert!(
        shown
            .exceptions
            .iter()
            .all(|exception| exception.item.as_ref().is_some_and(|uuid| uuid.len() == 32))
    );
    // The recent uses of the page are the first ones of the feed.
    for (sent, row) in shown.recent.iter().zip(&page.recent) {
        assert_eq!(sent.at, row.item_use.at);
        assert_eq!(sent.action, row.item_use.action.as_str());
        assert_eq!(sent.project, row.item_use.project_label);
        assert_eq!(sent.outcome, row.item_use.outcome.as_str());
        assert_eq!(sent.item_title, row.item_name);
    }
    assert_eq!(shown.recent.len(), 7);
    assert_eq!(page.recent.len(), 5);
}

#[test]
fn seq_goes_up_across_restarts() {
    let mut world = world();
    let phone = world.phone("Test iPhone", answer_key());
    world.start(config());
    let first = phone.wait_feed(&world, "the first feed", |_| true);
    assert!(first.seq >= now() - 5 && first.seq <= now());
    // The waiter stops; the relay keeps a feed whose seq is ahead of the clock (an
    // earlier run, or a clock that went back).
    world.worker = None;
    let ahead = now() + 1_000;
    world.relay.set_feed_seq(world.mac_id(), ahead);
    world.start(config());
    let second = phone.wait_feed(&world, "a feed after the restart", |feed| feed.seq > ahead);
    assert_eq!(second.seq, ahead + 1, "max(that seq + 1, now)");
    // A relay that holds a newer seq while the waiter runs: `409`, then a read-back.
    world.relay.set_feed_seq(world.mac_id(), ahead + 50);
    world.with(|vault| vault.set_agent_note(world.agent, "A new note.").unwrap());
    let third = phone.wait_feed(&world, "a feed after the 409", |feed| {
        feed.agents[0].note == "A new note."
    });
    assert_eq!(third.seq, ahead + 51);
}

#[test]
fn no_feed_without_a_live_iphone_or_while_the_vault_is_locked() {
    let mut world = world();
    let mut beat = config();
    beat.feed_beat = Duration::from_secs(1);
    world.start(beat);
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(world.feed_puts(), 0, "no iPhone in the team");
    let phone = world.phone("Test iPhone", answer_key());
    phone.wait_feed(&world, "a feed with an iPhone", |_| true);
    // Locked: nothing goes, not even the beat.
    world.with(|vault| vault.lock().unwrap());
    std::thread::sleep(Duration::from_millis(400));
    let before = world.feed_puts();
    std::thread::sleep(Duration::from_millis(2_500));
    assert_eq!(world.feed_puts(), before, "a locked Mac publishes nothing");
    world.with(|vault| vault.unlock(PASS).unwrap());
    wait_until("a feed after the unlock", || {
        (world.feed_puts() > before).then_some(())
    });
    // The iPhone is removed: no more feeds.
    world.with(|vault| {
        assert!(vault.remove_trusted_device(&phone.uuid).unwrap());
    });
    std::thread::sleep(Duration::from_millis(400));
    let before = world.feed_puts();
    std::thread::sleep(Duration::from_millis(2_500));
    assert_eq!(world.feed_puts(), before, "no live iPhone");
}

#[test]
fn a_face_id_removal_is_applied_settled_and_published() {
    let mut world = world();
    let [shop, api] = world.items;
    world.with(|vault| {
        vault
            .add_agent_exception(world.agent, shop, ExceptionKind::Never)
            .unwrap();
        vault
            .add_agent_exception(world.agent, api, ExceptionKind::Only)
            .unwrap();
    });
    let phone = world.phone("Test iPhone", answer_key());
    world.start(config());
    // End to end: the iPhone reads and opens the feed with the contract's AAD.
    let feed = phone.wait_feed(&world, "the exceptions", |feed| {
        feed.agents
            .first()
            .is_some_and(|agent| agent.exceptions.len() == 2)
    });
    assert_eq!(feed.mac.device, world.me().uuid);
    assert_eq!(feed.mac.name, "Synthetic MacBook");
    assert_eq!(feed.agents[0].name, "Claude Code");
    assert_eq!(feed.agents[0].host, "claude");
    let never = feed.agents[0]
        .exceptions
        .iter()
        .find(|exception| exception.kind == "never")
        .unwrap()
        .clone();
    assert_eq!(never.item_title, "Shop database");
    let removal = phone.removal(&world, &feed, &never);
    phone.send(&world, &removal, world.mac_id(), |text| {
        phone.answer.sign(text).unwrap()
    });
    let (outcome, settle) = phone.settle(&world, &removal.action_id);
    assert_eq!(outcome, "applied");
    assert_eq!(settle.reason, "");
    let shown_at = settle.feed_seq.expect("the feed that shows the result");
    assert!(shown_at > feed.seq);
    assert!(
        !world
            .exceptions()
            .iter()
            .any(|exception| exception.kind == ExceptionKind::Never)
    );
    let after = phone.wait_feed(&world, "the feed without the row", |feed| {
        feed.seq >= shown_at
    });
    assert_eq!(after.agents[0].exceptions.len(), 1);
    assert!(world.activity().iter().any(|line| line
        == "Removed on Test iPhone: “Not for this agent” for Claude Code and Shop database"));

    // An "only these items" row goes with the relay key of the iPhone, no Face ID. An
    // iPhone of 0.5.2 sends it in v1, ids only: it takes authority away, so it applies,
    // with a note in Activity.
    let only = after.agents[0].exceptions[0].clone();
    assert_eq!(only.kind, "only");
    let removal = phone.removal_v1(&world, &after, &only);
    phone.send(&world, &removal, world.mac_id(), |text| {
        phone.client.sign(text).unwrap()
    });
    assert_eq!(phone.settle(&world, &removal.action_id).0, "applied");
    assert!(world.exceptions().is_empty());
    assert!(world.activity().iter().any(|line| line
        == "Removed on Test iPhone: “Only these items” for Claude Code and API token. \
            Test iPhone did not sign the names; update Apassy on it"));
}

/// Section 9.5 step 8a: a v1 action signs ids only. One that gives authority back
/// (`never`, `always_ask`) is refused, with what to do, and the row stays; the gate makes
/// no proof for it either.
#[test]
fn a_v1_removal_that_gives_authority_back_is_refused() {
    let mut world = world();
    let [shop, api] = world.items;
    world.with(|vault| {
        vault
            .add_agent_exception(world.agent, shop, ExceptionKind::Never)
            .unwrap();
        vault
            .add_agent_exception(world.agent, api, ExceptionKind::AlwaysAsk)
            .unwrap();
    });
    let phone = world.phone("Test iPhone", answer_key());
    world.start(config());
    let feed = phone.wait_feed(&world, "the exceptions", |feed| {
        feed.agents
            .first()
            .is_some_and(|agent| agent.exceptions.len() == 2)
    });
    let rows = world.exceptions();
    for exception in feed.agents[0].exceptions.clone() {
        let removal = phone.removal_v1(&world, &feed, &exception);
        phone.send(&world, &removal, world.mac_id(), |text| {
            phone.answer.sign(text).unwrap()
        });
        let (outcome, settle) = phone.settle(&world, &removal.action_id);
        assert_eq!(
            (outcome.as_str(), settle.reason.as_str()),
            (
                "refused",
                "update Apassy on Test iPhone to remove this from it, or remove it on this Mac"
            ),
            "{}",
            exception.kind
        );
        assert_eq!(world.exceptions(), rows, "the row stays");
    }
    assert!(world.activity().iter().any(|line| line
        == "An action from Test iPhone did not count: update Apassy on Test iPhone to remove \
            this from it, or remove it on this Mac."));
    // The gate refuses it too, whatever its caller checked.
    let removal = phone.removal_v1(&world, &feed, &feed.agents[0].exceptions[0]);
    let signature = answer_key()
        .sign(removal.string().unwrap().as_bytes())
        .unwrap();
    let item_id = world.with(|vault| vault.item_by_uuid(&removal.item_uuid).unwrap().unwrap());
    let gate = OwnerGate::new(Arc::clone(&world.shared), None);
    assert_eq!(
        gate.authorize(
            OwnerAction::RemoveAgentException {
                agent_id: world.agent,
                item_id,
                kind: removal.kind,
            },
            OwnerCheck::RemoteAction {
                signed: Box::new(removal.clone()),
                signature,
            },
        )
        .unwrap_err(),
        OwnerAuthError::RemoteRejected
    );
}

/// Section 9.5 step 10: the names are checked again under the lock of the removal. A
/// rename that syncs in after the first check is not what the owner saw.
#[test]
fn the_names_are_those_of_the_vault_at_the_removal() {
    let world = world();
    let [shop, _] = world.items;
    world.with(|vault| {
        vault
            .add_agent_exception(world.agent, shop, ExceptionKind::Never)
            .unwrap();
    });
    let me = world.me();
    let item_uuid = world.with(|vault| vault.item_uuid(shop).unwrap().unwrap());
    let removal = RemovalAction {
        by: PHONE_UUID.to_owned(),
        to: me.uuid.clone(),
        team_id: world.team().to_owned(),
        action_id: ACTION_ID.to_owned(),
        agent_id: world.agent,
        item_uuid,
        kind: ExceptionKind::Never,
        created_at: 1,
        feed_seq: 1,
        time: now(),
        names: Some(names_digest("Claude Code", "Shop database", &me.name)),
    };
    let holds = |removal: &RemovalAction| {
        world.with(|vault| names_hold(vault, removal, world.agent, shop, &me.uuid))
    };
    assert!(holds(&removal));
    // A v1 action holds only for an `only` row.
    let mut v1 = removal.clone();
    v1.names = None;
    assert!(!holds(&v1));
    v1.kind = ExceptionKind::Only;
    assert!(holds(&v1));
    // The item is renamed (a sync from another device): the names the owner saw are gone.
    world.with(|vault| {
        let summary = vault
            .search("")
            .unwrap()
            .into_iter()
            .find(|summary| summary.id == shop)
            .unwrap();
        vault
            .update(shop, summary.revision, secret_item("Test DB", SHOP_SECRET))
            .unwrap();
    });
    assert!(!holds(&removal));
    assert_eq!(
        world.with(|vault| names_in_vault(vault, world.agent, shop, &me.uuid).unwrap()),
        Some(vec![names_digest("Claude Code", "Test DB", &me.name)])
    );
}

/// Section 9.3, v2: the feed of this Mac says that it checks the names (its plaintext
/// ends in a line feed, which the strict reader of 0.5.2 skips), and a removal that signs
/// the names the owner saw is applied for each kind, with no note in Activity.
#[test]
fn a_removal_that_signs_the_names_is_applied() {
    let mut world = world();
    let [shop, api] = world.items;
    world.with(|vault| {
        vault
            .add_agent_exception(world.agent, shop, ExceptionKind::Never)
            .unwrap();
        vault
            .add_agent_exception(world.agent, api, ExceptionKind::Only)
            .unwrap();
    });
    let phone = world.phone("Test iPhone", answer_key());
    world.start(config());
    let feed = phone.wait_feed(&world, "the exceptions", |feed| {
        feed.agents
            .first()
            .is_some_and(|agent| agent.exceptions.len() == 2)
    });
    let stored = stored_plaintext(&world);
    assert!(Feed::checks_names(stored.as_bytes()), "the mark of v2");
    assert!(stored.ends_with("}\n") && !stored.ends_with("\n\n"));
    assert_eq!(Feed::parse(stored.as_bytes()).unwrap().seq, feed.seq);
    let never = feed.agents[0]
        .exceptions
        .iter()
        .find(|exception| exception.kind == "never")
        .unwrap()
        .clone();
    let removal = phone.removal(&world, &feed, &never);
    assert_eq!(
        removal.names.as_deref(),
        Some(names_digest("Claude Code", "Shop database", "Synthetic MacBook").as_str())
    );
    assert!(
        removal
            .string()
            .unwrap()
            .starts_with("apassy-feed-action-v2\n")
    );
    phone.send(&world, &removal, world.mac_id(), |text| {
        phone.answer.sign(text).unwrap()
    });
    let (outcome, settle) = phone.settle(&world, &removal.action_id);
    assert_eq!((outcome.as_str(), settle.reason.as_str()), ("applied", ""));
    assert!(
        world.activity().iter().any(|line| line
            == "Removed on Test iPhone: “Not for this agent” for Claude Code and Shop database"),
        "{:?}",
        world.activity()
    );
    // "Only these items": the same names, signed with the relay key.
    let after = phone.wait_feed(&world, "the feed without the row", |feed| {
        feed.agents[0].exceptions.len() == 1
    });
    let only = after.agents[0].exceptions[0].clone();
    assert_eq!(only.kind, "only");
    let removal = phone.removal(&world, &after, &only);
    phone.send(&world, &removal, world.mac_id(), |text| {
        phone.client.sign(text).unwrap()
    });
    assert_eq!(phone.settle(&world, &removal.action_id).0, "applied");
    assert!(world.exceptions().is_empty());
}

/// Section 15: a holder of the question key who works with the relay serves a feed that
/// puts false names on real ids. The iPhone signs the names it showed; the Mac rebuilds
/// its own and refuses the action as `stale`, and the row stays. For each kind.
#[test]
fn a_feed_that_lies_about_the_names_is_stale() {
    let mut world = world();
    let [shop, api] = world.items;
    world.with(|vault| {
        vault
            .add_agent_exception(world.agent, shop, ExceptionKind::Never)
            .unwrap();
        vault
            .add_agent_exception(world.agent, api, ExceptionKind::Only)
            .unwrap();
    });
    let phone = world.phone("Test iPhone", answer_key());
    world.start(config());
    let feed = phone.wait_feed(&world, "the exceptions", |feed| {
        feed.agents
            .first()
            .is_some_and(|agent| agent.exceptions.len() == 2)
    });
    let rows = world.exceptions();
    let pick = |kind: &str| {
        feed.agents[0]
            .exceptions
            .iter()
            .find(|exception| exception.kind == kind)
            .unwrap()
            .clone()
    };
    let mac = world.me().name;
    for (exception, by_answer_key) in [(pick("never"), true), (pick("only"), false)] {
        // The lying feed: the real agent id and item uuid, with other names.
        let lies = [
            ("Scratch Bot", exception.item_title.as_str(), mac.as_str()),
            ("Claude Code", "Test DB", mac.as_str()),
            ("Claude Code", exception.item_title.as_str(), "Scratch Mac"),
        ];
        for (agent, title, mac_name) in lies {
            let mut removal = phone.removal(&world, &feed, &exception);
            removal.names = Some(names_digest(agent, title, mac_name));
            phone.send(&world, &removal, world.mac_id(), |text| {
                if by_answer_key {
                    phone.answer.sign(text).unwrap()
                } else {
                    phone.client.sign(text).unwrap()
                }
            });
            let (outcome, settle) = phone.settle(&world, &removal.action_id);
            assert_eq!(
                (outcome.as_str(), settle.reason.as_str()),
                ("stale", "the names on the iPhone did not match this Mac"),
                "{agent} / {title} / {mac_name}"
            );
            assert_eq!(settle.feed_seq, None);
            assert_eq!(world.exceptions(), rows, "the row stays");
        }
    }
    assert!(world.activity().iter().any(|line| line
        == "An action from Test iPhone did not count: the names on the iPhone did not match this Mac."));
    // False names with a signature that does not verify: the signature fails first, so no
    // line about names is ever blamed on an iPhone that did not sign.
    let other = DeviceKey::generate().unwrap();
    let mut forged = phone.removal(&world, &feed, &pick("never"));
    forged.names = Some(names_digest("Scratch Bot", "Shop database", &mac));
    phone.send(&world, &forged, world.mac_id(), |text| {
        other.sign(text).unwrap()
    });
    let (outcome, settle) = phone.settle(&world, &forged.action_id);
    assert_eq!(
        (outcome.as_str(), settle.reason.as_str()),
        ("refused", "its signature does not verify")
    );
    assert_eq!(world.exceptions(), rows, "the row stays");
    // The true names still work.
    let removal = phone.removal(&world, &feed, &pick("never"));
    phone.send(&world, &removal, world.mac_id(), |text| {
        phone.answer.sign(text).unwrap()
    });
    assert_eq!(phone.settle(&world, &removal.action_id).0, "applied");
}

/// A title that the feed cleans (a control character becomes a space there, a `?` in an
/// iPhone's list): an iPhone with its own copy of the item signs its own title, one
/// without signs the feed's; the Mac takes either.
#[test]
fn a_title_matches_in_either_form_that_an_iphone_shows() {
    let mut world = world();
    let title = "Shop\tdatabase";
    world.with(|vault| {
        let item = vault
            .add(secret_item(title, "SYNTH-tab-title-secret"))
            .unwrap()
            .id;
        vault
            .add_agent_exception(world.agent, item, ExceptionKind::Never)
            .unwrap();
    });
    let phone = world.phone("Test iPhone", answer_key());
    world.start(config());
    let feed = phone.wait_feed(&world, "the exception", |feed| {
        feed.agents
            .first()
            .is_some_and(|agent| agent.exceptions.len() == 1)
    });
    let exception = feed.agents[0].exceptions[0].clone();
    assert_eq!(exception.item_title, "Shop database");
    let mac = world.me().name;
    let here = names_here("Claude Code", title, &mac);
    assert_eq!(
        here,
        vec![
            names_digest("Claude Code", "Shop?database", &mac),
            names_digest("Claude Code", "Shop database", &mac),
        ]
    );
    // The feed's form, as an iPhone without the item signs it.
    let from_feed = phone.removal(&world, &feed, &exception);
    assert_eq!(from_feed.names.as_ref(), Some(&here[1]));
    // The own title, as an iPhone with its own copy of the item shows it.
    let mut own = phone.removal(&world, &feed, &exception);
    own.names = Some(here[0].clone());
    phone.send(&world, &own, world.mac_id(), |text| {
        phone.answer.sign(text).unwrap()
    });
    assert_eq!(phone.settle(&world, &own.action_id).0, "applied");
}

#[test]
fn bad_removals_are_refused_or_stale() {
    let mut world = world();
    let [shop, api] = world.items;
    world.with(|vault| {
        vault
            .add_agent_exception(world.agent, shop, ExceptionKind::Never)
            .unwrap();
        vault
            .add_agent_exception(world.agent, api, ExceptionKind::AlwaysAsk)
            .unwrap();
    });
    let phone = world.phone("Test iPhone", answer_key());
    world.start(config());
    let feed = phone.wait_feed(&world, "the exceptions", |feed| {
        feed.agents
            .first()
            .is_some_and(|agent| agent.exceptions.len() == 2)
    });
    let never = feed.agents[0]
        .exceptions
        .iter()
        .find(|exception| exception.kind == "never")
        .unwrap()
        .clone();
    let rows = world.exceptions();
    let expect = |removal: &RemovalAction, sign: &dyn Fn(&[u8]) -> Vec<u8>, outcome, reason| {
        phone.send(&world, removal, world.mac_id(), sign);
        let (clear, settle) = phone.settle(&world, &removal.action_id);
        assert_eq!((clear.as_str(), settle.reason.as_str()), (outcome, reason));
        assert_eq!(settle.feed_seq, None);
        assert_eq!(world.exceptions(), rows, "nothing changed");
    };
    let face_id = |text: &[u8]| answer_key().sign(text).unwrap();
    // A key that is not the registered answer key.
    let other = DeviceKey::generate().unwrap();
    expect(
        &phone.removal(&world, &feed, &never),
        &|text| other.sign(text).unwrap(),
        "refused",
        "its signature does not verify",
    );
    // The relay key of the iPhone for a removal that needs Face ID.
    expect(
        &phone.removal(&world, &feed, &never),
        &|text| phone.client.sign(text).unwrap(),
        "refused",
        "its signature does not verify",
    );
    // Outside the window of 60 s.
    let mut old = phone.removal(&world, &feed, &never);
    old.time = now() - 120;
    expect(&old, &face_id, "refused", "too old");
    // For another Mac.
    let mut elsewhere = phone.removal(&world, &feed, &never);
    elsewhere.to = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4e".to_owned();
    expect(&elsewhere, &face_id, "refused", "it is for another Mac");
    // An exception that the feed showed with another `created_at`: made again since.
    let mut remade = phone.removal(&world, &feed, &never);
    remade.created_at -= 1;
    expect(&remade, &face_id, "stale", "the list on this Mac changed");
    // A feed that this Mac never published.
    let mut unseen = phone.removal(&world, &feed, &never);
    unseen.feed_seq = feed.seq + 1_000;
    expect(&unseen, &face_id, "stale", "the list on this Mac changed");
    // A removed device.
    let gone_key = DeviceKey::generate().unwrap();
    let gone = world.phone("Old iPhone", gone_key);
    world.with(|vault| assert!(vault.remove_trusted_device(&gone.uuid).unwrap()));
    let removal = gone.removal(&world, &feed, &never);
    expect(
        &removal,
        &|text| gone.answer.sign(text).unwrap(),
        "refused",
        "the device is not an iPhone of this vault",
    );
    assert!(
        world.activity().iter().any(|line| line
            == "An action from Test iPhone did not count: its signature does not verify.")
    );

    // A locked vault: the Mac does not read the action, and nothing changes.
    world.with(|vault| vault.lock().unwrap());
    std::thread::sleep(Duration::from_millis(300));
    let locked = phone.removal(&world, &feed, &never);
    phone.send(&world, &locked, world.mac_id(), face_id);
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        world.relay.feed_action_state(&locked.action_id),
        Some(("open".to_owned(), None)),
        "no settle while locked"
    );
    world.with(|vault| vault.unlock(PASS).unwrap());
    assert_eq!(world.exceptions(), rows);
    // After the unlock it is checked as any other: still in its window, it applies.
    assert_eq!(phone.settle(&world, &locked.action_id).0, "applied");

    // A replay of the same action id by the relay: no second settle, no change.
    let settles = |id: &str| {
        world
            .relay
            .count(&format!("POST /v1/feed/actions/{id}/settle"))
    };
    let feed = phone.wait_feed(&world, "one exception left", |feed| {
        feed.agents[0].exceptions.len() == 1
    });
    let ask = feed.agents[0].exceptions[0].clone();
    let removal = phone.removal(&world, &feed, &ask);
    phone.send(&world, &removal, world.mac_id(), face_id);
    assert_eq!(phone.settle(&world, &removal.action_id).0, "applied");
    assert!(world.exceptions().is_empty());
    assert_eq!(settles(&removal.action_id), 1);
    world.with(|vault| {
        vault
            .add_agent_exception(world.agent, api, ExceptionKind::AlwaysAsk)
            .unwrap();
    });
    world.relay.reopen_feed_action(&removal.action_id);
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(settles(&removal.action_id), 1, "no second settle");
    assert_eq!(world.exceptions().len(), 1, "the row made again stays");
}

#[test]
fn the_gate_makes_a_remote_action_proof_only_for_its_removal() {
    let world = world();
    let [shop, api] = world.items;
    let phone = world.phone("Test iPhone", answer_key());
    let me = world.me();
    let item_uuid = world.with(|vault| {
        vault
            .add_agent_exception(world.agent, shop, ExceptionKind::Never)
            .unwrap();
        vault.item_uuid(shop).unwrap().unwrap()
    });
    let signed = RemovalAction {
        by: phone.uuid.clone(),
        to: me.uuid.clone(),
        team_id: world.team().to_owned(),
        action_id: ACTION_ID.to_owned(),
        agent_id: world.agent,
        item_uuid,
        kind: ExceptionKind::Never,
        created_at: world.exceptions()[0].created_at,
        feed_seq: 1,
        time: now(),
        names: Some(names_digest("Claude Code", "Shop database", &me.name)),
    };
    let signature = answer_key()
        .sign(signed.string().unwrap().as_bytes())
        .unwrap();
    let gate = OwnerGate::new(Arc::clone(&world.shared), None);
    let check = || OwnerCheck::RemoteAction {
        signed: Box::new(signed.clone()),
        signature: signature.clone(),
    };
    let remove = |item_id| OwnerAction::RemoveAgentException {
        agent_id: world.agent,
        item_id,
        kind: ExceptionKind::Never,
    };
    let proof = gate.authorize(remove(shop), check()).expect("the proof");
    assert_eq!(
        proof.method(),
        apassy::broker::approvals::CheckMethod::Remote
    );
    // Another item, another kind, another action: no proof.
    assert_eq!(
        gate.authorize(remove(api), check()).unwrap_err(),
        OwnerAuthError::RemoteRejected
    );
    assert_eq!(
        gate.authorize(
            OwnerAction::RemoveAgentException {
                agent_id: world.agent,
                item_id: shop,
                kind: ExceptionKind::AlwaysAsk,
            },
            check()
        )
        .unwrap_err(),
        OwnerAuthError::RemoteRejected
    );
    assert_eq!(
        gate.authorize(OwnerAction::Reveal { item_id: shop }, check())
            .unwrap_err(),
        OwnerAuthError::RemoteUnsupported
    );
    // A locked vault: no proof.
    world.with(|vault| vault.lock().unwrap());
    assert_eq!(
        gate.authorize(remove(shop), check()).unwrap_err(),
        OwnerAuthError::VaultLocked
    );
}

#[test]
fn an_old_relay_without_the_feed_is_named_once() {
    let mut world = world();
    world.relay.set_no_feed(true);
    let _phone = world.phone("Test iPhone", answer_key());
    world.start(config());
    let worker = world.worker.as_ref().unwrap();
    wait_until("the problem in the view", || {
        (worker.view().feed_problem.as_deref() == Some(UNSUPPORTED)).then_some(())
    });
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        world
            .activity()
            .iter()
            .filter(|line| line.as_str() == UNSUPPORTED)
            .count(),
        1
    );
    assert_eq!(world.feed_puts(), 0);
}

// ---- Review fixes: masking, a hostile relay, seq, the lock, and the switch. ----

/// No part of `secret` of 8 bytes or more is in `text`.
fn no_part_of(text: &str, secret: &str) -> bool {
    secret
        .as_bytes()
        .windows(8)
        .all(|part| !text.contains(std::str::from_utf8(part).unwrap()))
}

/// The broker of the world's vault on a socket in its folder.
fn broker_of(world: &World) -> (apassy::broker::BrokerHandle, std::path::PathBuf) {
    use apassy::broker::BrokerOptions;
    use apassy::broker::http::TlsClient;
    let socket = world._root.path().join("run").join("broker.sock");
    let options = BrokerOptions::with_tls(TlsClient::platform().expect("TLS"));
    let broker =
        apassy::broker::start_with(Arc::clone(&world.shared), &socket, options).expect("broker");
    (broker, socket)
}

/// A run of `script` with `items` by the world's agent, which has no grant: the broker
/// refuses it with `not_granted` and writes a use of each item, as every run does.
fn refused_run(world: &World, socket: &std::path::Path, items: &[u64], script: &str) {
    use apassy::agent::client;
    use apassy::agent::wire::Action;
    let answer = client::send(
        socket,
        &world.token,
        Action::Run {
            access_request_id: None,
            codes: Default::default(),
            items: items.to_vec(),
            command: vec!["/bin/sh".into(), "-c".into(), script.into()],
            cwd: world._root.path().display().to_string(),
            purpose: "Deploy the synthetic shop.".into(),
            path: Some("/usr/bin:/bin".into()),
            user_request: Some("Deploy the synthetic shop.".into()),
        },
    )
    .expect("broker answer");
    let code = answer.error.as_ref().map(|error| error.code.as_str());
    assert_eq!(code, Some("not_granted"), "{answer:?}");
}

/// Finding 1: the run masks the whole command with the values of every item of the
/// request before it cuts it, so the row of one item never holds a value of another, and
/// a value never leaves a part at the cut. The feed masks again with every value of the
/// vault, and a cut row that ends in the start of a value has that start masked too.
#[test]
fn run_commands_are_masked_with_every_item_before_the_cut() {
    let world = world();
    let [shop, api] = world.items;
    let (_broker, socket) = broker_of(&world);
    // The value of the shop item crosses byte 61 (the cut before) and the last value of
    // the API item crosses byte 256 (the cut now).
    let padding = "p".repeat(159);
    let tail = "e".repeat(40);
    let script =
        format!("deploy --api {API_SECRET} {SHOP_SECRET} {padding} --tail {API_SECRET} end {tail}");
    let text = format!("run /bin/sh -c {script}");
    let at = text.find(SHOP_SECRET).unwrap();
    assert!(at < 61 && at + SHOP_SECRET.len() > 61);
    let at = text.rfind(API_SECRET).unwrap();
    assert!(at < 256 && at + API_SECRET.len() > 256);
    refused_run(&world, &socket, &[shop, api], &script);
    let rows = world.with(|vault| {
        [shop, api].map(|item| vault.item_uses(item, 5).unwrap().remove(0).command_summary)
    });
    for row in &rows {
        assert!(row.len() <= 256, "{row}");
        assert!(
            row.starts_with("run /bin/sh -c deploy --api [apassy:secret] [apassy:secret] p"),
            "{row}"
        );
        assert!(row.ends_with("..."), "{row}");
        for secret in [SHOP_SECRET, API_SECRET] {
            assert!(no_part_of(row, secret), "a part of {secret} in {row}");
        }
    }

    // The API item is not in this run: its value at the cut stays in the row of the
    // shop item, and the feed masks its start.
    let before = "q".repeat(228);
    let script = format!("{before}{API_SECRET} end");
    refused_run(&world, &socket, &[shop], &script);
    let row = world.with(|vault| vault.item_uses(shop, 1).unwrap().remove(0).command_summary);
    assert!(row.ends_with("SYNTH-api-..."), "{row}");
    let me = world.me();
    let feed = world.with(|vault| build_feed(vault, &me, 1, now()).unwrap());
    let commands: Vec<&str> = feed.agents[0]
        .recent
        .iter()
        .map(|recent| recent.command.as_str())
        .collect();
    assert_eq!(commands.len(), 3);
    assert!(
        commands[0].ends_with("q[apassy:secret]..."),
        "{}",
        commands[0]
    );
    for command in &commands {
        assert!(command.len() <= 256, "{command}");
        for secret in [SHOP_SECRET, API_SECRET] {
            assert!(
                no_part_of(command, secret),
                "a part of {secret} in {command}"
            );
        }
    }
}

/// The Activity text of a run is masked as the use rows are: the whole command with the
/// values of every item of the request, and only then cut to 64 bytes. A value across
/// the cut leaves no part, and the row of each item holds no value of the other.
#[test]
fn the_activity_text_of_a_run_is_masked_with_every_item_before_the_cut() {
    let world = world();
    let [shop, api] = world.items;
    let (_broker, socket) = broker_of(&world);
    // The API value is whole before the cut; the shop value crosses byte 61, where the
    // text was cut before, also after the mask of the API value.
    let script = format!("deploy --api {API_SECRET} --db {SHOP_SECRET} --now");
    let text = format!("run /bin/sh -c {script}");
    let at = text.find(SHOP_SECRET).unwrap();
    assert!(at < 61 && at + SHOP_SECRET.len() > 61);
    let masked = text.replace(API_SECRET, "[apassy:secret]");
    let at = masked.find(SHOP_SECRET).unwrap();
    assert!(at < 61 && at + SHOP_SECRET.len() > 61);
    refused_run(&world, &socket, &[shop, api], &script);
    let (newest, rows) = world.with(|vault| {
        (
            vault.recent_activity(1).unwrap().remove(0),
            [shop, api].map(|item| vault.item_activity(item, 1).unwrap().remove(0)),
        )
    });
    assert_eq!(newest.decision, ActivityDecision::Deny);
    assert_eq!(
        newest.operation,
        "run /bin/sh -c deploy --api [apassy:secret] --db ..."
    );
    for row in &rows {
        assert_eq!(row.operation, newest.operation);
    }
    for row in rows.iter().chain([&newest]) {
        assert!(row.operation.len() <= 64, "{}", row.operation);
        assert!(!row.operation.contains("SYNTH"), "{}", row.operation);
        for secret in [SHOP_SECRET, API_SECRET] {
            assert!(no_part_of(&row.operation, secret), "{}", row.operation);
        }
    }

    // A short command is not cut; each value is masked.
    refused_run(
        &world,
        &socket,
        &[shop, api],
        &format!("x {SHOP_SECRET} {API_SECRET}"),
    );
    let row = world.with(|vault| vault.recent_activity(1).unwrap().remove(0));
    assert_eq!(
        row.operation,
        "run /bin/sh -c x [apassy:secret] [apassy:secret]"
    );
}

/// Finding 2: a relay floods the Mac with thousands of actions that do not open. The Mac
/// handles at most 20 of an answer, waits before it asks again, writes one Activity line
/// for all of them, and the earlier Activity rows stay.
#[test]
fn a_flood_of_actions_that_do_not_open_leaves_activity_alone() {
    let mut world = world();
    let phone = world.phone("Test iPhone", answer_key());
    world.start(config());
    phone.wait_feed(&world, "a feed", |_| true);
    world.with(|vault| {
        for index in 0..5 {
            vault
                .record_activity(&apassy::vault::NewActivity {
                    agent_id: None,
                    agent_name: "Synthetic".to_owned(),
                    item_id: None,
                    operation: "synthetic earlier row".to_owned(),
                    decision: apassy::vault::ActivityDecision::Allow,
                    reason: format!("earlier row {index}"),
                })
                .unwrap();
        }
    });
    let ids = world.relay.inject_garbage_actions(
        world.mac_id(),
        phone.client.device_id().unwrap(),
        3_000,
    );
    assert_eq!(ids.len(), 3_000);
    let settled = || {
        world
            .relay
            .log()
            .iter()
            .filter(|line| line.starts_with("POST /v1/feed/actions/") && line.ends_with("/settle"))
            .count()
    };
    wait_until("the first answer", || (settled() >= 20).then_some(()));
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(settled(), 20, "at most 20 of one answer, then a wait");
    wait_until("the second answer after the wait", || {
        (settled() >= 40).then_some(())
    });
    let rows = world.with(|vault| vault.recent_activity(500).unwrap());
    for index in 0..5 {
        let line = format!("earlier row {index}");
        assert!(rows.iter().any(|row| row.reason == line), "{line} stays");
    }
    let lines = world.activity();
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.as_str() == apassy::questions::feed::UNREADABLE_LINE)
            .count(),
        1,
        "{lines:?}"
    );
    assert!(
        !lines.iter().any(|line| line.starts_with("An action from")),
        "{lines:?}"
    );
}

/// Finding 2: a relay serves a damaged copy of a real action first. The id gets one
/// settle: the copy's. The real action does not get a second one and changes nothing.
#[test]
fn a_bad_copy_before_the_real_action_gets_the_only_settle() {
    let mut world = world();
    let [shop, _] = world.items;
    world.with(|vault| {
        vault
            .add_agent_exception(world.agent, shop, ExceptionKind::Never)
            .unwrap();
    });
    let phone = world.phone("Test iPhone", answer_key());
    world.start(config());
    let feed = phone.wait_feed(&world, "the exception", |feed| {
        feed.agents
            .first()
            .is_some_and(|agent| agent.exceptions.len() == 1)
    });
    let rows = world.exceptions();
    // Locked, the Mac reads no action: the relay has both copies before it looks.
    world.with(|vault| vault.lock().unwrap());
    std::thread::sleep(Duration::from_millis(300));
    let removal = phone.removal(&world, &feed, &feed.agents[0].exceptions[0]);
    phone.send(&world, &removal, world.mac_id(), |text| {
        phone.answer.sign(text).unwrap()
    });
    world.relay.bad_copy_first(&removal.action_id);
    world.with(|vault| vault.unlock(PASS).unwrap());
    let (outcome, settle) = phone.settle(&world, &removal.action_id);
    assert_eq!(
        (outcome.as_str(), settle.reason.as_str()),
        ("refused", "it could not be read")
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        world.relay.count(&format!(
            "POST /v1/feed/actions/{}/settle",
            removal.action_id
        )),
        1,
        "one settle for one id"
    );
    assert_eq!(world.exceptions(), rows, "the real action did not apply");
}

/// Finding 8: the vault locks while an answer of the action poll is on its way. The Mac
/// does not skip the action and does not settle it; after the unlock it applies it.
#[test]
fn an_action_that_a_lock_cut_short_is_checked_after_the_unlock() {
    let mut world = world();
    let [shop, _] = world.items;
    world.with(|vault| {
        vault
            .add_agent_exception(world.agent, shop, ExceptionKind::Never)
            .unwrap();
    });
    let phone = world.phone("Test iPhone", answer_key());
    world.start(config());
    let feed = phone.wait_feed(&world, "the exception", |feed| {
        feed.agents
            .first()
            .is_some_and(|agent| agent.exceptions.len() == 1)
    });
    let shared = Arc::clone(&world.shared);
    world.relay.on_next_actions(move || {
        shared.lock().unwrap().as_mut().unwrap().lock().unwrap();
    });
    let removal = phone.removal(&world, &feed, &feed.agents[0].exceptions[0]);
    phone.send(&world, &removal, world.mac_id(), |text| {
        phone.answer.sign(text).unwrap()
    });
    wait_until("the lock", || {
        world.with(|vault| vault.is_locked()).then_some(())
    });
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(
        world.relay.feed_action_state(&removal.action_id),
        Some(("open".to_owned(), None)),
        "no settle while locked"
    );
    world.with(|vault| vault.unlock(PASS).unwrap());
    assert_eq!(phone.settle(&world, &removal.action_id).0, "applied");
    assert!(world.exceptions().is_empty());
}

/// Finding 7: the read-back of the own feed follows `more`.
#[test]
fn the_read_back_follows_more() {
    let mut world = world();
    let phone = world.phone("Test iPhone", answer_key());
    world.start(config());
    phone.wait_feed(&world, "the first feed", |_| true);
    // The iPhone has a feed of its own too (a relay keeps one per device).
    let other = Sealed::new(&world.key(), b"synthetic aad", b"synthetic feed").unwrap();
    phone
        .client
        .put_feed(now(), &other)
        .expect("the iPhone's feed");
    world.worker = None;
    let ahead = now() + 1_000;
    world.relay.set_feed_seq(world.mac_id(), ahead);
    // One feed in each answer: the Mac's comes on the second page.
    world.relay.set_feed_page(Some(1));
    world.start(config());
    let next = wait_until("a feed after the restart", || {
        world
            .relay
            .feed_of(world.mac_id())
            .map(|(seq, ..)| seq)
            .filter(|seq| *seq > ahead)
    });
    assert_eq!(next, ahead + 1, "max(that seq + 1, now)");
}

/// Finding 7: a relay that answers `seq_not_newer` again and again gets three puts, then
/// the Mac waits.
#[test]
fn three_answers_seq_not_newer_make_the_mac_wait() {
    let mut world = world();
    let phone = world.phone("Test iPhone", answer_key());
    world.start(config());
    phone.wait_feed(&world, "the first feed", |_| true);
    std::thread::sleep(Duration::from_millis(1_200));
    world.relay.set_feed_not_newer(true);
    let before = world.feed_puts();
    world.with(|vault| vault.set_agent_note(world.agent, "A new note.").unwrap());
    wait_until("the first put", || {
        (world.feed_puts() > before).then_some(())
    });
    std::thread::sleep(Duration::from_millis(1_500));
    assert_eq!(world.feed_puts() - before, 3, "three puts, then a wait");
    world.relay.set_feed_not_newer(false);
    phone.wait_feed(&world, "the note after the wait", |feed| {
        feed.agents[0].note == "A new note."
    });
}

/// `403 feed_rate` (section 10.2): the read-back of the Mac's own feed at the start is a
/// pause of a whole minute, not a loop of reads; then the feed goes out as before.
#[test]
fn a_feed_rate_answer_makes_the_mac_wait_a_minute() {
    let mut world = world();
    let phone = world.phone("Test iPhone", answer_key());
    let reads = |world: &World| {
        world
            .relay
            .log()
            .iter()
            .filter(|line| *line == "GET /v1/feed")
            .count()
    };
    world.relay.rate_feed_reads(1);
    let started = Instant::now();
    world.start(config());
    wait_until("the refused read-back", || {
        (reads(&world) == 1).then_some(())
    });
    // A tick is 50 ms: a loop would have read about 60 times by now.
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(reads(&world), 1, "one read, then the pause");
    assert_eq!(world.feed_puts(), 0, "no feed before the read-back worked");
    // The questions go on meanwhile.
    assert!(world.relay.count("GET /v1/questions") > 0);
    let put = {
        let start = Instant::now();
        loop {
            if world.feed_puts() > 0 {
                break started.elapsed();
            }
            assert!(
                start.elapsed() < Duration::from_secs(90),
                "the feed after the pause"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    assert!(put >= Duration::from_secs(60), "{put:?}");
    assert_eq!(reads(&world), 2, "one read-back after the pause");
    phone.wait_feed(&world, "the feed after the pause", |_| true);
}

/// Finding 7: a retry gets `seq_not_newer`, and the relay holds that `seq` with other
/// bytes. That is not the feed the Mac sent: it publishes again with a higher `seq`.
#[test]
fn a_seq_that_landed_with_other_bytes_is_published_again() {
    let mut world = world();
    let phone = world.phone("Test iPhone", answer_key());
    world.start(config());
    let first = phone.wait_feed(&world, "the first feed", |_| true);
    std::thread::sleep(Duration::from_millis(1_200));
    world.relay.lose_next_answers("PUT /v1/feed", 1);
    world.with(|vault| vault.set_agent_note(world.agent, "A new note.").unwrap());
    let landed = wait_until("the put whose answer was lost", || {
        world
            .relay
            .feed_of(world.mac_id())
            .map(|(seq, ..)| seq)
            .filter(|seq| *seq > first.seq)
    });
    world.relay.swap_feed_bytes(world.mac_id());
    let feed = phone.wait_feed(&world, "a good feed above it", |feed| feed.seq > landed);
    assert_eq!(feed.agents[0].note, "A new note.");
}

/// Finding 3: "Show agents on the iPhone" off deletes the feed, on publishes it again;
/// the feed goes when the last iPhone goes, and when the questions go off.
#[test]
fn the_feed_leaves_the_relay_when_it_goes_off() {
    let mut world = world();
    let phone = world.phone("Test iPhone", answer_key());
    world.start(config());
    phone.wait_feed(&world, "the first feed", |_| true);
    let deletes = || world.relay.count("DELETE /v1/feed");
    let worker = world.worker.as_ref().unwrap();
    assert!(worker.feed_on(), "on by default");
    worker.set_feed(false);
    wait_until("the delete after off", || {
        world.relay.feed_of(world.mac_id()).is_none().then_some(())
    });
    assert_eq!(deletes(), 1);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        world.relay.feed_of(world.mac_id()),
        None,
        "off publishes nothing"
    );
    worker.set_feed(true);
    phone.wait_feed(&world, "a feed after on", |_| true);

    // The last iPhone leaves the vault.
    world.with(|vault| assert!(vault.remove_trusted_device(&phone.uuid).unwrap()));
    wait_until("the delete without an iPhone", || {
        world.relay.feed_of(world.mac_id()).is_none().then_some(())
    });
    assert_eq!(deletes(), 2);

    // A new iPhone, then the questions go off for the vault.
    let second = world.phone("Second iPhone", DeviceKey::generate().unwrap());
    second.wait_feed(&world, "a feed for the new iPhone", |_| true);
    world.with(|vault| {
        assert!(apassy::relay::membership::disable_questions(vault).unwrap());
    });
    wait_until("the delete when the questions go off", || {
        world.relay.feed_of(world.mac_id()).is_none().then_some(())
    });
    assert_eq!(deletes(), 3);
}

/// Finding 6: the gate takes the team and this Mac from the vault, not from the caller.
#[test]
fn the_gate_refuses_another_team_or_another_target() {
    let world = world();
    let [shop, _] = world.items;
    let phone = world.phone("Test iPhone", answer_key());
    let me = world.me();
    let item_uuid = world.with(|vault| {
        vault
            .add_agent_exception(world.agent, shop, ExceptionKind::Never)
            .unwrap();
        vault.item_uuid(shop).unwrap().unwrap()
    });
    let gate = OwnerGate::new(Arc::clone(&world.shared), None);
    let signed = RemovalAction {
        by: phone.uuid.clone(),
        to: me.uuid.clone(),
        team_id: world.team().to_owned(),
        action_id: ACTION_ID.to_owned(),
        agent_id: world.agent,
        item_uuid,
        kind: ExceptionKind::Never,
        created_at: world.exceptions()[0].created_at,
        feed_seq: 1,
        time: now(),
        names: Some(names_digest("Claude Code", "Shop database", &me.name)),
    };
    let authorize = |signed: &RemovalAction| {
        // The iPhone signs exactly what the caller says, so only the gate's own team and
        // target can refuse it.
        let signature = answer_key()
            .sign(signed.string().unwrap().as_bytes())
            .unwrap();
        gate.authorize(
            OwnerAction::RemoveAgentException {
                agent_id: world.agent,
                item_id: shop,
                kind: ExceptionKind::Never,
            },
            OwnerCheck::RemoteAction {
                signed: Box::new(signed.clone()),
                signature,
            },
        )
    };
    let mut other_team = signed.clone();
    other_team.team_id = "t_0000000000".to_owned();
    assert_eq!(
        authorize(&other_team).unwrap_err(),
        OwnerAuthError::RemoteRejected
    );
    let mut other_target = signed.clone();
    other_target.to = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4e".to_owned();
    assert_eq!(
        authorize(&other_target).unwrap_err(),
        OwnerAuthError::RemoteRejected
    );
    assert!(
        authorize(&signed).is_ok(),
        "the vault's own team, target, and names"
    );
    // A v1 action (ids only) makes no proof.
    let mut v1 = signed.clone();
    v1.names = None;
    assert_eq!(authorize(&v1).unwrap_err(), OwnerAuthError::RemoteRejected);
    // The gate rebuilds the names from the vault, whatever its caller checked.
    for (agent, title, mac) in [
        ("Scratch Bot", "Shop database", me.name.as_str()),
        ("Claude Code", "Test DB", me.name.as_str()),
        ("Claude Code", "Shop database", "Scratch Mac"),
    ] {
        let mut lying = signed.clone();
        lying.names = Some(names_digest(agent, title, mac));
        assert_eq!(
            authorize(&lying).unwrap_err(),
            OwnerAuthError::RemoteRejected,
            "{agent} / {title} / {mac}"
        );
    }
}

/// Section 9.4: the iPhone signs once with the `feed_seq` of the feed it showed. A newer
/// feed of the Mac in between does not matter while the row is as that feed showed it.
#[test]
fn an_action_from_an_older_feed_applies_while_the_row_is_the_same() {
    let mut world = world();
    let [shop, _] = world.items;
    world.with(|vault| {
        vault
            .add_agent_exception(world.agent, shop, ExceptionKind::Never)
            .unwrap();
    });
    let phone = world.phone("Test iPhone", answer_key());
    world.start(config());
    let older = phone.wait_feed(&world, "the exception", |feed| {
        feed.agents
            .first()
            .is_some_and(|agent| agent.exceptions.len() == 1)
    });
    world.with(|vault| vault.set_agent_note(world.agent, "A new note.").unwrap());
    phone.wait_feed(&world, "a newer feed", |feed| feed.seq > older.seq);
    let removal = phone.removal(&world, &older, &older.agents[0].exceptions[0]);
    assert_eq!(removal.feed_seq, older.seq);
    phone.send(&world, &removal, world.mac_id(), |text| {
        phone.answer.sign(text).unwrap()
    });
    assert_eq!(phone.settle(&world, &removal.action_id).0, "applied");
    assert!(world.exceptions().is_empty());
}
