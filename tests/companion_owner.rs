#![cfg(feature = "vault")]

//! The owner check by a paired iPhone (ADR 0014, `OwnerCheck::Companion`): a signature of
//! the approval key over the approval string of the contract. The gate rebuilds the
//! string from the action, checks the time, and verifies the signature. A good signature
//! gives a proof that `ApprovalQueue::approve` accepts. All data is synthetic.

#[path = "support/companion.rs"]
mod companion_support;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apassy::broker::approvals::{
    ApprovalOutcome, ApprovalQueue, ApprovalRefusal, CheckMethod, OwnerAction, OwnerAuthError,
    OwnerCheck, PROOF_LIFETIME, PendingRun,
};
use apassy::companion::crypto::{ApproveAction, approve_string};
use apassy::companion::digest::run_digest_hex;
use companion_support::{DEVICE, Fixture, PASS, PhoneKey, fixture, run};

const OTHER_DEVICE: &str = "fedcba9876543210fedcba9876543210";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

struct Setup {
    fx: Fixture,
    request: PhoneKey,
    approval: PhoneKey,
    queue: Arc<ApprovalQueue>,
}

/// A vault with one paired phone and an approval queue.
fn setup() -> Setup {
    let fx = fixture();
    let (request, approval) = (PhoneKey::generate(), PhoneKey::generate());
    fx.pair(DEVICE, "Test iPhone", &request.public(), &approval.public())
        .expect("pair");
    Setup {
        fx,
        request,
        approval,
        queue: Arc::new(ApprovalQueue::new()),
    }
}

impl Setup {
    /// Put `run` in the queue on a thread, and return the run as it waits and the thread.
    fn wait(&self, run: PendingRun) -> (PendingRun, std::thread::JoinHandle<ApprovalOutcome>) {
        let queue = Arc::clone(&self.queue);
        let waiter =
            std::thread::spawn(move || queue.wait_for(run, Duration::from_secs(20), || true));
        let waiting = loop {
            if let Some(run) = self.queue.pending().into_iter().next() {
                break run;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        (waiting, waiter)
    }

    /// The signature that the phone makes for `run` with `key`.
    fn sign(
        &self,
        key: &PhoneKey,
        device_id: &str,
        action: ApproveAction,
        run: &PendingRun,
        time: u64,
    ) -> Vec<u8> {
        let text =
            approve_string(device_id, action, run.id, &run_digest_hex(run), time).expect("string");
        key.sign(&text)
    }

    fn check(&self, signature: Vec<u8>, time: u64) -> OwnerCheck {
        OwnerCheck::Companion {
            device_id: DEVICE.to_owned(),
            time,
            signature,
        }
    }
}

#[test]
fn a_good_signature_makes_a_proof_that_the_queue_accepts() {
    let s = setup();
    let (waiting, waiter) = s.wait(run(false));
    let time = now();
    let signature = s.sign(&s.approval, DEVICE, ApproveAction::Approve, &waiting, time);
    let proof =
        s.fx.gate
            .authorize(
                OwnerAction::ApproveRun(waiting.clone()),
                s.check(signature, time),
            )
            .expect("the phone confirms the approval");
    assert_eq!(proof.method(), CheckMethod::Companion);
    assert_eq!(proof.action(), &OwnerAction::ApproveRun(waiting));
    assert!(proof.is_fresh());
    assert_eq!(s.queue.approve(proof), Ok(()));
    assert_eq!(waiter.join().expect("join"), ApprovalOutcome::Approved);
}

#[test]
fn approve_and_remember_needs_its_own_signature_and_an_offer() {
    let s = setup();
    let (waiting, waiter) = s.wait(run(true));
    let time = now();
    let signature = s.sign(
        &s.approval,
        DEVICE,
        ApproveAction::ApproveAndRemember,
        &waiting,
        time,
    );
    let proof =
        s.fx.gate
            .authorize(
                OwnerAction::ApproveAndRemember(waiting.clone()),
                s.check(signature, time),
            )
            .expect("proof");
    assert_eq!(proof.method(), CheckMethod::Companion);
    assert_eq!(s.queue.approve(proof), Ok(()));
    assert_eq!(
        waiter.join().expect("join"),
        ApprovalOutcome::ApprovedAndRemembered
    );

    // A run without an offer: the gate confirms, and the queue refuses.
    let (waiting, waiter) = s.wait(run(false));
    let time = now();
    let signature = s.sign(
        &s.approval,
        DEVICE,
        ApproveAction::ApproveAndRemember,
        &waiting,
        time,
    );
    let proof =
        s.fx.gate
            .authorize(
                OwnerAction::ApproveAndRemember(waiting.clone()),
                s.check(signature, time),
            )
            .expect("proof");
    assert_eq!(
        s.queue.approve(proof),
        Err(ApprovalRefusal::NothingToRemember)
    );
    assert!(s.queue.deny(waiting.id));
    assert_eq!(waiter.join().expect("join"), ApprovalOutcome::Denied);
}

#[test]
fn the_wrong_key_is_refused() {
    let s = setup();
    let (waiting, waiter) = s.wait(run(false));
    let time = now();
    let action = || OwnerAction::ApproveRun(waiting.clone());
    // The request key of the same phone signs requests, not approvals.
    let by_request_key = s.sign(&s.request, DEVICE, ApproveAction::Approve, &waiting, time);
    // A key that is not paired.
    let stranger = PhoneKey::generate();
    let by_stranger = s.sign(&stranger, DEVICE, ApproveAction::Approve, &waiting, time);
    for signature in [by_request_key, by_stranger] {
        assert_eq!(
            s.fx.gate
                .authorize(action(), s.check(signature, time))
                .unwrap_err(),
            OwnerAuthError::CompanionRejected
        );
    }
    // Nothing was approved.
    assert_eq!(s.queue.pending(), vec![waiting.clone()]);
    assert!(s.queue.deny(waiting.id));
    waiter.join().expect("join");
}

#[test]
fn a_signature_for_another_run_digest_action_device_or_time_is_refused() {
    let s = setup();
    let (waiting, waiter) = s.wait(run(true));
    let time = now();
    let good = s.sign(&s.approval, DEVICE, ApproveAction::Approve, &waiting, time);
    let rejected = |action: OwnerAction, signature: Vec<u8>, time: u64| {
        assert_eq!(
            s.fx.gate
                .authorize(action, s.check(signature, time))
                .unwrap_err(),
            OwnerAuthError::CompanionRejected
        );
    };

    // Tampered digest: the phone signed a run as the Mac showed it, and the action names a
    // changed run (any field).
    let mut changed = waiting.clone();
    changed.command = vec!["rm".to_owned(), "-rf".to_owned(), "/tmp/x".to_owned()];
    rejected(OwnerAction::ApproveRun(changed), good.clone(), time);
    let mut changed = waiting.clone();
    changed.cwd = "/tmp/other".to_owned();
    rejected(OwnerAction::ApproveRun(changed), good.clone(), time);
    let mut changed = waiting.clone();
    changed.remember = None;
    rejected(OwnerAction::ApproveRun(changed), good.clone(), time);
    // A signature over a digest that the phone made up.
    let text = approve_string(
        DEVICE,
        ApproveAction::Approve,
        waiting.id,
        &"ab".repeat(32),
        time,
    )
    .expect("string");
    rejected(
        OwnerAction::ApproveRun(waiting.clone()),
        s.approval.sign(&text),
        time,
    );

    // Another run: the same content with another ID.
    let mut other_run = waiting.clone();
    other_run.id = waiting.id.wrapping_add(1);
    rejected(OwnerAction::ApproveRun(other_run), good.clone(), time);

    // Approve and approve-and-remember do not stand in for each other.
    rejected(
        OwnerAction::ApproveAndRemember(waiting.clone()),
        good.clone(),
        time,
    );
    let remember = s.sign(
        &s.approval,
        DEVICE,
        ApproveAction::ApproveAndRemember,
        &waiting,
        time,
    );
    rejected(OwnerAction::ApproveRun(waiting.clone()), remember, time);

    // Another time than the signed one.
    rejected(
        OwnerAction::ApproveRun(waiting.clone()),
        good.clone(),
        time + 1,
    );
    // A signature for another device ID: the text names the device.
    let for_other_device = s.sign(
        &s.approval,
        OTHER_DEVICE,
        ApproveAction::Approve,
        &waiting,
        time,
    );
    rejected(
        OwnerAction::ApproveRun(waiting.clone()),
        for_other_device,
        time,
    );

    // Garbage.
    rejected(OwnerAction::ApproveRun(waiting.clone()), Vec::new(), time);
    rejected(
        OwnerAction::ApproveRun(waiting.clone()),
        vec![0x30; 70],
        time,
    );
    let mut flipped = good.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    rejected(OwnerAction::ApproveRun(waiting.clone()), flipped, time);

    // The good signature still works after every refusal, and the run still waits.
    assert_eq!(s.queue.pending(), vec![waiting.clone()]);
    let proof =
        s.fx.gate
            .authorize(
                OwnerAction::ApproveRun(waiting.clone()),
                s.check(good, time),
            )
            .expect("the good signature works");
    assert_eq!(s.queue.approve(proof), Ok(()));
    assert_eq!(waiter.join().expect("join"), ApprovalOutcome::Approved);
}

#[test]
fn an_old_or_future_time_is_stale() {
    let s = setup();
    let (waiting, waiter) = s.wait(run(false));
    let lifetime = PROOF_LIFETIME.as_secs();
    let action = || OwnerAction::ApproveRun(waiting.clone());
    // Signed correctly, but too old or too far ahead.
    for time in [
        now() - lifetime - 30,
        now() - 3600,
        0,
        now() + 120,
        now() + 86_400,
        u64::MAX,
    ] {
        let signature = s.sign(&s.approval, DEVICE, ApproveAction::Approve, &waiting, time);
        assert_eq!(
            s.fx.gate
                .authorize(action(), s.check(signature, time))
                .unwrap_err(),
            OwnerAuthError::CompanionStale,
            "time {time}"
        );
    }
    assert!(
        OwnerAuthError::CompanionStale
            .message()
            .contains("Nothing was approved.")
    );
    // A time inside the window works: 30 seconds old, and 30 seconds ahead of the Mac.
    for time in [now() - 30, now() + 30] {
        let signature = s.sign(&s.approval, DEVICE, ApproveAction::Approve, &waiting, time);
        assert!(
            s.fx.gate
                .authorize(action(), s.check(signature, time))
                .is_ok(),
            "time {time}"
        );
    }
    assert!(s.queue.deny(waiting.id));
    waiter.join().expect("join");
}

#[test]
fn a_removed_or_unknown_device_is_refused() {
    let s = setup();
    let (waiting, waiter) = s.wait(run(false));
    let time = now();
    let signature = s.sign(&s.approval, DEVICE, ApproveAction::Approve, &waiting, time);
    // The same phone with another device ID: not paired.
    let other = OwnerCheck::Companion {
        device_id: OTHER_DEVICE.to_owned(),
        time,
        signature: s.sign(
            &s.approval,
            OTHER_DEVICE,
            ApproveAction::Approve,
            &waiting,
            time,
        ),
    };
    assert_eq!(
        s.fx.gate
            .authorize(OwnerAction::ApproveRun(waiting.clone()), other)
            .unwrap_err(),
        OwnerAuthError::CompanionRejected
    );
    // A device ID that is not 32 lowercase hex characters.
    for bad in [
        "",
        "not-a-device",
        &DEVICE.to_uppercase(),
        &format!("{DEVICE}\n"),
    ] {
        let check = OwnerCheck::Companion {
            device_id: bad.to_owned(),
            time,
            signature: signature.clone(),
        };
        assert_eq!(
            s.fx.gate
                .authorize(OwnerAction::ApproveRun(waiting.clone()), check)
                .unwrap_err(),
            OwnerAuthError::CompanionRejected
        );
    }
    // The owner removes the device: the signature that worked a moment ago does not.
    assert!(
        s.fx.gate
            .authorize(
                OwnerAction::ApproveRun(waiting.clone()),
                s.check(signature.clone(), time)
            )
            .is_ok()
    );
    assert!(s.fx.with(|vault| vault.remove_companion_device(DEVICE).expect("remove")));
    assert_eq!(
        s.fx.gate
            .authorize(
                OwnerAction::ApproveRun(waiting.clone()),
                s.check(signature, time)
            )
            .unwrap_err(),
        OwnerAuthError::CompanionRejected
    );
    assert!(
        OwnerAuthError::CompanionRejected
            .message()
            .contains("Nothing was approved.")
    );
    assert!(s.queue.deny(waiting.id));
    waiter.join().expect("join");
}

#[test]
fn a_locked_vault_is_refused() {
    let s = setup();
    let (waiting, waiter) = s.wait(run(false));
    let time = now();
    let signature = s.sign(&s.approval, DEVICE, ApproveAction::Approve, &waiting, time);
    s.fx.with(|vault| vault.lock().expect("lock"));
    assert_eq!(
        s.fx.gate
            .authorize(
                OwnerAction::ApproveRun(waiting.clone()),
                s.check(signature.clone(), time)
            )
            .unwrap_err(),
        OwnerAuthError::VaultLocked
    );
    // After an unlock the same signature works again: the session is another one, but the
    // proof is made in the new session.
    s.fx.with(|vault| vault.unlock(PASS).expect("unlock"));
    assert!(
        s.fx.gate
            .authorize(
                OwnerAction::ApproveRun(waiting.clone()),
                s.check(signature, time)
            )
            .is_ok()
    );
    assert!(s.queue.deny(waiting.id));
    waiter.join().expect("join");
}

#[test]
fn a_phone_can_confirm_the_approval_of_a_run_only() {
    let s = setup();
    let (waiting, waiter) = s.wait(run(false));
    let time = now();
    let signature = s.sign(&s.approval, DEVICE, ApproveAction::Approve, &waiting, time);
    let request_key = s.request.public();
    let approval_key = s.approval.public();
    let actions = [
        OwnerAction::Reveal { item_id: 1 },
        OwnerAction::ChangeGrant {
            agent_id: 1,
            item_id: 1,
        },
        OwnerAction::ChangeGrants {
            agent_id: 1,
            item_ids: vec![1],
        },
        OwnerAction::ShowAllCredentials { agent_id: 1 },
        OwnerAction::ChangeRule {
            agent_id: 1,
            item_id: 1,
        },
        OwnerAction::ChangeItemRules { item_id: 1 },
        OwnerAction::RotateToken { agent_id: 1 },
        OwnerAction::ChangeTokenLifetime,
        OwnerAction::ChangeCalibration { level: 50 },
        OwnerAction::PromoteModel {
            candidate_id: 1,
            version: "v1".to_owned(),
        },
        OwnerAction::RollbackModel { activation_id: 1 },
        // A phone cannot pair another phone.
        OwnerAction::PairCompanion {
            device_id: OTHER_DEVICE.to_owned(),
            device_name: "Another".to_owned(),
            request_key,
            approval_key,
        },
    ];
    for action in actions {
        let text = format!("{action:?}");
        assert_eq!(
            s.fx.gate
                .authorize(action, s.check(signature.clone(), time))
                .unwrap_err(),
            OwnerAuthError::CompanionUnsupported,
            "{text}"
        );
    }
    assert!(
        OwnerAuthError::CompanionUnsupported
            .message()
            .contains("approval of a run only")
    );
    assert!(!OwnerAuthError::CompanionUnsupported.passphrase_fallback());
    assert!(s.queue.deny(waiting.id));
    waiter.join().expect("join");
}

#[test]
fn the_same_signature_may_be_sent_again_and_the_run_settles_once() {
    // Contract section 7: the approval string has no nonce. After a network error the
    // phone may send the same signature again within 60 seconds.
    let s = setup();
    let (waiting, waiter) = s.wait(run(false));
    let time = now();
    let signature = s.sign(&s.approval, DEVICE, ApproveAction::Approve, &waiting, time);
    let first =
        s.fx.gate
            .authorize(
                OwnerAction::ApproveRun(waiting.clone()),
                s.check(signature.clone(), time),
            )
            .expect("first proof");
    assert_eq!(s.queue.approve(first), Ok(()));
    assert_eq!(waiter.join().expect("join"), ApprovalOutcome::Approved);
    let second =
        s.fx.gate
            .authorize(
                OwnerAction::ApproveRun(waiting.clone()),
                s.check(signature, time),
            )
            .expect("the gate confirms again");
    assert_eq!(s.queue.approve(second), Err(ApprovalRefusal::NotWaiting));
}

#[test]
fn a_proof_of_one_run_cannot_approve_another_run() {
    let s = setup();
    let (first, waiter) = s.wait(run(false));
    let time = now();
    let signature = s.sign(&s.approval, DEVICE, ApproveAction::Approve, &first, time);
    let proof =
        s.fx.gate
            .authorize(
                OwnerAction::ApproveRun(first.clone()),
                s.check(signature, time),
            )
            .expect("proof");
    // The first run settles by a denial. A second run waits with another ID.
    assert!(s.queue.deny(first.id));
    waiter.join().expect("join");
    let (second, second_waiter) = s.wait(run(false));
    assert_ne!(second.id, first.id);
    assert_eq!(s.queue.approve(proof), Err(ApprovalRefusal::NotWaiting));
    assert_eq!(s.queue.pending(), vec![second.clone()]);
    assert!(s.queue.deny(second.id));
    second_waiter.join().expect("join");
}

#[test]
fn the_companion_check_and_action_do_not_print_a_signature_or_a_command() {
    let check = OwnerCheck::Companion {
        device_id: DEVICE.to_owned(),
        time: 1_790_000_000,
        signature: vec![0xde, 0xad, 0xbe, 0xef, 0x12, 0x34],
    };
    let debug = format!("{check:?}");
    assert_eq!(
        debug,
        format!(
            "OwnerCheck::Companion {{ device_id: {DEVICE}, time: 1790000000, signature: [redacted] }}"
        )
    );
    assert!(!debug.contains("222") && !debug.to_lowercase().contains("dead"));
    assert_eq!(check.method(), CheckMethod::Companion);

    let pair = OwnerAction::PairCompanion {
        device_id: DEVICE.to_owned(),
        device_name: "Test \"quoted\" iPhone".to_owned(),
        request_key: vec![4; 65],
        approval_key: vec![4; 65],
    };
    assert_eq!(pair.reason(), "pair the iPhone \"Test quoted iPhone\"");
    assert!(pair.run().is_none());
    let unnamed = OwnerAction::PairCompanion {
        device_id: DEVICE.to_owned(),
        device_name: "\"\n".to_owned(),
        request_key: Vec::new(),
        approval_key: Vec::new(),
    };
    assert_eq!(unnamed.reason(), "pair the iPhone \"unknown\"");
}

#[test]
fn the_passphrase_still_makes_a_proof_for_a_pairing() {
    // The pairing is confirmed on the Mac, with Touch ID or the passphrase.
    let s = setup();
    let other = PhoneKey::generate();
    let proof =
        s.fx.gate
            .authorize(
                OwnerAction::PairCompanion {
                    device_id: OTHER_DEVICE.to_owned(),
                    device_name: "Second".to_owned(),
                    request_key: other.public(),
                    approval_key: other.public(),
                },
                OwnerCheck::passphrase(PASS),
            )
            .expect("proof");
    assert_eq!(proof.method(), CheckMethod::Passphrase);
}
