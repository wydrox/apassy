//! Asking-Mac access transport. Relay ordering/roles never decide the winner.
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::access_request::{Answer, SignedBody, body_signature_message};
use super::envelope::{Sealed, answer_aad, card_aad, settle_aad};
use super::worker::{Shared, lock, unix_now};

struct Attempt {
    card: Sealed,
    posted: bool,
    after: u64,
    next: Instant,
    tries: usize,
    settle: Option<Sealed>,
    settled: bool,
}

pub(super) fn run(shared: &Shared) {
    let mut attempts: BTreeMap<String, Attempt> = BTreeMap::new();
    let mut epoch = None;
    while !shared.stop.load(Ordering::SeqCst) {
        let active = lock(&shared.state).active.clone();
        let Some(active) = active else {
            attempts.clear();
            shared.sleep(Duration::from_millis(250));
            continue;
        };
        if epoch != Some(active.epoch) {
            attempts.clear();
            epoch = Some(active.epoch);
        }
        let records = {
            let mut guard = lock(&shared.vault);
            let Some(v) = Shared::vault_of(&mut guard, &active) else {
                attempts.clear();
                continue;
            };
            let _ = v.expire_scoped_access_requests();
            v.scoped_access_requests().unwrap_or_default()
        };
        for r in records {
            let c = &r.card.card;
            if r.epoch != active.epoch
                || c.team_id != active.team_id
                || c.asker.device != active.me.uuid
                || c.asker.relay_device_id != active.client.device_id().unwrap_or(0)
            {
                continue;
            }
            let key = {
                let mut guard = lock(&shared.vault);
                Shared::vault_of(&mut guard, &active).and_then(|v| v.question_key().ok().flatten())
            };
            let Some(key) = key.filter(|k| k.key_id() == c.key_id) else {
                continue;
            };
            if !attempts.contains_key(&c.qid) {
                if r.state != "open" || c.expires_at.saturating_sub(unix_now()) <= 10 {
                    continue;
                }
                // Run publication has priority in this same carrier.
                if !shared.queue.pending().is_empty() {
                    continue;
                }
                let sealed = (|| {
                    let signature = active
                        .client
                        .sign(&body_signature_message("card", &r.card.body).ok()?)
                        .ok()?;
                    let wrapper = SignedBody::new("card", &r.card.body, &signature).ok()?;
                    let bytes = serde_json::to_vec(&wrapper).ok()?;
                    Sealed::new(
                        &key,
                        &card_aad(&c.team_id, &c.qid, &c.key_id, "member", c.expires_at),
                        &bytes,
                    )
                })();
                let Some(sealed) = sealed else {
                    lock(&shared.view).local_only.insert(r.id,"Review this access request on this Mac. It could not be sent to your other devices.".into());
                    continue;
                };
                attempts.insert(
                    c.qid.clone(),
                    Attempt {
                        card: sealed,
                        posted: false,
                        after: 0,
                        next: Instant::now(),
                        tries: 0,
                        settle: None,
                        settled: false,
                    },
                );
            }
            let a = attempts.get_mut(&c.qid).expect("inserted");
            if Instant::now() < a.next {
                continue;
            }
            let remaining = c.expires_at.saturating_sub(unix_now());
            if !a.posted && r.state == "open" && remaining > 10 {
                let result = active
                    .client
                    .post_question(&c.qid, "member", c.expires_at, &a.card);
                a.tries += 1;
                match result {
                    Ok(_) => a.posted = true,
                    Err(e) if e.status() == Some(409) => a.posted = true,
                    Err(e) => {
                        lock(&shared.view).local_only.insert(r.id,format!("Review this access request on this Mac. Remote publication failed: {e:?}"));
                        if !e.can_pass() {
                            a.next = Instant::now() + Duration::from_secs(300);
                            continue;
                        }
                        a.next = Instant::now()
                            + Duration::from_secs(
                                [2, 4, 8, 16, 30][a.tries.saturating_sub(1).min(4)],
                            );
                        continue;
                    }
                }
            }
            if a.posted && r.state == "open" && remaining > 0 {
                if let Ok(list) = active.client.answers(&c.qid, a.after, Duration::ZERO) {
                    for answer in list.answers {
                        a.after = a.after.max(answer.id);
                        if answer.key_id != c.key_id || answer.sealed().ciphertext_len() > 8208 {
                            continue;
                        }
                        let opened = answer.sealed().open(
                            &key,
                            &answer_aad(&c.team_id, &c.qid, &c.key_id, answer.device_id),
                        );
                        let parsed = opened.and_then(|b| Answer::parse(&b).ok());
                        let Some(parsed) = parsed else { continue };
                        let mut guard = lock(&shared.vault);
                        let Some(v) = Shared::vault_of(&mut guard, &active) else {
                            break;
                        };
                        let result = crate::broker::access_once::RemoteAccessAnswer::verify(
                            v,
                            r.id,
                            parsed,
                            answer.device_id,
                        )
                        .and_then(|proof| proof.commit(v));
                        if result.is_ok() {
                            shared.changed();
                            break;
                        }
                        let _=v.record_activity(&crate::vault::NewActivity{agent_id:c.agent.id.parse().ok(),
                            agent_name:c.agent.name.clone(),item_id:c.item.local_id.parse().ok(),
                            operation:"answer access request".into(),decision:crate::vault::ActivityDecision::Deny,
                            reason:"An access answer was refused: stale, changed, unauthenticated or already answered.".into()});
                    }
                }
            }
            let receipt = {
                let mut guard = lock(&shared.vault);
                Shared::vault_of(&mut guard, &active)
                    .and_then(|v| v.scoped_access_request(r.id).ok())
                    .and_then(|r| r.receipt)
            };
            if a.posted
                && !a.settled
                && remaining > 0
                && let Some(mut receipt) = receipt
            {
                if a.settle.is_none() {
                    loop {
                        let Ok(bytes) = serde_json::to_vec(&receipt) else {
                            break;
                        };
                        if bytes.len() <= 512 {
                            a.settle = (|| {
                                let sig = active
                                    .client
                                    .sign(&body_signature_message("settle", &bytes).ok()?)
                                    .ok()?;
                                let w = SignedBody::new("settle", &bytes, &sig).ok()?;
                                Sealed::new(
                                    &key,
                                    &settle_aad(&c.team_id, &c.qid, &c.key_id),
                                    &serde_json::to_vec(&w).ok()?,
                                )
                            })();
                            break;
                        }
                        if receipt
                            .device_name
                            .as_mut()
                            .is_none_or(|s| s.pop().is_none())
                        {
                            break;
                        }
                    }
                }
                if let Some(settle) = &a.settle {
                    match active.client.settle(&c.qid, settle) {
                        Ok(()) => a.settled = true,
                        Err(e) if !e.can_pass() => a.settled = true,
                        Err(_) => {}
                    }
                }
            }
            a.next = Instant::now() + Duration::from_secs(2);
        }
        shared.sleep(Duration::from_millis(250));
    }
}
