//! Typed ADR 0033 calls. This is a child of questions so the carrier stays shared.
use super::*;
use apassy::questions::access_request as access;
use apassy::vault::{QuestionKey, TrustedDeviceKind};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoAccessParams {
    #[serde(rename = "op")]
    _op: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessInput {
    #[serde(rename = "op")]
    _op: String,
    vault_id: String,
    qid: String,
    digest: String,
    kind: access::Choice,
    #[serde(default)]
    time: Option<u64>,
    #[serde(default)]
    signature: Option<String>,
}
#[derive(Clone)]
pub(super) struct PreparedAccess {
    answer: access::Answer,
    selected: Option<String>,
    drops: u64,
    devices: Vec<TrustedDevice>,
    started: Instant,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Guards {
    version: u32,
    high_water: u64,
    entries: BTreeMap<String, AccessGuard>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessGuard {
    protocol: String,
    vault_identity: String,
    team: String,
    asker: String,
    qid: String,
    digest: String,
    expires_at: u64,
    attempts: u8,
    posted: bool,
    #[serde(default)]
    card: Option<access::Card>,
    #[serde(default)]
    receipt: Option<access::Receipt>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardSeal {
    v: u32,
    nonce: String,
    ciphertext: String,
}
fn unavailable() -> CoreError {
    CoreError::new(
        "access_unavailable",
        "Review this access request on the asking Mac.",
    )
}
fn guard_unavailable() -> CoreError {
    CoreError::new(
        "history_storage_unavailable",
        "Access submission guards could not be saved. Review on the Mac.",
    )
}

impl Keys {
    fn access_card(&self, r: &Record, now: u64) -> CoreResult<access::VerifiedCard> {
        if self.is_removed()
            || r.to != "member"
            || r.key_id == apassy::relay::pairing::HANDOFF_KEY_ID
        {
            return Err(unavailable());
        }
        let (key_id, key) = self.key.as_ref().ok_or_else(unavailable)?;
        if key_id != &r.key_id || r.ciphertext.len() > 43712 {
            return Err(unavailable());
        }
        let key = QuestionKey::from_bytes(key.as_slice().try_into().map_err(|_| unavailable())?);
        let plain = apassy::questions::envelope::Sealed {
            key_id: r.key_id.clone(),
            nonce: r.nonce.clone(),
            ciphertext: r.ciphertext.clone(),
        }
        .open(
            &key,
            &apassy::questions::envelope::card_aad(
                &self.team_id,
                &r.qid,
                &r.key_id,
                &r.to,
                r.expires_at,
            ),
        )
        .ok_or_else(unavailable)?;
        // The signed asker identity must resolve only through live vault rows.
        for mac in &self.devices {
            if mac.kind != TrustedDeviceKind::Mac
                || mac.relay_devices.get(&self.team_id) != Some(&r.from_device_id)
            {
                continue;
            }
            let context = access::Context {
                vault_id: &self.vault_identity,
                team_id: &self.team_id,
                qid: &r.qid,
                key_id: &r.key_id,
                asker: &mac.uuid,
                relay_device_id: r.from_device_id,
                expires_at: r.expires_at,
            };
            // Historical cards can be inspected after expiry; never enable controls from this path.
            if let Ok(c) = access::verify_card(
                &plain,
                &mac.sign_key,
                &context,
                now.min(r.expires_at.saturating_sub(1)),
            ) {
                return Ok(c);
            }
        }
        Err(unavailable())
    }
    fn access_receipt(&self, r: &Record, c: &access::VerifiedCard) -> Option<access::Receipt> {
        let s = r.settle.as_ref()?;
        let (id, key) = self.key.as_ref()?;
        if id != &s.key_id {
            return None;
        }
        let plain = envelope::open(
            key,
            &decode_b64u(&s.nonce)?,
            &envelope::settle_aad(&self.team_id, &r.qid, id),
            &decode_b64u(&s.ciphertext)?,
        )?;
        let mac = self.devices.iter().find(|d| {
            d.uuid == c.card.asker.device
                && d.kind == TrustedDeviceKind::Mac
                && d.relay_devices.get(&self.team_id) == Some(&r.from_device_id)
        })?;
        access::verify_receipt(&plain, &mac.sign_key, c).ok()
    }
}

impl Core {
    pub(super) fn clear_access_history(&self, vault: &str) -> CoreResult<()> {
        let (mut guards, key) = self.access_guards(vault)?;
        for g in guards.entries.values_mut() {
            g.card = None;
            g.receipt = None;
        }
        guards.entries.retain(|_, g| g.expires_at > now());
        self.save_access_guards(vault, &guards, key.as_slice())
    }
    fn access_guard_path(&self, vault: &str) -> CoreResult<(std::path::PathBuf, String)> {
        if !self.request_guard_storage_ready || !super::super::config::valid_id(vault) {
            return Err(unavailable());
        }
        let name = format!("access-guards-v1-{vault}.json");
        let directory = self.paths.data_dir.join("request-history");
        let metadata = std::fs::symlink_metadata(&directory).map_err(|_| guard_unavailable())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(guard_unavailable());
        }
        Ok((directory.join(&name), name))
    }
    fn access_guards(&self, vault: &str) -> CoreResult<(Guards, Zeroizing<[u8; 32]>)> {
        let (path, _) = self.access_guard_path(vault)?;
        let exists = match std::fs::symlink_metadata(&path) {
            Ok(m) if m.is_file() && !m.file_type().is_symlink() && m.len() <= 2_097_152 => true,
            Ok(_) => return Err(guard_unavailable()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(guard_unavailable()),
        };
        let key = self
            .history_key_provider
            .as_deref()
            .ok_or_else(guard_unavailable)?
            .key(vault, !exists)
            .map_err(|_| guard_unavailable())?;
        if !exists {
            return Ok((
                Guards {
                    version: 1,
                    ..Default::default()
                },
                key,
            ));
        }
        let bytes = std::fs::read(path).map_err(|_| guard_unavailable())?;
        if bytes.len() > 2_097_152 {
            return Err(guard_unavailable());
        }
        let sealed: GuardSeal = serde_json::from_slice(&bytes).map_err(|_| guard_unavailable())?;
        if sealed.v != 1 {
            return Err(guard_unavailable());
        }
        let aad = format!("apassy-access-guards-v1\0{vault}");
        let plain = Zeroizing::new(
            envelope::open(
                key.as_slice(),
                &decode_b64u(&sealed.nonce).ok_or_else(guard_unavailable)?,
                aad.as_bytes(),
                &decode_b64u(&sealed.ciphertext).ok_or_else(guard_unavailable)?,
            )
            .ok_or_else(guard_unavailable)?,
        );
        let guards: Guards = serde_json::from_slice(&plain).map_err(|_| guard_unavailable())?;
        if guards.version != 1
            || guards.entries.len() > 1000
            || guards.high_water > now()
            || guards
                .entries
                .iter()
                .any(|(qid, g)| qid != &g.qid || g.protocol != access::PROTOCOL || g.attempts > 3)
        {
            return Err(guard_unavailable());
        }
        Ok((guards, key))
    }
    fn save_access_guards(&self, vault: &str, g: &Guards, key: &[u8]) -> CoreResult<()> {
        let (path, name) = self.access_guard_path(vault)?;
        let plain = Zeroizing::new(serde_json::to_vec(g).map_err(|_| guard_unavailable())?);
        if plain.len() > 1_500_000 {
            return Err(guard_unavailable());
        }
        let mut nonce = [0; 12];
        getrandom::fill(&mut nonce).map_err(|_| guard_unavailable())?;
        let aad = format!("apassy-access-guards-v1\0{vault}");
        let ciphertext =
            envelope::seal(key, &nonce, aad.as_bytes(), &plain).ok_or_else(guard_unavailable)?;
        let bytes = serde_json::to_vec(&GuardSeal {
            v: 1,
            nonce: encode_b64u(&nonce),
            ciphertext: encode_b64u(&ciphertext),
        })
        .map_err(|_| guard_unavailable())?;
        write_private(path.parent().ok_or_else(guard_unavailable)?, &name, &bytes)
            .map_err(|_| guard_unavailable())
    }
    fn access_open(
        &self,
        input: &AccessInput,
    ) -> CoreResult<(Using, Record, access::VerifiedCard)> {
        let using = self.context_for(&input.qid, Some(&input.vault_id))?;
        let r = guard(&self.questions)
            .contexts
            .get(&using.vault_id)
            .and_then(|c| c.records.get(&input.qid))
            .cloned()
            .ok_or_else(unavailable)?;
        let card = using.keys.access_card(&r, now())?;
        if r.state != "open" || now() >= card.card.expires_at || input.digest != card.digest {
            return Err(unavailable());
        }
        let own = using.keys.own_row()?;
        if own.kind != TrustedDeviceKind::Iphone
            || own.relay_devices.get(&using.keys.team_id) != Some(&using.keys.device_id)
            || own.sign_key != using.member.public_key()
            || (input.kind == access::Choice::AllowOnce
                && own.answer_key.as_ref() == Some(&own.sign_key))
        {
            return Err(unavailable());
        }
        Ok((using, r, card))
    }
    pub(crate) fn access_call(&self, op: &str, request: &str) -> CoreResult<String> {
        match op {
            "access_requests_list" => {
                let _: NoAccessParams = params(request)?;
                self.questions_refresh()?;
                self.questions_fetch(Duration::ZERO, false)?;
                let state = guard(&self.questions);
                let mut rows = Vec::new();
                for (vault, context) in &state.contexts {
                    for record in context.records.values() {
                        if let Ok(card) = context.keys.access_card(record, now()) {
                            let receipt = context.keys.access_receipt(record, &card);
                            if self.request_history_enabled
                                && let Ok((mut g, key)) = self.access_guards(vault)
                            {
                                g.entries
                                    .retain(|_, g| g.expires_at.saturating_add(30 * 86400) > now());
                                if g.entries.len() < 1000 || g.entries.contains_key(&record.qid) {
                                    let entry = g.entries.entry(record.qid.clone()).or_insert(
                                        AccessGuard {
                                            protocol: access::PROTOCOL.into(),
                                            vault_identity: card.card.vault_id.clone(),
                                            team: card.card.team_id.clone(),
                                            asker: card.card.asker.device.clone(),
                                            qid: record.qid.clone(),
                                            digest: card.digest.clone(),
                                            expires_at: card.card.expires_at,
                                            attempts: 0,
                                            posted: false,
                                            card: Some(card.card.clone()),
                                            receipt: None,
                                        },
                                    );
                                    if entry.digest == card.digest && entry.receipt.is_none() {
                                        entry.receipt = receipt.clone();
                                    }
                                    let _ = self.save_access_guards(vault, &g, key.as_slice());
                                }
                            }
                            let own = context.keys.own_row().ok().filter(|d| {
                                d.kind == TrustedDeviceKind::Iphone
                                    && d.relay_devices.get(&context.keys.team_id)
                                        == Some(&context.keys.device_id)
                            });
                            rows.push(json!({"vault_id":vault,"card":card.card,"digest":card.digest,
                                "state":state_of(record,now()),"receipt":receipt,
                                "answer_key":own.and_then(|d|d.answer_key).map(|k|encode_b64u(&k))}));
                        }
                    }
                }
                Ok(ok(
                    &json!({"protocol":access::PROTOCOL,"version":1,"requests":rows}),
                ))
            }
            "access_requests_history" => {
                let _: NoAccessParams = params(request)?;
                if !self.request_history_enabled {
                    return Ok(ok(
                        &json!({"protocol":access::PROTOCOL,"version":1,"requests":[]}),
                    ));
                }

                self.questions_refresh()?;
                let state = guard(&self.questions);
                let mut rows = Vec::new();
                for (vault, context) in &state.contexts {
                    if context.keys.is_removed() {
                        continue;
                    }
                    let Ok((guards, _)) = self.access_guards(vault) else {
                        continue;
                    };
                    for g in guards.entries.values() {
                        if g.vault_identity != context.keys.vault_identity {
                            continue;
                        }
                        if let Some(card) = &g.card {
                            rows.push(json!({"vault_id":vault,"card":card,"digest":g.digest,"state":"history","receipt":g.receipt,"answer_key":null}));
                        }
                    }
                }
                Ok(ok(
                    &json!({"protocol":access::PROTOCOL,"version":1,"requests":rows}),
                ))
            }
            "access_request_prepare" => {
                let input: AccessInput = params(request)?;
                if input.time.is_some() || input.signature.is_some() {
                    return Err(unavailable());
                }
                let (using, _r, card) = self.access_open(&input)?;
                let own = using.keys.own_row()?;
                let answer = access::Answer::prepare(&card, &own.uuid, input.kind, now())
                    .map_err(|_| unavailable())?;
                let bytes = answer.message(&card).map_err(|_| unavailable())?;
                let (g, _) = self.access_guards(&using.vault_id)?;
                if g.entries
                    .get(&input.qid)
                    .is_some_and(|g| g.posted || g.attempts >= 3)
                {
                    return Err(unavailable());
                }
                let selected = guard(&self.list).selected.clone();
                let mut state = guard(&self.questions);
                let prepared = PreparedAccess {
                    answer: answer.clone(),
                    selected,
                    drops: state.drops,
                    devices: using.keys.devices.clone(),
                    started: Instant::now(),
                };
                state
                    .access_prepared
                    .insert((using.vault_id, input.qid), prepared);
                Ok(ok(
                    &json!({"bytes":encode_b64u(&bytes),"time":answer.time,"digest":answer.digest,"needs_face_id":input.kind==access::Choice::AllowOnce,"retry_before":answer.retry_before()}),
                ))
            }
            "access_request_answer" => {
                let input: AccessInput = params(request)?;
                let lock = {
                    let mut locks = guard(&self.question_sending);
                    let weak = locks
                        .entry((input.vault_id.clone(), input.qid.clone()))
                        .or_default();
                    if let Some(lock) = weak.upgrade() {
                        lock
                    } else {
                        let lock = Arc::new(std::sync::Mutex::new(()));
                        *weak = Arc::downgrade(&lock);
                        lock
                    }
                };
                let _sending = guard(&lock);
                let (using, record, card) = self.access_open(&input)?;
                let prepared = guard(&self.questions)
                    .access_prepared
                    .get(&(input.vault_id.clone(), input.qid.clone()))
                    .cloned()
                    .ok_or_else(unavailable)?;
                let mut answer = prepared.answer;
                if input.time != Some(answer.time)
                    || input.kind != answer.kind
                    || input.digest != answer.digest
                    || prepared.selected != guard(&self.list).selected
                    || prepared.drops != guard(&self.questions).drops
                    || prepared.devices != using.keys.devices
                    || prepared.started.elapsed() >= Duration::from_secs(50)
                    || now() >= answer.retry_before()
                {
                    return Err(unavailable());
                }
                answer.check(&card, now()).map_err(|_| unavailable())?;
                let own = using.keys.own_row()?;
                if answer.kind == access::Choice::AllowOnce {
                    answer.signature = input.signature.ok_or_else(unavailable)?;
                    answer
                        .verify(
                            &card,
                            own.answer_key.as_deref().ok_or_else(unavailable)?,
                            now(),
                        )
                        .map_err(|_| unavailable())?;
                } else {
                    if input.signature.is_some() {
                        return Err(unavailable());
                    }
                    answer.signature = encode_b64u(
                        &using
                            .member
                            .sign(&answer.message(&card).map_err(|_| unavailable())?)?,
                    );
                }
                let storage_lock = guard(&self.questions);
                let live = storage_lock
                    .contexts
                    .get(&using.vault_id)
                    .filter(|c| Arc::ptr_eq(&c.member, &using.member))
                    .is_some_and(|c| c.keys.devices == using.keys.devices && !c.keys.is_removed());
                if !live
                    || !storage_lock
                        .access_prepared
                        .get(&(input.vault_id.clone(), input.qid.clone()))
                        .is_some_and(|p| {
                            p.answer.time == answer.time
                                && p.answer.digest == answer.digest
                                && p.answer.kind == answer.kind
                        })
                {
                    return Err(unavailable());
                }
                let (mut guards, key) = self.access_guards(&using.vault_id)?;
                guards
                    .entries
                    .retain(|_, g| g.expires_at.saturating_add(30 * 86400) > now());
                if guards.entries.len() >= 1000 && !guards.entries.contains_key(&input.qid) {
                    return Err(guard_unavailable());
                }
                let g = guards
                    .entries
                    .entry(input.qid.clone())
                    .or_insert(AccessGuard {
                        protocol: access::PROTOCOL.into(),
                        vault_identity: card.card.vault_id.clone(),
                        team: card.card.team_id.clone(),
                        asker: card.card.asker.device.clone(),
                        qid: input.qid.clone(),
                        digest: card.digest.clone(),
                        expires_at: card.card.expires_at,
                        attempts: 0,
                        posted: false,
                        card: self.request_history_enabled.then(|| card.card.clone()),
                        receipt: None,
                    });
                if g.digest != card.digest
                    || g.vault_identity != card.card.vault_id
                    || g.posted
                    || g.attempts >= 3
                {
                    return Err(unavailable());
                }
                g.attempts += 1;
                guards.high_water = now();
                self.save_access_guards(&using.vault_id, &guards, key.as_slice())?;
                drop(storage_lock);
                let (key_id, question_key) = using.keys.key.as_ref().ok_or_else(unavailable)?;
                let mut nonce = [0; 12];
                getrandom::fill(&mut nonce).map_err(|_| CoreError::io())?;
                let plaintext =
                    Zeroizing::new(serde_json::to_vec(&answer).map_err(|_| unavailable())?);
                let aad = envelope::answer_aad(
                    &using.keys.team_id,
                    &record.qid,
                    key_id,
                    using.keys.device_id,
                );
                let ciphertext = envelope::seal(question_key, &nonce, &aad, &plaintext)
                    .ok_or_else(unavailable)?;
                let body = json!({"v":1,"key_id":key_id,"nonce":encode_b64u(&nonce),"ciphertext":encode_b64u(&ciphertext)});
                let result = using
                    .member
                    .call_answer_once(&format!("/v1/questions/{}/answers", record.qid), &body)
                    .map_err(call_error)?;
                // A successful POST never proves consent. The signed Mac settle does that.
                let mut state = guard(&self.questions);
                state.context_mut(&using.vault_id, &using.member)?;
                let (mut latest, key) = self.access_guards(&using.vault_id)?;
                latest
                    .entries
                    .get_mut(&input.qid)
                    .ok_or_else(unavailable)?
                    .posted = true;
                self.save_access_guards(&using.vault_id, &latest, key.as_slice())?;
                state.access_prepared.remove(&(input.vault_id, input.qid));
                Ok(ok(&json!({"sent":true,"receipt":null,"relay":result})))
            }
            "access_request_cancel_prepared" => {
                let _: NoAccessParams = params(request)?;
                guard(&self.questions).access_prepared.clear();
                Ok(ok(&json!({})))
            }
            _ => Err(unavailable()),
        }
    }
}
