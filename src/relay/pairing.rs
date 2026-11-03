//! A QR capability hands question keys to a confirmed iPhone or Apple Watch (ADR 0039 §6)
//! over existing opaque question routes. The relay never sees the QR secret. No vault
//! snapshot or paid sync is involved.
use crate::questions::envelope::{Sealed, new_qid, open};
use crate::questions::{QuestionsClient, QuestionsError};
use crate::sync::DeviceKey;
use crate::sync::{decode_b64u, encode_b64u};
use crate::vault::{QuestionKey, TrustedDevice, Vault, VaultErrorKind, VaultResult};
use p256::pkcs8::DecodePrivateKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Reserved transport marker; never a request for an owner decision.
pub const HANDOFF_KEY_ID: &str = "c011ec7000000001";
const MARK: &str = "&handoff=";

#[derive(Clone)]
pub struct PairingChannel {
    qid: String,
    key: QuestionKey,
    mac_public: Vec<u8>,
    mac_private: Option<Zeroizing<Vec<u8>>>,
    raw_link: Zeroizing<String>,
}
impl std::fmt::Debug for PairingChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingChannel([redacted])")
    }
}
#[derive(Serialize, Deserialize)]
pub struct Handoff {
    pub v: u8,
    pub vault_id: String,
    pub team_id: String,
    pub recipient: Vec<u8>,
    #[serde(with = "secret_bytes")]
    pub question_key: Zeroizing<Vec<u8>>,
    pub key_updated_at: i64,
    pub key_updated_by: String,
    pub devices: Vec<TrustedDevice>,
}
mod secret_bytes {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        bytes: &Zeroizing<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        bytes.as_slice().serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Zeroizing<Vec<u8>>, D::Error> {
        Vec::<u8>::deserialize(deserializer).map(Zeroizing::new)
    }
}
/// The link code of a device link without a handoff: the fragment up to its first
/// parameter (`&pin=…`, contract node-pairing-v1 section 5).
fn link_code_of(raw_link: &str) -> Option<&str> {
    let fragment = raw_link.split_once("/link#")?.1;
    fragment.split('&').next()
}

// Never print secret-bearing handoffs.
impl PairingChannel {
    pub fn team_id(&self) -> Option<&str> {
        crate::sync::relay_crypto::link_code_team(link_code_of(&self.raw_link)?)
    }
    pub fn qid(&self) -> &str {
        &self.qid
    }
    /// A new channel for the device link `raw_link` without a handoff: a hosted link, or
    /// a pinned one with its `pin`, `alt`, and `name` (node-pairing-v1). The AAD and the
    /// safety words cover `raw_link` exactly as written, so they cover the pin too
    /// (section 8).
    pub fn generate(raw_link: &str) -> Option<Self> {
        let paired = crate::sync::PairedLink::parse(raw_link).ok()?;
        if paired.kind != crate::sync::LinkKind::Device
            || paired.handoff.is_some()
            || paired.without_handoff.as_str() != raw_link
        {
            return None;
        }
        let mac = DeviceKey::generate().ok()?;
        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::fill(bytes.as_mut()).ok()?;
        Some(Self {
            qid: new_qid()?,
            key: QuestionKey::from_bytes(*bytes),
            mac_public: mac.public_key().to_vec(),
            mac_private: Some(mac.pkcs8()?.clone()),
            raw_link: Zeroizing::new(raw_link.to_owned()),
        })
    }
    /// All secret material stays in the URL fragment; strip it before any relay call.
    pub fn link(&self, raw: &str) -> Zeroizing<String> {
        let secret = Zeroizing::new(encode_b64u(self.key.bytes()));
        Zeroizing::new(format!(
            "{raw}{MARK}2.{}.{}.{}",
            self.qid,
            secret.as_str(),
            encode_b64u(&self.mac_public)
        ))
    }
    /// Read the handoff of a scanned or pasted device link. Returns "the original full
    /// link without handoff" of the AAD (node-pairing-v1 section 8): the link, without
    /// the white space at its ends, up to `&handoff=`, with its `pin`, `alt`, and `name`
    /// exactly as written. A link without a pin gives the same text as before that
    /// contract. A link that the grammar refuses has no channel.
    pub fn parse(link: &str) -> Option<(&str, Self)> {
        let paired = crate::sync::PairedLink::parse(link).ok()?;
        if paired.kind != crate::sync::LinkKind::Device {
            return None;
        }
        let capsule = paired.handoff.as_deref()?;
        let trimmed = link.trim_matches(|c: char| c.is_ascii_whitespace());
        let raw = trimmed.get(..paired.without_handoff.len())?;
        if raw != paired.without_handoff.as_str() || !trimmed[raw.len()..].starts_with(MARK) {
            return None;
        }
        let mut parts = capsule.split('.');
        if parts.next()? != "2" {
            return None;
        }
        let qid = parts.next()?;
        let key = parts.next()?;
        let mac_public = decode_b64u(parts.next()?)?;
        p256::PublicKey::from_sec1_bytes(&mac_public).ok()?;
        if mac_public.len() != 65 || parts.next().is_some() {
            return None;
        }
        if !crate::questions::envelope::valid_qid(qid) {
            return None;
        }
        let decoded = Zeroizing::new(decode_b64u(key)?);
        let key: [u8; 32] = decoded.as_slice().try_into().ok()?;
        Some((
            raw,
            Self {
                qid: qid.to_owned(),
                key: QuestionKey::from_bytes(key),
                mac_public,
                mac_private: None,
                raw_link: Zeroizing::new(raw.to_owned()),
            },
        ))
    }
    // ECDH possession, not a public recipient label, controls access to the handoff.
    fn shared_key(&self, private: &[u8], peer: &[u8]) -> Option<QuestionKey> {
        let secret = p256::SecretKey::from_pkcs8_der(private).ok()?;
        let public = p256::PublicKey::from_sec1_bytes(peer).ok()?;
        let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
        let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, self.key.bytes());
        let prk = salt.extract(shared.raw_secret_bytes());
        let info = [b"apassy-connect-ecdh-v2".as_slice()];
        let okm = prk.expand(&info, ring::hkdf::HKDF_SHA256).ok()?;
        let mut key = Zeroizing::new([0; 32]);
        okm.fill(key.as_mut()).ok()?;
        Some(QuestionKey::from_bytes(*key))
    }
    fn aad(&self, team: &str, recipient: &[u8], device_name: &str) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(
            format!(
                "apassy-connect-handoff-v2\0{}\0{team}\0{}\0{}\0{}\0{device_name}",
                self.raw_link.as_str(),
                self.qid,
                encode_b64u(&self.mac_public),
                encode_b64u(recipient)
            )
            .into_bytes(),
        )
    }
    fn words(&self, key: &QuestionKey, team: &str, recipient: &[u8], name: &str) -> String {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key.bytes());
        let mut mac = ring::hmac::Context::with_key(&key);
        mac.update(b"apassy-connect-safety-v2\0");
        mac.update(&self.aad(team, recipient, name));
        let tag = mac.sign();
        tag.as_ref()[..6]
            .iter()
            .map(|b| crate::sync::relay_crypto::WORDS[usize::from(*b)])
            .collect::<Vec<_>>()
            .join(" ")
    }
    pub fn mac_safety(&self, team: &str, recipient: &[u8], name: &str) -> Option<String> {
        let key = self.shared_key(self.mac_private.as_ref()?, recipient)?;
        Some(self.words(&key, team, recipient, name))
    }
    pub fn phone_safety(&self, team: &str, phone: &DeviceKey, name: &str) -> Option<String> {
        let key = self.shared_key(phone.pkcs8()?, &self.mac_public)?;
        Some(self.words(&key, team, phone.public_key(), name))
    }
    pub fn seal(&self, vault: &Vault, team: &str, recipient: &[u8]) -> VaultResult<Sealed> {
        let device = vault
            .trusted_devices()?
            .into_iter()
            .find(|d| d.sign_key == recipient)
            .ok_or_else(|| crate::vault::VaultError::new(VaultErrorKind::InvalidInput))?;
        // The name of the link as the device sent it: the AAD binds it. A watch sent the
        // `~W` marker (ADR 0039 §2), an iPhone the `~` marker.
        let answer_key = device.answer_key.as_deref().unwrap_or_default();
        let name = match device.kind {
            crate::vault::TrustedDeviceKind::Watch => {
                crate::questions::device_link::watch_link_device_name(&device.name, answer_key)
            }
            crate::vault::TrustedDeviceKind::Iphone | crate::vault::TrustedDeviceKind::Mac => {
                crate::questions::device_link::link_device_name(&device.name, answer_key)
            }
        }
        .ok_or_else(|| crate::vault::VaultError::new(VaultErrorKind::InvalidInput))?;
        let wrapping = self
            .mac_private
            .as_ref()
            .and_then(|k| self.shared_key(k, recipient))
            .ok_or_else(|| crate::vault::VaultError::new(VaultErrorKind::InvalidInput))?;
        let (key, at, by) = vault.question_key_for_handoff()?;
        let handoff = Handoff {
            v: 1,
            vault_id: vault.sync_identity()?.vault_id,
            team_id: team.to_owned(),
            recipient: recipient.to_vec(),
            question_key: Zeroizing::new(key.bytes().to_vec()),
            key_updated_at: at,
            key_updated_by: by,
            // An iPhone never checks a watch signature, and an iPhone on 0.5.15 does not
            // know the kind `watch`: one such row makes the whole handoff unreadable to it.
            // A watch (or a Mac) gets every row of the team.
            devices: vault
                .trusted_devices()?
                .into_iter()
                .filter(|d| d.relay_devices.contains_key(team))
                .filter(|d| {
                    device.kind != crate::vault::TrustedDeviceKind::Iphone
                        || d.kind != crate::vault::TrustedDeviceKind::Watch
                })
                .collect(),
        };
        if !handoff
            .devices
            .iter()
            .any(|d| d.sign_key == recipient && d.answer_key.is_some())
        {
            return Err(crate::vault::VaultError::new(VaultErrorKind::InvalidInput));
        }
        // A fixed-capacity writer never reallocates a secret-bearing plaintext buffer.
        struct Plaintext(Zeroizing<Vec<u8>>);
        impl std::io::Write for Plaintext {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.0.len().saturating_add(bytes.len())
                    > crate::questions::envelope::MAX_CARD_BYTES
                {
                    return Err(std::io::Error::other(
                        "Connection key transfer is too large",
                    ));
                }
                self.0.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut plain = Plaintext(Zeroizing::new(Vec::with_capacity(
            crate::questions::envelope::MAX_CARD_BYTES,
        )));
        serde_json::to_writer(&mut plain, &handoff)
            .map_err(|_| crate::vault::VaultError::new(VaultErrorKind::Storage))?;
        let mut sealed = Sealed::new(&wrapping, &self.aad(team, recipient, &name), &plain.0)
            .ok_or_else(|| crate::vault::VaultError::new(VaultErrorKind::Storage))?;
        sealed.key_id = HANDOFF_KEY_ID.to_owned();
        Ok(sealed)
    }
    pub fn send(
        &self,
        client: &QuestionsClient,
        expires_at: u64,
        sealed: &Sealed,
    ) -> Result<(), QuestionsError> {
        match client.post_question(&self.qid, "member", expires_at, sealed) {
            Ok(_) => Ok(()),
            // The live relay refuses duplicate qids. Retrying our same random qid after
            // response loss means it already holds the handoff; the phone still authenticates it.
            Err(QuestionsError::Relay { status: 409, code }) if code == "conflict" => Ok(()),
            Err(error) => Err(error),
        }
    }
    /// Read only after the relay has confirmed this exact device key. Bound the page walk.
    pub fn receive(
        &self,
        client: &QuestionsClient,
        team: &str,
        phone: &DeviceKey,
        name: &str,
    ) -> Result<Option<Handoff>, QuestionsError> {
        let recipient = phone.public_key();
        let Some(wrapping) = phone
            .pkcs8()
            .and_then(|k| self.shared_key(k, &self.mac_public))
        else {
            return Ok(None);
        };
        let mut since = 0;
        for _ in 0..8 {
            let list = client.list(since, std::time::Duration::ZERO)?;
            for row in &list.questions {
                since = since.max(row.seq);
                if row.qid != self.qid || row.key_id != HANDOFF_KEY_ID || row.state != "open" {
                    continue;
                }
                let Some(nonce) = decode_b64u(&row.nonce).and_then(|n| n.try_into().ok()) else {
                    continue;
                };
                let Some(cipher) = decode_b64u(&row.ciphertext) else {
                    continue;
                };
                let Some(plain) =
                    open(&wrapping, &nonce, &self.aad(team, recipient, name), &cipher)
                else {
                    continue;
                };
                let Ok(handoff) = serde_json::from_slice::<Handoff>(&plain) else {
                    continue;
                };
                if handoff.v == 1 && handoff.team_id == team && handoff.recipient == recipient {
                    return Ok(Some(handoff));
                }
            }
            if list.questions.len() < 100 {
                break;
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::questions::device_link::{link_device_name, watch_link_device_name};
    use crate::relay::membership::{enable_questions, register_linked_device};
    use crate::vault::{RelayDevice, TrustedDeviceKind};

    const PASS: &str = "synthetic-pairing-pass";
    const TEAM: &str = "t_7k2m5q4x3c";

    /// The handoff to a watch (relay-questions-v1 section 21, ADR 0039 §6) carries the row
    /// of kind `watch`, and its AAD binds the `~W` name that the watch sent.
    #[test]
    fn a_watch_handoff_binds_its_watch_name_and_carries_its_row() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("p.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let mac = DeviceKey::generate().unwrap();
        vault
            .set_relay_device(&RelayDevice {
                relay_url: "https://relay.example.test".to_owned(),
                team_id: TEAM.to_owned(),
                device_id: 2,
                public_key: mac.public_key().to_vec(),
                key_pkcs8: mac.pkcs8().unwrap().clone(),
                created_at: 0,
            })
            .unwrap();
        enable_questions(&mut vault, "Synthetic Mac").unwrap();

        let raw = format!(
            "https://relay.example.test/link#apassy_lnk_{TEAM}_{}",
            "ab".repeat(32)
        );
        let channel = PairingChannel::generate(&raw).unwrap();
        let relay_key = DeviceKey::generate().unwrap();
        let answer_key = DeviceKey::generate().unwrap();
        let name = watch_link_device_name("Test Watch", answer_key.public_key()).unwrap();
        let row = register_linked_device(&mut vault, TEAM, 9, &name, relay_key.public_key())
            .unwrap()
            .unwrap();
        assert_eq!(row.kind, TrustedDeviceKind::Watch);
        assert_eq!(row.name, "Test Watch");
        assert_eq!(row.answer_key.as_deref(), Some(answer_key.public_key()));
        let sealed = channel.seal(&vault, TEAM, relay_key.public_key()).unwrap();
        assert_eq!(sealed.key_id, HANDOFF_KEY_ID);

        // The watch side: the channel of the scanned link, its relay key, its own name.
        let (_, watch) = PairingChannel::parse(&channel.link(&raw)).unwrap();
        let wrapping = watch
            .shared_key(relay_key.pkcs8().unwrap(), &watch.mac_public)
            .unwrap();
        let nonce: [u8; 12] = decode_b64u(&sealed.nonce).unwrap().try_into().unwrap();
        let cipher = decode_b64u(&sealed.ciphertext).unwrap();
        let plain = open(
            &wrapping,
            &nonce,
            &watch.aad(TEAM, relay_key.public_key(), &name),
            &cipher,
        )
        .unwrap();
        let handoff: Handoff = serde_json::from_slice(&plain).unwrap();
        assert_eq!(handoff.recipient, relay_key.public_key());
        assert!(handoff.devices.iter().any(|device| {
            device.kind == TrustedDeviceKind::Watch
                && device.sign_key == relay_key.public_key()
                && device.relay_devices.get(TEAM) == Some(&9)
        }));
        // The iPhone form of the same name and key does not open it.
        let iphone_name = link_device_name("Test Watch", answer_key.public_key()).unwrap();
        assert!(
            open(
                &wrapping,
                &nonce,
                &watch.aad(TEAM, relay_key.public_key(), &iphone_name),
                &cipher,
            )
            .is_none()
        );
    }

    /// An iPhone on 0.5.15 knows only the kinds `mac` and `iphone` and drops a handoff
    /// that it cannot parse. A handoff to an iPhone from a vault with a watch leaves the
    /// watch row out, so the old iPhone reads it; a handoff to the watch keeps it.
    #[test]
    fn an_iphone_handoff_leaves_out_watch_rows_and_parses_on_0_5_15() {
        #[derive(serde::Deserialize, PartialEq, Debug)]
        #[serde(rename_all = "lowercase")]
        enum OldKind {
            Mac,
            Iphone,
        }
        #[derive(serde::Deserialize)]
        struct OldDevice {
            kind: OldKind,
            sign_key: Vec<u8>,
        }
        #[derive(serde::Deserialize)]
        struct OldHandoff {
            v: u8,
            recipient: Vec<u8>,
            devices: Vec<OldDevice>,
        }

        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("p.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let mac = DeviceKey::generate().unwrap();
        vault
            .set_relay_device(&RelayDevice {
                relay_url: "https://relay.example.test".to_owned(),
                team_id: TEAM.to_owned(),
                device_id: 2,
                public_key: mac.public_key().to_vec(),
                key_pkcs8: mac.pkcs8().unwrap().clone(),
                created_at: 0,
            })
            .unwrap();
        enable_questions(&mut vault, "Synthetic Mac").unwrap();
        let raw = format!(
            "https://relay.example.test/link#apassy_lnk_{TEAM}_{}",
            "cd".repeat(32)
        );

        // A watch that is already in the team.
        let watch_relay = DeviceKey::generate().unwrap();
        let watch_answer = DeviceKey::generate().unwrap();
        let watch_name = watch_link_device_name("Test Watch", watch_answer.public_key()).unwrap();
        let watch_row =
            register_linked_device(&mut vault, TEAM, 9, &watch_name, watch_relay.public_key())
                .unwrap()
                .unwrap();
        assert_eq!(watch_row.kind, TrustedDeviceKind::Watch);
        // The iPhone that joins now.
        let phone_relay = DeviceKey::generate().unwrap();
        let phone_answer = DeviceKey::generate().unwrap();
        let phone_name = link_device_name("Test iPhone", phone_answer.public_key()).unwrap();
        let phone_row =
            register_linked_device(&mut vault, TEAM, 10, &phone_name, phone_relay.public_key())
                .unwrap()
                .unwrap();
        assert_eq!(phone_row.kind, TrustedDeviceKind::Iphone);

        let open_as = |channel: &PairingChannel, key: &DeviceKey, name: &str| {
            let sealed = channel.seal(&vault, TEAM, key.public_key()).unwrap();
            let (_, peer) = PairingChannel::parse(&channel.link(&raw)).unwrap();
            let wrapping = peer
                .shared_key(key.pkcs8().unwrap(), &peer.mac_public)
                .unwrap();
            let nonce: [u8; 12] = decode_b64u(&sealed.nonce).unwrap().try_into().unwrap();
            let cipher = decode_b64u(&sealed.ciphertext).unwrap();
            open(
                &wrapping,
                &nonce,
                &peer.aad(TEAM, key.public_key(), name),
                &cipher,
            )
            .unwrap()
        };

        // To the iPhone: no watch row, and the 0.5.15 kind set parses it.
        let channel = PairingChannel::generate(&raw).unwrap();
        let plain = open_as(&channel, &phone_relay, &phone_name);
        let handoff: Handoff = serde_json::from_slice(&plain).unwrap();
        assert!(
            handoff
                .devices
                .iter()
                .all(|d| d.kind != TrustedDeviceKind::Watch)
        );
        assert!(
            !handoff
                .devices
                .iter()
                .any(|d| d.sign_key == watch_relay.public_key())
        );
        let old: OldHandoff = serde_json::from_slice(&plain).unwrap();
        assert_eq!(old.v, 1);
        assert_eq!(old.recipient, phone_relay.public_key());
        assert!(
            old.devices
                .iter()
                .any(|d| { d.kind == OldKind::Iphone && d.sign_key == phone_relay.public_key() })
        );

        // To the watch: the watch row stays.
        let channel = PairingChannel::generate(&raw).unwrap();
        let plain = open_as(&channel, &watch_relay, &watch_name);
        let handoff: Handoff = serde_json::from_slice(&plain).unwrap();
        assert!(handoff.devices.iter().any(|d| {
            d.kind == TrustedDeviceKind::Watch && d.sign_key == watch_relay.public_key()
        }));
    }

    const PIN: &str = "u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE";

    fn link_code() -> String {
        format!("apassy_lnk_{TEAM}_{}", "ab".repeat(32))
    }

    /// Contract node-pairing-v1 section 8: the AAD and the safety words take the link up
    /// to `&handoff=` with the pin, the alternatives, and the name exactly as written, so
    /// a changed pin gives other words; a link without a pin gives today's text.
    #[test]
    fn a_handoff_after_a_pinned_fragment_binds_the_pin() {
        let raw = format!(
            "https://100.64.0.7:8444/link#{}&pin={PIN}&alt=apassy-mini.tail0123.ts.net&name=Studio",
            link_code()
        );
        let channel = PairingChannel::generate(&raw).unwrap();
        assert_eq!(channel.team_id(), Some(TEAM));
        let link = channel.link(&raw);
        let pasted = format!(" {}\n", link.as_str());
        let (read, phone_channel) = PairingChannel::parse(&pasted).unwrap();
        assert_eq!(read, raw, "the original full link without handoff");
        assert_eq!(phone_channel.qid(), channel.qid());
        assert_eq!(phone_channel.team_id(), Some(TEAM));
        // The relay call strips the handoff and the pin: the code alone goes.
        let (url, code) = crate::sync::PendingJoin::parse_link(&link, "").unwrap();
        assert_eq!(code.as_str(), link_code());
        assert_eq!(url.pin().unwrap().text(), PIN);

        // Both devices compute the same words; a link with another pin gives others.
        let phone = DeviceKey::generate().unwrap();
        let name = "Synthetic iPhone";
        let mac_words = channel.mac_safety(TEAM, phone.public_key(), name).unwrap();
        assert_eq!(
            phone_channel.phone_safety(TEAM, &phone, name).unwrap(),
            mac_words
        );
        let other_pin = crate::sync::encode_b64u(&[7u8; 32]);
        let tampered = link.replace(PIN, &other_pin);
        let (_, tampered_channel) = PairingChannel::parse(&tampered).unwrap();
        assert_ne!(
            tampered_channel.phone_safety(TEAM, &phone, name).unwrap(),
            mac_words
        );

        // A hosted link keeps today's AAD text.
        let hosted = format!("https://relay.example.test/link#{}", link_code());
        let channel = PairingChannel::generate(&hosted).unwrap();
        let hosted_link = channel.link(&hosted);
        let (read, _) = PairingChannel::parse(&hosted_link).unwrap();
        assert_eq!(read, hosted);
    }

    #[test]
    fn a_channel_needs_a_device_link_of_the_grammar() {
        let code = link_code();
        let team_code = format!("apassy_tcd_{}", "cd".repeat(32));
        for raw in [
            // A pair link, an unknown key, a pin of another form, and a link with a
            // handoff already.
            format!("https://100.64.0.7:8444/pair#{team_code}&pin={PIN}"),
            format!("https://relay.example.test/link#{code}&foo=1"),
            format!("https://100.64.0.7:8444/link#{code}&pin={}", &PIN[..42]),
            format!("https://relay.example.test/link#{code}&alt=b.example.com"),
            format!(" https://relay.example.test/link#{code}"),
        ] {
            assert!(PairingChannel::generate(&raw).is_none(), "{raw}");
        }
        let raw = format!("https://relay.example.test/link#{code}");
        let channel = PairingChannel::generate(&raw).unwrap();
        assert!(PairingChannel::generate(&channel.link(&raw)).is_none());
        // A link without a handoff, or with a broken one, has no channel.
        assert!(PairingChannel::parse(&raw).is_none());
        let broken = channel.link(&raw).replace("&handoff=2.", "&handoff=3.");
        assert!(PairingChannel::parse(&broken).is_none());
    }
}
