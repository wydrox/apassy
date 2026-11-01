//! A QR capability hands question keys to a confirmed iPhone over existing opaque question
//! routes. The relay never sees the QR secret. No vault snapshot or paid sync is involved.
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
// Never print secret-bearing handoffs.
impl PairingChannel {
    pub fn team_id(&self) -> Option<&str> {
        crate::sync::relay_crypto::link_code_team(self.raw_link.split_once("/link#")?.1)
    }
    pub fn qid(&self) -> &str {
        &self.qid
    }
    pub fn generate(raw_link: &str) -> Option<Self> {
        let (origin, code) = raw_link.split_once("/link#")?;
        crate::sync::RelayUrl::parse(origin).ok()?;
        crate::sync::relay_crypto::link_code_team(code)?;
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
    pub fn parse(link: &str) -> Option<(&str, Self)> {
        let (raw, capsule) = link.rsplit_once(MARK)?;
        let (origin, code) = raw.split_once("/link#")?;
        crate::sync::RelayUrl::parse(origin).ok()?;
        crate::sync::relay_crypto::link_code_team(code)?;
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
        let name = crate::questions::device_link::link_device_name(
            &device.name,
            device.answer_key.as_deref().unwrap_or_default(),
        )
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
            devices: vault
                .trusted_devices()?
                .into_iter()
                .filter(|d| d.relay_devices.contains_key(team))
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
