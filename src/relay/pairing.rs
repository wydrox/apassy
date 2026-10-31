//! A QR capability hands question keys to a confirmed iPhone over existing opaque question
//! routes. The relay never sees the QR secret. No vault snapshot or paid sync is involved.
use crate::questions::envelope::{Sealed, new_qid, open};
use crate::questions::{QuestionsClient, QuestionsError};
use crate::sync::{decode_b64u, encode_b64u};
use crate::vault::{QuestionKey, TrustedDevice, Vault, VaultErrorKind, VaultResult};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Reserved transport marker; never a request for an owner decision.
pub const HANDOFF_KEY_ID: &str = "c011ec7000000001";
const MARK: &str = "&handoff=";

#[derive(Clone)]
pub struct PairingChannel {
    qid: String,
    key: QuestionKey,
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
    pub fn qid(&self) -> &str {
        &self.qid
    }
    pub fn generate() -> Option<Self> {
        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::fill(bytes.as_mut()).ok()?;
        Some(Self {
            qid: new_qid()?,
            key: QuestionKey::from_bytes(*bytes),
        })
    }
    /// All secret material stays in the URL fragment; strip it before any relay call.
    pub fn link(&self, raw: &str) -> Zeroizing<String> {
        let secret = Zeroizing::new(encode_b64u(self.key.bytes()));
        Zeroizing::new(format!("{raw}{MARK}{}.{}", self.qid, secret.as_str()))
    }
    pub fn parse(link: &str) -> Option<(&str, Self)> {
        let (raw, capsule) = link.rsplit_once(MARK)?;
        if !raw.contains('#') {
            return None;
        }
        let (qid, key) = capsule.split_once('.')?;
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
            },
        ))
    }
    fn aad(&self, team: &str, recipient: &[u8]) -> Vec<u8> {
        format!(
            "apassy-connect-handoff-v1\0{team}\0{}\0{}",
            self.qid,
            encode_b64u(recipient)
        )
        .into_bytes()
    }
    pub fn seal(&self, vault: &Vault, team: &str, recipient: &[u8]) -> VaultResult<Sealed> {
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
        let mut sealed = Sealed::new(&self.key, &self.aad(team, recipient), &plain.0)
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
        recipient: &[u8],
    ) -> Result<Option<Handoff>, QuestionsError> {
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
                let Some(plain) = open(&self.key, &nonce, &self.aad(team, recipient), &cipher)
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
