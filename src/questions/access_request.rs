//! ADR 0033's inner protocol. Signatures cover exact body bytes, never reserialized JSON.
//! No function in this module grants access or interprets a run approval.

use ring::digest::{Context as DigestContext, SHA256};
use serde::{Deserialize, Deserializer, Serialize};

use crate::companion::crypto::verify_ecdsa;
use crate::sync::{decode_b64u, encode_b64u};

pub const PROTOCOL: &str = "apassy-access-request";
pub const LIFETIME: u64 = 300;
pub const MAX_TIME: u64 = (1 << 53) - 1;

fn required<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Choice {
    Deny,
    AllowOnce,
}
impl Choice {
    pub fn text(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::AllowOnce => "allow_once",
        }
    }
}

pub use crate::agent::wire::{AccessAction as Action, AccessScope as Scope};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostSource {
    MacConnectionLabel,
    AgentClaimed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    Development,
    Staging,
    Production,
    Unconfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Delivery {
    RealValue,
    Placeholder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeSource {
    AgentRequestedMacChecked,
    LegacyIncomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asker {
    pub device: String,
    pub relay_device_id: u64,
    pub name: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    pub id: String,
    pub name: String,
    #[serde(deserialize_with = "required")]
    pub host: Option<String>,
    pub host_source: HostSource,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Item {
    pub local_id: String,
    pub uuid: String,
    pub revision: String,
    pub name: String,
    pub environment: Environment,
    pub delivery: Delivery,
    pub binding_name: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub key: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Card {
    pub vault_id: String,
    pub team_id: String,
    pub qid: String,
    pub key_id: String,
    pub to: String,
    pub request_id: String,
    pub asker: Asker,
    pub vault_name: String,
    pub agent: Agent,
    pub item: Item,
    #[serde(deserialize_with = "required")]
    pub project: Option<Project>,
    pub cwd: String,
    #[serde(deserialize_with = "required")]
    pub action: Option<Action>,
    pub hosts: Vec<String>,
    pub scope_source: ScopeSource,
    pub reason: String,
    pub policy_digest: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub valid_answers: Vec<Choice>,
    #[serde(deserialize_with = "required")]
    pub local_review_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    AllowedOnce,
    Denied,
    GrantedOnMac,
    Expired,
    Invalidated,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptChoice {
    Deny,
    AllowOnce,
    GrantOnMac,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    Mac,
    Iphone,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub vault_id: String,
    pub team_id: String,
    pub qid: String,
    pub request_id: String,
    pub asker: String,
    pub digest: String,
    pub outcome: Outcome,
    #[serde(deserialize_with = "required")]
    pub answered_by: Option<String>,
    #[serde(deserialize_with = "required")]
    pub device_name: Option<String>,
    #[serde(deserialize_with = "required")]
    pub device_kind: Option<DeviceKind>,
    #[serde(deserialize_with = "required")]
    pub kind: Option<ReceiptChoice>,
    pub at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedBody {
    pub protocol: String,
    pub v: u32,
    pub part: String,
    pub body: String,
    pub digest: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Answer {
    pub protocol: String,
    pub v: u32,
    pub part: String,
    pub qid: String,
    pub request_id: String,
    pub asker: String,
    pub by: String,
    pub kind: Choice,
    pub digest: String,
    pub expires_at: u64,
    pub time: u64,
    pub signature: String,
}

/// An immutable, verified card. Retain `body` for retries and digest verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCard {
    pub card: Card,
    pub body: Vec<u8>,
    pub digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Malformed,
    Bounds,
    Identity,
    Signature,
    Expired,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn is_hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn positive(s: &str) -> bool {
    super::envelope::parse_decimal(s).is_some_and(|n| n > 0)
}
fn canonical_b64(s: &str) -> Option<Vec<u8>> {
    let bytes = decode_b64u(s)?;
    (encode_b64u(&bytes) == s).then_some(bytes)
}
fn field(out: &mut Vec<u8>, b: &[u8]) -> Result<(), Error> {
    let n = u32::try_from(b.len()).map_err(|_| Error::Bounds)?;
    out.extend(n.to_be_bytes());
    out.extend(b);
    Ok(())
}
pub fn body_digest(part: &str, body: &[u8]) -> Result<[u8; 32], Error> {
    let tag = match part {
        "card" => b"apassy-access-request-card-v1\0".as_slice(),
        "settle" => b"apassy-access-request-settle-v1\0".as_slice(),
        _ => return Err(Error::Malformed),
    };
    let mut bytes = tag.to_vec();
    field(&mut bytes, body)?;
    let mut context = DigestContext::new(&SHA256);
    context.update(&bytes);
    context
        .finish()
        .as_ref()
        .try_into()
        .map_err(|_| Error::Malformed)
}
pub fn body_signature_message(part: &str, body: &[u8]) -> Result<Vec<u8>, Error> {
    let tag = match part {
        "card" => b"apassy-access-request-card-sign-v1\0".as_slice(),
        "settle" => b"apassy-access-request-settle-sign-v1\0".as_slice(),
        _ => return Err(Error::Malformed),
    };
    let mut out = tag.to_vec();
    out.extend(body_digest(part, body)?);
    Ok(out)
}
impl SignedBody {
    pub fn new(part: &str, body: &[u8], signature: &[u8]) -> Result<Self, Error> {
        let wrapper = Self {
            protocol: PROTOCOL.into(),
            v: 1,
            part: part.into(),
            body: encode_b64u(body),
            digest: hex(&body_digest(part, body)?),
            signature: encode_b64u(signature),
        };
        wrapper.check_bounds()?;
        Ok(wrapper)
    }
    pub fn parse(bytes: &[u8], part: &str) -> Result<Self, Error> {
        if bytes.len() > if part == "card" { 32768 } else { 1024 } {
            return Err(Error::Bounds);
        }
        let w: Self = serde_json::from_slice(bytes).map_err(|_| Error::Malformed)?;
        if w.part != part {
            return Err(Error::Malformed);
        }
        w.check_bounds()?;
        Ok(w)
    }
    fn check_bounds(&self) -> Result<(), Error> {
        if self.protocol != PROTOCOL
            || self.v != 1
            || !["card", "settle"].contains(&self.part.as_str())
        {
            return Err(Error::Malformed);
        }
        let body = canonical_b64(&self.body).ok_or(Error::Malformed)?;
        let signature = canonical_b64(&self.signature).ok_or(Error::Malformed)?;
        let (body_cap, cap) = if self.part == "card" {
            (20000, 32768)
        } else {
            (512, 1024)
        };
        if body.len() > body_cap
            || signature.len() > 72
            || signature.is_empty()
            || serde_json::to_vec(self)
                .map_err(|_| Error::Malformed)?
                .len()
                > cap
        {
            return Err(Error::Bounds);
        }
        if hex(&body_digest(&self.part, &body)?) != self.digest {
            return Err(Error::Signature);
        }
        Ok(())
    }
    pub fn verify(&self, key: &[u8]) -> Result<Vec<u8>, Error> {
        self.check_bounds()?;
        let body = canonical_b64(&self.body).ok_or(Error::Malformed)?;
        let signature = canonical_b64(&self.signature).ok_or(Error::Malformed)?;
        if !verify_ecdsa(key, &body_signature_message(&self.part, &body)?, &signature) {
            return Err(Error::Signature);
        }
        Ok(body)
    }
}

/// Shared exact destination normalizer. It deliberately never calls `HostRule::covers`.
pub fn normal_host(text: &str) -> Option<String> {
    if text.is_empty()
        || text.contains(['/', '@', '*', '\\'])
        || text.chars().any(char::is_whitespace)
        || text.chars().any(char::is_control)
    {
        return None;
    }
    let (host, port) = match text.rsplit_once(':') {
        Some((h, p)) => {
            let n: u16 = p.parse().ok()?;
            if n == 0 || p != n.to_string() {
                return None;
            }
            (h, n)
        }
        None => (text, 443),
    };
    if host.ends_with('.') || host.contains(':') || host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let ascii = idna::domain_to_ascii_strict(host)
        .ok()?
        .to_ascii_lowercase();
    if !ascii.contains('.')
        || ascii.len() > 253
        || ascii.split('.').any(|p| {
            p.is_empty()
                || p.starts_with('-')
                || p.ends_with('-')
                || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return None;
    }
    // Reject ambiguous numeric IP spellings (including octal/hex and shortened IPv4).
    if ascii
        .split('.')
        .all(|p| p.bytes().all(|b| b.is_ascii_digit()) || p.starts_with("0x"))
    {
        return None;
    }
    Some(if port == 443 {
        ascii
    } else {
        format!("{ascii}:{port}")
    })
}
pub fn hosts_valid(hosts: &[String]) -> bool {
    hosts.len() <= 16
        && hosts.iter().all(|h| normal_host(h).as_ref() == Some(h))
        && hosts.windows(2).all(|w| w[0].as_bytes() < w[1].as_bytes())
}

impl Card {
    pub fn validate(&self) -> Result<(), Error> {
        if !uuid(&self.vault_id)
            || !uuid(&self.asker.device)
            || !positive(&self.request_id)
            || !positive(&self.agent.id)
            || !positive(&self.item.local_id)
            || super::envelope::parse_decimal(&self.item.revision).is_none()
            || !is_hex(&self.item.uuid, 32)
            || !is_hex(&self.policy_digest, 64)
            || !super::envelope::valid_qid(&self.qid)
            || !super::envelope::valid_key_id(&self.key_id)
            || canonical_b64(&self.qid).is_none()
            || self.to != "member"
            || self.team_id.is_empty()
            || self.team_id.len() > 128
            || self.asker.relay_device_id == 0
            || self.expires_at > MAX_TIME
            || self.created_at.checked_add(LIFETIME) != Some(self.expires_at)
        {
            return Err(Error::Malformed);
        }
        for (s, n) in [
            (&self.asker.name, 64),
            (&self.vault_name, 128),
            (&self.agent.name, 64),
            (&self.item.name, 128),
            (&self.item.binding_name, 128),
            (&self.cwd, 4096),
            (&self.reason, 500),
        ] {
            if s.len() > n {
                return Err(Error::Bounds);
            }
        }
        if self.agent.host.as_ref().is_some_and(|h| h.len() > 64)
            || (self.agent.host_source == HostSource::Unknown && self.agent.host.is_some())
            || self
                .project
                .as_ref()
                .is_some_and(|p| p.key.len() > 4096 || p.label.len() > 256 || p.key.is_empty())
            || self
                .local_review_reason
                .as_ref()
                .is_some_and(|r| r.is_empty() || r.len() > 256)
            || !hosts_valid(&self.hosts)
        {
            return Err(Error::Bounds);
        }
        let complete = self.project.is_some()
            && self.cwd.starts_with('/')
            && self.action.is_some()
            && !self.hosts.is_empty()
            && self.scope_source == ScopeSource::AgentRequestedMacChecked;
        match self.valid_answers.as_slice() {
            [Choice::Deny, Choice::AllowOnce] if complete && self.local_review_reason.is_none() => {
                Ok(())
            }
            [Choice::Deny] if self.local_review_reason.is_some() => Ok(()),
            _ => Err(Error::Malformed),
        }
    }
}

/// Outer identities and a live vault-owned key are supplied by the caller, never the card.
pub struct Context<'a> {
    pub vault_id: &'a str,
    pub team_id: &'a str,
    pub qid: &'a str,
    pub key_id: &'a str,
    pub asker: &'a str,
    pub relay_device_id: u64,
    pub expires_at: u64,
}
pub fn verify_card(
    bytes: &[u8],
    key: &[u8],
    context: &Context<'_>,
    now: u64,
) -> Result<VerifiedCard, Error> {
    let wrapper = SignedBody::parse(bytes, "card")?;
    let body = wrapper.verify(key)?;
    let card: Card = serde_json::from_slice(&body).map_err(|_| Error::Malformed)?;
    card.validate()?;
    if card.vault_id != context.vault_id
        || card.team_id != context.team_id
        || card.qid != context.qid
        || card.key_id != context.key_id
        || card.asker.device != context.asker
        || card.asker.relay_device_id != context.relay_device_id
        || card.expires_at != context.expires_at
    {
        return Err(Error::Identity);
    }
    if now < card.created_at.saturating_sub(5) || now >= card.expires_at {
        return Err(Error::Expired);
    }
    Ok(VerifiedCard {
        card,
        body,
        digest: wrapper.digest,
    })
}
impl Answer {
    pub fn prepare(card: &VerifiedCard, by: &str, kind: Choice, time: u64) -> Result<Self, Error> {
        if !uuid(by) || !card.card.valid_answers.contains(&kind) {
            return Err(Error::Identity);
        }
        let c = &card.card;
        let a = Self {
            protocol: PROTOCOL.into(),
            v: 1,
            part: "answer".into(),
            qid: c.qid.clone(),
            request_id: c.request_id.clone(),
            asker: c.asker.device.clone(),
            by: by.into(),
            kind,
            digest: card.digest.clone(),
            expires_at: c.expires_at,
            time,
            signature: String::new(),
        };
        a.check(card, time)?;
        Ok(a)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 8192 {
            return Err(Error::Bounds);
        }
        serde_json::from_slice(bytes).map_err(|_| Error::Malformed)
    }
    pub fn message(&self, card: &VerifiedCard) -> Result<Vec<u8>, Error> {
        let mut out = b"apassy-access-request-answer-v1\0".to_vec();
        for s in [
            &card.card.vault_id,
            &card.card.team_id,
            &self.qid,
            &self.request_id,
            &self.asker,
            &self.by,
            self.kind.text(),
        ] {
            field(&mut out, s.as_bytes())?;
        }
        if !is_hex(&self.digest, 64) {
            return Err(Error::Malformed);
        }
        for i in (0..64).step_by(2) {
            out.push(u8::from_str_radix(&self.digest[i..i + 2], 16).map_err(|_| Error::Malformed)?);
        }
        out.extend(self.expires_at.to_be_bytes());
        out.extend(self.time.to_be_bytes());
        Ok(out)
    }
    pub fn check(&self, card: &VerifiedCard, now: u64) -> Result<(), Error> {
        let c = &card.card;
        if self.protocol != PROTOCOL
            || self.v != 1
            || self.part != "answer"
            || self.qid != c.qid
            || self.request_id != c.request_id
            || self.asker != c.asker.device
            || self.digest != card.digest
            || self.expires_at != c.expires_at
            || !uuid(&self.by)
            || !c.valid_answers.contains(&self.kind)
        {
            return Err(Error::Identity);
        }
        if self.time > MAX_TIME
            || self.time < c.created_at
            || self.time >= c.expires_at
            || now >= c.expires_at
            || self.time < now.saturating_sub(55)
            || self.time > now.saturating_add(5)
        {
            return Err(Error::Expired);
        }
        Ok(())
    }
    pub fn verify(&self, card: &VerifiedCard, key: &[u8], now: u64) -> Result<(), Error> {
        self.check(card, now)?;
        let sig = canonical_b64(&self.signature).ok_or(Error::Malformed)?;
        if sig.len() > 72 || !verify_ecdsa(key, &self.message(card)?, &sig) {
            return Err(Error::Signature);
        }
        Ok(())
    }
    pub fn retry_before(&self) -> u64 {
        self.time.saturating_add(50).min(self.expires_at)
    }
}

pub fn verify_receipt(bytes: &[u8], key: &[u8], card: &VerifiedCard) -> Result<Receipt, Error> {
    let wrapper = SignedBody::parse(bytes, "settle")?;
    let r: Receipt = serde_json::from_slice(&wrapper.verify(key)?).map_err(|_| Error::Malformed)?;
    let c = &card.card;
    if r.vault_id != c.vault_id
        || r.team_id != c.team_id
        || r.qid != c.qid
        || r.request_id != c.request_id
        || r.asker != c.asker.device
        || r.digest != card.digest
        || r.expires_at != c.expires_at
        || r.at > MAX_TIME
    {
        return Err(Error::Identity);
    }
    let terminal = match r.outcome {
        Outcome::AllowedOnce => {
            r.kind == Some(ReceiptChoice::AllowOnce) && c.valid_answers.contains(&Choice::AllowOnce)
        }
        Outcome::Denied => r.kind == Some(ReceiptChoice::Deny),
        Outcome::GrantedOnMac => {
            r.kind == Some(ReceiptChoice::GrantOnMac) && r.device_kind == Some(DeviceKind::Mac)
        }
        Outcome::Expired | Outcome::Invalidated => {
            r.kind.is_none()
                && r.answered_by.is_none()
                && r.device_name.is_none()
                && r.device_kind.is_none()
        }
    };
    if !terminal
        || (r.kind.is_some()
            && (r.at < c.created_at
                || r.at >= c.expires_at
                || !r.answered_by.as_ref().is_some_and(|s| uuid(s))
                || r.device_name.is_none()
                || r.device_kind.is_none()))
    {
        return Err(Error::Malformed);
    }
    Ok(r)
}

/// Escape controls, format characters and literal backslashes without losing distinctions.
pub fn display_text(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if c == '\\' {
            out.push_str("\\\\");
        } else if c.is_control()
            || matches!(c, '\u{00ad}'|'\u{061c}'|'\u{200b}'..='\u{200f}'|'\u{2028}'..='\u{202e}'|'\u{2060}'..='\u{206f}'|'\u{feff}'|'\u{fff9}'..='\u{fffb}')
        {
            out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::DeviceKey;

    const BODY: &[u8] = include_bytes!("../../tests/fixtures/access-request-v1/card-body.json");
    const WIRE: &[u8] = include_bytes!("../../tests/fixtures/access-request-v1/card.json");
    fn vector() -> (VerifiedCard, Vec<u8>) {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/access-request-v1/vectors.json"
        ))
        .unwrap();
        let key = decode_b64u(vectors["public_key"].as_str().unwrap()).unwrap();
        let c: Card = serde_json::from_slice(BODY).unwrap();
        let context = Context {
            vault_id: &c.vault_id,
            team_id: &c.team_id,
            qid: &c.qid,
            key_id: &c.key_id,
            asker: &c.asker.device,
            relay_device_id: 2,
            expires_at: c.expires_at,
        };
        (
            verify_card(WIRE, &key, &context, c.created_at + 30).unwrap(),
            key,
        )
    }
    #[test]
    fn independently_generated_openssl_vectors() {
        let (card, key) = vector();
        assert_eq!(card.body, BODY);
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/access-request-v1/vectors.json"
        ))
        .unwrap();
        assert_eq!(card.digest, vectors["card_digest"].as_str().unwrap());
        for bytes in [
            include_bytes!("../../tests/fixtures/access-request-v1/deny.json").as_slice(),
            include_bytes!("../../tests/fixtures/access-request-v1/allow_once.json").as_slice(),
        ] {
            let answer = Answer::parse(bytes).unwrap();
            answer.verify(&card, &key, answer.time).unwrap();
            assert_eq!(
                hex(&answer.message(&card).unwrap()),
                vectors[format!("{}_message_hex", answer.kind.text())]
                    .as_str()
                    .unwrap()
            );
            assert!(
                answer
                    .verify(
                        &card,
                        DeviceKey::generate().unwrap().public_key(),
                        answer.time
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn independent_signed_settle_and_unchanged_outer_carrier_vectors() {
        let (card, key) = vector();
        let receipt = verify_receipt(
            include_bytes!("../../tests/fixtures/access-request-v1/settle.json"),
            &key,
            &card,
        )
        .unwrap();
        assert_eq!(receipt.outcome, Outcome::AllowedOnce);
        let carrier: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/access-request-v1/carrier.json"
        ))
        .unwrap();
        let question_key = crate::vault::QuestionKey::from_bytes(std::array::from_fn(|i| i as u8));
        for (name, plaintext) in [
            ("card", WIRE.as_ref()),
            (
                "deny",
                include_bytes!("../../tests/fixtures/access-request-v1/deny.json").as_slice(),
            ),
            (
                "allow_once",
                include_bytes!("../../tests/fixtures/access-request-v1/allow_once.json").as_slice(),
            ),
            (
                "settle",
                include_bytes!("../../tests/fixtures/access-request-v1/settle.json").as_slice(),
            ),
        ] {
            let row = &carrier[name];
            let sealed = super::super::envelope::Sealed {
                key_id: row["key_id"].as_str().unwrap().into(),
                nonce: row["nonce"].as_str().unwrap().into(),
                ciphertext: row["ciphertext"].as_str().unwrap().into(),
            };
            let c = &card.card;
            let aad = match name {
                "card" => super::super::envelope::card_aad(
                    &c.team_id,
                    &c.qid,
                    &c.key_id,
                    "member",
                    c.expires_at,
                ),
                "settle" => super::super::envelope::settle_aad(&c.team_id, &c.qid, &c.key_id),
                _ => super::super::envelope::answer_aad(&c.team_id, &c.qid, &c.key_id, 3),
            };
            assert_eq!(hex(&aad), row["aad_hex"].as_str().unwrap());
            assert_eq!(
                sealed.open(&question_key, &aad).unwrap().as_slice(),
                plaintext
            );
            let mut wrong = aad.clone();
            wrong.push(0);
            assert!(sealed.open(&question_key, &wrong).is_none());
        }
    }
    #[test]
    fn freshness_edges_and_long_prompt() {
        let (card, _) = vector();
        let mut answer = Answer::prepare(
            &card,
            "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b",
            Choice::AllowOnce,
            card.card.created_at + 100,
        )
        .unwrap();
        let now = answer.time;
        for (delta, accepted) in [(-56, false), (-55, true), (5, true), (6, false)] {
            answer.time = now.checked_add_signed(delta).unwrap();
            assert_eq!(answer.check(&card, now).is_ok(), accepted);
        }
        answer.time = card.card.created_at;
        assert!(answer.check(&card, answer.time).is_ok());
        assert!(answer.check(&card, answer.time + 56).is_err());
        answer.time = card.card.expires_at;
        assert!(answer.check(&card, answer.time - 1).is_err());
        answer.time -= 1;
        assert!(answer.check(&card, card.card.expires_at).is_err());
        answer.time = card.card.created_at - 1;
        assert!(answer.check(&card, card.card.created_at).is_err());
    }
    #[test]
    fn every_body_byte_is_authenticated() {
        let wrapper = SignedBody::parse(WIRE, "card").unwrap();
        let (_, key) = vector();
        for i in 0..BODY.len() {
            let mut bytes = BODY.to_vec();
            bytes[i] ^= 1;
            let mut changed = wrapper.clone();
            changed.body = encode_b64u(&bytes);
            assert!(changed.verify(&key).is_err(), "byte {i}");
            changed.digest = hex(&body_digest("card", &bytes).unwrap());
            assert!(changed.verify(&key).is_err(), "rehashed byte {i}");
        }
    }
    #[test]
    fn strict_json_and_protocol_separation() {
        let body = String::from_utf8(BODY.to_vec()).unwrap();
        assert!(
            serde_json::from_str::<Card>(&body.replacen('{', "{\"vault_id\":\"duplicate\",", 1))
                .is_err()
        );
        assert!(serde_json::from_str::<Card>(&body.replacen('{', "{\"unknown\":0,", 1)).is_err());
        assert!(
            serde_json::from_str::<Card>(
                &body.replace("\"local_review_reason\":null", "\"unknown\":null")
            )
            .is_err()
        );
        assert!(serde_json::from_slice::<Card>(b"\xff").is_err());
        assert!(serde_json::from_slice::<super::super::envelope::Card>(WIRE).is_err());
        assert!(SignedBody::parse(WIRE, "settle").is_err());
        for (field, value) in [
            ("protocol", serde_json::json!("apassy-question")),
            ("v", serde_json::json!(2)),
            ("part", serde_json::json!("answer")),
        ] {
            let mut w: serde_json::Value = serde_json::from_slice(WIRE).unwrap();
            w[field] = value;
            assert!(SignedBody::parse(&serde_json::to_vec(&w).unwrap(), "card").is_err());
        }
    }
    #[test]
    fn answer_cannot_replay_other_context_or_choice() {
        let (card, key) = vector();
        let answer = Answer::parse(include_bytes!(
            "../../tests/fixtures/access-request-v1/allow_once.json"
        ))
        .unwrap();
        let mut changed = card.clone();
        changed.card.vault_id = "e070dc14-a3ac-42c2-95aa-cc85d6d58900".into();
        assert!(answer.verify(&changed, &key, answer.time).is_err());
        changed = card.clone();
        changed.card.team_id.push('x');
        assert!(answer.verify(&changed, &key, answer.time).is_err());
        changed = card.clone();
        changed.card.request_id = "82".into();
        assert!(answer.verify(&changed, &key, answer.time).is_err());
        let mut changed = answer.clone();
        changed.kind = Choice::Deny;
        assert!(changed.verify(&card, &key, answer.time).is_err());
        changed = answer.clone();
        changed.by = "7f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b".into();
        assert!(changed.verify(&card, &key, answer.time).is_err());
    }
    #[test]
    fn exact_hosts_and_display_escaping() {
        assert_eq!(
            normal_host("API.example.test:443").as_deref(),
            Some("api.example.test")
        );
        assert_eq!(
            normal_host("bücher.example:8443").as_deref(),
            Some("xn--bcher-kva.example:8443")
        );
        for h in [
            "*.example.test",
            "https://example.test",
            "a@b.example",
            "127.1",
            "0x7f.1",
            "api.example.test:0443",
            "api.example.test/",
            "api.example.test\n",
            "api.example.test.",
        ] {
            assert!(normal_host(h).is_none(), "{h}");
        }
        assert!(!hosts_valid(&vec!["api.example.test".into(); 17]));
        assert!(!hosts_valid(&[
            "api.example.test".into(),
            "api.example.test".into()
        ]));
        assert_ne!(
            normal_host("api.example.test"),
            normal_host("evil.api.example.test")
        );
        assert_ne!(
            normal_host("api.example.test"),
            normal_host("api.example.test:8443")
        );
        assert_eq!(
            display_text("a\u{202e}b\\u{202e}"),
            "a\\u{202e}b\\\\u{202e}"
        );
    }
}
