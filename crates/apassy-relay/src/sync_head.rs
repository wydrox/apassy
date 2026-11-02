//! The signed head of a vault snapshot (ADR 0022 of the core, stage 1; docs/SPEC.md
//! section 24.3, and `docs/contracts/relay-sync-v1.md` of the core).
//!
//! A head is a short ASCII text of three lines that binds the snapshot bytes (hash and
//! size), the vault, the version, the previous head, the device, and a time. The device
//! that pushes it signs the exact bytes of the text with its P-256 key (`device::verify`).
//! The relay checks it on a push; every Mac checks it before a merge. This module holds
//! the grammar, the hash, and the signature check. It never touches a snapshot byte.

use sha2::{Digest, Sha256};

use crate::device;
use crate::hostkeys::decode_b64;
use crate::ids::{DeviceId, TeamId};

/// The first line of every head.
pub const HEAD_DOMAIN: &str = "apassy-relay-sync-head-v1";
/// The header that carries the head text, base64url.
pub const HEAD_HEADER: &str = "X-Apassy-Sync-Head";
/// The header that carries the DER signature of the head text, base64url.
pub const SIGNATURE_HEADER: &str = "X-Apassy-Sync-Signature";
/// The longest value of `X-Apassy-Sync-Head`, in characters.
pub const MAX_HEAD_HEADER: usize = 512;
/// The longest value of `X-Apassy-Sync-Signature`, in characters.
pub const MAX_SIGNATURE_HEADER: usize = 96;
/// The largest snapshot any team may allow, 64 MiB (`sync_bytes` is 1 MiB to this). The
/// head grammar refuses a larger `size`, as the app does (contract section 8.1).
pub const MAX_SNAPSHOT_BYTES: u64 = 67_108_864;
/// The `previous` of a head when the relay has no head.
pub const ZERO_HASH: [u8; 32] = [0; 32];

/// A head text that does not follow the grammar, or a header that cannot be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadError;

impl std::fmt::Display for HeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the sync head does not follow the grammar")
    }
}

impl std::error::Error for HeadError {}

/// The fields of one head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncHead {
    /// The UUID of the vault, 36 lowercase characters.
    pub vault_id: String,
    pub version: u64,
    pub snapshot_sha256: [u8; 32],
    pub size: u64,
    /// The head hash of the head before, or `ZERO_HASH`.
    pub previous: [u8; 32],
    pub team: TeamId,
    pub device: DeviceId,
    /// The clock of the pushing device. Not checked.
    pub time: u64,
}

impl SyncHead {
    /// Parses a head text. Anything but the exact grammar is refused: three lines joined
    /// with `\n`, no trailing newline, no `\r`, one space between fields, ASCII only.
    pub fn parse(text: &[u8]) -> Result<Self, HeadError> {
        let text = std::str::from_utf8(text).map_err(|_| HeadError)?;
        if !text.is_ascii() {
            return Err(HeadError);
        }
        let lines: Vec<&str> = text.split('\n').collect();
        let [first, second, third] = lines.as_slice() else {
            return Err(HeadError);
        };
        if *first != HEAD_DOMAIN {
            return Err(HeadError);
        }
        let second: Vec<&str> = second.split(' ').collect();
        let third: Vec<&str> = third.split(' ').collect();
        let [vault_id, version, snapshot, size] = second.as_slice() else {
            return Err(HeadError);
        };
        let [previous, device, time] = third.as_slice() else {
            return Err(HeadError);
        };
        if !is_uuid(vault_id) || time.len() > 12 {
            return Err(HeadError);
        }
        let (team, device) = device.split_once('/').ok_or(HeadError)?;
        let team = TeamId::parse(team).ok_or(HeadError)?;
        let version = positive(version)?;
        let size = positive(size)?;
        let device = positive(device)?;
        if size > MAX_SNAPSHOT_BYTES {
            return Err(HeadError);
        }
        let time = if *time == "0" { 0 } else { positive(time)? };
        Ok(Self {
            vault_id: (*vault_id).to_string(),
            version,
            snapshot_sha256: parse_hex(snapshot)?,
            size,
            previous: parse_hex(previous)?,
            team,
            device: DeviceId(device),
            time,
        })
    }

    /// The text of this head: what a device signs and what the relay stores.
    pub fn text(&self) -> String {
        format!(
            "{HEAD_DOMAIN}\n{} {} {} {}\n{} {}/{} {}",
            self.vault_id,
            self.version,
            hex(&self.snapshot_sha256),
            self.size,
            hex(&self.previous),
            self.team,
            self.device,
            self.time
        )
    }
}

/// A head from the two sync headers: the text and the DER signature, both base64url.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHead {
    pub head: SyncHead,
    /// The exact bytes that were signed.
    pub text: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedHead {
    /// Decodes and parses the header values. Checks only the form, not the signature.
    pub fn from_headers(head: &str, signature: &str) -> Result<Self, HeadError> {
        if head.is_empty()
            || head.len() > MAX_HEAD_HEADER
            || signature.is_empty()
            || signature.len() > MAX_SIGNATURE_HEADER
        {
            return Err(HeadError);
        }
        let text = decode_b64(head, MAX_HEAD_HEADER * 3 / 4).map_err(|_| HeadError)?;
        let signature =
            decode_b64(signature, device::MAX_SIGNATURE_BYTES).map_err(|_| HeadError)?;
        if signature.is_empty() {
            return Err(HeadError);
        }
        Ok(Self {
            head: SyncHead::parse(&text)?,
            text,
            signature,
        })
    }

    /// The head hash: SHA-256 of the text.
    pub fn hash(&self) -> [u8; 32] {
        head_hash(&self.text)
    }

    /// True when the signature verifies with `public_key` (65 bytes).
    pub fn verifies(&self, public_key: &[u8]) -> bool {
        device::verify(public_key, &self.text, &self.signature)
    }
}

/// The head hash of a head text: SHA-256 of its bytes.
pub fn head_hash(text: &[u8]) -> [u8; 32] {
    Sha256::digest(text).into()
}

/// Lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// 64 lowercase hex characters as 32 bytes.
pub fn parse_hex(text: &str) -> Result<[u8; 32], HeadError> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(HeadError),
    };
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return Err(HeadError);
    }
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        out[i] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Ok(out)
}

/// A decimal of 1 or more with no leading zero, that fits in `u64`.
fn positive(text: &str) -> Result<u64, HeadError> {
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HeadError);
    }
    text.parse::<u64>().map_err(|_| HeadError)
}

/// `8-4-4-4-12` lowercase hex.
fn is_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(b),
        })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::hostkeys::encode_b64;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};

    // The test vectors of `docs/contracts/relay-sync-v1.md` section 15 of the core.
    pub const PRIVATE: &str = "4f2d9c6e1b3a7d8f0c5e2a9b7f4d1c3e6a8b0d2f4c6e8a1b3d5f7a9c0e2b4d6f";
    pub const PUBLIC: &str = "04ea47901e55bd31d76b0a545d9c60bb8e10f7b2366f3abd1bfb88ead14cf668fc0ded38eded5f35623c3081110ec6b18410b48a1d433df5da33899d05b1318eb0";
    pub const PUBLIC_B64: &str =
        "BOpHkB5VvTHXawpUXZxgu44Q97I2bzq9G_uI6tFM9mj8De047e1fNWI8MIERDsaxhBC0ih1DPfXaM4mdBbExjrA";
    /// The team id of the vectors.
    pub const VECTOR_TEAM: &str = "t_7k2m5q4x3c";
    pub const HEAD1: &str = "apassy-relay-sync-head-v1\n0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77 1 5b77343bd881a4f425bde1ec9979946ec1add11de02010d4c63159977bac4de8 18\n0000000000000000000000000000000000000000000000000000000000000000 t_7k2m5q4x3c/2 1790000000";
    pub const HEAD2: &str = "apassy-relay-sync-head-v1\n0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77 2 7dd91ab21b30df12a943c507d6e7d808f6ea2608faa3239aa7fed621ecae241a 20\nd562a4c9951ac36b211ed9786a6897f16870639c54df9d168c56c39d4ce387d9 t_7k2m5q4x3c/2 1790000060";
    pub const HEAD1_B64: &str = "YXBhc3N5LXJlbGF5LXN5bmMtaGVhZC12MQowZjNjMmExMC01YjdlLTRkOWEtOGMyMS02ZjBlNGIxZDlhNzcgMSA1Yjc3MzQzYmQ4ODFhNGY0MjViZGUxZWM5OTc5OTQ2ZWMxYWRkMTFkZTAyMDEwZDRjNjMxNTk5NzdiYWM0ZGU4IDE4CjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAgdF83azJtNXE0eDNjLzIgMTc5MDAwMDAwMA";
    pub const HEAD2_B64: &str = "YXBhc3N5LXJlbGF5LXN5bmMtaGVhZC12MQowZjNjMmExMC01YjdlLTRkOWEtOGMyMS02ZjBlNGIxZDlhNzcgMiA3ZGQ5MWFiMjFiMzBkZjEyYTk0M2M1MDdkNmU3ZDgwOGY2ZWEyNjA4ZmFhMzIzOWFhN2ZlZDYyMWVjYWUyNDFhIDIwCmQ1NjJhNGM5OTUxYWMzNmIyMTFlZDk3ODZhNjg5N2YxNjg3MDYzOWM1NGRmOWQxNjhjNTZjMzlkNGNlMzg3ZDkgdF83azJtNXE0eDNjLzIgMTc5MDAwMDA2MA";
    pub const SIG1_B64: &str = "MEUCIHD6Ih2lhM6u-hBJFTF2urGCw1UeM8vL3oM2mIDm0MvgAiEAxXcwrQRcPb0WAAgj4tylCij4Qxlbu7jISfCuxGIJDHA";
    pub const SIG2_B64: &str = "MEUCIQDpxvOaoLg8rz7vXW0U0xd6lGyttG8CeaRV76DrHTChYgIgIpwTtg1Z-BqkmTw1uDnO8FHS_YddNgbMPCWJP8KKa-g";
    pub const HEAD1_HASH: &str = "d562a4c9951ac36b211ed9786a6897f16870639c54df9d168c56c39d4ce387d9";
    pub const HEAD2_HASH: &str = "2a3d34a3454acf98a897115ed30e8ea195852d7e943c780974c1f2489810cc3c";

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn vector_pair() -> EcdsaKeyPair {
        EcdsaKeyPair::from_private_key_and_public_key(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &unhex(PRIVATE),
            &unhex(PUBLIC),
            &SystemRandom::new(),
        )
        .unwrap()
    }

    #[test]
    fn the_vectors_hash_verify_and_parse() {
        assert_eq!(encode_b64(&unhex(PUBLIC)), PUBLIC_B64);
        assert_eq!(HEAD1.len(), 223);
        assert_eq!(encode_b64(HEAD1.as_bytes()), HEAD1_B64);
        assert_eq!(encode_b64(HEAD2.as_bytes()), HEAD2_B64);
        assert_eq!(hex(&head_hash(HEAD1.as_bytes())), HEAD1_HASH);
        assert_eq!(hex(&head_hash(HEAD2.as_bytes())), HEAD2_HASH);
        assert_eq!(
            hex(&Sha256::digest(b"synthetic snapshot")),
            "5b77343bd881a4f425bde1ec9979946ec1add11de02010d4c63159977bac4de8"
        );
        assert_eq!(
            hex(&Sha256::digest(b"synthetic snapshot 2")),
            "7dd91ab21b30df12a943c507d6e7d808f6ea2608faa3239aa7fed621ecae241a"
        );
        let public = unhex(PUBLIC);
        let stranger = device::DeviceKey::generate().unwrap();
        for (head, signature) in [(HEAD1_B64, SIG1_B64), (HEAD2_B64, SIG2_B64)] {
            let parsed = SignedHead::from_headers(head, signature).unwrap();
            assert!(parsed.verifies(&public));
            assert_eq!(parsed.head.team.as_str(), VECTOR_TEAM);
            assert_eq!(parsed.head.text().as_bytes(), parsed.text.as_slice());
            // One changed character of the text fails.
            let mut changed = parsed.text.clone();
            let last = changed.len() - 1;
            changed[last] = if changed[last] == b'0' { b'1' } else { b'0' };
            assert!(!device::verify(&public, &changed, &parsed.signature));
            // Another key fails.
            assert!(!parsed.verifies(&stranger.public_key()));
        }
        let one = SignedHead::from_headers(HEAD1_B64, SIG1_B64).unwrap();
        let two = SignedHead::from_headers(HEAD2_B64, SIG2_B64).unwrap();
        assert_eq!(two.head.previous, one.hash());
        assert_eq!((one.head.version, two.head.version), (1, 2));
        assert_eq!(one.head.previous, ZERO_HASH);
        assert_eq!(one.head.device, DeviceId(2));
        assert_eq!(one.head.time, 1_790_000_000);
        // A team id outside `a-z2-7` is not a team id.
        assert!(TeamId::parse("t_7k2m9q4x8c").is_none());
    }

    #[test]
    fn a_head_round_trips() {
        let pair = vector_pair();
        let rng = SystemRandom::new();
        let signature = pair.sign(&rng, HEAD1.as_bytes()).unwrap();
        let one = SignedHead::from_headers(HEAD1_B64, &encode_b64(signature.as_ref())).unwrap();
        assert!(one.verifies(&unhex(PUBLIC)));
        assert_eq!(one.head.text(), HEAD1);
        assert_eq!(one.head.size, 18);
        assert_eq!(one.head.vault_id, "0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77");
        let two = SyncHead {
            version: 2,
            snapshot_sha256: Sha256::digest(b"synthetic snapshot 2").into(),
            size: 20,
            previous: one.hash(),
            time: 1_790_000_060,
            ..one.head.clone()
        };
        assert_eq!(SyncHead::parse(two.text().as_bytes()).unwrap(), two);
        assert_eq!(two.text(), HEAD2);
    }

    #[test]
    fn a_new_signature_differs_and_still_verifies() {
        let pair = vector_pair();
        let rng = SystemRandom::new();
        let a = pair.sign(&rng, HEAD1.as_bytes()).unwrap();
        let b = pair.sign(&rng, HEAD1.as_bytes()).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
        let public = unhex(PUBLIC);
        assert!(device::verify(&public, HEAD1.as_bytes(), a.as_ref()));
        assert!(device::verify(&public, HEAD1.as_bytes(), b.as_ref()));
        assert!(!device::verify(&public, HEAD2.as_bytes(), a.as_ref()));
    }

    #[test]
    fn every_other_text_is_refused() {
        let good = HEAD1.to_string();
        assert!(SyncHead::parse(good.as_bytes()).is_ok());
        let zeros = "0".repeat(64);
        let sha = "5b77343bd881a4f425bde1ec9979946ec1add11de02010d4c63159977bac4de8";
        let vault = "0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77";
        let bad = [
            format!("{good}\n"),
            good.replace('\n', "\r\n"),
            format!(" {good}"),
            good.replacen("v1", "v2", 1),
            good.replace(" 1 ", "  1 "),
            good.replace(" 1 ", " 01 "),
            good.replace(" 1 ", " 0 "),
            good.replace(" 1 ", " -1 "),
            good.replace(" 1 ", " 18446744073709551616 "),
            good.replace(" 18\n", " 018\n"),
            good.replace(" 18\n", " 0\n"),
            good.replace(" 18\n", " 67108865\n"),
            good.replace(vault, &vault.to_uppercase()),
            good.replace(vault, "0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a7"),
            good.replace(vault, "0f3c2a105-b7e-4d9a-8c21-6f0e4b1d9a77"),
            good.replace(sha, &sha.to_uppercase()),
            good.replace(sha, &sha[..63]),
            good.replace(&zeros, &format!("{zeros}0")),
            good.replace("t_7k2m5q4x3c/2", "t_7k2m5q4x3c/02"),
            good.replace("t_7k2m5q4x3c/2", "t_7k2m5q4x3c/0"),
            good.replace("t_7k2m5q4x3c/2", "t_7k2m5q4x3c"),
            good.replace("t_7k2m5q4x3c/2", "t_7K2M5Q4X3C/2"),
            good.replace("t_7k2m5q4x3c/2", "t_7k2m9q4x8c/2"),
            good.replace("t_7k2m5q4x3c/2", "t_7k2m5q4x3c/2/3"),
            good.replace("1790000000", "1790000000000"),
            good.replace("1790000000", "01790000000"),
            good.replace("1790000000", "17900000\u{e9}0"),
            format!("{good} "),
            format!("{good}\nextra"),
            good.replace('\n', " "),
            String::new(),
        ];
        for text in bad {
            assert_eq!(SyncHead::parse(text.as_bytes()), Err(HeadError), "{text:?}");
        }
        assert!(SyncHead::parse(&[0xff, 0xfe]).is_err());
        assert!(SyncHead::parse(good.replace("1790000000", "0").as_bytes()).is_ok());
        assert!(SyncHead::parse(good.replace(" 18\n", " 67108864\n").as_bytes()).is_ok());
    }

    #[test]
    fn headers_are_checked_before_the_text() {
        let head = HEAD1_B64;
        assert!(SignedHead::from_headers(head, SIG1_B64).is_ok());
        assert!(SignedHead::from_headers("", SIG1_B64).is_err());
        assert!(SignedHead::from_headers(head, "").is_err());
        assert!(SignedHead::from_headers(&format!("{head}="), SIG1_B64).is_err());
        assert!(SignedHead::from_headers(head, &format!("{SIG1_B64}=")).is_err());
        assert!(SignedHead::from_headers(&"A".repeat(513), SIG1_B64).is_err());
        assert!(SignedHead::from_headers(head, &"A".repeat(97)).is_err());
        assert!(SignedHead::from_headers(head, &encode_b64(&[1u8; 73])).is_err());
        assert!(SignedHead::from_headers(head, "AA").is_ok());
    }
}
