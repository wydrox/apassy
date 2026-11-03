//! A small secret sealed under the node master key (plan D2): AES-256-GCM through
//! `ring`, with a key derived by HKDF-SHA256 from the master key.
//!
//! - Key: `HKDF-SHA256(salt = empty, ikm = master key, info)`, 32 bytes. The front's
//!   private key uses the info [`FRONT_INFO`], `apassy-node-front-v1`.
//! - Sealed form: `0x01 || nonce (12 bytes, random) || ciphertext || tag (16 bytes)`.
//! - The associated data is the caller's `context`. The node certificate binds the
//!   SHA-256 of its DER there, so a sealed key does not open next to another
//!   certificate.
//!
//! A wrong master key, a wrong context, a changed byte, a cut, and an unknown version
//! all give [`SealError::Open`]; the error does not say which.

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::hkdf::{HKDF_SHA256, Salt};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

/// The HKDF info of the front's private key.
pub const FRONT_INFO: &[u8] = b"apassy-node-front-v1";
/// The first byte of a sealed value.
pub const VERSION: u8 = 1;
/// The tag of AES-256-GCM.
const TAG_LEN: usize = 16;
/// A master key shorter than this is refused: the node key is 32 random bytes (64 hex
/// characters), and a short one is a bug.
pub const MIN_MASTER_KEY_BYTES: usize = 16;

/// Why a value was not sealed or opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// The master key is shorter than [`MIN_MASTER_KEY_BYTES`].
    WeakKey,
    /// No randomness for the nonce.
    Random,
    /// The value does not open: wrong key, wrong context, changed, cut, or unknown.
    Open,
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::WeakKey => "the node master key is too short",
            Self::Random => "no randomness for the sealed key",
            Self::Open => "the sealed key does not open with this node key",
        })
    }
}

impl std::error::Error for SealError {}

fn derive(master_key: &[u8], info: &[u8]) -> Result<LessSafeKey, SealError> {
    if master_key.len() < MIN_MASTER_KEY_BYTES {
        return Err(SealError::WeakKey);
    }
    let prk = Salt::new(HKDF_SHA256, &[]).extract(master_key);
    let info = [info];
    let okm = prk
        .expand(&info, &AES_256_GCM)
        .map_err(|_| SealError::WeakKey)?;
    Ok(LessSafeKey::new(UnboundKey::from(okm)))
}

/// Seal `plaintext` under `master_key` with the HKDF `info` and the associated data
/// `context`.
pub fn seal(
    master_key: &[u8],
    info: &[u8],
    context: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SealError> {
    let key = derive(master_key, info)?;
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| SealError::Random)?;
    // The buffer holds the plaintext until it is sealed in place; it is erased on drop.
    let mut in_out = Zeroizing::new(plaintext.to_vec());
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(context),
        &mut *in_out,
    )
    .map_err(|_| SealError::Open)?;
    let mut sealed = Vec::with_capacity(1 + NONCE_LEN + in_out.len());
    sealed.push(VERSION);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&in_out);
    Ok(sealed)
}

/// Open a value of [`seal`]. The plaintext is erased on drop.
pub fn open(
    master_key: &[u8],
    info: &[u8],
    context: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let key = derive(master_key, info)?;
    if sealed.len() < 1 + NONCE_LEN + TAG_LEN || sealed[0] != VERSION {
        return Err(SealError::Open);
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&sealed[1..=NONCE_LEN]);
    let mut buffer = Zeroizing::new(sealed[1 + NONCE_LEN..].to_vec());
    let length = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(context),
            &mut buffer[..],
        )
        .map_err(|_| SealError::Open)?
        .len();
    buffer.truncate(length);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SECRET: &[u8] = b"a PKCS#8 key, in a test";

    #[test]
    fn a_sealed_key_opens_only_with_the_right_master_key_info_and_context() {
        let sealed = seal(MASTER, FRONT_INFO, b"cert-hash", SECRET).expect("seal");
        assert_eq!(sealed[0], VERSION);
        assert_eq!(sealed.len(), 1 + NONCE_LEN + SECRET.len() + TAG_LEN);
        assert_eq!(
            &open(MASTER, FRONT_INFO, b"cert-hash", &sealed).expect("open")[..],
            SECRET
        );
        let mut other = MASTER.to_vec();
        other[0] ^= 1;
        assert_eq!(
            open(&other, FRONT_INFO, b"cert-hash", &sealed),
            Err(SealError::Open)
        );
        assert_eq!(
            open(MASTER, b"apassy-node-front-v2", b"cert-hash", &sealed),
            Err(SealError::Open)
        );
        assert_eq!(
            open(MASTER, FRONT_INFO, b"other-cert", &sealed),
            Err(SealError::Open)
        );
    }

    #[test]
    fn every_changed_or_cut_byte_is_refused() {
        let sealed = seal(MASTER, FRONT_INFO, b"", SECRET).expect("seal");
        for index in 0..sealed.len() {
            let mut changed = sealed.clone();
            changed[index] ^= 0x40;
            assert_eq!(
                open(MASTER, FRONT_INFO, b"", &changed),
                Err(SealError::Open),
                "byte {index}"
            );
        }
        for length in 0..sealed.len() {
            assert_eq!(
                open(MASTER, FRONT_INFO, b"", &sealed[..length]),
                Err(SealError::Open),
                "length {length}"
            );
        }
        let mut longer = sealed.clone();
        longer.push(0);
        assert_eq!(open(MASTER, FRONT_INFO, b"", &longer), Err(SealError::Open));
    }

    #[test]
    fn two_seals_differ_and_a_short_master_key_is_refused() {
        let one = seal(MASTER, FRONT_INFO, b"", SECRET).expect("one");
        let two = seal(MASTER, FRONT_INFO, b"", SECRET).expect("two");
        assert_ne!(one, two, "a fresh nonce for each seal");
        assert_eq!(
            seal(&MASTER[..MIN_MASTER_KEY_BYTES - 1], FRONT_INFO, b"", SECRET),
            Err(SealError::WeakKey)
        );
        assert_eq!(
            open(&MASTER[..MIN_MASTER_KEY_BYTES - 1], FRONT_INFO, b"", &one),
            Err(SealError::WeakKey)
        );
        let empty = seal(MASTER, FRONT_INFO, b"", b"").expect("empty");
        assert!(
            open(MASTER, FRONT_INFO, b"", &empty)
                .expect("open")
                .is_empty()
        );
    }
}
