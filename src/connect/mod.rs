//! The Apassy Connect account on this Mac (ADR 0037 stage 7, plan s7 unit M1, contract
//! [connect-account-v1](../../docs/contracts/connect-account-v1.md)).
//!
//! - [`device_key`]: the account device key. One non-exportable-by-Apassy P-256 key for
//!   each device, kept in the Keychain outside every vault through the signed helper
//!   (this device only, not synchronizable, behind Touch ID). It signs only the seven
//!   messages of section 5 ([`SIGNING_TAGS`]) and refuses any other.
//! - [`words`]: the ids, the link code and its hash, the six safety words, and the
//!   recovery code.
//! - [`client`]: one call for each route of the contract, over the relay HTTP client of
//!   the app (`https://` anywhere, `http://` on loopback only).
//! - [`account`]: the account of this Mac. Creation with the device key and a recovery
//!   code; sign-in by challenge and token (the account token lives 15 minutes in memory
//!   and goes only to the Connect origin); "Add a device…" with the safety words and a
//!   fresh owner check on this Mac; the join of this Mac to an account; revoke, recovery,
//!   deletion; the entitlement token kept in memory. The account file
//!   (`connect/account.json` in the data directory) holds ids, names, the origin, and the
//!   public key: no private key, no token, no email, no code.
//! - [`entitlement`]: the check of an entitlement token (section 10).
//!
//! **No account sign-in adds a device** (section 1): a new device joins only through
//! [`account::JoinRequest`], which ends only when a live device confirms it with the
//! words and `OwnerAction::ConfirmConnectDevice`.

pub mod account;
pub mod client;
pub mod device_key;
pub mod entitlement;
pub mod words;

use std::fmt;

pub use account::{
    AccountState, Clock, ConnectAccount, DeviceLink, JoinPoll, JoinRequest, PendingJoin,
    RevokeOutcome, account_file, drop_stale_account_rows, forget_this_device,
};
pub use client::{
    AccountCreated, AccountDeleted, AccountView, ConnectClient, DeviceView, GroupView, PlanView,
    PlansView, RecoverAnswer, RevokeAnswer, StoreDevice, VaultStoreView, WellKnown,
    configured_origin,
};
pub use device_key::{
    AccountSigner, DeviceKeyError, DeviceKeyStore, KeychainDeviceKeyStore, MemoryKeyStore,
    SIGNING_TAGS,
};
pub use entitlement::{Entitlement, EntitlementClaims, EntitlementError, EntitlementKey, Feature};
pub use words::{LinkCode, RecoveryCode, link_hash, safety_words, same_safety_words};

use crate::broker::approvals::ProofRefusal;

/// The hosted Connect origin (contract section 3). `APASSY_CONNECT_URL` points a build at
/// another Connect, for example the sandbox relay ([`configured_origin`]).
pub const DEFAULT_CONNECT_URL: &str = crate::sync::DEFAULT_RELAY_URL;

/// The platform of this build on the wire (`mac`, `iphone`, or `linux`).
pub const PLATFORM: &str = if cfg!(target_os = "macos") {
    "mac"
} else {
    "linux"
};

/// Sign `message` with the account device key, only when it begins with one of the
/// seven tags of section 5 (plan 0035 I-1: the allow-list contains
/// `apassy-bouncer sign-in v1`). The same as [`AccountSigner::sign`].
pub fn sign(signer: &AccountSigner, message: &[u8]) -> Result<Vec<u8>, ConnectError> {
    signer.sign(message)
}

/// Why a Connect step failed. No value holds a token, a code, or a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// Connect did not answer, or something that is not Connect answered.
    Offline,
    /// The connection broke after the request started: the step may have happened.
    Broken,
    /// `401`: the key, the nonce, or the token is not valid at Connect.
    Unauthenticated,
    /// This Mac is no longer a device of its account: it was revoked, or the account was
    /// deleted. Forget it ([`forget_this_device`]) and add it again from another device.
    Revoked,
    /// `403 join_pending`: the other device has not confirmed yet.
    JoinPending,
    /// `403 join_refused`: the other device refused, or the link expired.
    JoinRefused,
    /// `403 plan_required`: the account is not on Connect for this step.
    PlanRequired,
    /// `403 account_required`: the route needs a live account device.
    AccountRequired,
    /// `403 account_limit`: a count limit of the account (devices, vault stores).
    AccountLimit,
    /// `403 not_in_group`: the device belongs to an account outside the group.
    NotInGroup,
    /// `403 forbidden`: for example a link that does not work, or a wrong recovery code.
    Forbidden,
    /// `404`: no such thing, or this relay has no Connect accounts.
    NotFound,
    /// `409 conflict`.
    Conflict,
    /// `429`: wait this many seconds.
    RateLimited(u64),
    /// Another refusal of Connect, with its status and code.
    Refused { status: u16, code: String },
    /// The challenge names another Connect origin than the one this Mac uses.
    OriginMismatch,
    /// An answer of Connect fails the checks of this Mac (shape, ids, keys, times).
    BadAnswer,
    /// The account key never signs this message: it begins with no tag of section 5.
    TagRefused,
    /// The Keychain holds no account key for this Mac.
    NoDeviceKey,
    /// The account key cannot be read any more (the fingerprints changed), or another
    /// key is in the Keychain than the account file names.
    KeyLost,
    /// The Keychain is not available to this build (no signed helper).
    KeychainUnavailable,
    /// Touch ID was cancelled. Nothing changed.
    Cancelled,
    /// The owner check does not cover this step.
    OwnerCheck(ProofRefusal),
    /// The safety words of a join are not those of its link and keys.
    WordsMismatch,
    /// This Mac already has a Connect account.
    AccountExists,
    /// This Mac has no Connect account.
    NoAccount,
    /// A value of a bad shape was given.
    Invalid,
    /// A failure on this Mac: randomness, the account file, the vault.
    Local,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Offline => {
                "Apassy Connect could not be reached. Check the internet connection and try again."
            }
            Self::Broken => {
                "The connection to Apassy Connect broke. The step may have happened; check before you try again."
            }
            Self::Unauthenticated => "Apassy Connect did not accept this Mac's sign-in.",
            Self::Revoked => {
                "This Mac is no longer a device of its Apassy Connect account. Forget the account on this Mac, then add it again from another device."
            }
            Self::JoinPending => "The other device has not confirmed yet.",
            Self::JoinRefused => {
                "The other device refused, or the link expired. Make a new link on the other device."
            }
            Self::PlanRequired => "This account is not on Apassy Connect.",
            Self::AccountRequired => "This needs a device of an Apassy Connect account.",
            Self::AccountLimit => "This account has reached a limit of Apassy Connect.",
            Self::NotInGroup => "That device belongs to an account outside your family or team.",
            Self::Forbidden => "Apassy Connect refused this step.",
            Self::NotFound => {
                "Apassy Connect does not know it, or this relay has no Connect accounts."
            }
            Self::Conflict => {
                "Apassy Connect has a different state for this. Reload and try again."
            }
            Self::RateLimited(seconds) => {
                return write!(f, "Apassy Connect asks to wait {seconds} seconds.");
            }
            Self::Refused { status, code } => {
                return write!(f, "Apassy Connect refused this step ({status} {code}).");
            }
            Self::OriginMismatch => {
                "Apassy Connect answered for another address. Apassy did not sign in."
            }
            Self::BadAnswer => "Apassy Connect gave an answer that Apassy does not accept.",
            Self::TagRefused => "The account key of this Mac does not sign this.",
            Self::NoDeviceKey => "This Mac has no Apassy Connect key.",
            Self::KeyLost => {
                "This Mac's Apassy Connect key is gone (the Touch ID fingerprints changed). Add this Mac again from another device, or recover the account."
            }
            Self::KeychainUnavailable => {
                "The Keychain is not available to this build. Apassy Connect works only in Apassy.app."
            }
            Self::Cancelled => "Touch ID was cancelled. Nothing changed.",
            Self::OwnerCheck(refusal) => refusal.message(),
            Self::WordsMismatch => "The safety words do not match. Nothing was confirmed.",
            Self::AccountExists => "This Mac already has an Apassy Connect account.",
            Self::NoAccount => "This Mac has no Apassy Connect account.",
            Self::Invalid => "That value is not valid.",
            Self::Local => "Apassy could not complete this step on this Mac.",
        };
        f.write_str(text)
    }
}

impl std::error::Error for ConnectError {}
