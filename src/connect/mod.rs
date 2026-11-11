//! The Apassy Connect account on this Mac (ADR 0037 stage 7, plan s7 unit M1, contract
//! [connect-account-v1](../../docs/contracts/connect-account-v1.md)).
//!
//! - [`device_key`]: the account device key. One non-exportable-by-Apassy P-256 key for
//!   each device, kept in the Keychain outside every vault through the signed helper
//!   (this device only, not synchronizable, behind Touch ID). It signs only the twelve
//!   messages of sections 5 and 16 ([`SIGNING_TAGS`]) and refuses any other.
//! - [`words`]: the ids, the link code with its key fingerprint and its hash, the six
//!   safety words, and the recovery code with its Ed25519 key.
//! - [`trust`]: the signed device list and its check against the pin of this device: an
//!   account device is one that the list that this device verified holds.
//! - [`client`]: one call for each route of the contract, over the relay HTTP client of
//!   the app (`https://` anywhere, `http://` on loopback only).
//! - [`account`]: the account of this Mac. Creation with the device key and a recovery
//!   code; sign-in by challenge and token (the account token lives 15 minutes in memory
//!   and goes only to the Connect origin); "Add a device…" with the safety words and a
//!   fresh owner check on this Mac; the join of this Mac to an account; revoke, recovery,
//!   deletion; the entitlement token kept in memory. The account file
//!   (`connect/account.json` in the data directory) holds ids, names, the origin, the
//!   public key, and the trust store: no private key, no token, no email, no code.
//! - [`share`]: a vault shared between the accounts of one family or team (section 16):
//!   the pin of another account's root by a ceremony with six words, the entries of the
//!   device list that name another account, the trust store of the peers and the shared
//!   stores in the account file, and the signers of each shared store.
//! - [`entitlement`]: the check of an entitlement token (section 10).
//! - [`session`]: the one account session of the app (plan s7 unit M5b): opened with the
//!   vault unlock, closed at a lock and a quit; Settings › Connect, the sync of the vault
//!   stores, and the node's tunnel share its account, key, and token.
//! - [`key_file`]: where the key is kept on each platform: the Keychain on the Mac, a
//!   private file of the user on Linux (and, opt-in, the Secret Service).
//!
//! **No account sign-in adds a device** (section 1): a new device joins only through
//! [`account::JoinRequest`], which ends only when a live device confirms it with the
//! words and `OwnerAction::ConfirmConnectDevice`.

pub mod account;
pub mod client;
pub mod device_key;
pub mod entitlement;
pub mod key_file;
pub mod session;
pub mod share;
pub mod trust;
pub mod words;

use std::fmt;

pub use account::{
    AccountState, Clock, ConnectAccount, DeviceLink, Forgotten, JoinPoll, JoinRequest,
    ListedSigners, PendingJoin, RevokeOutcome, Sleeper, account_file, drop_account_rows,
    drop_stale_account_rows, forget_old_account_file, forget_this_device, group_invite_code,
    has_pending_join, is_old_account_file, signer_policy,
};
pub use client::{
    AccountCreated, AccountDeleted, AccountView, CheckoutAnswer, CheckoutRequest, ConnectClient,
    DeviceView, GroupDetail, GroupJoined, GroupMember, GroupView, InviteAnswer, MemberRemoved,
    PlanOffer, PlanPrice, PlanView, PlansView, PortalAnswer, RecoverAnswer, RevokeAnswer,
    SeatsAnswer, StoreDevice, VaultStoreView, WellKnown, configured_origin, set_configured_origin,
};
pub use device_key::{
    AccountSigner, DeviceKeyError, DeviceKeyStore, KeychainDeviceKeyStore, MemoryKeyStore,
    SIGNING_TAGS,
};
pub use entitlement::{Entitlement, EntitlementClaims, EntitlementError, EntitlementKey, Feature};
pub use key_file::{FileKeyStore, KEYRING_WARNING, key_file, platform_store};
pub use session::{AccountSession, AccountSlot, Follow, OpenTicket, SessionState};
pub use share::{
    LeftStore, PeerPin, Person, ShareLink, ShareNames, ShareOffer, SharePeerJoin, ShareRequest,
    ShareStatus, StoreShare, store_signer_policy,
};
pub use trust::ListEntry;
pub use words::{
    LinkCode, RecoveryCode, RecoveryKey, ShareCode, key_fingerprint, link_fingerprint, link_hash,
    new_account_id, safety_words, same_safety_words, share_fingerprint, share_link_hash,
    share_safety_words,
};

use crate::broker::approvals::ProofRefusal;

/// The hosted Connect origin (contract section 3). `APASSY_CONNECT_URL` points a build at
/// another Connect, for example the sandbox relay ([`configured_origin`]).
pub const DEFAULT_CONNECT_URL: &str = crate::sync::DEFAULT_RELAY_URL;

/// The platform of this build on the wire (`mac`, `iphone`, or `linux`). The iPhone core
/// (`ios/ApassyCore`) also names it itself ([`JoinRequest::start_on`]), because its tests
/// run on a Mac or Linux.
pub const PLATFORM: &str = if cfg!(target_os = "ios") {
    "iphone"
} else if cfg!(target_os = "macos") {
    "mac"
} else {
    "linux"
};

/// The platforms of section 2.
pub const PLATFORMS: [&str; 3] = ["mac", "iphone", "linux"];

/// Sign `message` with the account device key, only when it begins with one of the
/// twelve tags of sections 5 and 16 (plan 0035 I-1: the allow-list contains
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
    /// `401`: the key, the nonce, or the token is not valid at Connect. Never a removal.
    Unauthenticated,
    /// `403 device_removed`: Connect says that this device was removed from its account
    /// (revoked, or the account was deleted). Nothing is deleted on this device; the owner
    /// may forget the account here ([`forget_this_device`]) and add the device again.
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
    /// `409 account_id_taken`: an account creation names an id that Connect holds or held
    /// already. The device makes a new id and signs again.
    AccountIdTaken,
    /// The account was made, but the recovery code that its creation made is no longer in
    /// memory (Apassy was closed while the creation waited for Connect): it was never
    /// shown. The account works; a second device of the account keeps it reachable.
    RecoveryCodeNotShown,
    /// `409 seat_limit`: people or seats below the confirmed members, or above the
    /// maximum of the plan (connect-billing-v1 section 6).
    SeatLimit,
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
    /// The account key left memory with a sign-out (a lock): read it again first.
    SignedOut,
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
    /// The device that Connect names for a link code is not the one of the code: its key
    /// or the root of the device list does not give the fingerprint of the code, or the
    /// list does not verify or does not hold it.
    LinkMismatch,
    /// This device did not verify that device as a device of the account (the signed
    /// device list that this device verified does not hold its key).
    NotVerified,
    /// The account that Connect named for a share code is not the one of the code: the
    /// root of its device list and the inviting device do not give the fingerprint of the
    /// code, or the list does not verify or does not hold that device (section 16.2).
    ShareMismatch,
    /// This Mac already has a Connect account.
    AccountExists,
    /// The account file is from an earlier version of Apassy that kept no signed device
    /// list: this device must join its account again, after the owner forgets the
    /// account here.
    OldAccountFile,
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
            Self::Unauthenticated => concat!(
                "Apassy Connect did not accept this ",
                crate::computer!(),
                "'s sign-in."
            ),
            Self::Revoked => {
                "Apassy Connect says this device was removed from its account. To use the account here again, forget it on this device, then add the device from another device of the account."
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
            Self::AccountIdTaken => {
                "Apassy Connect holds that account id already. Apassy makes a new one; try again."
            }
            Self::RecoveryCodeNotShown => concat!(
                "Your Connect account is made, but Apassy was closed before it could show its recovery code, so it was not shown. Make a new one in Settings › Connect › New Recovery Code…, and add a second device, so that you can reach the account if this ",
                crate::computer!(),
                " is lost."
            ),
            Self::SeatLimit => {
                "That number is below the members of your family or team, or above the most the plan allows. Remove members first, or choose another number."
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
            Self::TagRefused => concat!(
                "The account key of this ",
                crate::computer!(),
                " does not sign this."
            ),
            Self::NoDeviceKey => concat!(
                "This ",
                crate::computer_cap!(),
                " has no Apassy Connect key."
            ),
            Self::SignedOut => {
                concat!(
                    "Apassy Connect is signed out on this ",
                    crate::computer!(),
                    ". Unlock Apassy and try again."
                )
            }
            Self::KeyLost => {
                crate::connect_key_lost!()
            }
            Self::KeychainUnavailable => {
                crate::connect_key_unavailable!()
            }
            Self::Cancelled => crate::connect_key_cancelled!(),
            Self::OwnerCheck(refusal) => refusal.message(),
            Self::WordsMismatch => "The safety words do not match. Nothing was confirmed.",
            Self::LinkMismatch => {
                "This code does not match the device that Apassy Connect named for it. Nothing was joined. Make a new code on the other device."
            }
            Self::NotVerified => {
                "Apassy could not verify that device as a device of your account. Nothing was changed."
            }
            Self::ShareMismatch => {
                "The code does not match the account that answered. Nothing was signed. Ask for a new code."
            }
            Self::AccountExists => concat!(
                "This ",
                crate::computer_cap!(),
                " already has an Apassy Connect account."
            ),
            Self::OldAccountFile => concat!(
                "This ",
                crate::computer!(),
                " must join its Apassy Connect account again: its account file is from an earlier version of Apassy. Forget the account on this ",
                crate::computer!(),
                ", then join it again from another device of the account."
            ),
            Self::NoAccount => concat!(
                "This ",
                crate::computer_cap!(),
                " has no Apassy Connect account."
            ),
            Self::Invalid => "That value is not valid.",
            Self::Local => concat!(
                "Apassy could not complete this step on this ",
                crate::computer!(),
                "."
            ),
        };
        f.write_str(text)
    }
}

impl std::error::Error for ConnectError {}
