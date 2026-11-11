//! The Apassy Connect account of this Mac (contract connect-account-v1 sections 6 to 10,
//! plan s7 unit M1).
//!
//! - [`ConnectAccount::create`]: a new account with the account device key and a
//!   recovery code that the Mac shows once and never stores.
//! - Sign-in: `POST /v1/account/challenge`, the origin check, `POST /v1/account/token`,
//!   in up to three rounds, each with a fresh challenge. The account token lives at most
//!   15 minutes, in memory only (`Zeroizing`), and goes only to the Connect origin of the
//!   account ([`ConnectAccount::with_token`]: the client of that origin is the only thing
//!   that gets it). Only `403 device_removed` at the token call, which Connect answers
//!   after a valid signature of this device, is [`ConnectError::Revoked`]; a `401` is
//!   never a removal. Even then nothing is deleted on this device: the owner forgets the
//!   account here with an explicit confirmation ([`forget_this_device`]).
//! - The device list is signed and has a cryptographic root ([`super::trust`]):
//!   [`ConnectAccount::view`] verifies it from the pinned root and from the pinned version
//!   on, and only a device of the verified list counts as a device of the account. A
//!   confirmation and a revoke are entries of that list that this Mac signs.
//! - "Add a device…" on this Mac: [`ConnectAccount::start_link`],
//!   [`ConnectAccount::pending_joins`] with the six safety words, and
//!   [`ConnectAccount::confirm_join`] with a fresh owner check
//!   (`OwnerAction::ConfirmConnectDevice`). **No account sign-in adds a device**: an
//!   unknown key that asks for a challenge gets `401` and nothing else.
//! - This Mac joins an account: [`JoinRequest`] (paste or QR of the link code, the words,
//!   the poll every 5 s until the other device confirms or refuses).
//! - [`ConnectAccount::revoke`], [`ConnectAccount::delete`] (both with a fresh owner
//!   check), [`ConnectAccount::recover`], [`ConnectAccount::entitlement`] (kept in
//!   memory), and the vault stores of section 8 for unit M3.
//!
//! The account file ([`account_file`], `connect/account.json` in the data directory,
//! mode 0600 in a 0700 directory) is [`AccountState`]: the origin, the ids, the names, the
//! public key, the creation time, and the trust store (the pinned root, the pinned version
//! and hash of the device list, the known keys, the keys that left the account, and the
//! peers and shared stores of section 16, [`super::share`]). It holds no private key, no
//! token, no email, no link code, no share code, and no recovery code.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::client::{
    AccountCreated, AccountDeleted, AccountView, Challenge, ChallengeRequest, CheckoutAnswer,
    CheckoutRequest, ConnectClient, CreateAccount, DeviceView, GroupDetail, GroupJoined,
    GroupMember, InviteAnswer, JoinBody, JoinCancel, MemberRemoved, PlanView, PortalAnswer,
    RecoverBody, RevokeAnswer, SeatsAnswer, StoreDevice, TokenRequest, VaultStoreView,
};
use super::device_key::{AccountSigner, DeviceKeyStore, recover_message};
use super::entitlement::Entitlement;
use super::share::{self, PeerPin, StoreShare};
use super::trust::{self, MAX_KNOWN, MAX_LEFT, Pin, point, valid_list_hash};
use super::words::{
    LinkCode, RecoveryCode, key_fingerprint, link_fingerprint, new_account_id, safety_words,
    valid_account_id, valid_device_id, valid_group_id,
};
use super::{ConnectError, PLATFORM};
use crate::broker::approvals::{ConnectGroupChange, OwnerAction, OwnerProof};
use crate::sync::{decode_b64u, encode_b64u};
use crate::vault::{Vault, VaultResult};

/// The longest life of an account token on this Mac (section 3), whatever Connect says.
pub const TOKEN_SECONDS: u64 = 900;
/// A token is renewed when it has less than this left.
const TOKEN_MARGIN: u64 = 60;
/// The version of the account file: 4 adds the peers and the shared stores of section 16
/// to the pinned device list of 3. A file of version 3 is read as a file of version 4
/// without peers and shared stores, and written as version 4 at its next change; a file
/// of an earlier version is refused.
const STATE_VERSION: u8 = 4;
/// The version before the peers: read and moved in place.
const STATE_VERSION_3: u8 = 3;
/// The longest account file that is read: the peers and the shared stores at their
/// bounds (`super::share`) fit with room.
const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;
/// A sign-in tries at most this many rounds, each with a fresh challenge.
const SIGN_IN_ROUNDS: usize = 3;
/// The waits before the second and the third round.
const SIGN_IN_WAITS: [Duration; SIGN_IN_ROUNDS - 1] =
    [Duration::from_secs(1), Duration::from_secs(3)];

/// The time source: Unix seconds. Tests move it.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The signers that the account file gives ([`signer_policy`]), published after each write
/// of the file, with a counter of the writes: the session of the app hands them to the
/// sync of the vault stores, whether or not a call to Connect worked
/// (`super::AccountSession::signers_after`).
pub type SignerFeed = Arc<std::sync::Mutex<(u64, Option<crate::sync::SignerPolicy>)>>;

/// The waits between sign-in rounds. Tests make them instant.
pub type Sleeper = Arc<dyn Fn(Duration) + Send + Sync>;

fn system_sleeper() -> Sleeper {
    Arc::new(std::thread::sleep)
}

fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    })
}

/// The waits between the tries of one account creation: the same body again after a lost
/// answer, until Connect answers or the last try is lost too (the creation stays pending).
const CREATE_WAITS: [Duration; 4] = [
    Duration::from_millis(250),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
];
/// A creation signs a new id at most this many times (`409 account_id_taken`).
const CREATE_ID_ROUNDS: usize = 4;

/// The pending creation of an account on this device, next to the account file
/// (`connect/pending-account.json`): the exact body of `POST /v1/account`, written before
/// the first try and removed when Connect answered it. Public values only: ids, names,
/// the public key, the public recovery key, and signatures; never the recovery code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingCreation {
    v: u8,
    origin: String,
    account_id: String,
    name: String,
    device_name: String,
    platform: String,
    public_key: String,
    recovery_key: String,
    signature: String,
    statement: String,
}

impl PendingCreation {
    fn path(account_file: &Path) -> PathBuf {
        account_file.with_file_name("pending-account.json")
    }

    /// The pending creation of `account_file` for this origin and key; `None` when there is
    /// none, or one of another shape, origin, or key (it goes).
    fn load(account_file: &Path, origin: &str, public_key: &str) -> Option<Self> {
        let path = Self::path(account_file);
        let meta = fs::symlink_metadata(&path).ok()?;
        let pending = (meta.is_file() && meta.permissions().mode() & 0o077 == 0)
            .then(|| fs::read(&path).ok())
            .flatten()
            .filter(|text| text.len() as u64 <= MAX_STATE_BYTES)
            .and_then(|text| serde_json::from_slice::<Self>(&text).ok())
            .filter(|pending| {
                pending.v == STATE_VERSION
                    && pending.origin == origin
                    && pending.public_key == public_key
                    && valid_account_id(&pending.account_id)
            });
        if pending.is_none() {
            let _ = fs::remove_file(&path);
        }
        pending
    }

    fn body(&self) -> CreateAccount<'_> {
        CreateAccount {
            account_id: &self.account_id,
            name: &self.name,
            device_name: &self.device_name,
            platform: &self.platform,
            public_key: &self.public_key,
            recovery_key: &self.recovery_key,
            signature: &self.signature,
            statement: &self.statement,
        }
    }

    /// Write it with mode 0600 next to the account file, before the first try.
    fn save(&self, account_file: &Path) -> Result<(), ConnectError> {
        let text = serde_json::to_vec_pretty(self).map_err(|_| ConnectError::Local)?;
        write_private(&Self::path(account_file), &text)
    }

    fn remove(account_file: &Path) {
        let _ = fs::remove_file(Self::path(account_file));
    }
}

/// The recovery codes of the pending creations of this process, by the pending file and
/// the account id: in memory only, so a creation that is repeated in the same run still
/// shows its code once. A restart forgets them ([`ConnectError::RecoveryCodeNotShown`]).
static PENDING_CODES: std::sync::Mutex<Vec<(PathBuf, String, RecoveryCode)>> =
    std::sync::Mutex::new(Vec::new());

fn pending_codes() -> std::sync::MutexGuard<'static, Vec<(PathBuf, String, RecoveryCode)>> {
    PENDING_CODES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Take the recovery code of the pending creation `account_id` of `account_file` out of
/// memory.
fn take_pending_code(account_file: &Path, account_id: &str) -> Option<RecoveryCode> {
    let mut codes = pending_codes();
    let index = codes
        .iter()
        .position(|(path, id, _)| path == account_file && id == account_id)?;
    Some(codes.swap_remove(index).2)
}

/// Forget the recovery codes of the pending creations of this process (tests: a restart).
#[doc(hidden)]
pub fn forget_pending_creation_codes() {
    pending_codes().clear();
}

/// Write `text` at `path` with mode 0600, in a 0700 directory, through a temporary file
/// and a rename.
fn write_private(path: &Path, text: &[u8]) -> Result<(), ConnectError> {
    let dir = path.parent().ok_or(ConnectError::Local)?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|_| ConnectError::Local)?;
    let meta = fs::symlink_metadata(dir).map_err(|_| ConnectError::Local)?;
    if !meta.is_dir() {
        return Err(ConnectError::Local);
    }
    if meta.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|_| ConnectError::Local)?;
    }
    let temporary = path.with_extension("json.new");
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| ConnectError::Local)?;
    file.write_all(text)
        .and_then(|()| file.sync_all())
        .map_err(|_| ConnectError::Local)?;
    drop(file);
    fs::rename(&temporary, path).map_err(|_| ConnectError::Local)
}

/// The account file in `data_dir` (`crate::paths::data_dir()` in the app).
pub fn account_file(data_dir: &Path) -> PathBuf {
    data_dir.join("connect").join("account.json")
}

/// A name of section 2 in its canonical form ([`trust::canonical_name`]): trimmed, 1 to
/// 64 bytes of UTF-8, no control character, not `-`.
fn clean_name(text: &str) -> Result<String, ConnectError> {
    trust::canonical_name(text)
        .map(str::to_owned)
        .ok_or(ConnectError::Invalid)
}

/// What the account file holds. No secret: see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountState {
    pub v: u8,
    /// The Connect origin of the account, without a trailing slash.
    pub origin: String,
    pub account_id: String,
    /// The account device id of this Mac.
    pub device_id: String,
    /// The person's name, when this Mac knows it.
    pub name: Option<String>,
    /// The name of this Mac at Connect.
    pub device_name: String,
    /// b64u of the public key of the account device key of this Mac.
    pub public_key: String,
    /// Unix seconds when this Mac became a device of the account.
    pub created_at: u64,
    /// b64u of the account root that this Mac pinned: its own key after a creation or a
    /// recovery, the root that the link fingerprint named after a join.
    pub root: String,
    /// The highest version of the signed device list that this Mac verified.
    pub list_version: u64,
    /// The list hash of that version: a later list must hold it (no fork).
    pub list_head: String,
    /// b64u of the devices of the list at `list_version` (at most 64).
    pub known: Vec<String>,
    /// b64u of the keys that left the list (that this Mac knew as devices, or that the list
    /// that it verified removed before it joined; at most 128): as the current head each
    /// signs only the versions of a vault store that this Mac had merged already, and below
    /// a head of a device of the list any (`crate::sync::SignerPolicy`).
    pub left: Vec<String>,
    /// The recovery code of this account was never shown on this device: a creation that a
    /// restart interrupted finished without it. Settings › Connect says so until a new
    /// code is made ([`ConnectAccount::new_recovery_code`]).
    #[serde(default)]
    pub recovery_unseen: bool,
    /// The other accounts whose root this account pinned (its own `peer` entries) or took
    /// from the `peer` entry of the account that made a store it joined (at most 64,
    /// section 16, [`PeerPin`]).
    #[serde(default)]
    pub peers: Vec<PeerPin>,
    /// The vault stores shared between accounts that this device knows: its own stores
    /// with shares and the stores it joined, with their members and the keys that ended
    /// ([`StoreShare`]).
    #[serde(default)]
    pub stores: Vec<StoreShare>,
}

impl AccountState {
    /// The account file of the root of an account (a creation, a recovery): the device list
    /// at version 1 with `public_key` (b64u) as its root and only device, named
    /// `device_name`.
    pub fn for_root(
        origin: &str,
        account_id: &str,
        device_id: &str,
        device_name: &str,
        public_key: &str,
        created_at: u64,
    ) -> Self {
        let list_head = point(public_key)
            .map(|key| trust::root_hash(origin, account_id, &key, device_name))
            .unwrap_or_default();
        Self {
            v: STATE_VERSION,
            origin: origin.to_owned(),
            account_id: account_id.to_owned(),
            device_id: device_id.to_owned(),
            name: None,
            device_name: device_name.to_owned(),
            public_key: public_key.to_owned(),
            created_at,
            root: public_key.to_owned(),
            list_version: 1,
            list_head,
            known: vec![public_key.to_owned()],
            left: Vec::new(),
            recovery_unseen: false,
            peers: Vec::new(),
            stores: Vec::new(),
        }
    }

    pub(super) fn keys(texts: &[String]) -> Vec<Vec<u8>> {
        texts.iter().filter_map(|text| point(text)).collect()
    }

    /// The pin of the device list.
    fn pin(&self) -> Pin<'_> {
        Pin {
            version: self.list_version,
            head: &self.list_head,
        }
    }

    fn is_valid(&self) -> bool {
        self.v == STATE_VERSION
            && ConnectClient::new(&self.origin).is_ok_and(|client| client.origin() == self.origin)
            && valid_account_id(&self.account_id)
            && valid_device_id(&self.device_id)
            && self
                .name
                .as_deref()
                .is_none_or(|name| clean_name(name).is_ok_and(|clean| clean == name))
            && clean_name(&self.device_name).is_ok_and(|clean| clean == self.device_name)
            && point(&self.public_key).is_some()
            && point(&self.root).is_some()
            && self.list_version >= 1
            && valid_list_hash(&self.list_head)
            && self.known.len() <= MAX_KNOWN
            && self.left.len() <= MAX_LEFT
            && self
                .known
                .iter()
                .chain(&self.left)
                .all(|key| point(key).is_some())
            && share::valid_state(&self.account_id, &self.peers, &self.stores)
    }

    /// The account file at `path`, or `None` when there is none. A file of a bad shape,
    /// a link, or a file that others can read is [`ConnectError::Local`].
    pub fn load(path: &Path) -> Result<Option<Self>, ConnectError> {
        let meta = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ConnectError::Local),
        };
        if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
            return Err(ConnectError::Local);
        }
        let mut text = Vec::new();
        fs::File::open(path)
            .and_then(|file| file.take(MAX_STATE_BYTES + 1).read_to_end(&mut text))
            .map_err(|_| ConnectError::Local)?;
        if text.len() as u64 > MAX_STATE_BYTES {
            return Err(ConnectError::Local);
        }
        let mut state: Self = match serde_json::from_slice(&text) {
            Ok(state) => state,
            // A file of an earlier version (no signed device list): this device joins its
            // account again after the owner forgets it here (`forget_old_account_file`).
            Err(_) if Self::earlier_version(&text) => return Err(ConnectError::OldAccountFile),
            Err(_) => return Err(ConnectError::Local),
        };
        // Version 3 is version 4 without peers and shared stores: it moves in place, and
        // the next write keeps version 4. This device does not join its account again.
        if state.v == STATE_VERSION_3 && state.peers.is_empty() && state.stores.is_empty() {
            state.v = STATE_VERSION;
        }
        // A file of the first build of version 4 kept keys in the ended accounts of a
        // store: they go (the next refresh takes the ended accounts from the lists again),
        // and the file is written back.
        if state.v == STATE_VERSION
            && !state.is_valid()
            && share::drop_ended_keys(&mut state.stores)
            && state.is_valid()
        {
            let _ = state.save(path);
        }
        if state.is_valid() {
            Ok(Some(state))
        } else if state.v < STATE_VERSION_3 {
            Err(ConnectError::OldAccountFile)
        } else {
            Err(ConnectError::Local)
        }
    }

    /// Whether `text` is an account file of an earlier version that does not move in
    /// place: a JSON object whose `v` is a number below 3.
    fn earlier_version(text: &[u8]) -> bool {
        serde_json::from_slice::<serde_json::Value>(text)
            .ok()
            .and_then(|value| value.get("v").and_then(serde_json::Value::as_u64))
            .is_some_and(|v| v < u64::from(STATE_VERSION_3))
    }

    /// Write the file at `path` with mode 0600, in a 0700 directory, through a temporary
    /// file and a rename.
    pub(super) fn save(&self, path: &Path) -> Result<(), ConnectError> {
        if !self.is_valid() {
            return Err(ConnectError::Invalid);
        }
        let text = serde_json::to_vec_pretty(self).map_err(|_| ConnectError::Local)?;
        write_private(path, &text)
    }
}

/// The proof that the owner forgot the account on this Mac ([`forget_this_device`]: after
/// an explicit confirmation, a revoke of this Mac, or a deletion). Only it lets
/// [`drop_account_rows`] remove every vault row of the account key: no answer of Connect,
/// and no missing or unreadable account file, ever does (B-L2).
#[derive(Debug)]
pub struct Forgotten(());

/// Forget the account on this Mac: the account file and the account device key go. Call
/// it only for an action of the owner on this device. Connect is not asked (a removed or
/// deleted device cannot ask). The vault rows that signed with the key go with
/// [`drop_account_rows`] and the returned proof, when each vault is open.
pub fn forget_this_device(
    store: &dyn DeviceKeyStore,
    path: &Path,
) -> Result<Forgotten, ConnectError> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(_) => return Err(ConnectError::Local),
    }
    AccountSigner::forget(store)?;
    Ok(Forgotten(()))
}

/// Whether the account file at `path` exists and this version of Apassy cannot read it: a
/// file of an earlier version ([`ConnectError::OldAccountFile`]), or one of a shape or with
/// a mode that it does not take. This device must join its account again, after the owner
/// forgets the file here ([`forget_old_account_file`]).
pub fn is_old_account_file(path: &Path) -> bool {
    AccountState::load(path).is_err()
}

/// Forget an account file at `path` that this version cannot read ([`is_old_account_file`]),
/// with the account key, after a fresh owner check for
/// [`OwnerAction::ForgetOldConnectAccount`] in the vault session `epoch`; then a creation
/// or a join works again on this device. A file that loads is not forgotten here
/// ([`ConnectError::Invalid`]). The proof is used up.
pub fn forget_old_account_file(
    store: &dyn DeviceKeyStore,
    path: &Path,
    proof: OwnerProof,
    epoch: &[u8; 32],
) -> Result<Forgotten, ConnectError> {
    proof
        .check(&OwnerAction::ForgetOldConnectAccount, epoch)
        .map_err(ConnectError::OwnerCheck)?;
    drop(proof);
    if !is_old_account_file(path) {
        return Err(ConnectError::Invalid);
    }
    forget_this_device(store, path)
}

/// Remove the vault store rows of `vault` (schema 34, `key_source = 'account'`) of
/// another public key than the account key of `state`: rows that this account can no
/// longer sign for. Call it when a vault opens and the account file loaded. Without an
/// account file, or with one that does not load, call nothing: the rows stay until this
/// Mac forgets the account ([`drop_account_rows`]). Returns how many rows went.
pub fn drop_stale_account_rows(vault: &mut Vault, state: &AccountState) -> VaultResult<usize> {
    let Some(key) = point(&state.public_key) else {
        return Ok(0);
    };
    let teams: Vec<String> = vault
        .relay_memberships()?
        .into_iter()
        .filter(|membership| membership.uses_account_key() && membership.public_key != key)
        .map(|membership| membership.team_id)
        .collect();
    let mut removed = 0;
    for team in teams {
        if vault.remove_relay_membership(&team)? {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Which keys may sign the heads of a vault store of the account of `state`: the devices
/// of the signed device list that this Mac verified, and the keys that left that list (as
/// the current head only for the versions that this Mac had merged of that store, and
/// below a head of a device of the list; `crate::sync::SignerPolicy`). A store shared
/// between accounts (section 16) has signers of its own
/// ([`share::store_signer_policy`]): the devices of the accounts that its signed `share`
/// entries name, through the roots that this account pinned. The trust store of the
/// account file decides alone: no answer of Connect (a group, a store marked shared, a
/// device it lists) adds a key.
pub fn signer_policy(state: &AccountState) -> crate::sync::SignerPolicy {
    crate::sync::SignerPolicy {
        accepted: AccountState::keys(&state.known),
        left: AccountState::keys(&state.left),
        stores: share::shared_signers(state),
    }
}

/// Remove every vault store row of `vault` that signs with an account key, after this
/// Mac left its account (`_forgotten`). Returns how many rows went.
pub fn drop_account_rows(vault: &mut Vault, _forgotten: &Forgotten) -> VaultResult<usize> {
    vault.remove_account_memberships()
}

/// The account token in memory. Debug is redacted; the text is erased on drop.
struct AccountToken {
    value: Zeroizing<String>,
    /// Unix seconds on this Mac's clock when this Mac stops using it.
    until: u64,
}

impl fmt::Debug for AccountToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountToken")
            .field("until", &self.until)
            .field("value", &"[redacted]")
            .finish()
    }
}

/// A token of the account `account_id`: `apassy_act_<account id>_<64 hex>`.
fn valid_token(token: &str, account_id: &str) -> bool {
    token
        .strip_prefix("apassy_act_")
        .and_then(|rest| rest.strip_prefix(account_id))
        .and_then(|rest| rest.strip_prefix('_'))
        .is_some_and(|secret| {
            secret.len() == 64
                && secret
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

/// The second half of a sign-in: check the challenge, sign, and take the token.
/// `expected_device` is the device id that the token must name (`None` for the first
/// sign-in of a join). Returns the token and the device id. A `401` stays
/// [`ConnectError::Unauthenticated`]: only `403 device_removed` is
/// [`ConnectError::Revoked`].
fn finish_sign_in(
    client: &ConnectClient,
    signer: &AccountSigner,
    account_id: &str,
    challenge: Challenge,
    expected_device: Option<&str>,
    now: u64,
) -> Result<(AccountToken, String), ConnectError> {
    if challenge.origin.trim_end_matches('/') != client.origin() {
        return Err(ConnectError::OriginMismatch);
    }
    if decode_b64u(&challenge.nonce).is_none_or(|nonce| nonce.len() != 32) {
        return Err(ConnectError::BadAnswer);
    }
    let public_key = signer.public_key_b64u();
    let signature =
        encode_b64u(&signer.sign_sign_in(client.origin(), account_id, &challenge.nonce)?);
    let answer = client.token(&TokenRequest {
        account_id,
        public_key: &public_key,
        nonce: &challenge.nonce,
        signature: &signature,
    })?;
    let value = Zeroizing::new(answer.token);
    if !valid_token(&value, account_id)
        || answer.account_id != account_id
        || !valid_device_id(&answer.device_id)
        || expected_device.is_some_and(|device| device != answer.device_id)
    {
        return Err(ConnectError::BadAnswer);
    }
    // Never longer than 15 minutes here; a clock ahead of Connect still gets a token,
    // and a `401` renews it.
    let lifetime = match answer.expires_at.checked_sub(now) {
        Some(left) if left > 0 => left.min(TOKEN_SECONDS),
        _ => TOKEN_SECONDS,
    };
    Ok((
        AccountToken {
            value,
            until: now.saturating_add(lifetime),
        },
        answer.device_id,
    ))
}

/// The link of "Add a device…": the code in memory, shown with a Copy button and as a QR
/// code of the same text, and its number at Connect. Debug is redacted.
pub struct DeviceLink {
    code: LinkCode,
    link_id: u64,
    expires_at: u64,
}

impl fmt::Debug for DeviceLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceLink")
            .field("link_id", &self.link_id)
            .field("expires_at", &self.expires_at)
            .field("code", &"[redacted]")
            .finish()
    }
}

impl DeviceLink {
    /// The text of the code, for the Copy button and the QR code (error correction M).
    pub fn code(&self) -> &str {
        self.code.expose()
    }

    pub fn link_id(&self) -> u64 {
        self.link_id
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// A device that asks to join through a link of this Mac, with the safety words that
/// this Mac computed for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingJoin {
    pub join_id: u64,
    pub link_id: u64,
    pub device_name: String,
    pub platform: String,
    /// The joining key, X9.63 (65 bytes).
    pub public_key: Vec<u8>,
    /// The joining key's signature over the `apassy-connect join v1` message of this
    /// link, which names `device_name`: this Mac checked it before it showed the name, and
    /// checks it again before it signs the name.
    pub signature: Vec<u8>,
    /// The six words: `"iPhone" asks to join your Apassy Connect account. Both devices
    /// show: <words>.`
    pub words: String,
    pub created_at: u64,
    pub expires_at: u64,
}

impl PendingJoin {
    /// The action that the owner check of the confirmation names: the account, the join,
    /// the name and the key of the device, and the words exactly as the sheet shows them.
    pub fn owner_action(&self, account_id: &str) -> OwnerAction {
        OwnerAction::ConfirmConnectDevice {
            account_id: account_id.to_owned(),
            join_id: self.join_id,
            device_name: self.device_name.clone(),
            public_key: self.public_key.clone(),
            words: self.words.clone(),
        }
    }
}

/// Whether a failed token call ends only this round of a sign-in: a nonce that Connect
/// does not take any more (`401`), or a busy Connect (`503`).
fn next_round(error: &ConnectError) -> bool {
    matches!(
        error,
        ConnectError::Unauthenticated | ConnectError::Refused { status: 503, .. }
    )
}

/// What a revoke did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeOutcome {
    pub answer: RevokeAnswer,
    /// This Mac revoked itself ("Forget this device"): its token is gone, and the caller
    /// runs [`forget_this_device`].
    pub this_device: bool,
}

/// The account of this Mac at one Connect. Debug is redacted.
pub struct ConnectAccount {
    client: ConnectClient,
    state: AccountState,
    path: PathBuf,
    /// The account device key in memory, from the Keychain. A sign-out (a lock, a quit,
    /// a revoke) drops it; [`ConnectAccount::reopen_signer`] reads it again.
    signer: Option<Arc<AccountSigner>>,
    token: Option<AccountToken>,
    entitlement: Option<Entitlement>,
    /// Connect answered `403 device_removed` to a valid signature of this Mac: every
    /// later call is [`ConnectError::Revoked`], also without the key in memory. The key
    /// and the account file stay until the owner forgets the account here.
    revoked: bool,
    /// The device list of the last view that counted ([`Self::verify`]): the signed name
    /// of each device for the owner checks.
    list: Option<trust::Verified>,
    clock: Clock,
    sleeper: Sleeper,
    /// Where each write of the account file publishes its signers ([`SignerFeed`]).
    feed: Option<SignerFeed>,
    /// What the shared vaults keep in memory between two refreshes (section 16).
    shares: share::ShareMemory,
}

impl fmt::Debug for ConnectAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectAccount")
            .field("state", &self.state)
            .field("signed_in", &self.token.is_some())
            .finish_non_exhaustive()
    }
}

/// One retry after a lost answer, with the same body: Connect answers the same result
/// (sections 6 and 7.2).
fn twice<T>(mut step: impl FnMut() -> Result<T, ConnectError>) -> Result<T, ConnectError> {
    match step() {
        Err(ConnectError::Offline | ConnectError::Broken) => step(),
        other => other,
    }
}

impl ConnectAccount {
    fn build(
        client: ConnectClient,
        state: AccountState,
        path: &Path,
        signer: Arc<AccountSigner>,
    ) -> Self {
        Self {
            client,
            state,
            path: path.to_owned(),
            signer: Some(signer),
            token: None,
            entitlement: None,
            revoked: false,
            list: None,
            clock: system_clock(),
            sleeper: system_sleeper(),
            feed: None,
            shares: share::ShareMemory::default(),
        }
    }

    /// Publish the signers of the account file in `feed` now and after each write of the
    /// file ([`SignerFeed`]).
    pub fn set_signer_feed(&mut self, feed: SignerFeed) {
        self.feed = Some(feed);
        self.publish();
    }

    /// The signers of the account file into the feed, when one is set.
    fn publish(&self) {
        if let Some(feed) = &self.feed {
            let mut held = feed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            held.0 = held.0.wrapping_add(1);
            held.1 = Some(signer_policy(&self.state));
        }
    }

    /// Write the account file, and publish its signers.
    fn write_state(&self) -> Result<(), ConnectError> {
        self.state.save(&self.path)?;
        self.publish();
        Ok(())
    }

    /// Make a new account at `client` with the account device key of this Mac (made now
    /// if this Mac has none) and a new recovery code, and write the account file at
    /// `path`. The recovery code comes back once: show it as 16 words with "Save it in
    /// another password manager"; Apassy never stores it. The first sign-in happens at
    /// the first call that needs the token.
    ///
    /// The body of the creation is written as the pending creation of this device before
    /// the first try (public values only), and the same body goes again after a lost
    /// answer, until Connect answers: a creation never ends with a key that Connect used
    /// while this Mac has no account file. A later call with a pending creation of this
    /// origin and key repeats its body (with its names) and Connect answers the account
    /// that it made. Its recovery code is in memory until the creation is answered: after a
    /// restart the account is still made and its file written, and the call answers
    /// [`ConnectError::RecoveryCodeNotShown`]. An id that Connect holds or held (`409
    /// account_id_taken`) gets a new id and a new body; a used key (`409 conflict`) and any
    /// other refusal end the creation.
    pub fn create(
        client: ConnectClient,
        store: &dyn DeviceKeyStore,
        path: &Path,
        name: &str,
        device_name: &str,
    ) -> Result<(Self, RecoveryCode), ConnectError> {
        if AccountState::load(path)?.is_some() {
            return Err(ConnectError::AccountExists);
        }
        let name = clean_name(name)?;
        let device_name = clean_name(device_name)?;
        let signer = AccountSigner::open_or_create(store)?;
        let public_key = signer.public_key_b64u();
        let mut pending = PendingCreation::load(path, client.origin(), &public_key);
        for _ in 0..CREATE_ID_ROUNDS {
            let creation = match pending.take() {
                Some(creation) => creation,
                None => {
                    // This device makes the account id: the root entry of the device list
                    // names it.
                    let recovery = RecoveryCode::generate()?;
                    let recovery_key = recovery.key()?.public_key_b64u();
                    let account_id = new_account_id()?;
                    let (root, _) = signer.sign_root(client.origin(), &account_id, &device_name)?;
                    let creation = PendingCreation {
                        v: STATE_VERSION,
                        origin: client.origin().to_owned(),
                        signature: encode_b64u(
                            &signer.sign_account(client.origin(), &recovery_key)?,
                        ),
                        account_id,
                        name: name.clone(),
                        device_name: device_name.clone(),
                        platform: PLATFORM.to_owned(),
                        public_key: public_key.clone(),
                        recovery_key,
                        statement: encode_b64u(&root),
                    };
                    // Nothing is sent before the pending creation is on disk.
                    creation.save(path)?;
                    pending_codes().push((path.to_owned(), creation.account_id.clone(), recovery));
                    creation
                }
            };
            let mut answer = client.create_account(&creation.body());
            for wait in CREATE_WAITS {
                if !matches!(answer, Err(ConnectError::Offline | ConnectError::Broken)) {
                    break;
                }
                std::thread::sleep(wait);
                answer = client.create_account(&creation.body());
            }
            match answer {
                Ok(created) => return Self::created(client, signer, path, &creation, &created),
                Err(ConnectError::AccountIdTaken) => {
                    // A new id and a new body; the code of this one is of no account.
                    PendingCreation::remove(path);
                    drop(take_pending_code(path, &creation.account_id));
                }
                // No answer: the creation stays pending, and the next call repeats it.
                Err(error @ (ConnectError::Offline | ConnectError::Broken)) => return Err(error),
                // Connect made nothing for now (a limit, a busy or failing service): the
                // same body goes again later.
                Err(
                    error @ (ConnectError::RateLimited(_)
                    | ConnectError::Refused {
                        status: 500..=599, ..
                    }),
                ) => return Err(error),
                Err(error) => {
                    PendingCreation::remove(path);
                    drop(take_pending_code(path, &creation.account_id));
                    return Err(error);
                }
            }
        }
        Err(ConnectError::AccountIdTaken)
    }

    /// The account that Connect made for the pending creation `creation`: the account
    /// file, then the end of the pending creation, and its recovery code when this process
    /// still holds it.
    fn created(
        client: ConnectClient,
        signer: AccountSigner,
        path: &Path,
        creation: &PendingCreation,
        created: &AccountCreated,
    ) -> Result<(Self, RecoveryCode), ConnectError> {
        if created.account_id != creation.account_id || !valid_device_id(&created.device_id) {
            return Err(ConnectError::BadAnswer);
        }
        // This Mac is the account root: version 1 of the device list. A code that this
        // process does not hold any more was never shown: the account file keeps saying so.
        let shown = pending_codes()
            .iter()
            .any(|(held, id, _)| held == path && *id == creation.account_id);
        let state = AccountState {
            name: Some(creation.name.clone()),
            recovery_unseen: !shown,
            ..AccountState::for_root(
                client.origin(),
                &created.account_id,
                &created.device_id,
                &creation.device_name,
                &creation.public_key,
                created.created_at,
            )
        };
        // A failed save keeps the creation pending (and its code in memory): the next call
        // repeats it and writes the file.
        state.save(path)?;
        PendingCreation::remove(path);
        let recovery = take_pending_code(path, &creation.account_id)
            .ok_or(ConnectError::RecoveryCodeNotShown)?;
        Ok((Self::build(client, state, path, Arc::new(signer)), recovery))
    }

    /// The account of this Mac from the account file at `path`, with its key from
    /// `store` (Touch ID in the Keychain). `None` without an account file. A key that is
    /// missing or differs from the file is [`ConnectError::KeyLost`].
    pub fn open(store: &dyn DeviceKeyStore, path: &Path) -> Result<Option<Self>, ConnectError> {
        let Some(state) = AccountState::load(path)? else {
            return Ok(None);
        };
        let client = ConnectClient::new(&state.origin)?;
        let signer = AccountSigner::open(store)?.ok_or(ConnectError::KeyLost)?;
        if signer.public_key_b64u() != state.public_key {
            return Err(ConnectError::KeyLost);
        }
        Ok(Some(Self::build(client, state, path, Arc::new(signer))))
    }

    /// Recover an account that has no live device (section 9): this Mac becomes its first
    /// device (the new root) with its account key, every vault store of the account is
    /// deleted at Connect, and a new recovery code replaces the old one. The old code
    /// never leaves this Mac: its key signs the request. A lost answer is sent once more
    /// with the same body. The new code comes back once, with the number of deleted
    /// stores.
    pub fn recover(
        client: ConnectClient,
        store: &dyn DeviceKeyStore,
        path: &Path,
        account_id: &str,
        recovery: &str,
        device_name: &str,
    ) -> Result<(Self, RecoveryCode, u64), ConnectError> {
        if AccountState::load(path)?.is_some() {
            return Err(ConnectError::AccountExists);
        }
        let account_id = account_id.trim();
        if !valid_account_id(account_id) {
            return Err(ConnectError::Invalid);
        }
        let old = RecoveryCode::parse(recovery).ok_or(ConnectError::Invalid)?;
        let device_name = clean_name(device_name)?;
        let signer = AccountSigner::open_or_create(store)?;
        let new = RecoveryCode::generate()?;
        let recovery_key = new.key()?.public_key_b64u();
        let public_key = signer.public_key_b64u();
        let message = recover_message(client.origin(), account_id, &public_key, &recovery_key);
        let signature = encode_b64u(&signer.sign(&message)?);
        let recovery_signature = encode_b64u(&old.key()?.sign_recover(&message)?);
        drop(old);
        // This device is the root of the new device list: its entry, signed over its name.
        let (root, _) = signer.sign_root(client.origin(), account_id, &device_name)?;
        let statement = encode_b64u(&root);
        let body = RecoverBody {
            account_id,
            device_name: &device_name,
            platform: PLATFORM,
            public_key: &public_key,
            recovery_key: &recovery_key,
            signature: &signature,
            recovery_signature: &recovery_signature,
            statement: &statement,
        };
        let answer = twice(|| client.recover(&body))?;
        if answer.account_id != account_id || !valid_device_id(&answer.device_id) {
            return Err(ConnectError::BadAnswer);
        }
        // This Mac is the new account root: version 1 of a new device list.
        let state = AccountState::for_root(
            client.origin(),
            &answer.account_id,
            &answer.device_id,
            &device_name,
            &public_key,
            0,
        );
        let mut account = Self::build(client, state, path, Arc::new(signer));
        account.state.created_at = account.now();
        account.state.save(path)?;
        Ok((account, new, answer.deleted_stores))
    }

    /// Use `clock` for every time of this account (tests).
    pub fn set_clock(&mut self, clock: Clock) {
        self.clock = clock;
    }

    /// Use `sleeper` for the waits between sign-in rounds (tests).
    pub fn set_sleeper(&mut self, sleeper: Sleeper) {
        self.sleeper = sleeper;
    }

    /// Whether Connect said that this device was removed from its account
    /// (`403 device_removed`). The account file and the key stay until the owner forgets
    /// the account on this device.
    pub fn is_removed(&self) -> bool {
        self.revoked
    }

    pub(super) fn now(&self) -> u64 {
        (self.clock)()
    }

    /// What the account file says.
    pub fn state(&self) -> &AccountState {
        &self.state
    }

    /// The client of the Connect origin of the account.
    pub fn client(&self) -> &ConnectClient {
        &self.client
    }

    /// The account device key of this Mac: for the sign-in of the bouncer brain
    /// (`AccountSigner::sign_brain_sign_in`, plan 0035 C3 and H) and for the relay-sync
    /// sign-ins and heads of the vault stores (unit M3). [`ConnectError::SignedOut`]
    /// after a sign-out. A holder of the key drops it when the vault locks, as
    /// [`Self::sign_out`] does.
    pub fn signer(&self) -> Result<Arc<AccountSigner>, ConnectError> {
        if self.revoked {
            return Err(ConnectError::Revoked);
        }
        self.signer.clone().ok_or(ConnectError::SignedOut)
    }

    /// Drop the token and the key from memory after Connect said `403 device_removed`:
    /// [`Self::sign_out`], and every later call is [`ConnectError::Revoked`]. Nothing is
    /// deleted.
    fn revoked(&mut self) -> ConnectError {
        self.sign_out();
        self.revoked = true;
        ConnectError::Revoked
    }

    /// Read the account device key of this Mac again from `store` (Touch ID) after a
    /// sign-out. A missing key, or another key than the account file names, is
    /// [`ConnectError::KeyLost`].
    pub fn reopen_signer(&mut self, store: &dyn DeviceKeyStore) -> Result<(), ConnectError> {
        let signer = AccountSigner::open(store)?.ok_or(ConnectError::KeyLost)?;
        if signer.public_key_b64u() != self.state.public_key {
            return Err(ConnectError::KeyLost);
        }
        self.signer = Some(Arc::new(signer));
        Ok(())
    }

    /// The public key of this Mac's account key, X9.63, from the account file (checked
    /// when it loaded). It needs no private key.
    pub(super) fn own_public_key(&self) -> Vec<u8> {
        point(&self.state.public_key).unwrap_or_default()
    }

    /// Whether a token is in memory and good for another minute.
    pub fn is_signed_in(&self) -> bool {
        self.token
            .as_ref()
            .is_some_and(|token| self.now().saturating_add(TOKEN_MARGIN) < token.until)
    }

    /// Drop the token, the entitlement, and the account device key from memory: a lock,
    /// a quit, a revoke. A later call that needs the key is [`ConnectError::SignedOut`]
    /// until [`Self::reopen_signer`].
    pub fn sign_out(&mut self) {
        self.token = None;
        self.entitlement = None;
        self.signer = None;
    }

    /// Sign in now: a challenge, the origin check, the signature, the token, in up to
    /// three rounds. A token call refused with `401` or `503` waits (1 s, then 3 s) and
    /// starts the next round with a fresh challenge; after the last round the sign-in is
    /// [`ConnectError::Unauthenticated`]. A challenge refused with `401` is
    /// [`ConnectError::Unauthenticated`] at once. Neither is a removal: only
    /// `403 device_removed` at the token call is [`ConnectError::Revoked`].
    pub fn sign_in(&mut self) -> Result<(), ConnectError> {
        self.token = None;
        let signer = self.signer()?;
        let public_key = signer.public_key_b64u();
        for round in 0..SIGN_IN_ROUNDS {
            if round > 0 {
                (self.sleeper)(SIGN_IN_WAITS[round - 1]);
            }
            let challenge = self.client.challenge(&ChallengeRequest {
                account_id: &self.state.account_id,
                public_key: &public_key,
            })?;
            let now = self.now();
            match finish_sign_in(
                &self.client,
                &signer,
                &self.state.account_id,
                challenge,
                Some(self.state.device_id.as_str()),
                now,
            ) {
                Ok((token, _)) => {
                    self.token = Some(token);
                    return Ok(());
                }
                Err(ConnectError::Revoked) => return Err(self.revoked()),
                Err(error) if next_round(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(ConnectError::Unauthenticated)
    }

    /// The token text, after a sign-in when the token is missing or nearly over.
    fn fresh_token(&mut self) -> Result<Zeroizing<String>, ConnectError> {
        if !self.is_signed_in() {
            self.sign_in()?;
        }
        self.token
            .as_ref()
            .map(|token| token.value.clone())
            .ok_or(ConnectError::Unauthenticated)
    }

    /// Run `call` with the client of the account origin and the account token: the only
    /// way the token leaves this type. A `401` signs in again once and repeats the call;
    /// a second `401` is [`ConnectError::Unauthenticated`] and drops the token.
    pub fn with_token<T>(
        &mut self,
        mut call: impl FnMut(&ConnectClient, &str) -> Result<T, ConnectError>,
    ) -> Result<T, ConnectError> {
        let token = self.fresh_token()?;
        match call(&self.client, token.as_str()) {
            Err(ConnectError::Unauthenticated) => {}
            other => return other,
        }
        drop(token);
        self.sign_in()?;
        let token = self.fresh_token()?;
        match call(&self.client, token.as_str()) {
            Err(ConnectError::Unauthenticated) => {
                self.token = None;
                Err(ConnectError::Unauthenticated)
            }
            other => other,
        }
    }

    /// The pinned root of the account file (X9.63).
    pub(super) fn root_key(&self) -> Vec<u8> {
        point(&self.state.root).unwrap_or_default()
    }

    /// Verify the device list of `view` from the pinned root and the pin, mark each device
    /// verified when the list holds its key (with the name that the list signed for it),
    /// and learn the list: the pin moves to its head, the known keys become its devices, and
    /// the keys that left are kept. Writes the account file when the trust store changed. A
    /// list that does not verify, is older than the pin, forks from it, or does not hold
    /// this Mac's own key as a device marks no device verified and changes nothing here. A
    /// row whose key is this Mac's own while its id is not, or the reverse, is not verified.
    fn verify(&mut self, view: &mut AccountView) -> Result<(), ConnectError> {
        let own = self.own_public_key();
        let verified = trust::verify_list(
            self.client.origin(),
            &self.state.account_id,
            &self.root_key(),
            &view.device_list,
        )
        .filter(|list| self.state.pin().accepts(list))
        .filter(|list| list.live.contains(&own));
        for device in &mut view.devices {
            device.fingerprint = point(&device.public_key)
                .map(|key| key_fingerprint(&key))
                .unwrap_or_default();
            device.verified = false;
            device.signed_name = None;
        }
        let Some(list) = verified else {
            view.list_verified = false;
            return Ok(());
        };
        view.list_verified = true;
        for device in &mut view.devices {
            let Some(key) = point(&device.public_key) else {
                continue;
            };
            let own_row = device.device_id == self.state.device_id;
            device.verified = list.live.contains(&key) && (key == own) == own_row;
            if device.verified {
                device.signed_name = list.name_of(&key).map(str::to_owned);
            }
        }
        self.advance(list.version, list.head(), &list.live, &list.removed)?;
        // What the list says of other accounts: its own peers and the members of its own
        // shared stores (section 16). The stores it joined learn their members from the
        // lists of the accounts that made them ([`Self::refresh_shares`]).
        if share::learn_own(&mut self.state, &list.shares) {
            self.write_state()?;
        }
        self.list = Some(list);
        Ok(())
    }

    /// The account file, to change it (`super::share`); [`Self::save_state`] writes it.
    pub(super) fn state_mut(&mut self) -> &mut AccountState {
        &mut self.state
    }

    /// Write the account file (and publish its signers).
    pub(super) fn save_state(&self) -> Result<(), ConnectError> {
        self.write_state()
    }

    /// Forget the device list of the last view: the next view gives it again.
    pub(super) fn forget_list(&mut self) {
        self.list = None;
    }

    /// The device list of the last view that counted, when this Mac has one.
    pub fn verified_list(&self) -> Option<&trust::Verified> {
        self.list.as_ref()
    }

    /// What the shared vaults keep in memory between two refreshes (`super::share`).
    pub(super) fn share_memory(&mut self) -> &mut share::ShareMemory {
        &mut self.shares
    }

    /// Move the trust store to the list version `version` with the hash `head`, the
    /// devices `live`, and the keys that the list removed `removed`, and write the account
    /// file when anything changed.
    pub(super) fn advance(
        &mut self,
        version: u64,
        head: &str,
        live: &[Vec<u8>],
        removed: &[Vec<u8>],
    ) -> Result<(), ConnectError> {
        let mut known = AccountState::keys(&self.state.known);
        let mut left = AccountState::keys(&self.state.left);
        let moved = trust::learn(&mut known, &mut left, live, removed);
        if !moved && version == self.state.list_version && head == self.state.list_head {
            return Ok(());
        }
        self.state.list_version = version;
        self.state.list_head = head.to_owned();
        self.state.known = known.iter().map(|key| encode_b64u(key)).collect();
        self.state.left = left.iter().map(|key| encode_b64u(key)).collect();
        self.write_state()
    }

    /// A fresh [`Self::view`] whose device list verified: the head that the next entry of
    /// this Mac names. A list that does not verify is [`ConnectError::BadAnswer`], and
    /// nothing is signed.
    pub(super) fn verified_view(&mut self) -> Result<AccountView, ConnectError> {
        let view = self.view()?;
        if !view.list_verified {
            return Err(ConnectError::BadAnswer);
        }
        Ok(view)
    }

    /// Sign the next entry of the device list (`op` for `key`, with `link_hash` for an
    /// `add`) from the head that this Mac verified, and send it with `send`. A `409` (the
    /// list moved: another device signed in between) reads the list again and signs once
    /// more. On success this Mac pins the entry it signed: the list hash it computed and
    /// the devices after the change.
    fn signed_change<T>(
        &mut self,
        op: &str,
        key: &[u8],
        (link_hash, name): (Option<&str>, Option<&str>),
        mut send: impl FnMut(&ConnectClient, &str, (u64, &str)) -> Result<T, ConnectError>,
    ) -> Result<T, ConnectError> {
        let signer = self.signer()?;
        let key_b64u = encode_b64u(key);
        for round in 0..2 {
            self.verified_view()?;
            let (version, previous) = (self.state.list_version + 1, self.state.list_head.clone());
            let (signature, hash) = signer.sign_list_entry(
                self.client.origin(),
                &self.state.account_id,
                (version, &previous),
                op,
                &key_b64u,
                link_hash,
                name,
            )?;
            let statement = encode_b64u(&signature);
            match self.with_token(|client, token| send(client, token, (version, &statement))) {
                Ok(answer) => {
                    let mut live = AccountState::keys(&self.state.known);
                    let mut removed = Vec::new();
                    match op {
                        "add" if !live.contains(&key.to_vec()) => live.push(key.to_vec()),
                        "remove" => {
                            live.retain(|held| held != key);
                            removed.push(key.to_vec());
                        }
                        _ => {}
                    }
                    self.advance(version, &hash, &live, &removed)?;
                    // The names of the list come again with the next view.
                    self.list = None;
                    return Ok(answer);
                }
                Err(ConnectError::Conflict) if round == 0 => {}
                Err(error) => return Err(error),
            }
        }
        Err(ConnectError::Conflict)
    }

    /// `GET /v1/account`: the account, its plan, its devices, its group, and the signed
    /// device list. The Mac polls it every 3 s while the checkout sheet is open (M2). The
    /// list is verified from the pinned root and the pin ([`AccountView::list_verified`]),
    /// each device is verified when the list holds its key ([`DeviceView::verified`]), and
    /// the trust store learns the list. The name of the person goes into the account file when this Mac did
    /// not know it; the email never does.
    pub fn view(&mut self) -> Result<AccountView, ConnectError> {
        let mut view = self.with_token(|client, token| client.account(token))?;
        if view.account_id != self.state.account_id {
            return Err(ConnectError::BadAnswer);
        }
        self.verify(&mut view)?;
        if self.state.name.is_none()
            && let Ok(name) = clean_name(&view.name)
        {
            self.state.name = Some(name);
            self.write_state()?;
        }
        Ok(view)
    }

    /// The keys (X9.63) of the verified devices of the account, from a fresh
    /// [`Self::view`]: the only keys whose heads a vault store of the account accepts
    /// (`RelayTransport::with_signer_keys`).
    pub fn verified_keys(&mut self) -> Result<Vec<Vec<u8>>, ConnectError> {
        Ok(self
            .view()?
            .devices
            .iter()
            .filter(|device| device.verified)
            .filter_map(|device| point(&device.public_key))
            .collect())
    }

    /// Which keys may sign the heads of a vault store of this account, after a fresh
    /// [`Self::view`] ([`signer_policy`]: from the trust store only).
    pub fn signer_policy(&mut self) -> Result<crate::sync::SignerPolicy, ConnectError> {
        self.view()?;
        Ok(signer_policy(&self.state))
    }

    /// The owner action of the deletion of this account.
    pub fn delete_action(&self) -> OwnerAction {
        OwnerAction::DeleteConnectAccount {
            account_id: self.state.account_id.clone(),
        }
    }

    /// Delete the account at Connect (section 6) after a fresh owner check for
    /// [`Self::delete_action`] in the vault session `epoch`, then forget it on this Mac:
    /// the account file and the account key go.
    /// The proof is used up, also when the call fails. Returns the answer of Connect
    /// and the proof for [`drop_account_rows`].
    pub fn delete(
        mut self,
        store: &dyn DeviceKeyStore,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<(AccountDeleted, Forgotten), ConnectError> {
        proof
            .check(&self.delete_action(), epoch)
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        let deleted = self.with_token(|client, token| client.delete_account(token))?;
        if deleted.account_id != self.state.account_id {
            return Err(ConnectError::BadAnswer);
        }
        self.sign_out();
        let forgotten = forget_this_device(store, &self.path)?;
        Ok((deleted, forgotten))
    }

    /// The action of "New Recovery Code…" for this account.
    pub fn new_recovery_code_action(&self) -> OwnerAction {
        OwnerAction::NewRecoveryCode {
            account_id: self.state.account_id.clone(),
        }
    }

    /// "New Recovery Code…" (section 9.1), after a fresh owner check for
    /// [`Self::new_recovery_code_action`] in the session `epoch`: this device makes a new
    /// recovery code and replaces the recovery key at Connect with its public key, in a
    /// statement that this device's key signs over the key that Connect stores now. Only a
    /// device that the verified device list holds does it. The new code comes back once:
    /// show it as at the creation; from now on only it recovers the account. A rotation
    /// that another device made in the meantime (`409 conflict`) reads the account and
    /// signs once more. Success also ends the mark of a code that was never shown
    /// ([`AccountState::recovery_unseen`]). The proof is used up, also when the call fails.
    pub fn new_recovery_code(
        &mut self,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<RecoveryCode, ConnectError> {
        proof
            .check(&self.new_recovery_code_action(), epoch)
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        let code = RecoveryCode::generate()?;
        let recovery_key = code.key()?.public_key_b64u();
        let mut rotated = None;
        for _ in 0..2 {
            let view = self.view()?;
            if !view.list_verified {
                return Err(ConnectError::NotVerified);
            }
            let previous = view
                .recovery_key
                .filter(|key| decode_b64u(key).is_some_and(|bytes| bytes.len() == 32))
                .ok_or(ConnectError::BadAnswer)?;
            let signer = self.signer()?;
            let signature = encode_b64u(&signer.sign_recovery_rotate(
                self.client.origin(),
                &self.state.account_id,
                &previous,
                &recovery_key,
            )?);
            let body = super::client::RecoveryRotate {
                previous: &previous,
                recovery_key: &recovery_key,
                signature: &signature,
            };
            match self.with_token(|client, token| client.rotate_recovery(token, &body)) {
                Err(ConnectError::Conflict) => continue,
                other => {
                    rotated = Some(other?);
                    break;
                }
            }
        }
        let rotated = rotated.ok_or(ConnectError::Conflict)?;
        if rotated.account_id != self.state.account_id {
            return Err(ConnectError::BadAnswer);
        }
        if self.state.recovery_unseen {
            self.state.recovery_unseen = false;
            self.state.save(&self.path)?;
        }
        Ok(code)
    }

    // ---- Devices (section 7). ----

    /// "Add a device…": a new link code in memory and its hash at Connect. The code names
    /// the account root that this Mac pinned and this Mac's key, so the new device checks
    /// the keys that Connect gives it. The link works once and for 10 minutes.
    pub fn start_link(&mut self) -> Result<DeviceLink, ConnectError> {
        let root = self.root_key();
        let code = LinkCode::generate(&self.state.account_id, &root, &self.own_public_key())?;
        let hash = code.link_hash();
        let answer = self.with_token(|client, token| client.link(token, &hash))?;
        Ok(DeviceLink {
            code,
            link_id: answer.link_id,
            expires_at: answer.expires_at,
        })
    }

    /// The devices that ask to join through `link`, each with the safety words that this
    /// Mac computes from the code it holds, its own key, and the joining key. Ask every
    /// 5 s while the sheet is open. An entry with a bad key, or a name that the joining
    /// key did not sign for this link ([`Self::join_signed`]), is left out.
    pub fn pending_joins(&mut self, link: &DeviceLink) -> Result<Vec<PendingJoin>, ConnectError> {
        let pending = self.with_token(|client, token| client.pending(token))?;
        let own_key = self.own_public_key();
        Ok(pending
            .into_iter()
            .filter(|join| join.link_id == link.link_id)
            .filter_map(|join| {
                let public_key = point(&join.public_key)?;
                let device_name = clean_name(&join.device_name).ok()?;
                let signature = decode_b64u(&join.signature)?;
                if !self.join_signed(link, &public_key, &device_name, &signature) {
                    return None;
                }
                let words = safety_words(
                    &self.state.account_id,
                    link.code.expose(),
                    &own_key,
                    &public_key,
                );
                Some(PendingJoin {
                    join_id: join.join_id,
                    link_id: join.link_id,
                    device_name,
                    platform: join.platform,
                    public_key,
                    signature,
                    words,
                    created_at: join.created_at,
                    expires_at: join.expires_at,
                })
            })
            .collect())
    }

    /// Whether `signature` is the joining key `public_key`'s over the `apassy-connect join
    /// v1` message of `link` with the canonical device name `device_name`: the name that
    /// the joining device asked for, whatever Connect reports.
    fn join_signed(
        &self,
        link: &DeviceLink,
        public_key: &[u8],
        device_name: &str,
        signature: &[u8],
    ) -> bool {
        trust::valid_name(device_name)
            && crate::sync::verify_signature(
                public_key,
                &super::device_key::join_message(
                    self.client.origin(),
                    &self.state.account_id,
                    &link.code.link_hash(),
                    &encode_b64u(public_key),
                    device_name,
                ),
                signature,
            )
    }

    /// Confirm `join` of `link` after a fresh owner check for
    /// [`PendingJoin::owner_action`] in the vault session `epoch`: this Mac signs the `add`
    /// entry of the device list for exactly the key for which it computed the words and the
    /// link of the join, after the head that it verified, and Connect adds that key. The
    /// words are computed again from the code and the key, so a changed entry is
    /// [`ConnectError::WordsMismatch`] and nothing is sent; a name that the joining key did
    /// not sign is [`ConnectError::NotVerified`], and nothing is sent. The key is then a
    /// device of the list here, with the name that it signed. The proof is used up, also
    /// when the call fails.
    pub fn confirm_join(
        &mut self,
        link: &DeviceLink,
        join: &PendingJoin,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<DeviceView, ConnectError> {
        if join.link_id != link.link_id
            || safety_words(
                &self.state.account_id,
                link.code.expose(),
                &self.own_public_key(),
                &join.public_key,
            ) != join.words
        {
            return Err(ConnectError::WordsMismatch);
        }
        if !self.join_signed(link, &join.public_key, &join.device_name, &join.signature) {
            return Err(ConnectError::NotVerified);
        }
        proof
            .check(&join.owner_action(&self.state.account_id), epoch)
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        let public_key = encode_b64u(&join.public_key);
        let link_hash = link.code.link_hash();
        let join_id = join.join_id;
        let name = join.device_name.clone();
        let mut device = self.signed_change(
            "add",
            &join.public_key,
            (Some(&link_hash), Some(&name)),
            |client, token, entry| client.confirm(token, join_id, &public_key, entry),
        )?;
        if device.public_key != public_key || !valid_device_id(&device.device_id) {
            return Err(ConnectError::BadAnswer);
        }
        device.verified = true;
        device.signed_name = Some(name);
        device.fingerprint = key_fingerprint(&join.public_key);
        Ok(device)
    }

    /// Refuse a join. Refusing gives no authority, so it needs no owner check.
    pub fn refuse_join(&mut self, join_id: u64) -> Result<(), ConnectError> {
        let answer = self.with_token(|client, token| client.refuse(token, join_id))?;
        if answer.join_id != join_id {
            return Err(ConnectError::BadAnswer);
        }
        Ok(())
    }

    /// The owner action of the revoke of `device`: the name that the signed device list
    /// holds for its key ([`DeviceView::shown_name`]) and the short fingerprint of that key,
    /// the key that the signed removal names.
    pub fn revoke_action(&self, device: &DeviceView) -> OwnerAction {
        OwnerAction::RevokeConnectDevice {
            account_id: self.state.account_id.clone(),
            device_id: device.device_id.clone(),
            device_name: device.shown_name().to_owned(),
            fingerprint: point(&device.public_key)
                .map(|key| key_fingerprint(&key))
                .unwrap_or_default(),
        }
    }

    /// Revoke `device` (section 7.4) after a fresh owner check for
    /// [`Self::revoke_action`] in the vault session `epoch`: this Mac signs the `remove`
    /// entry of the device list for the device's key, after the head that it verified. The
    /// key must be a device of that list, the row as this Mac verifies it now must give the
    /// same owner action (the same signed name and fingerprint), and a row whose key is this
    /// Mac's own must be this Mac's own row, and the reverse ([`ConnectError::NotVerified`]
    /// otherwise, and nothing is sent). This Mac may revoke itself ("Forget this device"):
    /// its token goes, and the caller runs [`forget_this_device`] and [`drop_account_rows`].
    /// The proof is used up, also when the call fails.
    pub fn revoke(
        &mut self,
        device: &DeviceView,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<RevokeOutcome, ConnectError> {
        let action = self.revoke_action(device);
        proof
            .check(&action, epoch)
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        let key = point(&device.public_key).ok_or(ConnectError::NotVerified)?;
        if (key == self.own_public_key()) != (device.device_id == self.state.device_id) {
            return Err(ConnectError::NotVerified);
        }
        let fresh = self
            .verified_view()?
            .devices
            .into_iter()
            .find(|row| row.device_id == device.device_id && row.public_key == device.public_key)
            .filter(|row| row.verified)
            .ok_or(ConnectError::NotVerified)?;
        if self.revoke_action(&fresh) != action
            || !AccountState::keys(&self.state.known).contains(&key)
        {
            return Err(ConnectError::NotVerified);
        }
        let device_id = device.device_id.clone();
        let answer = self.signed_change("remove", &key, (None, None), |client, token, entry| {
            client.revoke(token, &device_id, entry)
        })?;
        if answer.device_id != device.device_id {
            return Err(ConnectError::BadAnswer);
        }
        let this_device = answer.device_id == self.state.device_id;
        if this_device {
            self.sign_out();
        }
        Ok(RevokeOutcome {
            answer,
            this_device,
        })
    }

    // ---- The entitlement token (section 10). ----

    /// The entitlement token of the account, from memory while it is good for five more
    /// minutes, else from Connect, checked with the keys of the well-known document of
    /// the same origin. `None` when the account is not entitled (`403 plan_required`).
    /// It is never written anywhere.
    pub fn entitlement(&mut self) -> Result<Option<&Entitlement>, ConnectError> {
        let now = self.now();
        if self
            .entitlement
            .as_ref()
            .is_some_and(|entitlement| entitlement.is_fresh(now))
        {
            return Ok(self.entitlement.as_ref());
        }
        self.entitlement = None;
        let answer = match self.with_token(|client, token| client.entitlement(token)) {
            Ok(answer) => answer,
            Err(ConnectError::PlanRequired) => return Ok(None),
            Err(error) => return Err(error),
        };
        let token = Zeroizing::new(answer.token);
        let known = self.client.well_known()?;
        if known.v != 1 || known.origin.trim_end_matches('/') != self.client.origin() {
            return Err(ConnectError::BadAnswer);
        }
        let entitlement = Entitlement::checked(&token, &known.keys(), &self.state.account_id, now)
            .map_err(|_| ConnectError::BadAnswer)?;
        self.entitlement = Some(entitlement);
        Ok(self.entitlement.as_ref())
    }

    // ---- Vault stores (section 8), for unit M3. ----

    /// `POST /v1/account/vaults`: the store of the vault `vault_id`, with this Mac as
    /// store device 1. This Mac makes the store id and signs the `store` entry for it at
    /// the version after the head that it verified (section 16), which Connect appends in
    /// the transaction that makes the store: so the account's own list says which stores it
    /// made. A `409` (the list moved, or the id is taken) reads the list again and signs
    /// once more with a new id. The same vault again answers the existing store (its
    /// entry is not signed twice: this Mac then reads the list again).
    pub fn create_vault_store(
        &mut self,
        vault_id: &str,
        name: &str,
    ) -> Result<VaultStoreView, ConnectError> {
        if !crate::sync::relay_crypto::valid_vault_id(vault_id) {
            return Err(ConnectError::Invalid);
        }
        // A vault name is signed into no message: `-` is a vault name too.
        let name = name.trim();
        if name.is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
            return Err(ConnectError::Invalid);
        }
        let signer = self.signer()?;
        for round in 0..2 {
            self.verified_view()?;
            let mut shares = self
                .list
                .as_ref()
                .map(|list| list.shares.clone())
                .ok_or(ConnectError::BadAnswer)?;
            let (version, previous) = (self.state.list_version + 1, self.state.list_head.clone());
            if version > trust::MAX_ADD_VERSION {
                return Err(ConnectError::AccountLimit);
            }
            let team_id = super::words::new_store_id()?;
            let entry = trust::ListEntry {
                version,
                op: share::STORE.to_owned(),
                key: None,
                link_hash: None,
                name: None,
                by: signer.public_key_b64u(),
                signature: None,
                account_id: None,
                root: None,
                team_id: Some(team_id.clone()),
            };
            let (signature, hash) = signer.sign_share_entry(
                self.client.origin(),
                &self.state.account_id,
                (version, &previous),
                share::STORE,
                super::device_key::LIST_NONE,
                None,
                Some(&team_id),
            )?;
            let statement = encode_b64u(&signature);
            let body = super::client::VaultCreate {
                vault_id,
                name,
                team_id: &team_id,
                version,
                statement: &statement,
            };
            match self.with_token(|client, token| client.create_vault_store(token, &body)) {
                Ok(store) => {
                    if store.vault_id != vault_id
                        || !crate::sync::relay_crypto::valid_team_id(&store.team_id)
                    {
                        return Err(ConnectError::BadAnswer);
                    }
                    if store.team_id == team_id
                        && shares.apply(&self.state.account_id, &entry, &hash).is_ok()
                    {
                        let known = AccountState::keys(&self.state.known);
                        self.advance(version, &hash, &known, &[])?;
                        if share::learn_own(&mut self.state, &shares) {
                            self.write_state()?;
                        }
                    }
                    // The names and the entries of the list come again with the next view.
                    self.list = None;
                    return Ok(store);
                }
                Err(ConnectError::Conflict) if round == 0 => {}
                Err(error) => return Err(error),
            }
        }
        Err(ConnectError::Conflict)
    }

    /// `GET /v1/account/vaults`.
    pub fn vault_stores(&mut self) -> Result<Vec<VaultStoreView>, ConnectError> {
        self.with_token(|client, token| client.vault_stores(token))
    }

    /// The owner action of adding the device `device_id` of the account `account_id` to
    /// the store `team_id`.
    pub fn add_store_device_action(
        team_id: &str,
        device_id: &str,
        account_id: &str,
    ) -> OwnerAction {
        OwnerAction::AddStoreDevice {
            team_id: team_id.to_owned(),
            device_id: device_id.to_owned(),
            account_id: account_id.to_owned(),
        }
    }

    /// `POST /v1/account/vaults/{team_id}/devices`: add another device of the account to
    /// a store this Mac is in, after a fresh owner check for
    /// [`Self::add_store_device_action`] in the vault session `epoch`: the device can then
    /// read and write the relay copy. This Mac views the account first and adds only a
    /// device that it verified ([`DeviceView::verified`]), with the key that it verified;
    /// any other device is [`ConnectError::NotVerified`] and nothing is sent. The proof is
    /// used up, also when the call fails. An answer for another device or account is
    /// [`ConnectError::BadAnswer`].
    pub fn add_store_device(
        &mut self,
        team_id: &str,
        device_id: &str,
        account_id: &str,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<StoreDevice, ConnectError> {
        proof
            .check(
                &Self::add_store_device_action(team_id, device_id, account_id),
                epoch,
            )
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        if account_id != self.state.account_id {
            return Err(ConnectError::NotVerified);
        }
        let public_key = self
            .view()?
            .devices
            .into_iter()
            .find(|device| device.device_id == device_id)
            .filter(|device| device.verified)
            .map(|device| device.public_key)
            .ok_or(ConnectError::NotVerified)?;
        let added = self.with_token(|client, token| {
            client.add_store_device(token, team_id, device_id, &public_key)
        })?;
        if added.device_id != device_id || added.account_id != account_id {
            return Err(ConnectError::BadAnswer);
        }
        Ok(added)
    }

    /// `POST /v1/account/vaults/{team_id}/devices` for `device_id`, another live device
    /// of **this** account, without an owner check: the sync through Apassy Connect of
    /// unit M3 registers the account's own devices in a store that this Mac turned on
    /// (connect-account-v1 section 8). Those devices joined the account with the safety
    /// words and a fresh owner check on a live device, and each still needs the vault
    /// passphrase. A device that `devices` of the last [`Self::view`] does not list as a
    /// live device of this account is [`ConnectError::NotInGroup`] before any call, and
    /// one that this Mac did not verify ([`DeviceView::verified`]) is
    /// [`ConnectError::NotVerified`]; the call sends the key that this Mac verified. A
    /// member of a group goes through the link of relay-sync-v1 section 7.
    pub(crate) fn register_own_store_device(
        &mut self,
        team_id: &str,
        device_id: &str,
        live: &[DeviceView],
    ) -> Result<StoreDevice, ConnectError> {
        let device = live
            .iter()
            .find(|d| d.device_id == device_id)
            .filter(|_| device_id != self.state.device_id)
            .ok_or(ConnectError::NotInGroup)?;
        if !device.verified {
            return Err(ConnectError::NotVerified);
        }
        let public_key = device.public_key.clone();
        let account_id = self.state.account_id.clone();
        let added = self.with_token(|client, token| {
            client.add_store_device(token, team_id, device_id, &public_key)
        })?;
        if added.device_id != device_id || added.account_id != account_id {
            return Err(ConnectError::BadAnswer);
        }
        Ok(added)
    }

    /// The owner action of deleting the store `team_id`.
    pub fn delete_vault_store_action(team_id: &str) -> OwnerAction {
        OwnerAction::DeleteVaultStore {
            team_id: team_id.to_owned(),
        }
    }

    /// `DELETE /v1/account/vaults/{team_id}`: the store and its snapshots go, after a
    /// fresh owner check for [`Self::delete_vault_store_action`] in the vault session
    /// `epoch`. The proof is used up, also when the call fails.
    pub fn delete_vault_store(
        &mut self,
        team_id: &str,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<(), ConnectError> {
        proof
            .check(&Self::delete_vault_store_action(team_id), epoch)
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        let answer = self.with_token(|client, token| client.delete_vault_store(token, team_id))?;
        if answer.team_id != team_id {
            return Err(ConnectError::BadAnswer);
        }
        Ok(())
    }

    // ---- Plans, checkout, portal, and groups (connect-billing-v1, unit M2). ----

    /// `GET /v1/account/plan`: the plan state of the account.
    pub fn plan(&mut self) -> Result<PlanView, ConnectError> {
        self.with_token(|client, token| client.plan(token))
    }

    /// `POST /v1/account/checkout` (section 4): a Stripe Checkout session for `request`.
    /// The caller opens [`CheckoutAnswer::url`] in the default browser and polls
    /// [`Self::view`] every 3 s until the plan is entitled; the browser's return changes
    /// nothing. A URL that is not a page of `https://checkout.stripe.com/` is
    /// [`ConnectError::BadAnswer`]. No owner check: a checkout gives no authority over a
    /// vault or a device.
    pub fn checkout(&mut self, request: &CheckoutRequest) -> Result<CheckoutAnswer, ConnectError> {
        if !valid_checkout(request) {
            return Err(ConnectError::Invalid);
        }
        let answer = self.with_token(|client, token| client.checkout(token, request))?;
        if !stripe_page(&answer.url, CHECKOUT_ORIGIN) || answer.session_id.trim().is_empty() {
            return Err(ConnectError::BadAnswer);
        }
        Ok(answer)
    }

    /// `POST /v1/account/portal` (section 5): the Stripe Customer Portal of the account
    /// that pays. It needs no owner check (section 5): the portal changes nothing in
    /// Apassy, and Stripe confirms its own changes. A URL that is not a page of
    /// `https://billing.stripe.com/` is [`ConnectError::BadAnswer`].
    pub fn portal(&mut self) -> Result<PortalAnswer, ConnectError> {
        let answer = self.with_token(|client, token| client.portal(token))?;
        if !stripe_page(&answer.url, PORTAL_ORIGIN) {
            return Err(ConnectError::BadAnswer);
        }
        Ok(answer)
    }

    /// `GET /v1/account/group` (section 6): the family or team with its members, or
    /// `None` when the account is in none.
    pub fn group(&mut self) -> Result<Option<GroupDetail>, ConnectError> {
        match self.with_token(|client, token| client.group(token)) {
            Ok(group) if valid_group_id(&group.group_id) => Ok(Some(group)),
            Ok(_) => Err(ConnectError::BadAnswer),
            Err(ConnectError::NotFound | ConnectError::NotInGroup) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// `POST /v1/account/group/invites`: a link for one person, as `member` or (by a
    /// Team owner) `admin`. The link works once, for 7 days; Apassy never stores it.
    pub fn invite(&mut self, role: &str) -> Result<InviteAnswer, ConnectError> {
        if !matches!(role, "member" | "admin") {
            return Err(ConnectError::Invalid);
        }
        let answer = self.with_token(|client, token| client.invite(token, role))?;
        if !browser_url(&answer.url) || group_invite_code(&answer.url).is_none() {
            return Err(ConnectError::BadAnswer);
        }
        Ok(answer)
    }

    /// `POST /v1/account/group/join` with the invite link or its code, pasted into "Join
    /// a Family or Team". The account joins as `pending`: it gets nothing until the
    /// owner or an admin confirms it with an owner check on their Mac, so this needs none.
    pub fn join_group(&mut self, pasted: &str) -> Result<GroupJoined, ConnectError> {
        let code = group_invite_code(pasted).ok_or(ConnectError::Invalid)?;
        let joined = self.with_token(|client, token| client.join_group(token, &code))?;
        if !valid_group_id(&joined.group_id) || !code.contains(&joined.group_id) {
            return Err(ConnectError::BadAnswer);
        }
        Ok(joined)
    }

    /// The owner action of a change of the group `group_id`.
    pub fn group_change_action(&self, group_id: &str, change: ConnectGroupChange) -> OwnerAction {
        OwnerAction::ChangeConnectGroup {
            account_id: self.state.account_id.clone(),
            group_id: group_id.to_owned(),
            change,
        }
    }

    /// Confirm the pending member `account_id` ("`name`") of the group `group_id` after a
    /// fresh owner check for [`Self::group_change_action`] with
    /// [`ConnectGroupChange::ConfirmMember`] in the vault session `epoch`. The proof is
    /// used up, also when the call fails.
    pub fn confirm_member(
        &mut self,
        group_id: &str,
        account_id: &str,
        name: &str,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<GroupMember, ConnectError> {
        let action = self.group_change_action(
            group_id,
            ConnectGroupChange::ConfirmMember {
                account_id: account_id.to_owned(),
                name: name.to_owned(),
            },
        );
        proof
            .check(&action, epoch)
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        let member = self.with_token(|client, token| client.confirm_member(token, account_id))?;
        if member.account_id != account_id {
            return Err(ConnectError::BadAnswer);
        }
        Ok(member)
    }

    /// Remove the member `account_id` ("`name`") from the group `group_id`, or leave it
    /// (`account_id` is this account), after a fresh owner check for
    /// [`ConnectGroupChange::RemoveMember`] in the vault session `epoch`. The proof is
    /// used up, also when the call fails.
    pub fn remove_member(
        &mut self,
        group_id: &str,
        account_id: &str,
        name: &str,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<MemberRemoved, ConnectError> {
        let action = self.group_change_action(
            group_id,
            ConnectGroupChange::RemoveMember {
                account_id: account_id.to_owned(),
                name: name.to_owned(),
            },
        );
        proof
            .check(&action, epoch)
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        let removed = self.with_token(|client, token| client.remove_member(token, account_id))?;
        if removed.account_id != account_id {
            return Err(ConnectError::BadAnswer);
        }
        Ok(removed)
    }

    /// Ask Stripe for `quantity` people or seats of the group `group_id` after a fresh
    /// owner check for [`ConnectGroupChange::SetSeats`] in the vault session `epoch`. The
    /// new quantity applies when Stripe confirms it. The proof is used up, also when the
    /// call fails.
    pub fn set_seats(
        &mut self,
        group_id: &str,
        quantity: u64,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<SeatsAnswer, ConnectError> {
        if quantity == 0 {
            return Err(ConnectError::Invalid);
        }
        let action = self.group_change_action(group_id, ConnectGroupChange::SetSeats { quantity });
        proof
            .check(&action, epoch)
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        let answer = self.with_token(|client, token| client.set_seats(token, quantity))?;
        if answer.quantity != quantity {
            return Err(ConnectError::BadAnswer);
        }
        Ok(answer)
    }
}

/// The only origin of a Checkout Session the Mac opens (connect-billing-v1 section 4).
const CHECKOUT_ORIGIN: &str = "https://checkout.stripe.com/";
/// The only origin of a Customer Portal session the Mac opens (section 5).
const PORTAL_ORIGIN: &str = "https://billing.stripe.com/";

/// A Stripe page that the Mac opens in the default browser: `origin` itself followed by a
/// path, at most 4096 bytes, no space or control character. Another host, a longer host
/// that starts with Stripe's, or `http://` is refused.
fn stripe_page(url: &str, origin: &str) -> bool {
    url.len() <= 4096
        && url
            .strip_prefix(origin)
            .is_some_and(|path| !path.is_empty())
        && !url.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// An invite link the Mac shows: `https://`, a host, and no space or control character.
fn browser_url(url: &str) -> bool {
    url.len() <= 4096
        && url
            .strip_prefix("https://")
            .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'))
        && !url.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// A checkout body of section 4: a known plan and interval, people only for Family and
/// seats only for Team, each at least 1.
fn valid_checkout(request: &CheckoutRequest) -> bool {
    let interval = matches!(request.interval.as_str(), "month" | "year");
    let counts = match request.plan.as_str() {
        "personal" => request.people.is_none() && request.seats.is_none(),
        "family" => request.people.is_some_and(|n| n > 0) && request.seats.is_none(),
        "team" => request.seats.is_some_and(|n| n > 0) && request.people.is_none(),
        _ => false,
    };
    interval && counts
}

/// The invite code of a pasted invite link or code (connect-billing-v1 section 6):
/// `apassy_gin_<group id>_<64 hex>`, also after the `#` of
/// `https://<site>/connect/join#…`. `None` for any other text.
pub fn group_invite_code(pasted: &str) -> Option<String> {
    let text = pasted.trim();
    let code = text.rsplit_once('#').map_or(text, |(_, code)| code).trim();
    let rest = code.strip_prefix("apassy_gin_")?;
    let (group, secret) = rest.rsplit_once('_')?;
    (valid_group_id(group)
        && secret.len() == 64
        && secret
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| code.to_owned())
}

/// What a poll of a [`JoinRequest`] found.
#[derive(Debug)]
pub enum JoinPoll {
    /// The other device has not confirmed yet: ask again in 5 s.
    Waiting,
    /// The other device refused, or the link expired.
    Refused,
    /// The other device confirmed: this Mac is a device of the account, signed in.
    Confirmed(Box<ConnectAccount>),
}

/// This Mac joins an account with a link code of a live device (section 7.2). Debug is
/// redacted.
///
/// The join is kept on disk while it waits ([`PendingJoinFile`], public values only), so a
/// restart resumes it ([`Self::resume`]) and a confirmation that came after the owner left
/// the step still ends with this device in the account.
pub struct JoinRequest {
    client: ConnectClient,
    path: PathBuf,
    signer: Arc<AccountSigner>,
    account_id: String,
    link_hash: String,
    device_name: String,
    /// `0` for a key that is a device of the account already ([`Self::confirmer`] is
    /// `None`): no join waits at Connect.
    join_id: u64,
    confirmer_name: String,
    /// The account root, named by the fingerprint of the code with the confirming
    /// device's key.
    root: Vec<u8>,
    /// The key of the confirming device that the code named (X9.63); `None` when this
    /// device's key is in the account already (an earlier join that a device confirmed
    /// after this device had left it): the list then needs only this key as a device.
    confirmer: Option<Vec<u8>>,
    /// The pin of the device list of the join answer, verified from that root. The list
    /// that the new account file pins goes on from it and holds this device's own `add`.
    start: (u64, String),
    words: String,
    expires_at: u64,
    /// This device made a new account key for this join: its earlier key was used by a
    /// join that did not finish here.
    new_key: bool,
    clock: Clock,
}

impl fmt::Debug for JoinRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinRequest")
            .field("account_id", &self.account_id)
            .field("join_id", &self.join_id)
            .field("words", &self.words)
            .finish_non_exhaustive()
    }
}

/// Cancel the join of `link_hash` in `account_id` with the signed `apassy-connect
/// join-cancel v1` body.
fn cancel_join(
    client: &ConnectClient,
    signer: &AccountSigner,
    account_id: &str,
    link_hash: &str,
) -> Result<u64, ConnectError> {
    let public_key = signer.public_key_b64u();
    let signature =
        encode_b64u(&signer.sign_join_cancel(client.origin(), account_id, link_hash)?);
    let answer = client.cancel_join(&JoinCancel {
        account_id,
        link_hash,
        public_key: &public_key,
        signature: &signature,
    })?;
    Ok(answer.join_id)
}

/// The join of this device that waits for a confirmation, next to the account file
/// (`connect/pending-join.json`, mode 0600): written when Connect took the join, removed
/// when it ended (confirmed, refused, expired, or cancelled at Connect). Public values
/// only: the ids, the names, the keys, the hash of the link, the pin of the list of the
/// join answer, and the safety words; never the link code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingJoinFile {
    v: u8,
    origin: String,
    account_id: String,
    link_hash: String,
    device_name: String,
    public_key: String,
    join_id: u64,
    confirmer_name: String,
    confirmer: String,
    root: String,
    list_version: u64,
    list_head: String,
    words: String,
    expires_at: u64,
}

impl PendingJoinFile {
    fn path(account_file: &Path) -> PathBuf {
        account_file.with_file_name("pending-join.json")
    }

    /// The pending join of `account_file`; `None` when there is none, or one of another
    /// shape (it goes).
    fn load(account_file: &Path) -> Option<Self> {
        let path = Self::path(account_file);
        let meta = fs::symlink_metadata(&path).ok()?;
        let pending = (meta.is_file() && meta.permissions().mode() & 0o077 == 0)
            .then(|| fs::read(&path).ok())
            .flatten()
            .filter(|text| text.len() as u64 <= MAX_STATE_BYTES)
            .and_then(|text| serde_json::from_slice::<Self>(&text).ok())
            .filter(|pending| {
                pending.v == STATE_VERSION
                    && valid_account_id(&pending.account_id)
                    && valid_list_hash(&pending.link_hash)
                    && valid_list_hash(&pending.list_head)
                    && pending.list_version >= 1
                    && trust::valid_name(&pending.device_name)
                    && point(&pending.public_key).is_some()
                    && point(&pending.confirmer).is_some()
                    && point(&pending.root).is_some()
            });
        if pending.is_none() {
            let _ = fs::remove_file(&path);
        }
        pending
    }

    fn save(&self, account_file: &Path) -> Result<(), ConnectError> {
        let text = serde_json::to_vec_pretty(self).map_err(|_| ConnectError::Local)?;
        write_private(&Self::path(account_file), &text)
    }

    fn remove(account_file: &Path) {
        let _ = fs::remove_file(Self::path(account_file));
    }
}

/// Whether a join of this device waits on disk next to `account_file` ([`JoinRequest::resume`]).
pub fn has_pending_join(account_file: &Path) -> bool {
    PendingJoinFile::load(account_file).is_some()
}

/// End the pending join of `account_file` that the key of `signer` made: cancel it at
/// Connect, best effort, and remove the file. A device that starts another join, makes an
/// account, or recovers one calls it first.
fn end_pending_join(account_file: &Path, signer: &AccountSigner) {
    let Some(pending) = PendingJoinFile::load(account_file) else {
        return;
    };
    if pending.public_key == signer.public_key_b64u()
        && let Ok(client) = ConnectClient::new(&pending.origin)
    {
        let _ = cancel_join(&client, signer, &pending.account_id, &pending.link_hash);
    }
    PendingJoinFile::remove(account_file);
}

impl JoinRequest {
    /// Ask to join with the pasted or scanned `code`: the account device key of this Mac
    /// (made now if this Mac has none) signs the join, and the safety words come from the
    /// key of the confirming device. Show: `Waiting for <confirmer>… Both devices show:
    /// <words>.`
    ///
    /// The confirming device that Connect names must be the one of the code: the root of the
    /// signed device list of the answer and the confirmer's key give the fingerprint of the
    /// code, the list verifies from that root, and the confirmer is a device of it. Any
    /// other answer is [`ConnectError::LinkMismatch`], and the join is cancelled.
    ///
    /// A join of this device that still waits on disk is cancelled first (best effort).
    /// When Connect says that the key of this device is used (`409 conflict`: an earlier
    /// join that a device confirmed after this device had left it, so it has no account
    /// file), the join goes on from the device list that holds this key, verified from the
    /// root that the code names; when the key is no device of that account, this device
    /// makes a new key, joins with it, and says so ([`Self::made_new_key`]).
    pub fn start(
        client: ConnectClient,
        store: &dyn DeviceKeyStore,
        path: &Path,
        code: &str,
        device_name: &str,
    ) -> Result<Self, ConnectError> {
        Self::start_on(client, store, path, code, device_name, PLATFORM)
    }

    /// [`Self::start`] for a device of `platform` (one of [`super::PLATFORMS`]): the iPhone
    /// core joins as `iphone` also in its tests on a Mac or Linux.
    pub fn start_on(
        client: ConnectClient,
        store: &dyn DeviceKeyStore,
        path: &Path,
        code: &str,
        device_name: &str,
        platform: &'static str,
    ) -> Result<Self, ConnectError> {
        if !super::PLATFORMS.contains(&platform) {
            return Err(ConnectError::Invalid);
        }
        if AccountState::load(path)?.is_some() {
            return Err(ConnectError::AccountExists);
        }
        let code = LinkCode::parse(code).ok_or(ConnectError::Invalid)?;
        let device_name = clean_name(device_name)?;
        let signer = AccountSigner::open_or_create(store)?;
        end_pending_join(path, &signer);
        match Self::ask(&client, signer, path, &code, &device_name, platform)? {
            Asked::Waiting(request) => Ok(*request),
            Asked::KeyUsed(signer) => {
                match Self::already_joined(&client, signer, path, &code)? {
                    Ok(request) => Ok(request),
                    Err(signer) => {
                        // The key is no device of this account: a new key joins.
                        drop(signer);
                        AccountSigner::forget(store)?;
                        let signer = AccountSigner::open_or_create(store)?;
                        match Self::ask(&client, signer, path, &code, &device_name, platform)? {
                            Asked::Waiting(mut request) => {
                                request.new_key = true;
                                Ok(*request)
                            }
                            Asked::KeyUsed(_) => Err(ConnectError::Conflict),
                        }
                    }
                }
            }
        }
    }

    /// `POST /v1/account/devices/join` with the key of `signer`, the checks of the answer,
    /// and the pending join on disk.
    fn ask(
        client: &ConnectClient,
        signer: AccountSigner,
        path: &Path,
        code: &LinkCode,
        device_name: &str,
        platform: &'static str,
    ) -> Result<Asked, ConnectError> {
        let account_id = code.account_id().to_owned();
        let link_hash = code.link_hash();
        let public_key = signer.public_key_b64u();
        // The signature covers the canonical device name; the confirming device signs that
        // name into the device list only when it verifies.
        let signature = encode_b64u(&signer.sign_join(
            client.origin(),
            &account_id,
            &link_hash,
            device_name,
        )?);
        let body = JoinBody {
            account_id: &account_id,
            link_hash: &link_hash,
            device_name,
            platform,
            public_key: &public_key,
            signature: &signature,
        };
        let answer = match twice(|| client.join(&body)) {
            Ok(answer) => answer,
            Err(ConnectError::Conflict) => return Ok(Asked::KeyUsed(signer)),
            Err(error) => return Err(error),
        };
        let confirmer_key = point(&answer.confirmer.public_key).ok_or(ConnectError::BadAnswer)?;
        if answer.account_id != account_id || !valid_device_id(&answer.confirmer.device_id) {
            return Err(ConnectError::BadAnswer);
        }
        let checked = answer
            .device_list
            .first()
            .and_then(|entry| entry.key.as_deref())
            .and_then(point)
            .filter(|root| link_fingerprint(root, &confirmer_key) == code.fingerprint())
            .and_then(|root| {
                trust::verify_list(client.origin(), &account_id, &root, &answer.device_list)
                    .filter(|list| list.live.contains(&confirmer_key))
                    .map(|list| (root, list))
            });
        let Some((root, list)) = checked else {
            // Best effort: the link of the code is used up anyway.
            let _ = cancel_join(client, &signer, &account_id, &link_hash);
            return Err(ConnectError::LinkMismatch);
        };
        let words = safety_words(
            &account_id,
            code.expose(),
            &confirmer_key,
            signer.public_key(),
        );
        let request = Self {
            client: client.clone(),
            path: path.to_owned(),
            signer: Arc::new(signer),
            account_id,
            link_hash,
            device_name: device_name.to_owned(),
            join_id: answer.join_id,
            confirmer_name: clean_name(&answer.confirmer.name)
                .unwrap_or_else(|_| "your other device".to_owned()),
            root,
            confirmer: Some(confirmer_key),
            start: (list.version, list.head().to_owned()),
            words,
            expires_at: answer.expires_at,
            new_key: false,
            clock: system_clock(),
        };
        // A restart, a lock, or a quit while it waits resumes it from here.
        if let Err(error) = request.pending_file().save(path) {
            let _ = cancel_join(
                client,
                &request.signer,
                &request.account_id,
                &request.link_hash,
            );
            return Err(error);
        }
        Ok(Asked::Waiting(Box::new(request)))
    }

    /// The join of a key that Connect says is used: when it is a device of the account of
    /// `code` (a sign-in works) and the device list of the account, verified from the root
    /// that the code names with one of its live devices, holds it, the join goes on from
    /// that list, with the name that the list signed for this key. `Err(signer)` when the
    /// key is no device of that account.
    fn already_joined(
        client: &ConnectClient,
        signer: AccountSigner,
        path: &Path,
        code: &LinkCode,
    ) -> Result<Result<Self, AccountSigner>, ConnectError> {
        let account_id = code.account_id().to_owned();
        let public_key = signer.public_key_b64u();
        let challenge = match client.challenge(&ChallengeRequest {
            account_id: &account_id,
            public_key: &public_key,
        }) {
            Ok(challenge) => challenge,
            Err(
                ConnectError::Unauthenticated
                | ConnectError::JoinPending
                | ConnectError::JoinRefused,
            ) => return Ok(Err(signer)),
            Err(error) => return Err(error),
        };
        let now = system_clock()();
        let (token, _) = match finish_sign_in(client, &signer, &account_id, challenge, None, now) {
            Ok(signed_in) => signed_in,
            Err(ConnectError::Revoked) => return Ok(Err(signer)),
            Err(error) => return Err(error),
        };
        let view = client.account(token.value.as_str())?;
        if view.account_id != account_id {
            return Err(ConnectError::BadAnswer);
        }
        let Some(root) = view
            .device_list
            .first()
            .and_then(|entry| entry.key.as_deref())
            .and_then(point)
        else {
            return Err(ConnectError::BadAnswer);
        };
        let Some(list) = trust::verify_list(client.origin(), &account_id, &root, &view.device_list)
        else {
            return Err(ConnectError::LinkMismatch);
        };
        // The code names the root and one of its live devices.
        let Some(confirmer) = list
            .live
            .iter()
            .find(|key| link_fingerprint(&root, key) == code.fingerprint())
            .cloned()
        else {
            return Err(ConnectError::LinkMismatch);
        };
        let own = signer.public_key().to_vec();
        let Some(name) = list
            .live
            .contains(&own)
            .then(|| list.name_of(&own))
            .flatten()
            .map(str::to_owned)
        else {
            return Ok(Err(signer));
        };
        let confirmer_name = list
            .name_of(&confirmer)
            .unwrap_or("your other device")
            .to_owned();
        Ok(Ok(Self {
            client: client.clone(),
            path: path.to_owned(),
            signer: Arc::new(signer),
            account_id,
            link_hash: code.link_hash(),
            device_name: name,
            join_id: 0,
            confirmer_name,
            root,
            confirmer: None,
            start: (list.version, list.head().to_owned()),
            words: String::new(),
            expires_at: 0,
            new_key: false,
            clock: system_clock(),
        }))
    }

    /// The join of this device that waits on disk next to `path`, with its key from
    /// `store`: a restart, a lock, or a quit came while it waited. `None` without one, with
    /// an account file, or when the key of the store is not the key of the join (the file
    /// goes).
    pub fn resume(store: &dyn DeviceKeyStore, path: &Path) -> Result<Option<Self>, ConnectError> {
        if AccountState::load(path)?.is_some() {
            return Ok(None);
        }
        let Some(pending) = PendingJoinFile::load(path) else {
            return Ok(None);
        };
        let client = ConnectClient::new(&pending.origin)?;
        let signer = match AccountSigner::open(store)? {
            Some(signer) if signer.public_key_b64u() == pending.public_key => signer,
            _ => {
                PendingJoinFile::remove(path);
                return Ok(None);
            }
        };
        let (Some(root), Some(confirmer)) = (point(&pending.root), point(&pending.confirmer))
        else {
            PendingJoinFile::remove(path);
            return Ok(None);
        };
        Ok(Some(Self {
            client,
            path: path.to_owned(),
            signer: Arc::new(signer),
            account_id: pending.account_id,
            link_hash: pending.link_hash,
            device_name: pending.device_name,
            join_id: pending.join_id,
            confirmer_name: pending.confirmer_name,
            root,
            confirmer: Some(confirmer),
            start: (pending.list_version, pending.list_head),
            words: pending.words,
            expires_at: pending.expires_at,
            new_key: false,
            clock: system_clock(),
        }))
    }

    fn pending_file(&self) -> PendingJoinFile {
        PendingJoinFile {
            v: STATE_VERSION,
            origin: self.client.origin().to_owned(),
            account_id: self.account_id.clone(),
            link_hash: self.link_hash.clone(),
            device_name: self.device_name.clone(),
            public_key: self.signer.public_key_b64u(),
            join_id: self.join_id,
            confirmer_name: self.confirmer_name.clone(),
            confirmer: self
                .confirmer
                .as_deref()
                .map(encode_b64u)
                .unwrap_or_default(),
            root: encode_b64u(&self.root),
            list_version: self.start.0,
            list_head: self.start.1.clone(),
            words: self.words.clone(),
            expires_at: self.expires_at,
        }
    }

    /// Use `clock` for every time of this join (tests).
    pub fn set_clock(&mut self, clock: Clock) {
        self.clock = clock;
    }

    /// The six safety words that this Mac shows; empty when this device's key is in the
    /// account already (nothing to compare: the next poll finishes the join).
    pub fn words(&self) -> &str {
        &self.words
    }

    /// The name of the device that confirms.
    pub fn confirmer_name(&self) -> &str {
        &self.confirmer_name
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn join_id(&self) -> u64 {
        self.join_id
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Whether this device made a new account key for this join, because its earlier key
    /// was used by a join that did not finish on it. The device of that key stays in the
    /// account until a device of the account removes it.
    pub fn made_new_key(&self) -> bool {
        self.new_key
    }

    /// Whether this device's key is in the account already: the next poll finishes the
    /// join, with no words to compare.
    pub fn already_in_account(&self) -> bool {
        self.confirmer.is_none()
    }

    /// Ask whether the other device confirmed: `403 join_pending` waits, `403
    /// join_refused` ends, a nonce means confirmed, and this Mac signs in, reads the
    /// account, and writes the account file with the root of the code pinned and the
    /// device list that it verified: a list that goes on from the list of the join answer
    /// and holds this Mac's own `add`, made by the confirming device that the code named,
    /// with the link of the code, and with the device name that this Mac asked for. Any
    /// other list (an older one, one without that entry, or one whose entry names this Mac
    /// otherwise) is [`ConnectError::LinkMismatch`], and no account file is written. A token call
    /// refused with `401` or `503`, or a read of the account that fails on the way, waits
    /// for the next poll. A key that Connect does not know any more (`401` at the
    /// challenge: the join was cancelled or pruned) ends the join as refused. The pending
    /// join on disk goes when the join ends.
    pub fn poll(&mut self) -> Result<JoinPoll, ConnectError> {
        let polled = self.poll_once();
        if matches!(
            polled,
            Ok(JoinPoll::Refused | JoinPoll::Confirmed(_)) | Err(ConnectError::LinkMismatch)
        ) {
            PendingJoinFile::remove(&self.path);
        }
        polled
    }

    fn poll_once(&mut self) -> Result<JoinPoll, ConnectError> {
        let public_key = self.signer.public_key_b64u();
        let account_id = self.account_id.clone();
        let challenge = match self.client.challenge(&ChallengeRequest {
            account_id: &account_id,
            public_key: &public_key,
        }) {
            Ok(challenge) => challenge,
            Err(ConnectError::JoinPending) => return Ok(JoinPoll::Waiting),
            Err(ConnectError::JoinRefused | ConnectError::Unauthenticated) => {
                return Ok(JoinPoll::Refused);
            }
            Err(error) => return Err(error),
        };
        let now = (self.clock)();
        let (token, device_id) = match finish_sign_in(
            &self.client,
            &self.signer,
            &account_id,
            challenge,
            None,
            now,
        ) {
            Ok(signed_in) => signed_in,
            Err(error) if next_round(&error) => return Ok(JoinPoll::Waiting),
            Err(error) => return Err(error),
        };
        let view = match self.client.account(token.value.as_str()) {
            Ok(view) if view.account_id == account_id => view,
            Ok(_) => return Err(ConnectError::BadAnswer),
            Err(
                ConnectError::Offline
                | ConnectError::Broken
                | ConnectError::Unauthenticated
                | ConnectError::Refused { status: 503, .. },
            ) => return Ok(JoinPoll::Waiting),
            Err(error) => return Err(error),
        };
        let start = Pin {
            version: self.start.0,
            head: &self.start.1,
        };
        let own = self.signer.public_key();
        let list = trust::verify_list(
            self.client.origin(),
            &account_id,
            &self.root,
            &view.device_list,
        )
        .filter(|list| start.accepts(list))
        .filter(|list| match &self.confirmer {
            Some(confirmer) => list.added(own, confirmer, &self.link_hash),
            // A key in the account already: its `add` precedes the list of the start.
            None => list.live.iter().any(|key| key.as_slice() == own),
        })
        .filter(|list| list.name_of(own) == Some(self.device_name.as_str()))
        .ok_or(ConnectError::LinkMismatch)?;
        let state = AccountState {
            v: STATE_VERSION,
            origin: self.client.origin().to_owned(),
            account_id,
            device_id,
            name: clean_name(&view.name).ok(),
            device_name: self.device_name.clone(),
            public_key,
            created_at: now,
            root: encode_b64u(&self.root),
            list_version: list.version,
            list_head: list.head().to_owned(),
            known: list.live.iter().map(|key| encode_b64u(key)).collect(),
            // The keys that the list removed before this device joined: each signs only
            // what a live device vouches for (`crate::sync::SignerPolicy`).
            left: list
                .removed
                .iter()
                .rev()
                .take(MAX_LEFT)
                .rev()
                .filter(|key| !list.live.contains(key))
                .map(|key| encode_b64u(key))
                .collect(),
            recovery_unseen: false,
            peers: Vec::new(),
            stores: Vec::new(),
        };
        // The peers and shared stores of the list that this device pinned (section 16):
        // a second device of a person needs no ceremony.
        let mut state = state;
        share::learn_own(&mut state, &list.shares);
        state.save(&self.path)?;
        let mut account = ConnectAccount::build(
            self.client.clone(),
            state,
            &self.path,
            Arc::clone(&self.signer),
        );
        account.clock = Arc::clone(&self.clock);
        account.token = Some(token);
        account.list = Some(list);
        Ok(JoinPoll::Confirmed(Box::new(account)))
    }

    /// Cancel before the confirmation, with the signature of this Mac's key. The pending
    /// join on disk goes when Connect took the cancel; after any other answer it stays, so a
    /// confirmation that came first still ends with this device in the account at the
    /// next resume ([`Self::resume`]).
    pub fn cancel(self) -> Result<(), ConnectError> {
        if self.confirmer.is_none() {
            return Ok(());
        }
        let cancelled = cancel_join(
            &self.client,
            &self.signer,
            &self.account_id,
            &self.link_hash,
        )?;
        if cancelled != self.join_id {
            return Err(ConnectError::BadAnswer);
        }
        PendingJoinFile::remove(&self.path);
        Ok(())
    }
}

/// What a join request of one key got.
enum Asked {
    Waiting(Box<JoinRequest>),
    /// `409 conflict`: the key is or was a device of an account.
    KeyUsed(AccountSigner),
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str =
        "BOpHkB5VvTHXawpUXZxgu44Q97I2bzq9G_uI6tFM9mj8De047e1fNWI8MIERDsaxhBC0ih1DPfXaM4mdBbExjrA";

    fn state() -> AccountState {
        AccountState {
            v: 4,
            origin: "https://connect.example.test".to_owned(),
            account_id: "acc_k7m2q4x3ca".to_owned(),
            device_id: "dev_m2k7q3x4ab".to_owned(),
            name: Some("Rafal".to_owned()),
            device_name: "MacBook Pro".to_owned(),
            public_key: KEY.to_owned(),
            created_at: 1_790_000_000,
            root: KEY.to_owned(),
            list_version: 1,
            list_head: trust::root_hash(
                "https://connect.example.test",
                "acc_k7m2q4x3ca",
                &point(KEY).unwrap(),
                "MacBook Pro",
            ),
            known: vec![KEY.to_owned()],
            left: Vec::new(),
            recovery_unseen: false,
            peers: Vec::new(),
            stores: Vec::new(),
        }
    }

    #[test]
    fn an_account_file_without_a_pinned_list_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = account_file(dir.path());
        state().save(&path).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        // The earlier version: a trust store of chains, no pinned list.
        let object = value.as_object_mut().unwrap();
        object.insert("v".to_owned(), serde_json::json!(2));
        for field in ["list_version", "list_head", "left"] {
            object.remove(field);
        }
        object.insert("revoked".to_owned(), serde_json::json!([]));
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        // A file of an earlier version: this device joins its account again after the
        // owner forgets it here; a creation or a join says so.
        assert_eq!(
            AccountState::load(&path).unwrap_err(),
            ConnectError::OldAccountFile
        );
        assert!(is_old_account_file(&path));
        // A file of this version with a bad shape cannot be read either: the owner forgets
        // it here too.
        fs::write(&path, b"{\"v\":4}").unwrap();
        assert_eq!(AccountState::load(&path).unwrap_err(), ConnectError::Local);
        assert!(is_old_account_file(&path));
        // A file that loads is not one.
        state().save(&path).unwrap();
        assert!(!is_old_account_file(&path));
        // A key of the trust store that is not a point of the curve is refused too.
        let mut off = vec![4u8];
        off.extend_from_slice(&[9; 64]);
        for bad in [
            AccountState {
                root: encode_b64u(&off),
                ..state()
            },
            AccountState {
                known: vec![encode_b64u(&off)],
                ..state()
            },
            AccountState {
                left: vec![KEY.to_owned(); MAX_LEFT + 1],
                ..state()
            },
            AccountState {
                list_version: 0,
                ..state()
            },
            AccountState {
                list_head: "short".to_owned(),
                ..state()
            },
        ] {
            assert_eq!(bad.save(&path).unwrap_err(), ConnectError::Invalid);
        }
    }

    /// F6: a file of the first build of version 4 holds keys in the ended accounts of a
    /// store: they go at the load, the file is written back, and it loads as it is then.
    #[test]
    fn a_first_pass_file_with_keys_in_ended_moves_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = account_file(dir.path());
        let mut first = state();
        first.stores = vec![StoreShare {
            team_id: "t_7k2m5q4x3c".to_owned(),
            owner: share::OWNER_SELF.to_owned(),
            members: vec!["acc_m3n5p7q2rb".to_owned()],
            ended: vec!["acc_p4n6r2t7bc".to_owned()],
        }];
        first.save(&path).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["stores"][0]["ended"] = serde_json::json!(["acc_p4n6r2t7bc", KEY]);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let loaded = AccountState::load(&path).unwrap().unwrap();
        assert_eq!(loaded.stores[0].ended, vec!["acc_p4n6r2t7bc".to_owned()]);
        assert_eq!(loaded, first);
        // Written back: the file itself holds no key in `ended` any more.
        let again: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            again["stores"][0]["ended"],
            serde_json::json!(["acc_p4n6r2t7bc"])
        );
        assert!(!is_old_account_file(&path));
    }

    #[test]
    fn the_account_file_is_private_and_strict() {
        let dir = tempfile::tempdir().unwrap();
        let path = account_file(dir.path());
        assert_eq!(AccountState::load(&path).unwrap(), None);
        state().save(&path).unwrap();
        assert_eq!(AccountState::load(&path).unwrap(), Some(state()));
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let dir_meta = fs::metadata(path.parent().unwrap()).unwrap();
        assert_eq!(dir_meta.permissions().mode() & 0o777, 0o700);
        // A file that others can read is refused, and so is an unknown field.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(AccountState::load(&path).unwrap_err(), ConnectError::Local);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["token"] = serde_json::json!("apassy_act_x");
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(AccountState::load(&path).unwrap_err(), ConnectError::Local);
        // A bad shape is never written.
        let bad = AccountState {
            account_id: "acc_bad".to_owned(),
            ..state()
        };
        assert_eq!(bad.save(&path).unwrap_err(), ConnectError::Invalid);
    }

    #[test]
    fn a_token_names_its_account() {
        let secret = "ef".repeat(32);
        assert!(valid_token(
            &format!("apassy_act_acc_k7m2q4x3ca_{secret}"),
            "acc_k7m2q4x3ca"
        ));
        assert!(!valid_token(
            &format!("apassy_act_acc_m3n5p7q2rb_{secret}"),
            "acc_k7m2q4x3ca"
        ));
        assert!(!valid_token(
            &format!("apassy_acc_acc_k7m2q4x3ca_{secret}"),
            "acc_k7m2q4x3ca"
        ));
        assert!(!valid_token(
            "apassy_act_acc_k7m2q4x3ca_ef",
            "acc_k7m2q4x3ca"
        ));
    }

    #[test]
    fn only_stripe_pages_open_for_checkout_and_the_portal() {
        assert!(stripe_page(
            "https://checkout.stripe.com/c/pay/cs_test_a1",
            CHECKOUT_ORIGIN
        ));
        assert!(stripe_page(
            "https://billing.stripe.com/p/session/test_a1",
            PORTAL_ORIGIN
        ));
        for bad in [
            "https://checkout.stripe.com/",
            "https://checkout.stripe.com.evil.example/c/pay/cs_1",
            "https://evil.example/c/pay/cs_1",
            "http://checkout.stripe.com/c/pay/cs_1",
            "https://checkout.stripe.com@evil.example/c/pay/cs_1",
            "https://billing.stripe.com/p/session/test_a1",
            "https://checkout.stripe.com/c/pay/cs 1",
            "http://127.0.0.1:4242/c/pay/cs_1",
        ] {
            assert!(!stripe_page(bad, CHECKOUT_ORIGIN), "{bad}");
        }
        assert!(!stripe_page(
            "https://checkout.stripe.com/c/pay/cs_1",
            PORTAL_ORIGIN
        ));
    }

    #[test]
    fn names_are_trimmed_and_bounded() {
        assert_eq!(clean_name("  MacBook Pro ").unwrap(), "MacBook Pro");
        assert!(clean_name("   ").is_err());
        assert!(clean_name(&"a".repeat(65)).is_err());
        assert!(clean_name("Mac\u{7}").is_err());
        // The same canonical form as Connect's (`apassy_relay::device::canonical_name`):
        // bytes, not characters, count; NUL and other control characters never pass; the
        // placeholder `-` of the device-list message is never a name.
        let zoe = "Zoë’s iPhone";
        assert_eq!(clean_name(&format!("\t {zoe} \n")).unwrap(), zoe);
        let at_limit = format!("{}é", "a".repeat(62));
        assert_eq!(at_limit.len(), 64);
        assert_eq!(clean_name(&format!(" {at_limit} ")).unwrap(), at_limit);
        let over = format!("{}é", "a".repeat(63));
        assert_eq!(over.len(), 65);
        assert!(clean_name(&over).is_err());
        assert!(clean_name("Mac\u{0}mini").is_err());
        assert!(clean_name("-").is_err());
        assert!(clean_name(" - ").is_err());
        assert_eq!(clean_name("-Mac-").unwrap(), "-Mac-");
        assert!(trust::valid_name(zoe) && !trust::valid_name(" Mac") && !trust::valid_name("-"));
    }
}
