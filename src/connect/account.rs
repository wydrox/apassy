//! The Apassy Connect account of this Mac (contract connect-account-v1 sections 6 to 10,
//! plan s7 unit M1).
//!
//! - [`ConnectAccount::create`]: a new account with the account device key and a
//!   recovery code that the Mac shows once and never stores.
//! - Sign-in: `POST /v1/account/challenge`, the origin check, `POST /v1/account/token`.
//!   The account token lives at most 15 minutes, in memory only (`Zeroizing`), and goes
//!   only to the Connect origin of the account ([`ConnectAccount::with_token`]: the
//!   client of that origin is the only thing that gets it). A `401` after a fresh sign-in,
//!   or a challenge refused with `401`, is [`ConnectError::Revoked`]: the token is dropped
//!   at once.
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
//! public key, and the creation time. It holds no private key, no token, no email, no
//! link code, and no recovery code.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::client::{
    AccountDeleted, AccountView, Challenge, ChallengeRequest, CheckoutAnswer, CheckoutRequest,
    ConnectClient, CreateAccount, DeviceView, GroupDetail, GroupJoined, GroupMember, InviteAnswer,
    JoinBody, MemberRemoved, PlanView, PortalAnswer, RecoverBody, RevokeAnswer, SeatsAnswer,
    StoreDevice, TokenRequest, VaultStoreView,
};
use super::device_key::{AccountSigner, DeviceKeyStore};
use super::entitlement::Entitlement;
use super::words::{
    LinkCode, RecoveryCode, safety_words, valid_account_id, valid_device_id, valid_group_id,
};
use super::{ConnectError, PLATFORM};
use crate::broker::approvals::{ConnectGroupChange, OwnerAction, OwnerProof};
use crate::sync::{decode_b64u, encode_b64u};
use crate::vault::{Vault, VaultResult};

/// The longest life of an account token on this Mac (section 3), whatever Connect says.
pub const TOKEN_SECONDS: u64 = 900;
/// A token is renewed when it has less than this left.
const TOKEN_MARGIN: u64 = 60;
/// The version of the account file.
const STATE_VERSION: u8 = 1;
/// The longest account file that is read.
const MAX_STATE_BYTES: u64 = 16 * 1024;
/// A person's name or a device name: 1 to 64 bytes (section 2).
const MAX_NAME_BYTES: usize = 64;

/// The time source: Unix seconds. Tests move it.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    })
}

/// The account file in `data_dir` (`crate::paths::data_dir()` in the app).
pub fn account_file(data_dir: &Path) -> PathBuf {
    data_dir.join("connect").join("account.json")
}

/// A name of section 2: trimmed, 1 to 64 bytes of UTF-8, no control character.
fn clean_name(text: &str) -> Result<String, ConnectError> {
    let name = text.trim();
    if name.is_empty() || name.len() > MAX_NAME_BYTES || name.chars().any(char::is_control) {
        return Err(ConnectError::Invalid);
    }
    Ok(name.to_owned())
}

/// A P-256 public key in X9.63 form from its b64u.
fn point(b64u: &str) -> Option<Vec<u8>> {
    decode_b64u(b64u).filter(|key| key.len() == 65 && key[0] == 0x04)
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
}

impl AccountState {
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
        let state: Self = serde_json::from_slice(&text).map_err(|_| ConnectError::Local)?;
        if state.is_valid() {
            Ok(Some(state))
        } else {
            Err(ConnectError::Local)
        }
    }

    /// Write the file at `path` with mode 0600, in a 0700 directory, through a temporary
    /// file and a rename.
    fn save(&self, path: &Path) -> Result<(), ConnectError> {
        if !self.is_valid() {
            return Err(ConnectError::Invalid);
        }
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
        let text = serde_json::to_vec_pretty(self).map_err(|_| ConnectError::Local)?;
        let temporary = path.with_extension("json.new");
        let _ = fs::remove_file(&temporary);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| ConnectError::Local)?;
        file.write_all(&text)
            .and_then(|()| file.sync_all())
            .map_err(|_| ConnectError::Local)?;
        drop(file);
        fs::rename(&temporary, path).map_err(|_| ConnectError::Local)
    }
}

/// The proof that this Mac is no longer a device of its account: it forgot the account
/// ([`forget_this_device`], also after a revoke of this Mac or a deletion), or Connect
/// answered a fresh sign-in with `401` ([`ConnectError::Revoked`]). Only it lets
/// [`drop_account_rows`] remove every vault row of the account key: a missing or
/// unreadable account file never does (B-L2).
#[derive(Debug)]
pub struct Forgotten(());

impl Forgotten {
    /// The proof from a confirmed `401` of Connect: `Some` only for
    /// [`ConnectError::Revoked`] (a second `401` after a fresh sign-in, or a refused
    /// challenge).
    pub fn revoked(error: &ConnectError) -> Option<Self> {
        (*error == ConnectError::Revoked).then_some(Self(()))
    }
}

/// Forget the account on this Mac: the account file and the account device key go.
/// Connect is not asked (a revoked or deleted device cannot ask). The vault rows that
/// signed with the key go with [`drop_account_rows`] and the returned proof, when each
/// vault is open.
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
/// sign-in of a join). Returns the token and the device id.
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
    let answer = match client.token(&TokenRequest {
        account_id,
        public_key: &public_key,
        nonce: &challenge.nonce,
        signature: &signature,
    }) {
        Ok(answer) => answer,
        Err(ConnectError::Unauthenticated) => return Err(ConnectError::Revoked),
        Err(error) => return Err(error),
    };
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
    /// Connect confirmed that this Mac is no longer a device of the account: every later
    /// call is [`ConnectError::Revoked`], also without the key in memory.
    revoked: bool,
    clock: Clock,
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
            clock: system_clock(),
        }
    }

    /// Make a new account at `client` with the account device key of this Mac (made now
    /// if this Mac has none) and a new recovery code, and write the account file at
    /// `path`. The recovery code comes back once: show it as 16 words with "Save it in
    /// another password manager"; Apassy never stores it. The first sign-in happens at
    /// the first call that needs the token.
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
        let recovery = RecoveryCode::generate()?;
        let recovery_hash = recovery.hash();
        let public_key = signer.public_key_b64u();
        let signature = encode_b64u(&signer.sign_account(client.origin())?);
        let body = CreateAccount {
            name: &name,
            device_name: &device_name,
            platform: PLATFORM,
            public_key: &public_key,
            recovery_hash: &recovery_hash,
            signature: &signature,
        };
        let created = twice(|| client.create_account(&body))?;
        if !valid_account_id(&created.account_id) || !valid_device_id(&created.device_id) {
            return Err(ConnectError::BadAnswer);
        }
        let state = AccountState {
            v: STATE_VERSION,
            origin: client.origin().to_owned(),
            account_id: created.account_id,
            device_id: created.device_id,
            name: Some(name),
            device_name,
            public_key,
            created_at: created.created_at,
        };
        state.save(path)?;
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
    /// device with its account key, every vault store of the account is deleted at
    /// Connect, and a new recovery code replaces the old one. The new code comes back
    /// once, with the number of deleted stores.
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
        let new_hash = new.hash();
        let old_wire = old.wire();
        let public_key = signer.public_key_b64u();
        let signature = encode_b64u(&signer.sign_recover(client.origin(), account_id)?);
        let body = RecoverBody {
            account_id,
            recovery: &old_wire,
            device_name: &device_name,
            platform: PLATFORM,
            public_key: &public_key,
            recovery_hash: &new_hash,
            signature: &signature,
        };
        let answer = client.recover(&body)?;
        if answer.account_id != account_id || !valid_device_id(&answer.device_id) {
            return Err(ConnectError::BadAnswer);
        }
        let mut account = Self::build(
            client,
            AccountState {
                v: STATE_VERSION,
                origin: String::new(),
                account_id: answer.account_id,
                device_id: answer.device_id,
                name: None,
                device_name,
                public_key,
                created_at: 0,
            },
            path,
            Arc::new(signer),
        );
        account.state.origin = account.client.origin().to_owned();
        account.state.created_at = account.now();
        account.state.save(path)?;
        Ok((account, new, answer.deleted_stores))
    }

    /// Use `clock` for every time of this account (tests).
    pub fn set_clock(&mut self, clock: Clock) {
        self.clock = clock;
    }

    fn now(&self) -> u64 {
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

    /// Drop everything from memory after Connect confirmed the revoke: [`Self::sign_out`],
    /// and every later call is [`ConnectError::Revoked`].
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
    fn own_public_key(&self) -> Vec<u8> {
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

    /// Sign in now: a challenge, the origin check, the signature, the token. A key that
    /// Connect does not know any more is [`ConnectError::Revoked`] and drops the token.
    pub fn sign_in(&mut self) -> Result<(), ConnectError> {
        self.token = None;
        let signer = self.signer()?;
        let public_key = signer.public_key_b64u();
        let challenge = match self.client.challenge(&ChallengeRequest {
            account_id: &self.state.account_id,
            public_key: &public_key,
        }) {
            Ok(challenge) => challenge,
            Err(ConnectError::Unauthenticated) => return Err(self.revoked()),
            Err(error) => return Err(error),
        };
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
                Ok(())
            }
            Err(ConnectError::Revoked) => Err(self.revoked()),
            Err(error) => Err(error),
        }
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
    /// a second `401` is [`ConnectError::Revoked`] and drops the token.
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
            Err(ConnectError::Unauthenticated) => Err(self.revoked()),
            other => other,
        }
    }

    /// `GET /v1/account`: the account, its plan, its devices, its group. The Mac polls
    /// it every 3 s while the checkout sheet is open (M2). The name of the person goes
    /// into the account file when this Mac did not know it; the email never does.
    pub fn view(&mut self) -> Result<AccountView, ConnectError> {
        let view = self.with_token(|client, token| client.account(token))?;
        if view.account_id != self.state.account_id {
            return Err(ConnectError::BadAnswer);
        }
        if self.state.name.is_none()
            && let Ok(name) = clean_name(&view.name)
        {
            self.state.name = Some(name);
            self.state.save(&self.path)?;
        }
        Ok(view)
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

    // ---- Devices (section 7). ----

    /// "Add a device…": a new link code in memory and its hash at Connect. The link works
    /// once and for 10 minutes.
    pub fn start_link(&mut self) -> Result<DeviceLink, ConnectError> {
        let code = LinkCode::generate(&self.state.account_id)?;
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
    /// 5 s while the sheet is open. An entry with a bad key is left out.
    pub fn pending_joins(&mut self, link: &DeviceLink) -> Result<Vec<PendingJoin>, ConnectError> {
        let pending = self.with_token(|client, token| client.pending(token))?;
        let own_key = self.own_public_key();
        Ok(pending
            .into_iter()
            .filter(|join| join.link_id == link.link_id)
            .filter_map(|join| {
                let public_key = point(&join.public_key)?;
                let device_name = clean_name(&join.device_name).ok()?;
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
                    words,
                    created_at: join.created_at,
                    expires_at: join.expires_at,
                })
            })
            .collect())
    }

    /// Confirm `join` of `link` after a fresh owner check for
    /// [`PendingJoin::owner_action`] in the vault session `epoch`: Connect adds exactly
    /// the key for which this Mac computed the words. The words are computed again from
    /// the code and the key, so a changed entry is [`ConnectError::WordsMismatch`] and
    /// nothing is sent. The proof is used up, also when the call fails.
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
        proof
            .check(&join.owner_action(&self.state.account_id), epoch)
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        let public_key = encode_b64u(&join.public_key);
        let device =
            self.with_token(|client, token| client.confirm(token, join.join_id, &public_key))?;
        if device.public_key != public_key || !valid_device_id(&device.device_id) {
            return Err(ConnectError::BadAnswer);
        }
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

    /// The owner action of the revoke of `device`.
    pub fn revoke_action(&self, device: &DeviceView) -> OwnerAction {
        OwnerAction::RevokeConnectDevice {
            account_id: self.state.account_id.clone(),
            device_id: device.device_id.clone(),
            device_name: device.name.clone(),
        }
    }

    /// Revoke `device` (section 7.4) after a fresh owner check for
    /// [`Self::revoke_action`] in the vault session `epoch`. This Mac may revoke itself
    /// ("Forget this device"): its token goes, and the caller runs
    /// [`forget_this_device`] and [`drop_account_rows`]. The proof is used up, also when
    /// the call fails.
    pub fn revoke(
        &mut self,
        device: &DeviceView,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<RevokeOutcome, ConnectError> {
        proof
            .check(&self.revoke_action(device), epoch)
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        let answer = self.with_token(|client, token| client.revoke(token, &device.device_id))?;
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
    /// store device 1. The same vault again answers the existing store.
    pub fn create_vault_store(
        &mut self,
        vault_id: &str,
        name: &str,
    ) -> Result<VaultStoreView, ConnectError> {
        if !crate::sync::relay_crypto::valid_vault_id(vault_id) {
            return Err(ConnectError::Invalid);
        }
        let name = clean_name(name)?;
        let store =
            self.with_token(|client, token| client.create_vault_store(token, vault_id, &name))?;
        if store.vault_id != vault_id || !crate::sync::relay_crypto::valid_team_id(&store.team_id) {
            return Err(ConnectError::BadAnswer);
        }
        Ok(store)
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

    /// `POST /v1/account/vaults/{team_id}/devices`: add another live device of the
    /// account (or of the group) to a store this Mac is in, after a fresh owner check
    /// for [`Self::add_store_device_action`] in the vault session `epoch`: the device can
    /// then read and write the relay copy. The proof is used up, also when the call
    /// fails. An answer for another device or account is [`ConnectError::BadAnswer`].
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
        let added =
            self.with_token(|client, token| client.add_store_device(token, team_id, device_id))?;
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
    /// live device of this account is [`ConnectError::NotInGroup`] before any call; a
    /// member of a group goes through the link of relay-sync-v1 section 7 or
    /// [`Self::add_store_device`] with the owner check.
    pub(crate) fn register_own_store_device(
        &mut self,
        team_id: &str,
        device_id: &str,
        live: &[DeviceView],
    ) -> Result<StoreDevice, ConnectError> {
        if device_id == self.state.device_id || !live.iter().any(|d| d.device_id == device_id) {
            return Err(ConnectError::NotInGroup);
        }
        let account_id = self.state.account_id.clone();
        let added =
            self.with_token(|client, token| client.add_store_device(token, team_id, device_id))?;
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
    /// nothing. A URL that is not `https://` is [`ConnectError::BadAnswer`]. No owner
    /// check: a checkout gives no authority over a vault or a device.
    pub fn checkout(&mut self, request: &CheckoutRequest) -> Result<CheckoutAnswer, ConnectError> {
        if !valid_checkout(request) {
            return Err(ConnectError::Invalid);
        }
        let answer = self.with_token(|client, token| client.checkout(token, request))?;
        if !browser_url(&answer.url) || answer.session_id.trim().is_empty() {
            return Err(ConnectError::BadAnswer);
        }
        Ok(answer)
    }

    /// `POST /v1/account/portal` (section 5): the Stripe Customer Portal of the account
    /// that pays. It needs no owner check (section 5): the portal changes nothing in
    /// Apassy, and Stripe confirms its own changes.
    pub fn portal(&mut self) -> Result<PortalAnswer, ConnectError> {
        let answer = self.with_token(|client, token| client.portal(token))?;
        if !browser_url(&answer.url) {
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

/// A URL that the Mac opens in the default browser: `https://`, a host, and no space or
/// control character. Connect sends the Checkout, Portal, and invite URLs.
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
pub struct JoinRequest {
    client: ConnectClient,
    path: PathBuf,
    signer: Arc<AccountSigner>,
    code: LinkCode,
    device_name: String,
    join_id: u64,
    confirmer_name: String,
    words: String,
    expires_at: u64,
    clock: Clock,
}

impl fmt::Debug for JoinRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinRequest")
            .field("account_id", &self.code.account_id())
            .field("join_id", &self.join_id)
            .field("words", &self.words)
            .finish_non_exhaustive()
    }
}

impl JoinRequest {
    /// Ask to join with the pasted or scanned `code`: the account device key of this Mac
    /// (made now if this Mac has none) signs the join, and the safety words come from the
    /// key of the confirming device. Show: `Waiting for <confirmer>… Both devices show:
    /// <words>.`
    pub fn start(
        client: ConnectClient,
        store: &dyn DeviceKeyStore,
        path: &Path,
        code: &str,
        device_name: &str,
    ) -> Result<Self, ConnectError> {
        if AccountState::load(path)?.is_some() {
            return Err(ConnectError::AccountExists);
        }
        let code = LinkCode::parse(code).ok_or(ConnectError::Invalid)?;
        let device_name = clean_name(device_name)?;
        let signer = AccountSigner::open_or_create(store)?;
        let account_id = code.account_id().to_owned();
        let link_hash = code.link_hash();
        let public_key = signer.public_key_b64u();
        let signature = encode_b64u(&signer.sign_join(client.origin(), &account_id, &link_hash)?);
        let body = JoinBody {
            account_id: &account_id,
            link_hash: &link_hash,
            device_name: &device_name,
            platform: PLATFORM,
            public_key: &public_key,
            signature: &signature,
        };
        let answer = twice(|| client.join(&body))?;
        let confirmer_key = point(&answer.confirmer.public_key).ok_or(ConnectError::BadAnswer)?;
        if answer.account_id != account_id || !valid_device_id(&answer.confirmer.device_id) {
            return Err(ConnectError::BadAnswer);
        }
        let words = safety_words(
            &account_id,
            code.expose(),
            &confirmer_key,
            signer.public_key(),
        );
        Ok(Self {
            client,
            path: path.to_owned(),
            signer: Arc::new(signer),
            code,
            device_name,
            join_id: answer.join_id,
            confirmer_name: clean_name(&answer.confirmer.name)
                .unwrap_or_else(|_| "your other device".to_owned()),
            words,
            expires_at: answer.expires_at,
            clock: system_clock(),
        })
    }

    /// Use `clock` for every time of this join (tests).
    pub fn set_clock(&mut self, clock: Clock) {
        self.clock = clock;
    }

    /// The six safety words that this Mac shows.
    pub fn words(&self) -> &str {
        &self.words
    }

    /// The name of the device that confirms.
    pub fn confirmer_name(&self) -> &str {
        &self.confirmer_name
    }

    pub fn account_id(&self) -> &str {
        self.code.account_id()
    }

    pub fn join_id(&self) -> u64 {
        self.join_id
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Ask whether the other device confirmed: `403 join_pending` waits, `403
    /// join_refused` ends, a nonce means confirmed, and this Mac signs in and writes the
    /// account file.
    pub fn poll(&mut self) -> Result<JoinPoll, ConnectError> {
        let public_key = self.signer.public_key_b64u();
        let account_id = self.code.account_id().to_owned();
        let challenge = match self.client.challenge(&ChallengeRequest {
            account_id: &account_id,
            public_key: &public_key,
        }) {
            Ok(challenge) => challenge,
            Err(ConnectError::JoinPending) => return Ok(JoinPoll::Waiting),
            Err(ConnectError::JoinRefused) => return Ok(JoinPoll::Refused),
            Err(error) => return Err(error),
        };
        let now = (self.clock)();
        let (token, device_id) = finish_sign_in(
            &self.client,
            &self.signer,
            &account_id,
            challenge,
            None,
            now,
        )?;
        let state = AccountState {
            v: STATE_VERSION,
            origin: self.client.origin().to_owned(),
            account_id,
            device_id,
            name: None,
            device_name: self.device_name.clone(),
            public_key,
            created_at: now,
        };
        state.save(&self.path)?;
        let mut account = ConnectAccount::build(
            self.client.clone(),
            state,
            &self.path,
            Arc::clone(&self.signer),
        );
        account.clock = Arc::clone(&self.clock);
        account.token = Some(token);
        // The person's name for the account file; the join is done without it.
        let _ = account.view();
        Ok(JoinPoll::Confirmed(Box::new(account)))
    }

    /// Cancel before the confirmation.
    pub fn cancel(self) -> Result<(), ConnectError> {
        let public_key = self.signer.public_key_b64u();
        let answer =
            self.client
                .cancel_join(self.code.account_id(), &self.code.link_hash(), &public_key)?;
        if answer.join_id != self.join_id {
            return Err(ConnectError::BadAnswer);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> AccountState {
        AccountState {
            v: 1,
            origin: "https://connect.example.test".to_owned(),
            account_id: "acc_k7m2q4x3ca".to_owned(),
            device_id: "dev_m2k7q3x4ab".to_owned(),
            name: Some("Rafal".to_owned()),
            device_name: "MacBook Pro".to_owned(),
            public_key: "BOpHkB5VvTHXawpUXZxgu44Q97I2bzq9G_uI6tFM9mj8De047e1fNWI8MIERDsaxhBC0ih1DPfXaM4mdBbExjrA".to_owned(),
            created_at: 1_790_000_000,
        }
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
    fn names_are_trimmed_and_bounded() {
        assert_eq!(clean_name("  MacBook Pro ").unwrap(), "MacBook Pro");
        assert!(clean_name("   ").is_err());
        assert!(clean_name(&"a".repeat(65)).is_err());
        assert!(clean_name("Mac\u{7}").is_err());
    }
}
