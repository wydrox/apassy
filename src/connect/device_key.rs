//! The account device key of this Mac (contract connect-account-v1 section 5, plan s7
//! decision 2, plan 0035 I-1).
//!
//! One P-256 key for each physical device, made on the device and kept outside every
//! vault: one key for all vaults of this Mac. On the Mac it is a Keychain generic
//! password, account [`KEYCHAIN_ACCOUNT`], through the signed helper
//! ([`NativeHelper::keychain_store`]: this device only, not synchronizable, behind Touch
//! ID with the current fingerprints), the pattern of `src/node/master_key.rs`. The item
//! holds the PKCS#8 document of `ring`; Apassy reads it once with Touch ID and keeps the
//! [`AccountSigner`] in memory, erased on drop. It never goes into a vault, a file, a
//! log, or a request: Connect sees only the public key.
//!
//! The Keychain helper has no Secure Enclave key operation today (it stores and reads
//! generic passwords only), so the key is not hardware-bound yet. When the helper gains a
//! Secure Enclave `sign`, [`DeviceKeyStore`] is the seam: a store that signs inside the
//! Enclave replaces the read, and the allow-list of [`AccountSigner::sign`] stays.
//!
//! The key signs **only** messages that begin with one of the twelve ECDSA tags of
//! sections 5 and 16 ([`SIGNING_TAGS`]), each followed by its separator (`0x00`, or `\n` for the
//! head of relay-sync-v1 section 8). It refuses any other message, also the tags of the
//! free Connect (`apassy-relay connect v1`) and of the entitlement token, which only
//! Connect signs.
//!
//! When the helper says `keychain_unavailable` (a development build without a
//! provisioning profile) there is no account key: unlike the node key, it has no file
//! fallback, because it is the identity of this Mac at Connect. Linux keeps the key in a
//! private file of the user instead ([`super::key_file::FileKeyStore`]).
//!
//! The vault unlock opens the one account session of the app (`super::session`): the
//! Touch ID unlock reads this key together with the vault's unlock key, under one Touch
//! ID ([`DeviceKeyStore::keychain_account`]); a passphrase unlock reads it with a Touch
//! ID of its own.

use std::fmt;
use std::sync::Mutex;

use zeroize::Zeroizing;

use super::ConnectError;
use crate::native::{HelperErrorCode, KeychainSecret, NativeError, NativeHelper};
use crate::sync::{DeviceKey, HeadFields, SignedHead, encode_b64u, sha256_hex};

/// The Keychain account of the account device key.
pub const KEYCHAIN_ACCOUNT: &str = "connect-account-device-key";
/// The text of the Touch ID prompt that reads the key.
const READ_REASON: &str = "Apassy signs in to Apassy Connect with the key of this Mac.";

/// `POST /v1/account`.
pub const ACCOUNT_TAG: &str = "apassy-connect account v1";
/// `POST /v1/account/token`.
pub const SIGN_IN_TAG: &str = "apassy-connect sign-in v1";
/// `POST /v1/account/devices/join`.
pub const JOIN_TAG: &str = "apassy-connect join v1";
/// `POST /v1/account/devices/join/cancel`.
pub const JOIN_CANCEL_TAG: &str = "apassy-connect join-cancel v1";
/// An entry of the signed device list (section 7.5): the `add` of
/// `POST …/pending/{join_id}/confirm` and the `remove` of
/// `DELETE /v1/account/devices/{device_id}`, each signed by a device of the list.
pub const LIST_TAG: &str = "apassy-connect device-list v1";
/// The `previous` of version 1 of a device list, and the `link_hash` of an entry without
/// a link.
pub const LIST_NONE: &str = "-";
/// `POST /v1/account/recover`.
pub const RECOVER_TAG: &str = "apassy-connect recover v1";
/// `POST /v1/account/recovery`: a live device replaces the recovery key (section 9.1).
pub const RECOVERY_ROTATE_TAG: &str = "apassy-connect recovery-rotate v1";
/// The sign-in of the hosted bouncer brain (bouncer-brain-v2, plan 0035 A and H).
pub const BRAIN_SIGN_IN_TAG: &str = "apassy-bouncer sign-in v1";
/// The relay-sync-v1 team sign-in of a vault store.
pub const RELAY_SIGN_IN_TAG: &str = crate::sync::relay_crypto::SIGN_IN_TAG;
/// The first line of a relay-sync-v1 head of a vault store.
pub const SYNC_HEAD_TAG: &str = crate::sync::relay_crypto::HEAD_TAG;
/// An entry of the signed device list that names another account (section 16): `peer`,
/// `unpeer`, `share`, `unshare`, `join`, `leave` (`super::share`).
pub const SHARE_LIST_TAG: &str = "apassy-connect share-list v1";
/// `POST /v1/account/peers/join`: the device of another account that answers a share code.
pub const PEER_JOIN_TAG: &str = "apassy-connect peer-join v1";

/// The twelve tags that the account device key signs (sections 5 and 16), and nothing
/// else.
pub const SIGNING_TAGS: [&str; 12] = [
    ACCOUNT_TAG,
    SIGN_IN_TAG,
    JOIN_TAG,
    JOIN_CANCEL_TAG,
    LIST_TAG,
    RECOVER_TAG,
    RECOVERY_ROTATE_TAG,
    BRAIN_SIGN_IN_TAG,
    RELAY_SIGN_IN_TAG,
    SYNC_HEAD_TAG,
    SHARE_LIST_TAG,
    PEER_JOIN_TAG,
];

/// Whether `message` begins with an allowed tag and its separator.
fn allowed(message: &[u8]) -> bool {
    SIGNING_TAGS.iter().any(|tag| {
        let separator = if *tag == SYNC_HEAD_TAG { b'\n' } else { 0 };
        message.len() > tag.len()
            && message.starts_with(tag.as_bytes())
            && message[tag.len()] == separator
    })
}

/// Parts joined with one `0x00`, no trailing `0x00` (section 5).
fn joined(parts: &[&str]) -> Vec<u8> {
    parts.join("\0").into_bytes()
}

/// The `apassy-connect account v1` message: the new device key and the public key of
/// the recovery code (Ed25519, b64u).
pub fn account_message(origin: &str, public_key_b64u: &str, recovery_key_b64u: &str) -> Vec<u8> {
    joined(&[ACCOUNT_TAG, origin, public_key_b64u, recovery_key_b64u])
}

/// The `apassy-connect sign-in v1` message.
pub fn sign_in_message(
    origin: &str,
    account_id: &str,
    public_key_b64u: &str,
    nonce_b64u: &str,
) -> Vec<u8> {
    joined(&[SIGN_IN_TAG, origin, account_id, public_key_b64u, nonce_b64u])
}

/// The `apassy-connect join v1` message: it names the device name in its canonical form
/// (`super::trust::canonical_name`), so the confirming device signs that name into the
/// device list only when this signature verifies.
pub fn join_message(
    origin: &str,
    account_id: &str,
    link_hash: &str,
    public_key_b64u: &str,
    device_name: &str,
) -> Vec<u8> {
    joined(&[
        JOIN_TAG,
        origin,
        account_id,
        link_hash,
        public_key_b64u,
        device_name,
    ])
}

/// The `apassy-connect recovery-rotate v1` message: the device that signs it, the
/// recovery key that Connect stores now (`previous`), and the new one (section 9.1).
pub fn recovery_rotate_message(
    origin: &str,
    account_id: &str,
    public_key_b64u: &str,
    previous_b64u: &str,
    recovery_key_b64u: &str,
) -> Vec<u8> {
    joined(&[
        RECOVERY_ROTATE_TAG,
        origin,
        account_id,
        public_key_b64u,
        previous_b64u,
        recovery_key_b64u,
    ])
}

/// The `apassy-connect join-cancel v1` message.
pub fn join_cancel_message(
    origin: &str,
    account_id: &str,
    link_hash: &str,
    public_key_b64u: &str,
) -> Vec<u8> {
    joined(&[
        JOIN_CANCEL_TAG,
        origin,
        account_id,
        link_hash,
        public_key_b64u,
    ])
}

/// The `apassy-connect device-list v1` message of version `version` of a device list:
/// `previous` is the list hash of the entry before ([`list_hash`]), or [`LIST_NONE`] for
/// version 1; `op` is `root`, `add`, or `remove`; `link_hash` is the link of an `add`, else
/// [`LIST_NONE`]; `name` is the device name of a `root` or an `add`, else [`LIST_NONE`];
/// `by_b64u` is the key that signs the entry (for the `root`, the root key itself).
#[allow(clippy::too_many_arguments)]
pub fn list_message(
    origin: &str,
    account_id: &str,
    version: u64,
    previous: &str,
    op: &str,
    key_b64u: &str,
    link_hash: &str,
    name: &str,
    by_b64u: &str,
) -> Vec<u8> {
    joined(&[
        LIST_TAG,
        origin,
        account_id,
        &version.to_string(),
        previous,
        op,
        key_b64u,
        link_hash,
        name,
        by_b64u,
    ])
}

/// The `apassy-connect share-list v1` message of version `version` of a device list
/// (section 16): `previous` is the list hash of the entry before; `op` is `peer`,
/// `unpeer`, `share`, `unshare`, `join`, or `leave`; `peer_account` is the other account;
/// `root_b64u` is the root that a `peer` pins, else [`LIST_NONE`]; `team_id` is the vault
/// store of a `share`, `unshare`, `join`, or `leave`, else [`LIST_NONE`]; `by_b64u` is the
/// signing device.
#[allow(clippy::too_many_arguments)]
pub fn share_list_message(
    origin: &str,
    account_id: &str,
    version: u64,
    previous: &str,
    op: &str,
    peer_account: &str,
    root_b64u: &str,
    team_id: &str,
    by_b64u: &str,
) -> Vec<u8> {
    joined(&[
        SHARE_LIST_TAG,
        origin,
        account_id,
        &version.to_string(),
        previous,
        op,
        peer_account,
        root_b64u,
        team_id,
        by_b64u,
    ])
}

/// The `apassy-connect peer-join v1` message (section 16.2): the device `key_b64u` of the
/// account `joiner_account`, whose root is `joiner_root_b64u`, answers the share code of
/// `inviter_account` whose hash is `link_hash`.
pub fn peer_join_message(
    origin: &str,
    inviter_account: &str,
    link_hash: &str,
    joiner_account: &str,
    joiner_root_b64u: &str,
    key_b64u: &str,
) -> Vec<u8> {
    joined(&[
        PEER_JOIN_TAG,
        origin,
        inviter_account,
        link_hash,
        joiner_account,
        joiner_root_b64u,
        key_b64u,
    ])
}

/// The list hash of an entry: b64u of SHA-256 of its message (43 characters).
pub fn list_hash(message: &[u8]) -> String {
    encode_b64u(ring::digest::digest(&ring::digest::SHA256, message).as_ref())
}

/// The `apassy-connect recover v1` message: the new device key and the public key of the
/// new recovery code. The new device signs it, and so does the old recovery key.
pub fn recover_message(
    origin: &str,
    account_id: &str,
    public_key_b64u: &str,
    recovery_key_b64u: &str,
) -> Vec<u8> {
    joined(&[
        RECOVER_TAG,
        origin,
        account_id,
        public_key_b64u,
        recovery_key_b64u,
    ])
}

/// The `apassy-bouncer sign-in v1` message: the account id in the place of the team id
/// (vector `brain_sign_in`, bouncer-brain-v2).
pub fn brain_sign_in_message(
    brain_origin: &str,
    account_id: &str,
    public_key_b64u: &str,
    nonce_b64u: &str,
) -> Vec<u8> {
    joined(&[
        BRAIN_SIGN_IN_TAG,
        brain_origin,
        account_id,
        public_key_b64u,
        nonce_b64u,
    ])
}

/// Why the key store gave no key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceKeyError {
    /// The Keychain cannot be used by this build.
    Unavailable,
    /// The owner cancelled Touch ID. Nothing changes.
    Cancelled,
    /// The item was there and cannot be read any more (the fingerprints changed). It is
    /// deleted: this Mac needs a new link or the recovery code.
    Lost,
    /// Another failure. The text has no secret.
    Failed(String),
}

impl From<DeviceKeyError> for ConnectError {
    fn from(error: DeviceKeyError) -> Self {
        match error {
            DeviceKeyError::Unavailable => Self::KeychainUnavailable,
            DeviceKeyError::Cancelled => Self::Cancelled,
            DeviceKeyError::Lost => Self::KeyLost,
            DeviceKeyError::Failed(_) => Self::Local,
        }
    }
}

/// Where the account key is kept. Tests use [`MemoryKeyStore`].
pub trait DeviceKeyStore: Send + Sync {
    /// The stored PKCS#8 document, or `None` when there is none.
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, DeviceKeyError>;
    /// Store `pkcs8`, replacing an earlier key.
    fn store(&self, pkcs8: &[u8]) -> Result<(), DeviceKeyError>;
    /// Delete the key. True when there was one.
    fn delete(&self) -> Result<bool, DeviceKeyError>;
    /// The Keychain account of the key when this store is the Keychain of the Mac: the
    /// Touch ID unlock then reads the key with the vault's unlock key, under one Touch ID
    /// (`NativeHelper::keychain_read_with_also`). `None` for every other store.
    fn keychain_account(&self) -> Option<&'static str> {
        None
    }
}

/// The Keychain through the signed helper of the app.
pub struct KeychainDeviceKeyStore {
    helper: NativeHelper,
}

impl KeychainDeviceKeyStore {
    pub fn new(helper: NativeHelper) -> Self {
        Self { helper }
    }
}

fn keychain_error(error: &NativeError) -> DeviceKeyError {
    match error.code() {
        Some(HelperErrorCode::KeychainUnavailable) => DeviceKeyError::Unavailable,
        Some(HelperErrorCode::Cancelled | HelperErrorCode::Fallback) => DeviceKeyError::Cancelled,
        _ => DeviceKeyError::Failed(error.to_string()),
    }
}

impl DeviceKeyStore for KeychainDeviceKeyStore {
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, DeviceKeyError> {
        let state = self
            .helper
            .keychain_exists(KEYCHAIN_ACCOUNT)
            .map_err(|error| keychain_error(&error))?;
        if !state.exists {
            return Ok(None);
        }
        if state.biometry_changed {
            let _ = self.helper.keychain_delete(KEYCHAIN_ACCOUNT);
            return Err(DeviceKeyError::Lost);
        }
        match self.helper.keychain_read(KEYCHAIN_ACCOUNT, READ_REASON) {
            Ok(secret) => Ok(Some(Zeroizing::new(secret.expose().to_vec()))),
            Err(error) if error.code() == Some(HelperErrorCode::NotFound) => Ok(None),
            Err(error) if error.code() == Some(HelperErrorCode::BiometryChanged) => {
                let _ = self.helper.keychain_delete(KEYCHAIN_ACCOUNT);
                Err(DeviceKeyError::Lost)
            }
            Err(error) => Err(keychain_error(&error)),
        }
    }

    fn store(&self, pkcs8: &[u8]) -> Result<(), DeviceKeyError> {
        let secret = KeychainSecret::new(pkcs8.to_vec())
            .map_err(|error| DeviceKeyError::Failed(error.to_string()))?;
        self.helper
            .keychain_store(KEYCHAIN_ACCOUNT, &secret)
            .map_err(|error| keychain_error(&error))
    }

    fn delete(&self) -> Result<bool, DeviceKeyError> {
        self.helper
            .keychain_delete(KEYCHAIN_ACCOUNT)
            .map_err(|error| keychain_error(&error))
    }

    fn keychain_account(&self) -> Option<&'static str> {
        Some(KEYCHAIN_ACCOUNT)
    }
}

/// A key store in memory: the key is gone when the process ends. For the tests and for
/// a process without the Keychain helper that must not keep an account.
#[derive(Default)]
pub struct MemoryKeyStore {
    key: Mutex<Option<Zeroizing<Vec<u8>>>>,
    reads: Mutex<usize>,
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a key is stored.
    pub fn has_key(&self) -> bool {
        self.key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }

    /// How many reads found a key (each is one Touch ID in the Keychain store).
    pub fn reads(&self) -> usize {
        *self
            .reads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl DeviceKeyStore for MemoryKeyStore {
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, DeviceKeyError> {
        let key = self
            .key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if key.is_some() {
            *self
                .reads
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
        }
        Ok(key)
    }

    fn store(&self, pkcs8: &[u8]) -> Result<(), DeviceKeyError> {
        *self
            .key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(Zeroizing::new(pkcs8.to_vec()));
        Ok(())
    }

    fn delete(&self) -> Result<bool, DeviceKeyError> {
        Ok(self
            .key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .is_some())
    }
}

/// The account device key in memory, with the allow-list of section 5. It has no way to
/// give out its private key. Debug shows the public key only.
pub struct AccountSigner {
    key: DeviceKey,
}

impl fmt::Debug for AccountSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountSigner")
            .field("public_key", &self.key.public_key_b64u())
            .field("key", &"[redacted]")
            .finish()
    }
}

impl AccountSigner {
    /// The key of this Mac, when the store has one (Touch ID in the Keychain store). A
    /// stored document that is not a P-256 key of `ring` is [`ConnectError::KeyLost`].
    pub fn open(store: &dyn DeviceKeyStore) -> Result<Option<Self>, ConnectError> {
        match store.read()? {
            Some(document) => DeviceKey::from_pkcs8(document)
                .map(|key| Some(Self { key }))
                .map_err(|_| ConnectError::KeyLost),
            None => Ok(None),
        }
    }

    /// The key of this Mac, made once: the stored key, or a new key that is stored first.
    /// A Touch ID that the owner cancels makes no key.
    pub fn open_or_create(store: &dyn DeviceKeyStore) -> Result<Self, ConnectError> {
        if let Some(signer) = Self::open(store)? {
            return Ok(signer);
        }
        let key = DeviceKey::generate().map_err(|_| ConnectError::Local)?;
        let document = key.pkcs8().ok_or(ConnectError::Local)?;
        store.store(document)?;
        Ok(Self { key })
    }

    /// Delete the key of this Mac from `store`. True when there was one.
    pub fn forget(store: &dyn DeviceKeyStore) -> Result<bool, ConnectError> {
        Ok(store.delete()?)
    }

    /// A signer over a given key: the test vectors (`DeviceKey::from_raw`) and the
    /// fixtures. The allow-list holds for it too.
    pub fn with_key(key: DeviceKey) -> Self {
        Self { key }
    }

    /// The public key, X9.63 (65 bytes).
    pub fn public_key(&self) -> &[u8] {
        self.key.public_key()
    }

    /// The public key as b64u, as the wire carries it.
    pub fn public_key_b64u(&self) -> String {
        encode_b64u(self.key.public_key())
    }

    /// The hex SHA-256 of the 65 raw key bytes: `public_key_sha256` of plan 0035 I-3.
    pub fn public_key_sha256(&self) -> String {
        sha256_hex(self.key.public_key())
    }

    /// An ECDSA P-256 SHA-256 signature (DER) over `message`, only when it begins with
    /// one of [`SIGNING_TAGS`] and its separator. Any other message is
    /// [`ConnectError::TagRefused`] and nothing is signed.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ConnectError> {
        if !allowed(message) {
            return Err(ConnectError::TagRefused);
        }
        self.key.sign(message).map_err(|_| ConnectError::Local)
    }

    /// The signature of `POST /v1/account` for `origin`, with the public key of the
    /// recovery code.
    pub fn sign_account(
        &self,
        origin: &str,
        recovery_key_b64u: &str,
    ) -> Result<Vec<u8>, ConnectError> {
        self.sign(&account_message(
            origin,
            &self.public_key_b64u(),
            recovery_key_b64u,
        ))
    }

    /// The signature of `POST /v1/account/token`.
    pub fn sign_sign_in(
        &self,
        origin: &str,
        account_id: &str,
        nonce_b64u: &str,
    ) -> Result<Vec<u8>, ConnectError> {
        self.sign(&sign_in_message(
            origin,
            account_id,
            &self.public_key_b64u(),
            nonce_b64u,
        ))
    }

    /// The signature of `POST /v1/account/devices/join`, over the canonical
    /// `device_name`.
    pub fn sign_join(
        &self,
        origin: &str,
        account_id: &str,
        link_hash: &str,
        device_name: &str,
    ) -> Result<Vec<u8>, ConnectError> {
        self.sign(&join_message(
            origin,
            account_id,
            link_hash,
            &self.public_key_b64u(),
            device_name,
        ))
    }

    /// The signature of `POST /v1/account/devices/join/cancel`.
    pub fn sign_recovery_rotate(
        &self,
        origin: &str,
        account_id: &str,
        previous_b64u: &str,
        recovery_key_b64u: &str,
    ) -> Result<Vec<u8>, ConnectError> {
        self.sign(&recovery_rotate_message(
            origin,
            account_id,
            &self.public_key_b64u(),
            previous_b64u,
            recovery_key_b64u,
        ))
    }

    /// The signature of `POST /v1/account/devices/join/cancel`.
    pub fn sign_join_cancel(
        &self,
        origin: &str,
        account_id: &str,
        link_hash: &str,
    ) -> Result<Vec<u8>, ConnectError> {
        self.sign(&join_cancel_message(
            origin,
            account_id,
            link_hash,
            &self.public_key_b64u(),
        ))
    }

    /// An entry of the device list signed by this device: version `version` after the
    /// entry with the list hash `previous`, `op` (`add` with its `link_hash` and the name of
    /// the new device, or `remove`) for `key_b64u`. Returns the signature and the list hash
    /// of the entry.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_list_entry(
        &self,
        origin: &str,
        account_id: &str,
        (version, previous): (u64, &str),
        op: &str,
        key_b64u: &str,
        link_hash: Option<&str>,
        name: Option<&str>,
    ) -> Result<(Vec<u8>, String), ConnectError> {
        let message = list_message(
            origin,
            account_id,
            version,
            previous,
            op,
            key_b64u,
            link_hash.unwrap_or(LIST_NONE),
            name.unwrap_or(LIST_NONE),
            &self.public_key_b64u(),
        );
        Ok((self.sign(&message)?, list_hash(&message)))
    }

    /// An entry of the device list that names another account (section 16), signed by
    /// this device: version `version` after the entry with the list hash `previous`, `op`
    /// for `peer_account`, with the root that a `peer` pins and the store of a `share`,
    /// `unshare`, `join`, or `leave`. Returns the signature and the list hash of the entry.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_share_entry(
        &self,
        origin: &str,
        account_id: &str,
        (version, previous): (u64, &str),
        op: &str,
        peer_account: &str,
        root_b64u: Option<&str>,
        team_id: Option<&str>,
    ) -> Result<(Vec<u8>, String), ConnectError> {
        let message = share_list_message(
            origin,
            account_id,
            version,
            previous,
            op,
            peer_account,
            root_b64u.unwrap_or(LIST_NONE),
            team_id.unwrap_or(LIST_NONE),
            &self.public_key_b64u(),
        );
        Ok((self.sign(&message)?, list_hash(&message)))
    }

    /// The signature of `POST /v1/account/peers/join`: this device of `joiner_account`
    /// (root `joiner_root_b64u`) answers the share code of `inviter_account`.
    pub fn sign_peer_join(
        &self,
        origin: &str,
        inviter_account: &str,
        link_hash: &str,
        joiner_account: &str,
        joiner_root_b64u: &str,
    ) -> Result<Vec<u8>, ConnectError> {
        self.sign(&peer_join_message(
            origin,
            inviter_account,
            link_hash,
            joiner_account,
            joiner_root_b64u,
            &self.public_key_b64u(),
        ))
    }

    /// The root entry of a new device list (version 1) with this device as its root and
    /// only device, named `name`: what `POST /v1/account` and `POST /v1/account/recover`
    /// carry as `statement`. Returns the signature and the list hash of the entry.
    pub fn sign_root(
        &self,
        origin: &str,
        account_id: &str,
        name: &str,
    ) -> Result<(Vec<u8>, String), ConnectError> {
        let key = self.public_key_b64u();
        self.sign_list_entry(
            origin,
            account_id,
            (1, LIST_NONE),
            "root",
            &key,
            None,
            Some(name),
        )
    }

    /// The signature of `POST /v1/account/recover` by the new device, with the public key
    /// of the new recovery code.
    pub fn sign_recover(
        &self,
        origin: &str,
        account_id: &str,
        recovery_key_b64u: &str,
    ) -> Result<Vec<u8>, ConnectError> {
        self.sign(&recover_message(
            origin,
            account_id,
            &self.public_key_b64u(),
            recovery_key_b64u,
        ))
    }

    /// The signature of the sign-in of the hosted bouncer brain at `brain_origin`
    /// (bouncer-brain-v2; plan 0035 A, H, and I-1). The brain answers with its own
    /// token; the account token never goes there (I-2).
    pub fn sign_brain_sign_in(
        &self,
        brain_origin: &str,
        account_id: &str,
        nonce_b64u: &str,
    ) -> Result<Vec<u8>, ConnectError> {
        self.sign(&brain_sign_in_message(
            brain_origin,
            account_id,
            &self.public_key_b64u(),
            nonce_b64u,
        ))
    }

    /// The signature of the relay-sync-v1 team sign-in of the vault store `team_id`.
    pub fn sign_relay_sign_in(
        &self,
        origin: &str,
        team_id: &str,
        nonce_b64u: &str,
    ) -> Result<Vec<u8>, ConnectError> {
        self.sign(&crate::sync::sign_in_message(
            origin,
            team_id,
            &self.public_key_b64u(),
            nonce_b64u,
        ))
    }

    /// A relay-sync-v1 head of a vault store, signed with the account key. Fields that do
    /// not fit the grammar are [`ConnectError::Invalid`].
    pub fn sign_head(&self, fields: HeadFields) -> Result<SignedHead, ConnectError> {
        if !fields.is_valid() {
            return Err(ConnectError::Invalid);
        }
        let text = fields.text();
        let signature = self.sign(text.as_bytes())?;
        Ok(SignedHead {
            fields,
            text,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::verify_signature;

    #[test]
    fn the_key_is_made_once_and_never_leaves_the_store() {
        let store = MemoryKeyStore::new();
        let first = AccountSigner::open_or_create(&store).unwrap();
        assert!(store.has_key());
        let again = AccountSigner::open_or_create(&store).unwrap();
        assert_eq!(first.public_key(), again.public_key());
        assert_eq!(store.reads(), 1);
        let shown = format!("{first:?}");
        assert!(shown.contains("[redacted]"));
        assert!(shown.contains(&first.public_key_b64u()));
        assert!(AccountSigner::forget(&store).unwrap());
        assert!(AccountSigner::open(&store).unwrap().is_none());
        assert!(!AccountSigner::forget(&store).unwrap());
    }

    #[test]
    fn a_damaged_document_is_a_lost_key() {
        let store = MemoryKeyStore::new();
        store.store(&[1, 2, 3]).unwrap();
        assert_eq!(
            AccountSigner::open(&store).unwrap_err(),
            ConnectError::KeyLost
        );
    }

    #[test]
    fn only_the_twelve_tags_are_signed() {
        let store = MemoryKeyStore::new();
        let signer = AccountSigner::open_or_create(&store).unwrap();
        let origin = "https://connect.example.test";
        let account = "acc_k7m2q4x3ca";
        let nonce = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        let recovery = "Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc";
        for signature in [
            signer.sign_account(origin, recovery).unwrap(),
            signer.sign_sign_in(origin, account, nonce).unwrap(),
            signer
                .sign_join(origin, account, "K6tgKp", "Synthetic")
                .unwrap(),
            signer.sign_join_cancel(origin, account, "K6tgKp").unwrap(),
            signer
                .sign_list_entry(
                    origin,
                    account,
                    (2, "K6tgKp"),
                    "add",
                    &signer.public_key_b64u(),
                    Some("K6tgKp"),
                    Some("Synthetic"),
                )
                .unwrap()
                .0,
            signer.sign_root(origin, account, "Synthetic").unwrap().0,
            signer.sign_recover(origin, account, recovery).unwrap(),
            signer
                .sign_brain_sign_in("https://brain.example.test", account, nonce)
                .unwrap(),
            signer
                .sign_relay_sign_in(origin, "t_7k2m5q4x3c", nonce)
                .unwrap(),
            signer
                .sign_share_entry(
                    origin,
                    account,
                    (3, "K6tgKp"),
                    "share",
                    "acc_m3n5p7q2rb",
                    None,
                    Some("t_7k2m5q4x3c"),
                )
                .unwrap()
                .0,
            signer
                .sign_peer_join(origin, account, "K6tgKp", "acc_m3n5p7q2rb", "K6tgKp")
                .unwrap(),
        ] {
            assert!(signature.len() <= 72);
        }
        let message = account_message(origin, &signer.public_key_b64u(), recovery);
        let signature = signer.sign(&message).unwrap();
        assert!(verify_signature(signer.public_key(), &message, &signature));
        for refused in [
            b"apassy-relay connect v1\0https://connect.example.test\0key".to_vec(),
            b"apassy-connect entitlement v1\0payload".to_vec(),
            b"apassy-connect link v1\0code".to_vec(),
            b"apassy-connect link-keys v1\0keys".to_vec(),
            b"apassy-connect recovery key v1\0bytes".to_vec(),
            b"apassy-connect share-keys v1\0keys".to_vec(),
            b"apassy-connect share-safety v1\0words".to_vec(),
            b"apassy-connect share-link v1\0code".to_vec(),
            b"apassy-connect share-list v1".to_vec(),
            b"apassy-connect join-cancel v1".to_vec(),
            b"apassy-connect account v1".to_vec(),
            b"apassy-connect account v1x\0origin".to_vec(),
            b"apassy-connect account v1\norigin".to_vec(),
            b"apassy-relay-sync-head-v1\0vault".to_vec(),
            b" apassy-connect account v1\0origin".to_vec(),
            Vec::new(),
        ] {
            assert_eq!(
                signer.sign(&refused).unwrap_err(),
                ConnectError::TagRefused,
                "{}",
                String::from_utf8_lossy(&refused)
            );
        }
    }

    #[test]
    fn a_head_of_a_vault_store_is_signed_with_the_account_key() {
        let store = MemoryKeyStore::new();
        let signer = AccountSigner::open_or_create(&store).unwrap();
        let fields = HeadFields {
            vault_id: "0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77".to_owned(),
            version: 1,
            snapshot_sha256: "ab".repeat(32),
            size: 10,
            previous: crate::sync::NO_PREVIOUS.to_owned(),
            team_id: "t_7k2m5q4x3c".to_owned(),
            device_id: 1,
            time: 1_790_000_000,
        };
        let head = signer.sign_head(fields.clone()).unwrap();
        assert!(head.verify(signer.public_key()));
        let bad = HeadFields {
            version: 0,
            ..fields
        };
        assert_eq!(signer.sign_head(bad).unwrap_err(), ConnectError::Invalid);
    }
}
