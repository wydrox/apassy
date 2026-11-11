//! The one Apassy Connect account session of this device (plan s7 unit M5b).
//!
//! Settings › Connect, the sync of the vault stores, and the node's tunnel use one
//! [`AccountSession`]: one account in memory, one account device key read for each
//! unlock, one token. No part reads the key store on its own.
//!
//! - **Opened with the vault.** When a vault session starts (an unlock, another vault, a
//!   new vault), the desktop calls [`AccountSession::follow`] with its epoch: with an
//!   account file the session reads the key once ([`AccountSession::open_now`], on a
//!   worker thread: the read can ask the owner on the Mac). The Touch ID unlock of the
//!   Mac reads the key with the same Touch ID as the vault's unlock key and hands it over
//!   with [`AccountSession::offer_key`]; [`AccountSession::open_offered`] then opens the
//!   session without a read of the store.
//! - **Closed with the vault.** [`AccountSession::close`] at a lock, at a quit, and at
//!   every new vault session: the account, its key, and its token leave memory. A close
//!   never waits for a call on its way: that call drops the account when it ends, and
//!   [`AccountSession::tidy`] drops it at the next frame if nobody else did. So the key
//!   is never in memory while Apassy is locked, and it closes exactly when the vault
//!   does, also when the screen lock or sleep locks the vault (the auto-lock rule "When
//!   the screen locks or the computer sleeps").
//! - **Shared states.** [`SessionState`]: closed (locked), opening, open, signed out
//!   (the key was not read now: cancelled, or unavailable; "Sign In…" reads it again),
//!   and removed (Connect said `403 device_removed` to a valid signature, or the key
//!   cannot be used any more). A removal seen by any part ([`AccountSession::with_account`])
//!   is the state of all three. Nothing is deleted: only the owner's "Forget This Mac…"
//!   deletes the key and the account file.
//! - **Never in the way of the vault.** Opening needs no network: the account file and
//!   the key. Connect is asked only after it opened, by each part, and an unreachable
//!   Connect is a state of the part that asked, never of the unlock.
//!
//! The session holds no vault: the key is the device's, outside every vault (the
//! Keychain of the Mac, a private file on Linux: [`super::key_file`]).

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};

use zeroize::Zeroizing;

use super::ConnectError;
use super::account::{AccountState, ConnectAccount, account_file};
use super::device_key::{AccountSigner, DeviceKeyError, DeviceKeyStore};

/// The account in memory, shared with the sync of the vault stores
/// (`desktop::ui::connect::live::SyncAccount`).
pub type AccountSlot = Arc<Mutex<Option<ConnectAccount>>>;

/// The state of the session for the vault session it follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// No vault session (locked), or no account file: nothing is in memory.
    Closed,
    /// The key is being read for this vault session.
    Opening,
    /// The account and its key are in memory.
    Open,
    /// The key was not read for this vault session: the owner cancelled, or the store
    /// cannot be used now. "Sign In…" reads it again.
    SignedOut(ConnectError),
    /// Connect said that this device was removed from its account, or the key cannot be
    /// used any more ([`ConnectError::Revoked`], [`ConnectError::KeyLost`]). The key and
    /// the account file stay until the owner forgets the account here.
    Removed(ConnectError),
}

impl SessionState {
    /// The state after a failed read or call with `error`.
    fn after(error: ConnectError) -> Self {
        match error {
            ConnectError::Revoked | ConnectError::KeyLost => Self::Removed(error),
            other => Self::SignedOut(other),
        }
    }
}

/// What [`AccountSession::follow`] asks of the caller.
#[derive(Debug)]
pub enum Follow {
    /// Nothing to do: the session already follows this vault session, or there is no
    /// vault session, or no account file.
    Nothing,
    /// Read the key: run [`AccountSession::open_now`] with the ticket on a worker.
    Read(OpenTicket),
}

/// One read of the key for one vault session. A ticket of an earlier vault session opens
/// nothing ([`AccountSession::open_now`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenTicket {
    generation: u64,
}

/// The account key that the Touch ID unlock of the Mac read with the vault's unlock key
/// (one Touch ID). Debug is redacted; the bytes are erased on drop.
struct Offered(Zeroizing<Vec<u8>>);

impl fmt::Debug for Offered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Offered([redacted])")
    }
}

/// A key store that gives one key once and stores nothing: the key that the unlock
/// read, opened as [`ConnectAccount::open`] opens a key of a store.
struct GivenKey(Mutex<Option<Zeroizing<Vec<u8>>>>);

impl DeviceKeyStore for GivenKey {
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, DeviceKeyError> {
        Ok(lock(&self.0).take())
    }

    fn store(&self, _pkcs8: &[u8]) -> Result<(), DeviceKeyError> {
        Err(DeviceKeyError::Unavailable)
    }

    fn delete(&self) -> Result<bool, DeviceKeyError> {
        Err(DeviceKeyError::Unavailable)
    }
}

#[derive(Default)]
struct Config {
    store: Option<Arc<dyn DeviceKeyStore>>,
    /// The data directory: the account file is `connect/account.json` in it.
    dir: Option<PathBuf>,
}

struct Inner {
    /// The vault session that the session follows; `None` while locked.
    epoch: Option<[u8; 32]>,
    state: SessionState,
    /// Counts each open and close: a read for an earlier one opens nothing.
    generation: u64,
    /// The key of the open account, so that a caller gets it without the account lock.
    signer: Option<Arc<AccountSigner>>,
    /// A close came while a call held the account: the account goes when it is free.
    pending_close: bool,
    /// The account of this vault session while a call of an earlier one still holds the
    /// slot: it goes into the slot when the slot is free.
    waiting: Option<ConnectAccount>,
    offered: Option<Offered>,
}

impl Inner {
    /// Put the slot in order while its lock is held: the account that a close left goes,
    /// and the waiting account of this vault session takes its place.
    fn settle(&mut self, slot: &mut Option<ConnectAccount>) {
        if self.pending_close {
            if let Some(mut account) = slot.take() {
                account.sign_out();
            }
            self.pending_close = false;
        }
        if let Some(account) = self.waiting.take()
            && let Some(mut old) = slot.replace(account)
        {
            old.sign_out();
        }
    }
}

/// The account session of this device. Share it with an `Arc`. Debug shows the state.
pub struct AccountSession {
    config: Mutex<Config>,
    slot: AccountSlot,
    inner: Mutex<Inner>,
}

impl fmt::Debug for AccountSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountSession")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl Default for AccountSession {
    fn default() -> Self {
        Self::new()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The account of `slot` when nobody holds it, without waiting.
fn try_lock(slot: &AccountSlot) -> Option<MutexGuard<'_, Option<ConnectAccount>>> {
    match slot.try_lock() {
        Ok(guard) => Some(guard),
        Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
        Err(TryLockError::WouldBlock) => None,
    }
}

// Lock order: the slot before `inner` when both are held and the slot lock waits. A
// step that holds `inner` takes the slot only with `try_lock`, so the UI thread never
// waits for a call on the account.
impl AccountSession {
    /// A session without a key store and without a data directory: it never reads a
    /// file or a key until [`Self::configure`] gives it both (the tests, and every
    /// `DesktopApp` that is not the window of the app).
    pub fn new() -> Self {
        Self {
            config: Mutex::new(Config::default()),
            slot: Arc::new(Mutex::new(None)),
            inner: Mutex::new(Inner {
                epoch: None,
                state: SessionState::Closed,
                generation: 0,
                signer: None,
                pending_close: false,
                waiting: None,
                offered: None,
            }),
        }
    }

    /// A session over `store` and the account file of the data directory `dir`.
    pub fn with(store: Arc<dyn DeviceKeyStore>, dir: &Path) -> Self {
        let session = Self::new();
        session.configure(Some(store), Some(dir.to_path_buf()));
        session
    }

    /// The session of this device: the key store of the platform
    /// ([`super::key_file::platform_store`]) and the account file of `dir`.
    pub fn platform(dir: &Path) -> Self {
        let session = Self::new();
        session.configure(
            super::key_file::platform_store(dir),
            Some(dir.to_path_buf()),
        );
        session
    }

    /// Set the key store and the data directory. The session closes first.
    pub fn configure(&self, store: Option<Arc<dyn DeviceKeyStore>>, dir: Option<PathBuf>) {
        self.close();
        let mut config = lock(&self.config);
        config.store = store;
        config.dir = dir;
    }

    /// The key store, for the steps of Settings › Connect that make or delete the key
    /// (creation, join, recovery, forget). `None` when this build has none.
    pub fn store(&self) -> Option<Arc<dyn DeviceKeyStore>> {
        lock(&self.config).store.clone()
    }

    /// The account file, when the session has a data directory.
    pub fn path(&self) -> Option<PathBuf> {
        lock(&self.config).dir.as_deref().map(account_file)
    }

    /// What the account file says now (a small file, no secret). `None` without one,
    /// or when it does not load.
    pub fn account_state(&self) -> Option<AccountState> {
        self.path()
            .and_then(|path| AccountState::load(&path).ok().flatten())
    }

    /// This device has a Connect account (the account file), without asking Connect.
    pub fn has_account(&self) -> bool {
        self.account_state().is_some()
    }

    /// The state for the vault session that the session follows.
    pub fn state(&self) -> SessionState {
        lock(&self.inner).state.clone()
    }

    /// The vault session that the session follows.
    pub fn epoch(&self) -> Option<[u8; 32]> {
        lock(&self.inner).epoch
    }

    /// The account and its key are in memory.
    pub fn is_open(&self) -> bool {
        self.state() == SessionState::Open
    }

    /// The account in memory, for the sync of the vault stores. A holder locks it for
    /// its Connect calls and never keeps it: the account leaves the slot at a close.
    /// The account in the slot is the session's only after [`Self::tidy`] or inside
    /// [`Self::with_account`]; prefer that.
    pub fn slot(&self) -> AccountSlot {
        Arc::clone(&self.slot)
    }

    /// The account device key while the session is open.
    pub fn signer(&self) -> Option<Arc<AccountSigner>> {
        let inner = lock(&self.inner);
        if inner.state == SessionState::Open {
            inner.signer.clone()
        } else {
            None
        }
    }

    /// Follow the vault session `epoch` (`None`: locked). A new vault session closes the
    /// session of the earlier one; with an account file the session opens for the new
    /// one: with the key that its unlock offered ([`Self::offer_key`]), else with one
    /// read of the store, which the caller runs ([`Follow::Read`]). The same vault
    /// session again does nothing: one read for each unlock.
    pub fn follow(&self, epoch: Option<[u8; 32]>) -> Follow {
        if self.epoch() == epoch {
            return Follow::Nothing;
        }
        let offered = lock(&self.inner).offered.take();
        self.close();
        let Some(epoch) = epoch else {
            return Follow::Nothing;
        };
        if let Some(Offered(key)) = offered {
            self.open_with(epoch, key);
            return Follow::Nothing;
        }
        let has_account = self.has_account();
        let has_store = self.store().is_some();
        let mut inner = lock(&self.inner);
        inner.epoch = Some(epoch);
        if !has_account || !has_store {
            inner.state = SessionState::Closed;
            return Follow::Nothing;
        }
        inner.state = SessionState::Opening;
        Follow::Read(OpenTicket {
            generation: inner.generation,
        })
    }

    /// "Sign In…" after a cancelled or failed read: read the key again for the vault
    /// session that the session follows. `None` while locked, without an account file,
    /// or when the session is open, opening, or removed.
    pub fn retry(&self) -> Option<OpenTicket> {
        let has_account = self.has_account() && self.store().is_some();
        let mut inner = lock(&self.inner);
        let retry = matches!(
            inner.state,
            SessionState::SignedOut(_) | SessionState::Closed
        );
        if inner.epoch.is_none() || !has_account || !retry {
            return None;
        }
        inner.generation += 1;
        inner.state = SessionState::Opening;
        Some(OpenTicket {
            generation: inner.generation,
        })
    }

    /// Read the key from the store and open the account: the one read of an unlock. It
    /// blocks (the Keychain asks for Touch ID): run it on a worker. A ticket of an earlier
    /// vault session, or one that a close ended, opens nothing and drops what it read.
    pub fn open_now(&self, ticket: OpenTicket) -> SessionState {
        let (store, path) = (self.store(), self.path());
        let opened = match (store, path) {
            (Some(store), Some(path)) => ConnectAccount::open(store.as_ref(), &path),
            _ => Ok(None),
        };
        self.install_opened(ticket, opened)
    }

    fn install_opened(
        &self,
        ticket: OpenTicket,
        opened: Result<Option<ConnectAccount>, ConnectError>,
    ) -> SessionState {
        let mut inner = lock(&self.inner);
        if inner.generation != ticket.generation || inner.state != SessionState::Opening {
            // A lock or another vault session came first.
            drop(inner);
            if let Ok(Some(mut account)) = opened {
                account.sign_out();
            }
            return self.state();
        }
        inner.state = match opened {
            Ok(Some(account)) => {
                inner.signer = account.signer().ok();
                self.put(&mut inner, account);
                SessionState::Open
            }
            Ok(None) => SessionState::Closed,
            Err(error) => SessionState::after(error),
        };
        inner.state.clone()
    }

    /// Put `account` in the slot, or let it wait there for a call of an earlier vault
    /// session that still holds the slot. Never waits.
    fn put(&self, inner: &mut Inner, account: ConnectAccount) {
        inner.waiting = Some(account);
        if let Some(mut slot) = try_lock(&self.slot) {
            inner.settle(&mut slot);
        }
    }

    /// The account key that the Touch ID unlock read together with the vault's unlock key
    /// (one Touch ID, the same access control). It opens the session of the vault session
    /// that this unlock starts ([`Self::open_offered`]), and nothing else: a failed unlock
    /// drops it ([`Self::drop_offered`]), and so does a lock.
    pub fn offer_key(&self, pkcs8: Zeroizing<Vec<u8>>) {
        lock(&self.inner).offered = Some(Offered(pkcs8));
    }

    /// Forget an offered key (the unlock failed).
    pub fn drop_offered(&self) {
        lock(&self.inner).offered = None;
    }

    /// Open the session for the vault session `epoch` with the offered key, without a
    /// read of the store. False when no key was offered.
    pub fn open_offered(&self, epoch: [u8; 32]) -> bool {
        let Some(Offered(key)) = lock(&self.inner).offered.take() else {
            return false;
        };
        self.open_with(epoch, key);
        true
    }

    /// Open the account of the account file with `key` for the vault session `epoch`. A
    /// key that is not the one that the account file names is the removed state, as a
    /// read of that key from the store would be. No network, no store.
    fn open_with(&self, epoch: [u8; 32], key: Zeroizing<Vec<u8>>) {
        if self.epoch() != Some(epoch) {
            self.close();
        }
        let opened = match self.path() {
            Some(path) => ConnectAccount::open(&GivenKey(Mutex::new(Some(key))), &path),
            None => Ok(None),
        };
        let ticket = {
            let mut inner = lock(&self.inner);
            inner.epoch = Some(epoch);
            inner.state = SessionState::Opening;
            OpenTicket {
                generation: inner.generation,
            }
        };
        self.install_opened(ticket, opened);
    }

    /// An account that Settings › Connect made, joined, or recovered in the vault session
    /// `epoch`: it is the account of the session now. Another vault session (the vault
    /// locked or changed meanwhile) drops it from memory; its file and key stay.
    pub fn install(&self, mut account: ConnectAccount, epoch: Option<[u8; 32]>) -> bool {
        let mut inner = lock(&self.inner);
        if epoch.is_none() || inner.epoch != epoch {
            drop(inner);
            account.sign_out();
            return false;
        }
        inner.signer = account.signer().ok();
        inner.state = SessionState::Open;
        self.put(&mut inner, account);
        true
    }

    /// Close the session: the account, its key, and its token leave memory. It never
    /// waits for a call on its way; that call, or [`Self::tidy`], drops the account.
    pub fn close(&self) {
        let mut inner = lock(&self.inner);
        inner.epoch = None;
        inner.state = SessionState::Closed;
        inner.generation += 1;
        inner.signer = None;
        inner.offered = None;
        if let Some(mut account) = inner.waiting.take() {
            account.sign_out();
        }
        inner.pending_close = true;
        if let Some(mut slot) = try_lock(&self.slot) {
            inner.settle(&mut slot);
        }
    }

    /// The account is forgotten on this device (the key and the account file are gone):
    /// nothing stays in memory, and the session follows the vault session without one.
    pub fn forget(&self) {
        let epoch = self.epoch();
        self.close();
        lock(&self.inner).epoch = epoch;
    }

    /// Drop an account that a close left in the slot because a call held it, and put the
    /// waiting account in. Call it at each frame; it never waits.
    pub fn tidy(&self) {
        let mut inner = lock(&self.inner);
        if !inner.pending_close && inner.waiting.is_none() {
            return;
        }
        if let Some(mut slot) = try_lock(&self.slot) {
            inner.settle(&mut slot);
        }
    }

    /// Run `work` with the account of the session: a Connect call of Settings, of the
    /// sync, or of the tunnel. It waits for another call on the account (run it on a
    /// worker thread). Closed or opening: [`ConnectError::SignedOut`]; removed: that
    /// error. A removal that `work` meets (`403 device_removed`, a lost key) is the state
    /// of the session for every part.
    pub fn with_account<T>(
        &self,
        work: impl FnOnce(&mut ConnectAccount) -> Result<T, ConnectError>,
    ) -> Result<T, ConnectError> {
        let mut slot = lock(&self.slot);
        let generation = {
            let mut inner = lock(&self.inner);
            inner.settle(&mut slot);
            match &inner.state {
                SessionState::Open => inner.generation,
                SessionState::Removed(error) => return Err(error.clone()),
                _ => return Err(ConnectError::SignedOut),
            }
        };
        let result = match slot.as_mut() {
            Some(account) => work(account),
            None => Err(ConnectError::SignedOut),
        };
        let mut inner = lock(&self.inner);
        // A close during the call: the account goes now.
        inner.settle(&mut slot);
        drop(slot);
        if let Err(error @ (ConnectError::Revoked | ConnectError::KeyLost)) = &result
            && inner.generation == generation
        {
            inner.state = SessionState::Removed(error.clone());
            inner.signer = None;
        }
        result
    }

    /// Take the open account out of the session for a step that ends it (the deletion of
    /// the account). The session is signed out until "Sign In…" reads the key again. It
    /// waits for a call on the account: run it on a worker.
    pub fn take(&self) -> Option<ConnectAccount> {
        let mut slot = lock(&self.slot);
        let mut inner = lock(&self.inner);
        inner.settle(&mut slot);
        if inner.state != SessionState::Open {
            return None;
        }
        inner.state = SessionState::SignedOut(ConnectError::SignedOut);
        inner.signer = None;
        slot.take()
    }

    /// Take whatever account is in memory, open or removed, before the owner forgets the
    /// account on this device. It waits for a call on the account: run it on a worker.
    pub fn take_any(&self) -> Option<ConnectAccount> {
        let mut slot = lock(&self.slot);
        let mut inner = lock(&self.inner);
        inner.settle(&mut slot);
        inner.signer = None;
        slot.take().map(|mut account| {
            account.sign_out();
            account
        })
    }

    /// Mark a removal that a holder of [`Self::slot`] met outside [`Self::with_account`].
    pub fn note(&self, error: &ConnectError) {
        if matches!(error, ConnectError::Revoked | ConnectError::KeyLost) {
            let mut inner = lock(&self.inner);
            if inner.state == SessionState::Open {
                inner.state = SessionState::Removed(error.clone());
                inner.signer = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect::MemoryKeyStore;
    use crate::connect::account::AccountState;

    const EPOCH: [u8; 32] = [7; 32];
    const OTHER: [u8; 32] = [8; 32];

    /// An account file of `signer` in `dir`, as a creation writes it.
    fn account_file_of(dir: &Path, signer: &AccountSigner) {
        let public_key = signer.public_key_b64u();
        let (root, known) = AccountState::new_trust(&public_key, signer.public_key(), &[]);
        let state = AccountState {
            v: 2,
            origin: "http://127.0.0.1:9".to_owned(),
            account_id: "acc_k7m2q4x3ca".to_owned(),
            device_id: "dev_k7m2q4x3ca".to_owned(),
            name: Some("Synthetic".to_owned()),
            device_name: "Test".to_owned(),
            public_key,
            created_at: 1_790_000_000,
            root,
            known,
            revoked: Vec::new(),
        };
        state.save(&account_file(dir)).expect("account file");
    }

    fn session_with_account() -> (tempfile::TempDir, Arc<MemoryKeyStore>, AccountSession) {
        let dir = tempfile::tempdir().expect("dir");
        let store = Arc::new(MemoryKeyStore::new());
        let signer = AccountSigner::open_or_create(store.as_ref()).expect("key");
        account_file_of(dir.path(), &signer);
        let session = AccountSession::with(store.clone(), dir.path());
        (dir, store, session)
    }

    fn open(session: &AccountSession, epoch: [u8; 32]) -> SessionState {
        match session.follow(Some(epoch)) {
            Follow::Read(ticket) => session.open_now(ticket),
            Follow::Nothing => session.state(),
        }
    }

    #[test]
    fn one_read_for_each_unlock_and_nothing_while_locked() {
        let (_dir, store, session) = session_with_account();
        let created = store.reads();
        assert_eq!(session.state(), SessionState::Closed);
        assert!(session.signer().is_none());
        assert_eq!(open(&session, EPOCH), SessionState::Open);
        assert_eq!(store.reads(), created + 1);
        // The same vault session again reads nothing.
        assert!(matches!(session.follow(Some(EPOCH)), Follow::Nothing));
        for _ in 0..3 {
            session.with_account(|_| Ok(())).expect("a call");
        }
        assert!(session.signer().is_some());
        assert_eq!(store.reads(), created + 1, "one read for the unlock");
        // The lock: nothing in memory.
        assert!(matches!(session.follow(None), Follow::Nothing));
        assert_eq!(session.state(), SessionState::Closed);
        assert!(session.signer().is_none());
        assert!(lock(&session.slot()).is_none());
        assert_eq!(
            session.with_account(|_| Ok(())).unwrap_err(),
            ConnectError::SignedOut
        );
        // The next unlock reads once more.
        assert_eq!(open(&session, OTHER), SessionState::Open);
        assert_eq!(store.reads(), created + 2);
    }

    #[test]
    fn a_read_for_an_earlier_vault_session_opens_nothing() {
        let (_dir, _store, session) = session_with_account();
        let Follow::Read(ticket) = session.follow(Some(EPOCH)) else {
            panic!("a read");
        };
        assert_eq!(session.state(), SessionState::Opening);
        session.close();
        assert_eq!(session.open_now(ticket), SessionState::Closed);
        assert!(lock(&session.slot()).is_none());
        assert!(session.signer().is_none());
    }

    #[test]
    fn a_close_while_a_call_holds_the_account_drops_it_after_the_call() {
        let (_dir, _store, session) = session_with_account();
        open(&session, EPOCH);
        let slot = session.slot();
        let held = lock(&slot);
        session.close();
        assert!(session.signer().is_none());
        session.tidy();
        assert!(held.is_some(), "the holder keeps it until it ends");
        drop(held);
        session.tidy();
        assert!(lock(&slot).is_none());
    }

    #[test]
    fn an_offered_key_opens_without_a_read_and_only_its_unlock() {
        let (_dir, store, session) = session_with_account();
        let reads = store.reads();
        let key = store.read().unwrap().expect("key");
        let reads = reads + 1; // the read of this test
        session.offer_key(key.clone());
        assert!(matches!(session.follow(Some(EPOCH)), Follow::Nothing));
        assert_eq!(session.state(), SessionState::Open);
        assert_eq!(store.reads(), reads, "no read of the store");
        // An offer that no unlock took goes with a close.
        session.offer_key(key.clone());
        session.close();
        assert!(matches!(session.follow(Some(OTHER)), Follow::Read(_)));
        // Another key than the account file names is a lost key.
        session.close();
        let stranger = crate::sync::DeviceKey::generate().expect("key");
        session.offer_key(Zeroizing::new(stranger.pkcs8().expect("pkcs8").to_vec()));
        assert!(session.open_offered(EPOCH));
        assert_eq!(
            session.state(),
            SessionState::Removed(ConnectError::KeyLost)
        );
    }

    #[test]
    fn a_removal_that_one_part_meets_is_the_state_of_all() {
        let (_dir, _store, session) = session_with_account();
        open(&session, EPOCH);
        let result: Result<(), _> = session.with_account(|_| Err(ConnectError::Revoked));
        assert_eq!(result.unwrap_err(), ConnectError::Revoked);
        assert_eq!(
            session.state(),
            SessionState::Removed(ConnectError::Revoked)
        );
        assert!(session.signer().is_none());
        assert_eq!(
            session.with_account(|_| Ok(())).unwrap_err(),
            ConnectError::Revoked
        );
        // An offline Connect changes nothing.
        let (_dir, _store, session) = session_with_account();
        open(&session, EPOCH);
        let result: Result<(), _> = session.with_account(|_| Err(ConnectError::Offline));
        assert_eq!(result.unwrap_err(), ConnectError::Offline);
        assert!(session.is_open());
    }

    #[test]
    fn without_an_account_file_or_a_store_nothing_is_read() {
        let dir = tempfile::tempdir().expect("dir");
        let store = Arc::new(MemoryKeyStore::new());
        AccountSigner::open_or_create(store.as_ref()).expect("key");
        let reads = store.reads();
        let session = AccountSession::with(store.clone(), dir.path());
        assert!(matches!(session.follow(Some(EPOCH)), Follow::Nothing));
        assert_eq!(session.state(), SessionState::Closed);
        assert_eq!(store.reads(), reads);
        let unconfigured = AccountSession::new();
        assert!(matches!(unconfigured.follow(Some(EPOCH)), Follow::Nothing));
        assert!(unconfigured.path().is_none());
    }

    #[test]
    fn a_cancelled_read_is_signed_out_and_sign_in_reads_again() {
        struct Cancelling(MemoryKeyStore, Mutex<bool>);
        impl DeviceKeyStore for Cancelling {
            fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, DeviceKeyError> {
                if std::mem::replace(&mut *lock(&self.1), false) {
                    return Err(DeviceKeyError::Cancelled);
                }
                self.0.read()
            }
            fn store(&self, pkcs8: &[u8]) -> Result<(), DeviceKeyError> {
                self.0.store(pkcs8)
            }
            fn delete(&self) -> Result<bool, DeviceKeyError> {
                self.0.delete()
            }
        }
        let dir = tempfile::tempdir().expect("dir");
        let store = Arc::new(Cancelling(MemoryKeyStore::new(), Mutex::new(false)));
        let signer = AccountSigner::open_or_create(store.as_ref()).expect("key");
        account_file_of(dir.path(), &signer);
        *lock(&store.1) = true;
        let session = AccountSession::with(store.clone(), dir.path());
        assert_eq!(
            open(&session, EPOCH),
            SessionState::SignedOut(ConnectError::Cancelled)
        );
        let ticket = session.retry().expect("sign in again");
        assert_eq!(session.open_now(ticket), SessionState::Open);
        assert!(session.retry().is_none(), "open: nothing to retry");
        session.close();
        assert!(session.retry().is_none(), "locked: no read");
    }
}
