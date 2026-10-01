//! The pairing window (contract companion-v1, section 5).
//!
//! The Mac has one window at a time. Its states:
//!
//! ```text
//!   open ──valid pair request──▶ waiting for the owner ──right code + owner check──▶ paired
//!     │                               │  │
//!     └──cancel or expiry──▶ gone     │  └──cancel, or three wrong codes──▶ denied
//!                                     └──expiry──▶ expired
//! ```
//!
//! - `open` makes a 32-byte secret and a window of 5 minutes. Only one window exists.
//! - A valid pair request moves the window to "waiting for the owner". It accepts no
//!   second request. A leaked link alone pairs nothing: the code is computed from the
//!   secret and both keys of the request, and only the device that sent the request
//!   shows it.
//! - The owner types the code on the Mac. [`Pairing::check_code`] compares it in
//!   constant time with the code of the waiting request. A wrong code counts, and three
//!   wrong codes close the window. A right code gives a [`PairCandidate`]. The caller
//!   then runs the owner check for `OwnerAction::PairCompanion` and stores the device
//!   through [`Pairing::complete`], which stores it and moves the window to "paired" in
//!   one step.
//! - The answer for the phone (`waiting`, `paired`, `denied`, `expired`) is kept for
//!   5 minutes after the window ends. A status lookup needs the device ID and the proof
//!   of the pair request, compared in constant time.
//!
//! Lock order: the pairing lock comes before the vault lock, never the other way. The
//! closures of [`Pairing::submit`] and [`Pairing::complete`] run under the pairing lock
//! and may take the vault lock.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use super::crypto::{
    PUBLIC_KEY_BYTES, SECRET_BYTES, constant_time_eq, hmac_sha256, pair_string, pairing_code,
    pairing_code_hash, verify_ecdsa, verify_hmac,
};
use super::wire::{
    ErrorCode, MAX_DEVICE_NAME_CHARS, PairAccepted, PairRequest, PairStatus, decode_fixed,
    valid_device_id,
};
use crate::broker::approvals::OwnerAction;

/// How long a window is open, from `open`.
pub const WINDOW_LIFETIME: Duration = Duration::from_secs(300);
/// How long the answer for the phone is kept after the window ends.
pub const RESULT_KEEP: Duration = Duration::from_secs(300);
/// After a right code, the window lasts at least this much longer, so that the owner
/// check (Touch ID or the passphrase) can finish.
pub const CONFIRM_GRACE: Duration = Duration::from_secs(120);
/// Three wrong codes close the window.
pub const MAX_WRONG_CODES: u32 = 3;

/// A source of time. The window uses a monotonic clock for its deadline and the Unix
/// time for the numbers that the phone sees.
pub trait Clock: Send + Sync + fmt::Debug {
    fn now(&self) -> Instant;
    fn unix_seconds(&self) -> u64;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn unix_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    }
}

/// A clock that moves only when a test says so.
#[derive(Debug)]
pub struct ManualClock {
    start: Instant,
    unix_start: u64,
    elapsed: Mutex<Duration>,
}

impl ManualClock {
    /// A clock that starts at `unix_start` Unix seconds.
    pub fn new(unix_start: u64) -> Self {
        Self {
            start: Instant::now(),
            unix_start,
            elapsed: Mutex::new(Duration::ZERO),
        }
    }

    pub fn advance(&self, by: Duration) {
        *self.elapsed.lock().unwrap_or_else(PoisonError::into_inner) += by;
    }

    fn elapsed(&self) -> Duration {
        *self.elapsed.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.start + self.elapsed()
    }

    fn unix_seconds(&self) -> u64 {
        self.unix_start + self.elapsed().as_secs()
    }
}

/// A new window: the secret for the link and the end of the window.
pub struct OpenedWindow {
    /// The pairing secret. The link has it. It is erased on drop.
    pub secret: Zeroizing<[u8; SECRET_BYTES]>,
    /// The end of the window, Unix seconds.
    pub expires_at: u64,
}

impl fmt::Debug for OpenedWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedWindow")
            .field("secret", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Why a window did not open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// A window is open or waits for the owner. Cancel it first.
    AlreadyOpen,
    /// The system did not give random bytes.
    NoRandom,
}

impl OpenError {
    pub fn message(self) -> &'static str {
        match self {
            Self::AlreadyOpen => {
                "A pairing window is already open. Cancel it first. Nothing was paired."
            }
            Self::NoRandom => {
                "The system gave no random bytes for the pairing code. Nothing was paired."
            }
        }
    }
}

/// Why a pair request was refused (contract 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairRequestError {
    /// A field is missing or has a bad format: `400 bad_request`.
    BadRequest,
    /// No open window, a used window, or a bad proof or signature: `401 unauthorized`.
    /// The three window cases give the same answer.
    Unauthorized,
    /// The device ID is paired already: `409 already_paired`.
    AlreadyPaired,
}

impl PairRequestError {
    /// The wire error for this refusal.
    pub fn code(self) -> ErrorCode {
        match self {
            Self::BadRequest => ErrorCode::BadRequest,
            Self::Unauthorized => ErrorCode::Unauthorized,
            Self::AlreadyPaired => ErrorCode::AlreadyPaired,
        }
    }
}

/// The device that asks to pair, as the owner confirms it. It holds the public keys only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairCandidate {
    pub device_id: String,
    pub device_name: String,
    pub request_key: [u8; PUBLIC_KEY_BYTES],
    pub approval_key: [u8; PUBLIC_KEY_BYTES],
}

impl PairCandidate {
    /// The owner action that the owner check must name.
    pub fn action(&self) -> OwnerAction {
        OwnerAction::PairCompanion {
            device_id: self.device_id.clone(),
            device_name: self.device_name.clone(),
            request_key: self.request_key.to_vec(),
            approval_key: self.approval_key.to_vec(),
        }
    }
}

/// Why the typed code did not pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeError {
    /// No request waits for the owner: the window is gone, or has no request yet.
    NoRequest,
    /// The text is not 6 digits. It does not count as a wrong code.
    Malformed,
    /// The code is wrong. `remaining` tries are left.
    Wrong { remaining: u32 },
    /// The third wrong code closed the window.
    Closed,
}

impl CodeError {
    /// Text for the owner.
    pub fn message(self) -> String {
        match self {
            Self::NoRequest => {
                "No iPhone waits to pair. Make a new code. Nothing was paired.".to_owned()
            }
            Self::Malformed => "Type the 6 digits that the iPhone shows.".to_owned(),
            Self::Wrong { remaining } => format!(
                "The code is wrong. {remaining} {} left. Nothing was paired.",
                if remaining == 1 {
                    "try is"
                } else {
                    "tries are"
                }
            ),
            Self::Closed => {
                "The code is wrong. The pairing window is closed. Nothing was paired.".to_owned()
            }
        }
    }
}

/// Why [`Pairing::complete`] did not pair.
#[derive(Debug, PartialEq, Eq)]
pub enum CompleteError<E> {
    /// The window is gone, or waits for another device. The store did not run.
    NotWaiting,
    /// The store failed. The window still waits.
    Store(E),
}

/// What the Mac window shows, for the desktop app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingView {
    /// No window.
    Closed,
    /// The window is open and has no request yet.
    Open { expires_at: u64 },
    /// A device asked to pair and the owner has not decided.
    Waiting {
        device_id: String,
        device_name: String,
        expires_at: u64,
        wrong_codes: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    Paired,
    Denied,
    Expired,
}

struct Waiting {
    candidate: PairCandidate,
    proof: [u8; SECRET_BYTES],
    wrong_codes: u32,
}

enum Window {
    Closed,
    Open,
    Waiting(Box<Waiting>),
}

/// The kept answer for the phone.
struct Outcome {
    device_id: String,
    proof: [u8; SECRET_BYTES],
    ended: Ended,
    mac_name: String,
    at: Instant,
}

struct State {
    window: Window,
    secret: Zeroizing<[u8; SECRET_BYTES]>,
    mac_name: String,
    deadline: Instant,
    expires_at: u64,
    outcome: Option<Outcome>,
}

/// The pairing window. It is shared: the listener threads and the desktop app hold the
/// same value.
pub struct Pairing {
    clock: Arc<dyn Clock>,
    state: Mutex<State>,
}

impl fmt::Debug for Pairing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pairing").finish_non_exhaustive()
    }
}

impl Pairing {
    /// A pairing window on the system clock.
    pub fn new() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }

    /// A pairing window on `clock`. The tests use a [`ManualClock`].
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        let now = clock.now();
        Self {
            state: Mutex::new(State {
                window: Window::Closed,
                secret: Zeroizing::new([0; SECRET_BYTES]),
                mac_name: String::new(),
                deadline: now,
                expires_at: 0,
                outcome: None,
            }),
            clock,
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Move a window that ran out of time to its end state, and drop an answer that ran
    /// out of time. Every call starts with it.
    fn refresh(&self, state: &mut State) {
        let now = self.clock.now();
        if !matches!(state.window, Window::Closed) && now >= state.deadline {
            if let Window::Waiting(waiting) = &state.window {
                state.outcome = Some(Outcome {
                    device_id: waiting.candidate.device_id.clone(),
                    proof: waiting.proof,
                    ended: Ended::Expired,
                    mac_name: state.mac_name.clone(),
                    // The answer is kept from the end of the window, not from this call.
                    at: state.deadline,
                });
            }
            Self::close(state);
        }
        if let Some(outcome) = &state.outcome
            && now.saturating_duration_since(outcome.at) >= RESULT_KEEP
        {
            state.outcome = None;
        }
    }

    /// End the window and erase its secret.
    fn close(state: &mut State) {
        state.window = Window::Closed;
        *state.secret = [0; SECRET_BYTES];
    }

    /// Open a window for 5 minutes with a new secret. `mac_name` is for the answer
    /// that the phone gets after pairing.
    pub fn open(&self, mac_name: &str) -> Result<OpenedWindow, OpenError> {
        let mut secret = Zeroizing::new([0u8; SECRET_BYTES]);
        getrandom::fill(secret.as_mut_slice()).map_err(|_| OpenError::NoRandom)?;
        let mut state = self.lock();
        self.refresh(&mut state);
        if !matches!(state.window, Window::Closed) {
            return Err(OpenError::AlreadyOpen);
        }
        let now = self.clock.now();
        state.window = Window::Open;
        state.secret = secret.clone();
        state.mac_name = mac_name
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_DEVICE_NAME_CHARS)
            .collect();
        state.deadline = now + WINDOW_LIFETIME;
        state.expires_at = self.clock.unix_seconds() + WINDOW_LIFETIME.as_secs();
        Ok(OpenedWindow {
            secret,
            expires_at: state.expires_at,
        })
    }

    /// What the window shows now.
    pub fn view(&self) -> PairingView {
        let mut state = self.lock();
        self.refresh(&mut state);
        match &state.window {
            Window::Closed => PairingView::Closed,
            Window::Open => PairingView::Open {
                expires_at: state.expires_at,
            },
            Window::Waiting(waiting) => PairingView::Waiting {
                device_id: waiting.candidate.device_id.clone(),
                device_name: waiting.candidate.device_name.clone(),
                expires_at: state.expires_at,
                wrong_codes: waiting.wrong_codes,
            },
        }
    }

    /// Handle a pair request, in the order of contract 5.3: the formats, then the
    /// window and the proof (one answer for no window, a used window, and a bad proof),
    /// then both signatures, then `is_paired`. `is_paired` runs last, under the pairing
    /// lock, and answers whether the device ID is paired already.
    pub fn submit(
        &self,
        request: &PairRequest,
        is_paired: impl FnOnce(&str) -> bool,
    ) -> Result<PairAccepted, PairRequestError> {
        let valid = request.validate().ok_or(PairRequestError::BadRequest)?;
        let string = pair_string(
            &valid.device_id,
            &valid.device_name,
            &valid.request_key,
            &valid.approval_key,
        )
        .ok_or(PairRequestError::BadRequest)?;
        let mut state = self.lock();
        self.refresh(&mut state);
        let open = matches!(state.window, Window::Open);
        // Check the proof also when no window is open, so that the answer takes the
        // same time. A closed window has an erased secret and refuses anyway.
        let proof_ok = verify_hmac(state.secret.as_slice(), string.as_bytes(), &valid.proof);
        if !(open && proof_ok) {
            return Err(PairRequestError::Unauthorized);
        }
        let signatures_ok = verify_ecdsa(
            &valid.request_key,
            string.as_bytes(),
            &valid.request_key_signature,
        ) && verify_ecdsa(
            &valid.approval_key,
            string.as_bytes(),
            &valid.approval_key_signature,
        );
        if !signatures_ok {
            return Err(PairRequestError::Unauthorized);
        }
        if is_paired(&valid.device_id) {
            return Err(PairRequestError::AlreadyPaired);
        }
        state.window = Window::Waiting(Box::new(Waiting {
            candidate: PairCandidate {
                device_id: valid.device_id,
                device_name: valid.device_name,
                request_key: valid.request_key,
                approval_key: valid.approval_key,
            },
            proof: valid.proof,
            wrong_codes: 0,
        }));
        Ok(PairAccepted {
            expires_at: state.expires_at,
        })
    }

    /// Check the code that the owner typed. Spaces are ignored. A right code returns the
    /// device that waits, and gives the window [`CONFIRM_GRACE`] for the owner check. A
    /// wrong code counts, and the third one closes the window.
    pub fn check_code(&self, typed: &str) -> Result<PairCandidate, CodeError> {
        let typed: String = typed.chars().filter(|c| *c != ' ').collect();
        let mut state = self.lock();
        self.refresh(&mut state);
        let now = self.clock.now();
        let Window::Waiting(waiting) = &state.window else {
            return Err(CodeError::NoRequest);
        };
        if typed.len() != 6 || !typed.bytes().all(|b| b.is_ascii_digit()) {
            return Err(CodeError::Malformed);
        }
        let hash = pairing_code_hash(
            state.secret.as_slice(),
            &waiting.candidate.request_key,
            &waiting.candidate.approval_key,
        );
        if constant_time_eq(typed.as_bytes(), pairing_code(&hash).as_bytes()) {
            let candidate = waiting.candidate.clone();
            state.deadline = state.deadline.max(now + CONFIRM_GRACE);
            return Ok(candidate);
        }
        let Window::Waiting(waiting) = &mut state.window else {
            return Err(CodeError::NoRequest);
        };
        waiting.wrong_codes += 1;
        let wrong = waiting.wrong_codes;
        if wrong >= MAX_WRONG_CODES {
            self.end_waiting(&mut state, Ended::Denied);
            return Err(CodeError::Closed);
        }
        Err(CodeError::Wrong {
            remaining: MAX_WRONG_CODES - wrong,
        })
    }

    /// Store the device and move the window to "paired", in one step under the pairing
    /// lock. Call it after the owner check for `candidate.action()`. `store` runs only
    /// while the window still waits for exactly this device, and it must store the device
    /// (`Vault::add_companion_device`). When `store` fails the window still waits.
    pub fn complete<T, E>(
        &self,
        candidate: &PairCandidate,
        store: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, CompleteError<E>> {
        let mut state = self.lock();
        self.refresh(&mut state);
        match &state.window {
            Window::Waiting(waiting) if &waiting.candidate == candidate => {}
            _ => return Err(CompleteError::NotWaiting),
        }
        let stored = store().map_err(CompleteError::Store)?;
        self.end_waiting(&mut state, Ended::Paired);
        Ok(stored)
    }

    /// Close the window. A request that waits gets the answer `denied`. It needs no
    /// owner check: it only takes authority away.
    pub fn cancel(&self) {
        let mut state = self.lock();
        self.refresh(&mut state);
        if matches!(state.window, Window::Waiting(_)) {
            self.end_waiting(&mut state, Ended::Denied);
        } else {
            Self::close(&mut state);
        }
    }

    /// End a window that waits for the owner and keep the answer for the phone.
    fn end_waiting(&self, state: &mut State, ended: Ended) {
        if let Window::Waiting(waiting) = &state.window {
            state.outcome = Some(Outcome {
                device_id: waiting.candidate.device_id.clone(),
                proof: waiting.proof,
                ended,
                mac_name: state.mac_name.clone(),
                at: self.clock.now(),
            });
        }
        Self::close(state);
    }

    /// The answer for `GET /v1/pair/<device_id>` (contract 5.5). `proof` is the header
    /// text. `None` for a wrong device ID, a wrong proof, a proof of a bad format, or an
    /// answer that is no longer kept: the caller answers `404 not_found`.
    pub fn status(&self, device_id: &str, proof: &str) -> Option<PairStatus> {
        let proof = decode_fixed::<SECRET_BYTES>(proof)?;
        if !valid_device_id(device_id) {
            return None;
        }
        let mut state = self.lock();
        self.refresh(&mut state);
        let matches = |id: &str, expected: &[u8; SECRET_BYTES]| {
            // Both comparisons run, so a wrong ID and a wrong proof take the same time.
            let id_ok = constant_time_eq(id.as_bytes(), device_id.as_bytes());
            let proof_ok = constant_time_eq(expected, &proof);
            id_ok && proof_ok
        };
        if let Window::Waiting(waiting) = &state.window
            && matches(&waiting.candidate.device_id, &waiting.proof)
        {
            return Some(PairStatus::Waiting);
        }
        let outcome = state.outcome.as_ref()?;
        if !matches(&outcome.device_id, &outcome.proof) {
            return None;
        }
        Some(match outcome.ended {
            Ended::Paired => PairStatus::Paired {
                mac_name: outcome.mac_name.clone(),
            },
            Ended::Denied => PairStatus::Denied,
            Ended::Expired => PairStatus::Expired,
        })
    }
}

impl Default for Pairing {
    fn default() -> Self {
        Self::new()
    }
}

/// The proof of a pair request, as the phone computes it: the HMAC of the pair string
/// under the secret. The tests use it to play the phone.
pub fn pair_proof(secret: &[u8], pair_string: &str) -> [u8; 32] {
    hmac_sha256(secret, pair_string.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::companion::crypto::tests::{TestKey, bytes};
    use crate::native::base64::encode_url;

    const DEVICE: &str = "0123456789abcdef0123456789abcdef";
    const OTHER_DEVICE: &str = "fedcba9876543210fedcba9876543210";

    /// A phone: a device ID and two keys.
    struct Phone {
        device_id: String,
        name: String,
        request: TestKey,
        approval: TestKey,
    }

    impl Phone {
        fn new(device_id: &str, name: &str) -> Self {
            Self {
                device_id: device_id.to_owned(),
                name: name.to_owned(),
                request: TestKey::generate(),
                approval: TestKey::generate(),
            }
        }

        fn string(&self) -> String {
            pair_string(
                &self.device_id,
                &self.name,
                &self.request.public(),
                &self.approval.public(),
            )
            .expect("string")
        }

        /// The pair request as the phone sends it, for a window with `secret`.
        fn request(&self, secret: &[u8]) -> PairRequest {
            let string = self.string();
            PairRequest {
                v: 1,
                device_id: self.device_id.clone(),
                device_name: self.name.clone(),
                request_key: encode_url(&self.request.public()),
                approval_key: encode_url(&self.approval.public()),
                request_key_signature: encode_url(&self.request.sign(&string)),
                approval_key_signature: encode_url(&self.approval.sign(&string)),
                proof: encode_url(&pair_proof(secret, &string)),
            }
        }

        fn proof_text(&self, secret: &[u8]) -> String {
            encode_url(&pair_proof(secret, &self.string()))
        }

        /// The code that this phone shows.
        fn code(&self, secret: &[u8]) -> String {
            let hash = pairing_code_hash(secret, &self.request.public(), &self.approval.public());
            pairing_code(&hash)
        }
    }

    fn setup() -> (Arc<ManualClock>, Pairing) {
        let clock = Arc::new(ManualClock::new(1_790_000_000));
        let pairing = Pairing::with_clock(clock.clone());
        (clock, pairing)
    }

    fn not_paired(_: &str) -> bool {
        false
    }

    fn wrong_code(right: &str) -> String {
        format!(
            "{:06}",
            (right.parse::<u32>().expect("digits") + 1) % 1_000_000
        )
    }

    #[test]
    fn a_window_opens_for_five_minutes_with_a_random_secret() {
        let (_, pairing) = setup();
        assert_eq!(pairing.view(), PairingView::Closed);
        let window = pairing.open("Mac mini").expect("open");
        assert_eq!(window.expires_at, 1_790_000_300);
        assert_ne!(*window.secret, [0u8; 32]);
        assert_eq!(
            pairing.view(),
            PairingView::Open {
                expires_at: 1_790_000_300
            }
        );
        assert!(!format!("{window:?}").contains(&format!("{:?}", window.secret.as_slice())));
        assert!(format!("{window:?}").contains("[redacted]"));
        // Two windows have two secrets.
        pairing.cancel();
        let second = pairing.open("Mac mini").expect("open again");
        assert_ne!(*window.secret, *second.secret);
    }

    #[test]
    fn only_one_window_at_a_time() {
        let (clock, pairing) = setup();
        pairing.open("Mac").expect("open");
        assert_eq!(pairing.open("Mac").unwrap_err(), OpenError::AlreadyOpen);
        // Also while a request waits.
        let window_secret = pairing.lock().secret.clone();
        let phone = Phone::new(DEVICE, "Test iPhone");
        pairing
            .submit(&phone.request(&*window_secret), not_paired)
            .expect("submit");
        assert_eq!(pairing.open("Mac").unwrap_err(), OpenError::AlreadyOpen);
        assert!(
            OpenError::AlreadyOpen
                .message()
                .contains("Nothing was paired.")
        );
        // After the window ended, a new one opens.
        clock.advance(WINDOW_LIFETIME);
        assert!(pairing.open("Mac").is_ok());
    }

    #[test]
    fn a_valid_request_waits_for_the_owner_and_accepts_no_second_request() {
        let (_, pairing) = setup();
        let secret = pairing.open("Mac mini").expect("open").secret;
        let phone = Phone::new(DEVICE, "Test iPhone");
        let accepted = pairing
            .submit(&phone.request(&*secret), not_paired)
            .expect("submit");
        assert_eq!(accepted.expires_at, 1_790_000_300);
        assert_eq!(
            pairing.view(),
            PairingView::Waiting {
                device_id: DEVICE.to_owned(),
                device_name: "Test iPhone".to_owned(),
                expires_at: 1_790_000_300,
                wrong_codes: 0
            }
        );
        // The same phone again, and another phone with the right secret.
        assert_eq!(
            pairing
                .submit(&phone.request(&*secret), not_paired)
                .unwrap_err(),
            PairRequestError::Unauthorized
        );
        let other = Phone::new(OTHER_DEVICE, "Other");
        assert_eq!(
            pairing
                .submit(&other.request(&*secret), not_paired)
                .unwrap_err(),
            PairRequestError::Unauthorized
        );
        // The first request still waits.
        assert!(matches!(
            pairing.view(),
            PairingView::Waiting { device_name, .. } if device_name == "Test iPhone"
        ));
    }

    #[test]
    fn a_request_without_a_window_or_with_a_bad_proof_gets_one_answer() {
        let (_, pairing) = setup();
        let phone = Phone::new(DEVICE, "Test iPhone");
        // No window.
        assert_eq!(
            pairing
                .submit(&phone.request(&[7u8; 32]), not_paired)
                .unwrap_err(),
            PairRequestError::Unauthorized
        );
        // Also with the erased secret of a closed window.
        assert_eq!(
            pairing
                .submit(&phone.request(&[0u8; 32]), not_paired)
                .unwrap_err(),
            PairRequestError::Unauthorized
        );
        // A window with another secret.
        let secret = pairing.open("Mac").expect("open").secret;
        let mut wrong = *secret;
        wrong[0] ^= 1;
        assert_eq!(
            pairing
                .submit(&phone.request(&wrong), not_paired)
                .unwrap_err(),
            PairRequestError::Unauthorized
        );
        // The window is still open and takes the right request.
        assert!(pairing.submit(&phone.request(&*secret), not_paired).is_ok());
        // All refusals map to the same wire error.
        assert_eq!(
            PairRequestError::Unauthorized.code(),
            ErrorCode::Unauthorized
        );
        assert_eq!(PairRequestError::BadRequest.code(), ErrorCode::BadRequest);
        assert_eq!(
            PairRequestError::AlreadyPaired.code(),
            ErrorCode::AlreadyPaired
        );
    }

    #[test]
    fn the_checks_run_in_the_order_of_the_contract() {
        let (_, pairing) = setup();
        let secret = pairing.open("Mac").expect("open").secret;
        let phone = Phone::new(DEVICE, "Test iPhone");
        let calls = std::cell::Cell::new(0);
        let counting = |_: &str| {
            calls.set(calls.get() + 1);
            false
        };

        // 1. A bad format is a 400, also without a valid proof.
        let mut bad = phone.request(&[1u8; 32]);
        bad.device_name = " Test iPhone".to_owned();
        assert_eq!(
            pairing.submit(&bad, counting).unwrap_err(),
            PairRequestError::BadRequest
        );
        let mut bad = phone.request(&*secret);
        bad.v = 2;
        assert_eq!(
            pairing.submit(&bad, counting).unwrap_err(),
            PairRequestError::BadRequest
        );
        // 2. A bad proof is a 401 before the signatures and the device check.
        let mut bad_proof = phone.request(&[1u8; 32]);
        bad_proof.request_key_signature = encode_url(&[0u8; 70]);
        assert_eq!(
            pairing.submit(&bad_proof, counting).unwrap_err(),
            PairRequestError::Unauthorized
        );
        // 3. A right proof with a bad signature is a 401, before the device check.
        let mut bad_signature = phone.request(&*secret);
        let other_key = TestKey::generate();
        bad_signature.approval_key_signature = encode_url(&other_key.sign(&phone.string()));
        assert_eq!(
            pairing.submit(&bad_signature, counting).unwrap_err(),
            PairRequestError::Unauthorized
        );
        let mut swapped = phone.request(&*secret);
        std::mem::swap(
            &mut swapped.request_key_signature,
            &mut swapped.approval_key_signature,
        );
        assert_eq!(
            pairing.submit(&swapped, counting).unwrap_err(),
            PairRequestError::Unauthorized
        );
        // A signature over another name.
        let mut other_name = phone.request(&*secret);
        let renamed = pair_string(
            DEVICE,
            "Other name",
            &phone.request.public(),
            &phone.approval.public(),
        )
        .expect("string");
        other_name.request_key_signature = encode_url(&phone.request.sign(&renamed));
        assert_eq!(
            pairing.submit(&other_name, counting).unwrap_err(),
            PairRequestError::Unauthorized
        );
        assert_eq!(
            calls.get(),
            0,
            "the device check ran only after the signatures"
        );
        // 4. Only then the device check: 409.
        let paired = |id: &str| id == DEVICE;
        assert_eq!(
            pairing
                .submit(&phone.request(&*secret), paired)
                .unwrap_err(),
            PairRequestError::AlreadyPaired
        );
        // A refusal changed nothing: the window is still open.
        assert!(matches!(pairing.view(), PairingView::Open { .. }));
        assert!(pairing.submit(&phone.request(&*secret), counting).is_ok());
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn keys_that_are_not_points_are_refused() {
        let (_, pairing) = setup();
        let secret = pairing.open("Mac").expect("open").secret;
        let phone = Phone::new(DEVICE, "Test iPhone");
        // A key of the right shape that is not on the curve. The phone signs and proves
        // for the changed key, so only the point check can refuse it.
        let mut off_curve = phone.request.public();
        off_curve[64] ^= 1;
        let string = pair_string(DEVICE, "Test iPhone", &off_curve, &phone.approval.public())
            .expect("string");
        let request = PairRequest {
            v: 1,
            device_id: DEVICE.to_owned(),
            device_name: "Test iPhone".to_owned(),
            request_key: encode_url(&off_curve),
            approval_key: encode_url(&phone.approval.public()),
            request_key_signature: encode_url(&phone.request.sign(&string)),
            approval_key_signature: encode_url(&phone.approval.sign(&string)),
            proof: encode_url(&pair_proof(&*secret, &string)),
        };
        assert_eq!(
            pairing.submit(&request, not_paired).unwrap_err(),
            PairRequestError::Unauthorized
        );
    }

    #[test]
    fn the_code_is_accepted_with_spaces_anywhere() {
        let (_, pairing) = setup();
        let secret = pairing.open("Mac mini").expect("open").secret;
        let phone = Phone::new(DEVICE, "Test iPhone");
        pairing
            .submit(&phone.request(&*secret), not_paired)
            .expect("submit");
        let code = phone.code(&*secret);
        let spread: Vec<String> = code.chars().map(String::from).collect();
        for typed in [
            spread.join(" "),
            format!(" {} ", spread.join("  ")),
            format!("{} {} {}", &code[..1], &code[1..5], &code[5..]),
        ] {
            assert!(pairing.check_code(&typed).is_ok(), "{typed:?}");
        }
        assert!(matches!(
            pairing.view(),
            PairingView::Waiting { wrong_codes: 0, .. }
        ));
    }

    #[test]
    fn the_right_code_gives_the_candidate_and_the_owner_pairs_the_device() {
        let (_, pairing) = setup();
        let secret = pairing.open("Mac mini").expect("open").secret;
        let phone = Phone::new(DEVICE, "Test iPhone");
        pairing
            .submit(&phone.request(&*secret), not_paired)
            .expect("submit");
        let code = phone.code(&*secret);
        assert_eq!(code.len(), 6);
        // The owner types it with a space, as the phone shows it.
        let typed = format!("{} {}", &code[..3], &code[3..]);
        let candidate = pairing.check_code(&typed).expect("right code");
        assert_eq!(candidate.device_id, DEVICE);
        assert_eq!(candidate.device_name, "Test iPhone");
        assert_eq!(candidate.request_key.to_vec(), phone.request.public());
        assert_eq!(candidate.approval_key.to_vec(), phone.approval.public());
        match candidate.action() {
            OwnerAction::PairCompanion {
                device_id,
                device_name,
                request_key,
                approval_key,
            } => {
                assert_eq!(device_id, DEVICE);
                assert_eq!(device_name, "Test iPhone");
                assert_eq!(request_key, phone.request.public());
                assert_eq!(approval_key, phone.approval.public());
            }
            other => panic!("wrong action {other:?}"),
        }
        // The phone still sees "waiting" until the device is stored.
        let proof = phone.proof_text(&*secret);
        assert_eq!(pairing.status(DEVICE, &proof), Some(PairStatus::Waiting));
        let stored: Result<u32, CompleteError<()>> =
            pairing.complete(&candidate, || Ok::<u32, ()>(7));
        assert_eq!(stored, Ok(7));
        assert_eq!(pairing.view(), PairingView::Closed);
        assert_eq!(
            pairing.status(DEVICE, &proof),
            Some(PairStatus::Paired {
                mac_name: "Mac mini".to_owned()
            })
        );
        // The window is over: no second request, no second completion.
        assert_eq!(
            pairing
                .submit(&phone.request(&*secret), not_paired)
                .unwrap_err(),
            PairRequestError::Unauthorized
        );
        let again: Result<u32, CompleteError<()>> =
            pairing.complete(&candidate, || Ok::<u32, ()>(8));
        assert_eq!(again, Err(CompleteError::NotWaiting));
    }

    #[test]
    fn the_code_of_another_device_is_wrong() {
        // An attacker who has the link pairs first. Its code is not the code that the
        // owner's phone shows.
        let (_, pairing) = setup();
        let secret = pairing.open("Mac").expect("open").secret;
        let attacker = Phone::new(OTHER_DEVICE, "Attacker");
        let owner_phone = Phone::new(DEVICE, "Test iPhone");
        pairing
            .submit(&attacker.request(&*secret), not_paired)
            .expect("attacker pairs first");
        let owners_code = owner_phone.code(&*secret);
        assert_ne!(owners_code, attacker.code(&*secret));
        assert!(matches!(
            pairing.check_code(&owners_code),
            Err(CodeError::Wrong { .. })
        ));
        // The owner phone got a 401 for its request, and the owner cancels.
        assert_eq!(
            pairing
                .submit(&owner_phone.request(&*secret), not_paired)
                .unwrap_err(),
            PairRequestError::Unauthorized
        );
        pairing.cancel();
        let proof = owner_phone.proof_text(&*secret);
        assert_eq!(pairing.status(DEVICE, &proof), None);
        assert_eq!(
            pairing.status(OTHER_DEVICE, &attacker.proof_text(&*secret)),
            Some(PairStatus::Denied)
        );
    }

    #[test]
    fn three_wrong_codes_close_the_window() {
        let (_, pairing) = setup();
        let secret = pairing.open("Mac").expect("open").secret;
        let phone = Phone::new(DEVICE, "Test iPhone");
        pairing
            .submit(&phone.request(&*secret), not_paired)
            .expect("submit");
        let right = phone.code(&*secret);
        let wrong = wrong_code(&right);
        assert_eq!(
            pairing.check_code(&wrong),
            Err(CodeError::Wrong { remaining: 2 })
        );
        assert_eq!(
            pairing.check_code(&wrong),
            Err(CodeError::Wrong { remaining: 1 })
        );
        assert!(matches!(
            pairing.view(),
            PairingView::Waiting { wrong_codes: 2, .. }
        ));
        assert_eq!(pairing.check_code(&wrong), Err(CodeError::Closed));
        // The window is closed: the right code no longer works.
        assert_eq!(pairing.view(), PairingView::Closed);
        assert_eq!(pairing.check_code(&right), Err(CodeError::NoRequest));
        let proof = phone.proof_text(&*secret);
        assert_eq!(pairing.status(DEVICE, &proof), Some(PairStatus::Denied));
        let result: Result<(), CompleteError<()>> = pairing.complete(
            &PairCandidate {
                device_id: DEVICE.to_owned(),
                device_name: "Test iPhone".to_owned(),
                request_key: phone.request.public().try_into().expect("65"),
                approval_key: phone.approval.public().try_into().expect("65"),
            },
            || Ok(()),
        );
        assert_eq!(result, Err(CompleteError::NotWaiting));
        assert!(
            CodeError::Wrong { remaining: 2 }
                .message()
                .contains("2 tries are left")
        );
        assert!(
            CodeError::Wrong { remaining: 1 }
                .message()
                .contains("1 try is left")
        );
        assert!(CodeError::Closed.message().contains("Nothing was paired."));
    }

    #[test]
    fn a_right_code_in_between_does_not_reset_the_wrong_count() {
        let (_, pairing) = setup();
        let secret = pairing.open("Mac").expect("open").secret;
        let phone = Phone::new(DEVICE, "Test iPhone");
        pairing
            .submit(&phone.request(&*secret), not_paired)
            .expect("submit");
        let right = phone.code(&*secret);
        let wrong = wrong_code(&right);
        assert!(pairing.check_code(&wrong).is_err());
        assert!(pairing.check_code(&wrong).is_err());
        assert!(pairing.check_code(&right).is_ok());
        assert!(matches!(
            pairing.view(),
            PairingView::Waiting { wrong_codes: 2, .. }
        ));
        assert_eq!(pairing.check_code(&wrong), Err(CodeError::Closed));
    }

    #[test]
    fn a_malformed_code_is_not_counted() {
        let (_, pairing) = setup();
        let secret = pairing.open("Mac").expect("open").secret;
        let phone = Phone::new(DEVICE, "Test iPhone");
        // No request yet.
        assert_eq!(pairing.check_code("123456"), Err(CodeError::NoRequest));
        pairing
            .submit(&phone.request(&*secret), not_paired)
            .expect("submit");
        for text in [
            "",
            "12345",
            "1234567",
            "abcdef",
            "12 34 5x",
            "١٢٣٤٥٦",
            "12345\n",
        ] {
            assert_eq!(
                pairing.check_code(text),
                Err(CodeError::Malformed),
                "{text:?}"
            );
        }
        assert!(matches!(
            pairing.view(),
            PairingView::Waiting { wrong_codes: 0, .. }
        ));
        assert_eq!(
            CodeError::Malformed.message(),
            "Type the 6 digits that the iPhone shows."
        );
    }

    #[test]
    fn cancel_gives_denied_and_needs_no_check() {
        let (_, pairing) = setup();
        let secret = pairing.open("Mac").expect("open").secret;
        let phone = Phone::new(DEVICE, "Test iPhone");
        pairing
            .submit(&phone.request(&*secret), not_paired)
            .expect("submit");
        pairing.cancel();
        assert_eq!(pairing.view(), PairingView::Closed);
        assert_eq!(
            pairing.status(DEVICE, &phone.proof_text(&*secret)),
            Some(PairStatus::Denied)
        );
        // A cancel without a window changes nothing.
        pairing.cancel();
        assert_eq!(
            pairing.status(DEVICE, &phone.proof_text(&*secret)),
            Some(PairStatus::Denied)
        );
        // A cancel of an open window with no request leaves no answer.
        let secret = pairing.open("Mac").expect("open").secret;
        pairing.cancel();
        assert_eq!(pairing.view(), PairingView::Closed);
        assert_eq!(
            pairing
                .submit(&phone.request(&*secret), not_paired)
                .unwrap_err(),
            PairRequestError::Unauthorized
        );
    }

    #[test]
    fn an_open_window_expires_after_five_minutes() {
        let (clock, pairing) = setup();
        let secret = pairing.open("Mac").expect("open").secret;
        clock.advance(WINDOW_LIFETIME - Duration::from_secs(1));
        assert!(matches!(pairing.view(), PairingView::Open { .. }));
        clock.advance(Duration::from_secs(1));
        assert_eq!(pairing.view(), PairingView::Closed);
        let phone = Phone::new(DEVICE, "Test iPhone");
        assert_eq!(
            pairing
                .submit(&phone.request(&*secret), not_paired)
                .unwrap_err(),
            PairRequestError::Unauthorized
        );
    }

    #[test]
    fn a_waiting_request_expires_and_the_answer_is_kept_for_five_minutes() {
        let (clock, pairing) = setup();
        let secret = pairing.open("Mac").expect("open").secret;
        let phone = Phone::new(DEVICE, "Test iPhone");
        pairing
            .submit(&phone.request(&*secret), not_paired)
            .expect("submit");
        let proof = phone.proof_text(&*secret);
        clock.advance(WINDOW_LIFETIME - Duration::from_secs(1));
        assert_eq!(pairing.status(DEVICE, &proof), Some(PairStatus::Waiting));
        clock.advance(Duration::from_secs(1));
        assert_eq!(pairing.status(DEVICE, &proof), Some(PairStatus::Expired));
        assert_eq!(pairing.view(), PairingView::Closed);
        // The right code no longer works.
        assert_eq!(
            pairing.check_code(&phone.code(&*secret)),
            Err(CodeError::NoRequest)
        );
        // The answer stays until 5 minutes after the end of the window.
        clock.advance(RESULT_KEEP - Duration::from_secs(1));
        assert_eq!(pairing.status(DEVICE, &proof), Some(PairStatus::Expired));
        clock.advance(Duration::from_secs(1));
        assert_eq!(pairing.status(DEVICE, &proof), None);
    }

    #[test]
    fn the_answer_is_kept_from_the_end_of_the_window_even_when_nobody_asked() {
        let (clock, pairing) = setup();
        let secret = pairing.open("Mac").expect("open").secret;
        let phone = Phone::new(DEVICE, "Test iPhone");
        pairing
            .submit(&phone.request(&*secret), not_paired)
            .expect("submit");
        // Nobody asks during the window. The first call comes 7 minutes after the end.
        clock.advance(WINDOW_LIFETIME + Duration::from_secs(420));
        assert_eq!(pairing.status(DEVICE, &phone.proof_text(&*secret)), None);
        // With the first call 2 minutes after the end, the answer is there.
        let (clock, pairing) = setup();
        let secret = pairing.open("Mac").expect("open").secret;
        pairing
            .submit(&phone.request(&*secret), not_paired)
            .expect("submit");
        clock.advance(WINDOW_LIFETIME + Duration::from_secs(120));
        assert_eq!(
            pairing.status(DEVICE, &phone.proof_text(&*secret)),
            Some(PairStatus::Expired)
        );
    }

    #[test]
    fn the_paired_answer_is_kept_for_five_minutes() {
        let (clock, pairing) = setup();
        let secret = pairing.open("Mac mini").expect("open").secret;
        let phone = Phone::new(DEVICE, "Test iPhone");
        pairing
            .submit(&phone.request(&*secret), not_paired)
            .expect("submit");
        let candidate = pairing.check_code(&phone.code(&*secret)).expect("code");
        pairing
            .complete(&candidate, || Ok::<(), ()>(()))
            .expect("pair");
        let proof = phone.proof_text(&*secret);
        clock.advance(RESULT_KEEP - Duration::from_secs(1));
        assert_eq!(
            pairing.status(DEVICE, &proof),
            Some(PairStatus::Paired {
                mac_name: "Mac mini".to_owned()
            })
        );
        clock.advance(Duration::from_secs(1));
        assert_eq!(pairing.status(DEVICE, &proof), None);
    }

    #[test]
    fn a_right_code_gives_time_for_the_owner_check() {
        let (clock, pairing) = setup();
        let secret = pairing.open("Mac").expect("open").secret;
        let phone = Phone::new(DEVICE, "Test iPhone");
        pairing
            .submit(&phone.request(&*secret), not_paired)
            .expect("submit");
        // The owner types the right code 10 seconds before the window ends.
        clock.advance(WINDOW_LIFETIME - Duration::from_secs(10));
        let candidate = pairing.check_code(&phone.code(&*secret)).expect("code");
        // The owner check takes 60 seconds, more than the rest of the window.
        clock.advance(Duration::from_secs(60));
        assert!(pairing.complete(&candidate, || Ok::<(), ()>(())).is_ok());

        // Without the owner check finishing, the window ends after the grace time.
        let (clock, pairing) = setup();
        let secret = pairing.open("Mac").expect("open").secret;
        pairing
            .submit(&phone.request(&*secret), not_paired)
            .expect("submit");
        clock.advance(WINDOW_LIFETIME - Duration::from_secs(10));
        let candidate = pairing.check_code(&phone.code(&*secret)).expect("code");
        clock.advance(CONFIRM_GRACE + Duration::from_secs(1));
        let stored = std::cell::Cell::new(false);
        let result = pairing.complete(&candidate, || {
            stored.set(true);
            Ok::<(), ()>(())
        });
        assert_eq!(result, Err(CompleteError::NotWaiting));
        assert!(
            !stored.get(),
            "the device is not stored after the window ended"
        );
        assert_eq!(
            pairing.status(DEVICE, &phone.proof_text(&*secret)),
            Some(PairStatus::Expired)
        );
    }

    #[test]
    fn a_failed_store_leaves_the_window_waiting() {
        let (_, pairing) = setup();
        let secret = pairing.open("Mac").expect("open").secret;
        let phone = Phone::new(DEVICE, "Test iPhone");
        pairing
            .submit(&phone.request(&*secret), not_paired)
            .expect("submit");
        let candidate = pairing.check_code(&phone.code(&*secret)).expect("code");
        let failed: Result<(), CompleteError<&str>> = pairing.complete(&candidate, || Err("full"));
        assert_eq!(failed, Err(CompleteError::Store("full")));
        assert!(matches!(pairing.view(), PairingView::Waiting { .. }));
        assert_eq!(
            pairing.status(DEVICE, &phone.proof_text(&*secret)),
            Some(PairStatus::Waiting)
        );
        // The owner can try again.
        assert!(pairing.complete(&candidate, || Ok::<(), &str>(())).is_ok());
    }

    #[test]
    fn complete_names_the_device_that_waits() {
        let (_, pairing) = setup();
        let secret = pairing.open("Mac").expect("open").secret;
        let phone = Phone::new(DEVICE, "Test iPhone");
        pairing
            .submit(&phone.request(&*secret), not_paired)
            .expect("submit");
        let mut other = pairing.check_code(&phone.code(&*secret)).expect("code");
        other.device_id = OTHER_DEVICE.to_owned();
        let ran = std::cell::Cell::new(false);
        let result = pairing.complete(&other, || {
            ran.set(true);
            Ok::<(), ()>(())
        });
        assert_eq!(result, Err(CompleteError::NotWaiting));
        assert!(!ran.get());
        let mut other_key = pairing.check_code(&phone.code(&*secret)).expect("code");
        other_key.approval_key = other_key.request_key;
        assert_eq!(
            pairing.complete(&other_key, || Ok::<(), ()>(())),
            Err(CompleteError::NotWaiting)
        );
    }

    #[test]
    fn status_needs_the_device_id_and_the_right_proof() {
        let (_, pairing) = setup();
        let secret = pairing.open("Mac").expect("open").secret;
        let phone = Phone::new(DEVICE, "Test iPhone");
        // An open window with no request: nothing to answer.
        assert_eq!(pairing.status(DEVICE, &phone.proof_text(&*secret)), None);
        pairing
            .submit(&phone.request(&*secret), not_paired)
            .expect("submit");
        let proof = phone.proof_text(&*secret);
        assert_eq!(pairing.status(DEVICE, &proof), Some(PairStatus::Waiting));
        // Wrong device ID with the right proof.
        assert_eq!(pairing.status(OTHER_DEVICE, &proof), None);
        // Right device ID with a wrong proof, a proof for the same string under another
        // secret, and a proof of a bad format.
        let mut wrong = *secret;
        wrong[5] ^= 1;
        assert_eq!(pairing.status(DEVICE, &phone.proof_text(&wrong)), None);
        assert_eq!(pairing.status(DEVICE, &encode_url(&[0u8; 32])), None);
        assert_eq!(pairing.status(DEVICE, "short"), None);
        assert_eq!(pairing.status(DEVICE, &format!("{proof}=")), None);
        assert_eq!(pairing.status(DEVICE, ""), None);
        // A device ID of a bad format.
        assert_eq!(pairing.status("nope", &proof), None);
        assert_eq!(pairing.status(&DEVICE.to_uppercase(), &proof), None);
    }

    #[test]
    fn the_secret_is_erased_when_the_window_ends() {
        let (_, pairing) = setup();
        pairing.open("Mac").expect("open");
        assert_ne!(*pairing.lock().secret, [0u8; 32]);
        pairing.cancel();
        assert_eq!(*pairing.lock().secret, [0u8; 32]);
    }

    #[test]
    fn a_request_is_valid_only_for_the_window_of_its_secret() {
        // A request that was made for the first window does not work in the second.
        let (_, pairing) = setup();
        let first = pairing.open("Mac").expect("open").secret;
        pairing.cancel();
        let second = pairing.open("Mac").expect("open again").secret;
        let phone = Phone::new(DEVICE, "Test iPhone");
        assert_eq!(
            pairing
                .submit(&phone.request(&*first), not_paired)
                .unwrap_err(),
            PairRequestError::Unauthorized
        );
        assert!(pairing.submit(&phone.request(&*second), not_paired).is_ok());
        assert_eq!(bytes(&encode_url(&*second)), second.to_vec());
    }
}
