//! A device of one relay team with its own key, for calls outside relay sync: the
//! questions of stage 5 (contract relay-questions-v1, sections 10 and 13). The caller
//! builds each request and reads each answer; this type signs in (contract relay-sync-v1
//! section 5), adds the access token, and keeps the retries and the `429` hold of every
//! relay call.
//!
//! The iPhone core uses it with the key of a relay membership of its vault, and with
//! the device of a join that confirms a notifications-only team (plan §A7). Debug is
//! redacted; the key goes with the last holder, and [`RelayMember::close`] ends every
//! call in flight at once (the vault locked).

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use zeroize::Zeroizing;

use super::{ApiError, JoinedDevice, Request, Session, call, json_request};
use crate::sync::relay_crypto::DeviceKey;
use crate::sync::relay_http::{Cancel, RelayUrl};
use crate::sync::{SyncError, relay_crypto::valid_team_id};
use crate::vault::VaultErrorKind;

/// Why a call of [`RelayMember::call`] failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayCallError {
    /// No relay answered, the connection broke, or the answer is not the relay's.
    Unreachable,
    /// The relay answered with an error envelope: its status and code.
    Relay { status: u16, code: String },
    /// A failure on this device: the key, a lock, a removal.
    Sync(SyncError),
}

impl From<ApiError> for RelayCallError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::Unreachable | ApiError::Broken => Self::Unreachable,
            ApiError::Relay { status, code, .. } => Self::Relay { status, code },
            ApiError::Sync(error) => Self::Sync(error),
        }
    }
}

/// A device of one team on one relay, with its key in memory.
pub struct RelayMember {
    session: Arc<Session>,
}

impl fmt::Debug for RelayMember {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayMember")
            .field("url", &self.session.url.as_str())
            .field("team_id", &self.session.team_id)
            .finish_non_exhaustive()
    }
}

impl RelayMember {
    /// The device `device_id` of `team_id` on `relay_url`, with its PKCS#8 key (a relay
    /// membership of the vault).
    pub fn new(
        relay_url: &str,
        team_id: &str,
        device_id: u64,
        key_pkcs8: Zeroizing<Vec<u8>>,
    ) -> Result<Self, SyncError> {
        if !valid_team_id(team_id) || device_id == 0 {
            return Err(SyncError::Damaged);
        }
        let url = RelayUrl::parse(relay_url)?;
        let key = DeviceKey::from_pkcs8(key_pkcs8)?;
        Ok(Self {
            session: Arc::new(Session::new(url, team_id, key, Some(device_id))),
        })
    }

    /// The team on the relay.
    pub fn team_id(&self) -> &str {
        &self.session.team_id
    }

    /// The relay origin.
    pub fn relay_url(&self) -> &str {
        self.session.url.as_str()
    }

    /// The device number on the relay, once known.
    pub fn device_id(&self) -> Option<u64> {
        self.session.device_id()
    }

    /// The kind of the team, `operator` or `connect` (relay-connect-v1 section 2), as the
    /// last sign-in said it. `None` before the first sign-in, and from a relay that does
    /// not say it.
    pub fn team_kind(&self) -> Option<String> {
        self.session.team_kind()
    }

    /// The public key, X9.63 (65 bytes).
    pub fn public_key(&self) -> &[u8] {
        self.session.key.public_key()
    }

    /// An ECDSA P-256 SHA-256 signature by the device key, DER.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SyncError> {
        self.session.key.sign(message)
    }

    /// One call with the access token: `method` on `path` (with its query), a JSON
    /// `body` when given, and a long poll of `wait` (at most 25 s) when the path asks
    /// for one. Returns the `result` of the envelope. A `401` signs in again once.
    pub fn call(
        &self,
        method: &'static str,
        path: &str,
        body: Option<&Value>,
        wait: Duration,
    ) -> Result<Value, RelayCallError> {
        self.call_until(method, path, body, wait, None)
    }

    /// [`Self::call`] that `cancel` ends: a long poll that the caller ends when it has
    /// another question to wait for. A request has one cancel, so a call in flight
    /// with `cancel` ends by `cancel` only: the caller closes it at a lock too. A later
    /// call after [`Self::close`] still fails at once.
    pub(crate) fn call_until(
        &self,
        method: &'static str,
        path: &str,
        body: Option<&Value>,
        wait: Duration,
        cancel: Option<&Cancel>,
    ) -> Result<Value, RelayCallError> {
        let wait = wait.min(super::MAX_WAIT);
        let session = &self.session;
        let closed = || session.cancel.is_closed() || cancel.is_some_and(Cancel::is_closed);
        let result = session.authed(|bearer| {
            let mut request = match body {
                Some(body) => json_request(method, path, Some(bearer), body),
                None => Request::new(method, path.to_owned(), Some(bearer)),
            };
            request.wait = wait;
            session.bind(&mut request, None);
            if let Some(cancel) = cancel {
                if cancel.is_closed() {
                    return Err(ApiError::Sync(SyncError::Vault(VaultErrorKind::Locked)));
                }
                request.cancel = Some(cancel);
            }
            call::<Value>(&session.url, &request)
        });
        match result {
            Err(_) if closed() => Err(RelayCallError::Sync(SyncError::Vault(
                VaultErrorKind::Locked,
            ))),
            other => other.map_err(RelayCallError::from),
        }
    }

    /// Drop the access token, end every call in flight, and refuse every later one.
    pub fn close(&self) {
        self.session.close();
    }
}

impl JoinedDevice {
    /// The device as a [`RelayMember`] that shares this session: for a team that never
    /// holds a copy (a notifications-only team), where the device does not download.
    pub fn member(&self) -> RelayMember {
        RelayMember {
            session: Arc::clone(&self.session),
        }
    }

    /// The PKCS#8 document of the device key, for the vault that keeps it.
    pub fn key_pkcs8(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.session.key.pkcs8().cloned()
    }
}
