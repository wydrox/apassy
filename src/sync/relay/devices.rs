//! The device calls of relay sync on the first Mac (contract relay-sync-v1, sections 7.1
//! and 9): "Add a Mac…" makes a link and confirms the new Mac with the safety words;
//! "Devices…" lists and removes devices; the last device can delete the relay copy.
//!
//! Each call signs in with the device key of the unlocked vault, or with the key in
//! memory ([`KeySource::Memory`]) on a thread that must not hold the vault. A lock ends
//! a call in flight at once ([`RelaySync::forget`]), and the call fails with `Locked`.
//! Confirming
//! a new Mac gives it authority: the caller runs the owner check
//! (`OwnerAction::ConfirmSyncDevice`) before [`RelaySync::confirm_link`].

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use zeroize::Zeroizing;

use serde::de::IgnoredAny;

use super::{
    ApiError, RelaySync, RelayTransport, Request, Session, call, ended_by_lock, json_request,
    sync_error,
};
use crate::sync::relay_crypto::{decode_b64u, link_code_team, safety_words};
use crate::sync::{RelayRefusal, SyncError};
use crate::vault::{Vault, VaultErrorKind};

/// Where a device call finds the device key of this Mac.
#[derive(Debug, Clone, Copy)]
pub enum KeySource<'a> {
    /// The key in memory, else the relay row of this unlocked vault.
    Vault(&'a Vault),
    /// Only the key in memory, from an earlier call with the vault: for a call on a
    /// thread that must not hold the vault. `Locked` when the vault locked since.
    Memory,
}

impl<'a> From<&'a Vault> for KeySource<'a> {
    fn from(vault: &'a Vault) -> Self {
        Self::Vault(vault)
    }
}

impl<'a> From<&'a mut Vault> for KeySource<'a> {
    fn from(vault: &'a mut Vault) -> Self {
        Self::Vault(vault)
    }
}

/// A live device of the team (`DeviceView`, relay SPEC section 23.5).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeviceView {
    pub id: u64,
    #[serde(default)]
    pub member_id: u64,
    #[serde(default)]
    pub member_name: String,
    pub name: String,
    /// The public key, b64u.
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub key_holder: bool,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub last_seen_at: Option<u64>,
    /// Whether this is the device of the caller.
    #[serde(default)]
    pub current: bool,
}

impl DeviceView {
    /// The public key, X9.63, when it has the right shape.
    pub fn public_key_bytes(&self) -> Option<Vec<u8>> {
        decode_b64u(&self.public_key).filter(|key| key.len() == 65 && key[0] == 0x04)
    }
}

/// A link code works this long after the relay made it (contract section 7.1).
const LINK_CODE_SECONDS: u64 = 10 * 60;

/// A link code of "Add a Mac…". It works once, for 10 minutes. Debug is redacted.
pub struct LinkCode {
    /// `apassy_lnk_<team id>_<64 hex>`.
    pub code: Zeroizing<String>,
    /// The text that the owner pastes on the other Mac: `<relay URL>/link#<code>`.
    pub link: Zeroizing<String>,
    /// Unix time when the code expires.
    pub expires_at: u64,
}

impl fmt::Debug for LinkCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkCode")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// A Mac that asks to join with a link (`LinkView`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingLink {
    pub id: u64,
    pub device_name: String,
    /// The public key of the new Mac, X9.63.
    pub public_key: Vec<u8>,
    pub created_at: u64,
    pub expires_at: u64,
    /// The safety words, computed on this Mac from the code it holds and the key. `None`
    /// for a link of a code that this Mac does not hold (a link that the relay made
    /// before that code): it can only be refused.
    pub safety: Option<String>,
}

#[derive(Deserialize)]
struct LinkView {
    id: u64,
    device_name: String,
    public_key: String,
    #[serde(default)]
    created_at: u64,
    #[serde(default)]
    expires_at: u64,
}

/// `request` of a device call, bound to `session`: a lock ends it at once.
fn bound<'a>(session: &'a Session, mut request: Request<'a>) -> Request<'a> {
    session.bind(&mut request, None);
    request
}

/// The result of a device call of `session`: a call that a lock ended is `Locked`.
fn ended<T>(session: &Session, result: Result<T, ApiError>) -> Result<T, SyncError> {
    ended_by_lock(session, result.map_err(sync_error))
}

impl RelaySync {
    /// The session of `key`: the one in memory, or one from the unlocked vault.
    fn session_from(&self, key: KeySource<'_>) -> Result<Arc<Session>, SyncError> {
        match key {
            KeySource::Vault(vault) => self.session(vault),
            KeySource::Memory => super::lock(&self.session)
                .clone()
                .ok_or(SyncError::Vault(VaultErrorKind::Locked)),
        }
    }

    /// The transport of the synced vault, with the session of `key`.
    fn transport_from(&self, key: KeySource<'_>) -> Result<RelayTransport, SyncError> {
        let state = self.require_state()?;
        let session = self.session_from(key)?;
        Ok(self.transport(session, &state))
    }

    /// `POST /v1/devices/links`: a new link code for another Mac.
    pub fn create_link<'a>(&self, key: impl Into<KeySource<'a>>) -> Result<LinkCode, SyncError> {
        let session = self.session_from(key.into())?;
        #[derive(Deserialize)]
        struct Created {
            secret: String,
            expires_at: u64,
        }
        let created: Created = ended(
            &session,
            session.authed(|bearer| {
                call(
                    &session.url,
                    &bound(
                        &session,
                        json_request(
                            "POST",
                            "/v1/devices/links",
                            Some(bearer),
                            &serde_json::json!({}),
                        ),
                    ),
                )
            }),
        )?;
        let code = Zeroizing::new(created.secret);
        if link_code_team(&code) != Some(session.team_id.as_str()) {
            return Err(SyncError::RelayUnreachable);
        }
        let link = Zeroizing::new(format!("{}/link#{}", session.url.as_str(), code.as_str()));
        Ok(LinkCode {
            code,
            link,
            expires_at: created.expires_at,
        })
    }

    /// `GET /v1/devices/links`: the Macs that wait for a confirmation. With the code
    /// that this Mac holds, each link that the relay made after that code gets its
    /// safety words; an older link is of an older code.
    pub fn pending_links<'a>(
        &self,
        key: impl Into<KeySource<'a>>,
        held: Option<&LinkCode>,
    ) -> Result<Vec<PendingLink>, SyncError> {
        let session = self.session_from(key.into())?;
        let views: Vec<LinkView> = ended(
            &session,
            session.authed(|bearer| {
                call(
                    &session.url,
                    &bound(
                        &session,
                        Request::new("GET", "/v1/devices/links".to_owned(), Some(bearer)),
                    ),
                )
            }),
        )?;
        let mut links = Vec::new();
        for view in views {
            let Some(public_key) =
                decode_b64u(&view.public_key).filter(|key| key.len() == 65 && key[0] == 0x04)
            else {
                continue;
            };
            let safety = held
                .filter(|code| view.created_at >= code.expires_at.saturating_sub(LINK_CODE_SECONDS))
                .map(|code| safety_words(&session.team_id, &code.code, &public_key));
            links.push(PendingLink {
                id: view.id,
                device_name: view.device_name,
                public_key,
                created_at: view.created_at,
                expires_at: view.expires_at,
                safety,
            });
        }
        Ok(links)
    }

    /// `POST /v1/devices/links/{id}/confirm` with the words that this Mac computed. The
    /// caller ran the owner check first. A `409` means that the relay's record of the
    /// new Mac differs: the link is refused, and nothing is added.
    pub fn confirm_link<'a>(
        &self,
        key: impl Into<KeySource<'a>>,
        link: &PendingLink,
    ) -> Result<DeviceView, SyncError> {
        let key = key.into();
        let safety = link
            .safety
            .as_deref()
            .ok_or(SyncError::Relay(RelayRefusal::Conflict))?;
        let session = self.session_from(key)?;
        let path = format!("/v1/devices/links/{}/confirm", link.id);
        let confirmed = session.authed(|bearer| {
            call::<DeviceView>(
                &session.url,
                &bound(
                    &session,
                    json_request(
                        "POST",
                        &path,
                        Some(bearer),
                        &serde_json::json!({"safety": safety}),
                    ),
                ),
            )
        });
        match confirmed {
            Ok(device) => {
                *super::lock(&session.devices) = None;
                Ok(device)
            }
            Err(ApiError::Relay { status: 409, .. }) => {
                let _ = self.refuse_link(key, link.id);
                Err(SyncError::Relay(RelayRefusal::Conflict))
            }
            Err(error) => ended(&session, Err(error)),
        }
    }

    /// `POST /v1/devices/links/{id}/refuse`.
    pub fn refuse_link<'a>(
        &self,
        key: impl Into<KeySource<'a>>,
        link_id: u64,
    ) -> Result<(), SyncError> {
        let session = self.session_from(key.into())?;
        let path = format!("/v1/devices/links/{link_id}/refuse");
        ended(
            &session,
            session.authed(|bearer| {
                call::<IgnoredAny>(
                    &session.url,
                    &bound(
                        &session,
                        json_request("POST", &path, Some(bearer), &serde_json::json!({})),
                    ),
                )
            }),
        )
        .map(|_| ())
    }

    /// `GET /v1/devices`: the live devices of the team.
    pub fn devices<'a>(&self, key: impl Into<KeySource<'a>>) -> Result<Vec<DeviceView>, SyncError> {
        let session = self.session_from(key.into())?;
        ended(&session, session.devices(true))
    }

    /// `DELETE /v1/devices/{id}`: the tokens of that device end at once. The last device
    /// of the owner cannot be removed (`409`). It asks the relay also when the relay
    /// refused this device before: "Turn off" must not trust an old refusal, since a
    /// suspended relay gives the same `401` (contract section 13).
    pub fn remove_device<'a>(
        &self,
        key: impl Into<KeySource<'a>>,
        device_id: u64,
    ) -> Result<(), SyncError> {
        let session = self.session_from(key.into())?;
        session.ask_again();
        let path = format!("/v1/devices/{device_id}");
        ended(
            &session,
            session.authed(|bearer| {
                call::<IgnoredAny>(
                    &session.url,
                    &bound(&session, Request::new("DELETE", path.clone(), Some(bearer))),
                )
            }),
        )?;
        *super::lock(&session.devices) = None;
        Ok(())
    }

    /// The receipts of the current version: which device merged which version, for
    /// "Received by …". Each Mac sends its receipt after a merge. It asks from the
    /// version that this Mac saw, so the answer has no chain of older heads.
    pub fn receipts<'a>(
        &self,
        key: impl Into<KeySource<'a>>,
    ) -> Result<Vec<super::Receipt>, SyncError> {
        let since = self.require_state()?.last_remote_version;
        let transport = self.transport_from(key.into())?;
        ended(
            &transport.session,
            transport
                .head_view(since, Duration::ZERO)
                .map(|view| view.receipts),
        )
    }

    /// "Delete the copy on the relay" (contract section 9, `DELETE /v1/sync`): every
    /// head, receipt, and snapshot goes. Only the owner's device may. Returns the last
    /// version. The local vault and the state do not change. It asks the relay also
    /// when the relay refused this device before, as [`Self::remove_device`].
    pub fn delete_relay_copy<'a>(&self, key: impl Into<KeySource<'a>>) -> Result<u64, SyncError> {
        let key = key.into();
        let since = self.require_state()?.last_remote_version;
        let transport = self.transport_from(key)?;
        let session = self.session_from(key)?;
        session.ask_again();
        let current = ended(&session, transport.head_view(since, Duration::ZERO))?.version;
        #[derive(Deserialize)]
        struct Deleted {
            last_version: u64,
        }
        let deleted: Deleted = ended(
            &session,
            session.authed(|bearer| {
                let mut request = bound(
                    &session,
                    Request::new("DELETE", "/v1/sync".to_owned(), Some(bearer)),
                );
                request.headers.push(("If-Match", format!("\"{current}\"")));
                call(&session.url, &request)
            }),
        )?;
        Ok(deleted.last_version)
    }
}
