//! Account-free, questions-only onboarding. No operator code, account, or sync entitlement.
use crate::sync::relay::{clean_name, json_request};
use crate::sync::relay_http;
use crate::sync::{DeviceKey, RelayUrl, SyncError, decode_b64u, encode_b64u};
use crate::vault::{MembershipPurpose, PendingConnect, RelayMembership, Vault};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::BTreeSet;
use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, PartialEq, Eq)]
pub enum ConnectError {
    Sync(SyncError),
    Offline,
    KeyUsed,
    DailyCapacity,
    TotalCapacity,
    NetworkLimit,
    TryLater(u64),
    Unsupported,
    Refused,
    OriginChanged,
}
impl From<SyncError> for ConnectError {
    fn from(e: SyncError) -> Self {
        Self::Sync(e)
    }
}
impl From<crate::vault::VaultError> for ConnectError {
    fn from(e: crate::vault::VaultError) -> Self {
        Self::Sync(e.into())
    }
}
impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Offline => "Connect could not reach the relay. Check your internet connection and try again. Your connection key is saved; retrying uses the same key.",
            Self::KeyUsed => "The relay has already used this connection key, but could not recover the connection. This relay may not support recovery yet, or the connection was removed. Your key is saved. Try again after the relay is updated, or contact relay support. Apassy will not create another connection with a new key.",
            Self::DailyCapacity => "Connect has reached the relay's daily creation limit (normally 50 connections per 24 hours), or new connections are temporarily off. Try again in an hour. Your saved key will be reused.",
            Self::TotalCapacity => "Connect has no room for a new connection (normally 100 connections in total). Try again later or contact relay support. Your saved key will be reused.",
            Self::TryLater(seconds) => return write!(f, "Connect asks you to wait {seconds} seconds before trying again. Your connection key is saved and will be reused."),
            Self::NetworkLimit => "This network has reached Connect's creation limit (up to 5 connections per day). Wait until tomorrow and try again. Your saved key will be reused.",
            Self::Unsupported => "This relay does not support Connect. Update the relay, then try again.",
            Self::OriginChanged => "A connection is already waiting at another relay address. Retry with that address so Apassy can reuse its saved key.",
            Self::Refused => "The relay could not complete Connect. Nothing was enabled. Your connection key is saved; try again later.",
            Self::Sync(e) => return write!(f, "{e}"),
        })
    }
}

/// Commit a stable key and request labels before returning anything that can send a request.
/// A retry after a lock/restart reads this same row, even if labels have since changed.
pub fn prepare_connect(
    vault: &mut Vault,
    relay: &str,
    team: &str,
    device: &str,
) -> Result<PendingConnect, ConnectError> {
    let url = RelayUrl::parse(relay)?;
    if let Some(pending) = vault.pending_connect()? {
        if pending.relay_url != url.as_str() {
            return Err(ConnectError::OriginChanged);
        }
        return Ok(pending);
    }
    if super::membership::questions_membership(vault)?.is_some()
        || super::membership::existing_questions_team(vault)?.is_some()
    {
        return Err(SyncError::AlreadyEnabled.into());
    }
    let key = DeviceKey::generate()?;
    let pending = PendingConnect {
        relay_url: url.as_str().to_owned(),
        team_name: label(team, "Vault"),
        device_name: label(device, "Mac"),
        key_pkcs8: key.pkcs8().cloned().ok_or(ConnectError::Refused)?,
        created: None,
    };
    vault.keep_pending_connect(&pending)?;
    Ok(pending)
}

fn label(name: &str, fallback: &str) -> String {
    let name = clean_name(name, fallback);
    let mut out = String::new();
    for c in name.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > 64 {
            break;
        }
        out.push(c);
    }
    if out.trim().is_empty() {
        fallback.to_owned()
    } else {
        out
    }
}

#[derive(Deserialize)]
struct Created {
    team_id: String,
    device_id: u64,
    kind: String,
}
#[derive(Deserialize)]
struct Challenge {
    nonce: String,
    origin: String,
    expires_at: u64,
}
#[derive(Serialize)]
struct Create<'a> {
    v: u8,
    team: &'a str,
    device_name: &'a str,
    public_key: &'a str,
    signature: String,
    // Omit on legacy 0.5.8, whose request parser refuses unknown fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_nonce: Option<&'a str>,
}
#[derive(Debug)]
enum Failure {
    Offline,
    Backoff(u64),
    Relay(u16, String, String),
}

/// A single bounded request: a capacity refusal is presented immediately, never retried in a loop.
fn post<T: DeserializeOwned>(
    url: &RelayUrl,
    path: &str,
    body: &impl Serialize,
) -> Result<T, Failure> {
    let mut request = json_request("POST", path, None, body);
    request.deadline = Some(Instant::now() + Duration::from_secs(30));
    let answer = relay_http::exchange(url, &request).map_err(|_| Failure::Offline)?;
    if answer.status == 429
        && let Some(seconds) = answer
            .header("retry-after")
            .and_then(|s| s.parse::<u64>().ok())
    {
        return Err(Failure::Backoff(seconds.clamp(1, 86_400)));
    }
    if matches!(answer.status, 404 | 405) {
        return Err(Failure::Relay(
            answer.status,
            "not_found".to_owned(),
            String::new(),
        ));
    }
    #[derive(Deserialize)]
    struct Envelope<T> {
        ok: bool,
        result: Option<T>,
        error: Option<Error>,
    }
    #[derive(Deserialize)]
    struct Error {
        code: String,
        #[serde(default)]
        message: String,
    }
    let envelope: Envelope<T> =
        serde_json::from_slice(&answer.body).map_err(|_| Failure::Offline)?;
    if envelope.ok && (200..300).contains(&answer.status) {
        envelope.result.ok_or(Failure::Offline)
    } else {
        let error = envelope.error.ok_or(Failure::Offline)?;
        Err(Failure::Relay(answer.status, error.code, error.message))
    }
}
fn failure(error: Failure) -> ConnectError {
    match error {
        Failure::Offline => ConnectError::Offline,
        Failure::Backoff(seconds) => ConnectError::TryLater(seconds),
        Failure::Relay(409, code, _) if code == "connect_key_used" => ConnectError::KeyUsed,
        Failure::Relay(503, _, message) if message.contains("no room") => {
            ConnectError::TotalCapacity
        }
        Failure::Relay(503, _, _) => ConnectError::DailyCapacity,
        Failure::Relay(429, _, _) => ConnectError::NetworkLimit,
        Failure::Relay(404, _, _) => ConnectError::Unsupported,
        _ => ConnectError::Refused,
    }
}

/// Only a persisted attempt can be sent. One retry after a lost response uses exactly its key.
/// `connect_key_used` feature-detects F06 via a fresh challenge, never via a version string.
pub fn create_connect(pending: &PendingConnect) -> Result<RelayMembership, ConnectError> {
    let url = RelayUrl::parse(&pending.relay_url)?;
    let key = DeviceKey::from_pkcs8(pending.key_pkcs8.clone())?;
    let created = if let Some((team_id, device_id)) = &pending.created {
        Created {
            team_id: team_id.clone(),
            device_id: *device_id,
            kind: "connect".to_owned(),
        }
    } else {
        let public = key.public_key_b64u();
        let mut message =
            format!("apassy-relay connect v1\0{}\0{public}", url.as_str()).into_bytes();
        let request = Create {
            v: 1,
            team: &pending.team_name,
            device_name: &pending.device_name,
            public_key: &public,
            signature: encode_b64u(&key.sign(&message)?),
            recovery_nonce: None,
        };
        let first = post::<Created>(&url, "/v1/connect", &request);
        let result = match first {
            Err(Failure::Offline) => post(&url, "/v1/connect", &request),
            other => other,
        };
        match result {
            Ok(created) => created,
            Err(Failure::Relay(409, code, _)) if code == "connect_key_used" => {
                #[derive(Serialize)]
                struct Ask<'a> {
                    public_key: &'a str,
                }
                let challenge: Challenge = post(
                    &url,
                    "/v1/connect/challenge",
                    &Ask {
                        public_key: &public,
                    },
                )
                .map_err(|error| match error {
                    Failure::Relay(404 | 405, _, _) => ConnectError::KeyUsed,
                    other => failure(other),
                })?;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                if challenge.origin.trim_end_matches('/') != url.as_str()
                    || challenge.expires_at <= now
                    || challenge.expires_at > now.saturating_add(120)
                    || !decode_b64u(&challenge.nonce).is_some_and(|n| n.len() == 32)
                {
                    return Err(ConnectError::Refused);
                }
                message.extend_from_slice(b"\0recovery\0");
                message.extend_from_slice(challenge.nonce.as_bytes());
                let request = Create {
                    signature: encode_b64u(&key.sign(&message)?),
                    recovery_nonce: Some(&challenge.nonce),
                    ..request
                };
                post(&url, "/v1/connect", &request).map_err(failure)?
            }
            Err(error) => return Err(failure(error)),
        }
    };
    if !crate::sync::relay_crypto::valid_team_id(&created.team_id)
        || created.device_id == 0
        || created.kind != "connect"
    {
        return Err(ConnectError::Refused);
    }
    Ok(RelayMembership {
        team_id: created.team_id,
        relay_url: pending.relay_url.clone(),
        device_id: created.device_id,
        public_key: key.public_key().to_vec(),
        key_pkcs8: pending.key_pkcs8.clone(),
        purposes: BTreeSet::from([MembershipPurpose::Questions]),
        created_at: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn connect_capacity_errors_explain_the_different_bounds() {
        assert_eq!(
            failure(Failure::Relay(
                503,
                "busy".into(),
                "The relay has no room for new teams now.".into()
            )),
            ConnectError::TotalCapacity
        );
        assert_eq!(
            failure(Failure::Relay(
                503,
                "busy".into(),
                "The relay made its teams of the day.".into()
            )),
            ConnectError::DailyCapacity
        );
        assert!(ConnectError::TotalCapacity.to_string().contains("100"));
        assert!(ConnectError::DailyCapacity.to_string().contains("50"));
        assert!(ConnectError::NetworkLimit.to_string().contains("tomorrow"));
    }
}
