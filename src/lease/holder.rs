//! The key holder's lease of one vault item (contract private-sharing-v1 sections 2 and
//! 4.2, plan s6 units F and G): read the source, make the lease, and store a rotated
//! refresh token, one flight per item.
//!
//! - **Single flight.** [`KeyHolder::lease`] holds a lock of the item around the read of
//!   the source, the provider call, and the store of a rotated refresh token. A second
//!   run of the same item waits, then reads the token that the first run stored. Without
//!   it, two runs send the same refresh token, and a provider that rotates refresh
//!   tokens refuses the second (or, with reuse detection, revokes the grant). The crate
//!   has no async runtime: the lock is a `std::sync::Mutex` per item, and a run waits on
//!   its own thread.
//! - **Compare-and-swap.** A rotated token is stored only while the field still holds
//!   the token that was sent (`Vault::swap_secret_field`). When the field changed after
//!   the read (a synced copy of another Mac, or the owner), the newer stored token stays
//!   and the token of this answer is dropped ([`RotationOutcome::KeptNewer`]). When the
//!   provider refuses the refresh token (400 or 401), the source is read once more; a
//!   stored token that differs from the one sent is tried once.
//! - **Stored before the run fails.** A token endpoint that rotates the refresh token in
//!   an answer that is otherwise unusable has already ended the old token, so the new one
//!   is stored before the run fails (the error carries it, [`LeaseError::update_field`]).
//!
//! Only the device that runs the lease refreshes. Synced copies converge by the
//! compare-and-swap and the item revision that it raises. A provider with reuse
//! detection can still revoke the grant when two Macs refresh the same token within the
//! same second, before either copy synced: a documented limit (contract section 4.2).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use super::oauth::{REFRESH_TOKEN_FIELD, ROTATED_NOT_STORED, ROTATED_STORED};
use super::{
    Lease, LeaseError, LeaseKind, LeaseSource, LeaseStatus, ProviderEndpoints, RunScope,
    UpdateField, acquire,
};
use crate::broker::SharedVault;
use crate::broker::http::TlsClient;
use crate::vault::{FieldSwap, SecretValue, VaultErrorKind};

/// What happened to the refresh token of a lease or of a failed lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationOutcome {
    /// The answer kept the refresh token (or the kind has none).
    Unchanged,
    /// The new refresh token is stored.
    Stored,
    /// The field changed after the read (another Mac through sync, or the owner): the
    /// newer stored token stays, and the token of this answer is dropped.
    KeptNewer,
    /// The vault did not store the new token. The caller writes the activity row with
    /// the error and "authorize again" (contract section 4.2).
    NotStored,
}

/// A lease and what happened to its refresh token. The rotated token is stored already:
/// `lease.update_field` is `None`.
#[derive(Debug)]
pub struct Held {
    pub lease: Lease,
    pub rotation: RotationOutcome,
}

/// Why [`KeyHolder::lease`] made no lease. The caller fails the run with `lease_failed`
/// and delivers nothing (contract rule 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeldError {
    /// The vault is locked, or the item has no source row: no provider call.
    Vault(VaultErrorKind),
    /// The lease failed. A refresh token rotated by the failed answer was handled first
    /// (`rotation`); `error.update_field` is `None`.
    Lease {
        error: LeaseError,
        rotation: RotationOutcome,
    },
}

impl fmt::Display for HeldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vault(kind) => write!(
                f,
                "The item cannot make temporary credentials: {kind:?}. {}",
                super::NOT_RUN
            ),
            Self::Lease { error, .. } => f.write_str(&error.message),
        }
    }
}

impl std::error::Error for HeldError {}

/// The key holder of one vault: it makes the leases of its items, one flight per item.
pub struct KeyHolder {
    vault: SharedVault,
    endpoints: ProviderEndpoints,
    tls: Option<Arc<TlsClient>>,
    flights: Mutex<HashMap<u64, Arc<Mutex<()>>>>,
}

impl fmt::Debug for KeyHolder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyHolder")
            .field("endpoints", &self.endpoints)
            .finish_non_exhaustive()
    }
}

impl KeyHolder {
    pub fn new(
        vault: SharedVault,
        endpoints: ProviderEndpoints,
        tls: Option<Arc<TlsClient>>,
    ) -> Self {
        Self {
            vault,
            endpoints,
            tls,
            flights: Mutex::new(HashMap::new()),
        }
    }

    /// The lock of one item's flight.
    fn flight(&self, item: u64) -> Arc<Mutex<()>> {
        let mut flights = self.flights.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(flights.entry(item).or_default())
    }

    /// Make the lease of `item` for one run: read the source, call the provider, and
    /// store a rotated refresh token, under the item's lock. Call it only after the
    /// owner's decision (contract rule 5). The vault is held only to read and to store,
    /// never during the provider call.
    pub fn lease(&self, item: u64, scope: &RunScope) -> Result<Held, HeldError> {
        let flight = self.flight(item);
        let _one = flight.lock().unwrap_or_else(PoisonError::into_inner);
        let mut source = self.read(item)?;
        let mut result = acquire(&source, scope, &self.endpoints, self.tls.as_deref());
        if let Err(error) = &result
            && is_refused(error)
        {
            // Another key holder may have rotated the token after the read: read once
            // more, and try a stored token that differs from the one sent.
            let again = self.read(item)?;
            if refresh_token(&again).is_some() && refresh_token(&again) != refresh_token(&source) {
                source = again;
                result = acquire(&source, scope, &self.endpoints, self.tls.as_deref());
            }
        }
        let sent = refresh_token(&source);
        match result {
            Ok(mut lease) => {
                let rotation = self.store(item, sent, lease.update_field.take());
                Ok(Held { lease, rotation })
            }
            Err(mut error) => {
                let rotation = self.store(item, sent, error.update_field.take());
                if rotation == RotationOutcome::Stored {
                    error.message = error.message.replace(ROTATED_NOT_STORED, ROTATED_STORED);
                }
                Err(HeldError::Lease { error, rotation })
            }
        }
    }

    /// The lease source of `item`, read and checked again under the vault lock. The
    /// variable is the item's binding, or `APASSY_ITEM_<id>` without one.
    fn read(&self, item: u64) -> Result<LeaseSource, HeldError> {
        let guard = self.vault.lock().unwrap_or_else(PoisonError::into_inner);
        let vault = guard
            .as_ref()
            .ok_or(HeldError::Vault(VaultErrorKind::Locked))?;
        let row = vault
            .short_lived(item)
            .map_err(|error| HeldError::Vault(error.kind()))?
            .ok_or(HeldError::Vault(VaultErrorKind::NotFound))?;
        let failed = |error: LeaseError| HeldError::Lease {
            error,
            rotation: RotationOutcome::Unchanged,
        };
        let source = vault.short_lived_source(item).map_err(|_| {
            failed(LeaseError::invalid_source(
                row.kind,
                "its fields are not the fields of its kind.",
            ))
        })?;
        let env_name = vault
            .env_binding(item)
            .ok()
            .flatten()
            .map(|binding| binding.env_name)
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| format!("APASSY_ITEM_{item}"));
        LeaseSource::from_vault(source, &env_name).map_err(failed)
    }

    /// Store a rotated refresh token with the compare-and-swap against `sent`.
    fn store(
        &self,
        item: u64,
        sent: Option<&SecretValue>,
        update: Option<UpdateField>,
    ) -> RotationOutcome {
        let Some(update) = update else {
            return RotationOutcome::Unchanged;
        };
        let Some(sent) = sent else {
            return RotationOutcome::NotStored;
        };
        let mut guard = self.vault.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(vault) = guard.as_mut() else {
            return RotationOutcome::NotStored;
        };
        match vault.swap_secret_field(item, &update.field, sent, &update.value) {
            Ok(FieldSwap::Stored) => RotationOutcome::Stored,
            Ok(FieldSwap::Changed) => RotationOutcome::KeptNewer,
            Err(_) => RotationOutcome::NotStored,
        }
    }
}

/// The refresh token of an `oauth_refresh` source.
fn refresh_token(source: &LeaseSource) -> Option<&SecretValue> {
    (source.kind() == LeaseKind::OauthRefresh)
        .then(|| super::field(&source.fields, REFRESH_TOKEN_FIELD))
        .flatten()
        .map(|field| &field.value)
}

/// The token endpoint refused the refresh token or the client, and rotated nothing.
fn is_refused(error: &LeaseError) -> bool {
    error.kind == LeaseKind::OauthRefresh
        && error.update_field.is_none()
        && matches!(error.status, LeaseStatus::Http(400 | 401))
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;
    use std::time::Duration;

    use serde_json::json;

    use super::*;
    use crate::contracts::CredentialKind;
    use crate::lease::testing::{Reply, Seen, endpoints, fake};
    use crate::lease::{LeaseCode, scan};
    use crate::vault::{Field, ItemDraft, ShortLivedKind, Vault};

    const PASS: &str = "synthetic-key-holder-pass";
    const CLIENT_SECRET: &str = "synthetic-holder-client-secret-0001";
    const REFRESH: &str = "synthetic-holder-refresh-token-0001";
    const ROTATED: &str = "synthetic-holder-refresh-token-0002";
    const NEWER: &str = "synthetic-holder-refresh-token-0009";
    const ACCESS: &str = "synthetic-holder-access-token-0001";
    const SETTINGS: &str = r#"{"token_url":"https://auth.example.test/oauth/token","client_auth":"body","revoke_url":"https://auth.example.test/oauth/revoke"}"#;

    fn field(name: &str, value: &str, secret: bool) -> Field {
        Field {
            name: name.to_owned(),
            value: SecretValue::new(value.to_owned()),
            secret,
        }
    }

    /// A vault with one OAuth source item, shared as the broker shares it.
    fn source_vault(dir: &tempfile::TempDir) -> (SharedVault, u64) {
        let mut vault = Vault::create(&dir.path().join("v.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let item = vault
            .add(ItemDraft {
                title: "Synthetic OAuth".to_owned(),
                kind: CredentialKind::Custom,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![
                    field("client_id", "synthetic-holder-client", false),
                    field("client_secret", CLIENT_SECRET, true),
                    field("refresh_token", REFRESH, true),
                ],
            })
            .unwrap()
            .id;
        vault
            .set_short_lived(item, ShortLivedKind::OauthRefresh, SETTINGS, 1)
            .unwrap();
        (Arc::new(Mutex::new(Some(vault))), item)
    }

    fn stored(vault: &SharedVault, item: u64) -> String {
        let guard = vault.lock().unwrap();
        guard
            .as_ref()
            .unwrap()
            .reveal(item, "refresh_token")
            .unwrap()
            .expose()
            .to_owned()
    }

    fn set_stored(vault: &SharedVault, item: u64, from: &str, to: &str) {
        let mut guard = vault.lock().unwrap();
        let swap = guard
            .as_mut()
            .unwrap()
            .swap_secret_field(
                item,
                "refresh_token",
                &SecretValue::new(from.to_owned()),
                &SecretValue::new(to.to_owned()),
            )
            .unwrap();
        assert_eq!(swap, FieldSwap::Stored);
    }

    fn scope() -> RunScope {
        RunScope {
            run_label: "holder".to_owned(),
            ttl_wanted: 900,
        }
    }

    fn sent(seen: &Seen) -> String {
        seen.form_value("refresh_token").expect("a refresh grant")
    }

    #[test]
    fn a_rotated_token_of_a_failed_answer_is_stored_before_the_run_fails() {
        let dir = tempfile::TempDir::new().unwrap();
        let (vault, item) = source_vault(&dir);
        let (destination, server) = fake(1, |_, _: &Seen| {
            Reply::json(
                200,
                &json!({
                    "access_token": ACCESS,
                    "token_type": "DPoP",
                    "expires_in": 900,
                    "refresh_token": ROTATED
                }),
            )
        });
        let holder = KeyHolder::new(Arc::clone(&vault), endpoints(destination), None);
        let failure = holder.lease(item, &scope()).unwrap_err();
        let seen = server.join().expect("fake token endpoint");
        assert_eq!(sent(&seen[0]), REFRESH);
        let HeldError::Lease { error, rotation } = &failure else {
            panic!("a lease error: {failure:?}");
        };
        // The run fails, and the new refresh token is the stored one.
        assert_eq!(error.code, LeaseCode::LeaseFailed);
        assert_eq!(error.status, LeaseStatus::InvalidAnswer);
        assert_eq!(*rotation, RotationOutcome::Stored);
        assert_eq!(stored(&vault, item), ROTATED);
        assert!(error.update_field.is_none());
        assert!(
            error.message.contains("not a bearer token"),
            "{}",
            error.message
        );
        assert!(error.message.contains(ROTATED_STORED), "{}", error.message);
        assert!(!error.message.contains("authorize the item again"));
        scan::assert_no_secrets(
            format!("{failure} {failure:?}"),
            &[CLIENT_SECRET, REFRESH, ROTATED, ACCESS],
        );
    }

    #[test]
    fn two_concurrent_runs_refresh_one_after_the_other() {
        let dir = tempfile::TempDir::new().unwrap();
        let (vault, item) = source_vault(&dir);
        // A provider that rotates the refresh token at each use and refuses a token that
        // was used already (reuse detection). The first answer is slow, so that a second
        // run without the lock would read the same token meanwhile.
        let current = Arc::new(Mutex::new(REFRESH.to_owned()));
        let (destination, server) = fake(2, move |index, seen: &Seen| {
            if index == 0 {
                std::thread::sleep(Duration::from_millis(300));
            }
            let mut current = current.lock().unwrap();
            if sent(seen) != *current {
                return Reply::json(400, &json!({"error": "invalid_grant"}));
            }
            *current = format!("synthetic-holder-refresh-token-1{index:03}");
            Reply::json(
                200,
                &json!({
                    "access_token": ACCESS,
                    "token_type": "Bearer",
                    "expires_in": 900,
                    "refresh_token": current.as_str()
                }),
            )
        });
        let holder = Arc::new(KeyHolder::new(
            Arc::clone(&vault),
            endpoints(destination),
            None,
        ));
        let start = Arc::new(Barrier::new(2));
        let runs: Vec<_> = (0..2)
            .map(|_| {
                let holder = Arc::clone(&holder);
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    holder.lease(item, &scope()).map(|held| held.rotation)
                })
            })
            .collect();
        for run in runs {
            assert_eq!(run.join().unwrap(), Ok(RotationOutcome::Stored));
        }
        let seen = server.join().expect("fake token endpoint");
        // The second run sent the token that the first run stored.
        assert_eq!(sent(&seen[0]), REFRESH);
        assert_eq!(sent(&seen[1]), "synthetic-holder-refresh-token-1000");
        assert_eq!(stored(&vault, item), "synthetic-holder-refresh-token-1001");
    }

    #[test]
    fn a_token_that_changed_after_the_read_is_kept() {
        let dir = tempfile::TempDir::new().unwrap();
        let (vault, item) = source_vault(&dir);
        // While the provider answers, a synced copy of another Mac stores a newer token.
        let shared = Arc::clone(&vault);
        let (destination, server) = fake(1, move |_, _: &Seen| {
            set_stored(&shared, item, REFRESH, NEWER);
            Reply::json(
                200,
                &json!({"access_token": ACCESS, "expires_in": 900, "refresh_token": ROTATED}),
            )
        });
        let holder = KeyHolder::new(Arc::clone(&vault), endpoints(destination), None);
        let held = holder.lease(item, &scope()).expect("lease");
        server.join().expect("fake token endpoint");
        assert_eq!(held.rotation, RotationOutcome::KeptNewer);
        assert!(held.lease.update_field.is_none());
        assert_eq!(
            stored(&vault, item),
            NEWER,
            "the newer token is not overwritten"
        );
    }

    #[test]
    fn a_refused_token_is_read_again_once() {
        let dir = tempfile::TempDir::new().unwrap();
        let (vault, item) = source_vault(&dir);
        // Another key holder rotated the token after this one read it: the provider
        // refuses the old one, and the newer stored token is tried once.
        let shared = Arc::clone(&vault);
        let (destination, server) = fake(2, move |index, seen: &Seen| {
            if index == 0 {
                assert_eq!(sent(seen), REFRESH);
                set_stored(&shared, item, REFRESH, NEWER);
                return Reply::json(400, &json!({"error": "invalid_grant"}));
            }
            assert_eq!(sent(seen), NEWER);
            Reply::json(
                200,
                &json!({"access_token": ACCESS, "expires_in": 900, "refresh_token": ROTATED}),
            )
        });
        let holder = KeyHolder::new(Arc::clone(&vault), endpoints(destination), None);
        let held = holder.lease(item, &scope()).expect("lease");
        server.join().expect("fake token endpoint");
        assert_eq!(held.rotation, RotationOutcome::Stored);
        assert_eq!(stored(&vault, item), ROTATED);
        // A refusal of the token that is still stored is not tried again.
        let (destination, server) = fake(1, |_, _: &Seen| {
            Reply::json(400, &json!({"error": "invalid_grant"}))
        });
        let holder = KeyHolder::new(Arc::clone(&vault), endpoints(destination), None);
        let failure = holder.lease(item, &scope()).unwrap_err();
        assert_eq!(server.join().expect("fake").len(), 1);
        assert!(matches!(
            failure,
            HeldError::Lease {
                rotation: RotationOutcome::Unchanged,
                ..
            }
        ));
        assert_eq!(stored(&vault, item), ROTATED);
    }
}
