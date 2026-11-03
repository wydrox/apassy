//! The host and the trainer of the bouncer brain, as the owner chose them (ADR 0035
//! section 1, plan 0035 unit C2).
//!
//! - [`change`] applies a change of one choice with the proof of a fresh owner check
//!   for exactly that change ([`owner_action`]). The global owner window never covers it
//!   (`OwnerAction::needs_fresh_local_check`). A return to this Mac needs the check too.
//! - [`hosting_client`] builds the client of the chosen host from the vault row: no row
//!   is this Mac (`None`); an own server is an `https://` client with its bearer token
//!   from the vault ([`StaticBearer`]); Apassy Connect needs the Connect sign-in of unit
//!   C3 and is refused until then. The address never comes from `bouncer.json` or from
//!   `APASSY_BOUNCER_URL`: those stay loopback-only.
//!
//! The bouncer gate still decides every run on this Mac. A remote answer that is
//! missing, slow or wrong is "unavailable", and the owner is asked.

use std::sync::Arc;

use zeroize::Zeroizing;

use super::approvals::{OwnerAction, OwnerProof};
use super::bouncer::{BouncerClient, BrainCredential, StaticBearer};
use super::http::TlsClient;
use crate::vault::{
    BouncerHostChange, BouncerHostKind, BouncerHostRole, Vault, VaultError, VaultErrorKind,
};

/// The refusal while this build has no Connect sign-in (plan 0035 unit C3).
pub const CONNECT_UNAVAILABLE: &str = "Apassy Connect hosting needs the Connect sign-in, which this version does not have yet. The bouncer brain runs on this Mac.";

/// The action that the proof of `change` for `role` must name.
pub fn owner_action(role: BouncerHostRole, change: &BouncerHostChange) -> OwnerAction {
    let kind = change.kind;
    let url = change.normalized_url();
    let consent_version = change.consent_version;
    match role {
        BouncerHostRole::Hosting => OwnerAction::ChangeBouncerHosting {
            kind,
            url,
            consent_version,
        },
        BouncerHostRole::Training => OwnerAction::ChangeBouncerTraining {
            kind,
            url,
            consent_version,
        },
    }
}

fn vault_message(error: &VaultError) -> String {
    match error.kind() {
        VaultErrorKind::Locked => "The vault is locked. Nothing changed.".to_owned(),
        VaultErrorKind::InvalidInput => {
            "Nothing changed. The address must be https:// with a host name, and the token must have 16 to 512 characters without spaces.".to_owned()
        }
        _ => format!("Nothing changed. The vault could not store the choice ({error})."),
    }
}

/// The owner changes who hosts or trains the bouncer brain. The proof must name exactly
/// this change ([`owner_action`]) in this vault session. The call holds the vault, so
/// nothing can change between the proof check and the write.
pub fn change(
    vault: &mut Vault,
    role: BouncerHostRole,
    change: &BouncerHostChange,
    proof: OwnerProof,
    now: u64,
) -> Result<(), String> {
    proof
        .check(&owner_action(role, change), &vault.epoch())
        .map_err(|refusal| refusal.message().to_owned())?;
    vault
        .set_bouncer_host(role, change, now)
        .map_err(|error| vault_message(&error))
}

/// The client of the chosen bouncer brain host. `Ok(None)`: this Mac (no row). The
/// bearer of an own server leaves the vault only into the client, which sends it to
/// that server alone.
pub fn hosting_client(
    vault: &Vault,
    tls: &Arc<TlsClient>,
) -> Result<Option<BouncerClient>, String> {
    let host = vault
        .bouncer_host(BouncerHostRole::Hosting)
        .map_err(|error| vault_message(&error))?;
    let Some(host) = host else {
        return Ok(None);
    };
    match host.kind {
        BouncerHostKind::ThisMac => Ok(None),
        BouncerHostKind::Connect => Err(CONNECT_UNAVAILABLE.to_owned()),
        BouncerHostKind::OwnServer => {
            let bearer = vault
                .bouncer_host_bearer(BouncerHostRole::Hosting)
                .map_err(|error| vault_message(&error))?
                .ok_or_else(|| "The server of the bouncer brain has no token in the vault. Choose the server again.".to_owned())?;
            let bearer =
                StaticBearer::new(Zeroizing::new(bearer.expose().to_owned())).ok_or_else(|| {
                    "The token of the bouncer brain server is not valid. Choose the server again."
                        .to_owned()
                })?;
            let credential: Arc<dyn BrainCredential> = Arc::new(bearer);
            BouncerClient::remote(&host.url, credential, Arc::clone(tls))
                .map(Some)
                .map_err(|reason| {
                    format!("The address of the bouncer brain server is refused: {reason}")
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::vault::{HOSTING_CONSENT_VERSION, SecretValue};

    const PASS: &str = "synthetic-brain-host-pass";
    const BEARER: &str = "SYNTH-brain-host-bearer-0123456789";

    fn own(url: &str) -> BouncerHostChange {
        BouncerHostChange {
            kind: BouncerHostKind::OwnServer,
            url: url.to_owned(),
            bearer: Some(SecretValue::new(BEARER.to_owned())),
            consent_version: HOSTING_CONSENT_VERSION,
        }
    }

    fn vault(dir: &tempfile::TempDir) -> Vault {
        let mut vault = Vault::create(&dir.path().join("v.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault
    }

    #[test]
    fn the_proof_names_the_role_the_kind_the_address_and_the_consent() {
        let change = own("https://brain.synthetic.ts.net/");
        assert_eq!(
            owner_action(BouncerHostRole::Hosting, &change),
            OwnerAction::ChangeBouncerHosting {
                kind: BouncerHostKind::OwnServer,
                url: "https://brain.synthetic.ts.net".to_owned(),
                consent_version: HOSTING_CONSENT_VERSION,
            }
        );
        assert_eq!(
            owner_action(BouncerHostRole::Training, &BouncerHostChange::this_mac()),
            OwnerAction::ChangeBouncerTraining {
                kind: BouncerHostKind::ThisMac,
                url: String::new(),
                consent_version: 0,
            }
        );
        assert!(owner_action(BouncerHostRole::Hosting, &change).needs_fresh_local_check());
        // The action names no bearer.
        assert!(!format!("{:?}", owner_action(BouncerHostRole::Hosting, &change)).contains(BEARER));
    }

    #[test]
    fn a_change_needs_a_proof_for_exactly_that_change() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = vault(&dir);
        let epoch = vault.epoch();
        let change_one = own("https://brain.synthetic.ts.net");
        let wrong = [
            OwnerAction::ChangeCalibration { level: 80 },
            owner_action(BouncerHostRole::Training, &change_one),
            owner_action(
                BouncerHostRole::Hosting,
                &own("https://other.synthetic.ts.net"),
            ),
            OwnerAction::ChangeBouncerHosting {
                kind: BouncerHostKind::OwnServer,
                url: "https://brain.synthetic.ts.net".to_owned(),
                consent_version: HOSTING_CONSENT_VERSION + 1,
            },
            owner_action(BouncerHostRole::Hosting, &BouncerHostChange::this_mac()),
        ];
        for action in wrong {
            let proof = OwnerProof::issue_for_test(action.clone(), epoch, Instant::now());
            let refused = change(
                &mut vault,
                BouncerHostRole::Hosting,
                &change_one,
                proof,
                1_700_000_000,
            )
            .unwrap_err();
            assert!(refused.contains("another action"), "{action:?}: {refused}");
        }
        // Another vault session.
        let proof = OwnerProof::issue_for_test(
            owner_action(BouncerHostRole::Hosting, &change_one),
            [9; 32],
            Instant::now(),
        );
        assert!(
            change(&mut vault, BouncerHostRole::Hosting, &change_one, proof, 1)
                .unwrap_err()
                .contains("locked after the owner check")
        );
        // A stale proof.
        let proof = OwnerProof::issue_for_test(
            owner_action(BouncerHostRole::Hosting, &change_one),
            epoch,
            Instant::now()
                - crate::broker::approvals::PROOF_LIFETIME
                - std::time::Duration::from_secs(1),
        );
        assert!(
            change(&mut vault, BouncerHostRole::Hosting, &change_one, proof, 1)
                .unwrap_err()
                .contains("too old")
        );
        assert_eq!(vault.bouncer_host(BouncerHostRole::Hosting).unwrap(), None);

        // The exact proof changes the choice; the return to this Mac needs its own.
        let proof = OwnerProof::issue_for_test(
            owner_action(BouncerHostRole::Hosting, &change_one),
            epoch,
            Instant::now(),
        );
        change(
            &mut vault,
            BouncerHostRole::Hosting,
            &change_one,
            proof,
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(
            vault
                .bouncer_host(BouncerHostRole::Hosting)
                .unwrap()
                .unwrap()
                .kind,
            BouncerHostKind::OwnServer
        );
        let back = BouncerHostChange::this_mac();
        let proof = OwnerProof::issue_for_test(
            owner_action(BouncerHostRole::Hosting, &change_one),
            epoch,
            Instant::now(),
        );
        assert!(change(&mut vault, BouncerHostRole::Hosting, &back, proof, 2).is_err());
        let proof = OwnerProof::issue_for_test(
            owner_action(BouncerHostRole::Hosting, &back),
            epoch,
            Instant::now(),
        );
        change(&mut vault, BouncerHostRole::Hosting, &back, proof, 2).unwrap();
        assert_eq!(vault.bouncer_host(BouncerHostRole::Hosting).unwrap(), None);
    }

    #[test]
    fn this_mac_gives_no_client_and_connect_is_refused_until_its_sign_in() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = vault(&dir);
        let tls = Arc::new(TlsClient::platform().unwrap());
        assert!(hosting_client(&vault, &tls).unwrap().is_none());
        vault
            .set_bouncer_host(
                BouncerHostRole::Hosting,
                &BouncerHostChange {
                    kind: BouncerHostKind::Connect,
                    url: "https://brain.connect.example".to_owned(),
                    bearer: None,
                    consent_version: HOSTING_CONSENT_VERSION,
                },
                1,
            )
            .unwrap();
        assert_eq!(
            hosting_client(&vault, &tls).unwrap_err(),
            CONNECT_UNAVAILABLE
        );
        // An own server gives an https client of that address.
        vault
            .set_bouncer_host(
                BouncerHostRole::Hosting,
                &own("https://brain.synthetic.ts.net"),
                2,
            )
            .unwrap();
        let client = hosting_client(&vault, &tls).unwrap().unwrap();
        assert_eq!(client.url(), "https://brain.synthetic.ts.net");
        assert_eq!(client.port(), None, "not a loopback client");
        // The training choice never changes the host.
        vault
            .set_bouncer_host(
                BouncerHostRole::Training,
                &own("https://trainer.synthetic.ts.net"),
                3,
            )
            .unwrap();
        assert_eq!(
            hosting_client(&vault, &tls).unwrap().unwrap().url(),
            "https://brain.synthetic.ts.net"
        );
    }
}
