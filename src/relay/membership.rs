//! Relay memberships of this Mac for their purposes (stage 5 plan §A1, A6; contract
//! relay-questions-v1 sections 2 and 5).
//!
//! A membership is one key pair of this Mac in one relay team ([`RelayMembership`]). Relay
//! sync uses the membership with the purpose `sync` (`Vault::relay_device`); the
//! questions use the membership with the purpose `questions`:
//!
//! - a vault that syncs through the relay asks through its sync team: "Send questions
//!   through the relay" adds the purpose `questions` to the sync membership
//!   ([`enable_questions`]), with no relay call;
//! - a vault that syncs another way (iCloud Drive) can ask through a notifications-only
//!   team: an ordinary team that never gets a snapshot ([`create_questions_team`]).
//!
//! Turning the questions on also makes the question key of the vault when it has none
//! (`Vault::ensure_question_key`) and registers this Mac as a trusted device with the
//! public key of the membership and its device number in the team. The row syncs to the
//! other devices, which then accept its answers. Turning them off takes the purpose away
//! and never touches relay sync ([`disable_questions`]).
//!
//! The creation of a team (`POST /v1/teams`, contract relay-sync-v1 section 6) is shared
//! with relay sync ([`create_team_on_relay`]).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::sync::relay::{call, clean_name, json_request, sync_error};
use crate::sync::relay_crypto::valid_team_id;
use crate::sync::{DeviceKey, RelayRefusal, RelayUrl, SyncError, valid_team_code};
use crate::vault::{
    MembershipPurpose, RelayMembership, TrustedDevice, TrustedDeviceKind, Vault, VaultErrorKind,
    VaultResult,
};

/// A new team on the relay: its ID and the device number of its first device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CreatedTeam {
    pub(crate) team_id: String,
    pub(crate) device_id: u64,
}

/// `POST /v1/teams` with the operator team code: a new team named `team` with the key
/// `key` as its first device, named `device` (relay-sync-v1 section 6). The team code
/// must have its form; the caller checks it.
pub(crate) fn create_team_on_relay(
    url: &RelayUrl,
    team_code: &str,
    team: &str,
    device: &str,
    key: &DeviceKey,
) -> Result<CreatedTeam, SyncError> {
    #[derive(Serialize)]
    struct NewTeam<'a> {
        code: &'a str,
        team: &'a str,
        owner: &'a str,
        device_name: &'a str,
        public_key: &'a str,
    }
    #[derive(Deserialize)]
    struct Created {
        team_id: String,
        device_id: u64,
    }
    let created: Created = call(
        url,
        &json_request(
            "POST",
            "/v1/teams",
            None,
            &NewTeam {
                code: team_code,
                team,
                owner: "owner",
                device_name: &clean_name(device, "Mac"),
                public_key: &key.public_key_b64u(),
            },
        ),
    )
    .map_err(sync_error)?;
    if !valid_team_id(&created.team_id) || created.device_id == 0 {
        return Err(SyncError::RelayUnreachable);
    }
    Ok(CreatedTeam {
        team_id: created.team_id,
        device_id: created.device_id,
    })
}

/// Whether this Mac can send the questions of the open vault through the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuestionsAvailability {
    /// On: the membership of this team carries them.
    On { team_id: String },
    /// Off; the relay sync team of the vault can carry them, with no relay call.
    CanTurnOn { team_id: String },
    /// Off; the vault is not on the relay. A notifications-only team needs a team code.
    NeedsTeam,
}

/// The membership with the purpose `questions`, or `None`. At most one is used: the
/// first by team.
pub fn questions_membership(vault: &Vault) -> VaultResult<Option<RelayMembership>> {
    Ok(vault
        .relay_memberships()?
        .into_iter()
        .find(|membership| membership.purposes.contains(&MembershipPurpose::Questions)))
}

/// What "Send questions through the relay" can do for the open vault. Off by default:
/// only a membership with the purpose `questions` turns it on.
pub fn questions_availability(vault: &Vault) -> VaultResult<QuestionsAvailability> {
    if let Some(membership) = questions_membership(vault)? {
        return Ok(QuestionsAvailability::On {
            team_id: membership.team_id,
        });
    }
    Ok(match vault.relay_device()? {
        Some(device) => QuestionsAvailability::CanTurnOn {
            team_id: device.team_id,
        },
        None => QuestionsAvailability::NeedsTeam,
    })
}

/// Turn the questions on through the relay sync team of the vault: the sync membership
/// gets the purpose `questions`, the vault gets a question key when it has none, and this
/// Mac registers as a trusted device named `device_name`. No relay call. `NotEnabled`:
/// the vault does not sync through the relay ([`create_questions_team`] then).
pub fn enable_questions(vault: &mut Vault, device_name: &str) -> Result<TrustedDevice, SyncError> {
    if let Some(membership) = questions_membership(vault)? {
        vault.ensure_question_key()?;
        return Ok(register_this_device(vault, &membership, device_name)?);
    }
    let sync = vault.relay_device()?.ok_or(SyncError::NotEnabled)?;
    let mut membership = vault
        .relay_membership(&sync.team_id)?
        .ok_or(SyncError::NotEnabled)?;
    membership.purposes.insert(MembershipPurpose::Questions);
    vault.set_membership_purposes(&membership.team_id, &membership.purposes)?;
    vault.ensure_question_key()?;
    Ok(register_this_device(vault, &membership, device_name)?)
}

/// Turn the questions on through a new notifications-only team (plan A6): a new device
/// key, `POST /v1/teams` with the operator team code, and a membership with the purpose
/// `questions` only, so relay sync stays as it is and the team never gets a snapshot.
/// Then the question key and the trusted device, as [`enable_questions`].
pub fn create_questions_team(
    vault: &mut Vault,
    relay_url: &str,
    team_code: &str,
    vault_name: &str,
    device_name: &str,
) -> Result<TrustedDevice, SyncError> {
    if vault.is_locked() {
        return Err(SyncError::Vault(VaultErrorKind::Locked));
    }
    if questions_membership(vault)?.is_some() {
        return Err(SyncError::AlreadyEnabled);
    }
    let url = RelayUrl::parse(relay_url)?;
    let team_code = team_code.trim();
    if !valid_team_code(team_code) {
        return Err(SyncError::Relay(RelayRefusal::InviteInvalid));
    }
    let key = DeviceKey::generate()?;
    let team = clean_name(vault_name, "Vault");
    let created = create_team_on_relay(&url, team_code, &team, device_name, &key)?;
    let membership = RelayMembership {
        team_id: created.team_id,
        relay_url: url.as_str().to_owned(),
        device_id: created.device_id,
        public_key: key.public_key().to_vec(),
        key_pkcs8: key
            .pkcs8()
            .cloned()
            .unwrap_or_else(|| Zeroizing::new(Vec::new())),
        purposes: BTreeSet::from([MembershipPurpose::Questions]),
        created_at: 0,
    };
    vault.add_relay_membership(&membership)?;
    vault.ensure_question_key()?;
    Ok(register_this_device(vault, &membership, device_name)?)
}

/// Turn the questions off on this Mac: the membership loses the purpose `questions`; a
/// notifications-only membership goes with its key. Relay sync is never touched. The
/// trusted device row stays, so an answer that is on its way still verifies. Returns
/// whether they were on.
pub fn disable_questions(vault: &mut Vault) -> VaultResult<bool> {
    let Some(membership) = questions_membership(vault)? else {
        return Ok(false);
    };
    let mut rest = membership.purposes.clone();
    rest.remove(&MembershipPurpose::Questions);
    if rest.is_empty() {
        vault.remove_relay_membership(&membership.team_id)?;
    } else {
        vault.set_membership_purposes(&membership.team_id, &rest)?;
    }
    Ok(true)
}

/// The trusted device row of this Mac for `membership`: the live Mac row with the
/// public key of the membership. `None` when it is not registered.
pub fn this_device(
    vault: &Vault,
    membership: &RelayMembership,
) -> VaultResult<Option<TrustedDevice>> {
    Ok(vault.trusted_devices()?.into_iter().find(|device| {
        device.kind == TrustedDeviceKind::Mac && device.sign_key == membership.public_key
    }))
}

/// Register this Mac as a trusted device for `membership`, or bring its row up to date:
/// the name, the public key of the membership (`sign_key`), and its device number in the
/// team. A new row gets a new random UUID.
pub fn register_this_device(
    vault: &mut Vault,
    membership: &RelayMembership,
    device_name: &str,
) -> VaultResult<TrustedDevice> {
    let name = clean_name(device_name, "Mac");
    let uuid = match this_device(vault, membership)? {
        Some(device) if device.name == name => device.uuid,
        Some(device) => {
            vault.register_trusted_device(
                &device.uuid,
                &name,
                TrustedDeviceKind::Mac,
                &membership.public_key,
                None,
            )?;
            device.uuid
        }
        None => {
            let uuid = new_device_uuid()?;
            vault.register_trusted_device(
                &uuid,
                &name,
                TrustedDeviceKind::Mac,
                &membership.public_key,
                None,
            )?;
            uuid
        }
    };
    vault.set_trusted_device_relay_id(&uuid, &membership.team_id, membership.device_id)?;
    vault
        .trusted_device(&uuid)?
        .ok_or_else(|| crate::vault::VaultError::new(VaultErrorKind::Storage))
}

/// A random UUID (version 4) in the form of the contract: 36 lowercase characters
/// `8-4-4-4-12`.
pub fn new_device_uuid() -> VaultResult<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|_| crate::vault::VaultError::new(VaultErrorKind::Storage))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

/// A device UUID of the contract form: 36 lowercase characters `8-4-4-4-12`.
pub fn valid_device_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(at, byte)| match at {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_device_uuid_has_the_contract_form() {
        let a = new_device_uuid().unwrap();
        let b = new_device_uuid().unwrap();
        assert!(valid_device_uuid(&a), "{a}");
        assert_ne!(a, b);
        assert!(valid_device_uuid("0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d"));
        for bad in [
            "",
            "0B7E5C3A-9D1F-4A2B-8C6D-4E0F1A2B3C4D",
            "0b7e5c3a9d1f4a2b8c6d4e0f1a2b3c4d",
            "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4",
            "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4g",
        ] {
            assert!(!valid_device_uuid(bad), "{bad}");
        }
    }

    #[test]
    fn questions_go_on_through_the_sync_team_and_off_without_touching_sync() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("m.db"), "synthetic-member-pass").unwrap();
        vault.unlock("synthetic-member-pass").unwrap();
        assert_eq!(
            questions_availability(&vault).unwrap(),
            QuestionsAvailability::NeedsTeam
        );
        assert!(matches!(
            enable_questions(&mut vault, "Synthetic Mac"),
            Err(SyncError::NotEnabled)
        ));
        let key = DeviceKey::generate().unwrap();
        vault
            .set_relay_device(&crate::vault::RelayDevice {
                relay_url: "https://relay.example.test".to_owned(),
                team_id: "t_7k2m5q4x3c".to_owned(),
                device_id: 2,
                public_key: key.public_key().to_vec(),
                key_pkcs8: key.pkcs8().unwrap().clone(),
                created_at: 0,
            })
            .unwrap();
        assert_eq!(
            questions_availability(&vault).unwrap(),
            QuestionsAvailability::CanTurnOn {
                team_id: "t_7k2m5q4x3c".to_owned()
            }
        );
        assert!(vault.question_key().unwrap().is_none());
        let device = enable_questions(&mut vault, "Synthetic Mac").unwrap();
        assert!(valid_device_uuid(&device.uuid));
        assert_eq!(device.kind, TrustedDeviceKind::Mac);
        assert_eq!(device.sign_key, key.public_key());
        assert_eq!(device.relay_devices.get("t_7k2m5q4x3c"), Some(&2));
        assert!(vault.question_key().unwrap().is_some());
        assert_eq!(
            questions_availability(&vault).unwrap(),
            QuestionsAvailability::On {
                team_id: "t_7k2m5q4x3c".to_owned()
            }
        );
        // Again: the same row and the same key.
        let key_id = vault.question_key().unwrap().unwrap().key_id();
        let again = enable_questions(&mut vault, "Synthetic Mac").unwrap();
        assert_eq!(again.uuid, device.uuid);
        assert_eq!(vault.question_key().unwrap().unwrap().key_id(), key_id);
        assert_eq!(vault.trusted_devices().unwrap().len(), 1);

        assert!(disable_questions(&mut vault).unwrap());
        assert!(!disable_questions(&mut vault).unwrap());
        assert_eq!(
            vault.relay_device().unwrap().unwrap().team_id,
            "t_7k2m5q4x3c",
            "relay sync stays"
        );
        assert_eq!(
            questions_availability(&vault).unwrap(),
            QuestionsAvailability::CanTurnOn {
                team_id: "t_7k2m5q4x3c".to_owned()
            }
        );
    }
}
