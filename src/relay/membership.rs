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
//! - a second Mac of a vault that already has a questions team joins that team with a
//!   device link from a Mac in it ([`join_questions_team`]); a vault never gets a second
//!   questions team ([`existing_questions_team`]).
//!
//! Turning the questions on (after the owner check for
//! `OwnerAction::EnableRelayQuestions`) also makes the question key of the vault when it
//! has none (`Vault::ensure_question_key`) and registers this Mac as a trusted device with
//! the public key of the membership and its device number in the team. Only these calls
//! write the row of a Mac; the questions waiter never does. The row of an iPhone or an
//! Apple Watch is written by the Mac that confirms its link ([`register_linked_device`]),
//! from the keys of the link. The rows sync to the other devices, which then accept their answers.
//! Turning them off takes the purpose away and never touches relay sync
//! ([`disable_questions`]).
//!
//! A device that the owner removed (its row has `deleted_at`) never registers its keys
//! again (`Vault::trusted_key_removed`): this Mac then shows "removed" until the owner
//! turns the questions on again with a new key.
//!
//! The creation of a team (`POST /v1/teams`, contract relay-sync-v1 section 6) is shared
//! with relay sync ([`create_team_on_relay`]).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::sync::relay::{call, clean_name, json_request, sync_error};
use crate::sync::relay_crypto::valid_team_id;
use crate::sync::{DeviceKey, RelayRefusal, RelayUrl, SyncError, valid_team_code};
use crate::vault::{
    MembershipPurpose, RelayMembership, TrustedDevice, TrustedDeviceKind, Vault, VaultErrorKind,
    VaultResult,
};

/// The Apassy release that ends the free paths on the hosted relay (ADR 0037 D14, stage 7):
/// the questions-only Connect path of ADR 0032 and relay sync on
/// `apassy-relay.wyderka.cc`. The notice ships two releases before (R1 = 0.5.17,
/// implementation plan s7 section 5). The owner moved the end from 0.5.19 to 0.5.20 on
/// 2026-11-06, because Apassy Connect has no sign-in in the app yet. A later slip changes
/// it here and in the iPhone app (`VaultText.swift`, `FreeRelayNotice.endVersion`); a test
/// checks that both say the same.
pub const FREE_RELAY_PATHS_END_VERSION: &str = "0.5.20";

/// Whether `url` is the hosted relay (`DEFAULT_RELAY_URL`), whose free paths end with
/// [`FREE_RELAY_PATHS_END_VERSION`]. A relay that the owner runs is never the hosted one.
pub fn on_hosted_relay(url: &str) -> bool {
    RelayUrl::parse(url).is_ok_and(|url| url.as_str() == crate::sync::DEFAULT_RELAY_URL)
}

/// The sync membership of `vault` when it is a vault store of Apassy Connect (plan s7
/// unit M3, connect-account-v1 section 8): a membership whose device key is the Connect
/// account device key of this Mac. Its row keeps the public key of that key and no
/// private key (schema 34, `key_source = 'account'`); the account signs its sign-ins and
/// heads (`crate::sync::RelaySync::set_account_signer`). `None` for a vault that syncs
/// another way or with a key of its own.
pub fn connect_store_membership(vault: &Vault) -> VaultResult<Option<crate::vault::RelayDevice>> {
    Ok(vault.relay_device()?.filter(|row| row.uses_account_key()))
}

/// Whether `membership` signs with the Connect account key: its row holds no private key
/// (only an account row of schema 34 has none).
pub fn signs_with_account_key(membership: &RelayMembership) -> bool {
    membership.key_pkcs8.is_empty()
}

/// A new team on the relay: its ID and the device number of its first device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CreatedTeam {
    pub(crate) team_id: String,
    pub(crate) device_id: u64,
}

/// `POST /v1/teams` with the operator team code: a new team named `team` with the key
/// `key` as its first device, named `device` (relay-sync-v1 section 6). The team code
/// must have its form; the caller checks it.
///
/// `url` brings its trust: a pinned node (the team code of kind `node` of a node pairing
/// link, node-pairing-v1 section 6; plan S2–S3 unit L4) gets the request only after its
/// leaf certificate matches the pin, at its origin or an alternative; another
/// certificate is `PinMismatch` before any request byte. A hosted address keeps system
/// trust.
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
    /// Off; the vault is not on the relay and has no questions team. A
    /// Connect makes a questions-only team without an account or operator code.
    NeedsTeam,
    /// Off; the vault has a questions team that this Mac is not in: it joins with a
    /// device link from a Mac in it ([`join_questions_team`]), never with a new team.
    JoinTeam { team_id: String },
    /// The owner removed this Mac from the questions: the key of its membership is the
    /// key of a removed device. `sync`: the key is the relay sync key of the vault, so
    /// only a new join of relay sync gives a new key; else turning the questions on
    /// drops the old key and joins the team again.
    Removed { team_id: String, sync: bool },
}

/// The membership with the purpose `questions`, or `None`. At most one is used: the
/// membership of the questions team that the vault names (`Vault::questions_team`), else
/// the first by team. During "Move Approvals to Connect" the vault keeps the hosted
/// membership beside the node one until the first round trip
/// ([`move_questions_keeping_hosted`]); the named team is the node team then.
pub fn questions_membership(vault: &Vault) -> VaultResult<Option<RelayMembership>> {
    let mut asking: Vec<RelayMembership> = vault
        .relay_memberships()?
        .into_iter()
        .filter(|membership| membership.purposes.contains(&MembershipPurpose::Questions))
        .collect();
    if asking.len() > 1
        && let Some(team) = vault.questions_team()?
        && let Some(at) = asking
            .iter()
            .position(|membership| membership.team_id == team)
    {
        return Ok(Some(asking.swap_remove(at)));
    }
    Ok(asking.into_iter().next())
}

/// The hosted membership that "Move Approvals to Connect" keeps until the first question
/// went round through the node team (plan s7 unit M5, section 5): a membership with the
/// purpose `questions` that is not the questions team of the vault. `None` when no move
/// waits.
pub fn retiring_questions_membership(vault: &Vault) -> VaultResult<Option<RelayMembership>> {
    let Some(team) = vault.questions_team()? else {
        return Ok(None);
    };
    Ok(vault.relay_memberships()?.into_iter().find(|membership| {
        membership.purposes.contains(&MembershipPurpose::Questions) && membership.team_id != team
    }))
}

/// "Move Approvals to Connect", the vault step after a device joined the node team
/// through a code with the Connect route: the node team becomes the questions team of
/// the vault and this Mac registers with the key of `node`, but the membership of
/// `hosted_team` stays as it is ([`retiring_questions_membership`]): the old path keeps
/// working, also after a quit, until [`finish_move_to_connect`] (the first question went
/// round through the new route) or [`undo_move_to_connect`] (a failure). `NotEnabled`:
/// the questions of the vault are not on `hosted_team`. `InvalidRelayAddress`: `node`
/// has no pin.
pub fn move_questions_keeping_hosted(
    vault: &mut Vault,
    node: &RelayMembership,
    hosted_team: &str,
    device_name: &str,
) -> Result<TrustedDevice, SyncError> {
    if vault.is_locked() {
        return Err(SyncError::Vault(VaultErrorKind::Locked));
    }
    if node.pin.is_none() || node.team_id == hosted_team {
        return Err(SyncError::InvalidRelayAddress);
    }
    questions_membership(vault)?
        .filter(|membership| membership.team_id == hosted_team)
        .ok_or(SyncError::NotEnabled)?;
    if vault.trusted_key_removed(&node.public_key)? {
        return Err(SyncError::Vault(VaultErrorKind::AlreadyExists));
    }
    vault.add_relay_membership(node)?;
    let kept = (|| -> VaultResult<TrustedDevice> {
        vault.set_questions_team(&node.team_id)?;
        vault.ensure_question_key()?;
        register_this_device(vault, node, device_name)
    })();
    kept.map_err(|error| {
        let _ = vault.set_questions_team(hosted_team);
        let _ = vault.remove_relay_membership(&node.team_id);
        SyncError::Vault(error.kind())
    })
}

/// The end of "Move Approvals to Connect" after the first question went round through
/// the node team: the kept hosted membership loses the purpose `questions` (a
/// notifications-only one goes with its key; relay sync never changes). The caller took
/// its devices off the hosted relay first ([`leave_hosted_team`]). Returns the membership
/// that went, or `None` when no move waited.
pub fn finish_move_to_connect(vault: &mut Vault) -> VaultResult<Option<RelayMembership>> {
    let Some(hosted) = retiring_questions_membership(vault)? else {
        return Ok(None);
    };
    let mut rest = hosted.purposes.clone();
    rest.remove(&MembershipPurpose::Questions);
    if rest.is_empty() {
        vault.remove_relay_membership(&hosted.team_id)?;
    } else {
        vault.set_membership_purposes(&hosted.team_id, &rest)?;
    }
    Ok(Some(hosted))
}

/// Undo "Move Approvals to Connect" before its first round trip: the kept hosted team is
/// the questions team of the vault again, and the node membership goes (its trusted
/// device rows stay, so an answer on its way still verifies). Returns the hosted team, or
/// `None` when no move waited.
pub fn undo_move_to_connect(vault: &mut Vault) -> VaultResult<Option<String>> {
    let Some(hosted) = retiring_questions_membership(vault)? else {
        return Ok(None);
    };
    let node = vault.questions_team()?;
    vault.set_questions_team(&hosted.team_id)?;
    if let Some(node) = node {
        vault.remove_relay_membership(&node)?;
    }
    Ok(Some(hosted.team_id))
}

/// Take the devices of the notifications-only team of `hosted` off its relay
/// (`DELETE /v1/devices/{id}`): first the other devices, then this Mac's own, which the
/// relay may refuse for the last owner (its key goes anyway). Best effort: returns
/// whether every other device left. A relay sync team keeps its devices: `false`, no
/// call.
pub fn leave_hosted_team(hosted: &RelayMembership) -> bool {
    if !questions_only(hosted) {
        return false;
    }
    let Ok(client) = crate::questions::QuestionsClient::from_membership(hosted) else {
        return false;
    };
    let own = hosted.device_id;
    let others: Option<Vec<u64>> = client.devices().ok().map(|devices| {
        devices
            .into_iter()
            .filter(|device| device.id != own && !device.current)
            .map(|device| device.id)
            .collect()
    });
    let mut all = others.is_some();
    for device in others.unwrap_or_default() {
        all &= client.remove_device(device).is_ok();
    }
    let _ = client.remove_device(own);
    client.close();
    all
}

/// Why the hosted relay refuses a path for good (`410`, connect-account-v1 section 4):
/// the app stops calling it, shows one state with the choices of the notice, and keeps
/// every local thing (plan s7 unit M5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathEnded {
    /// `410 free_connect_ended`: the free questions, feed, and push of a free Connect
    /// team, or `POST /v1/connect`, after Apassy [`FREE_RELAY_PATHS_END_VERSION`].
    FreeEnded,
    /// `410 hosted_retired`: the hosted relay serves Apassy Connect only.
    Retired,
}

impl PathEnded {
    /// The refusal of an error envelope: `410` with one of the two codes.
    pub fn of_answer(status: u16, code: &str) -> Option<Self> {
        match (status, code) {
            (410, "free_connect_ended") => Some(Self::FreeEnded),
            (410, "hosted_retired") => Some(Self::Retired),
            _ => None,
        }
    }

    /// The refusal of a relay sync or a relay call.
    pub fn of_sync(error: SyncError) -> Option<Self> {
        match error {
            SyncError::Relay(RelayRefusal::FreeEnded) => Some(Self::FreeEnded),
            SyncError::Relay(RelayRefusal::HostedRetired) => Some(Self::Retired),
            _ => None,
        }
    }

    /// The code of the envelope.
    pub fn code(self) -> &'static str {
        match self {
            Self::FreeEnded => "free_connect_ended",
            Self::Retired => "hosted_retired",
        }
    }
}

/// What "Send questions through the relay" can do for the open vault. Off by default:
/// only a membership with the purpose `questions` turns it on.
pub fn questions_availability(vault: &Vault) -> VaultResult<QuestionsAvailability> {
    if let Some(membership) = questions_membership(vault)? {
        if vault.trusted_key_removed(&membership.public_key)? {
            return Ok(QuestionsAvailability::Removed {
                sync: membership.purposes.contains(&MembershipPurpose::Sync),
                team_id: membership.team_id,
            });
        }
        return Ok(QuestionsAvailability::On {
            team_id: membership.team_id,
        });
    }
    if let Some(device) = vault.relay_device()? {
        if vault.trusted_key_removed(&device.public_key)? {
            return Ok(QuestionsAvailability::Removed {
                team_id: device.team_id,
                sync: true,
            });
        }
        return Ok(QuestionsAvailability::CanTurnOn {
            team_id: device.team_id,
        });
    }
    Ok(match existing_questions_team(vault)? {
        Some(team_id) => QuestionsAvailability::JoinTeam { team_id },
        None => QuestionsAvailability::NeedsTeam,
    })
}

/// The questions team of the vault that this Mac has no membership in: the team that the
/// vault names (`Vault::questions_team`), else the team in which the most live trusted
/// devices have a device number. `None`: the vault has no questions team yet, or this
/// Mac is in it.
pub fn existing_questions_team(vault: &Vault) -> VaultResult<Option<String>> {
    let mine: BTreeSet<String> = vault
        .relay_memberships()?
        .into_iter()
        .map(|membership| membership.team_id)
        .collect();
    if let Some(team) = vault.questions_team()? {
        return Ok((!mine.contains(&team)).then_some(team));
    }
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for device in vault.trusted_devices()? {
        for team in device.relay_devices.keys() {
            *counts.entry(team.clone()).or_default() += 1;
        }
    }
    Ok(counts
        .into_iter()
        .filter(|(team, _)| !mine.contains(team))
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
        .map(|(team, _)| team))
}

/// The questions membership of this Mac that relay sync on `url` uses instead of a new
/// team (plans section 4.1): a vault that asks through a Connect team (or another
/// questions team) on the same relay pushes its copy into that team, and the membership
/// then has both purposes (`Vault::set_relay_device` adds `sync`). `None`: this Mac has
/// no questions membership with its own key on that relay. `AlreadyExists`: the owner
/// removed this Mac's key, so relay sync with it would be refused too.
pub fn questions_team_for_sync(
    vault: &Vault,
    url: &RelayUrl,
) -> Result<Option<RelayMembership>, SyncError> {
    let Some(membership) = questions_membership(vault)? else {
        return Ok(None);
    };
    let same_relay =
        RelayUrl::parse(&membership.relay_url).is_ok_and(|own| own.as_str() == url.as_str());
    // An account key (schema 34) has no private key here: Connect accounts sync their way.
    if !same_relay || membership.key_pkcs8.is_empty() {
        return Ok(None);
    }
    if vault.trusted_key_removed(&membership.public_key)? {
        return Err(SyncError::Vault(VaultErrorKind::AlreadyExists));
    }
    Ok(Some(membership))
}

/// Whether the key of this Mac in `membership` is the key of a removed device: the owner
/// removed this Mac from the questions.
pub fn this_device_removed(vault: &Vault, membership: &RelayMembership) -> VaultResult<bool> {
    vault.trusted_key_removed(&membership.public_key)
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
    // A vault store of Apassy Connect has no key of its own here (schema 34): its store
    // keeps no questions (connect-account-v1 section 8). A notifications-only team does.
    if sync.uses_account_key() {
        return Err(SyncError::NotEnabled);
    }
    if vault.trusted_key_removed(&sync.public_key)? {
        return Err(SyncError::Vault(VaultErrorKind::AlreadyExists));
    }
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
/// Then the question key and the trusted device, as [`enable_questions`]. It holds the
/// vault across the relay call: the app uses [`new_questions_team`] on a thread of its
/// own, then [`adopt_questions_team`].
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
    if questions_membership(vault)?.is_some() || existing_questions_team(vault)?.is_some() {
        return Err(SyncError::AlreadyEnabled);
    }
    let membership = new_questions_team(relay_url, team_code, vault_name, device_name)?;
    adopt_questions_team(vault, &membership, device_name)
}

/// The relay part of [`create_questions_team`], with no vault: a new device key and
/// `POST /v1/teams` with the operator team code. The membership has the purpose
/// `questions` only. The team code must have its form (`InviteInvalid` otherwise).
pub fn new_questions_team(
    relay_url: &str,
    team_code: &str,
    vault_name: &str,
    device_name: &str,
) -> Result<RelayMembership, SyncError> {
    new_questions_team_at(
        &RelayUrl::parse(relay_url)?,
        team_code,
        vault_name,
        device_name,
    )
}

/// [`new_questions_team`] at the address `url` with its trust: on a pinned node the
/// membership keeps the pin and the alternatives of `url` (vault schema 28), and the
/// team is made only after the pin check.
pub fn new_questions_team_at(
    url: &RelayUrl,
    team_code: &str,
    vault_name: &str,
    device_name: &str,
) -> Result<RelayMembership, SyncError> {
    let team_code = team_code.trim();
    if !valid_team_code(team_code) {
        return Err(SyncError::Relay(RelayRefusal::InviteInvalid));
    }
    let key = DeviceKey::generate()?;
    let team = clean_name(vault_name, "Vault");
    let created = create_team_on_relay(url, team_code, &team, device_name, &key)?;
    Ok(RelayMembership {
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
        pin: url.trust().pin_text(),
        alt: url.alternative_list(),
    })
}

/// The vault part of [`create_questions_team`], with no relay call: keep `membership`
/// (from [`new_questions_team`]), name its team as the questions team of the vault, make
/// the question key when the vault has none, and register this Mac. `AlreadyEnabled` when
/// the vault got a questions membership or a questions team in the meantime: the new team
/// then stays unused on the relay, and the vault keeps one team.
pub fn adopt_questions_team(
    vault: &mut Vault,
    membership: &RelayMembership,
    device_name: &str,
) -> Result<TrustedDevice, SyncError> {
    if vault.is_locked() {
        return Err(SyncError::Vault(VaultErrorKind::Locked));
    }
    if questions_membership(vault)?.is_some()
        || existing_questions_team(vault)?.is_some_and(|team| team != membership.team_id)
    {
        return Err(SyncError::AlreadyEnabled);
    }
    keep_questions_membership(vault, membership, device_name)
}

/// Keep the questions team of the vault on the Mac's own node (plan S2–S3, unit N4,
/// decision D6): `membership` is the first device of this Mac in a new team of devices
/// on the node (`RunningNode::create_device_team`), with the node origin, the pin, and the
/// alternatives of the node (`crate::node::questions_team::new_node_team`). Then as
/// [`adopt_questions_team`]: the team becomes the questions team of the vault, the vault
/// gets its question key, and this Mac registers. No relay call. `InvalidRelayAddress`:
/// the membership has no pin (a node team is always pinned). `AlreadyEnabled`: the vault
/// has a questions membership (a hosted one moves with [`move_questions_to_node`]) or
/// another questions team.
pub fn adopt_node_team(
    vault: &mut Vault,
    membership: &RelayMembership,
    device_name: &str,
) -> Result<TrustedDevice, SyncError> {
    if membership.pin.is_none() {
        return Err(SyncError::InvalidRelayAddress);
    }
    adopt_questions_team(vault, membership, device_name)
}

/// "Move approvals to this Mac" (ADR 0037, Migration; plan S2–S3 D6), the vault step
/// after a device joined the node team: the questions of the vault go through `node`
/// (this Mac's device in the team of devices on its node) instead of the membership of
/// `hosted_team`. The hosted membership loses the purpose `questions` (a
/// notifications-only one goes with its key; relay sync never changes), the node team
/// becomes the questions team of the vault, and this Mac registers with the key of
/// `node`. On a failure the hosted questions stay as they were.
///
/// Returns the hosted membership as it was, for the relay calls that take its devices
/// off the hosted relay (best effort, by the caller, only for a notifications-only team).
/// `NotEnabled`: the questions of the vault are not on `hosted_team` any more.
/// `InvalidRelayAddress`: `node` has no pin.
pub fn move_questions_to_node(
    vault: &mut Vault,
    node: &RelayMembership,
    hosted_team: &str,
    device_name: &str,
) -> Result<RelayMembership, SyncError> {
    if vault.is_locked() {
        return Err(SyncError::Vault(VaultErrorKind::Locked));
    }
    if node.pin.is_none() || node.team_id == hosted_team {
        return Err(SyncError::InvalidRelayAddress);
    }
    let hosted = questions_membership(vault)?
        .filter(|membership| membership.team_id == hosted_team)
        .ok_or(SyncError::NotEnabled)?;
    if vault.trusted_key_removed(&node.public_key)? {
        return Err(SyncError::Vault(VaultErrorKind::AlreadyExists));
    }
    disable_questions(vault)?;
    match keep_questions_membership(vault, node, device_name) {
        Ok(_) => Ok(hosted),
        Err(error) => {
            // The hosted questions come back as they were.
            let _ = if questions_only(&hosted) {
                vault.add_relay_membership(&hosted)
            } else {
                vault.set_membership_purposes(&hosted.team_id, &hosted.purposes)
            };
            let _ = vault.set_questions_team(&hosted.team_id);
            Err(error)
        }
    }
}

/// A Mac joins the questions team of the vault (a second Mac of an iCloud Drive vault):
/// `membership` is its new key in that team, from a device link that a Mac in the team
/// confirmed after its owner check. The caller checked the owner on this Mac for
/// `OwnerAction::EnableRelayQuestions` naming the team. Then as [`adopt_questions_team`].
/// `AlreadyEnabled`: the vault has a questions membership on this Mac, or names another
/// questions team.
pub fn join_questions_team(
    vault: &mut Vault,
    membership: &RelayMembership,
    device_name: &str,
) -> Result<TrustedDevice, SyncError> {
    if vault.is_locked() {
        return Err(SyncError::Vault(VaultErrorKind::Locked));
    }
    if questions_membership(vault)?.is_some()
        || vault
            .questions_team()?
            .is_some_and(|team| team != membership.team_id)
    {
        return Err(SyncError::AlreadyEnabled);
    }
    keep_questions_membership(vault, membership, device_name)
}

fn keep_questions_membership(
    vault: &mut Vault,
    membership: &RelayMembership,
    device_name: &str,
) -> Result<TrustedDevice, SyncError> {
    if vault.trusted_key_removed(&membership.public_key)? {
        return Err(SyncError::Vault(VaultErrorKind::AlreadyExists));
    }
    vault.add_relay_membership(membership)?;
    let kept = (|| -> VaultResult<TrustedDevice> {
        vault.set_questions_team(&membership.team_id)?;
        vault.ensure_question_key()?;
        register_this_device(vault, membership, device_name)
    })();
    if kept.is_err() {
        // The vault does not keep half a membership.
        let _ = vault.remove_relay_membership(&membership.team_id);
    }
    Ok(kept?)
}

/// Write the row of a device that this Mac confirmed through a device link of the team
/// `team_id` (relay-questions-v1 section 5.2). The caller passed the owner check for
/// `OwnerAction::ConfirmSyncDevice` of exactly this link. An iPhone or an Apple Watch
/// sends its answer key with the link (`crate::questions::device_link`); its row gets a
/// new UUID, the name of the link, the kind of the marker (`~` an iPhone, `~W` a watch,
/// ADR 0039 §2), the relay key of the link as `sign_key`, the answer key, and its device
/// number. A link without an answer key (a Mac) writes nothing: a Mac writes its own row
/// after its own owner check. `AlreadyExists`: a key of the link is a key of a removed
/// device.
pub fn register_linked_device(
    vault: &mut Vault,
    team_id: &str,
    relay_device_id: u64,
    link_device_name: &str,
    sign_key: &[u8],
) -> VaultResult<Option<TrustedDevice>> {
    use crate::questions::device_link::{LinkedDeviceKind, split_linked_device_name};
    let (name, found) = split_linked_device_name(link_device_name);
    let Some((linked, answer_key)) = found else {
        return Ok(None);
    };
    let (kind, fallback) = match linked {
        LinkedDeviceKind::Iphone => (TrustedDeviceKind::Iphone, "iPhone"),
        LinkedDeviceKind::Watch => (TrustedDeviceKind::Watch, "Apple Watch"),
    };
    let name = clean_name(&name, fallback);
    // The number is checked first: a removal would make the new keys unusable.
    if !valid_team_id(team_id) || relay_device_id == 0 {
        return Err(crate::vault::VaultError::new(VaultErrorKind::InvalidInput));
    }
    if vault
        .trusted_devices()?
        .iter()
        .any(|device| device.relay_devices.get(team_id) == Some(&relay_device_id))
    {
        return Err(crate::vault::VaultError::new(VaultErrorKind::AlreadyExists));
    }
    let uuid = new_device_uuid()?;
    vault.register_trusted_device(&uuid, &name, kind, sign_key, Some(&answer_key))?;
    vault.set_trusted_device_relay_id(&uuid, team_id, relay_device_id)?;
    vault.trusted_device(&uuid)
}

/// Whether the questions membership of the vault is a notifications-only team: it has
/// no other purpose, so no snapshot goes through it.
pub fn questions_only(membership: &RelayMembership) -> bool {
    membership
        .purposes
        .iter()
        .all(|purpose| *purpose == MembershipPurpose::Questions)
}

/// Turn the questions off on this Mac: the membership loses the purpose `questions`; a
/// notifications-only membership goes with its key. Relay sync is never touched. The
/// trusted device row stays, so an answer that is on its way still verifies. Returns
/// whether they were on.
///
/// During "Move Approvals to Connect" the kept hosted membership loses the purpose too,
/// so off never falls back to the old path.
pub fn disable_questions(vault: &mut Vault) -> VaultResult<bool> {
    let mut any = false;
    // At most the node team and the kept hosted team; the bound guards a loop.
    for _ in 0..4 {
        let Some(membership) = questions_membership(vault)? else {
            break;
        };
        let mut rest = membership.purposes.clone();
        rest.remove(&MembershipPurpose::Questions);
        if rest.is_empty() {
            vault.remove_relay_membership(&membership.team_id)?;
        } else {
            vault.set_membership_purposes(&membership.team_id, &rest)?;
        }
        any = true;
    }
    Ok(any)
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
/// team. A new row gets a new random UUID. Only the calls that turn the questions on
/// after the owner check use it. `AlreadyExists`: the owner removed this Mac (its key is
/// the key of a removed device).
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

    /// A relay of one canned answer to `POST /v1/teams` behind the real TLS front of a
    /// node on the loopback (with the front's test hooks), and a new self-signed node
    /// certificate. Returns the front, the node origin, the pin, and the number of
    /// connections that reached the relay behind the front.
    fn pinned_team_relay() -> (
        crate::net::tls_front::FrontHandle,
        String,
        crate::net::pin::Pin,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use crate::net::certificate::NodeCertificate;
        use crate::net::tls_front::{Front, FrontLimits, FrontOptions};
        use std::io::{Read, Write};
        use std::net::{IpAddr, Ipv4Addr, TcpListener};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target = listener.local_addr().unwrap();
        let reached = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&reached);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                count.fetch_add(1, Ordering::SeqCst);
                // The head, then the JSON body of its Content-Length.
                let mut seen = Vec::new();
                let mut buf = [0u8; 4096];
                while let Ok(read) = stream.read(&mut buf) {
                    if read == 0 {
                        break;
                    }
                    seen.extend_from_slice(&buf[..read]);
                    let text = String::from_utf8_lossy(&seen).to_string();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let length = head
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())?
                            })
                            .unwrap_or(0);
                        if body.len() >= length {
                            break;
                        }
                    }
                }
                // The envelope of relay-sync-v1 section 4.
                let body = r#"{"ok":true,"result":{"team_id":"t_7k2m5q4x3c","device_id":1}}"#;
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        let certificate = NodeCertificate::generate("Synthetic build box").unwrap();
        let pin = certificate.pin;
        let mut options = FrontOptions::new(
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            0,
            certificate,
            target,
        );
        options.allow_loopback_bind = true;
        options.allow_test_peers = true;
        // The refused attempts count too: more than a real peer's minute allows.
        options.limits = FrontLimits {
            max_connections: 64,
            max_per_peer: 64,
            new_per_peer_per_minute: 10_000,
            ..FrontLimits::default()
        };
        let front = Front::start(options).unwrap();
        let origin = format!("https://127.0.0.1:{}", front.bound()[0].port());
        (front, origin, pin, reached)
    }

    /// The team of a node pairing link (plan S2–S3 unit L4) is made through the pin: a
    /// wrong pin and system trust are refused before any byte reaches the relay; the
    /// right pin makes the team, and a questions membership keeps the pin and the
    /// alternatives of the address.
    #[test]
    fn a_team_on_a_pinned_node_is_made_only_through_its_pin() {
        use crate::net::pin::Pin;
        use crate::sync::TlsTrust;
        use std::sync::atomic::Ordering;
        let (_front, origin, pin, reached) = pinned_team_relay();
        let code = format!("apassy_tcd_{}", "cd".repeat(32));
        let key = DeviceKey::generate().unwrap();
        let other = Pin::of_certificate(b"synthetic other certificate");
        let wrong = RelayUrl::parse_with_trust(&origin, TlsTrust::Pinned(other)).unwrap();
        assert_eq!(
            create_team_on_relay(&wrong, &code, "Personal", "Synthetic Mac", &key).unwrap_err(),
            SyncError::PinMismatch
        );
        let system = RelayUrl::parse(&origin).unwrap();
        assert_eq!(
            create_team_on_relay(&system, &code, "Personal", "Synthetic Mac", &key).unwrap_err(),
            SyncError::RelayUnreachable
        );
        assert_eq!(reached.load(Ordering::SeqCst), 0, "no request reached it");

        let node = RelayUrl::parse_with_trust(&origin, TlsTrust::Pinned(pin)).unwrap();
        let created = create_team_on_relay(&node, &code, "Personal", "Synthetic Mac", &key)
            .expect("the team");
        assert_eq!(
            created,
            CreatedTeam {
                team_id: "t_7k2m5q4x3c".to_owned(),
                device_id: 1
            }
        );
        assert_eq!(reached.load(Ordering::SeqCst), 1);

        // A questions team at the address with an alternative: the membership keeps the
        // pin and the alternative (vault schema 28).
        let node = node
            .alternatives(&["apassy-node.tail0123.ts.net".to_owned()])
            .unwrap();
        let membership =
            new_questions_team_at(&node, &code, "Personal", "Synthetic Mac").expect("team");
        assert_eq!(membership.relay_url, origin);
        assert_eq!(membership.pin, Some(pin.text()));
        let port = origin.rsplit(':').next().unwrap();
        assert_eq!(
            membership.alt,
            [format!("apassy-node.tail0123.ts.net:{port}")]
        );
        assert_eq!(reached.load(Ordering::SeqCst), 2);
    }

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

    /// The marker of the confirmed link picks the kind of the row (ADR 0039 §2): `~W` a
    /// watch, `~` an iPhone; a name without a valid key writes nothing.
    #[test]
    fn a_linked_device_row_takes_the_kind_of_its_marker() {
        use crate::questions::device_link::{link_device_name, watch_link_device_name};
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("l.db"), "synthetic-link-pass").unwrap();
        vault.unlock("synthetic-link-pass").unwrap();
        let team = "t_7k2m5q4x3c";
        let (watch_relay, watch_answer) = (
            DeviceKey::generate().unwrap(),
            DeviceKey::generate().unwrap(),
        );
        let name = watch_link_device_name("Test Watch", watch_answer.public_key()).unwrap();
        let watch = register_linked_device(&mut vault, team, 5, &name, watch_relay.public_key())
            .unwrap()
            .unwrap();
        assert_eq!(watch.kind, TrustedDeviceKind::Watch);
        assert_eq!(watch.name, "Test Watch");
        assert_eq!(watch.sign_key, watch_relay.public_key());
        assert_eq!(watch.answer_key.as_deref(), Some(watch_answer.public_key()));
        assert_eq!(watch.relay_devices.get(team), Some(&5));

        let (phone_relay, phone_answer) = (
            DeviceKey::generate().unwrap(),
            DeviceKey::generate().unwrap(),
        );
        let name = link_device_name("Test iPhone", phone_answer.public_key()).unwrap();
        let phone = register_linked_device(&mut vault, team, 6, &name, phone_relay.public_key())
            .unwrap()
            .unwrap();
        assert_eq!(phone.kind, TrustedDeviceKind::Iphone);
        assert_eq!(phone.name, "Test iPhone");
        assert_eq!(phone.answer_key.as_deref(), Some(phone_answer.public_key()));

        // A Mac, and a watch marker with a point off the curve: no row.
        let other = DeviceKey::generate().unwrap();
        let mut off = [0xffu8; 33];
        off[0] = 0x02;
        for name in [
            "Mac mini".to_owned(),
            format!("Test Watch ~W{}", crate::sync::encode_b64u(&off)),
        ] {
            assert_eq!(
                register_linked_device(&mut vault, team, 7, &name, other.public_key()).unwrap(),
                None,
                "{name}"
            );
        }
        assert_eq!(vault.trusted_devices().unwrap().len(), 2);
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
                account_key: false,
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

    fn membership(team: &str, url: &str, pin: bool) -> RelayMembership {
        let key = DeviceKey::generate().unwrap();
        RelayMembership {
            team_id: team.to_owned(),
            relay_url: url.to_owned(),
            device_id: 1,
            public_key: key.public_key().to_vec(),
            key_pkcs8: key.pkcs8().unwrap().clone(),
            purposes: BTreeSet::from([MembershipPurpose::Questions]),
            created_at: 0,
            pin: pin.then(|| crate::net::pin::Pin::of_certificate(b"synthetic node").text()),
            alt: Vec::new(),
        }
    }

    /// Plan s7 unit M5, "Move Approvals to Connect": the hosted membership stays in the
    /// vault beside the node team until the first round trip; the node team carries the
    /// questions at once; undo puts the hosted team back; the end removes only the hosted
    /// membership. A quit in between keeps both (the rows are in the vault).
    #[test]
    fn the_move_to_connect_keeps_the_hosted_path_until_the_first_round_trip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("c.db");
        let mut vault = Vault::create(&path, "synthetic-move-pass").unwrap();
        vault.unlock("synthetic-move-pass").unwrap();
        let hosted = membership("t_hostedaaaa", crate::sync::DEFAULT_RELAY_URL, false);
        adopt_questions_team(&mut vault, &hosted, "Synthetic Mac").unwrap();
        assert!(retiring_questions_membership(&vault).unwrap().is_none());
        assert!(undo_move_to_connect(&mut vault).unwrap().is_none());
        assert!(finish_move_to_connect(&mut vault).unwrap().is_none());

        let node = membership("t_nodebbbbbb", "https://100.64.0.7:8444", true);
        // A node team without a pin, or the same team, is refused; nothing changes.
        let unpinned = membership("t_nodecccccc", "https://100.64.0.7:8444", false);
        assert!(move_questions_keeping_hosted(&mut vault, &unpinned, "t_hostedaaaa", "M").is_err());
        assert!(matches!(
            move_questions_keeping_hosted(&mut vault, &node, "t_otherdddd", "M"),
            Err(SyncError::NotEnabled)
        ));
        assert_eq!(
            questions_membership(&vault).unwrap().unwrap().team_id,
            "t_hostedaaaa"
        );

        move_questions_keeping_hosted(&mut vault, &node, "t_hostedaaaa", "Synthetic Mac").unwrap();
        assert_eq!(
            questions_membership(&vault).unwrap().unwrap().team_id,
            "t_nodebbbbbb",
            "the node team carries the questions"
        );
        assert_eq!(
            retiring_questions_membership(&vault)
                .unwrap()
                .unwrap()
                .team_id,
            "t_hostedaaaa",
            "the hosted path stays"
        );
        // The notice of N1 is gone: the questions membership is not on the hosted relay.
        assert!(!on_hosted_relay(
            &questions_membership(&vault).unwrap().unwrap().relay_url
        ));
        // After a quit and an unlock: the same two memberships.
        drop(vault);
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock("synthetic-move-pass").unwrap();
        assert_eq!(
            retiring_questions_membership(&vault)
                .unwrap()
                .unwrap()
                .team_id,
            "t_hostedaaaa"
        );

        // A failure before the round trip: undo, the hosted path as before.
        assert_eq!(
            undo_move_to_connect(&mut vault).unwrap().as_deref(),
            Some("t_hostedaaaa")
        );
        assert_eq!(
            questions_membership(&vault).unwrap().unwrap().team_id,
            "t_hostedaaaa"
        );
        assert!(vault.relay_membership("t_nodebbbbbb").unwrap().is_none());
        assert!(retiring_questions_membership(&vault).unwrap().is_none());

        // Off during the move: neither path asks any more.
        let node_off = membership("t_nodeffffff", "https://100.64.0.7:8444", true);
        move_questions_keeping_hosted(&mut vault, &node_off, "t_hostedaaaa", "Synthetic Mac")
            .unwrap();
        assert!(disable_questions(&mut vault).unwrap());
        assert!(questions_membership(&vault).unwrap().is_none());
        assert!(retiring_questions_membership(&vault).unwrap().is_none());
        let hosted = membership("t_hostedaaaa", crate::sync::DEFAULT_RELAY_URL, false);
        vault.add_relay_membership(&hosted).unwrap();
        vault.set_questions_team("t_hostedaaaa").unwrap();

        // Again, and the first round trip ends it: only the hosted membership goes.
        let node = membership("t_nodeeeeeee", "https://100.64.0.7:8444", true);
        move_questions_keeping_hosted(&mut vault, &node, "t_hostedaaaa", "Synthetic Mac").unwrap();
        let gone = finish_move_to_connect(&mut vault).unwrap().unwrap();
        assert_eq!(gone.team_id, "t_hostedaaaa");
        assert!(vault.relay_membership("t_hostedaaaa").unwrap().is_none());
        assert_eq!(
            questions_membership(&vault).unwrap().unwrap().team_id,
            "t_nodeeeeeee"
        );
        assert!(retiring_questions_membership(&vault).unwrap().is_none());
    }

    #[test]
    fn a_410_of_the_hosted_relay_is_an_end_and_never_passes() {
        assert_eq!(
            PathEnded::of_answer(410, "free_connect_ended"),
            Some(PathEnded::FreeEnded)
        );
        assert_eq!(
            PathEnded::of_answer(410, "hosted_retired"),
            Some(PathEnded::Retired)
        );
        assert_eq!(PathEnded::of_answer(410, "gone"), None);
        assert_eq!(PathEnded::of_answer(404, "hosted_retired"), None);
        for why in [PathEnded::FreeEnded, PathEnded::Retired] {
            let error = crate::sync::relay::sync_error(crate::sync::relay::ApiError::Relay {
                status: 410,
                code: why.code().to_owned(),
                retry_after: None,
            });
            assert_eq!(PathEnded::of_sync(error), Some(why));
            assert!(!crate::sync::relay::is_transient(error), "no retry storm");
            let questions = crate::questions::QuestionsError::Relay {
                status: 410,
                code: why.code().to_owned(),
            };
            assert_eq!(questions.path_ended(), Some(why));
            assert!(!questions.can_pass());
        }
    }
}
