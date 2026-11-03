//! The questions team of a vault on the Mac's node (ADR 0037 stage 2; plan
//! `docs/design/implementation-plan-s2-s3.md`, unit N4, decision D6).
//!
//! With the tailnet route on, the questions of a vault go through a **team of devices on
//! the Mac's own node** instead of the hosted relay:
//!
//! - [`new_node_team`] makes the team in process (`RunningNode::create_device_team`, the
//!   ADR 0019 bootstrap of `POST /v1/teams` without a code), with a new device key of
//!   this Mac as its first device and key holder. The membership has the node origin, the
//!   pin of the node certificate, and the alternative destinations
//!   (`crate::relay::membership::adopt_node_team` keeps it in the vault).
//! - The questions worker, the feed, and the access requests then use that membership as
//!   any other: they reach the node over the loopback through the local route of the
//!   origin, and sign the node origin (plan D1).
//! - [`device_link`] makes the device link that an iPhone scans: the node origin, the
//!   pin, the alternatives, and the node name (node-pairing-v1 section 6). The ADR 0032
//!   handoff is appended by the pairing channel of the sheet, as for a hosted link.
//! - The team of the personal cloud agents (`Node::start`) is another team in the same
//!   node: one node hosts several teams (ADR 0037 §2).
//!
//! An identity is per team (ADR 0019 §4): moving the questions of a vault from the hosted
//! relay to the node needs a new device key on the iPhone and a new confirmation
//! (`Node::move_approvals`, `Node::finish_move`).

use std::collections::BTreeSet;

use zeroize::Zeroizing;

use super::backend::{NodeError, RunningNode};
use super::tailnet::{QUESTIONS_TEAM_NAME, TailnetRoute};
use crate::questions::QuestionsClient;
use crate::sync::{DeviceKey, LinkCode, SyncError, membership_relay_url};
use crate::vault::{MembershipPurpose, RelayMembership, Vault};

/// A node error for a relay call that failed.
pub fn sync_error(error: SyncError) -> NodeError {
    let code = match error {
        SyncError::Vault(crate::vault::VaultErrorKind::Locked) => "vault_locked",
        SyncError::AlreadyEnabled => "conflict",
        SyncError::NotEnabled => "not_found",
        _ => "relay_error",
    };
    NodeError::new(code, error.to_string())
}

/// Whether `membership` is a team of the node of `origin`: it names the origin and has a
/// pin.
pub fn on_node(membership: &RelayMembership, origin: &str) -> bool {
    membership.relay_url == origin && membership.pin.is_some()
}

/// The questions membership of the vault, when it is a team of the node of `origin`.
pub fn node_questions_membership(
    vault: &Vault,
    origin: &str,
) -> Result<Option<RelayMembership>, NodeError> {
    crate::relay::membership::questions_membership(vault)
        .map(|found| found.filter(|membership| on_node(membership, origin)))
        .map_err(|_| NodeError::new("vault_error", "The relay memberships cannot be read."))
}

/// A new team of devices on `node` for the questions of a vault: a new device key of this
/// Mac, named `device_name`, is its first device and key holder. The membership names
/// the node origin and has the pin and the alternatives of `route`, and the purpose
/// `questions` only. Nothing is stored: the caller keeps it in the vault
/// (`crate::relay::membership::adopt_node_team`) or in memory (a move).
pub fn new_node_team(
    node: &dyn RunningNode,
    route: &TailnetRoute,
    device_name: &str,
) -> Result<RelayMembership, NodeError> {
    let key = DeviceKey::generate().map_err(sync_error)?;
    let device = crate::sync::relay::clean_name(device_name, "Mac");
    let (team, device_id) =
        node.create_device_team(QUESTIONS_TEAM_NAME, &device, &key.public_key_b64u())?;
    Ok(RelayMembership {
        team_id: team.0,
        relay_url: route.origin.clone(),
        device_id,
        public_key: key.public_key().to_vec(),
        key_pkcs8: key
            .pkcs8()
            .cloned()
            .unwrap_or_else(|| Zeroizing::new(Vec::new())),
        purposes: BTreeSet::from([MembershipPurpose::Questions]),
        created_at: 0,
        pin: Some(route.pin.text()),
        alt: route.alt.clone(),
    })
}

/// A device link of the questions team of `membership` through `client` (the client of
/// that membership): `POST /v1/devices/links`, then the link text with the origin of the
/// membership. A membership of a node gives the pinned form with its alternatives and the
/// node name `name` (node-pairing-v1 section 6: "the Mac's own device links name the node
/// origin"); a hosted one gives today's link.
pub fn device_link(
    client: &QuestionsClient,
    membership: &RelayMembership,
    name: Option<&str>,
) -> Result<LinkCode, SyncError> {
    let code = client.create_link()?;
    if membership.pin.is_none() {
        return Ok(code);
    }
    let url = membership_relay_url(membership)?;
    code.for_origin(&url, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{LinkKind, PairedLink};

    #[test]
    fn a_node_membership_needs_the_origin_and_a_pin() {
        let key = DeviceKey::generate().unwrap();
        let mut membership = RelayMembership {
            team_id: "t_7k2m5q4x3c".to_owned(),
            relay_url: "https://100.64.0.7:8444".to_owned(),
            device_id: 1,
            public_key: key.public_key().to_vec(),
            key_pkcs8: key.pkcs8().unwrap().clone(),
            purposes: BTreeSet::from([MembershipPurpose::Questions]),
            created_at: 0,
            pin: None,
            alt: Vec::new(),
        };
        assert!(!on_node(&membership, "https://100.64.0.7:8444"));
        membership.pin = Some(crate::net::pin::Pin::of_certificate(b"synthetic").text());
        assert!(on_node(&membership, "https://100.64.0.7:8444"));
        assert!(!on_node(&membership, "https://100.64.0.8:8444"));
    }

    #[test]
    fn a_pinned_link_of_the_node_origin_reads_back_with_its_name() {
        let pin = crate::net::pin::Pin::of_certificate(b"synthetic node certificate");
        let url = crate::sync::RelayUrl::parse_with_trust(
            "https://100.64.0.7:8444",
            crate::sync::TlsTrust::Pinned(pin),
        )
        .unwrap()
        .alternatives(&["apassy-mini.tail0123.ts.net:8444".to_owned()])
        .unwrap();
        let code = LinkCode {
            code: Zeroizing::new(format!("apassy_lnk_t_7k2m5q4x3c_{}", "ab".repeat(32))),
            link: Zeroizing::new(String::new()),
            expires_at: 1,
        };
        let link = code.for_origin(&url, Some("Mac mini “Studio”")).unwrap();
        let read = PairedLink::parse(&link.link).unwrap();
        assert_eq!(read.kind, LinkKind::Device);
        assert_eq!(read.origin, "https://100.64.0.7:8444");
        assert_eq!(read.pin, Some(pin));
        assert_eq!(
            read.alt,
            vec!["apassy-mini.tail0123.ts.net:8444".to_owned()]
        );
        assert_eq!(read.name.as_deref(), Some("Mac mini “Studio”"));
        assert_eq!(read.code.as_str(), code.code.as_str());
    }
}
