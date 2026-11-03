#![cfg(feature = "vault")]

//! Relay sync with a pinned node (contract node-pairing-v1; plan S2–S3, unit N3).
//! Synthetic values only.
//!
//! The in-process fake relay (`tests/common/fake_relay.rs`) stands behind the real TLS
//! front of the node (`apassy::net::tls_front`) on the loopback, with the test hooks that
//! let the front bind `127.0.0.1` and admit a loopback peer. The front presents a new
//! self-signed node certificate; the clients trust only its pin. The origin of the node
//! is `https://127.0.0.1:<front port>`: an explicit port, never 443.

use crate::common::fake_relay;

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use apassy::contracts::CredentialKind;
use apassy::net::certificate::NodeCertificate;
use apassy::net::pin::Pin;
use apassy::net::tls_front::{Front, FrontHandle, FrontLimits, FrontOptions};
use apassy::sync::{
    LinkKind, PairedLink, PendingJoin, RelayConfig, RelaySync, RelayUrl, SyncError, TlsTrust,
};
use apassy::vault::{Field, ItemDraft, SecretValue, Vault};
use fake_relay::FakeRelay;
use tempfile::TempDir;

const PASS: &str = "synthetic-pinned-pass";

/// The fake relay behind a TLS front with a node certificate: the front, the node
/// origin, and the pin of its certificate. The relay reports the node origin in its
/// sign-in challenge.
fn pinned_node(relay: &FakeRelay) -> (FrontHandle, String, Pin) {
    let target: SocketAddr = relay
        .url
        .strip_prefix("http://")
        .expect("plain fake relay")
        .parse()
        .expect("loopback address");
    let certificate = NodeCertificate::generate("Synthetic Test Mac").expect("certificate");
    let pin = certificate.pin;
    let mut options = FrontOptions::new(
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        0,
        certificate,
        target,
    );
    options.allow_loopback_bind = true;
    options.allow_test_peers = true;
    // One connection per request: the test makes more than the per-minute limit of a
    // real peer.
    options.limits = FrontLimits {
        max_connections: 256,
        max_per_peer: 256,
        new_per_peer_per_minute: 100_000,
        ..FrontLimits::default()
    };
    let front = Front::start(options).expect("front");
    let port = front.bound()[0].port();
    let origin = format!("https://127.0.0.1:{port}");
    relay.set_origin(&origin);
    (front, origin, pin)
}

/// One Mac: a data folder, its local vault path, and its relay sync.
struct Mac {
    data: PathBuf,
    vault_path: PathBuf,
    sync: RelaySync,
}

fn mac(root: &TempDir, name: &str, config: impl FnOnce(PathBuf, PathBuf) -> RelayConfig) -> Mac {
    let data = root.path().join(name).join("Apassy");
    fs::create_dir_all(&data).expect("data dir");
    let vault_path = data.join("vault.db");
    Mac {
        sync: RelaySync::new(config(data.clone(), vault_path.clone())),
        data,
        vault_path,
    }
}

fn create_vault(mac: &Mac) -> Vault {
    let mut vault = Vault::create(&mac.vault_path, PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    vault
}

fn item(title: &str, token: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![Field {
            name: "token".to_owned(),
            value: SecretValue::new(token.to_owned()),
            secret: true,
        }],
    }
}

fn titles(vault: &Vault) -> Vec<String> {
    let mut titles: Vec<String> = vault
        .search("")
        .expect("search")
        .into_iter()
        .map(|summary| summary.title)
        .collect();
    titles.sort();
    titles
}

/// A Mac makes its team on the node with a node pairing link (`/pair#`, the path of
/// unit L4), and a second Mac joins with the pinned device link of the first. Both keep
/// the pin in the sync link and in the membership, and both sync through the front.
#[test]
fn a_pairing_link_makes_a_team_on_a_pinned_node_and_a_pinned_device_link_joins_it() {
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    let (_front, origin, pin) = pinned_node(&relay);

    // The node pairing link of `apassy pair`: origin, team code, pin.
    let node = RelayUrl::parse_with_trust(&origin, TlsTrust::Pinned(pin)).expect("node url");
    let pair_text = PairedLink::format(
        LinkKind::Pair,
        &node,
        &relay.team_code(),
        Some("Synthetic build box"),
    )
    .expect("pair link");
    assert!(pair_text.contains(&format!("&pin={}", pin.text())));
    let pairing = PairedLink::parse(&pair_text).expect("the pair link reads back");
    assert_eq!(pairing.kind, LinkKind::Pair);
    assert_eq!(pairing.origin, origin);
    assert_eq!(pairing.name.as_deref(), Some("Synthetic build box"));
    let pairing_url = pairing.url().expect("url");

    let a = mac(&root, "a", |data, vault_path| {
        RelayConfig::in_data_dir(&data, &vault_path, &pairing.origin, "vault")
            .with_url_trust(&pairing_url)
    });
    let mut vault_a = create_vault(&a);
    vault_a.add(item("Alpha", "SYNTH-alpha")).expect("add");
    let report = a
        .sync
        .create_team(
            &mut vault_a,
            "Personal",
            pairing.code.as_str(),
            "Synthetic MacBook",
        )
        .expect("create team on the node");
    assert!(report.outcome.pushed);
    assert_eq!(report.link.url, origin, "the origin is the stored value");
    assert_eq!(report.link.pin.as_deref(), Some(pin.text().as_str()));
    assert!(report.link.alt.is_empty());
    let membership = vault_a
        .relay_membership(&report.link.team_id)
        .expect("read")
        .expect("membership");
    assert_eq!(membership.pin.as_deref(), Some(pin.text().as_str()));
    // The relay saw the requests in clear behind the front; the pin never went there.
    assert!(
        relay
            .log()
            .iter()
            .any(|line| line.starts_with("POST /v1/teams"))
    );
    assert!(
        !relay
            .log()
            .iter()
            .any(|line| line.contains(&pin.text()) || line.contains("pin="))
    );

    // The device link of the first Mac names the node origin and carries the pin.
    let code = a.sync.create_link(&vault_a).expect("link");
    assert!(
        code.link.starts_with(&format!("{origin}/link#apassy_lnk_")),
        "{}",
        code.link.as_str()
    );
    assert!(code.link.contains(&format!("&pin={}", pin.text())));
    let (joined_url, joined_code) = PendingJoin::parse_link(&code.link, "").expect("parse");
    assert_eq!(joined_url.pin(), Some(pin));
    assert_eq!(joined_code.as_str(), code.code.as_str());

    // The second Mac joins: the same words on both, the owner confirms on the first.
    let pending = PendingJoin::request(&code.link, "", "Synthetic Mac mini").expect("request");
    let links = a.sync.pending_links(&vault_a, Some(&code)).expect("links");
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].safety.as_deref(), Some(pending.safety.as_str()));
    a.sync.confirm_link(&vault_a, &links[0]).expect("confirm");
    let joined = pending.poll().expect("poll").expect("confirmed");

    // The second Mac has only the origin in its settings: the pin comes with the join.
    let b = mac(&root, "b", |data, vault_path| {
        RelayConfig::in_data_dir(&data, &vault_path, &origin, "vault")
    });
    let download = joined.download(&b.data.join("sync")).expect("download");
    let (mut vault_b, adopted) = b.sync.adopt(&joined, &download, PASS).expect("adopt");
    vault_b.unlock(PASS).expect("unlock");
    assert_eq!(adopted.link.url, origin);
    assert_eq!(adopted.link.pin.as_deref(), Some(pin.text().as_str()));
    let kept = vault_b
        .relay_membership(&adopted.link.team_id)
        .expect("read")
        .expect("membership");
    assert_eq!(kept.pin.as_deref(), Some(pin.text().as_str()));
    assert_eq!(titles(&vault_b), ["Alpha"]);

    // Both sync through the front: the second Mac's relay sync takes the pin from its
    // membership (vault schema 28), with nothing in its settings.
    vault_b.add(item("Beta", "SYNTH-beta")).expect("add");
    let pushed = b.sync.sync(&mut vault_b).expect("sync b");
    assert!(pushed.pushed);
    a.sync.sync(&mut vault_a).expect("sync a");
    assert_eq!(titles(&vault_a), ["Alpha", "Beta"]);

    // A new relay sync of the second Mac (after a restart) has only the origin in its
    // settings: its session takes the pin from the membership (vault schema 28).
    let restarted = RelaySync::new(RelayConfig::in_data_dir(
        &b.data,
        &b.vault_path,
        &origin,
        "vault",
    ));
    vault_b.add(item("Gamma", "SYNTH-gamma")).expect("add");
    assert!(
        restarted
            .sync(&mut vault_b)
            .expect("sync after restart")
            .pushed
    );
    a.sync.sync(&mut vault_a).expect("sync a");
    assert_eq!(titles(&vault_a), ["Alpha", "Beta", "Gamma"]);

    // A relay sync of the stored link (`RelayConfig::for_link`) has the pin too.
    let again = RelayConfig::for_link(&b.data, &b.vault_path, &adopted.link, "vault")
        .expect("config of the link");
    assert_eq!(again.relay_url().expect("url").pin(), Some(pin));
}

/// A client with another pin, or with the system trust store, never gets a request
/// byte to the node: the relay behind the front sees nothing.
#[test]
fn a_wrong_pin_or_system_trust_refuses_the_node_before_any_request() {
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    let (_front, origin, pin) = pinned_node(&relay);
    let other = Pin::of_certificate(b"synthetic other certificate");
    assert_ne!(other, pin);

    let wrong = mac(&root, "wrong", |data, vault_path| {
        RelayConfig::in_data_dir(&data, &vault_path, &origin, "vault")
            .with_trust(TlsTrust::Pinned(other), &[])
    });
    let mut vault = create_vault(&wrong);
    assert_eq!(
        wrong
            .sync
            .create_team(&mut vault, "Personal", &relay.team_code(), "Synthetic Mac")
            .unwrap_err(),
        SyncError::PinMismatch
    );
    assert_eq!(
        SyncError::PinMismatch.to_string(),
        apassy::sync::PIN_CHANGED_TEXT
    );
    assert!(vault.relay_device().expect("row").is_none());

    // The same node with the system trust store: its certificate is in no store.
    let system = mac(&root, "system", |data, vault_path| {
        RelayConfig::in_data_dir(&data, &vault_path, &origin, "vault")
    });
    let mut vault = create_vault(&system);
    assert_eq!(
        system
            .sync
            .create_team(&mut vault, "Personal", &relay.team_code(), "Synthetic Mac")
            .unwrap_err(),
        SyncError::RelayUnreachable
    );
    assert!(relay.log().is_empty(), "{:?}", relay.log());

    // A device link with another pin is refused before any request too.
    let link = format!(
        "{origin}/link#apassy_lnk_t_7k2m5q4x3c_{}&pin={}",
        "ab".repeat(32),
        other.text()
    );
    assert_eq!(
        PendingJoin::request(&link, "", "Synthetic iPhone").unwrap_err(),
        SyncError::PinMismatch
    );
    assert!(relay.log().is_empty(), "{:?}", relay.log());
}
