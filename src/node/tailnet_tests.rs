//! Tests of the tailnet route of the node service (plan S2–S3, unit N4) with the fake
//! node of `tests.rs`, the real TLS front on the loopback (the test hook of
//! `Node::with_test_tailnet`), and a fake Tailscale command line. All values are
//! synthetic.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::funnel::tests::{FakeCli, serve_443_only};
use super::master_key::tests::FakeKeys;
use super::tests::{FakeBackend, FakeState, PASS, synthetic_vault};
use super::{MoveState, Node, NodeOptions, tailnet};
use crate::broker::SharedVault;
use crate::broker::approvals::ApprovalQueue;
use crate::broker::decide::BrokerContext;
use crate::broker::http::TlsClient;
use crate::broker::prompts::PromptStore;
use crate::relay::membership::questions_membership;
use crate::sync::{DeviceKey, RelayUrl};
use crate::vault::{MembershipPurpose, TrustedDeviceKind, Vault};

struct Fixture {
    _dir: tempfile::TempDir,
    vault: SharedVault,
    backend: FakeBackend,
    cli: Arc<FakeCli>,
    node: Arc<Node>,
    broker: BrokerContext,
    port: u16,
}

fn free_port() -> u16 {
    let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    probe.local_addr().unwrap().port()
}

/// An unlocked vault with the tailnet route on (the public route off) on a free port.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _) = synthetic_vault(&dir);
    let port = free_port();
    vault.set_cloud_tailnet_on(true).unwrap();
    vault.set_cloud_tailnet_port(Some(port)).unwrap();
    let vault: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let backend = FakeBackend::default();
    let cli = Arc::new(FakeCli::connected(serve_443_only()));
    let node = Arc::new(
        Node::new(NodeOptions {
            backend: Arc::new(backend.clone()),
            keys: Arc::new(FakeKeys::empty()),
            cli: cli.clone(),
            data_dir: dir.path().join("node"),
        })
        .with_test_tailnet(),
    );
    let broker = BrokerContext {
        vault: Arc::clone(&vault),
        tls: TlsClient::platform().unwrap(),
        approvals: Arc::new(ApprovalQueue::new()),
        approval_timeout: Duration::from_secs(20),
        run_timeout: Duration::from_secs(20),
        bouncer: None,
        model_gate: None,
        prompts: Arc::new(PromptStore::new(Vec::new())),
    };
    Fixture {
        _dir: dir,
        vault,
        backend,
        cli,
        node,
        broker,
        port,
    }
}

impl Fixture {
    fn with_vault<T>(&self, f: impl FnOnce(&mut Vault) -> T) -> T {
        f(self.vault.lock().unwrap().as_mut().unwrap())
    }

    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.backend.state.lock().unwrap()
    }

    fn origin(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    fn start(&self) {
        self.node.start(&self.vault, self.broker.clone()).unwrap();
    }
}

fn local_route(origin: &str) -> Option<SocketAddr> {
    crate::sync::relay_http::local_route_for_test(&RelayUrl::parse(origin).unwrap())
}

#[test]
fn the_tailnet_route_starts_without_funnel_and_a_lock_stops_the_front_before_the_relay() {
    let fx = fixture();
    // No cloud agent: the tailnet route alone wants the node.
    let epoch = fx.with_vault(|vault| vault.epoch());
    assert_eq!(fx.with_vault(|vault| Node::wanted(vault)), Some(epoch));
    fx.start();
    assert!(fx.node.is_running() && fx.node.tailnet_running());
    let origin = fx.origin();
    assert_eq!(fx.node.node_origin().as_deref(), Some(origin.as_str()));
    {
        let state = fx.state();
        let tailnet = state.tailnet.as_ref().expect("the tailnet route");
        assert_eq!(tailnet.node_origin, origin);
        assert!(!tailnet.tailnet_agents);
        assert_eq!(
            tailnet.push_gateway.as_deref(),
            Some(tailnet::DEFAULT_PUSH_GATEWAY)
        );
        // No public listener, and the node origin is the only origin.
        assert_eq!(state.public_listen, None);
        assert_eq!(state.public_url, origin);
    }
    // No Funnel command ran.
    assert!(
        fx.cli.calls().iter().all(|call| !call.contains("funnel")),
        "{:?}",
        fx.cli.calls()
    );
    let status = fx.node.status(&fx.vault);
    assert_eq!(status.url, None, "no MCP URL without the public route");
    let route = status.tailnet;
    assert!(route.on && route.running);
    assert_eq!(route.origin.as_deref(), Some(origin.as_str()));
    assert_eq!(
        route.bound,
        vec![SocketAddr::from((Ipv4Addr::LOCALHOST, fx.port))]
    );
    assert!(!route.serve_fallback);
    let pin = route.pin.clone().expect("a pin");
    assert_eq!(pin.len(), 43);
    assert_eq!(route.pin_words.as_deref().unwrap().split(' ').count(), 6);
    assert_eq!(route.questions_team, None);
    assert_eq!(
        fx.with_vault(|vault| vault.cloud_node_setting().unwrap().node_origin),
        Some(origin.clone())
    );
    // The Mac's own clients go to the relay's tailnet listener, plain.
    let target = fx
        .state()
        .tailnet_listener
        .as_ref()
        .unwrap()
        .local_addr()
        .unwrap();
    assert_eq!(local_route(&origin), Some(target));

    // A lock: the front stops first, then the relay, then the local route goes.
    fx.state().watch_at_stop = Some((route.bound[0], origin.clone()));
    fx.with_vault(|vault| vault.lock().unwrap());
    fx.node.stop();
    assert!(!fx.node.is_running());
    assert_eq!(
        fx.state().seen_at_stop,
        Some((false, true)),
        "at the relay's stop the front was closed and the local route still set"
    );
    assert_eq!(local_route(&origin), None);
    assert!(std::net::TcpStream::connect(route.bound[0]).is_err());
    assert_eq!(fx.with_vault(|vault| Node::wanted(vault)), None);

    // An unlock starts it again with the same certificate.
    fx.with_vault(|vault| vault.unlock(PASS).unwrap());
    fx.start();
    let again = fx.node.status(&fx.vault).tailnet;
    assert_eq!(again.pin.as_deref(), Some(pin.as_str()));
    fx.node.set_tailnet(&fx.vault, false).unwrap();
    assert!(!fx.node.is_running());
    assert_eq!(local_route(&origin), None);
    assert_eq!(fx.with_vault(|vault| Node::wanted(vault)), None);
}

#[test]
fn the_questions_team_is_made_once_and_reused_after_a_restart() {
    let fx = fixture();
    fx.start();
    let origin = fx.origin();
    let pin = fx.node.status(&fx.vault).tailnet.pin.unwrap();
    let first = fx
        .node
        .ensure_questions_team(&fx.vault, "Synthetic Mac")
        .unwrap();
    assert_eq!(first.relay_url, origin);
    assert_eq!(first.pin.as_deref(), Some(pin.as_str()));
    assert!(first.alt.is_empty(), "the loopback stand-in has none");
    assert_eq!(
        first.purposes,
        BTreeSet::from([MembershipPurpose::Questions])
    );
    let kept = fx.with_vault(|vault| questions_membership(vault).unwrap().unwrap());
    assert_eq!(kept.team_id, first.team_id);
    assert_eq!(kept.pin.as_deref(), Some(pin.as_str()));
    assert_eq!(
        fx.with_vault(|vault| vault.questions_team().unwrap()),
        Some(first.team_id.clone())
    );
    // This Mac is a trusted device of the team.
    let mac = fx.with_vault(|vault| {
        crate::relay::membership::this_device(vault, &kept)
            .unwrap()
            .unwrap()
    });
    assert_eq!(mac.kind, TrustedDeviceKind::Mac);
    // A second call keeps the team.
    let second = fx
        .node
        .ensure_questions_team(&fx.vault, "Synthetic Mac")
        .unwrap();
    assert_eq!(second.team_id, first.team_id);
    assert_eq!(fx.state().device_teams.len(), 1);

    // A restart: the same origin, pin, and team.
    fx.node.stop();
    fx.start();
    let status = fx.node.status(&fx.vault).tailnet;
    assert_eq!(status.pin.as_deref(), Some(pin.as_str()));
    assert_eq!(
        status.questions_team.as_deref(),
        Some(first.team_id.as_str())
    );
    assert_eq!(status.devices.len(), 1);
    assert!(status.devices[0].this_mac);
    let third = fx
        .node
        .ensure_questions_team(&fx.vault, "Synthetic Mac")
        .unwrap();
    assert_eq!(third.team_id, first.team_id);
    assert_eq!(fx.state().device_teams.len(), 1);
    fx.node.stop();
}

#[test]
fn after_a_certificate_replacement_the_team_and_its_links_take_the_new_pin() {
    let fx = fixture();
    fx.start();
    let old_pin = fx.node.status(&fx.vault).tailnet.pin.unwrap();
    let first = fx
        .node
        .ensure_questions_team(&fx.vault, "Synthetic Mac")
        .unwrap();
    assert_eq!(first.pin.as_deref(), Some(old_pin.as_str()));
    fx.node.stop();
    // The certificate is lost while the relay directory and the team stay: the next
    // start makes a new one, and the pin changes.
    let front = fx._dir.path().join("node").join(tailnet::FRONT_DIR);
    std::fs::remove_file(front.join(crate::net::certificate::CERT_FILE)).unwrap();
    fx.start();
    let new_pin = fx.node.status(&fx.vault).tailnet.pin.unwrap();
    assert_ne!(new_pin, old_pin);
    // The same team, with the pin that the front serves now, in the vault too.
    let again = fx
        .node
        .ensure_questions_team(&fx.vault, "Synthetic Mac")
        .unwrap();
    assert_eq!(again.team_id, first.team_id);
    assert_eq!(again.pin.as_deref(), Some(new_pin.as_str()));
    let kept = fx.with_vault(|vault| questions_membership(vault).unwrap().unwrap());
    assert_eq!(kept.pin.as_deref(), Some(new_pin.as_str()));
    // A pairing link is built from that membership (`questions_team::device_link`): it
    // carries the new pin.
    let url = crate::sync::membership_relay_url(&kept).unwrap();
    assert_eq!(url.pin().map(|pin| pin.text()), Some(new_pin));
    fx.node.stop();
}

#[test]
fn revoke_removes_the_device_on_the_node_and_its_row_and_refuses_this_mac() {
    let fx = fixture();
    fx.start();
    let team = fx
        .node
        .ensure_questions_team(&fx.vault, "Synthetic Mac")
        .unwrap();
    // An iPhone of the team: a device on the node and its trusted device row.
    let phone = DeviceKey::generate().unwrap();
    let answer = DeviceKey::generate().unwrap();
    fx.state()
        .device_teams
        .get_mut(&team.team_id)
        .unwrap()
        .push(crate::node::backend::NodeDevice {
            id: 2,
            name: "Synthetic iPhone".to_owned(),
            member_id: 1,
            member_name: "owner".to_owned(),
            role: "owner".to_owned(),
            key_holder: false,
            created_at: 1,
            last_seen_at: Some(2),
            push: true,
        });
    let uuid = crate::relay::membership::new_device_uuid().unwrap();
    fx.with_vault(|vault| {
        vault
            .register_trusted_device(
                &uuid,
                "Synthetic iPhone",
                TrustedDeviceKind::Iphone,
                phone.public_key(),
                Some(answer.public_key()),
            )
            .unwrap();
        vault
            .set_trusted_device_relay_id(&uuid, &team.team_id, 2)
            .unwrap();
    });
    let status = fx.node.status(&fx.vault).tailnet;
    let shown = status.devices.iter().find(|device| device.id == 2).unwrap();
    assert_eq!(shown.kind, Some(TrustedDeviceKind::Iphone));
    assert!(shown.push && !shown.this_mac);

    let own = fx
        .node
        .revoke_device(&fx.vault, team.device_id)
        .unwrap_err();
    assert_eq!(own.code, "conflict");
    fx.node.revoke_device(&fx.vault, 2).unwrap();
    assert_eq!(fx.state().revoked_devices, vec![(team.team_id.clone(), 2)]);
    assert!(
        fx.with_vault(|vault| vault.trusted_device_by_relay_id(&team.team_id, 2).unwrap())
            .is_none()
    );
    fx.node.stop();
}

#[test]
fn the_tailnet_off_refuses_the_team_and_the_move() {
    let fx = fixture();
    fx.with_vault(|vault| vault.set_cloud_tailnet_on(false).unwrap());
    assert_eq!(fx.with_vault(|vault| Node::wanted(vault)), None);
    assert_eq!(
        fx.node
            .ensure_questions_team(&fx.vault, "Synthetic Mac")
            .unwrap_err()
            .code,
        "tailnet_off"
    );
    assert_eq!(
        fx.node
            .move_approvals(&fx.vault, "Synthetic Mac")
            .unwrap_err()
            .code,
        "tailnet_off"
    );
    assert_eq!(fx.node.move_state(), MoveState::Idle);
    // The default port and gateway.
    let status = fx.node.status(&fx.vault).tailnet;
    assert!(!status.on && !status.running);
    assert_eq!(status.port, fx.port);
    assert_eq!(status.push_gateway, tailnet::DEFAULT_PUSH_GATEWAY);
    assert!(fx.node.set_tailnet_port(&fx.vault, Some(8443)).is_err());
    fx.node.set_tailnet_port(&fx.vault, None).unwrap();
    assert_eq!(fx.node.status(&fx.vault).tailnet.port, 8444);
}

/// "Move approvals to this Mac": a vault whose questions go through a hosted
/// notifications-only team (the in-process fake relay) moves them to a team on the node;
/// the hosted membership goes and the hosted relay gets the `DELETE`.
#[cfg(feature = "desktop")]
#[test]
fn move_approvals_ends_with_no_hosted_membership_and_a_delete_on_the_hosted_relay() {
    use crate::desktop::fake_relay::FakeRelay;
    use crate::relay::membership::{adopt_questions_team, new_questions_team};

    let fx = fixture();
    let hosted_relay = FakeRelay::start();
    let hosted = new_questions_team(
        &hosted_relay.url,
        &hosted_relay.team_code(),
        "Synthetic vault",
        "Synthetic Mac",
    )
    .unwrap();
    let hosted_team = hosted.team_id.clone();
    fx.with_vault(|vault| adopt_questions_team(vault, &hosted, "Synthetic Mac").unwrap());
    fx.start();
    let status = fx.node.status(&fx.vault).tailnet;
    assert_eq!(
        status.questions_elsewhere.as_deref(),
        Some(hosted_relay.url.as_str())
    );
    // A node team cannot be made beside the hosted one: the move does it.
    assert_eq!(
        fx.node
            .ensure_questions_team(&fx.vault, "Synthetic Mac")
            .unwrap_err()
            .code,
        "conflict"
    );
    let start = fx.node.move_approvals(&fx.vault, "Synthetic Mac").unwrap();
    assert_eq!(start.hosted_team, hosted_team);
    assert_eq!(
        fx.node.move_state(),
        MoveState::Pairing {
            team_id: start.team_id.clone(),
            hosted_team: hosted_team.clone(),
        }
    );
    // Until the end the questions still go through the hosted team.
    assert_eq!(
        fx.with_vault(|vault| questions_membership(vault).unwrap().unwrap().team_id),
        hosted_team
    );
    let done = fx.node.finish_move(&fx.vault, "Synthetic Mac").unwrap();
    assert_eq!(done.team_id, start.team_id);
    assert_eq!(fx.node.move_state(), MoveState::Idle);
    let now = fx.with_vault(|vault| questions_membership(vault).unwrap().unwrap());
    assert_eq!(now.team_id, start.team_id);
    assert_eq!(now.relay_url, fx.origin());
    assert!(now.pin.is_some());
    assert!(
        fx.with_vault(|vault| vault.relay_membership(&hosted_team).unwrap())
            .is_none(),
        "no hosted membership is left"
    );
    assert_eq!(
        fx.with_vault(|vault| vault.questions_team().unwrap()),
        Some(start.team_id.clone())
    );
    assert!(
        hosted_relay
            .log()
            .iter()
            .any(|line| line.starts_with("DELETE /v1/devices/")),
        "{:?}",
        hosted_relay.log()
    );
    let status = fx.node.status(&fx.vault).tailnet;
    assert_eq!(status.questions_elsewhere, None);
    assert_eq!(
        status.questions_team.as_deref(),
        Some(start.team_id.as_str())
    );
    // A second end has nothing to do.
    assert_eq!(
        fx.node
            .finish_move(&fx.vault, "Synthetic Mac")
            .unwrap_err()
            .code,
        "not_found"
    );
    fx.node.stop();
}
