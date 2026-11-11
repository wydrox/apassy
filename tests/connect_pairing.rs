#![cfg(feature = "vault")]

//! Approvals through Apassy Connect (plan s7 unit M5; contracts node-pairing-v1 section
//! 7a and connect-tunnel-v1 section 3.3). Synthetic values only; no network beyond the
//! loopback.
//!
//! The node is the in-process fake relay behind the real TLS front of a node
//! (`apassy::net::tls_front`) with a new self-signed node certificate. Its origin is a
//! closed port on the loopback: the tailnet address does not answer. The pairing code
//! carries the Connect route as its last alternative; the simulated iPhone core joins
//! with the same calls as `ios/ApassyCore` (`PendingJoin::request_via` with its dialer,
//! `PairingChannel::receive`), and its dialer stands in for the Connect dial: a byte pipe
//! to the node's TLS front, inside which the client runs the pinned TLS of the pin.
//!
//! - A code with both routes pairs the iPhone over the dial when the tailnet address is
//!   unreachable; the code without the route is the code of today.
//! - The handoff (its AAD text, the safety words, and the question key it carries) is the
//!   same through the dial.
//! - "Move Approvals to Connect" keeps the hosted membership and its devices until the
//!   first question went round through the new route, and only then takes them off.
//! - A revoke on the node holds at the next request of the iPhone through the dial.

use crate::common::fake_relay;

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use apassy::net::certificate::NodeCertificate;
use apassy::net::pin::Pin;
use apassy::net::tls_front::{Front, FrontHandle, FrontLimits, FrontOptions};
use apassy::questions::QuestionsClient;
use apassy::questions::QuestionsError;
use apassy::questions::device_link::link_device_name;
use apassy::questions::envelope::{Sealed, new_qid};
use apassy::relay::membership::{
    adopt_questions_team, finish_move_to_connect, leave_hosted_team, move_questions_keeping_hosted,
    new_questions_team, new_questions_team_at, questions_membership, register_linked_device,
    retiring_questions_membership,
};
use apassy::relay::pairing::PairingChannel;
use apassy::sync::{
    DEFAULT_RELAY_URL, DeviceKey, HttpError, NodeRoute, PairedLink, PendingJoin, RelayUrl,
    TlsTrust, TunnelDialer, TunnelPipe, TunnelRoute,
};
use apassy::vault::{QuestionKey, RelayMembership, Vault};
use fake_relay::FakeRelay;
use tempfile::TempDir;

const PASS: &str = "synthetic-connect-pairing-pass";
const NODE: &str = "node_k7m2q4x3ca";
const IPHONE: &str = "Synthetic iPhone";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The bytes of a dial: a TCP stream to the node's TLS front.
struct TcpPipe(TcpStream);

impl Read for TcpPipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for TcpPipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl TunnelPipe for TcpPipe {
    fn set_read_timeout(&self, timeout: Duration) -> std::io::Result<()> {
        self.0.set_read_timeout(Some(timeout))
    }
    fn set_write_timeout(&self, timeout: Duration) -> std::io::Result<()> {
        self.0.set_write_timeout(Some(timeout))
    }
    fn closer(&self) -> Arc<dyn Fn() + Send + Sync> {
        let stream = self.0.try_clone().expect("clone");
        Arc::new(move || {
            let _ = stream.shutdown(Shutdown::Both);
        })
    }
}

/// The Connect dial of the simulated iPhone core: it counts its dials and the routes
/// that reached the node.
struct Dialer {
    front: SocketAddr,
    dials: AtomicUsize,
    reached: Mutex<Vec<NodeRoute>>,
}

impl TunnelDialer for Dialer {
    fn direct_first(&self, _url: &RelayUrl) -> bool {
        true
    }
    fn reached(&self, _url: &RelayUrl, route: NodeRoute) {
        self.reached.lock().unwrap().push(route);
    }
    fn direct_failed(&self, _url: &RelayUrl) {}
    fn dial(
        &self,
        route: &TunnelRoute,
        _deadline: Instant,
    ) -> Result<Box<dyn TunnelPipe>, HttpError> {
        assert_eq!(route.node(), NODE, "the dial names the node of the code");
        self.dials.fetch_add(1, Ordering::SeqCst);
        let stream = TcpStream::connect(self.front).map_err(|_| HttpError::Connect)?;
        Ok(Box::new(TcpPipe(stream)))
    }
}

/// The node: the fake relay behind a TLS front with a node certificate, its origin at a
/// closed port (the tailnet address that does not answer), the pin, and the front.
struct Node {
    relay: FakeRelay,
    _front: FrontHandle,
    front: SocketAddr,
    origin: String,
    pin: Pin,
}

fn node() -> Node {
    let relay = FakeRelay::start();
    let target: SocketAddr = relay
        .url
        .strip_prefix("http://")
        .expect("plain fake relay")
        .parse()
        .expect("loopback address");
    let certificate = NodeCertificate::generate("Synthetic Studio").expect("certificate");
    let pin = certificate.pin;
    let mut options = FrontOptions::new(
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        0,
        certificate,
        target,
    );
    options.allow_loopback_bind = true;
    options.allow_test_peers = true;
    options.limits = FrontLimits {
        max_connections: 256,
        max_per_peer: 256,
        new_per_peer_per_minute: 100_000,
        ..FrontLimits::default()
    };
    let front_handle = Front::start(options).expect("front");
    let front = front_handle.bound()[0];
    // A port that nothing listens on: the tailnet address of the code.
    let closed = {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        listener.local_addr().expect("addr").port()
    };
    let origin = format!("https://127.0.0.1:{closed}");
    relay.set_origin(&origin);
    Node {
        relay,
        _front: front_handle,
        front,
        origin,
        pin,
    }
}

/// The Connect route of the node through the configured Connect origin of this build.
fn route() -> TunnelRoute {
    TunnelRoute::new(&apassy::connect::configured_origin(), NODE).expect("route")
}

/// This Mac's way to its own node: the origin with the front as an alternative (the Mac
/// reaches its node locally; the code never names that destination).
fn mac_url(node: &Node) -> RelayUrl {
    RelayUrl::parse_with_trust(&node.origin, TlsTrust::Pinned(node.pin))
        .expect("origin")
        .alternatives(&[format!("127.0.0.1:{}", node.front.port())])
        .expect("alternative")
}

/// The address that the code names: the origin, the pin, and the Connect route.
fn advertised(node: &Node, with_route: bool) -> RelayUrl {
    let url = RelayUrl::parse_with_trust(&node.origin, TlsTrust::Pinned(node.pin)).expect("url");
    if with_route {
        url.with_tunnel(Some(route())).expect("route")
    } else {
        url
    }
}

/// A Mac vault, unlocked, with a question key and this Mac in the team of `membership`.
fn mac_vault(root: &TempDir, membership: &RelayMembership) -> Vault {
    let mut vault = Vault::create(&root.path().join("mac.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    adopt_questions_team(&mut vault, membership, "Synthetic Mac").expect("adopt");
    vault
}

/// What the simulated iPhone core keeps after its join: its client of the team, its
/// relay key, and the handoff it received.
struct Phone {
    client: QuestionsClient,
    device_id: u64,
    handoff: apassy::relay::pairing::Handoff,
    aad_text: String,
}

/// The pairing of an iPhone with the code `link` (with the ADR 0032 handoff) shown by
/// the Mac whose client of the node team is `mac`: the iPhone joins through `dialer`, the
/// Mac confirms with the same safety words and registers it, and sends the handoff; the
/// iPhone reads it. Returns the iPhone.
fn pair(
    vault: &mut Vault,
    mac: &QuestionsClient,
    code: &apassy::sync::LinkCode,
    raw: &str,
    dialer: Arc<Dialer>,
) -> Phone {
    let channel = PairingChannel::generate(raw).expect("channel");
    let link = channel.link(raw);
    // The iPhone: the grammar, the handoff, and the join through its transport.
    let (aad_text, phone_channel) = PairingChannel::parse(&link).expect("handoff");
    let answer = DeviceKey::generate().expect("answer key");
    let name = link_device_name(IPHONE, answer.public_key()).expect("name");
    let key = DeviceKey::generate().expect("key");
    let pending = PendingJoin::request_via(
        &link,
        DEFAULT_RELAY_URL,
        &name,
        key,
        Some(dialer as Arc<dyn TunnelDialer>),
    )
    .expect("request through the dial");
    // The Mac: the same words, then the confirmation and the row of the iPhone.
    let links = mac.pending_links(Some(code)).expect("links");
    assert_eq!(links.len(), 1);
    // The six words of the handoff (ADR 0032), as the add sheet shows them.
    assert_eq!(
        channel.mac_safety(mac.team_id(), &links[0].public_key, &links[0].device_name),
        Some(pending.safety.clone()),
        "both devices show the same words"
    );
    let device = mac.confirm_link(&links[0]).expect("confirm");
    register_linked_device(
        vault,
        mac.team_id(),
        device.id,
        &links[0].device_name,
        &links[0].public_key,
    )
    .expect("register")
    .expect("an iPhone row");
    let sealed = channel
        .seal(vault, mac.team_id(), &links[0].public_key)
        .expect("seal");
    channel.send(mac, now() + 300, &sealed).expect("send");
    // The iPhone: confirmed, then the handoff through the dial.
    let joined = pending.poll().expect("poll").expect("confirmed");
    let phone_key = DeviceKey::from_pkcs8(joined.key_pkcs8().expect("key")).expect("key");
    assert_eq!(
        phone_channel.phone_safety(mac.team_id(), &phone_key, &name),
        channel.mac_safety(mac.team_id(), phone_key.public_key(), &name),
        "both devices compute the same words"
    );
    let client = QuestionsClient::from_member(joined.member());
    let handoff = phone_channel
        .receive(&client, mac.team_id(), &phone_key, &name)
        .expect("receive")
        .expect("the handoff");
    Phone {
        client,
        device_id: device.id,
        handoff,
        aad_text: aad_text.to_owned(),
    }
}

/// A sealed card or answer of the contract's shape: the key of the vault, random bytes.
fn sealed(key: &QuestionKey, what: &[u8]) -> Sealed {
    Sealed::new(key, b"synthetic aad", what).expect("seal")
}

/// Node-pairing-v1 section 7a and plan s7 unit M5: the code of a node on Connect carries
/// the route beside the tailnet address; the iPhone pairs through the dial when the
/// tailnet address does not answer, and the handoff is the handoff of today: the same
/// words, the AAD text of the link as written, and the question key of the vault.
#[test]
fn a_code_with_both_routes_pairs_an_iphone_through_the_dial() {
    let root = TempDir::new().expect("dir");
    let node = node();
    let membership =
        new_questions_team_at(&mac_url(&node), &node.relay.team_code(), "Personal", "Mac")
            .expect("node team");
    let mut vault = mac_vault(&root, &membership);
    let mac = QuestionsClient::from_membership(&membership).expect("client");
    let code = mac.create_link().expect("link");

    // Without the route the code is the code of today: an older iPhone app reads it.
    let plain = code
        .for_origin(&advertised(&node, false), Some("Studio"))
        .expect("plain");
    assert!(!plain.link.contains("node="), "{}", plain.link.as_str());
    assert!(!plain.link.contains("wss://"), "{}", plain.link.as_str());

    let routed = code
        .for_origin(&advertised(&node, true), Some("Studio"))
        .expect("routed");
    let raw = routed.link.as_str().to_owned();
    assert!(
        raw.contains(&format!("&alt={}&node={NODE}", route().text())),
        "{raw}"
    );
    let read = PairedLink::parse(&raw).expect("the grammar reads it");
    assert_eq!(read.origin, node.origin);
    assert_eq!(read.pin, Some(node.pin));
    // The fragment never reaches a server: the node saw no pin and no route.
    let dialer = Arc::new(Dialer {
        front: node.front,
        dials: AtomicUsize::new(0),
        reached: Mutex::new(Vec::new()),
    });
    let phone = pair(&mut vault, &mac, &routed, &raw, Arc::clone(&dialer));
    assert!(dialer.dials.load(Ordering::SeqCst) > 0, "through the dial");
    assert!(
        dialer
            .reached
            .lock()
            .unwrap()
            .iter()
            .all(|route| *route == NodeRoute::Tunnel),
        "every connection went through Connect: {:?}",
        dialer.reached.lock().unwrap()
    );
    assert!(
        !node
            .relay
            .log()
            .iter()
            .any(|line| line.contains("pin=") || line.contains("node=") || line.contains(NODE)),
        "the fragment stays on the devices"
    );
    // The AAD text is the link as written, with the route: the words cover it.
    assert_eq!(phone.aad_text, raw);
    // The question key transfer: the key and the rows of the vault, unchanged.
    let (key, at, by) = vault.question_key_for_handoff().expect("key");
    assert_eq!(
        phone.handoff.question_key.as_slice(),
        key.bytes().as_slice()
    );
    assert_eq!(phone.handoff.key_updated_at, at);
    assert_eq!(phone.handoff.key_updated_by, by);
    assert_eq!(phone.handoff.team_id, membership.team_id);
    assert!(
        phone
            .handoff
            .devices
            .iter()
            .any(|device| device.name == IPHONE)
    );
    // A question of the Mac reaches the iPhone through the dial with the same bytes.
    let qid = new_qid().expect("qid");
    let card = sealed(&key, b"synthetic card");
    mac.post_question(&qid, "member", now() + 300, &card)
        .expect("post");
    let listed = phone.client.list(0, Duration::ZERO).expect("list");
    let question = listed
        .questions
        .iter()
        .find(|question| question.qid == qid)
        .expect("the iPhone sees the question");
    assert_eq!(
        question.ciphertext, card.ciphertext,
        "the digest input is unchanged"
    );
    assert_eq!(question.nonce, card.nonce);
}

/// Plan s7 section 5 and unit M5: "Move Approvals to Connect". After the iPhone paired
/// through the code with the route, the vault asks through the node team while the
/// hosted membership and its devices stay; they leave the hosted relay only after the
/// first question went round through the new route. A revoke on the node holds at the
/// next request of the iPhone.
#[test]
fn the_move_to_connect_retires_the_hosted_path_only_after_the_first_round_trip() {
    let root = TempDir::new().expect("dir");
    let hosted = FakeRelay::start();
    let hosted_membership = new_questions_team(
        &hosted.url,
        &hosted.team_code(),
        "Personal",
        "Synthetic Mac",
    )
    .expect("hosted team");
    let mut vault = mac_vault(&root, &hosted_membership);
    let hosted_team = hosted_membership.team_id.clone();
    let hosted_devices = hosted.team_devices(&hosted_team).len();
    assert!(hosted_devices >= 1);

    // The node team of the move, and the iPhone pairs through the dial. The fake relays
    // number their teams alike: a first team on the node gives it another id.
    let node = node();
    new_questions_team_at(&mac_url(&node), &node.relay.team_code(), "Other", "Mac")
        .expect("a first node team");
    let membership =
        new_questions_team_at(&mac_url(&node), &node.relay.team_code(), "Personal", "Mac")
            .expect("node team");
    let mac = QuestionsClient::from_membership(&membership).expect("client");
    let code = mac.create_link().expect("link");
    let routed = code
        .for_origin(&advertised(&node, true), Some("Studio"))
        .expect("routed");
    let raw = routed.link.as_str().to_owned();
    // The move keeps the hosted path; the node team needs the vault's question key and
    // this Mac's row first, as the window's move does.
    move_questions_keeping_hosted(&mut vault, &membership, &hosted_team, "Synthetic Mac")
        .expect("move");
    let dialer = Arc::new(Dialer {
        front: node.front,
        dials: AtomicUsize::new(0),
        reached: Mutex::new(Vec::new()),
    });
    let phone = pair(&mut vault, &mac, &routed, &raw, dialer);
    assert_eq!(
        questions_membership(&vault).unwrap().unwrap().team_id,
        membership.team_id,
        "the questions go through the node team"
    );
    // Before the round trip: the hosted membership and its devices stay.
    let kept = retiring_questions_membership(&vault)
        .unwrap()
        .expect("the hosted path stays");
    assert_eq!(kept.team_id, hosted_team);
    assert_eq!(hosted.team_devices(&hosted_team).len(), hosted_devices);
    assert_eq!(hosted.count("DELETE /v1/devices"), 0);

    // The first round trip through the new route: the Mac asks, the iPhone answers
    // through the dial, the Mac reads the answer.
    let (key, _, _) = vault.question_key_for_handoff().expect("key");
    let qid = new_qid().expect("qid");
    mac.post_question(&qid, "member", now() + 300, &sealed(&key, b"card"))
        .expect("post");
    phone
        .client
        .post_answer(&qid, &sealed(&key, b"answer"))
        .expect("the iPhone answers through the dial");
    let answers = mac.answers(&qid, 0, Duration::ZERO).expect("answers");
    assert_eq!(answers.answers.len(), 1, "the round trip went through");

    // Only now: the hosted devices leave and the membership goes.
    assert!(leave_hosted_team(&kept), "every other device left");
    assert!(hosted.count("DELETE /v1/devices") >= 1);
    finish_move_to_connect(&mut vault).expect("finish");
    assert!(retiring_questions_membership(&vault).unwrap().is_none());
    assert!(vault.relay_membership(&hosted_team).unwrap().is_none());
    assert_eq!(
        questions_membership(&vault).unwrap().unwrap().team_id,
        membership.team_id
    );

    // A revoke on the node: the next request of the iPhone through the dial is refused.
    mac.remove_device(phone.device_id).expect("revoke");
    let refused = phone.client.list(0, Duration::ZERO).unwrap_err();
    assert!(
        matches!(refused, QuestionsError::Removed),
        "the next request: {refused:?}"
    );
}
