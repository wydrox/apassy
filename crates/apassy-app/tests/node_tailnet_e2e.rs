//! The Mac's node over the tailnet, end to end (plan S2–S3, unit N4). Synthetic values
//! only.
//!
//! The real embedded relay (`apassy_relay::embedded::EmbeddedRelay`) runs in the node
//! service of the app (`apassy::node::Node`) with its tailnet route on. The test hook of
//! `Node::with_test_tailnet` makes `127.0.0.1` the tailnet address: the real TLS front
//! binds and admits the loopback, with the node certificate and its pin. Then:
//!
//! 1. The Mac makes the questions team on the node in process and a device link through
//!    the local route of the node origin (plain HTTP to the relay's tailnet listener, the
//!    node origin signed): the link names the node origin, the pin, and the node name.
//! 2. The local route goes, so every later request of this process goes through the
//!    front over pinned TLS: a "device" (the Rust client pieces that the iPhone core
//!    uses) joins with the pinned link, the Mac confirms it with the same safety words,
//!    the Mac posts a question, the device reads it and answers, and the Mac reads the
//!    answer and settles. A link with another pin is refused.
//! 3. A stop closes the front: nothing listens on the port.

use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apassy::broker::SharedVault;
use apassy::broker::approvals::ApprovalQueue;
use apassy::broker::decide::BrokerContext;
use apassy::broker::http::TlsClient;
use apassy::broker::prompts::PromptStore;
use apassy::net::pin::Pin;
use apassy::node::funnel::{CliOutput, TailscaleCli};
use apassy::node::master_key::NoKeychain;
use apassy::node::{Node, NodeOptions};
use apassy::questions::{QuestionsClient, Sealed};
use apassy::sync::{PairedLink, PendingJoin, clear_local_route};
use apassy::vault::Vault;
use apassy_relay::embedded::EmbeddedRelay;

const PASS: &str = "synthetic-node-e2e-pass";
const QID: &str = "oKGio6SlpqeoqaqrrK2urw";
const KEY_ID: &str = "630dcd2966c43366";

/// No Tailscale on the test machine: the test hook stands in for it.
struct NoTailscale;

impl TailscaleCli for NoTailscale {
    fn run(&self, _args: &[&str]) -> Option<CliOutput> {
        None
    }
}

/// A directory of its own, removed at the end.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let path =
            std::env::temp_dir().join(format!("apassy-node-e2e-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn free_port() -> u16 {
    let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("probe");
    probe.local_addr().expect("address").port()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// A sealed body of synthetic bytes: the relay never opens it.
fn sealed(nonce: &str, ciphertext: &str) -> Sealed {
    Sealed {
        key_id: KEY_ID.to_owned(),
        nonce: nonce.to_owned(),
        ciphertext: ciphertext.to_owned(),
    }
}

fn broker(vault: &SharedVault) -> BrokerContext {
    BrokerContext {
        vault: Arc::clone(vault),
        tls: TlsClient::platform().expect("tls"),
        approvals: Arc::new(ApprovalQueue::new()),
        approval_timeout: Duration::from_secs(20),
        run_timeout: Duration::from_secs(20),
        bouncer: None,
        model_gate: None,
        prompts: Arc::new(PromptStore::new(Vec::new())),
    }
}

#[test]
fn a_device_pairs_with_the_pinned_link_and_answers_a_question_through_the_front() {
    let dir = TempDir::new();
    let port = free_port();
    let mut vault = Vault::create(&dir.0.join("vault.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    vault.set_cloud_tailnet_on(true).expect("tailnet on");
    vault.set_cloud_tailnet_port(Some(port)).expect("port");
    let vault: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let node = Node::new(NodeOptions {
        backend: Arc::new(EmbeddedRelay::default()),
        keys: Arc::new(NoKeychain),
        cli: Arc::new(NoTailscale),
        data_dir: dir.0.join("node"),
    })
    .with_test_tailnet();
    node.start(&vault, broker(&vault)).expect("the node starts");
    let origin = format!("https://127.0.0.1:{port}");
    assert_eq!(node.node_origin().as_deref(), Some(origin.as_str()));
    let status = node.status(&vault).tailnet;
    assert!(status.running, "{:?}", node.status(&vault).warnings);
    let pin = status.pin.clone().expect("a pin");

    // 1. The questions team on the node, and its link through the local route.
    let membership = node
        .ensure_questions_team(&vault, "Synthetic Mac")
        .expect("the questions team");
    assert_eq!(membership.relay_url, origin);
    assert_eq!(membership.pin.as_deref(), Some(pin.as_str()));
    let (mac, code) = node.pairing_link(&vault).expect("a pairing link");
    assert!(
        code.link
            .starts_with(&format!("{origin}/link#apassy_lnk_{}_", membership.team_id)),
        "the link names the node origin"
    );
    let paired = PairedLink::parse(&code.link).expect("the link reads back");
    assert_eq!(paired.origin, origin);
    assert_eq!(paired.pin.map(|pin| pin.text()), Some(pin.clone()));
    assert!(paired.name.is_some(), "the node name");

    // 2. From here every request goes through the front, with the pin.
    clear_local_route(&origin);
    let mut wrong = code.link.to_string();
    wrong = wrong.replace(&pin, &Pin::of_certificate(b"another synthetic node").text());
    assert!(
        PendingJoin::request(&wrong, "", "Synthetic iPhone").is_err(),
        "another pin is refused"
    );
    let pending =
        PendingJoin::request(&code.link, "", "Synthetic iPhone").expect("the device asks");
    let links = mac.pending_links(Some(&code)).expect("links");
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].safety.as_deref(), Some(pending.safety.as_str()));
    let device = mac.confirm_link(&links[0]).expect("confirm");
    let end = Instant::now() + Duration::from_secs(20);
    let joined = loop {
        if let Some(joined) = pending.poll().expect("poll") {
            break joined;
        }
        assert!(Instant::now() < end, "the join was not confirmed");
        std::thread::sleep(Duration::from_millis(100));
    };
    // `team()` is the name of the team; the member has its id.
    assert_eq!(joined.member().team_id(), membership.team_id);
    assert_eq!(joined.device_id(), device.id);
    let phone = QuestionsClient::from_member(joined.member());

    // A question of the Mac, the answer of the device, the settle of the Mac.
    let card = sealed(
        "AAECAwQFBgcICQoL",
        "c3ludGhldGljIHF1ZXN0aW9uIGNhcmQgY2lwaGVydGV4dCAwMDAx",
    );
    mac.post_question(QID, "member", now() + 300, &card)
        .expect("post");
    let listed = phone.list(0, Duration::ZERO).expect("list");
    let question = listed
        .questions
        .iter()
        .find(|question| question.qid == QID)
        .expect("the device sees the question");
    assert_eq!(question.ciphertext, card.ciphertext);
    assert_eq!(question.from_device_id, membership.device_id);
    phone
        .post_answer(
            QID,
            &sealed(
                "AQIDBAUGBwgJCgsM",
                "c3ludGhldGljIGFuc3dlciBjaXBoZXJ0ZXh0IGJvZHkgMDAwMg",
            ),
        )
        .expect("answer");
    let answers = mac.answers(QID, 0, Duration::ZERO).expect("answers");
    assert_eq!(answers.answers.len(), 1);
    assert_eq!(answers.answers[0].device_id, device.id);
    mac.settle(
        QID,
        &sealed(
            "AgMEBQYHCAkKCwwN",
            "c3ludGhldGljIHNldHRsZSBjaXBoZXJ0ZXh0IGJvZHkgMDAwMw",
        ),
    )
    .expect("settle");
    let after = phone.list(0, Duration::ZERO).expect("list again");
    assert!(
        after
            .questions
            .iter()
            .any(|question| question.qid == QID && question.state == "settled"),
        "the question is settled"
    );

    // 3. A stop closes the front and the relay.
    phone.close();
    mac.close();
    node.stop();
    assert!(!node.is_running());
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
}
