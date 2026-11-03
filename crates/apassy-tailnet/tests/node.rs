//! The T0 acceptance tests (docs/design/implementation-plan-s4-teams.md, T0). They
//! need the Go archive: `cargo test -p apassy-tailnet --features tailnet` with the
//! pinned Go on PATH, or with APASSY_LIBTAILSCALE_DIR. Without the feature they
//! compile to nothing, so a build without Go skips them.
//!
//! None of them reaches a control server: the control URL is 127.0.0.1:1, where
//! nothing listens. No fixed host port and no fixed path: each test has its own
//! temporary state directory, and port 8443 is on the node's own userspace stack.

#![cfg(feature = "tailnet")]

use std::os::unix::fs::PermissionsExt;
use std::thread;
use std::time::{Duration, Instant};

use apassy_tailnet::{APASSY_PORT, BUILD, Error, TailnetNode, TailnetOptions};
use zeroize::Zeroizing;

const OFFLINE_CONTROL: &str = "http://127.0.0.1:1";
const FAKE_KEY: &str = "tskey-auth-kSpikeTest-NotARealKey0123456789";

fn offline(dir: &tempfile::TempDir, hostname: &str) -> TailnetOptions {
    let mut options = TailnetOptions::new(dir.path().join("state"), hostname);
    options.control_url = Some(OFFLINE_CONTROL.to_owned());
    options
}

#[test]
fn the_archive_links_and_a_node_object_is_made_and_dropped() {
    assert!(BUILD.linked, "the feature `tailnet` links the archive");
    let dir = tempfile::tempdir().unwrap();
    let mut options = offline(&dir, "apassy-t0-make");
    options.auth_key = Some(Zeroizing::new(FAKE_KEY.to_owned()));

    let node = TailnetNode::new(&options).expect("a node object");
    assert_eq!(node.hostname(), "apassy-t0-make");
    // Not started: tsnet has written no state yet.
    assert!(!node.dir().join("tailscaled.state").exists());
    let shown = format!("{node:?} {options:?}");
    assert!(!shown.contains("NotARealKey"), "{shown}");
    drop(node);

    let mode = std::fs::metadata(dir.path().join("state"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o700,
        "the state directory holds the node private key"
    );
}

#[test]
fn up_without_a_network_fails_with_a_readable_error() {
    let dir = tempfile::tempdir().unwrap();
    let mut options = offline(&dir, "apassy-t0-offline");
    options.auth_key = Some(Zeroizing::new(FAKE_KEY.to_owned()));
    options.up_timeout = Duration::from_secs(10);

    let started = Instant::now();
    let error = TailnetNode::up(options).expect_err("no control server, so no node");
    let elapsed = started.elapsed();
    let message = error.to_string();

    // The timeout, plus the close of the node (tsnet waits up to about 5 s).
    assert!(
        elapsed < Duration::from_secs(40),
        "took {elapsed:?}: {message}"
    );
    assert!(
        matches!(
            error,
            Error::UpTimeout { .. }
                | Error::Tailscale {
                    call: "tailscale_up",
                    ..
                }
        ),
        "{error:?}"
    );
    assert!(
        message.contains("apassy-t0-offline") || message.contains("tailscale_up"),
        "{message}"
    );
    assert!(!message.contains("NotARealKey"), "{message}");
}

#[test]
fn a_listener_on_the_apassy_port_refuses_a_second_bind() {
    let dir = tempfile::tempdir().unwrap();
    let node = TailnetNode::new(&offline(&dir, "apassy-t0-listen")).unwrap();
    node.start().unwrap();

    let first = node.listen(APASSY_PORT).expect("the first listener");
    assert_eq!(first.port(), APASSY_PORT);
    let second = node
        .listen(APASSY_PORT)
        .expect_err("a second listener on the Apassy port");
    let message = second.to_string();
    assert!(
        matches!(
            second,
            Error::Tailscale {
                call: "tailscale_listen",
                ..
            }
        ),
        "{second:?}"
    );
    assert!(message.contains("already"), "{message}");

    // Another port is not affected.
    drop(node.listen(APASSY_PORT + 1).expect("another port"));

    // Closing the first listener frees the port; Go sees the close asynchronously.
    drop(first);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match node.listen(APASSY_PORT) {
            Ok(_again) => break,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(100)),
            Err(error) => panic!("the port stayed taken after its listener closed: {error}"),
        }
    }
}

#[test]
fn dropping_the_node_ends_a_blocked_accept() {
    let dir = tempfile::tempdir().unwrap();
    let node = TailnetNode::new(&offline(&dir, "apassy-t0-close")).unwrap();
    node.start().unwrap();
    let listener = node.listen(APASSY_PORT).unwrap();

    let waiting = thread::spawn(move || listener.accept().map(|accepted| accepted.remote));
    thread::sleep(Duration::from_millis(500));
    let started = Instant::now();
    drop(node);
    let result = waiting.join().expect("the accept thread");
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
    assert!(
        matches!(result, Err(Error::Closed { .. } | Error::Tailscale { .. })),
        "{result:?}"
    );
}
