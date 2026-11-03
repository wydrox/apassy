//! The node without a window (plan S2-S3, unit L1): `serve` on a temporary directory
//! with the loopback test hook, reached through its TLS front with the pin; `pair` with
//! the running node; the shapes of `status --json` and `doctor --json`; the
//! `apassy-team` alias. Each node uses a free loopback port and its own directory under
//! `/tmp` (short paths for the Unix sockets). No Tailscale, no network, synthetic values.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use apassy::net::Pin;
use apassy::node::funnel::{CliOutput, TailscaleCli};
use apassy_relay::node::config::{CONTROL_SOCKET, NodeSettings, STATE_FILE, ensure_private_dir};
use apassy_relay::node::doctor::{self, CHECK_IDS};
use apassy_relay::node::serve::{self, ServeOptions, Serving};
use apassy_relay::node::status::{self, Probe};
use apassy_relay::node::{pair, team};
use apassy_relay::server::operator;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use serde_json::Value;

// ----- the client: pinned TLS 1.3 -----

#[derive(Debug)]
struct PinVerifier {
    pin: Pin,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if intermediates.is_empty() && self.pin.matches(end_entity.as_ref()) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("pin mismatch".to_owned()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

type Tls = StreamOwned<ClientConnection, TcpStream>;

fn connect(address: SocketAddr, pin: Pin) -> std::io::Result<Tls> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier { pin, provider }))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let socket = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let name = ServerName::try_from("apassy-node.invalid")
        .expect("name")
        .to_owned();
    let connection =
        ClientConnection::new(Arc::new(config), name).map_err(std::io::Error::other)?;
    let mut tls = StreamOwned::new(connection, socket);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    Ok(tls)
}

/// `GET /healthz` through the front: the status line.
fn healthz_through_front(address: SocketAddr, pin: Pin) -> std::io::Result<String> {
    let mut tls = connect(address, pin)?;
    let request = format!("GET /healthz HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes())?;
    tls.flush()?;
    let mut answer = Vec::new();
    // The relay closes after the answer; an unclean close of the TLS stream still has
    // the bytes.
    let _ = tls.read_to_end(&mut answer);
    let text = String::from_utf8_lossy(&answer).into_owned();
    Ok(text.lines().next().unwrap_or_default().to_owned())
}

// ----- the node -----

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .expect("a free port")
}

fn short_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("an")
        .tempdir_in("/tmp")
        .expect("a temporary directory")
}

/// A node directory with a free port and no push.
fn node_dir(root: &Path) -> (PathBuf, u16) {
    let dir = root.join("node");
    ensure_private_dir(&dir).unwrap();
    let port = free_port();
    NodeSettings {
        port,
        push_gateway: None,
        ..NodeSettings::default()
    }
    .save(&dir)
    .unwrap();
    (dir, port)
}

fn start(dir: &Path) -> Serving {
    let options = ServeOptions {
        node_dir: dir.to_owned(),
        credentials_dir: None,
        wait_for_tailnet: Some(Duration::from_secs(1)),
        test_loopback: true,
    };
    Serving::start(options)
        .expect("the node starts")
        .expect("no stop came")
}

#[test]
fn serve_answers_healthz_through_the_front_with_the_pin_and_stops_within_5_seconds() {
    let root = short_tempdir();
    let (dir, port) = node_dir(root.path());
    let serving = start(&dir);
    let state = serving.state().clone();
    assert_eq!(state.origin, format!("https://127.0.0.1:{port}"));
    assert_eq!(state.port, port);
    assert_eq!(state.bound, vec![format!("127.0.0.1:{port}")]);
    assert_eq!(state.key_source, "file");
    assert!(state.push_gateway.is_none());
    assert!(state.tailnet_target().is_some());
    assert!(dir.join(STATE_FILE).is_file());
    assert!(dir.join(CONTROL_SOCKET).exists());
    assert!(serve::is_running(&dir));
    assert!(serve::loopback_healthy(&state, Duration::from_secs(2)));

    let pin = apassy::net::pin::parse(&state.pin).expect("a pin");
    let front = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let line = healthz_through_front(front, pin).expect("through the front");
    assert!(line.starts_with("HTTP/1.1 200"), "{line}");

    // Another pin is refused in the handshake.
    let other = Pin::of_certificate(b"another certificate");
    assert!(connect(front, other).is_err());

    // A second node on the same directory is refused.
    let second = Serving::start(ServeOptions {
        node_dir: dir.clone(),
        credentials_dir: None,
        wait_for_tailnet: Some(Duration::from_secs(1)),
        test_loopback: true,
    });
    assert!(second.is_err());

    // `serve --stop` from another process waits until the node has stopped.
    let stopper = {
        let dir = dir.clone();
        std::thread::spawn(move || serve::stop_running(&dir, Duration::from_secs(10)))
    };
    let started = Instant::now();
    serving.wait();
    serving.stop();
    assert!(stopper.join().unwrap().unwrap());
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(TcpStream::connect_timeout(&front, Duration::from_secs(1)).is_err());
    assert!(!dir.join(STATE_FILE).exists());
    assert!(!dir.join(CONTROL_SOCKET).exists());
    assert!(!serve::is_running(&dir));
}

#[test]
fn a_restart_keeps_the_pin_and_the_key() {
    let root = short_tempdir();
    let (dir, _) = node_dir(root.path());
    let first = start(&dir);
    let pin = first.state().pin.clone();
    first.stop();
    let second = start(&dir);
    assert_eq!(second.state().pin, pin);
    second.stop();
}

/// True for a node pairing link of node-pairing-v1 section 5 with this origin and pin:
/// `/pair#`, a team code, the pin, and an optional canonical name, in this order.
fn is_pair_link(link: &str, origin: &str, pin: &str) -> bool {
    let Some(fragment) = link.strip_prefix(&format!("{origin}/pair#")) else {
        return false;
    };
    let mut parts = fragment.split('&');
    let code_ok = parts.next().is_some_and(|code| {
        code.strip_prefix("apassy_tcd_").is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
    });
    let pin_ok = parts.next() == Some(format!("pin={pin}").as_str());
    let rest: Vec<&str> = parts.collect();
    let name_ok = match rest.as_slice() {
        [] => true,
        [name] => name.strip_prefix("name=").is_some_and(|value| {
            let bytes = value.as_bytes();
            let mut index = 0;
            while index < bytes.len() {
                let b = bytes[index];
                if b == b'%' {
                    let hex = &bytes[index + 1..(index + 3).min(bytes.len())];
                    if hex.len() != 2
                        || !hex
                            .iter()
                            .all(|h| h.is_ascii_digit() || (b'A'..=b'F').contains(h))
                    {
                        return false;
                    }
                    index += 3;
                } else if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                    index += 1;
                } else {
                    return false;
                }
            }
            !value.is_empty()
        }),
        _ => false,
    };
    link.len() <= 2048 && code_ok && pin_ok && name_ok
}

#[test]
fn pair_makes_a_one_use_node_link_of_the_running_node() {
    let root = short_tempdir();
    let (dir, _) = node_dir(root.path());
    let serving = start(&dir);
    let state = serving.state().clone();
    let first = pair::make(&dir, 10).expect("a link");
    assert!(
        is_pair_link(&first.link, &state.origin, &state.pin),
        "{}",
        first.link
    );
    assert_eq!(first.origin, state.origin);
    assert_eq!(first.pin, state.pin);
    let now = apassy_relay::now_unix();
    assert!(first.expires_at > now && first.expires_at <= now + 600 + 5);
    let json = pair::to_json(&first);
    let mut keys: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["expires_at", "link", "origin", "pin"]);
    // A second link has another code.
    let second = pair::make(&dir, 1).expect("a second link");
    assert_ne!(first.link, second.link);
    serving.stop();
    // A stopped node makes no link.
    assert_eq!(pair::make(&dir, 10).unwrap_err().code, 3);
}

// ----- status and doctor -----

struct FakeTailscale;

impl TailscaleCli for FakeTailscale {
    fn run(&self, args: &[&str]) -> Option<CliOutput> {
        (args == ["status", "--json"]).then(|| CliOutput {
            success: true,
            stdout: r#"{"BackendState":"Running","Self":{"DNSName":"build-box.tail0123.ts.net.","TailscaleIPs":["100.64.0.7","fd7a:115c:a1e0::7"]}}"#.to_owned(),
            stderr: String::new(),
        })
    }
}

/// The system of a test: no systemd, a Tailscale that runs, the real control and
/// operator sockets.
struct FakeProbe {
    unit_dir: PathBuf,
}

impl Probe for FakeProbe {
    fn systemctl(&self, _args: &[&str]) -> Option<(i32, String)> {
        None
    }
    fn tailscale(&self) -> &dyn TailscaleCli {
        &FakeTailscale
    }
    fn running(&self, dir: &Path) -> bool {
        serve::is_running(dir)
    }
    fn operator(&self, dir: &Path, command: &operator::Command) -> Result<Value, String> {
        operator::send(&apassy_relay::node::config::admin_socket(dir), command)
            .map_err(|error| error.message)
    }
    fn unit_path(&self) -> Option<PathBuf> {
        Some(self.unit_dir.join("apassy-node.service"))
    }
    fn unit_dir(&self) -> Option<PathBuf> {
        Some(self.unit_dir.clone())
    }
    fn linger(&self) -> Option<bool> {
        Some(false)
    }
    fn gateway_date(&self, _gateway: &str) -> Option<u64> {
        Some(1_000_000)
    }
    fn bind(&self, _ip: IpAddr, _port: u16) -> Result<(), std::io::ErrorKind> {
        Ok(())
    }
    fn port_owner(&self, _port: u16) -> Option<String> {
        None
    }
    fn credentials_dir(&self) -> Option<PathBuf> {
        None
    }
    fn now(&self) -> u64 {
        1_000_000 + 30
    }
}

fn keys_of(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
    keys.sort_unstable();
    keys
}

fn sorted(words: &[&str]) -> Vec<String> {
    let mut list: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
    list.sort_unstable();
    list
}

#[test]
fn status_json_has_the_documented_shape() {
    let root = short_tempdir();
    let (dir, port) = node_dir(root.path());
    let probe = FakeProbe {
        unit_dir: root.path().join("units"),
    };
    // A stopped node: no pin yet, no teams.
    let stopped = serde_json::to_value(status::collect(&dir, &probe).unwrap()).unwrap();
    assert_eq!(
        keys_of(&stopped),
        sorted(&[
            "version",
            "data_dir",
            "running",
            "pid",
            "started_at",
            "service",
            "routes",
            "pin",
            "teams",
            "push_gateway",
            "key",
        ])
    );
    assert_eq!(stopped["running"], false);
    assert_eq!(stopped["pin"], Value::Null);
    assert_eq!(stopped["routes"]["tailnet"]["port"], port);
    assert_eq!(stopped["routes"]["funnel"], "n/a");
    assert_eq!(stopped["routes"]["lan"], "off");
    assert_eq!(stopped["key"]["source"], "none");
    assert_eq!(
        keys_of(&stopped["service"]),
        sorted(&["unit", "installed", "enabled", "active"])
    );
    assert_eq!(
        keys_of(&stopped["routes"]["tailnet"]),
        sorted(&["origin", "port", "route", "bound", "alternatives"])
    );
    assert_eq!(keys_of(&stopped["key"]), sorted(&["source", "path"]));

    // A running node: its origin, pin, addresses, and its (empty) team list.
    let serving = start(&dir);
    let running = serde_json::to_value(status::collect(&dir, &probe).unwrap()).unwrap();
    assert_eq!(running["running"], true);
    assert_eq!(running["pin"], serving.state().pin.as_str());
    assert_eq!(
        running["routes"]["tailnet"]["origin"],
        serving.state().origin.as_str()
    );
    assert_eq!(running["routes"]["tailnet"]["route"], "direct");
    assert_eq!(running["teams"], Value::Array(Vec::new()));
    assert!(running.get("teams_error").is_none(), "{running}");
    assert_eq!(running["key"]["source"], "file");
    serving.stop();

    // After the stop, the pin is read from the certificate on disk.
    let after = serde_json::to_value(status::collect(&dir, &probe).unwrap()).unwrap();
    assert_eq!(after["running"], false);
    assert_eq!(after["pin"], running["pin"]);
}

#[test]
fn doctor_json_has_the_documented_shape() {
    let root = short_tempdir();
    let (dir, _) = node_dir(root.path());
    let units = root.path().join("units");
    std::fs::create_dir_all(&units).unwrap();
    // A host service of the old binary.
    std::fs::write(
        units.join("apassy-team-host-t_7k2m5q4x3c.service"),
        "[Service]\nExecStart=/usr/local/bin/apassy-team --team t_7k2m5q4x3c host --dialog\n",
    )
    .unwrap();
    let probe = FakeProbe { unit_dir: units };
    let report = serde_json::to_value(doctor::collect(&dir, &probe).unwrap()).unwrap();
    assert_eq!(keys_of(&report), sorted(&["ok", "checks"]));
    let checks = report["checks"].as_array().unwrap();
    let ids: Vec<&str> = checks
        .iter()
        .map(|check| check["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, CHECK_IDS);
    for check in checks {
        let keys = keys_of(check);
        assert!(
            keys == sorted(&["id", "status", "detail"])
                || keys == sorted(&["id", "status", "detail", "hint"]),
            "{check}"
        );
        assert!(
            ["pass", "warn", "fail", "skip"].contains(&check["status"].as_str().unwrap()),
            "{check}"
        );
    }
    let by_id = |id: &str| {
        checks
            .iter()
            .find(|check| check["id"] == id)
            .cloned()
            .unwrap()
    };
    assert_eq!(by_id("tailscale_installed")["status"], "pass");
    assert_eq!(by_id("tailscale_running")["status"], "pass");
    assert_eq!(by_id("data_dir")["status"], "pass");
    assert_eq!(by_id("linger")["status"], "warn");
    assert_eq!(by_id("clock")["status"], "skip", "push is off");
    assert_eq!(by_id("old_host_service")["status"], "warn");
    assert!(
        by_id("old_host_service")["hint"]
            .as_str()
            .unwrap()
            .contains("apassy team host install")
    );
    // The fake Tailscale address is on no interface of the test machine.
    assert_eq!(by_id("tailscale_address")["status"], "fail");
    assert_eq!(report["ok"], false);
}

// ----- the apassy-team alias -----

#[test]
fn the_alias_prints_one_deprecation_line_and_the_same_stdout() {
    let bin = env!("CARGO_BIN_EXE_apassy-team");
    let home = short_tempdir();
    let run = |deprecation: bool| {
        let mut command = Command::new(bin);
        command
            .arg("--version")
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join("config"))
            .env_remove(team::DEPRECATION_ENV);
        if deprecation {
            command.env(team::DEPRECATION_ENV, "1");
        }
        command.output().expect("run apassy-team")
    };
    let plain = run(false);
    let warned = run(true);
    assert!(plain.status.success());
    assert!(warned.status.success());
    let version = format!("apassy-team {}\n", env!("CARGO_PKG_VERSION"));
    assert_eq!(String::from_utf8_lossy(&plain.stdout), version);
    assert_eq!(plain.stdout, warned.stdout);
    // Not a terminal: no line, so scripts and MCP clients see no change.
    assert!(plain.stderr.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&warned.stderr),
        format!("{}\n", team::DEPRECATION_LINE)
    );
}
