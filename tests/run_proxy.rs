#![cfg(feature = "vault")]

//! The run proxy (ADR 0011) with real clients: curl, Python, and Node when they are
//! installed. A synthetic HTTPS service checks the real value. The process gets only
//! a placeholder. Synthetic values only.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use apassy::broker::exec::{self, Network, RunOutput, SecretEnv};
use apassy::broker::http::TlsClient;
use apassy::broker::proxy::{
    HostRule, OtherHosts, ProxyEvent, ProxyOptions, ProxyOutcome, ProxySecret, RunProxy,
    mint_placeholder,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use zeroize::Zeroizing;

const REAL: &str = "sk_live_FAKE-proxy-value-0123456789-abcdefghij-KLMN";
const OTHER_REAL: &str = "ghp_FAKE-other-value-0123456789-abcdefghij-KLMN";
const NAME: &str = "DEMO_KEY";

/// What the service got.
#[derive(Debug, Clone)]
struct Seen {
    path: String,
    authorization: Option<String>,
    body: String,
}

struct Service<T = Seen> {
    port: u16,
    root: CertificateDer<'static>,
    seen: Arc<Mutex<Vec<T>>>,
}

fn validity(params: &mut CertificateParams) {
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(1);
}

/// An HTTPS service on `localhost` with its own test root.
fn start_service() -> Service {
    start_service_with(serve)
}

/// An HTTPS service on `localhost` with its own test root; `handler` serves each
/// connection.
fn start_service_with<T: Send + 'static>(
    handler: fn(StreamOwned<ServerConnection, TcpStream>, &Mutex<Vec<T>>),
) -> Service<T> {
    let mut root = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Apassy proxy test root");
    root.distinguished_name = name;
    root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    validity(&mut root);
    let root_key = KeyPair::generate().expect("root key");
    let root_cert = root.self_signed(&root_key).expect("root");
    let issuer = Issuer::new(root, root_key);
    let mut leaf = CertificateParams::new(vec!["localhost".to_owned()]).expect("leaf");
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.use_authority_key_identifier_extension = true;
    validity(&mut leaf);
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf_cert = leaf.signed_by(&leaf_key, &issuer).expect("leaf cert");
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf_cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .expect("server config");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let config = Arc::new(config);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let thread_seen = Arc::clone(&seen);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let config = Arc::clone(&config);
            let seen = Arc::clone(&thread_seen);
            thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
                let Ok(tls) = ServerConnection::new(config) else {
                    return;
                };
                handler(StreamOwned::new(tls, stream), &seen);
            });
        }
    });
    Service {
        port,
        root: root_cert.der().clone(),
        seen,
    }
}

fn serve(stream: StreamOwned<ServerConnection, TcpStream>, seen: &Mutex<Vec<Seen>>) {
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let path = line.split(' ').nth(1).unwrap_or_default().to_owned();
        let mut authorization = None;
        let mut length = 0usize;
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 {
                return;
            }
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            let (name, value) = header.split_once(':').unwrap_or((header, ""));
            match name.to_ascii_lowercase().as_str() {
                "authorization" => authorization = Some(value.trim().to_owned()),
                "content-length" => length = value.trim().parse().unwrap_or(0),
                _ => {}
            }
        }
        let mut body = vec![0u8; length];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        seen.lock().expect("seen").push(Seen {
            path: path.clone(),
            authorization: authorization.clone(),
            body: String::from_utf8_lossy(&body).into_owned(),
        });
        let authorized = authorization.as_deref() == Some(&format!("Bearer {REAL}"));
        let out = reader.get_mut();
        let answer = match path.as_str() {
            "/whoami" if authorized => ok("200 OK", "{\"ok\":true}"),
            "/whoami" => ok("401 Unauthorized", "{\"ok\":false}"),
            // A service that returns the value, as `vercel env pull` does.
            "/leak" => ok("200 OK", &format!("{{\"value\":\"{REAL}\"}}")),
            "/chunked-leak" => {
                let (a, b) = REAL.split_at(11);
                format!(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\nv={a}\r\n{:x}\r\n{b};\r\n0\r\n\r\n",
                    a.len() + 2,
                    b.len() + 1
                )
            }
            "/store" => ok("201 Created", "{\"stored\":true}"),
            _ => ok("404 Not Found", "{}"),
        };
        if out.write_all(answer.as_bytes()).is_err() || out.flush().is_err() {
            return;
        }
    }
}

fn ok(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

struct Run {
    proxy: RunProxy,
    placeholder: String,
    other_placeholder: String,
}

fn start_proxy<T>(service: &Service<T>, other_hosts: OtherHosts) -> Run {
    let placeholder = mint_placeholder(REAL).expect("placeholder");
    let other_placeholder = mint_placeholder(OTHER_REAL).expect("placeholder");
    let secrets = vec![
        ProxySecret {
            name: NAME.to_owned(),
            placeholder: placeholder.clone(),
            value: Zeroizing::new(REAL.to_owned()),
            hosts: vec![HostRule::parse(&format!("localhost:{}", service.port)).expect("rule")],
        },
        ProxySecret {
            name: "OTHER_KEY".to_owned(),
            placeholder: other_placeholder.clone(),
            value: Zeroizing::new(OTHER_REAL.to_owned()),
            hosts: vec![HostRule::parse("api.github.invalid").expect("rule")],
        },
    ];
    let proxy = RunProxy::start(
        secrets,
        ProxyOptions {
            tls: TlsClient::with_extra_roots(vec![service.root.clone()]).expect("tls"),
            other_hosts,
            enforce: true,
        },
    )
    .expect("proxy");
    Run {
        proxy,
        placeholder,
        other_placeholder,
    }
}

fn node_dir() -> Option<String> {
    let path = std::env::var("PATH").unwrap_or_default();
    path.split(':')
        .find(|dir| Path::new(dir).join("node").is_file())
        .map(str::to_owned)
}

/// The `PATH` of a run: the system folders and the folder of `node`.
fn run_path() -> String {
    match node_dir() {
        Some(dir) => format!("/usr/bin:/bin:{dir}"),
        None => "/usr/bin:/bin".to_owned(),
    }
}

/// Whether the `node` of a run reads `HTTPS_PROXY`. Node before 22.21 ignores it
/// and connects directly (Debian 13 has Node 20). The probe names a closed port as
/// the proxy: a node that reads the variable is refused there, and one that ignores
/// it looks up the name instead.
fn node_reads_proxy_variables() -> bool {
    let Ok(port) = TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
    else {
        return false;
    };
    std::process::Command::new("node")
        .args([
            "-e",
            "fetch('https://apassy.invalid/').catch(e=>console.log((e.cause||e).code))",
        ])
        .env("PATH", run_path())
        .env("NODE_USE_ENV_PROXY", "1")
        .env("HTTPS_PROXY", format!("http://127.0.0.1:{port}"))
        .output()
        .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).contains("ECONNREFUSED"))
}

fn run(run: &Run, script: &str) -> RunOutput {
    // A folder of its own: on Linux the sandbox of a run cannot have `/tmp` itself
    // as its working directory (the sandbox hides the host `/tmp`).
    let cwd = tempfile::tempdir().expect("cwd");
    let network = run.proxy.network();
    let env = [
        SecretEnv {
            name: NAME.to_owned(),
            value: Zeroizing::new(run.placeholder.clone()),
        },
        SecretEnv {
            name: "OTHER_KEY".to_owned(),
            value: Zeroizing::new(run.other_placeholder.clone()),
        },
    ];
    let masks = [SecretEnv {
        name: NAME.to_owned(),
        value: Zeroizing::new(REAL.to_owned()),
    }];
    exec::run_with(
        &["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()],
        cwd.path(),
        Some(&run_path()),
        &env,
        &masks,
        Network::from(network),
        Duration::from_secs(60),
    )
    .expect("run")
}

fn reversed(text: &str) -> String {
    text.chars().rev().collect()
}

fn events(run: Run) -> Vec<ProxyEvent> {
    run.proxy.finish()
}

#[test]
fn curl_gets_the_real_value_only_at_the_service() {
    let service = start_service();
    let proxied = start_proxy(&service, OtherHosts::Tunnel);
    let out = run(
        &proxied,
        &format!(
            "curl -sS https://localhost:{}/whoami -H \"Authorization: Bearer $DEMO_KEY\"; echo; printf %s \"$DEMO_KEY\" | rev",
            service.port
        ),
    );
    assert_eq!(out.exit_code, Some(0), "{out:?}");
    assert!(out.stdout.contains("{\"ok\":true}"), "{out:?}");
    // The process holds the placeholder, not the value.
    assert!(
        out.stdout.contains(&reversed(&proxied.placeholder)),
        "{out:?}"
    );
    assert!(!out.stdout.contains(&reversed(REAL)));
    let seen = service.seen.lock().expect("seen").clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].authorization.as_deref(),
        Some(format!("Bearer {REAL}").as_str())
    );
    let log = events(proxied);
    assert_eq!(log.len(), 1, "{log:?}");
    assert_eq!(log[0].outcome, ProxyOutcome::Swapped);
    assert_eq!(log[0].status, Some(200));
    assert_eq!(log[0].path.as_deref(), Some("/whoami"));
    assert_eq!(log[0].secrets, vec![NAME.to_owned()]);
    let text = format!("{log:?}");
    assert!(!text.contains(REAL));
}

/// A `python3` on `PATH` that reads `SSL_CERT_FILE`. Apple's Python 3.9 (LibreSSL
/// 2.8.3) does not read it.
fn openssl_python() -> Option<String> {
    let path = std::env::var("PATH").unwrap_or_default();
    path.split(':')
        .map(|dir| Path::new(dir).join("python3"))
        .filter(|python| python.is_file())
        .find(|python| {
            std::process::Command::new(python)
                .args(["-c", "import ssl; print(ssl.OPENSSL_VERSION)"])
                .output()
                .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).starts_with("OpenSSL"))
        })
        .map(|python| python.display().to_string())
}

fn python_script(python: &str, port: u16) -> String {
    format!(
        "{python} -c \"import os,urllib.request as u; r=u.Request('https://localhost:{port}/whoami', headers={{'Authorization':'Bearer '+os.environ['DEMO_KEY']}}); print(u.urlopen(r).read().decode())\""
    )
}

#[test]
fn python_and_node_use_the_proxy_too() {
    let service = start_service();
    let proxied = start_proxy(&service, OtherHosts::Tunnel);
    let port = service.port;
    let mut swapped = 0;
    if let Some(python) = openssl_python() {
        let out = run(&proxied, &python_script(&python, port));
        assert!(out.stdout.contains("{\"ok\":true}"), "{python}: {out:?}");
        swapped += 1;
    } else {
        eprintln!("SKIP python: no python3 with OpenSSL on PATH");
    }
    if node_reads_proxy_variables() {
        let node = run(
            &proxied,
            &format!(
                "node -e \"fetch('https://localhost:{port}/whoami',{{headers:{{Authorization:'Bearer '+process.env.DEMO_KEY}}}}).then(r=>r.text()).then(t=>console.log(t),e=>{{console.error(e.cause||e);process.exit(3)}})\""
            ),
        );
        assert!(node.stdout.contains("{\"ok\":true}"), "node: {node:?}");
        swapped += 1;
    } else {
        eprintln!("SKIP node: no node on PATH that reads HTTPS_PROXY");
    }
    let log = events(proxied);
    assert_eq!(log.len(), swapped, "{log:?}");
    assert!(
        log.iter()
            .all(|event| event.outcome == ProxyOutcome::Swapped),
        "{log:?}"
    );
}

/// A client that does not trust the run authority fails closed: the TLS handshake
/// with the proxy fails, and no request reaches the service.
#[cfg(target_os = "macos")]
#[test]
fn a_client_that_ignores_the_trust_file_fails_closed() {
    let apple_python = Path::new("/usr/bin/python3");
    let is_libressl = std::process::Command::new(apple_python)
        .args(["-c", "import ssl; print(ssl.OPENSSL_VERSION)"])
        .output()
        .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).starts_with("LibreSSL"));
    if !is_libressl {
        eprintln!("SKIP: /usr/bin/python3 is not Apple's LibreSSL build");
        return;
    }
    let service = start_service();
    let proxied = start_proxy(&service, OtherHosts::Tunnel);
    let out = run(&proxied, &python_script("/usr/bin/python3", service.port));
    assert_ne!(out.exit_code, Some(0), "{out:?}");
    assert!(out.stderr.contains("CERTIFICATE_VERIFY_FAILED"), "{out:?}");
    assert!(service.seen.lock().expect("seen").is_empty());
    let log = events(proxied);
    assert_eq!(log.len(), 1, "{log:?}");
    assert_eq!(log[0].outcome, ProxyOutcome::Failed);
    assert!(
        log[0]
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("did not accept"))
    );
}

#[test]
fn an_answer_with_the_real_value_gets_the_placeholder() {
    let service = start_service();
    let proxied = start_proxy(&service, OtherHosts::Tunnel);
    let port = service.port;
    let out = run(
        &proxied,
        &format!(
            "curl -sS https://localhost:{port}/leak | rev; echo; curl -sS https://localhost:{port}/chunked-leak | rev"
        ),
    );
    assert_eq!(out.exit_code, Some(0), "{out:?}");
    let placeholder = reversed(&proxied.placeholder);
    assert_eq!(
        out.stdout.matches(&placeholder).count(),
        2,
        "both answers: {out:?}"
    );
    let (a, b) = proxied.placeholder.split_at(11);
    assert!(
        out.stdout.contains(&reversed(&format!("v={a}{b};"))),
        "a value split over two chunks: {out:?}"
    );
    assert!(!out.stdout.contains(&reversed(REAL)));
    let log = events(proxied);
    assert!(
        log.iter().all(|event| event
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("real value"))),
        "{log:?}"
    );
}

#[test]
fn a_placeholder_in_a_body_or_another_header_stops_the_request() {
    let service = start_service();
    let proxied = start_proxy(&service, OtherHosts::Tunnel);
    let port = service.port;
    let out = run(
        &proxied,
        &format!(
            "curl -sS -i https://localhost:{port}/store -H 'Authorization: Bearer '\"$DEMO_KEY\" --data-binary \"value=$DEMO_KEY\"; echo; \
             curl -sS -i https://localhost:{port}/store -H \"X-Note: $DEMO_KEY\"; echo; \
             curl -sS -i https://localhost:{port}/whoami -H \"Authorization: Bearer $OTHER_KEY\""
        ),
    );
    assert_eq!(out.stdout.matches("403 Forbidden").count(), 3, "{out:?}");
    assert_eq!(out.stdout.matches("X-Apassy-Proxy: refused").count(), 3);
    assert!(
        out.stdout
            .contains("request body has the placeholder of DEMO_KEY")
    );
    assert!(out.stdout.contains("in the X-Note header"));
    assert!(
        out.stdout
            .contains("OTHER_KEY is only for api.github.invalid")
    );
    let seen = service.seen.lock().expect("seen").clone();
    assert!(
        seen.iter()
            .all(|s| s.path != "/store" || !s.body.contains("value=")),
        "the body with the placeholder did not arrive: {seen:?}"
    );
    assert!(seen.iter().all(|s| s.path != "/whoami"), "{seen:?}");
    let log = events(proxied);
    assert_eq!(
        log.iter()
            .filter(|event| event.outcome == ProxyOutcome::Refused)
            .count(),
        3,
        "{log:?}"
    );
}

#[test]
fn other_hosts_get_a_blind_tunnel_or_a_refusal() {
    let service = start_service();
    let port = service.port;
    // 127.0.0.1 is not the host of the rule (localhost), so the proxy does not look
    // inside and does not swap. The service gets the placeholder.
    let tunnel = start_proxy(&service, OtherHosts::Tunnel);
    let out = run(
        &tunnel,
        &format!(
            "curl -sS -k https://127.0.0.1:{port}/whoami -H \"Authorization: Bearer $DEMO_KEY\""
        ),
    );
    assert!(out.stdout.contains("{\"ok\":false}"), "{out:?}");
    let seen = service.seen.lock().expect("seen").clone();
    assert_eq!(
        seen[0].authorization.as_deref(),
        Some(format!("Bearer {}", tunnel.placeholder).as_str())
    );
    let log = events(tunnel);
    assert_eq!(log[0].outcome, ProxyOutcome::Tunneled, "{log:?}");

    let refuse = start_proxy(&service, OtherHosts::Refuse);
    let out = run(
        &refuse,
        &format!("curl -sS -k https://127.0.0.1:{port}/whoami"),
    );
    assert_ne!(out.exit_code, Some(0), "{out:?}");
    let log = events(refuse);
    assert_eq!(log[0].outcome, ProxyOutcome::Refused, "{log:?}");
    assert_eq!(service.seen.lock().expect("seen").len(), 1);
}

#[test]
fn the_proxy_needs_the_password_of_the_run() {
    let service = start_service();
    let proxied = start_proxy(&service, OtherHosts::Tunnel);
    let url = proxied
        .proxy
        .network()
        .env
        .iter()
        .find(|(name, _)| name == "HTTPS_PROXY")
        .map(|(_, value)| value.clone())
        .expect("proxy url");
    let address = url.rsplit('@').next().expect("address");
    let mut stream = TcpStream::connect(address).expect("connect");
    write!(
        stream,
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
        service.port, service.port
    )
    .expect("write");
    let mut answer = [0u8; 64];
    let read = stream.read(&mut answer).expect("read");
    assert!(
        String::from_utf8_lossy(&answer[..read]).starts_with("HTTP/1.1 407"),
        "{}",
        String::from_utf8_lossy(&answer[..read])
    );
    assert!(events(proxied).is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn on_macos_the_process_can_reach_only_the_proxy() {
    let service = start_service();
    let proxied = start_proxy(&service, OtherHosts::Tunnel);
    let port = service.port;
    let out = run(
        &proxied,
        &format!(
            "curl -sS --noproxy '*' https://localhost:{port}/whoami; echo \"direct=$?\"; \
             python3 -c \"import socket; socket.create_connection(('127.0.0.1',{port}),timeout=3)\" 2>&1 | tail -1; \
             curl -sS https://localhost:{port}/whoami -H \"Authorization: Bearer $DEMO_KEY\""
        ),
    );
    assert!(
        out.stdout.contains("direct=7"),
        "curl without the proxy: {out:?}"
    );
    assert!(
        out.stdout.contains("Operation not permitted"),
        "python without the proxy: {out:?}"
    );
    assert!(
        out.stdout.contains("{\"ok\":true}"),
        "through the proxy: {out:?}"
    );
    assert_eq!(service.seen.lock().expect("seen").len(), 1);
}

// Linux (ADR 0011 stage 2, unit X2): the run is in a bubblewrap sandbox whose network
// namespace has one way out, a bridge to the proxy port. The CI job `linux-isolation`
// has bubblewrap and sets APASSY_REQUIRE_BWRAP=1, so there these tests fail instead of
// skip. Elsewhere the run has no rule and says why.

/// The rule of a proxied run on this computer; `None` (skip) without bubblewrap,
/// unless the job requires it.
#[cfg(target_os = "linux")]
fn netns_or_skip(run: &Run) -> bool {
    let network = run.proxy.network();
    if network.rule == apassy::broker::proxy::NetworkRule::Netns {
        return true;
    }
    assert!(
        std::env::var_os("APASSY_REQUIRE_BWRAP").is_none(),
        "APASSY_REQUIRE_BWRAP is set, but the run has no network rule: {}",
        network.report()
    );
    eprintln!("SKIP: no Linux network rule here: {}", network.report());
    false
}

#[cfg(target_os = "linux")]
#[test]
fn linux_direct_connection_fails_in_a_proxied_run() {
    let service = start_service();
    let proxied = start_proxy(&service, OtherHosts::Tunnel);
    if !netns_or_skip(&proxied) {
        return;
    }
    let port = service.port;
    // The service listens on the host's 127.0.0.1, the same address that the
    // bridge uses in the namespace: only the proxy port leads out.
    let out = run(
        &proxied,
        &format!(
            "curl -sS --max-time 5 --noproxy '*' https://localhost:{port}/whoami; echo \"direct=$?\"; \
             curl -sS --max-time 5 --noproxy '*' https://1.1.1.1/; echo \"outside=$?\"; \
             python3 -c \"import socket; socket.create_connection(('127.0.0.1',{port}),timeout=3)\" 2>&1 | tail -1; \
             curl -sS https://localhost:{port}/whoami -H \"Authorization: Bearer $DEMO_KEY\""
        ),
    );
    assert!(
        out.stdout.contains("direct=7"),
        "curl without the proxy: {out:?}"
    );
    assert!(
        out.stdout.contains("outside=7"),
        "curl to the internet without the proxy: {out:?}"
    );
    assert!(
        out.stdout.contains("Connection refused"),
        "python without the proxy: {out:?}"
    );
    assert!(
        out.stdout.contains("{\"ok\":true}"),
        "through the proxy: {out:?}"
    );
    let seen = service.seen.lock().expect("seen").clone();
    assert_eq!(seen.len(), 1, "only the proxied request arrives: {seen:?}");
    assert_eq!(
        seen[0].authorization.as_deref(),
        Some(format!("Bearer {REAL}").as_str())
    );
    let log = events(proxied);
    assert_eq!(log.len(), 1, "{log:?}");
    assert_eq!(log[0].outcome, ProxyOutcome::Swapped);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_proxied_run_reports_netns() {
    let service = start_service();
    let proxied = start_proxy(&service, OtherHosts::Tunnel);
    if !netns_or_skip(&proxied) {
        return;
    }
    assert_eq!(
        proxied.proxy.network().report(),
        serde_json::json!({"rule": "netns"})
    );
    // PID 1 is the Apassy init; the processes of the host are not there; the
    // variable holds the placeholder.
    let out = run(
        &proxied,
        "tr '\\0' ' ' < /proc/1/cmdline; echo; ls /proc | grep -c '^[0-9]'; printf %s \"$DEMO_KEY\" | rev",
    );
    assert_eq!(out.exit_code, Some(0), "{out:?}");
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert!(lines[0].contains("__netns-bridge"), "{out:?}");
    let processes: usize = lines[1].trim().parse().expect("count");
    assert!(processes < 10, "{out:?}");
    assert!(
        out.stdout.contains(&reversed(&proxied.placeholder)),
        "{out:?}"
    );
    assert!(!out.stdout.contains(&reversed(REAL)));
}

/// Without bubblewrap (every Linux test job but `linux-isolation`) the run has no
/// rule and names the reason and the fix; with it, the rule is `netns`. Either way
/// the process holds only placeholders and the proxy swaps.
#[cfg(target_os = "linux")]
#[test]
fn linux_proxied_run_reports_its_rule_and_holds_only_placeholders() {
    use apassy::broker::proxy::NetworkRule;
    let service = start_service();
    let proxied = start_proxy(&service, OtherHosts::Tunnel);
    let network = proxied.proxy.network();
    let report = network.report();
    match network.rule {
        NetworkRule::Netns => assert_eq!(report, serde_json::json!({"rule": "netns"})),
        NetworkRule::None => {
            assert!(
                std::env::var_os("APASSY_REQUIRE_BWRAP").is_none(),
                "{report}"
            );
            assert_eq!(report["rule"], "none");
            assert!(
                [
                    "bwrap_missing",
                    "bwrap_too_old",
                    "userns_blocked",
                    "sandbox_program_missing"
                ]
                .contains(&report["reason"].as_str().unwrap_or_default()),
                "{report}"
            );
            assert!(report["fix"].as_str().is_some_and(|fix| !fix.is_empty()));
            assert!(network.linux.is_none());
        }
        NetworkRule::Seatbelt => panic!("Seatbelt on Linux"),
    }
    let text = report.to_string();
    assert!(!text.contains(REAL) && !text.contains(&proxied.placeholder));
    let out = run(
        &proxied,
        &format!(
            "curl -sS https://localhost:{}/whoami -H \"Authorization: Bearer $DEMO_KEY\"; echo; printf %s \"$DEMO_KEY\" | rev",
            service.port
        ),
    );
    assert_eq!(out.exit_code, Some(0), "{out:?}");
    assert!(out.stdout.contains("{\"ok\":true}"), "{out:?}");
    assert!(
        out.stdout.contains(&reversed(&proxied.placeholder)),
        "{out:?}"
    );
    assert!(!out.stdout.contains(&reversed(REAL)));
    let seen = service.seen.lock().expect("seen").clone();
    assert_eq!(
        seen[0].authorization.as_deref(),
        Some(format!("Bearer {REAL}").as_str())
    );
}

// WebSocket (ADR 0011 stage 5, unit P3). A raw client goes through the run proxy
// with CONNECT, as a program does, to a WebSocket service on `localhost`.

/// What the WebSocket service got.
#[derive(Debug, Clone, PartialEq, Eq)]
enum WsSeen {
    Handshake {
        path: String,
        authorization: Option<String>,
        extensions: Option<String>,
    },
    Frame {
        opcode: u8,
        payload: Vec<u8>,
    },
}

/// A frame. A frame of the client is masked (RFC 6455 §5.3).
fn ws_frame(fin: bool, opcode: u8, payload: &[u8], masked: bool) -> Vec<u8> {
    let mut out = vec![(u8::from(fin) << 7) | opcode];
    let mask_bit: u8 = if masked { 0x80 } else { 0 };
    if payload.len() < 126 {
        out.push(mask_bit | u8::try_from(payload.len()).expect("short"));
    } else {
        out.push(mask_bit | 126);
        out.extend_from_slice(&u16::try_from(payload.len()).expect("length").to_be_bytes());
    }
    if masked {
        let key = [0x5a, 0x17, 0xc3, 0x09];
        out.extend_from_slice(&key);
        out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
    } else {
        out.extend_from_slice(payload);
    }
    out
}

/// One frame: (fin, opcode, unmasked payload).
fn read_ws_frame(from: &mut impl Read) -> Option<(bool, u8, Vec<u8>)> {
    let mut head = [0u8; 2];
    from.read_exact(&mut head).ok()?;
    let len = match head[1] & 0x7f {
        126 => {
            let mut bytes = [0u8; 2];
            from.read_exact(&mut bytes).ok()?;
            usize::from(u16::from_be_bytes(bytes))
        }
        127 => {
            let mut bytes = [0u8; 8];
            from.read_exact(&mut bytes).ok()?;
            usize::try_from(u64::from_be_bytes(bytes)).ok()?
        }
        short => usize::from(short),
    };
    let mut key = None;
    if head[1] & 0x80 != 0 {
        let mut bytes = [0u8; 4];
        from.read_exact(&mut bytes).ok()?;
        key = Some(bytes);
    }
    let mut payload = vec![0u8; len];
    from.read_exact(&mut payload).ok()?;
    if let Some(key) = key {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[i % 4];
        }
    }
    Some((head[0] & 0x80 != 0, head[0] & 0x0f, payload))
}

/// A WebSocket service. `/ws` answers 101 and, in the same write, a frame with the
/// real value; then it echoes text frames, answers `split` with the value split
/// over two fragments, and answers a Close. `/ws-deflate` turns on an extension.
/// `/ws-deny` answers 401 with the value in the body.
fn serve_ws(stream: StreamOwned<ServerConnection, TcpStream>, seen: &Mutex<Vec<WsSeen>>) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let path = line.split(' ').nth(1).unwrap_or_default().to_owned();
    let mut authorization = None;
    let mut extensions = None;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).unwrap_or(0) == 0 {
            return;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':').unwrap_or((header, ""));
        match name.to_ascii_lowercase().as_str() {
            "authorization" => authorization = Some(value.trim().to_owned()),
            "sec-websocket-extensions" => extensions = Some(value.trim().to_owned()),
            _ => {}
        }
    }
    seen.lock().expect("seen").push(WsSeen::Handshake {
        path: path.clone(),
        authorization,
        extensions,
    });
    let out = reader.get_mut();
    if path.starts_with("/ws-deny") {
        let _ =
            out.write_all(ok("401 Unauthorized", &format!("{{\"value\":\"{REAL}\"}}")).as_bytes());
        let _ = out.flush();
        return;
    }
    let extension = if path.starts_with("/ws-deflate") {
        "Sec-WebSocket-Extensions: permessage-deflate\r\n"
    } else {
        ""
    };
    let mut answer = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n{extension}\r\n"
    )
    .into_bytes();
    answer.extend(ws_frame(
        true,
        1,
        format!("welcome {REAL}").as_bytes(),
        false,
    ));
    if out.write_all(&answer).is_err() || out.flush().is_err() {
        return;
    }
    loop {
        let Some((_, opcode, payload)) = read_ws_frame(&mut reader) else {
            return;
        };
        seen.lock().expect("seen").push(WsSeen::Frame {
            opcode,
            payload: payload.clone(),
        });
        let reply = match (opcode, payload.as_slice()) {
            (8, _) => {
                let out = reader.get_mut();
                let _ = out.write_all(&ws_frame(true, 8, &1000u16.to_be_bytes(), false));
                let _ = out.flush();
                return;
            }
            (1, b"split") => {
                let (a, b) = REAL.split_at(11);
                let mut reply = ws_frame(false, 1, format!("v={a}").as_bytes(), false);
                reply.extend(ws_frame(true, 0, format!("{b};").as_bytes(), false));
                reply
            }
            (1, text) => ws_frame(true, 1, &[&b"echo:"[..], text].concat(), false),
            _ => continue,
        };
        let out = reader.get_mut();
        if out.write_all(&reply).is_err() || out.flush().is_err() {
            return;
        }
    }
}

fn start_ws_service() -> Service<WsSeen> {
    start_service_with(serve_ws)
}

fn base64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let bytes = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let word = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
        for place in 0..4 {
            if place <= chunk.len() {
                let index = usize::try_from((word >> (18 - 6 * place)) & 63).expect("index");
                out.push(char::from(TABLE[index]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The address and the password of the proxy, from `HTTPS_PROXY` of the run.
fn proxy_login(run: &Run) -> (String, String) {
    let url = run
        .proxy
        .network()
        .env
        .iter()
        .find(|(name, _)| name == "HTTPS_PROXY")
        .map(|(_, value)| value.clone())
        .expect("proxy url");
    let rest = url.strip_prefix("http://apassy:").expect("proxy user");
    let (password, address) = rest.split_once('@').expect("proxy address");
    (address.to_owned(), password.to_owned())
}

/// Reads one head byte by byte, so no byte after it is taken.
fn read_raw_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).unwrap_or(0) == 0 {
            break;
        }
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// CONNECT through the proxy with the password of the run: the stream and the
/// answer head.
fn connect_through(run: &Run, target: &str) -> (TcpStream, String) {
    let (address, password) = proxy_login(run);
    let mut tcp = TcpStream::connect(address).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(20)))
        .expect("timeout");
    let login = base64(format!("apassy:{password}").as_bytes());
    write!(
        tcp,
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {login}\r\n\r\n"
    )
    .expect("write");
    let answer = read_raw_head(&mut tcp);
    (tcp, answer)
}

type WsClient = BufReader<StreamOwned<ClientConnection, TcpStream>>;

/// A WebSocket through the proxy: CONNECT to `target`, TLS for `localhost` with
/// `roots`, and `request`. The client and the answer head.
fn open_ws(
    run: &Run,
    target: &str,
    request: &str,
    roots: Vec<CertificateDer<'static>>,
) -> (WsClient, String) {
    let (tcp, answer) = connect_through(run, target);
    assert!(answer.starts_with("HTTP/1.1 200 "), "{answer}");
    let mut store = RootCertStore::empty();
    for root in roots {
        store.add(root).expect("root");
    }
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_root_certificates(store)
            .with_no_client_auth();
    let name = ServerName::try_from("localhost").expect("name");
    let conn = ClientConnection::new(Arc::new(config), name).expect("tls");
    let mut tls = StreamOwned::new(conn, tcp);
    tls.write_all(request.as_bytes()).expect("request");
    tls.flush().expect("flush");
    let mut client = BufReader::new(tls);
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if client.read_line(&mut line).expect("head") == 0 {
            break;
        }
        head.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    (client, head)
}

/// The run authority, as the trust file of the run has it.
fn run_roots(run: &Run) -> Vec<CertificateDer<'static>> {
    vec![CertificateDer::from_pem_file(&run.proxy.network().ca_file).expect("run authority")]
}

fn ws_request(path: &str, port: u16, extra: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n"
    )
}

/// The frame of the service that follows its 101.
fn read_welcome(client: &mut WsClient, run: &Run) {
    let (_, opcode, payload) = read_ws_frame(client).expect("welcome");
    assert_eq!(opcode, 1);
    assert_eq!(
        payload,
        format!("welcome {}", run.placeholder).into_bytes(),
        "the value in the first frame became the placeholder"
    );
}

/// The Close handshake from the client side.
fn close_ws(client: &mut WsClient) {
    client
        .get_mut()
        .write_all(&ws_frame(true, 8, &1000u16.to_be_bytes(), true))
        .expect("close");
    loop {
        let (_, opcode, _) = read_ws_frame(client).expect("close answer");
        if opcode == 8 {
            return;
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn websocket_handshake_swaps_the_auth_header() {
    let service = start_ws_service();
    let proxied = start_proxy(&service, OtherHosts::Tunnel);
    let port = service.port;
    let (mut client, head) = open_ws(
        &proxied,
        &format!("localhost:{port}"),
        &ws_request(
            "/ws",
            port,
            &format!("Authorization: Bearer {}\r\n", proxied.placeholder),
        ),
        run_roots(&proxied),
    );
    assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
    read_welcome(&mut client, &proxied);
    // Frames go both ways.
    client
        .get_mut()
        .write_all(&ws_frame(true, 1, b"hello", true))
        .expect("send");
    let (_, opcode, payload) = read_ws_frame(&mut client).expect("echo");
    assert_eq!((opcode, payload.as_slice()), (1, &b"echo:hello"[..]));
    close_ws(&mut client);
    let seen = service.seen.lock().expect("seen").clone();
    assert_eq!(
        seen[0],
        WsSeen::Handshake {
            path: "/ws".to_owned(),
            authorization: Some(format!("Bearer {REAL}")),
            extensions: None,
        }
    );
    assert!(seen.contains(&WsSeen::Frame {
        opcode: 1,
        payload: b"hello".to_vec()
    }));
    let log = events(proxied);
    assert_eq!(log[0].outcome, ProxyOutcome::Swapped, "{log:?}");
    assert_eq!(log[0].status, Some(101));
    assert_eq!(log[0].path.as_deref(), Some("/ws"));
    assert_eq!(log[0].secrets, vec![NAME.to_owned()]);
    assert!(
        log.iter().any(|event| event
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("WebSocket frame had a real value"))),
        "{log:?}"
    );
    assert!(!format!("{log:?}").contains(REAL));
}

#[test]
fn websocket_query_token_is_swapped() {
    let service = start_ws_service();
    let proxied = start_proxy(&service, OtherHosts::Tunnel);
    let port = service.port;
    let (mut client, head) = open_ws(
        &proxied,
        &format!("localhost:{port}"),
        &ws_request(&format!("/ws?token={}", proxied.placeholder), port, ""),
        run_roots(&proxied),
    );
    assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
    read_welcome(&mut client, &proxied);
    close_ws(&mut client);
    let seen = service.seen.lock().expect("seen").clone();
    assert!(
        matches!(&seen[0], WsSeen::Handshake { path, .. } if *path == format!("/ws?token={REAL}")),
        "{seen:?}"
    );
    let log = events(proxied);
    assert_eq!(log[0].outcome, ProxyOutcome::Swapped, "{log:?}");
    assert!(!format!("{log:?}").contains(REAL));
}

#[test]
fn the_extension_offer_is_removed() {
    let service = start_ws_service();
    let proxied = start_proxy(&service, OtherHosts::Tunnel);
    let port = service.port;
    let offer = "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n";
    let (mut client, head) = open_ws(
        &proxied,
        &format!("localhost:{port}"),
        &ws_request("/ws", port, offer),
        run_roots(&proxied),
    );
    assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
    assert!(
        !head
            .to_ascii_lowercase()
            .contains("sec-websocket-extensions"),
        "{head}"
    );
    read_welcome(&mut client, &proxied);
    close_ws(&mut client);
    // A service that turns on an extension anyway is refused: its frames could not
    // be checked.
    let (_, head) = open_ws(
        &proxied,
        &format!("localhost:{port}"),
        &ws_request("/ws-deflate", port, offer),
        run_roots(&proxied),
    );
    assert!(head.starts_with("HTTP/1.1 502 "), "{head}");
    let seen = service.seen.lock().expect("seen").clone();
    let offers: Vec<&Option<String>> = seen
        .iter()
        .filter_map(|seen| match seen {
            WsSeen::Handshake { extensions, .. } => Some(extensions),
            WsSeen::Frame { .. } => None,
        })
        .collect();
    assert_eq!(offers, vec![&None, &None], "{seen:?}");
    let log = events(proxied);
    assert!(
        log.iter().any(|event| event.outcome == ProxyOutcome::Failed
            && event
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("extension"))),
        "{log:?}"
    );
}

#[test]
fn a_server_frame_with_the_value_reaches_the_client_as_the_placeholder() {
    let service = start_ws_service();
    let proxied = start_proxy(&service, OtherHosts::Tunnel);
    let port = service.port;
    let (mut client, head) = open_ws(
        &proxied,
        &format!("localhost:{port}"),
        &ws_request("/ws", port, ""),
        run_roots(&proxied),
    );
    assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
    // One frame (it came in one write with the 101).
    read_welcome(&mut client, &proxied);
    // Split over two fragments of one message.
    client
        .get_mut()
        .write_all(&ws_frame(true, 1, b"split", true))
        .expect("send");
    let mut message = Vec::new();
    loop {
        let (fin, opcode, payload) = read_ws_frame(&mut client).expect("fragment");
        assert!(opcode == 1 || opcode == 0, "{opcode}");
        assert!(!contains(&payload, REAL.as_bytes()));
        message.extend_from_slice(&payload);
        if fin {
            break;
        }
    }
    assert_eq!(message, format!("v={};", proxied.placeholder).into_bytes());
    close_ws(&mut client);
    let placeholder = proxied.placeholder.clone();
    let log = events(proxied);
    assert!(!format!("{log:?}").contains(REAL));
    assert!(!format!("{log:?}").contains(&placeholder));
}

#[test]
fn a_client_frame_with_a_placeholder_closes_with_1008() {
    let service = start_ws_service();
    let proxied = start_proxy(&service, OtherHosts::Tunnel);
    let port = service.port;
    let (mut client, head) = open_ws(
        &proxied,
        &format!("localhost:{port}"),
        &ws_request("/ws", port, ""),
        run_roots(&proxied),
    );
    assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
    read_welcome(&mut client, &proxied);
    let body = format!("{{\"store\":\"{}\"}}", proxied.placeholder);
    client
        .get_mut()
        .write_all(&ws_frame(true, 1, body.as_bytes(), true))
        .expect("send");
    let (_, opcode, payload) = read_ws_frame(&mut client).expect("close");
    assert_eq!(opcode, 8);
    assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), 1008);
    let reason = String::from_utf8_lossy(&payload[2..]).into_owned();
    assert!(reason.contains(NAME), "{reason}");
    assert!(!reason.contains(&proxied.placeholder));
    // The frame never reached the service.
    let seen = service.seen.lock().expect("seen").clone();
    assert!(
        seen.iter().all(|seen| match seen {
            WsSeen::Frame { payload, .. } => !contains(payload, proxied.placeholder.as_bytes()),
            WsSeen::Handshake { .. } => true,
        }),
        "{seen:?}"
    );
    let placeholder = proxied.placeholder.clone();
    let log = events(proxied);
    let refused: Vec<&ProxyEvent> = log
        .iter()
        .filter(|event| event.outcome == ProxyOutcome::Refused)
        .collect();
    assert_eq!(refused.len(), 1, "{log:?}");
    assert!(
        refused[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains(NAME)),
        "{log:?}"
    );
    let text = format!("{log:?}");
    assert!(
        !text.contains(REAL) && !text.contains(&placeholder),
        "{text}"
    );
}

#[test]
fn websocket_to_another_host_is_a_tunnel() {
    let service = start_ws_service();
    let port = service.port;
    // 127.0.0.1 is not the host of the rule (localhost): a blind tunnel, no swap.
    let tunnel = start_proxy(&service, OtherHosts::Tunnel);
    let (mut client, head) = open_ws(
        &tunnel,
        &format!("127.0.0.1:{port}"),
        &ws_request(
            "/ws",
            port,
            &format!("Authorization: Bearer {}\r\n", tunnel.placeholder),
        ),
        vec![service.root.clone()],
    );
    assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
    let _ = read_ws_frame(&mut client).expect("welcome");
    close_ws(&mut client);
    let seen = service.seen.lock().expect("seen").clone();
    assert_eq!(
        seen[0],
        WsSeen::Handshake {
            path: "/ws".to_owned(),
            authorization: Some(format!("Bearer {}", tunnel.placeholder)),
            extensions: None,
        }
    );
    let log = events(tunnel);
    assert_eq!(log.len(), 1, "{log:?}");
    assert_eq!(log[0].outcome, ProxyOutcome::Tunneled);

    // A run that reaches only the hosts of its secrets refuses it.
    let refuse = start_proxy(&service, OtherHosts::Refuse);
    let (_, answer) = connect_through(&refuse, &format!("127.0.0.1:{port}"));
    assert!(answer.starts_with("HTTP/1.1 403 "), "{answer}");
    let log = events(refuse);
    assert_eq!(log[0].outcome, ProxyOutcome::Refused, "{log:?}");
    assert_eq!(service.seen.lock().expect("seen").len(), seen.len());
}

#[test]
fn an_upgrade_other_than_websocket_is_refused() {
    let service = start_ws_service();
    let proxied = start_proxy(&service, OtherHosts::Tunnel);
    let port = service.port;
    let request = format!(
        "GET /ws HTTP/1.1\r\nHost: localhost:{port}\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n"
    );
    let (_, head) = open_ws(
        &proxied,
        &format!("localhost:{port}"),
        &request,
        run_roots(&proxied),
    );
    assert!(head.starts_with("HTTP/1.1 501 "), "{head}");
    assert!(service.seen.lock().expect("seen").is_empty());
    let log = events(proxied);
    assert_eq!(log[0].outcome, ProxyOutcome::Refused, "{log:?}");
}

#[test]
fn a_refused_websocket_answer_gets_the_placeholder() {
    let service = start_ws_service();
    let proxied = start_proxy(&service, OtherHosts::Tunnel);
    let port = service.port;
    let (mut client, head) = open_ws(
        &proxied,
        &format!("localhost:{port}"),
        &ws_request("/ws-deny", port, ""),
        run_roots(&proxied),
    );
    assert!(head.starts_with("HTTP/1.1 401 "), "{head}");
    let mut body = Vec::new();
    let _ = client.read_to_end(&mut body);
    let body = String::from_utf8_lossy(&body).into_owned();
    assert!(body.contains(&proxied.placeholder), "{body}");
    assert!(!body.contains(REAL));
    let log = events(proxied);
    assert_eq!(log[0].status, Some(401), "{log:?}");
}

/// The plan (D11) names the auth header and the key query parameter as the swap
/// positions of a handshake. A placeholder in `Sec-WebSocket-Protocol` is not one:
/// the handshake is refused and the service gets nothing.
#[test]
fn a_placeholder_in_the_subprotocol_header_is_refused() {
    let service = start_ws_service();
    let proxied = start_proxy(&service, OtherHosts::Tunnel);
    let port = service.port;
    let (_, head) = open_ws(
        &proxied,
        &format!("localhost:{port}"),
        &ws_request(
            "/ws",
            port,
            &format!("Sec-WebSocket-Protocol: key.{}\r\n", proxied.placeholder),
        ),
        run_roots(&proxied),
    );
    assert!(head.starts_with("HTTP/1.1 403 "), "{head}");
    assert!(service.seen.lock().expect("seen").is_empty());
    let placeholder = proxied.placeholder.clone();
    let log = events(proxied);
    assert_eq!(log[0].outcome, ProxyOutcome::Refused, "{log:?}");
    assert!(
        log[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("Sec-WebSocket-Protocol")),
        "{log:?}"
    );
    assert!(!format!("{log:?}").contains(&placeholder));
}
