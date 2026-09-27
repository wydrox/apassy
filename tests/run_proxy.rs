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
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
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

struct Service {
    port: u16,
    root: CertificateDer<'static>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

fn validity(params: &mut CertificateParams) {
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(1);
}

/// An HTTPS service on `localhost` with its own test root.
fn start_service() -> Service {
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
                serve(StreamOwned::new(tls, stream), &seen);
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

fn start_proxy(service: &Service, other_hosts: OtherHosts) -> Run {
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

fn run(run: &Run, script: &str) -> RunOutput {
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
    let path = match node_dir() {
        Some(dir) => format!("/usr/bin:/bin:{dir}"),
        None => "/usr/bin:/bin".to_owned(),
    };
    exec::run_with(
        &["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()],
        Path::new("/tmp"),
        Some(&path),
        &env,
        &masks,
        Network {
            env: &network.env,
            sandbox_profile: network.sandbox_profile.as_deref(),
        },
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
    if node_dir().is_some() {
        let node = run(
            &proxied,
            &format!(
                "node -e \"fetch('https://localhost:{port}/whoami',{{headers:{{Authorization:'Bearer '+process.env.DEMO_KEY}}}}).then(r=>r.text()).then(t=>console.log(t),e=>{{console.error(e.cause||e);process.exit(3)}})\""
            ),
        );
        assert!(node.stdout.contains("{\"ok\":true}"), "node: {node:?}");
        swapped += 1;
    } else {
        eprintln!("SKIP node: not on PATH");
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
