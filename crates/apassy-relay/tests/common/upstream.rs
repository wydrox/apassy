//! A mock HTTPS upstream for the proxy tests. It runs in process on 127.0.0.1, with
//! its own test certificate authority and one leaf certificate for all its hosts.
//! It records every request it gets, and it answers with an echo of the request, so
//! a test can check what the relay sent and what came back.
//!
//! Special targets: `/chunked`, `/big?n=N`, `/close`, `/gzip`, `/redirect`. Every
//! other target gets the echo.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use apassy_relay::config::UpstreamOptions;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

/// One request that the mock got.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Recorded {
    /// The first header with this name, compared without case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

pub struct MockUpstream {
    pub addr: SocketAddr,
    /// The DER of the test root. `options()` trusts it.
    pub ca_der: Vec<u8>,
    hosts: Vec<String>,
    seen: Arc<Mutex<Vec<Recorded>>>,
    connections: Arc<AtomicUsize>,
}

/// A rough year, to give the test certificates a validity that macOS accepts.
fn this_year() -> i32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    1970 + i32::try_from(secs / 31_556_952).unwrap_or(56)
}

fn validity(params: &mut CertificateParams) {
    let year = this_year();
    params.not_before = rcgen::date_time_ymd(year - 1, 12, 1);
    params.not_after = rcgen::date_time_ymd(year + 1, 1, 5);
}

/// An HTTPS mock for `hosts` (a leaf certificate that names all of them).
pub fn start(hosts: &[&str]) -> MockUpstream {
    let mut root = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Apassy relay test root");
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
    let mut leaf =
        CertificateParams::new(hosts.iter().map(|h| (*h).to_owned()).collect::<Vec<_>>())
            .expect("leaf");
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
    let addr = listener.local_addr().expect("addr");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(AtomicUsize::new(0));
    let (thread_seen, thread_connections) = (Arc::clone(&seen), Arc::clone(&connections));
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread_connections.fetch_add(1, Ordering::SeqCst);
            let config = Arc::clone(&config);
            let seen = Arc::clone(&thread_seen);
            thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
                let Ok(tls) = ServerConnection::new(config) else {
                    return;
                };
                let _ = serve(StreamOwned::new(tls, stream), &seen);
            });
        }
    });
    MockUpstream {
        addr,
        ca_der: root_cert.der().to_vec(),
        hosts: hosts.iter().map(|h| (*h).to_owned()).collect(),
        seen,
        connections,
    }
}

impl MockUpstream {
    /// The relay options: trust the test root, and resolve each host to the mock.
    pub fn options(&self) -> UpstreamOptions {
        UpstreamOptions {
            extra_roots_der: vec![self.ca_der.clone()],
            resolve: self
                .hosts
                .iter()
                .map(|host| (host.clone(), 443, self.addr))
                .collect(),
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(20),
        }
    }

    /// Every request that the mock got, in order.
    pub fn requests(&self) -> Vec<Recorded> {
        self.seen.lock().expect("seen").clone()
    }

    /// How many TCP connections the mock accepted, with or without a request.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

type Tls = StreamOwned<ServerConnection, TcpStream>;

fn serve(stream: Tls, seen: &Mutex<Vec<Recorded>>) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }
    let mut parts = line.trim_end().splitn(3, ' ');
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    let mut headers = Vec::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            return Ok(());
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.push((name.to_owned(), value.trim().to_owned()));
        }
    }
    let length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;
    let recorded = Recorded {
        method,
        target,
        headers,
        body,
    };
    seen.lock().expect("seen").push(recorded.clone());
    answer(reader.get_mut(), &recorded)?;
    let stream = reader.get_mut();
    stream.conn.send_close_notify();
    let _ = stream.flush();
    Ok(())
}

fn echo(recorded: &Recorded) -> Vec<u8> {
    let mut headers = serde_json::Map::new();
    for (name, value) in &recorded.headers {
        headers.insert(name.to_ascii_lowercase(), value.clone().into());
    }
    serde_json::to_vec(&serde_json::json!({
        "method": recorded.method,
        "target": recorded.target,
        "authorization": recorded.header("authorization"),
        "headers": headers,
        "body": String::from_utf8_lossy(&recorded.body),
    }))
    .expect("echo json")
}

fn echo_header(recorded: &Recorded) -> String {
    match recorded.header("authorization") {
        Some(value) => format!("X-Echo-Authorization: {value}\r\n"),
        None => String::new(),
    }
}

fn write_chunked(stream: &mut Tls, data: &[u8], piece: usize) -> std::io::Result<()> {
    for part in data.chunks(piece) {
        write!(stream, "{:x}\r\n", part.len())?;
        stream.write_all(part)?;
        stream.write_all(b"\r\n")?;
    }
    stream.write_all(b"0\r\n\r\n")
}

fn answer(stream: &mut Tls, recorded: &Recorded) -> std::io::Result<()> {
    let (path, query) = recorded
        .target
        .split_once('?')
        .unwrap_or((recorded.target.as_str(), ""));
    let head_only = recorded.method == "HEAD";
    match path {
        "/chunked" => {
            let body = echo(recorded);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                echo_header(recorded)
            )?;
            write_chunked(stream, &body, 7)
        }
        "/big" => {
            let count: usize = query
                .strip_prefix("n=")
                .and_then(|n| n.parse().ok())
                .unwrap_or(1);
            let auth = recorded.header("authorization").unwrap_or("-").to_owned();
            let mut body = Vec::new();
            for index in 0..count {
                if index > 0 {
                    body.push(b',');
                }
                body.extend_from_slice(auth.as_bytes());
            }
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            )?;
            // Pieces of 97 bytes, so the borders fall inside the values.
            write_chunked(stream, &body, 97)
        }
        "/close" => {
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Connection: close\r\n\r\n",
                echo_header(recorded)
            )?;
            stream.write_all(&echo(recorded))
        }
        "/gzip" => {
            let body = b"this is not really gzip";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )?;
            stream.write_all(body)
        }
        "/redirect" => {
            let host = recorded.header("host").unwrap_or("localhost");
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: https://{host}/echo\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
        }
        _ => {
            let body = echo(recorded);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
                echo_header(recorded),
                body.len()
            )?;
            if head_only {
                return Ok(());
            }
            stream.write_all(&body)
        }
    }
}
