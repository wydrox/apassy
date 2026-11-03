//! Fuzz the TLS side of the node's front (`apassy::net::tls_front::TlsSide`), the code
//! that every tailnet peer reaches before the relay (plan D2, unit N2).
//!
//! The first byte picks a mode:
//!
//! - raw: the input, cut into chunks, is what a peer sends before any handshake. The
//!   front must not panic, must give no plaintext before the handshake ends (early data
//!   is off), and must keep its output small.
//! - session: a real rustls client with the pin verifier finishes a TLS 1.3 handshake in
//!   memory. Then the input is plaintext in both directions, in chunks. Every byte must
//!   come out on the other side unchanged and in order, and the close must arrive.
//! - corrupt: as session, and one byte of the client's records is changed on the way.
//!   The front may refuse; what it delivers must be a prefix of what the client sent
//!   (AEAD).

#![no_main]

use std::io::{Read, Write};
use std::sync::{Arc, OnceLock};

use apassy::net::certificate::NodeCertificate;
use apassy::net::pin::Pin;
use apassy::net::tls_front::{Received, TlsSide, server_config};
use libfuzzer_sys::fuzz_target;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, ServerConfig, SignatureScheme,
};

/// The output of the front for one raw input stays below this.
const MAX_RAW_OUTPUT: usize = 64 * 1024;

struct Fixture {
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
}

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

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let certificate = NodeCertificate::generate("fuzz").expect("certificate");
        let server = server_config(&certificate.der, &certificate.key).expect("server config");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinVerifier {
                pin: certificate.pin,
                provider,
            }))
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        Fixture {
            server,
            client: Arc::new(client),
        }
    })
}

/// Cut `data` into chunks: each chunk is a length byte (1 to 256) and that many bytes.
fn chunks(mut data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while let Some((&length, rest)) = data.split_first() {
        let length = (usize::from(length) + 1).min(rest.len());
        if length == 0 {
            break;
        }
        out.push(&rest[..length]);
        data = &rest[length..];
    }
    out
}

fn raw(data: &[u8]) {
    let Ok(mut side) = TlsSide::new(Arc::clone(&fixture().server)) else {
        return;
    };
    let mut output = Vec::new();
    for chunk in chunks(data) {
        let mut plain = Vec::new();
        let result = side.receive(chunk, &mut plain);
        side.outgoing(&mut output);
        assert!(
            !side.is_handshaking() || plain.is_empty(),
            "plaintext before the handshake ended"
        );
        assert!(output.len() < MAX_RAW_OUTPUT, "the front writes too much");
        if result.is_err() {
            return;
        }
    }
}

/// Bytes from the front into the client; the plaintext goes to `plain`.
fn to_client(client: &mut ClientConnection, mut bytes: &[u8], plain: &mut Vec<u8>) -> bool {
    while !bytes.is_empty() {
        if client.read_tls(&mut bytes).is_err() || client.process_new_packets().is_err() {
            return false;
        }
        let mut buffer = [0u8; 4096];
        loop {
            match client.reader().read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => plain.extend_from_slice(&buffer[..read]),
            }
        }
    }
    true
}

fn from_client(client: &mut ClientConnection) -> Vec<u8> {
    let mut out = Vec::new();
    while client.wants_write() {
        if client.write_tls(&mut out).is_err() {
            break;
        }
    }
    out
}

fn session(data: &[u8], corrupt: bool) {
    let fixture = fixture();
    let name = ServerName::try_from("apassy-node.invalid")
        .expect("name")
        .to_owned();
    let mut client = ClientConnection::new(Arc::clone(&fixture.client), name).expect("client");
    let mut server = TlsSide::new(Arc::clone(&fixture.server)).expect("server");
    let mut ignored = Vec::new();
    for _ in 0..16 {
        let up = from_client(&mut client);
        if !up.is_empty() {
            server.receive(&up, &mut ignored).expect("the handshake");
        }
        let mut down = Vec::new();
        server.outgoing(&mut down);
        assert!(
            to_client(&mut client, &down, &mut ignored),
            "the client takes it"
        );
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
    }
    assert!(!server.is_handshaking() && !client.is_handshaking());
    assert_eq!(server.alpn(), Some(&b"http/1.1"[..]));
    assert!(ignored.is_empty());

    // The input: a byte that says where to corrupt, then the chunks. Even chunks go up,
    // odd chunks go down.
    let (flip_at, data) = match data.split_first() {
        Some((&at, rest)) => (usize::from(at), rest),
        None => (0, data),
    };
    let mut sent_up = Vec::new();
    let mut got_up = Vec::new();
    let mut sent_down = Vec::new();
    let mut got_down = Vec::new();
    let mut flipped = false;
    for (index, chunk) in chunks(data).into_iter().enumerate() {
        if index % 2 == 0 {
            client.writer().write_all(chunk).expect("client write");
            sent_up.extend_from_slice(chunk);
            let mut records = from_client(&mut client);
            if corrupt && !flipped && !records.is_empty() {
                let at = flip_at % records.len();
                records[at] ^= 0x01;
                flipped = true;
            }
            match server.receive(&records, &mut got_up) {
                Ok(Received::Open) => {}
                Ok(Received::Closed) => panic!("no close was sent"),
                Err(_) => {
                    assert!(corrupt, "an unchanged record is refused");
                    break;
                }
            }
            assert!(
                sent_up.starts_with(&got_up),
                "the front delivers only what the client sent"
            );
        } else {
            server.send(chunk).expect("front send");
            sent_down.extend_from_slice(chunk);
            let mut records = Vec::new();
            server.outgoing(&mut records);
            assert!(to_client(&mut client, &records, &mut got_down));
            assert_eq!(got_down, sent_down, "the client gets what the front sent");
        }
    }
    if corrupt && flipped {
        return;
    }
    assert_eq!(got_up, sent_up, "every byte reached the target");
    // The close in both directions.
    client.send_close_notify();
    let close = from_client(&mut client);
    let mut tail = Vec::new();
    assert_eq!(
        server.receive(&close, &mut tail).expect("close"),
        Received::Closed
    );
    assert!(tail.is_empty());
    server.close();
    let mut records = Vec::new();
    server.outgoing(&mut records);
    assert!(to_client(&mut client, &records, &mut tail));
    let mut byte = [0u8; 1];
    assert!(matches!(client.reader().read(&mut byte), Ok(0)));
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 3 {
        0 => raw(rest),
        1 => session(rest, false),
        _ => session(rest, true),
    }
});
