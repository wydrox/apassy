//! Headless tests of Settings > iPhone companion (ADR 0020): the listener follows the setting and
//! the lock, the QR code is drawn from its modules, a pairing goes from the QR code to a
//! stored device through the code and the owner check, and "Remove" and "Reset pairing"
//! act at once. A real listener runs on a temporary vault. The phone is a rustls client
//! that accepts only the pinned certificate, with keys made by ring. All values are
//! synthetic.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, OutputCommand};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use tempfile::TempDir;

use super::companion::{countdown, draw_qr, keep_code_characters};
use super::owner_tests::{
    PASS, WRONG, collect, confirm_with, input, socket_dir, unlocked_app_with_item,
};
use crate::companion::crypto::tests::TestKey;
use crate::companion::crypto::{
    certificate_pin, display_code, pair_string, pairing_code, pairing_code_hash, request_string,
};
use crate::companion::pairing::{PairingView, pair_proof};
use crate::desktop::companion::{Listener, QUIET_ZONE, QrModules, now};
use crate::desktop::{BrokerState, DesktopApp};
use crate::native::base64::{decode_url, encode_url};

const MAC_LINK_HOST: &str = "192.0.2.10";

// ---- The app under test. ----

/// A port that is free now. The vault keeps it as the port of the listener.
fn free_port() -> u16 {
    let socket = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("bind");
    socket.local_addr().expect("addr").port()
}

fn set_port(app: &DesktopApp, port: u16) {
    let shared = app.owner_ui.session.shared_vault();
    let mut guard = shared.lock().expect("vault");
    guard
        .as_mut()
        .expect("open vault")
        .set_companion_port(port)
        .expect("port");
}

/// An unlocked app with a running broker, a free port, and a link host that needs no
/// network.
fn app_with_broker(dir: &TempDir) -> (DesktopApp, u16) {
    let (mut app, _) = unlocked_app_with_item(dir);
    app.start_broker(&socket_dir(dir));
    assert!(matches!(app.broker, BrokerState::Running(_)));
    let port = free_port();
    set_port(&app, port);
    app.companion.test_options.link_hosts = Some(vec![MAC_LINK_HOST.to_owned()]);
    app.companion.test_options.allow_local_peers = true;
    (app, port)
}

fn running_port(app: &DesktopApp) -> Option<u16> {
    match &app.companion.listener {
        Listener::Running { handle, .. } => Some(handle.port()),
        _ => None,
    }
}

fn pin(app: &DesktopApp) -> String {
    match &app.companion.listener {
        Listener::Running { handle, .. } => handle.certificate_pin().to_owned(),
        _ => panic!("the listener runs"),
    }
}

/// True when nothing listens on `port`: this test can bind it.
fn port_is_free(port: u16) -> bool {
    TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).is_ok()
}

fn can_connect(port: u16) -> bool {
    TcpStream::connect_timeout(
        &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        Duration::from_secs(2),
    )
    .is_ok()
}

/// The text of Settings > Notifications after three frames, and the output commands of
/// the last one (a copy to the pasteboard would be one).
fn settings_frame(ctx: &egui::Context, app: &mut DesktopApp) -> (String, Vec<OutputCommand>) {
    super::open_settings(app, super::SettingsTab::Notifications);
    let mut text = String::new();
    let mut commands = Vec::new();
    for _ in 0..3 {
        let output = ctx.run_ui(input(0.0, Vec::new()), |ui| super::draw(app, ui));
        text.clear();
        for clipped in &output.shapes {
            collect(&clipped.shape, &mut text);
        }
        commands = output.platform_output.commands.clone();
        output.drop_without_applying_deltas();
    }
    (text, commands)
}

/// Poll the app until `done` holds.
fn poll_until(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    what: &str,
    done: impl Fn(&DesktopApp) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !done(app) {
        assert!(Instant::now() < deadline, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(10));
        app.poll_companion(ctx);
    }
}

// ---- The phone. ----

#[derive(Debug)]
struct PinVerifier {
    pin: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if certificate_pin(end_entity.as_ref()) == self.pin {
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

/// One HTTPS exchange with the pinned certificate. The answer is the status and the body.
fn exchange(port: u16, pin: &str, raw: &str) -> std::io::Result<(u16, String)> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier {
            pin: pin.to_owned(),
            provider,
        }))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tcp = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(10)))?;
    let name = ServerName::try_from("mac.local").expect("name");
    let connection = ClientConnection::new(Arc::new(config), name).expect("connection");
    let mut tls = StreamOwned::new(connection, tcp);
    tls.write_all(raw.as_bytes())?;
    tls.flush()?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => bytes.extend_from_slice(&chunk[..read]),
            Err(error) if bytes.is_empty() => return Err(error),
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").expect("an HTTP answer");
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("a status");
    Ok((status, body.to_owned()))
}

const DEVICE: &str = "0123456789abcdef0123456789abcdef";
const DEVICE_NAME: &str = "Test iPhone";

struct Phone {
    request: TestKey,
    approval: TestKey,
}

impl Phone {
    fn new() -> Self {
        Self {
            request: TestKey::generate(),
            approval: TestKey::generate(),
        }
    }

    fn pair_text(&self) -> String {
        pair_string(
            DEVICE,
            DEVICE_NAME,
            &self.request.public(),
            &self.approval.public(),
        )
        .expect("pair string")
    }

    /// The code that the phone shows, "ddd ddd".
    fn code(&self, secret: &[u8]) -> String {
        let hash = pairing_code_hash(secret, &self.request.public(), &self.approval.public());
        display_code(&pairing_code(&hash))
    }

    /// `POST /v1/pair` with the secret of the link.
    fn pair(&self, port: u16, pin: &str, secret: &[u8]) -> (u16, String) {
        let text = self.pair_text();
        let body = serde_json::json!({
            "v": 1,
            "device_id": DEVICE,
            "device_name": DEVICE_NAME,
            "request_key": encode_url(&self.request.public()),
            "approval_key": encode_url(&self.approval.public()),
            "request_key_signature": encode_url(&self.request.sign(&text)),
            "approval_key_signature": encode_url(&self.approval.sign(&text)),
            "proof": encode_url(&pair_proof(secret, &text)),
        })
        .to_string();
        let raw = format!(
            "POST /v1/pair HTTP/1.1\r\nHost: mac.local\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        exchange(port, pin, &raw).expect("pair request")
    }

    /// A signed `GET /v1/status`.
    fn status(&self, port: u16, pin: &str) -> std::io::Result<(u16, String)> {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).expect("random");
        let time = now();
        let path = "/v1/status";
        let text = request_string("GET", path, DEVICE, time, &nonce, b"").expect("request string");
        let raw = format!(
            "GET {path} HTTP/1.1\r\nHost: mac.local\r\nX-Apassy-Device: {DEVICE}\r\nX-Apassy-Time: {time}\r\nX-Apassy-Nonce: {}\r\nX-Apassy-Signature: {}\r\n\r\n",
            encode_url(&nonce),
            encode_url(&self.request.sign(&text)),
        );
        exchange(port, pin, &raw)
    }
}

/// The secret in a pairing link.
fn link_secret(link: &str) -> Vec<u8> {
    let query = link.split_once('?').expect("a query").1;
    let value = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("s="))
        .expect("the secret");
    decode_url(value).expect("b64u secret")
}

// ---- The listener follows the setting and the lock. ----

#[test]
fn the_listener_follows_the_setting_the_lock_and_the_quit() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, port) = app_with_broker(&dir);
    let ctx = egui::Context::default();

    // Off by default: nothing listens, also after a frame.
    assert!(
        !app.owner_ui
            .session
            .companion_status()
            .expect("status")
            .0
            .enabled
    );
    app.poll_companion(&ctx);
    assert!(matches!(app.companion.listener, Listener::Off));
    assert!(port_is_free(port));

    // The owner turns it on: it listens on the port of the vault.
    app.set_companion_on(true);
    assert_eq!(running_port(&app), Some(port));
    assert!(can_connect(port));
    let first_pin = pin(&app);

    // A lock stops it at once, without a frame in between.
    app.lock_vault(Some(&ctx));
    assert!(matches!(app.companion.listener, Listener::Off));
    assert!(port_is_free(port), "the port is closed after the lock");

    // An unlock starts it again, in the next frame, with the same certificate.
    app.owner_ui.session.unlock(PASS).expect("unlock");
    assert!(matches!(app.companion.listener, Listener::Off));
    app.poll_companion(&ctx);
    assert_eq!(running_port(&app), Some(port));
    assert_eq!(
        pin(&app),
        first_pin,
        "a lock does not change the certificate"
    );

    // A passphrase change ends the vault session. The listener restarts for the new one.
    let epoch = match &app.companion.listener {
        Listener::Running { epoch, .. } => *epoch,
        _ => panic!("running"),
    };
    app.owner_ui
        .session
        .change_passphrase(PASS, "ui-owner-pass-new-1", "ui-owner-pass-new-1")
        .expect("change");
    app.end_waiting_runs();
    assert!(matches!(app.companion.listener, Listener::Off));
    assert!(port_is_free(port));
    app.poll_companion(&ctx);
    let restarted = match &app.companion.listener {
        Listener::Running { epoch, .. } => *epoch,
        _ => panic!("the listener runs for the new session"),
    };
    assert_ne!(restarted, epoch);

    // The owner turns it off.
    app.set_companion_on(false);
    assert!(matches!(app.companion.listener, Listener::Off));
    assert!(port_is_free(port));
    app.poll_companion(&ctx);
    assert!(
        matches!(app.companion.listener, Listener::Off),
        "it stays off"
    );

    // A quit stops it too.
    app.set_companion_on(true);
    assert_eq!(running_port(&app), Some(port));
    app.shut_down();
    assert!(matches!(app.companion.listener, Listener::Off));
    assert!(port_is_free(port));
}

#[test]
fn a_session_change_stops_the_listener_without_a_lock() {
    // Opening another vault file and a restore go through `end_waiting_runs`. The
    // listener of the old session must not serve the new one.
    let dir = TempDir::new().expect("temp dir");
    let (mut app, port) = app_with_broker(&dir);
    let ctx = egui::Context::default();
    app.set_companion_on(true);
    assert_eq!(running_port(&app), Some(port));
    let other = dir.path().join("other.db");
    app.owner_ui
        .session
        .create_file(&other, PASS)
        .expect("create another vault");
    app.end_waiting_runs();
    assert!(matches!(app.companion.listener, Listener::Off));
    assert!(port_is_free(port));
    // The new vault file starts locked, so nothing is wanted.
    app.poll_companion(&ctx);
    assert!(matches!(app.companion.listener, Listener::Off));
}

#[test]
fn a_failed_start_says_why_and_a_retry_works() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, port) = app_with_broker(&dir);
    let ctx = egui::Context::default();
    let occupied = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).expect("occupy the port");
    app.set_companion_on(true);
    let Listener::Failed { message, .. } = &app.companion.listener else {
        panic!("the start fails when the port is taken");
    };
    assert!(
        message.contains(&format!("another program already uses port {port}")),
        "{message}"
    );
    assert!(
        message.contains("Nothing listens on the network"),
        "{message}"
    );
    assert_eq!(app.status_kind, crate::desktop::StatusKind::Error);

    // A failed listener is not started again in each frame, and the page says why.
    app.poll_companion(&ctx);
    assert!(matches!(app.companion.listener, Listener::Failed { .. }));
    let (text, _) = settings_frame(&ctx, &mut app);
    assert!(text.contains("another program already uses port"), "{text}");
    assert!(text.contains("Try again"), "{text}");
    assert!(
        !text.contains("Pair an iPhone"),
        "no pairing without a listener: {text}"
    );

    drop(occupied);
    app.retry_companion();
    assert_eq!(running_port(&app), Some(port));
}

#[test]
fn without_the_broker_the_listener_does_not_start() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    app.set_companion_on(true);
    let Listener::Failed { message, .. } = &app.companion.listener else {
        panic!("no approval queue, no listener");
    };
    assert!(message.contains("agent broker is not running"), "{message}");
}

// ---- The settings page. ----

#[test]
fn the_settings_page_shows_the_companion() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, port) = app_with_broker(&dir);
    let ctx = egui::Context::default();
    let (text, _) = settings_frame(&ctx, &mut app);
    for expected in [
        "iPhone companion",
        "Allow the iPhone app on this network",
        "This works only while the vault is unlocked.",
        "Off. Nothing listens on the network.",
        "Paired iPhones",
        "No iPhone is paired.",
        "Reset pairing…",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    assert!(!text.contains("Pair an iPhone"), "off: no pairing: {text}");

    app.set_companion_on(true);
    let (text, _) = settings_frame(&ctx, &mut app);
    assert!(
        text.contains(&format!("Listening on port {port}")),
        "{text}"
    );
    assert!(text.contains("Pair an iPhone"), "{text}");
    assert!(
        text.contains("Open the Apassy app on the iPhone and scan the code."),
        "{text}"
    );
}

#[test]
fn the_qr_code_is_drawn_from_its_modules_and_never_copied() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = app_with_broker(&dir);
    let ctx = egui::Context::default();
    app.set_companion_on(true);
    app.open_pairing(&ctx);
    poll_until(&mut app, &ctx, "the pairing window", |app| {
        app.companion.invite.is_some()
    });
    let (text, commands) = settings_frame(&ctx, &mut app);
    for expected in [
        "Mac name",
        "Code works for",
        "Cancel",
        "Do not photograph or share",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    assert!(
        !text.contains("apassy://") && !text.contains("Copy"),
        "the link is not text and has no copy button: {text}"
    );
    assert!(
        commands.is_empty(),
        "the link never goes to the pasteboard: {} commands",
        commands.len()
    );
    // The countdown counts down from about 5 minutes.
    let seconds = match app.companion_controller().expect("running").view() {
        PairingView::Open { expires_at } => expires_at.saturating_sub(now()),
        other => panic!("an open window, got {other:?}"),
    };
    assert!((295..=300).contains(&seconds), "{seconds}");
    assert!(text.contains("4:5") || text.contains("5:00"), "{text}");

    // Cancel closes the window and needs no owner check.
    app.cancel_pairing();
    assert!(app.companion.invite.is_none());
    assert_eq!(
        app.companion_controller().expect("running").view(),
        PairingView::Closed
    );
    assert!(app.owner.check.is_none());
}

#[test]
fn qr_modules_have_the_finder_patterns_and_a_quiet_zone() {
    let link = "apassy://pair?v=1&h=Mac-mini.local,192.0.2.10&p=48620&c=5PYNCqbX89O2pklLHIYbmfZJxvnsUauvIBsg8pcyfJU&s=s9IIzFKuwMPGM-IW92PJK8U5dG0y14hgHYP9lX4UI0g&n=Mac%20mini&e=1790000300";
    let qr = QrModules::new(link).expect("the link fits in a QR code");
    let width = qr.width();
    assert!(
        width >= 21 && (width - 21).is_multiple_of(4),
        "a QR version: {width}"
    );
    for corner in [(0, 0), (width - 7, 0), (0, width - 7)] {
        for i in 0..7 {
            for (x, y) in [(i, 0), (i, 6), (0, i), (6, i)] {
                assert!(
                    qr.is_dark(corner.0 + x, corner.1 + y),
                    "the ring of a finder"
                );
            }
        }
        assert!(!qr.is_dark(corner.0 + 1, corner.1 + 1), "the light ring");
        assert!(qr.is_dark(corner.0 + 3, corner.1 + 3), "the dark centre");
    }
    assert!(
        !qr.is_dark(width, 0) && !qr.is_dark(0, width),
        "outside is light"
    );

    // Drawn: about 200 points, whole points per module, black and white only.
    let ctx = egui::Context::default();
    let mut side = 0.0;
    let output = ctx.run_ui(input(0.0, Vec::new()), |ui| {
        side = draw_qr(ui, &qr, 200.0, "Pairing QR code").rect.width();
    });
    let total = (width + 2 * QUIET_ZONE) as f32;
    assert!(side <= 200.0 && side > 200.0 - total, "{side}");
    assert_eq!(side % total, 0.0, "whole points per module");
    let mut colors = std::collections::BTreeSet::new();
    fn fills(shape: &egui::Shape, colors: &mut std::collections::BTreeSet<[u8; 4]>) {
        match shape {
            egui::Shape::Rect(rect) => {
                colors.insert(rect.fill.to_array());
            }
            egui::Shape::Vec(nested) => nested.iter().for_each(|inner| fills(inner, colors)),
            _ => {}
        }
    }
    for clipped in &output.shapes {
        fills(&clipped.shape, &mut colors);
    }
    assert_eq!(
        colors,
        [[0, 0, 0, 255], [255, 255, 255, 255]].into_iter().collect()
    );
    output.drop_without_applying_deltas();
}

#[test]
fn the_code_field_keeps_digits_and_spaces_only() {
    for (typed, kept) in [
        ("348 942", "348 942"),
        ("348942", "348942"),
        ("34a8-9 42", "3489 42"),
        ("12345678901", "123456"),
        // Spaces are ignored, wherever they stand, and do not use up the 6 digits.
        ("3 4 8 9 4 2", "3 4 8 9 4 2"),
        ("348 94 2", "348 94 2"),
        (" 3 4 8 9 4 2", " 3 4 8 9 4 2"),
        ("3 4 8 9 4 2 7 7", "3 4 8 9 4 2"),
        ("348 942 ", "348 942"),
        ("1 2 3 4 5 6 7", "1 2 3 4 5 6"),
        ("", ""),
        ("abc", ""),
    ] {
        let mut code = typed.to_owned();
        keep_code_characters(&mut code);
        assert_eq!(code, kept, "typed {typed}");
    }
    // A paste of spaces does not fill the field with nothing else.
    let mut spaces = " ".repeat(500);
    keep_code_characters(&mut spaces);
    assert!(spaces.len() <= 32, "{}", spaces.len());
    assert_eq!(countdown(272), "4:32");
    assert_eq!(countdown(300), "5:00");
    assert_eq!(countdown(9), "0:09");
}

// ---- Pairing, removing, and resetting. ----

/// Open a window on the controller (the test needs the secret of the link), let the
/// phone send its request, and poll until the app shows it.
fn phone_asks_to_pair(app: &mut DesktopApp, ctx: &egui::Context, phone: &Phone) -> Vec<u8> {
    let controller = app.companion_controller().expect("the listener runs");
    let invite = controller.open().expect("a pairing window");
    assert!(
        invite.link.contains(&format!("h={MAC_LINK_HOST}")),
        "the link has the host of the test"
    );
    let secret = link_secret(&invite.link);
    let port = running_port(app).expect("port");
    let (status, body) = phone.pair(port, &pin(app), &secret);
    assert_eq!(status, 200, "{body}");
    poll_until(app, ctx, "the request of the phone", |app| {
        matches!(
            app.companion_controller().expect("running").view(),
            PairingView::Waiting { .. }
        )
    });
    secret
}

#[test]
fn a_pairing_goes_from_the_phone_through_the_code_and_the_owner_check() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, port) = app_with_broker(&dir);
    let ctx = egui::Context::default();
    app.set_companion_on(true);
    let phone = Phone::new();
    let secret = phone_asks_to_pair(&mut app, &ctx, &phone);
    let code = phone.code(&secret);
    let digits = code.replace(' ', "");

    // The Mac asks for the code. It does not show it.
    let (text, _) = settings_frame(&ctx, &mut app);
    assert!(
        text.contains(
            "\"Test iPhone\" wants to pair. Type the 6-digit code that the iPhone shows."
        ),
        "{text}"
    );
    assert!(text.contains("Pair") && text.contains("Cancel"), "{text}");
    assert!(
        !text.contains(&digits) && !text.contains(&code),
        "the code is on the phone only"
    );
    assert!(app.owner.check.is_none(), "no owner check before the code");

    // A code that is not 6 digits counts as nothing. A wrong code shows the tries left.
    app.companion.code = "12".to_owned();
    app.submit_pairing_code(&ctx);
    assert_eq!(
        app.companion.notice.as_ref().map(|n| n.text.as_str()),
        Some("Type the 6 digits that the iPhone shows.")
    );
    let wrong = if digits == "000000" {
        "000001"
    } else {
        "000000"
    };
    app.companion.code = wrong.to_owned();
    app.submit_pairing_code(&ctx);
    assert!(app.companion.code.is_empty(), "the typed code is erased");
    let (text, _) = settings_frame(&ctx, &mut app);
    assert!(
        text.contains("The code is wrong. 2 tries are left."),
        "{text}"
    );
    assert!(text.contains("Wrong codes so far: 1 of 3."), "{text}");
    assert!(
        app.owner.check.is_none(),
        "a wrong code starts no owner check"
    );
    assert!(
        app.owner_ui
            .session
            .companion_devices()
            .expect("devices")
            .is_empty()
    );

    // The right code, with the space of the phone, opens the owner check.
    app.companion.code = code.clone();
    app.submit_pairing_code(&ctx);
    assert!(app.companion.code.is_empty());
    let text = super::owner_tests::app_frame(&ctx, &mut app);
    assert!(text.contains("Confirm that it is you"), "{text}");
    assert!(
        text.contains("Pair the iPhone \"Test iPhone\"."),
        "the sheet names the device: {text}"
    );
    assert!(text.contains("can never see a secret value"), "{text}");
    assert!(
        app.owner_ui
            .session
            .companion_devices()
            .expect("devices")
            .is_empty()
    );

    // A wrong passphrase pairs nothing. The right one stores the device.
    confirm_with(&mut app, &ctx, WRONG);
    assert!(
        app.owner_ui
            .session
            .companion_devices()
            .expect("devices")
            .is_empty()
    );
    confirm_with(&mut app, &ctx, PASS);
    assert!(app.owner.check.is_none());
    let devices = app.owner_ui.session.companion_devices().expect("devices");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, DEVICE);
    assert_eq!(devices[0].name, DEVICE_NAME);
    assert_eq!(app.status_kind, crate::desktop::StatusKind::Ok);
    assert!(
        app.status_text.contains("\"Test iPhone\" is paired"),
        "{}",
        app.status_text
    );

    // The window is closed, and the page lists the device.
    app.poll_companion(&ctx);
    assert_eq!(
        app.companion_controller().expect("running").view(),
        PairingView::Closed
    );
    assert!(app.companion.notice.is_none());
    let (text, _) = settings_frame(&ctx, &mut app);
    assert!(text.contains("Test iPhone"), "{text}");
    assert!(text.contains("Last seen never"), "{text}");
    assert!(text.contains("Remove"), "{text}");
    assert!(!text.contains("No iPhone is paired."), "{text}");

    // The phone is paired: a signed request works.
    let (status, body) = phone.status(port, &pin(&app)).expect("status");
    assert_eq!(status, 200, "{body}");
    assert!(body.contains(DEVICE), "{body}");
    let (text, _) = settings_frame(&ctx, &mut app);
    assert!(text.contains("Last seen just now"), "{text}");

    // "Remove" needs no owner check and works at once.
    app.remove_companion_device(DEVICE, DEVICE_NAME);
    assert!(app.owner.check.is_none());
    assert!(
        app.owner_ui
            .session
            .companion_devices()
            .expect("devices")
            .is_empty()
    );
    let (status, body) = phone.status(port, &pin(&app)).expect("status");
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("unpaired"), "{body}");
}

#[test]
fn three_wrong_codes_close_the_window() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = app_with_broker(&dir);
    let ctx = egui::Context::default();
    app.set_companion_on(true);
    let phone = Phone::new();
    let secret = phone_asks_to_pair(&mut app, &ctx, &phone);
    let digits = phone.code(&secret).replace(' ', "");
    let wrong = if digits == "000000" {
        "000001"
    } else {
        "000000"
    };
    for _ in 0..3 {
        app.companion.code = wrong.to_owned();
        app.submit_pairing_code(&ctx);
    }
    let notice = app.companion.notice.as_ref().expect("a notice");
    assert!(notice.error);
    assert!(
        notice.text.contains("The pairing window is closed"),
        "{}",
        notice.text
    );
    app.poll_companion(&ctx);
    assert_eq!(
        app.companion_controller().expect("running").view(),
        PairingView::Closed
    );
    // Even the right code pairs nothing now.
    app.companion.code = digits;
    app.submit_pairing_code(&ctx);
    assert!(app.owner.check.is_none());
    assert!(
        app.owner_ui
            .session
            .companion_devices()
            .expect("devices")
            .is_empty()
    );
}

#[test]
fn reset_pairing_removes_every_device_and_makes_a_new_certificate() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, port) = app_with_broker(&dir);
    let ctx = egui::Context::default();
    app.set_companion_on(true);
    let phone = Phone::new();
    let secret = phone_asks_to_pair(&mut app, &ctx, &phone);
    app.companion.code = phone.code(&secret);
    app.submit_pairing_code(&ctx);
    confirm_with(&mut app, &ctx, PASS);
    assert_eq!(
        app.owner_ui
            .session
            .companion_devices()
            .expect("devices")
            .len(),
        1
    );
    let old_pin = pin(&app);
    assert_eq!(phone.status(port, &old_pin).expect("status").0, 200);

    // The button opens a confirmation. Nothing changes before "Reset pairing" there.
    app.ui.sheet = Some(super::Sheet::ResetCompanion);
    let (text, _) = settings_frame(&ctx, &mut app);
    assert!(text.contains("Reset pairing?"), "{text}");
    assert_eq!(
        app.owner_ui
            .session
            .companion_devices()
            .expect("devices")
            .len(),
        1
    );

    app.ui.sheet = None;
    app.reset_companion();
    assert!(app.owner.check.is_none(), "a reset needs no owner check");
    assert!(
        app.owner_ui
            .session
            .companion_devices()
            .expect("devices")
            .is_empty()
    );
    assert_eq!(running_port(&app), Some(port), "the listener runs again");
    let new_pin = pin(&app);
    assert_ne!(new_pin, old_pin, "a new certificate");
    // A phone that pinned the old certificate cannot connect any more.
    assert!(phone.status(port, &old_pin).is_err());
    let (status, body) = phone.status(port, &new_pin).expect("status");
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("unpaired"), "{body}");
}

#[test]
fn a_lock_ends_a_pairing_in_progress() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = app_with_broker(&dir);
    let ctx = egui::Context::default();
    app.set_companion_on(true);
    let phone = Phone::new();
    let secret = phone_asks_to_pair(&mut app, &ctx, &phone);
    app.companion.code = phone.code(&secret);
    app.submit_pairing_code(&ctx);
    assert!(app.owner.check.is_some(), "the owner check waits");
    app.lock_vault(Some(&ctx));
    assert!(app.owner.check.is_none(), "the lock closes the owner check");
    assert!(matches!(app.companion.listener, Listener::Off));
    assert!(app.companion.code.is_empty());
    assert!(app.companion.invite.is_none());
}

#[test]
fn the_pairing_request_of_the_owner_check_names_exactly_the_device() {
    use crate::broker::approvals::OwnerAction;
    use crate::desktop::owner_check::OwnerRequest;

    let request = OwnerRequest::PairCompanion {
        device_id: DEVICE.to_owned(),
        device_name: DEVICE_NAME.to_owned(),
        request_key: vec![4; 65],
        approval_key: vec![5; 65],
    };
    assert_eq!(
        request.action(),
        OwnerAction::PairCompanion {
            device_id: DEVICE.to_owned(),
            device_name: DEVICE_NAME.to_owned(),
            request_key: vec![4; 65],
            approval_key: vec![5; 65],
        }
    );
    assert!(
        request
            .describe()
            .starts_with("Pair the iPhone \"Test iPhone\".")
    );
}
