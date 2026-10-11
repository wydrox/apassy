//! Browser passkeys and one-time codes (contract section 9): the strict wire, the
//! client data and relying party checks, the caller checks, and the cancellation of
//! the host. Synthetic data only: no vault, no browser, no real account.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use apassy::browser::caller;
use apassy::browser::relay::{self, read_frame, write_frame};
#[cfg(feature = "vault")]
use apassy::browser::webauthn;
use apassy::browser::webauthn::{decode_bytes, decode_ids, encode_bytes};
use apassy::browser::wire::{
    self, Command as WireCommand, Data, EXTENSION_ORIGIN, LoginRow, PasskeyCreateRequest,
    PasskeyGetRequest, Request, Response,
};
use apassy::owner::wire::SecretText;

const RID: &str = "3b241101-e2bb-4255-8caf-4136c566a962";

fn b64url(bytes: &[u8]) -> String {
    encode_bytes(bytes)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

/// `clientDataJSON` exactly as the service worker builds it.
fn client_json(kind: &str, challenge: &[u8], origin: &str) -> String {
    format!(
        r#"{{"type":"{kind}","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
        b64url(challenge)
    )
}

fn get_packet(origin: &str, rp_id: &str, client: &str, allowed: &[String]) -> String {
    serde_json::json!({
        "v": 1,
        "cmd": "passkey_get",
        "rid": RID,
        "origin": origin,
        "rp_id": rp_id,
        "client_data_json": encode_bytes(client.as_bytes()),
        "allowed": allowed,
    })
    .to_string()
}

fn create_value() -> serde_json::Value {
    serde_json::json!({
        "v": 1,
        "cmd": "passkey_create",
        "rid": RID,
        "origin": "https://login.example.com",
        "rp_id": "example.com",
        "client_data_json": encode_bytes(client_json("webauthn.create", &[7; 32], "https://login.example.com").as_bytes()),
        "user_handle": encode_bytes(&[1, 2, 3, 4]),
        "user_name": "owner@example.com",
        "user_display_name": "Owner",
        "algorithms": [-7, -257],
        "excluded": [encode_bytes(&[9; 16])],
        "title": " Example ",
    })
}

fn parse(text: &str) -> Result<WireCommand, wire::WireError> {
    Request::parse(text.as_bytes())
}

fn code(text: &str) -> &'static str {
    parse(text).unwrap_err().code
}

// ------------------------------------------------------------------ strict wire

#[test]
fn passkey_get_parses_into_its_own_packet() {
    let client = client_json("webauthn.get", &[1; 32], "https://example.com");
    let allowed = vec![encode_bytes(&[5; 16]), encode_bytes(&[6; 1023])];
    let command = parse(&get_packet(
        "https://example.com",
        "example.com",
        &client,
        &allowed,
    ))
    .unwrap();
    assert_eq!(
        command,
        WireCommand::PasskeyGet(PasskeyGetRequest {
            rid: RID.to_owned(),
            origin: "https://example.com".to_owned(),
            rp_id: "example.com".to_owned(),
            client_data_json: encode_bytes(client.as_bytes()),
            allowed: allowed.clone(),
        })
    );
    // Debug shows neither the client data nor the credential IDs.
    let debug = format!("{command:?}");
    assert!(!debug.contains(&encode_bytes(client.as_bytes())), "{debug}");
    assert!(!debug.contains(&allowed[0]), "{debug}");
}

#[test]
fn passkey_get_refuses_anything_outside_the_contract() {
    let client = client_json("webauthn.get", &[1; 32], "https://example.com");
    let good: serde_json::Value = serde_json::from_str(&get_packet(
        "https://example.com",
        "example.com",
        &client,
        &[],
    ))
    .unwrap();
    let with = |key: &str, value: serde_json::Value| {
        let mut packet = good.clone();
        packet[key] = value;
        packet.to_string()
    };
    let without = |key: &str| {
        let mut packet = good.clone();
        packet.as_object_mut().unwrap().remove(key);
        packet.to_string()
    };
    assert_eq!(code(&with("extra", 1.into())), "bad_request");
    assert_eq!(
        code(&with("hash", "AAAA".into())),
        "bad_request",
        "no page-owned hash"
    );
    assert_eq!(code(&with("v", 2.into())), "bad_version");
    for key in ["rid", "origin", "rp_id", "client_data_json", "allowed", "v"] {
        assert_eq!(code(&without(key)), "bad_request", "{key}");
    }
    for rid in [
        "",
        "3B241101-E2BB-4255-8CAF-4136C566A962",
        "3b241101e2bb42558caf4136c566a962",
        "x",
    ] {
        assert_eq!(code(&with("rid", rid.into())), "bad_request", "{rid}");
    }
    for origin in [
        "http://example.com",
        "https://example.com/",
        "null",
        "https://EXAMPLE.com",
        "https://127.0.0.1",
        "https://example.com:443",
    ] {
        assert_eq!(
            code(&with("origin", origin.into())),
            "bad_request",
            "{origin}"
        );
    }
    for rp in ["com", "Example.com", "1.2.3.4", ""] {
        assert_eq!(code(&with("rp_id", rp.into())), "bad_request", "{rp}");
    }
    // The client data: canonical standard base64 only.
    let raw = encode_bytes(client.as_bytes());
    for text in [
        raw[..raw.len() - 1].to_owned(),
        format!("{raw}===="),
        raw.replace('+', "-").replace('/', "_") + "!",
        format!(" {raw}"),
        format!("{raw}\n"),
        String::new(),
    ] {
        assert_eq!(
            code(&with("client_data_json", text.clone().into())),
            "bad_request",
            "{text:?}"
        );
    }
    // Credential IDs: at most 256, each 1 to 1023 bytes.
    let id = encode_bytes(&[1; 16]);
    assert!(parse(&with("allowed", serde_json::json!(vec![id.clone(); 256]))).is_ok());
    assert_eq!(
        code(&with("allowed", serde_json::json!(vec![id; 257]))),
        "bad_request"
    );
    assert_eq!(
        code(&with("allowed", serde_json::json!([""]))),
        "bad_request"
    );
    assert_eq!(
        code(&with(
            "allowed",
            serde_json::json!([encode_bytes(&[1; 1024])])
        )),
        "bad_request"
    );
    assert_eq!(
        code(&with("allowed", serde_json::json!(["AQ"]))),
        "bad_request"
    );
    assert_eq!(
        code(&with("allowed", serde_json::json!([1]))),
        "bad_request"
    );
    // Twice the same key is not a second chance.
    let twice = good
        .to_string()
        .replacen('{', r#"{"cmd":"passkey_get","#, 1);
    assert_eq!(code(&twice), "bad_request");
}

#[test]
fn passkey_create_parses_and_checks_its_fields() {
    let command = parse(&create_value().to_string()).unwrap();
    let WireCommand::PasskeyCreate(PasskeyCreateRequest {
        title,
        algorithms,
        user_name,
        excluded,
        ..
    }) = &command
    else {
        panic!("not a create: {command:?}");
    };
    assert_eq!(title, "Example");
    assert_eq!(algorithms, &[-7, -257]);
    assert_eq!(user_name, "owner@example.com");
    assert_eq!(excluded.len(), 1);
    assert!(!format!("{command:?}").contains(&encode_bytes(&[1, 2, 3, 4])));
    let with = |key: &str, value: serde_json::Value| {
        let mut packet = create_value();
        packet[key] = value;
        packet.to_string()
    };
    assert_eq!(
        code(&with("user_handle", encode_bytes(&[1; 65]).into())),
        "bad_request"
    );
    assert_eq!(code(&with("user_handle", "".into())), "bad_request");
    assert_eq!(
        code(&with("algorithms", serde_json::json!([]))),
        "bad_request"
    );
    assert_eq!(
        code(&with("algorithms", serde_json::json!(vec![-7; 17]))),
        "bad_request"
    );
    assert_eq!(
        code(&with("algorithms", serde_json::json!(["-7"]))),
        "bad_request"
    );
    assert_eq!(code(&with("title", "  ".into())), "bad_request");
    assert_eq!(code(&with("title", "a".repeat(129).into())), "bad_request");
    for text in [
        "me\nfor https://github.com",
        "me\u{202e}gro",
        "me\u{2066}x",
        "a\u{0}b",
    ] {
        assert_eq!(
            code(&with("user_name", text.into())),
            "bad_request",
            "{text:?}"
        );
        assert_eq!(
            code(&with("user_display_name", text.into())),
            "bad_request",
            "{text:?}"
        );
        assert_eq!(code(&with("title", text.into())), "bad_request", "{text:?}");
    }
    assert_eq!(
        code(&with("user_name", "a".repeat(257).into())),
        "bad_request"
    );
    assert_eq!(
        code(&with("excluded", serde_json::json!(["AQ==", " "]))),
        "bad_request"
    );
    assert_eq!(
        code(&with("allowed", serde_json::json!([]))),
        "bad_request",
        "a get field"
    );
}

#[test]
fn fill_code_parses_and_checks_its_fields() {
    assert_eq!(
        parse(r#"{"v":1,"cmd":"fill_code","url":"https://example.com/2fa","item":7}"#).unwrap(),
        WireCommand::FillCode {
            url: "https://example.com/2fa".to_owned(),
            item: 7,
            field: None
        }
    );
    assert_eq!(
        parse(
            r#"{"v":1,"cmd":"fill_code","url":"https://example.com/","item":7,"field":"Backup"}"#
        )
        .unwrap(),
        WireCommand::FillCode {
            url: "https://example.com/".to_owned(),
            item: 7,
            field: Some("Backup".to_owned())
        }
    );
    for text in [
        r#"{"v":1,"cmd":"fill_code","url":"https://example.com/","item":0}"#,
        r#"{"v":1,"cmd":"fill_code","url":"","item":7}"#,
        r#"{"v":1,"cmd":"fill_code","item":7}"#,
        r#"{"v":1,"cmd":"fill_code","url":"https://example.com/","item":7,"field":" "}"#,
        r#"{"v":1,"cmd":"fill_code","url":"https://example.com/","item":7,"field":"a\u202eb"}"#,
        r#"{"v":1,"cmd":"fill_code","url":"https://example.com/","item":7,"code":"123456"}"#,
    ] {
        assert_eq!(code(text), "bad_request", "{text}");
    }
    assert_eq!(
        code(r#"{"v":2,"cmd":"fill_code","url":"https://example.com/","item":7}"#),
        "bad_version"
    );
}

#[test]
fn legacy_requests_and_literals_are_unchanged() {
    let request = Request {
        v: 1,
        cmd: "fill".to_owned(),
        url: Some("https://github.com/".to_owned()),
        item: Some(7),
        title: None,
        username: None,
        password: None,
        length: None,
        symbols: None,
    };
    assert_eq!(
        request.command().unwrap(),
        WireCommand::Fill {
            url: "https://github.com/".to_owned(),
            item: 7
        }
    );
    assert_eq!(
        parse(r#"{"v":1,"cmd":"status"}"#).unwrap(),
        WireCommand::Status
    );
    assert_eq!(code(r#"{"v":1,"cmd":"status","rid":"x"}"#), "bad_request");
    assert!(wire::is_guarded_command("passkey_get"));
    assert!(wire::is_guarded_command("passkey_create"));
    assert!(wire::is_guarded_command("fill_code"));
    assert!(!wire::is_guarded_command("fill"));
}

#[test]
fn answers_serialize_as_the_contract_says_and_debug_hides_them() {
    let passkey = Response::ok(
        "Signed.",
        Data::Passkey {
            rid: RID.to_owned(),
            credential_id: "Y3JlZA==".to_owned(),
            user_handle: "dXNlcg==".to_owned(),
            authenticator_data: "YXV0aA==".to_owned(),
            signature: "c2lnbmF0dXJlLWNhbmFyeQ==".to_owned(),
            client_data_json: "Y2xpZW50LWNhbmFyeQ==".to_owned(),
        },
    );
    let json = serde_json::to_value(&passkey).unwrap();
    assert_eq!(json["data"]["type"], "passkey");
    assert_eq!(json["data"]["rid"], RID);
    assert_eq!(json["data"]["signature"], "c2lnbmF0dXJlLWNhbmFyeQ==");
    let debug = format!("{passkey:?}");
    for hidden in ["c2lnbmF0dXJl", "Y2xpZW50", "Y3JlZA", "dXNlcg", "YXV0aA"] {
        assert!(!debug.contains(hidden), "{debug}");
    }
    let created = Response::ok(
        "Saved.",
        Data::PasskeyCreated {
            rid: RID.to_owned(),
            item: 12,
            credential_id: "Y3JlZA==".to_owned(),
            attestation_object: "YXR0".to_owned(),
            authenticator_data: "YXV0aA==".to_owned(),
            public_key_spki: "c3BraQ==".to_owned(),
            algorithm: -7,
            client_data_json: "Y2xpZW50".to_owned(),
        },
    );
    let json = serde_json::to_value(&created).unwrap();
    assert_eq!(json["data"]["type"], "passkey_created");
    assert_eq!(json["data"]["item"], 12);
    assert_eq!(json["data"]["algorithm"], -7);
    assert!(!format!("{created:?}").contains("YXR0"));
    let otp = Response::ok(
        "Code.",
        Data::Code {
            item: 7,
            origin: "https://example.com".to_owned(),
            code: SecretText::new("493817".to_owned()),
            remaining: 21,
        },
    );
    let json = serde_json::to_value(&otp).unwrap();
    assert_eq!(json["data"]["type"], "code");
    assert_eq!(json["data"]["code"], "493817");
    assert_eq!(json["data"]["remaining"], 21);
    assert!(!format!("{otp:?}").contains("493817"));
    // A login row says only whether it has a code.
    let row: LoginRow = serde_json::from_str(r#"{"item":1,"title":"A","username":"b"}"#).unwrap();
    assert!(!row.has_totp);
    let row = serde_json::to_value(LoginRow {
        has_totp: true,
        ..row
    })
    .unwrap();
    assert_eq!(row["has_totp"], true);
}

// ------------------------------------------------------------------ base64

#[test]
fn byte_helpers_are_strict_and_bounded() {
    assert_eq!(encode_bytes(b""), "");
    assert_eq!(encode_bytes(b"f"), "Zg==");
    assert_eq!(encode_bytes(b"fo"), "Zm8=");
    assert_eq!(encode_bytes(b"foo"), "Zm9v");
    assert_eq!(encode_bytes(&[0xfb, 0xff, 0xbf]), "+/+/");
    assert_eq!(decode_bytes("Zm9vYmFy", 0, 6).unwrap(), b"foobar");
    assert_eq!(decode_bytes("Zg==", 1, 1).unwrap(), b"f");
    // Bounds.
    assert!(decode_bytes("Zm9v", 4, 10).is_err());
    assert!(decode_bytes("Zm9vYmFy", 0, 5).is_err());
    assert!(decode_bytes("", 1, 10).is_err());
    // Controls, white space, URL alphabet, bad padding, unused bits.
    for text in [
        "Zg=",
        "Zg",
        "Zg===",
        "Z===",
        "Zh==",
        "Zm9=",
        "Zm9v\n",
        "Zm9v\r\n",
        "Zm\u{0}9v",
        "Zm 9v",
        "-_-_",
        "Zg==Zg==",
        "=Zg=",
        "Zm9v=",
        "\u{FF21}AAA",
    ] {
        assert!(decode_bytes(text, 0, 64).is_err(), "{text:?}");
    }
    // A very long text is refused before decoding.
    assert!(decode_bytes(&"A".repeat(1_000_000), 0, 1023).is_err());
    let ids = decode_ids(&[encode_bytes(&[1]), encode_bytes(&[2; 1023])]).unwrap();
    assert_eq!(ids, vec![vec![1], vec![2; 1023]]);
    assert!(decode_ids(&vec![encode_bytes(&[1]); 257]).is_err());
    assert!(decode_ids(&[String::new()]).is_err());
}

// ------------------------------------------------------------------ client data

#[cfg(feature = "vault")]
mod client_data {
    use super::*;
    use webauthn::{TYPE_CREATE, TYPE_GET, client_data};

    fn check(
        origin: &str,
        rp_id: &str,
        json: &str,
        kind: &str,
    ) -> Result<webauthn::ClientData, &'static str> {
        client_data(RID, origin, rp_id, &encode_bytes(json.as_bytes()), kind)
            .map_err(|error| error.code)
    }

    fn get(origin: &str, rp_id: &str) -> Result<webauthn::ClientData, &'static str> {
        check(
            origin,
            rp_id,
            &client_json(TYPE_GET, &[3; 32], origin),
            TYPE_GET,
        )
    }

    #[test]
    fn the_hash_is_sha256_of_the_exact_bytes() {
        let json = client_json(TYPE_CREATE, &[3; 32], "https://example.com");
        let data = check("https://example.com", "example.com", &json, TYPE_CREATE).unwrap();
        assert_eq!(data.client_data_json, json.as_bytes());
        let digest = ring::digest::digest(&ring::digest::SHA256, json.as_bytes());
        assert_eq!(&data.client_data_hash[..], digest.as_ref());
        assert_eq!(data.rid, RID);
        assert_eq!(data.origin, "https://example.com");
        assert_eq!(data.rp_id, "example.com");
        let debug = format!("{data:?}");
        assert!(!debug.contains("challenge"), "{debug}");
    }

    #[test]
    fn the_relying_party_is_a_registrable_suffix_of_the_origin() {
        assert!(get("https://example.com", "example.com").is_ok());
        assert!(get("https://login.example.com", "example.com").is_ok());
        assert!(get("https://a.b.example.com:8443", "b.example.com").is_ok());
        assert!(get("https://example.co.uk", "example.co.uk").is_ok());
        assert!(get("https://www.example.co.uk", "example.co.uk").is_ok());
        assert!(get("https://owner.github.io", "owner.github.io").is_ok());
        assert!(get("https://x.owner.github.io", "owner.github.io").is_ok());
        assert!(get("http://localhost:8080", "localhost").is_ok());
        assert!(get("https://localhost", "localhost").is_ok());
        // Public suffixes, ICANN and private.
        assert_eq!(
            get("https://example.com", "com").unwrap_err(),
            "bad_request"
        );
        assert_eq!(
            get("https://example.co.uk", "co.uk").unwrap_err(),
            "unsupported"
        );
        assert_eq!(
            get("https://owner.github.io", "github.io").unwrap_err(),
            "unsupported"
        );
        assert_eq!(
            get("https://x.blogspot.com", "blogspot.com").unwrap_err(),
            "unsupported"
        );
        // Suffix confusion.
        assert_eq!(
            get("https://evilexample.com", "example.com").unwrap_err(),
            "unsupported"
        );
        assert_eq!(
            get("https://example.com.evil.com", "example.com").unwrap_err(),
            "unsupported"
        );
        assert_eq!(
            get("https://example.com", "login.example.com").unwrap_err(),
            "unsupported"
        );
        assert_eq!(
            get("https://other.github.io", "owner.github.io").unwrap_err(),
            "unsupported"
        );
        assert_eq!(
            get("https://evil.com", "example.com").unwrap_err(),
            "unsupported"
        );
        // localhost only for itself; unknown suffixes go to the browser.
        assert_eq!(
            get("http://localhost", "example.com").unwrap_err(),
            "unsupported"
        );
        assert_eq!(
            get("https://example.com", "localhost").unwrap_err(),
            "unsupported"
        );
        assert_eq!(
            get("https://app.example.test", "example.test").unwrap_err(),
            "unsupported"
        );
        // Origins outside https and local http.
        assert_eq!(
            get("http://example.com", "example.com").unwrap_err(),
            "bad_request"
        );
        assert_eq!(
            get("https://127.0.0.1", "127.0.0.1").unwrap_err(),
            "bad_request"
        );
        assert_eq!(
            get("https://[::1]", "localhost").unwrap_err(),
            "bad_request"
        );
    }

    #[test]
    fn the_client_data_must_be_the_one_of_the_service_worker() {
        let origin = "https://example.com";
        let rp = "example.com";
        let challenge = b64url(&[3; 32]);
        let bad = |json: &str, kind: &str| check(origin, rp, json, kind).unwrap_err();
        // Type.
        assert_eq!(
            bad(&client_json(TYPE_GET, &[3; 32], origin), TYPE_CREATE),
            "bad_request"
        );
        assert_eq!(
            bad(&client_json(TYPE_CREATE, &[3; 32], origin), TYPE_GET),
            "bad_request"
        );
        assert_eq!(
            bad(&client_json("payment.get", &[3; 32], origin), "payment.get"),
            "bad_request"
        );
        // Origin of the bytes against the origin of the browser.
        assert_eq!(
            bad(
                &client_json(TYPE_GET, &[3; 32], "https://evil.com"),
                TYPE_GET
            ),
            "bad_request"
        );
        assert_eq!(
            bad(
                &client_json(TYPE_GET, &[3; 32], "https://login.example.com"),
                TYPE_GET
            ),
            "bad_request"
        );
        // Cross origin.
        let cross = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}","crossOrigin":true}}"#
        );
        assert_eq!(bad(&cross, TYPE_GET), "bad_request");
        let missing =
            format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}"}}"#);
        assert_eq!(bad(&missing, TYPE_GET), "bad_request");
        let text = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}","crossOrigin":"false"}}"#
        );
        assert_eq!(bad(&text, TYPE_GET), "bad_request");
        let top = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}","crossOrigin":false,"topOrigin":"{origin}"}}"#
        );
        assert_eq!(bad(&top, TYPE_GET), "bad_request");
        // Another order, white space, an escape, a duplicate key: not the bytes of the
        // service worker.
        let order = format!(
            r#"{{"challenge":"{challenge}","type":"webauthn.get","origin":"{origin}","crossOrigin":false}}"#
        );
        assert_eq!(bad(&order, TYPE_GET), "bad_request");
        let spaced = format!(
            r#"{{"type": "webauthn.get","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
        );
        assert_eq!(bad(&spaced, TYPE_GET), "bad_request");
        let escaped = format!(
            r#"{{"type":"webauthn\u002eget","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
        );
        assert_eq!(bad(&escaped, TYPE_GET), "bad_request");
        let twice = format!(
            r#"{{"type":"webauthn.get","type":"webauthn.get","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
        );
        assert_eq!(bad(&twice, TYPE_GET), "bad_request");
        let trailing = format!("{}\n", client_json(TYPE_GET, &[3; 32], origin));
        assert_eq!(bad(&trailing, TYPE_GET), "bad_request");
        // Challenge: base64url without padding, 16 to 1024 bytes.
        assert!(
            check(
                origin,
                rp,
                &client_json(TYPE_GET, &[3; 16], origin),
                TYPE_GET
            )
            .is_ok()
        );
        assert!(
            check(
                origin,
                rp,
                &client_json(TYPE_GET, &[3; 1024], origin),
                TYPE_GET
            )
            .is_ok()
        );
        assert_eq!(
            bad(&client_json(TYPE_GET, &[3; 15], origin), TYPE_GET),
            "bad_request"
        );
        assert_eq!(
            bad(&client_json(TYPE_GET, &[3; 1025], origin), TYPE_GET),
            "bad_request"
        );
        for challenge in [
            encode_bytes(&[0xfb; 32]),
            format!("{}=", b64url(&[3; 32])),
            format!("{}\\n", b64url(&[3; 32])),
            "AAAAAAAAAAAAAAAAAAAAAB".to_owned(),
        ] {
            let json = format!(
                r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
            );
            assert_eq!(bad(&json, TYPE_GET), "bad_request", "{challenge}");
        }
        // The base64 of the client data, and the request ID.
        let raw = encode_bytes(client_json(TYPE_GET, &[3; 32], origin).as_bytes());
        assert!(client_data(RID, origin, rp, &raw[..raw.len() - 1], TYPE_GET).is_err());
        assert!(client_data(RID, origin, rp, &format!("{raw}\n"), TYPE_GET).is_err());
        assert!(client_data("not-a-uuid", origin, rp, &raw, TYPE_GET).is_err());
        assert!(client_data(RID, origin, rp, &raw, "webauthn.other").is_err());
        assert!(client_data(RID, origin, rp, &encode_bytes(&[b'x'; 4097]), TYPE_GET).is_err());
    }
}

// ------------------------------------------------------------------ caller checks

/// The test program is not in an app bundle, so both checks fail without a guard.
#[test]
fn caller_checks_fail_closed_outside_a_bundle() {
    if std::env::var_os(caller::GUARD_ENV).is_some() {
        return;
    }
    let error = caller::check_browser_parent().unwrap_err();
    assert_eq!(error.code, "unsupported");
    let (one, _two) = UnixStream::pair().unwrap();
    assert_eq!(caller::check_peer(&one).unwrap_err().code, "unsupported");
}

/// A guarded command through the host without a verified browser gets `unsupported`,
/// and the app never sees it.
#[test]
fn the_host_refuses_a_passkey_request_from_an_unverified_caller() {
    if std::env::var_os(caller::GUARD_ENV).is_some() {
        return;
    }
    let dir = TempDir::new("refuse");
    let socket = dir.path().join("b.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = client_json("webauthn.get", &[1; 32], "https://example.com");
    let mut input = Vec::new();
    write_frame(
        &mut input,
        get_packet("https://example.com", "example.com", &client, &[]).as_bytes(),
    )
    .unwrap();
    write_frame(
        &mut input,
        br#"{"v":1,"cmd":"fill_code","url":"https://example.com/","item":7}"#,
    )
    .unwrap();
    let mut out = Vec::new();
    let status = relay::run(args(), std::io::Cursor::new(input), &mut out, &socket);
    assert_eq!(status, 0);
    let answers = frames(&out);
    assert_eq!(answers.len(), 2);
    assert!(
        answers.iter().all(|answer| answer["code"] == "unsupported"),
        "{answers:?}"
    );
    assert!(listener.accept().is_err(), "the app saw a refused request");
}

// ------------------------------------------------------------------ cancellation

/// The browser closes the native port while the app shows the owner dialog. The host
/// shuts the connection down at once: the app sees the hang-up in well under the 230 s
/// of an unanswered request, and the host answers nothing.
#[test]
fn the_end_of_the_input_reaches_the_app_without_waiting() {
    let dir = TempDir::new("eof");
    let socket = dir.path().join("b.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let (got_line, line_seen) = std::sync::mpsc::channel();
    let app = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while byte[0] != b'\n' {
            stream.read_exact(&mut byte).unwrap();
            line.push(byte[0]);
        }
        got_line.send(line).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let started = Instant::now();
        let hang_up = matches!(stream.read(&mut byte), Ok(0));
        (hang_up, started.elapsed())
    });
    let (mut browser, host_input) = UnixStream::pair().unwrap();
    // A legacy fill also waits for the owner, and needs no caller check.
    write_frame(
        &mut browser,
        br#"{"v":1,"cmd":"fill","url":"https://example.com/","item":7}"#,
    )
    .unwrap();
    let host = {
        let socket = socket.clone();
        thread::spawn(move || {
            let mut out = Vec::new();
            let started = Instant::now();
            let status = relay::serve(args(), host_input, &mut out, &socket);
            (status, out, started.elapsed())
        })
    };
    let line = line_seen.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(line.starts_with(br#"{"v":1,"cmd":"fill""#));
    thread::sleep(Duration::from_millis(200));
    drop(browser);
    let (hang_up, waited) = app.join().unwrap();
    assert!(hang_up, "the app did not see the hang-up");
    assert!(waited < Duration::from_secs(5), "the app waited {waited:?}");
    let (status, out, ran) = host.join().unwrap();
    assert_eq!(status, 0);
    assert!(out.is_empty(), "an answer for a closed port");
    assert!(ran < Duration::from_secs(10), "the host ran {ran:?}");
}

/// Without a cancellation the host still answers in order.
#[test]
fn serve_answers_each_message_in_order() {
    let dir = TempDir::new("order");
    let socket = dir.path().join("b.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let app = thread::spawn(move || {
        for index in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut byte = [0u8; 1];
            while byte[0] != b'\n' {
                stream.read_exact(&mut byte).unwrap();
            }
            let answer = format!(
                "{{\"ok\":true,\"code\":\"ok\",\"message\":\"{index}\",\"data\":{{\"type\":\"none\"}}}}\n"
            );
            stream.write_all(answer.as_bytes()).unwrap();
        }
    });
    let (mut browser, host_input) = UnixStream::pair().unwrap();
    let (host_output, mut answers) = UnixStream::pair().unwrap();
    let host = {
        let socket = socket.clone();
        thread::spawn(move || relay::serve(args(), host_input, host_output, &socket))
    };
    write_frame(&mut browser, br#"{"v":1,"cmd":"status"}"#).unwrap();
    write_frame(&mut browser, br#"{"v":1,"cmd":"show"}"#).unwrap();
    for index in ["0", "1"] {
        let answer = read_frame(&mut answers).unwrap().unwrap();
        let answer: serde_json::Value = serde_json::from_slice(&answer).unwrap();
        assert_eq!(answer["message"], index);
    }
    app.join().unwrap();
    drop(browser);
    assert_eq!(host.join().unwrap(), 0);
}

// ------------------------------------------------------------------ the Swift guard

/// The Swift guard, built once per test process. `None` when this Mac has no Swift
/// compiler.
fn guard_binary() -> Option<&'static Path> {
    static GUARD: OnceLock<Option<PathBuf>> = OnceLock::new();
    GUARD
        .get_or_init(|| build_guard("apassy-browser-guard", &[]))
        .as_deref()
}

/// The guard with its self-test modes (`-D APASSY_BROWSER_GUARD_SELFTEST`). Only this
/// test build has them; they answer `allowed` or `refused`, never `ok`.
fn selftest_guard() -> Option<&'static Path> {
    static GUARD: OnceLock<Option<PathBuf>> = OnceLock::new();
    GUARD
        .get_or_init(|| {
            build_guard(
                "apassy-browser-guard-selftest",
                &["-D", "APASSY_BROWSER_GUARD_SELFTEST"],
            )
        })
        .as_deref()
}

fn build_guard(name: &str, flags: &[&str]) -> Option<PathBuf> {
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("native/ApassyBrowserGuard/main.swift");
    let status = Command::new("xcrun")
        .args([
            "--sdk",
            "macosx",
            "swiftc",
            "-O",
            "-swift-version",
            "6",
            "-warnings-as-errors",
        ])
        .args(flags)
        .arg("-o")
        .arg(&out)
        .arg(&source)
        .status();
    match status {
        Ok(status) if status.success() => Some(out),
        _ => {
            eprintln!("skip: the Swift guard does not build on this Mac");
            None
        }
    }
}

fn run_guard(guard: &Path, check: &str, stdin: Stdio) -> (i32, Vec<u8>) {
    let output = Command::new(guard)
        .arg(check)
        .stdin(stdin)
        .stderr(Stdio::null())
        .output()
        .unwrap();
    (output.status.code().unwrap_or(-1), output.stdout)
}

#[test]
fn the_swift_guard_refuses_a_wrong_parent_and_an_unsigned_self() {
    let Some(guard) = guard_binary() else { return };
    // The parent is this test program: not apassy-browser-host, not the app, and the
    // guard has no team signature.
    assert_eq!(
        run_guard(guard, "browser-parent", Stdio::null()),
        (1, Vec::new())
    );
    let (one, _two) = UnixStream::pair().unwrap();
    let peer = Stdio::from(std::os::fd::OwnedFd::from(one));
    assert_eq!(run_guard(guard, "socket-peer", peer), (1, Vec::new()));
    assert_eq!(
        run_guard(guard, "socket-peer", Stdio::null()),
        (1, Vec::new())
    );
    assert_ne!(run_guard(guard, "anything", Stdio::null()).0, 0);
    // An ad hoc signature with the identifier of the guard, in the place of the guard
    // in a bundle, has no team, so it refuses too.
    let dir = TempDir::new("adhoc");
    let macos = dir.path().join("Apassy.app/Contents/MacOS");
    std::fs::create_dir_all(&macos).unwrap();
    let copy = macos.join("apassy-browser-guard");
    std::fs::copy(guard, &copy).unwrap();
    let signed = Command::new("/usr/bin/codesign")
        .args([
            "--force",
            "--sign",
            "-",
            "--identifier",
            caller::GUARD_IDENTIFIER,
        ])
        .arg(&copy)
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(signed.success());
    assert_eq!(
        run_guard(&copy, "browser-parent", Stdio::null()),
        (1, Vec::new())
    );
}

/// The real host program with the real guard (debug override): a passkey request from
/// a caller that is not a known browser gets `unsupported`, and the app never sees it.
#[test]
fn the_host_program_runs_the_guard_and_refuses() {
    let Some(guard) = guard_binary() else { return };
    let dir = TempDir::new("host");
    let socket = dir.path().join("b.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_apassy-browser-host"))
        .arg(EXTENSION_ORIGIN)
        .env(caller::GUARD_ENV, guard)
        .env(wire::SOCKET_ENV, &socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let client = client_json("webauthn.get", &[1; 32], "https://example.com");
    write_frame(
        &mut stdin,
        get_packet("https://example.com", "example.com", &client, &[]).as_bytes(),
    )
    .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let answer = read_frame(&mut stdout).unwrap().unwrap();
    let answer: serde_json::Value = serde_json::from_slice(&answer).unwrap();
    assert_eq!(answer["code"], "unsupported", "{answer}");
    assert!(
        answer["message"]
            .as_str()
            .unwrap()
            .contains("cannot verify"),
        "{answer}"
    );
    drop(stdin);
    assert!(child.wait().unwrap().success());
    assert!(listener.accept().is_err(), "the app saw a refused request");
}

/// `check_peer` hands the socket to the real guard, which refuses: its parent is not
/// the Apassy app and the peer is not the host. It runs in a child test process,
/// because only the environment names a guard in a debug build.
#[test]
fn check_peer_runs_the_guard_and_refuses() {
    let Some(guard) = guard_binary() else { return };
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "check_peer_child",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(caller::GUARD_ENV, guard)
        .env("APASSY_TEST_PEER_CHILD", "1")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{text}");
    assert!(text.contains("peer-check: refused by the guard"), "{text}");
}

#[test]
fn check_peer_child() {
    if std::env::var_os("APASSY_TEST_PEER_CHILD").is_none() {
        return;
    }
    let (one, _two) = UnixStream::pair().unwrap();
    let error = caller::check_peer(&one).unwrap_err();
    assert_eq!(error.code, "unsupported");
    assert!(error.message.contains("cannot verify"), "{}", error.message);
    let error = caller::check_browser_parent().unwrap_err();
    assert!(error.message.contains("cannot verify"), "{}", error.message);
    println!("peer-check: refused by the guard");
}

// ------------------------------------------------------------------ browser arguments

/// A `KERN_PROCARGS2` buffer as the kernel makes it: `argc`, the executable path,
/// padding zeros, the arguments, then the environment.
fn procargs(argc: i32, path: &str, args: &[&[u8]], env: &[&str]) -> Vec<u8> {
    let mut out = argc.to_ne_bytes().to_vec();
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    for arg in args {
        out.extend_from_slice(arg);
        out.push(0);
    }
    for var in env {
        out.extend_from_slice(var.as_bytes());
        out.push(0);
    }
    out
}

fn parse_verdict(guard: &Path, buffer: &[u8]) -> String {
    let mut child = Command::new(guard)
        .args(["selftest-parse", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // A buffer longer than the guard reads may end the pipe early.
    let _ = child.stdin.take().unwrap().write_all(buffer);
    let output = child.wait_with_output().unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.success(), text == "allowed\n", "{text}");
    text
}

const HELIUM_PATH: &str = "/Applications/Helium.app/Contents/MacOS/Helium";

fn browser_args(extra: &[&str]) -> Vec<u8> {
    let mut args: Vec<&[u8]> = vec![HELIUM_PATH.as_bytes()];
    args.extend(extra.iter().map(|arg| arg.as_bytes()));
    procargs(
        args.len() as i32,
        HELIUM_PATH,
        &args,
        &["HOME=/Users/owner"],
    )
}

#[test]
fn the_guard_refuses_unsafe_browser_switches_in_every_form() {
    let Some(guard) = selftest_guard() else {
        return;
    };
    let allowed = |extra: &[&str]| {
        assert_eq!(
            parse_verdict(guard, &browser_args(extra)),
            "allowed\n",
            "{extra:?}"
        );
    };
    allowed(&[]);
    allowed(&["--profile-directory=Default", "https://example.com"]);
    allowed(&["--user-data-dir=/tmp/profile", "--headless=new"]);
    // Names that only look like an unsafe switch.
    allowed(&[
        "--load-extensions-later",
        "load-extension",
        "--remote=debugging",
    ]);
    allowed(&["https://example.com/?--load-extension=x"]);
    for extra in [
        &["--load-extension=/tmp/x"][..],
        &["--load-extension", "/tmp/x"],
        &["--load-extension"],
        &["-load-extension=/tmp/x"],
        &["---load-extension=/tmp/x"],
        &["--LOAD-EXTENSION=/tmp/x"],
        &["--Load-Extension", "/tmp/x"],
        &["--disable-extensions-except=/tmp/x"],
        &["--disable-extensions-except", "/tmp/x"],
        &["--remote-debugging-port=9222"],
        &["--remote-debugging-port", "9222"],
        &["--remote-debugging-pipe"],
        &["--remote-debugging-address=127.0.0.1"],
        &["-remote-debugging-io-pipes=3,4"],
        &["--remote-debugging"],
        // After `--`, Chromium reads no switch; the guard still refuses.
        &["--", "--load-extension=/tmp/x"],
        &["https://example.com", "--remote-debugging-port=0"],
    ] {
        let text = parse_verdict(guard, &browser_args(extra));
        assert!(text.starts_with("refused: --"), "{extra:?}: {text}");
    }
    // The environment is not read as arguments.
    let env_only = procargs(
        1,
        HELIUM_PATH,
        &[HELIUM_PATH.as_bytes()],
        &["X=--load-extension=/tmp/x"],
    );
    assert_eq!(parse_verdict(guard, &env_only), "allowed\n");
}

#[test]
fn the_guard_refuses_malformed_and_oversized_arguments() {
    let Some(guard) = selftest_guard() else {
        return;
    };
    let refused = |buffer: &[u8], what: &str| {
        let text = parse_verdict(guard, buffer);
        assert!(text.starts_with("refused"), "{what}: {text}");
    };
    let path = HELIUM_PATH;
    let one: &[&[u8]] = &[path.as_bytes()];
    refused(b"", "empty");
    refused(&[1, 0, 0], "shorter than argc");
    refused(&1i32.to_ne_bytes(), "argc only");
    refused(&procargs(0, path, one, &[]), "argc 0");
    refused(&procargs(-1, path, one, &[]), "negative argc");
    refused(&procargs(257, path, one, &[]), "too many arguments");
    refused(&procargs(1, "", one, &[]), "empty executable path");
    // More arguments than the buffer holds.
    refused(&procargs(3, path, one, &[]), "missing arguments");
    // The last argument has no terminator.
    let mut cut = procargs(1, path, one, &[]);
    cut.pop();
    refused(&cut, "unterminated argument");
    let mut no_path_end = 1i32.to_ne_bytes().to_vec();
    no_path_end.extend_from_slice(path.as_bytes());
    refused(&no_path_end, "unterminated executable path");
    refused(
        &procargs(
            2,
            path,
            &[path.as_bytes(), b"\xff\xfe--load-extension"],
            &[],
        ),
        "invalid UTF-8",
    );
    // 256 arguments pass; the 64 KiB argument area is a hard limit.
    let many: Vec<&[u8]> = vec![b"x".as_slice(); 256];
    assert_eq!(
        parse_verdict(guard, &procargs(256, path, &many, &[])),
        "allowed\n"
    );
    // The area after argc: the path, 4 padding zeros, the argument, its terminator.
    let fits = "a".repeat(64 * 1024 - path.len() - 4 - 1);
    let edge = procargs(1, path, &[fits.as_bytes()], &[]);
    assert_eq!(edge.len(), 4 + 64 * 1024);
    assert_eq!(parse_verdict(guard, &edge), "allowed\n");
    let over = "a".repeat(fits.len() + 1);
    refused(
        &procargs(1, path, &[over.as_bytes()], &[]),
        "argument area over 64 KiB",
    );
    // An unsafe switch hidden after the limit is never read: refused as too long.
    let mut hidden: Vec<&[u8]> = vec![path.as_bytes(), over.as_bytes()];
    hidden.push(b"--load-extension=/tmp/x");
    refused(&procargs(3, path, &hidden, &[]), "switch after the limit");
    // More input than the largest kernel buffer.
    refused(&vec![b'a'; (4 << 20) + 1], "longer than kern.argmax");
    // An empty argv[0] shifts the parse by one string; the switch is still found.
    let shifted = procargs(2, path, &[b"", b"--load-extension=/tmp/x"], &["A=b"]);
    assert!(parse_verdict(guard, &shifted).starts_with("refused"));
}

/// A process that waits on its standard input, with these arguments. It reads no
/// file and opens no window.
fn waiting_process(args: &[&str]) -> std::process::Child {
    Command::new("/bin/sh")
        .args(["-c", "read line", "sh"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn process_verdict(guard: &Path, mode: &str, pid: u32) -> String {
    let output = Command::new(guard)
        .arg(mode)
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .unwrap();
    String::from_utf8(output.stdout).unwrap()
}

/// The guard reads the arguments of a real process from the kernel, not from `ps`.
#[test]
fn the_guard_reads_real_process_arguments_from_the_kernel() {
    let Some(guard) = selftest_guard() else {
        return;
    };
    let cases: [(&[&str], bool); 6] = [
        (&["https://example.com"], true),
        (&["--user-data-dir=/tmp/x"], true),
        (&["--load-extension=/tmp/x"], false),
        (&["--load-extension", "/tmp/x"], false),
        (&["--remote-debugging-pipe"], false),
        (&["--DISABLE-EXTENSIONS-EXCEPT", "/tmp/x"], false),
    ];
    for (args, ok) in cases {
        let mut child = waiting_process(args);
        // /bin/sh may exec the real shell; the arguments stay the same.
        thread::sleep(Duration::from_millis(200));
        let text = process_verdict(guard, "selftest-process", child.id());
        let _ = child.kill();
        let _ = child.wait();
        if ok {
            assert_eq!(text, "allowed\n", "{args:?}");
        } else {
            assert!(
                text.starts_with("refused: the browser runs with --"),
                "{args:?}: {text}"
            );
        }
    }
    // A process that is gone, launchd (no task port for this user), and a bad ID.
    let mut child = waiting_process(&[]);
    let gone = child.id();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(process_verdict(guard, "selftest-process", gone).starts_with("refused"));
    assert!(process_verdict(guard, "selftest-process", 1).starts_with("refused"));
    let output = Command::new(guard)
        .args(["selftest-process", "not-a-pid"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "refused: no process\n"
    );
    // A signed process that is not a known browser fails before its arguments.
    let mut child = waiting_process(&[]);
    thread::sleep(Duration::from_millis(200));
    let text = process_verdict(guard, "selftest-browser", child.id());
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(text, "refused: the browser is not a known signed browser\n");
}

fn app_verdict(guard: &Path, path: &Path) -> String {
    let output = Command::new(guard)
        .arg("selftest-app")
        .arg(path)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(
        output.status.success(),
        output.stdout == b"allowed\n",
        "{output:?}"
    );
    String::from_utf8(output.stdout).unwrap()
}

/// The allow-list is exact: two signing identifiers, each with its own team, a
/// Developer ID chain for each, and no wildcard.
#[test]
fn the_known_browsers_are_exact_identifiers_and_teams() {
    let Some(guard) = selftest_guard() else {
        return;
    };
    let output = Command::new(guard)
        .args(["selftest-known", "-"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 5, "{text}");
    assert_eq!(lines[4], "allowed");
    let chain = " and certificate 1[field.1.2.840.113635.100.6.2.6] exists \
                 and certificate leaf[field.1.2.840.113635.100.6.1.13] exists";
    for (index, (identifier, team)) in [
        ("net.imput.helium", "S4Q33XPHB4"),
        ("com.google.Chrome", "EQHXZ8M8AV"),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(lines[index * 2], format!("known {identifier} {team}"));
        assert_eq!(
            lines[index * 2 + 1],
            format!(
                "requirement anchor apple generic and identifier \"{identifier}\"{chain} \
                 and certificate leaf[subject.OU] = \"{team}\""
            )
        );
    }
    // No wildcard, prefix, or alternative in any requirement.
    for line in lines.iter().filter(|line| line.starts_with("requirement ")) {
        for bad in ["*", " or ", "beta", "canary", "dev\"", "~"] {
            assert!(!line.contains(bad), "{bad}: {line}");
        }
    }
}

/// Synthetic code with the identifier of a known browser but no Developer ID chain,
/// a bare executable, and Apple's own apps are not known browsers. The real signed
/// Helium is, and so is Chrome when it is installed (nothing launches).
#[test]
fn the_browser_allow_list_refuses_lookalikes_and_bare_executables() {
    let Some(guard) = selftest_guard() else {
        return;
    };
    let dir = TempDir::new("lookalike");
    let refused = "refused: the code is not a known signed browser\n";
    for identifier in [
        "com.google.Chrome",
        "com.google.Chrome.beta",
        "com.google.Chrome.dev",
        "com.google.Chrome.canary",
        "com.google.Chrome.helper",
        "net.imput.helium",
        "org.chromium.Chromium",
    ] {
        let copy = dir.path().join(identifier);
        std::fs::copy("/usr/bin/true", &copy).unwrap();
        let signed = Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--identifier", identifier])
            .arg(&copy)
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(signed.success(), "{identifier}");
        assert_eq!(app_verdict(guard, &copy), refused, "ad hoc {identifier}");
    }
    // A bare, unsigned executable named like Chrome, and a missing path.
    let bare = dir.path().join("Google Chrome");
    std::fs::copy("/usr/bin/true", &bare).unwrap();
    let _ = Command::new("/usr/bin/codesign")
        .args(["--remove-signature"])
        .arg(&bare)
        .stderr(Stdio::null())
        .status();
    assert!(app_verdict(guard, &bare).starts_with("refused"));
    assert!(app_verdict(guard, &dir.path().join("missing")).starts_with("refused"));
    // Apple's own signed apps and tools are not known browsers.
    for path in [
        "/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app",
        "/System/Applications/Calculator.app",
        "/bin/ls",
    ] {
        if Path::new(path).exists() {
            assert_eq!(app_verdict(guard, Path::new(path)), refused, "{path}");
        }
    }
    // Official builds, when present.
    for path in [
        "/Applications/Helium.app",
        "/Applications/Google Chrome.app",
    ] {
        if Path::new(path).exists() {
            assert_eq!(app_verdict(guard, Path::new(path)), "allowed\n", "{path}");
        }
    }
}

/// The release guard has no self-test mode: it answers nothing on standard output.
#[test]
fn the_release_guard_has_no_self_test_mode() {
    let Some(guard) = guard_binary() else { return };
    let mut child = waiting_process(&[]);
    for mode in [
        "selftest-parse",
        "selftest-process",
        "selftest-browser",
        "selftest-known",
        "selftest-app",
    ] {
        let output = Command::new(guard)
            .args([mode, &child.id().to_string()])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .unwrap();
        assert_ne!(output.status.code(), Some(0), "{mode}");
        assert!(output.stdout.is_empty(), "{mode}");
    }
    let _ = child.kill();
    let _ = child.wait();
    let bytes = std::fs::read(guard).unwrap();
    assert!(!bytes.windows(9).any(|window| window == b"selftest-"));
}

/// Opt-in: the real signed Helium, headless, with a new profile in a temporary folder
/// and a mock keychain, so no window opens and no real profile or keychain changes.
/// Run with `cargo test --test browser_passkeys -- --ignored real_helium`.
#[test]
#[ignore = "starts the real Helium headless"]
fn the_guard_checks_real_helium_arguments() {
    let Some(guard) = selftest_guard() else {
        return;
    };
    if !Path::new(HELIUM_PATH).exists() {
        eprintln!("skip: no Helium");
        return;
    }
    let dir = TempDir::new("helium");
    let run = |name: &str, extra: &[String]| {
        let mut child = Command::new(HELIUM_PATH)
            .args([
                "--headless=new",
                "--use-mock-keychain",
                "--no-first-run",
                "--no-default-browser-check",
            ])
            .arg(format!(
                "--user-data-dir={}",
                dir.path().join(name).display()
            ))
            .args(extra)
            .arg("about:blank")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        thread::sleep(Duration::from_secs(2));
        let alive = child.try_wait().unwrap().is_none();
        let text = process_verdict(guard, "selftest-browser", child.id());
        let _ = Command::new("/bin/kill")
            .arg(child.id().to_string())
            .status();
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
        let _ = child.wait();
        assert!(alive, "Helium exited before the check ({name})");
        text
    };
    assert_eq!(run("clean", &[]), "allowed\n");
    let none = dir.path().join("none").display().to_string();
    assert_eq!(
        run("load", &[format!("--load-extension={none}")]),
        "refused: the browser runs with --load-extension\n"
    );
    assert_eq!(
        run("except", &[format!("--disable-extensions-except={none}")]),
        "refused: the browser runs with --disable-extensions-except\n"
    );
    assert_eq!(
        run("port", &["--remote-debugging-port=0".to_string()]),
        "refused: the browser runs with --remote-debugging-port\n"
    );
}

// ------------------------------------------------------------------ helpers

fn args() -> Vec<std::ffi::OsString> {
    vec!["apassy-browser-host".into(), EXTENSION_ORIGIN.into()]
}

fn frames(mut bytes: &[u8]) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    while let Some(message) = read_frame(&mut bytes).unwrap() {
        out.push(serde_json::from_slice(&message).unwrap());
    }
    out
}

/// A short temporary directory: a Unix socket path has at most 104 bytes.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = PathBuf::from("/tmp").join(format!("apk-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
