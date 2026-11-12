//! SPEC24 vault sync: the signed head, compare-and-swap pushes, snapshot downloads,
//! the long poll, receipts, delete, limits, separation between teams, and backups.

#[path = "common/relay.rs"]
mod relay;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

use apassy_relay::config::UpstreamOptions;
use apassy_relay::device::{self, DeviceKey};
use apassy_relay::hostkeys::{decode_b64, encode_b64};
use apassy_relay::ids::TeamId;
use apassy_relay::server::directory::TeamLimitsUpdate;
use apassy_relay::server::operator::Command;
use apassy_relay::sync_head::{head_hash, hex};
use relay::{EDGE_SECRET, TestRelay, start, team_of};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const VAULT: &str = "0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77";
const OTHER_VAULT: &str = "11111111-2222-4333-8444-555555555555";
const ZEROS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// The device key of the test vectors of `docs/contracts/relay-sync-v1.md` (core).
const VECTOR_PRIVATE: &str = "4f2d9c6e1b3a7d8f0c5e2a9b7f4d1c3e6a8b0d2f4c6e8a1b3d5f7a9c0e2b4d6f";
const VECTOR_PUBLIC_B64: &str =
    "BOpHkB5VvTHXawpUXZxgu44Q97I2bzq9G_uI6tFM9mj8De047e1fNWI8MIERDsaxhBC0ih1DPfXaM4mdBbExjrA";
/// The team id of the contract's test vectors.
const VECTOR_TEAM: &str = "t_7k2m5q4x3c";

/// One device of a team: its access token, its key, and its id.
struct Mac {
    token: String,
    key: DeviceKey,
    id: u64,
}

/// An HTTP answer with its headers.
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn code(&self) -> String {
        self.json()["error"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    fn result(&self) -> Value {
        assert_eq!(self.status, 200, "{}", String::from_utf8_lossy(&self.body));
        self.json()["result"].clone()
    }
}

fn send(
    base: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    headers: &[(&str, String)],
    body: Vec<u8>,
) -> Answer {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into();
    let mut builder = ureq::http::Request::builder()
        .method(method)
        .uri(format!("{base}{path}"))
        .header("X-Apassy-Edge", EDGE_SECRET);
    if let Some(token) = token {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    for (name, value) in headers {
        builder = builder.header(*name, value.as_str());
    }
    let mut response = agent
        .run(builder.body(body).expect("request"))
        .expect("http call");
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let body = response
        .body_mut()
        .with_config()
        .limit(u64::MAX)
        .read_to_vec()
        .unwrap_or_default();
    Answer {
        status,
        headers,
        body,
    }
}

/// A head text in the grammar of section 24.3.
fn head_text(
    team: &str,
    device: u64,
    vault: &str,
    version: u64,
    body: &[u8],
    previous: &str,
) -> String {
    format!(
        "apassy-relay-sync-head-v1\n{vault} {version} {} {}\n{previous} {team}/{device} 1790000000",
        hex(&Sha256::digest(body)),
        body.len()
    )
}

/// The headers of a push of `text` signed by `key`.
fn push_headers(if_match: u64, text: &str, key: &DeviceKey) -> Vec<(&'static str, String)> {
    vec![
        ("If-Match", format!("\"{if_match}\"")),
        ("Content-Type", "application/octet-stream".to_string()),
        ("X-Apassy-Sync-Head", encode_b64(text.as_bytes())),
        (
            "X-Apassy-Sync-Signature",
            encode_b64(&key.sign(text.as_bytes()).unwrap()),
        ),
    ]
}

fn put(base: &str, mac: &Mac, headers: Vec<(&'static str, String)>, body: &[u8]) -> Answer {
    send(
        base,
        "PUT",
        "/v1/sync/snapshot",
        Some(&mac.token),
        &headers,
        body.to_vec(),
    )
}

/// The device ids and the head hash that the chain needs, for the pushes of one team.
struct Pusher {
    team: TeamId,
    version: u64,
    previous: String,
}

impl Pusher {
    fn new(team: &TeamId) -> Self {
        Self {
            team: team.clone(),
            version: 0,
            previous: ZEROS.to_string(),
        }
    }

    /// The next head of `mac` for `body`.
    fn next(&self, mac: &Mac, body: &[u8]) -> String {
        head_text(
            self.team.as_str(),
            mac.id,
            VAULT,
            self.version + 1,
            body,
            &self.previous,
        )
    }

    /// Pushes the next version and expects 200.
    fn push(&mut self, relay: &TestRelay, mac: &Mac, body: &[u8]) -> Value {
        let text = self.next(mac, body);
        let answer = put(
            &relay.url,
            mac,
            push_headers(self.version, &text, &mac.key),
            body,
        );
        let result = answer.result();
        self.version += 1;
        self.previous = hex(&head_hash(text.as_bytes()));
        assert_eq!(result["version"], self.version);
        assert_eq!(
            answer.header("ETag"),
            Some(format!("\"{}\"", self.version).as_str())
        );
        result
    }
}

fn get(relay: &TestRelay, mac: &Mac, path: &str) -> Answer {
    send(&relay.url, "GET", path, Some(&mac.token), &[], Vec::new())
}

fn sync_files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// A new team through a team code: the owner's Mac is device 1.
fn personal_team(relay: &mut TestRelay) -> Mac {
    let (token, key) = relay.new_team_device("Personal", "owner");
    relay.switch_team(&token);
    Mac { token, key, id: 1 }
}

/// Adds a Mac of the same member through a confirmed device link.
fn add_mac(relay: &TestRelay, first: &Mac, key: DeviceKey) -> Mac {
    let team = team_of(&first.token);
    let made = relay.ok("POST", "/v1/devices/links", &first.token, None);
    let code = made["secret"].as_str().unwrap().to_string();
    let pending = relay.ok(
        "POST",
        "/v1/devices/link",
        "",
        Some(&json!({"code": code, "device_name": "Mac mini", "public_key": key.public_key_b64()})),
    );
    let links = relay.ok("GET", "/v1/devices/links", &first.token, None);
    assert_eq!(links[0]["public_key"], key.public_key_b64());
    let words = device::safety_words(&team, &code, &key.public_key());
    assert_eq!(pending["safety"], words);
    let added = relay.ok(
        "POST",
        &format!("/v1/devices/links/{}/confirm", pending["id"]),
        &first.token,
        Some(&json!({"safety": words})),
    );
    assert_eq!(added["public_key"], key.public_key_b64());
    let token = relay.sign_in(&team, &key);
    Mac {
        token,
        key,
        id: added["id"].as_u64().unwrap(),
    }
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// The vector device key, as a PKCS#8 document in ring's P-256 form.
fn vector_key() -> DeviceKey {
    let template = DeviceKey::generate().unwrap();
    let doc = template.pkcs8();
    assert_eq!(doc.len(), 138);
    assert_eq!(&doc[73..], template.public_key().as_slice());
    assert_eq!(&doc[68..73], &[0xa1, 0x44, 0x03, 0x42, 0x00]);
    let mut pkcs8 = doc[..36].to_vec();
    pkcs8.extend(unhex(VECTOR_PRIVATE));
    pkcs8.extend_from_slice(&doc[68..73]);
    pkcs8.extend(decode_b64(VECTOR_PUBLIC_B64, 65).unwrap());
    let key = DeviceKey::from_pkcs8(&pkcs8).unwrap();
    assert_eq!(key.public_key_b64(), VECTOR_PUBLIC_B64);
    key
}

/// A raw push for bodies that do not match their `Content-Length`: the request head and
/// the first bytes. The caller sends the rest or closes.
fn raw_push(
    relay: &TestRelay,
    mac: &Mac,
    headers: &[(&'static str, String)],
    content_length: u64,
    first: &[u8],
) -> TcpStream {
    let address = relay.url.strip_prefix("http://").unwrap();
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut text = format!(
        "PUT /v1/sync/snapshot HTTP/1.1\r\nHost: {address}\r\nX-Apassy-Edge: {EDGE_SECRET}\r\n\
         Authorization: Bearer {}\r\nContent-Length: {content_length}\r\nConnection: close\r\n",
        mac.token
    );
    for (name, value) in headers {
        text.push_str(&format!("{name}: {value}\r\n"));
    }
    text.push_str("\r\n");
    stream.write_all(text.as_bytes()).unwrap();
    stream.write_all(first).unwrap();
    stream.flush().unwrap();
    stream
}

/// Reads the answer of a raw request: the status, the headers, and the JSON body.
fn read_answer(stream: TcpStream) -> (u16, Vec<(String, String)>, Value) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let status: u16 = line.split(' ').nth(1).unwrap().parse().unwrap();
    let mut headers = Vec::new();
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').unwrap();
        if name.eq_ignore_ascii_case("Content-Length") {
            length = value.trim().parse().unwrap();
        }
        headers.push((name.to_string(), value.trim().to_string()));
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).unwrap();
    (status, headers, serde_json::from_slice(&body).unwrap())
}

#[test]
fn the_vector_heads_chain_on_a_team_with_the_vector_ids() {
    let mut relay = start(UpstreamOptions::default());
    let owner = personal_team(&mut relay);
    let vector = add_mac(&relay, &owner, vector_key());
    assert_eq!(vector.id, 2);
    // Rename the team to the vector team id while the relay is stopped.
    let old = team_of(&owner.token);
    relay.edit_offline(|config| {
        let conn = directory_connection_at(config);
        conn.execute(
            "UPDATE team SET id = ?1 WHERE id = ?2",
            [VECTOR_TEAM, old.as_str()],
        )
        .unwrap();
        let team = TeamId::parse(VECTOR_TEAM).unwrap();
        std::fs::rename(config.team_path(&old), config.team_path(&team)).unwrap();
    });
    let team = TeamId::parse(VECTOR_TEAM).unwrap();
    relay.team_id = team.clone();
    let owner = Mac {
        token: relay.sign_in(&team, &owner.key),
        ..owner
    };
    let vector = Mac {
        token: relay.sign_in(&team, &vector.key),
        ..vector
    };
    relay.owner_token = owner.token.clone();
    let one: &[u8] = b"synthetic snapshot";
    let two: &[u8] = b"synthetic snapshot 2";
    let head1 = head_text(VECTOR_TEAM, 2, VAULT, 1, one, ZEROS);
    let hash1 = hex(&head_hash(head1.as_bytes()));
    let head2 = head_text(VECTOR_TEAM, 2, VAULT, 2, two, &hash1);
    assert_eq!(
        head1,
        "apassy-relay-sync-head-v1\n0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77 1 5b77343bd881a4f425bde1ec9979946ec1add11de02010d4c63159977bac4de8 18\n0000000000000000000000000000000000000000000000000000000000000000 t_7k2m5q4x3c/2 1790000000"
    );
    // Head 2 on an empty team: the version check comes before the previous check.
    let answer = put(
        &relay.url,
        &vector,
        push_headers(0, &head2, &vector.key),
        two,
    );
    assert_eq!(
        (answer.status, answer.code()),
        (403, "sync_head_invalid".into())
    );
    assert!(
        answer.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("version")
    );
    // Head 2 signed by another live device but naming device 2.
    let answer = put(&relay.url, &owner, push_headers(0, &head1, &owner.key), one);
    assert_eq!(
        (answer.status, answer.code()),
        (403, "sync_head_invalid".into())
    );
    assert!(
        answer.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("device")
    );
    // Head 1 on an empty team.
    let answer = put(
        &relay.url,
        &vector,
        push_headers(0, &head1, &vector.key),
        one,
    );
    let result = answer.result();
    assert_eq!(result["version"], 1);
    assert_eq!(result["head"], encode_b64(head1.as_bytes()));
    assert_eq!(result["device_id"], 2);
    assert_eq!(result["device_name"], "Mac mini");
    assert_eq!(result["chain"], json!([]));
    // Head 1 after head 1.
    let answer = put(
        &relay.url,
        &vector,
        push_headers(1, &head1, &vector.key),
        one,
    );
    assert_eq!(
        (answer.status, answer.code()),
        (403, "sync_head_invalid".into())
    );
    assert!(
        answer.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("version")
    );
    // Head 2 with a changed size, and with a body of another hash.
    let resized = head2.replace(" 20\n", " 21\n");
    let answer = put(
        &relay.url,
        &vector,
        push_headers(1, &resized, &vector.key),
        b"synthetic snapshot 2.",
    );
    assert_eq!(
        (answer.status, answer.code()),
        (403, "sync_head_invalid".into())
    );
    assert!(
        answer.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("hash")
    );
    let answer = put(
        &relay.url,
        &vector,
        push_headers(1, &head2, &vector.key),
        b"synthetic snapshot 3",
    );
    assert_eq!(
        (answer.status, answer.code()),
        (403, "sync_head_invalid".into())
    );
    assert!(
        answer.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("hash")
    );
    // Head 2 after head 1.
    let answer = put(
        &relay.url,
        &vector,
        push_headers(1, &head2, &vector.key),
        two,
    );
    assert_eq!(answer.result()["version"], 2);
    let since0 = get(&relay, &vector, "/v1/sync/head?since=0").result();
    assert_eq!(since0["chain_from"], 1);
    assert_eq!(since0["kept_from"], 1);
    let chain = since0["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0]["head"], encode_b64(head1.as_bytes()));
    assert_eq!(chain[1]["head"], encode_b64(head2.as_bytes()));
    for entry in chain {
        let text = decode_b64(entry["head"].as_str().unwrap(), 512).unwrap();
        let signature = decode_b64(entry["signature"].as_str().unwrap(), 72).unwrap();
        assert!(device::verify(&vector.key.public_key(), &text, &signature));
    }
    let since1 = get(&relay, &vector, "/v1/sync/head?since=1").result();
    assert_eq!(since1["chain"].as_array().unwrap().len(), 1);
    assert_eq!(since1["chain_from"], 2);
    for (version, body) in [(1, one), (2, two)] {
        let answer = get(
            &relay,
            &owner,
            &format!("/v1/sync/snapshot?version={version}"),
        );
        assert_eq!(answer.status, 200);
        assert_eq!(answer.body, body);
        assert_eq!(
            answer.header("Content-Type"),
            Some("application/octet-stream")
        );
        assert_eq!(
            answer.header("Content-Length"),
            Some(body.len().to_string().as_str())
        );
        assert_eq!(
            answer.header("ETag"),
            Some(format!("\"{version}\"").as_str())
        );
        assert_eq!(answer.header("Cache-Control"), Some("no-store"));
        let head = if version == 1 { &head1 } else { &head2 };
        assert_eq!(
            answer.header("X-Apassy-Sync-Head"),
            Some(encode_b64(head.as_bytes()).as_str())
        );
        assert!(answer.header("X-Apassy-Sync-Signature").is_some());
    }
    let dir = relay.config.sync_dir(&team);
    assert_eq!(sync_files(&dir), ["1.bin", "2.bin"]);
    let rows = relay.vault_rows("SELECT version, device_id FROM sync_head ORDER BY version");
    assert_eq!(
        rows,
        [
            (b"1".to_vec(), b"2".to_vec()),
            (b"2".to_vec(), b"2".to_vec())
        ]
    );
    let audit = relay.ok("GET", "/v1/audit?limit=500", &owner.token, None);
    let pushed: Vec<&Value> = audit
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["action"] == "sync_pushed")
        .collect();
    assert_eq!(pushed.len(), 2);
    assert_eq!(
        pushed[1]["detail"],
        json!({"version": 2, "device_id": 2, "size": 20})
    );
    let fetched = audit
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["action"] == "sync_fetched")
        .count();
    assert_eq!(fetched, 2);
    // A second download of the same version writes no second row.
    get(&relay, &owner, "/v1/sync/snapshot?version=2");
    let audit = relay.ok("GET", "/v1/audit?limit=500", &owner.token, None);
    assert_eq!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["action"] == "sync_fetched")
            .count(),
        2
    );
    // No audit row holds a head, a signature, or a snapshot byte.
    let text = audit.to_string();
    assert!(!text.contains("synthetic snapshot"));
    assert!(!text.contains(&encode_b64(head1.as_bytes())));
    assert!(!text.contains(&hash1));
}

/// Opens `relay.db` with the master key of the tests.
fn directory_connection_at(config: &apassy_relay::config::RelayConfig) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(config.directory_path()).unwrap();
    conn.execute_batch(&format!("PRAGMA key = '{}';", relay::VAULT_KEY))
        .unwrap();
    conn
}

#[test]
fn malformed_pushes_are_400_before_the_token() {
    let mut relay = start(UpstreamOptions::default());
    let member_token = relay.owner_token.clone();
    let mac = personal_team(&mut relay);
    let team = team_of(&mac.token);
    let body = b"snapshot";
    let text = head_text(team.as_str(), 1, VAULT, 1, body, ZEROS);
    let good = push_headers(0, &text, &mac.key);
    let without = |name: &str| -> Vec<(&'static str, String)> {
        good.iter()
            .filter(|(key, _)| *key != name)
            .cloned()
            .collect()
    };
    let with = |name: &'static str, value: &str| -> Vec<(&'static str, String)> {
        let mut headers = without(name);
        headers.push((name, value.to_string()));
        headers
    };
    let nobody = Mac {
        token: "apassy_acc_t_abcdefgh23_00".into(),
        key: DeviceKey::generate().unwrap(),
        id: 1,
    };
    for headers in [
        without("If-Match"),
        with("If-Match", "0"),
        with("If-Match", "\"x\""),
        without("X-Apassy-Sync-Head"),
        without("X-Apassy-Sync-Signature"),
        with("X-Apassy-Sync-Head", "%%%"),
        with(
            "X-Apassy-Sync-Head",
            &format!("{}=", encode_b64(text.as_bytes())),
        ),
        with(
            "X-Apassy-Sync-Head",
            &encode_b64(format!("{text}\n").as_bytes()),
        ),
        with(
            "X-Apassy-Sync-Head",
            &encode_b64(text.replace(" 1 ", " 01 ").as_bytes()),
        ),
        with("X-Apassy-Sync-Signature", &"A".repeat(97)),
        // The grammar allows at most 64 MiB, as the app does.
        with(
            "X-Apassy-Sync-Head",
            &encode_b64(text.replace(" 8\n", " 67108865\n").as_bytes()),
        ),
    ] {
        for mac in [&mac, &nobody] {
            let answer = put(&relay.url, mac, headers.clone(), body);
            assert_eq!(
                (answer.status, answer.code()),
                (400, "invalid_request".into()),
                "{headers:?}"
            );
        }
    }
    // Transfer-Encoding is refused, and so is a missing Content-Length.
    let stream = raw_push(
        &relay,
        &mac,
        &[
            good.clone(),
            vec![("Transfer-Encoding", "chunked".to_string())],
        ]
        .concat(),
        8,
        b"",
    );
    assert_eq!(read_answer(stream).0, 400);
    // Nothing was stored.
    assert_eq!(get(&relay, &mac, "/v1/sync/head").result()["version"], 0);
    assert!(sync_files(&relay.config.sync_dir(&team)).is_empty());
    // A good push still works, and a member token gets 401.
    let answer = put(&relay.url, &mac, good.clone(), body);
    assert_eq!(answer.status, 200);
    // The member token of a team without devices.
    let member = Mac {
        token: member_token,
        key: DeviceKey::generate().unwrap(),
        id: 1,
    };
    assert_eq!(put(&relay.url, &member, good, body).status, 401);
}

#[test]
fn pushes_are_compare_and_swap() {
    let mut relay = start(UpstreamOptions::default());
    let first = personal_team(&mut relay);
    let second = add_mac(&relay, &first, DeviceKey::generate().unwrap());
    let team = team_of(&first.token);
    let mut pusher = Pusher::new(&team);
    pusher.push(&relay, &first, b"version one");
    // A stale If-Match: 412 with the current version.
    let text = head_text(team.as_str(), second.id, VAULT, 1, b"stale", ZEROS);
    let answer = put(
        &relay.url,
        &second,
        push_headers(0, &text, &second.key),
        b"stale",
    );
    assert_eq!(
        (answer.status, answer.code()),
        (412, "precondition_failed".into())
    );
    assert_eq!(answer.header("ETag"), Some("\"1\""));
    // A bad signature: another key signs a head that names this device.
    let text = pusher.next(&second, b"two");
    let stranger = DeviceKey::generate().unwrap();
    let answer = put(
        &relay.url,
        &second,
        push_headers(1, &text, &stranger),
        b"two",
    );
    assert_eq!(
        (answer.status, answer.code()),
        (403, "sync_head_invalid".into())
    );
    assert!(
        answer.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("signature")
    );
    // A head from a device the team does not have, and from another team.
    for (team_text, device) in [(team.as_str(), 99), ("t_abcdefgh23", second.id)] {
        let text = head_text(team_text, device, VAULT, 2, b"two", &pusher.previous);
        let answer = put(
            &relay.url,
            &second,
            push_headers(1, &text, &second.key),
            b"two",
        );
        assert_eq!(
            (answer.status, answer.code()),
            (403, "sync_head_invalid".into())
        );
        assert!(
            answer.json()["error"]["message"]
                .as_str()
                .unwrap()
                .contains("device")
        );
    }
    // A broken chain: the previous hash is not the current head's.
    let text = head_text(team.as_str(), second.id, VAULT, 2, b"two", &"ab".repeat(32));
    let answer = put(
        &relay.url,
        &second,
        push_headers(1, &text, &second.key),
        b"two",
    );
    assert!(
        answer.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("previous")
    );
    // Another vault on top of this one.
    let text = head_text(
        team.as_str(),
        second.id,
        OTHER_VAULT,
        2,
        b"two",
        &pusher.previous,
    );
    let answer = put(
        &relay.url,
        &second,
        push_headers(1, &text, &second.key),
        b"two",
    );
    assert!(
        answer.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("vault id")
    );
    // A size that is not the Content-Length.
    let text = pusher.next(&second, b"two").replace(" 3\n", " 4\n");
    let answer = put(
        &relay.url,
        &second,
        push_headers(1, &text, &second.key),
        b"two",
    );
    assert!(
        answer.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("size")
    );
    assert_eq!(get(&relay, &first, "/v1/sync/head").result()["version"], 1);
    // Two pushes at one version, both past the first checks: one commits, one is 412.
    // Bodies over 1 KiB: tiny_http reads a smaller body before the handler runs.
    let a_body = vec![b'a'; 2000];
    let b_body = vec![b'b'; 2000];
    let a_text = pusher.next(&first, &a_body);
    let b_text = pusher.next(&second, &b_body);
    let mut a = raw_push(
        &relay,
        &first,
        &push_headers(1, &a_text, &first.key),
        2000,
        &a_body[..1000],
    );
    let mut b = raw_push(
        &relay,
        &second,
        &push_headers(1, &b_text, &second.key),
        2000,
        &b_body[..1000],
    );
    std::thread::sleep(Duration::from_millis(500));
    a.write_all(&a_body[1000..]).unwrap();
    let (status, _, value) = read_answer(a);
    assert_eq!(status, 200, "{value}");
    b.write_all(&b_body[1000..]).unwrap();
    let (status, headers, value) = read_answer(b);
    assert_eq!(status, 412, "{value}");
    assert!(
        headers
            .iter()
            .any(|(name, v)| name.eq_ignore_ascii_case("ETag") && v == "\"2\"")
    );
    pusher.version = 2;
    pusher.previous = hex(&head_hash(a_text.as_bytes()));
    let since1 = get(&relay, &first, "/v1/sync/head?since=1").result();
    assert_eq!(since1["chain"].as_array().unwrap().len(), 1);
    assert_eq!(since1["device_id"], first.id);
    // The same race from two threads: one 200, one 412.
    let url = relay.url.clone();
    let texts = [
        pusher.next(&first, b"thread one"),
        pusher.next(&second, b"thread two"),
    ];
    let handles: Vec<_> = [
        (first, texts[0].clone(), b"thread one"),
        (second, texts[1].clone(), b"thread two"),
    ]
    .into_iter()
    .map(|(mac, text, body)| {
        let url = url.clone();
        std::thread::spawn(move || {
            let status = put(&url, &mac, push_headers(2, &text, &mac.key), body).status;
            (status, mac)
        })
    })
    .collect();
    let results: Vec<(u16, Mac)> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let mut statuses: Vec<u16> = results.iter().map(|(status, _)| *status).collect();
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 412]);
    let first = &results[0].1;
    let since2 = get(&relay, first, "/v1/sync/head?since=2").result();
    assert_eq!(since2["version"], 3);
    assert_eq!(since2["chain"].as_array().unwrap().len(), 1);
    // The current and the previous snapshot only, and no temporary file.
    assert_eq!(
        sync_files(&relay.config.sync_dir(&team)),
        ["2.bin", "3.bin"]
    );
    assert_eq!(
        get(&relay, first, "/v1/sync/snapshot?version=1").status,
        404
    );
    assert_eq!(
        get(&relay, first, "/v1/sync/snapshot?version=2").body,
        a_body
    );
    assert_eq!(
        get(&relay, first, "/v1/sync/snapshot?version=4").status,
        404
    );
    assert_eq!(get(&relay, first, "/v1/sync/snapshot").status, 400);
    let refused = relay
        .ok("GET", "/v1/audit?limit=500", &relay.owner_token, None)
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["action"] == "sync_refused")
        .count();
    assert!(refused >= 1);
}

#[test]
fn bodies_must_match_content_length_and_the_limit() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let team = team_of(&mac.token);
    let dir = relay.config.sync_dir(&team);
    // 64 MiB and one byte: 413 before the body, and no file. (A head with that size is
    // outside the grammar, 400; the length is checked before the head's size.)
    let big = 67_108_865u64;
    let text = format!(
        "apassy-relay-sync-head-v1\n{VAULT} 1 {} {}\n{ZEROS} {team}/1 1790000000",
        "ab".repeat(32),
        big - 1
    );
    let stream = raw_push(&relay, &mac, &push_headers(0, &text, &mac.key), big, b"");
    let (status, _, value) = read_answer(stream);
    assert_eq!(
        (status, value["error"]["code"].as_str()),
        (413, Some("payload_too_large"))
    );
    assert!(sync_files(&dir).is_empty());
    // A caller without a valid token gets the same 413, before the token: a length
    // that no push can have.
    let nobody = Mac {
        token: "apassy_acc_t_abcdefgh23_00".into(),
        key: DeviceKey::generate().unwrap(),
        id: 1,
    };
    let stream = raw_push(&relay, &nobody, &push_headers(0, &text, &mac.key), big, b"");
    let (status, _, value) = read_answer(stream);
    assert_eq!(
        (status, value["error"]["code"].as_str()),
        (413, Some("payload_too_large"))
    );
    // A body shorter than its Content-Length: 400, and the temporary file is gone.
    let body = vec![b'x'; 2000];
    let text = head_text(team.as_str(), 1, VAULT, 1, &body, ZEROS);
    let stream = raw_push(
        &relay,
        &mac,
        &push_headers(0, &text, &mac.key),
        2000,
        &body[..1000],
    );
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let (status, _, value) = read_answer(stream);
    assert_eq!(
        (status, value["error"]["code"].as_str()),
        (400, Some("invalid_request"))
    );
    assert!(sync_files(&dir).iter().all(|name| !name.ends_with(".tmp")));
    assert_eq!(get(&relay, &mac, "/v1/sync/head").result()["version"], 0);
    // The same head with the whole body.
    assert_eq!(
        put(&relay.url, &mac, push_headers(0, &text, &mac.key), &body).status,
        200
    );
    assert_eq!(sync_files(&dir), ["1.bin"]);
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(dir.join("1.bin")).unwrap().permissions(),
    );
    assert_eq!(mode & 0o777, 0o600);
    let mode =
        std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&dir).unwrap().permissions());
    assert_eq!(mode & 0o777, 0o700);
}

#[test]
fn the_long_poll_wakes_on_a_push_and_on_a_delete() {
    let mut relay = start(UpstreamOptions::default());
    let first = personal_team(&mut relay);
    let second = add_mac(&relay, &first, DeviceKey::generate().unwrap());
    let team = team_of(&first.token);
    let mut pusher = Pusher::new(&team);
    pusher.push(&relay, &first, b"one");
    let poll = |token: String, url: String, since: u64| {
        std::thread::spawn(move || {
            let started = Instant::now();
            let path = format!("/v1/sync/head?since={since}&wait=25");
            let answer = send(&url, "GET", &path, Some(&token), &[], Vec::new());
            (started.elapsed(), answer.result())
        })
    };
    let waiting = poll(second.token.clone(), relay.url.clone(), 1);
    std::thread::sleep(Duration::from_millis(700));
    // A second poll of the same device is answered at once.
    let started = Instant::now();
    let again = get(&relay, &second, "/v1/sync/head?since=1&wait=25").result();
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(again["version"], 1);
    pusher.push(&relay, &first, b"two");
    let (elapsed, view) = waiting.join().unwrap();
    assert!(elapsed >= Duration::from_millis(600), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    assert_eq!(view["version"], 2);
    assert_eq!(view["chain"].as_array().unwrap().len(), 1);
    // A delete wakes it too.
    let waiting = poll(second.token.clone(), relay.url.clone(), 2);
    std::thread::sleep(Duration::from_millis(700));
    let deleted = send(
        &relay.url,
        "DELETE",
        "/v1/sync",
        Some(&first.token),
        &[("If-Match", "\"2\"".to_string())],
        Vec::new(),
    );
    assert_eq!(deleted.result(), json!({"last_version": 2}));
    let (elapsed, view) = waiting.join().unwrap();
    assert!(elapsed >= Duration::from_millis(600), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    assert_eq!(view, json!({"version": 0, "chain": [], "receipts": []}));
    // `wait` over 25 is refused.
    assert_eq!(
        get(&relay, &second, "/v1/sync/head?since=0&wait=26").status,
        400
    );
}

#[test]
fn delete_is_for_an_owner_device_with_the_current_version() {
    let mut relay = start(UpstreamOptions::default());
    let owner = personal_team(&mut relay);
    let team = team_of(&owner.token);
    let (_, member_token, member_key) = relay.join_device("member", "alice");
    let member = Mac {
        token: member_token,
        key: member_key,
        id: 2,
    };
    let mut pusher = Pusher::new(&team);
    pusher.push(&relay, &owner, b"one");
    // No role limits a push in this stage.
    pusher.push(&relay, &member, b"two");
    let delete = |mac: &Mac, if_match: Option<&str>| {
        let headers: Vec<(&str, String)> = if_match
            .map(|value| vec![("If-Match", value.to_string())])
            .unwrap_or_default();
        send(
            &relay.url,
            "DELETE",
            "/v1/sync",
            Some(&mac.token),
            &headers,
            Vec::new(),
        )
    };
    assert_eq!(delete(&member, Some("\"2\"")).code(), "forbidden");
    assert_eq!(delete(&owner, None).status, 400);
    let stale = delete(&owner, Some("\"1\""));
    assert_eq!((stale.status, stale.header("ETag")), (412, Some("\"2\"")));
    assert_eq!(
        delete(&owner, Some("\"2\"")).result(),
        json!({"last_version": 2})
    );
    assert!(sync_files(&relay.config.sync_dir(&team)).is_empty());
    assert!(
        relay
            .vault_rows("SELECT version, size FROM sync_head")
            .is_empty()
    );
    assert_eq!(
        delete(&owner, Some("\"0\"")).result(),
        json!({"last_version": 0})
    );
    // The next push is version 1 with zeros as the previous hash.
    let mut pusher = Pusher::new(&team);
    pusher.push(&relay, &member, b"again");
    let audit = relay.ok("GET", "/v1/audit?limit=500", &owner.token, None);
    let deleted: Vec<&Value> = audit
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["action"] == "sync_deleted")
        .collect();
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0]["detail"]["last_version"], 2);
}

#[test]
fn receipts_show_in_the_head() {
    let mut relay = start(UpstreamOptions::default());
    let first = personal_team(&mut relay);
    let second = add_mac(&relay, &first, DeviceKey::generate().unwrap());
    let team = team_of(&first.token);
    let mut pusher = Pusher::new(&team);
    let result = pusher.push(&relay, &first, b"one");
    assert_eq!(result["receipts"], json!([]));
    relay.fails(
        "POST",
        "/v1/sync/receipt",
        Some(&second.token),
        Some(&json!({"version": 2})),
        409,
        "conflict",
    );
    relay.fails(
        "POST",
        "/v1/sync/receipt",
        Some(&second.token),
        Some(&json!({"version": 1, "extra": 1})),
        400,
        "invalid_request",
    );
    let receipt = relay.ok(
        "POST",
        "/v1/sync/receipt",
        &second.token,
        Some(&json!({"version": 1})),
    );
    assert_eq!(receipt["version"], 1);
    let view = get(&relay, &first, "/v1/sync/head?since=1").result();
    let receipts = view["receipts"].as_array().unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["device_id"], second.id);
    assert_eq!(receipts[0]["device_name"], "Mac mini");
    assert_eq!(receipts[0]["version"], 1);
    // A revoked device's receipt is not shown, and its token is 401.
    relay.ok(
        "DELETE",
        &format!("/v1/devices/{}", second.id),
        &first.token,
        None,
    );
    let view = get(&relay, &first, "/v1/sync/head").result();
    assert_eq!(view["receipts"], json!([]));
    assert_eq!(get(&relay, &second, "/v1/sync/head").status, 401);
    let text = pusher.next(&second, b"two");
    assert_eq!(
        put(
            &relay.url,
            &second,
            push_headers(1, &text, &second.key),
            b"two"
        )
        .status,
        401
    );
}

#[test]
fn a_team_sees_nothing_of_another_team() {
    let mut relay = start(UpstreamOptions::default());
    let a = personal_team(&mut relay);
    let b = personal_team(&mut relay);
    let team_a = team_of(&a.token);
    let team_b = team_of(&b.token);
    let mut pusher = Pusher::new(&team_b);
    pusher.push(&relay, &b, b"team b snapshot");
    let files_b = sync_files(&relay.config.sync_dir(&team_b));
    // Team A's token reads team A: no snapshot.
    assert_eq!(
        get(&relay, &a, "/v1/sync/head?since=0").result()["version"],
        0
    );
    assert_eq!(get(&relay, &a, "/v1/sync/snapshot?version=1").status, 404);
    // A's token with B's team id in it is 401 on every sync endpoint.
    let forged = Mac {
        token: a.token.replace(team_a.as_str(), team_b.as_str()),
        key: DeviceKey::generate().unwrap(),
        id: 1,
    };
    let text = pusher.next(&forged, b"x");
    assert_eq!(get(&relay, &forged, "/v1/sync/head").status, 401);
    assert_eq!(
        get(&relay, &forged, "/v1/sync/snapshot?version=1").status,
        401
    );
    assert_eq!(
        put(&relay.url, &forged, push_headers(1, &text, &a.key), b"x").status,
        401
    );
    let deleted = send(
        &relay.url,
        "DELETE",
        "/v1/sync",
        Some(&forged.token),
        &[("If-Match", "\"1\"".into())],
        Vec::new(),
    );
    assert_eq!(deleted.status, 401);
    let receipt = send(
        &relay.url,
        "POST",
        "/v1/sync/receipt",
        Some(&forged.token),
        &[("Content-Type", "application/json".into())],
        b"{\"version\":1}".to_vec(),
    );
    assert_eq!(receipt.status, 401);
    // A's own push of a head naming team B is refused, and B is untouched.
    let text = head_text(team_b.as_str(), 1, VAULT, 1, b"x", ZEROS);
    let answer = put(&relay.url, &a, push_headers(0, &text, &a.key), b"x");
    assert_eq!(answer.code(), "sync_head_invalid");
    assert_eq!(sync_files(&relay.config.sync_dir(&team_b)), files_b);
    assert_eq!(
        get(&relay, &b, "/v1/sync/snapshot?version=1").body,
        b"team b snapshot"
    );
    assert!(sync_files(&relay.config.sync_dir(&team_a)).is_empty());
}

#[test]
fn sync_limits_and_the_operator() {
    let mut relay = start(UpstreamOptions::default());
    let first = personal_team(&mut relay);
    let second = add_mac(&relay, &first, DeviceKey::generate().unwrap());
    let team = team_of(&first.token);
    let set = |update: Value| {
        relay
            .operator(Command::Limits {
                team: team.clone(),
                set: Some(serde_json::from_value::<TeamLimitsUpdate>(update).unwrap()),
            })
            .unwrap()
    };
    let limits = set(json!({"sync_pushes_per_hour": 2, "sync_transfers": 1}));
    assert_eq!(limits["sync_pushes_per_hour"], 2);
    assert_eq!(limits["sync_transfers"], 1);
    assert_eq!(limits["sync_bytes"], 67_108_864);
    for bad in [
        json!({"sync_bytes": 1_048_575}),
        json!({"sync_bytes": 67_108_865u64}),
        json!({"sync_transfers": 0}),
        json!({"sync_transfers": 9}),
        json!({"sync_pushes_per_hour": 0}),
    ] {
        assert!(
            relay
                .operator(Command::Limits {
                    team: team.clone(),
                    set: Some(serde_json::from_value::<TeamLimitsUpdate>(bad.clone()).unwrap()),
                })
                .is_err(),
            "{bad}"
        );
    }
    let mut pusher = Pusher::new(&team);
    pusher.push(&relay, &first, b"one");
    // One transfer at once: a push that waits for its body holds the slot.
    let body = vec![b'2'; 4096];
    let text = pusher.next(&second, &body);
    let mut held = raw_push(
        &relay,
        &second,
        &push_headers(1, &text, &second.key),
        4096,
        &body[..100],
    );
    std::thread::sleep(Duration::from_millis(500));
    let busy = get(&relay, &first, "/v1/sync/snapshot?version=1");
    assert_eq!((busy.status, busy.code()), (503, "busy".into()));
    assert_eq!(busy.header("Retry-After"), Some("2"));
    held.write_all(&body[100..]).unwrap();
    assert_eq!(read_answer(held).0, 200);
    pusher.version = 2;
    pusher.previous = hex(&head_hash(text.as_bytes()));
    assert_eq!(
        get(&relay, &first, "/v1/sync/snapshot?version=1").status,
        200
    );
    // Two pushes in the hour: the third is 403 team_limit with one limit row.
    let text = pusher.next(&first, b"three");
    for _ in 0..2 {
        let answer = put(
            &relay.url,
            &first,
            push_headers(2, &text, &first.key),
            b"three",
        );
        assert_eq!((answer.status, answer.code()), (403, "team_limit".into()));
    }
    let rows: Vec<Value> = relay
        .ok("GET", "/v1/audit?limit=500", &first.token, None)
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["action"] == "limit_reached")
        .cloned()
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["detail"], json!({"limit": "sync_pushes_per_hour"}));
    // A smaller sync_bytes refuses a larger push with 413.
    set(json!({"sync_pushes_per_hour": 600, "sync_bytes": 1_048_576}));
    let big = vec![7u8; 1_048_577];
    let text = pusher.next(&first, &big);
    let answer = put(&relay.url, &first, push_headers(2, &text, &first.key), &big);
    assert_eq!(
        (answer.status, answer.code()),
        (413, "payload_too_large".into())
    );
    // `teams` shows the sync version and size.
    let teams = relay.operator(Command::Teams).unwrap();
    let info = teams
        .as_array()
        .unwrap()
        .iter()
        .find(|info| info["id"] == team.as_str())
        .unwrap()
        .clone();
    assert_eq!(info["sync_version"], 2);
    assert_eq!(info["sync_size"], body.len());
}

#[test]
fn backups_hold_the_snapshots_and_a_deleted_team_loses_them() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let team = team_of(&mac.token);
    let mut pusher = Pusher::new(&team);
    pusher.push(&relay, &mac, b"first");
    pusher.push(&relay, &mac, b"second");
    let manifest = relay.operator(Command::Backup).unwrap();
    let names: Vec<&str> = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| file["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&format!("teams/{team}.sync/1.bin").as_str()),
        "{names:?}"
    );
    assert!(
        names.contains(&format!("teams/{team}.sync/2.bin").as_str()),
        "{names:?}"
    );
    let dir = Path::new(manifest["dir"].as_str().unwrap());
    assert_eq!(
        std::fs::read(dir.join(format!("teams/{team}.sync/2.bin"))).unwrap(),
        b"second"
    );
    let file = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|file| file["name"] == format!("teams/{team}.sync/2.bin"))
        .unwrap();
    assert_eq!(file["sha256"], hex(&Sha256::digest(b"second")));
    assert_eq!(file["bytes"], 6);
    // The operator deletes the team: its snapshots go with its file.
    relay
        .operator(Command::Suspend { team: team.clone() })
        .unwrap();
    relay
        .operator(Command::Delete {
            team: team.clone(),
            free_connect_key: false,
        })
        .unwrap();
    assert!(!relay.config.sync_dir(&team).exists());
    assert!(!relay.config.team_path(&team).exists());
}

/// A removed device stays a signer of the heads it pushed while it was a member: the
/// head answer lists its key with the newest version it pushed, so the other Macs can
/// still check the chain. It cannot push again, and the others push on top of its head.
#[test]
fn a_removed_device_signs_its_old_heads_only() {
    let mut relay = start(UpstreamOptions::default());
    let first = personal_team(&mut relay);
    let second = add_mac(&relay, &first, DeviceKey::generate().unwrap());
    let team = team_of(&first.token);
    let mut pusher = Pusher::new(&team);
    pusher.push(&relay, &first, b"one");
    pusher.push(&relay, &second, b"two");
    relay.ok(
        "DELETE",
        &format!("/v1/devices/{}", second.id),
        &first.token,
        None,
    );
    let view = get(&relay, &first, "/v1/sync/head?since=0").result();
    assert_eq!(view["device_id"], second.id);
    let signers = view["signers"].as_array().unwrap();
    assert_eq!(signers.len(), 2);
    assert_eq!(signers[0]["device_id"], first.id);
    assert_eq!(signers[0]["public_key"], first.key.public_key_b64());
    assert!(signers[0].get("removed").is_none());
    assert!(signers[0].get("last_version").is_none());
    assert_eq!(signers[1]["device_id"], second.id);
    assert_eq!(signers[1]["public_key"], second.key.public_key_b64());
    assert_eq!(signers[1]["removed"], true);
    assert_eq!(signers[1]["last_version"], 2);
    // The removed device cannot push.
    let text = pusher.next(&second, b"three");
    assert_eq!(
        put(
            &relay.url,
            &second,
            push_headers(2, &text, &second.key),
            b"three"
        )
        .status,
        401
    );
    // The remaining device pushes on top of the removed device's head.
    let result = pusher.push(&relay, &first, b"three");
    assert_eq!(result["version"], 3);
    // A page after the removed device's heads does not name it.
    let view = get(&relay, &first, "/v1/sync/head?since=2").result();
    let signers = view["signers"].as_array().unwrap();
    assert_eq!(signers.len(), 1);
    assert_eq!(signers[0]["device_id"], first.id);
}

/// A device removed after the push passed its last check of the caller (while it
/// waited for the commit of another push) still gets no head: the commit checks the
/// device again in its own transaction, which a removal also needs.
#[test]
fn a_device_removed_before_the_commit_gets_no_head() {
    use apassy_relay::error::{RelayError, codes};
    use apassy_relay::server::auth::{Principal, authenticate_core};
    use apassy_relay::server::sync::{self, PushRequest};

    let mut relay = start(UpstreamOptions::default());
    let first = personal_team(&mut relay);
    let second = add_mac(&relay, &first, DeviceKey::generate().unwrap());
    let team = team_of(&first.token);
    let hub = relay.hub();
    let core = hub.for_token(&second.token).expect("core");
    let now = apassy_relay::now_unix();
    let Principal::Member(by) = authenticate_core(&core, &second.token, now).expect("auth") else {
        panic!("a member");
    };
    let body = b"one".to_vec();
    let text = Pusher::new(&team).next(&second, &body);
    let mut headers = push_headers(0, &text, &second.key);
    headers.push(("Content-Length", body.len().to_string()));
    let request = PushRequest::from_headers(|name| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    })
    .expect("headers");
    // The removal comes right after the last check of the caller.
    let reauth = || {
        core.store.with(|conn| {
            conn.execute(
                "UPDATE device SET revoked_at = ?1 WHERE id = ?2",
                rusqlite::params![now as i64, second.id as i64],
            )
            .map_err(|_| RelayError::internal("revoke"))
        })?;
        Ok(by.clone())
    };
    let refused = sync::push(&core, &by, &request, &mut body.as_slice(), &reauth, now)
        .expect_err("a removed device gets no head");
    assert_eq!(refused.error.code, codes::UNAUTHENTICATED);
    let view = get(&relay, &first, "/v1/sync/head?since=0").result();
    assert_eq!(view["version"], 0, "nothing stored");
    assert_eq!(
        sync_files(&relay.config.sync_dir(&team)),
        Vec::<String>::new(),
        "no snapshot file stays"
    );
}

/// The new Mac takes back its pending link with the code and its key: the first Mac no
/// longer sees it, and the key is refused at sign-in. A confirmed link cannot be taken
/// back (409); a wrong key cannot cancel (403).
#[test]
fn a_new_device_cancels_its_pending_link() {
    let mut relay = start(UpstreamOptions::default());
    let first = personal_team(&mut relay);
    let team = team_of(&first.token);
    let link = |key: &DeviceKey| -> (String, Value) {
        let made = relay.ok("POST", "/v1/devices/links", &first.token, None);
        let code = made["secret"].as_str().unwrap().to_string();
        let pending = relay.ok(
            "POST",
            "/v1/devices/link",
            "",
            Some(&json!({"code": code, "device_name": "Mac mini", "public_key": key.public_key_b64()})),
        );
        (code, pending)
    };
    let key = DeviceKey::generate().unwrap();
    let (code, pending) = link(&key);
    let stranger = DeviceKey::generate().unwrap();
    relay.fails(
        "POST",
        "/v1/devices/link/cancel",
        None,
        Some(&json!({"code": code, "public_key": stranger.public_key_b64()})),
        403,
        "forbidden",
    );
    relay.fails(
        "POST",
        "/v1/devices/link/cancel",
        Some(&first.token),
        Some(&json!({"code": code, "public_key": key.public_key_b64()})),
        401,
        "unauthenticated",
    );
    let cancel = json!({"code": code, "public_key": key.public_key_b64()});
    let done = relay.ok("POST", "/v1/devices/link/cancel", "", Some(&cancel));
    assert_eq!(done["id"], pending["id"]);
    // A retry answers the same.
    relay.ok("POST", "/v1/devices/link/cancel", "", Some(&cancel));
    assert_eq!(
        relay.ok("GET", "/v1/devices/links", &first.token, None),
        json!([])
    );
    let (status, value) = relay.call(
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": team.as_str(), "public_key": key.public_key_b64()})),
    );
    assert_eq!(
        (status, value["error"]["code"].as_str()),
        (403, Some("join_refused"))
    );
    let rows = relay.ok("GET", "/v1/audit?limit=500", &first.token, None);
    assert!(
        rows.as_array()
            .unwrap()
            .iter()
            .any(|row| row["action"] == "device_link_cancelled")
    );
    // After a confirmation the link cannot be taken back.
    let other = DeviceKey::generate().unwrap();
    let (code, pending) = link(&other);
    let words = device::safety_words(&team, &code, &other.public_key());
    relay.ok(
        "POST",
        &format!("/v1/devices/links/{}/confirm", pending["id"]),
        &first.token,
        Some(&json!({"safety": words})),
    );
    relay.fails(
        "POST",
        "/v1/devices/link/cancel",
        None,
        Some(&json!({"code": code, "public_key": other.public_key_b64()})),
        409,
        "conflict",
    );
}

#[test]
fn backups_racing_delete_push_or_team_creation_restore_complete_sets() {
    use apassy_relay::server::sync;
    use std::sync::mpsc;
    for action in ["delete", "push", "create"] {
        let mut relay = start(UpstreamOptions::default());
        let mac = personal_team(&mut relay);
        let team = team_of(&mac.token);
        let mut pusher = Pusher::new(&team);
        pusher.push(&relay, &mac, &vec![42; 1024 * 1024]);
        let hub = relay.hub();
        let core = hub.team(&team).unwrap();
        // Force the backup to stop after directory capture and before the team copy.
        let commit = core.sync_commit.lock().unwrap();
        let at = apassy_relay::now_unix();
        let stamp = apassy_relay::cli::commands::fmt_time(at)
            .replace(' ', "T")
            .replace(':', "-");
        let captured = relay
            .config
            .backup_dir
            .join(format!(".{stamp}.partial/relay.db"));
        let backup = std::thread::scope(|scope| {
            let work = scope.spawn(|| hub.backup(at));
            let until = Instant::now() + Duration::from_secs(5);
            while !captured.exists() {
                assert!(Instant::now() < until, "backup did not capture directory");
                std::thread::sleep(Duration::from_millis(10));
            }
            let (done, completed) = mpsc::channel();
            let relay = &relay;
            let mutation = scope.spawn(move || {
                match action {
                    "delete" => {
                        send(
                            &relay.url,
                            "DELETE",
                            "/v1/sync",
                            Some(&mac.token),
                            &[("If-Match", "\"1\"".into())],
                            Vec::new(),
                        )
                        .result();
                    }
                    "push" => {
                        pusher.push(relay, &mac, b"second");
                    }
                    "create" => {
                        relay.new_team_device("concurrent", "owner");
                    }
                    _ => unreachable!(),
                }
                done.send(()).unwrap();
            });
            assert!(
                completed.recv_timeout(Duration::from_millis(100)).is_err(),
                "mutation finished while backup holds its consistency locks"
            );
            drop(commit);
            let result = work.join().unwrap();
            mutation.join().unwrap();
            result
        })
        .unwrap();
        let mut restored = relay.config.clone();
        restored.data_dir = Path::new(backup["dir"].as_str().unwrap()).to_path_buf();
        assert_eq!(
            sync::verify_restored(&restored).unwrap(),
            backup["teams"].as_u64().unwrap() as usize
        );
    }
}

#[test]
fn snapshot_validation_includes_suspended_teams_and_rejects_missing_or_corrupt_files() {
    use apassy_relay::server::sync;
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let team = team_of(&mac.token);
    let mut pusher = Pusher::new(&team);
    pusher.push(&relay, &mac, b"old chain metadata");
    pusher.push(&relay, &mac, b"previous snapshot");
    pusher.push(&relay, &mac, b"recoverable");
    assert!(!relay.config.sync_dir(&team).join("1.bin").exists());
    relay
        .operator(Command::Suspend { team: team.clone() })
        .unwrap();
    let manifest = relay.operator(Command::Backup).unwrap();
    let mut restored = relay.config.clone();
    restored.data_dir = Path::new(manifest["dir"].as_str().unwrap()).to_path_buf();
    assert_eq!(
        sync::verify_restored(&restored).unwrap(),
        manifest["teams"].as_u64().unwrap() as usize
    );
    let file = restored.sync_dir(&team).join("3.bin");
    std::fs::write(&file, b"unrecoverab").unwrap();
    assert!(sync::verify_restored(&restored).is_err());
    std::fs::remove_file(&file).unwrap();
    assert!(sync::verify_restored(&restored).is_err());
    // Even with no open core, a failed verification cannot publish a manifest.
    let failed_time = apassy_relay::now_unix() + 10;
    std::fs::remove_file(relay.config.sync_dir(&team).join("3.bin")).unwrap();
    assert!(relay.hub().backup(failed_time).is_err());
}
