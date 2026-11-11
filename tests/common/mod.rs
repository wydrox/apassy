//! Test helpers shared by integration tests.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

/// The fake relay names the sync module of the app `relay_api` in its parent module.
#[cfg(feature = "vault")]
use apassy::sync as relay_api;

#[cfg(feature = "vault")]
pub mod fake_connect;
#[cfg(feature = "vault")]
pub mod fake_relay;

/// The fake relay keeps the vault stores of the fake Connect (plan s7 unit M3).
#[cfg(feature = "vault")]
impl fake_connect::StoreRelay for fake_relay::FakeRelay {
    fn url(&self) -> String {
        self.url.clone()
    }
    fn set_origin(&self, origin: &str) {
        fake_relay::FakeRelay::set_origin(self, origin);
    }
    fn add_store_team(&self, name: &str, device_name: &str, public_key: &[u8]) -> (String, u64) {
        fake_relay::FakeRelay::add_store_team(self, name, device_name, public_key)
    }
    fn add_store_device(&self, team_id: &str, device_name: &str, public_key: &[u8]) -> u64 {
        fake_relay::FakeRelay::add_store_device(self, team_id, device_name, public_key)
    }
    fn remove_team(&self, team_id: &str) {
        fake_relay::FakeRelay::remove_team(self, team_id);
    }
    fn set_team_sync_bytes(&self, team_id: &str, bytes: u64) {
        fake_relay::FakeRelay::set_team_sync_bytes(self, team_id, bytes);
    }
    fn set_store_guard(&self, guard: fake_connect::StoreGuard) {
        fake_relay::FakeRelay::set_store_guard(self, guard);
    }
}

/// A fake Jev-compatible bouncer (contract v2). By default it answers a clean,
/// matching, read-only command: `task_match` 0.95 and every other fact 0.02.
/// `overrides` sets other probabilities. It keeps each request body.
pub struct FakeBouncer {
    pub url: String,
    pub bodies: Arc<Mutex<Vec<String>>>,
}

pub fn fake_bouncer(overrides: &'static [(&'static str, f64)]) -> FakeBouncer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake bouncer");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&bodies);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; length];
            if reader.read_exact(&mut body).is_err() {
                continue;
            }
            let request: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            seen.lock()
                .expect("bodies")
                .push(String::from_utf8_lossy(&body).into_owned());
            let mut answers = serde_json::Map::new();
            if let Some(questions) = request["questions"].as_object() {
                for name in questions.keys() {
                    let default = if name == "task_match" { 0.95 } else { 0.02 };
                    let p = overrides
                        .iter()
                        .find(|(n, _)| n == name)
                        .map_or(default, |(_, p)| *p);
                    answers.insert(name.clone(), serde_json::json!({"type": "noul", "noul": p}));
                }
            }
            let out = serde_json::json!({"answers": answers, "usage": {"input_tokens": 1, "output_tokens": 0}}).to_string();
            let mut stream = stream;
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{out}",
                out.len()
            );
        }
    });
    FakeBouncer { url, bodies }
}

/// `PRAGMA key` on a raw SQLCipher connection to a vault file of a test, with the KDF
/// that the vault uses for that file (`apassy::vault::test_kdf`).
#[cfg(feature = "vault")]
pub fn key_raw(conn: &rusqlite::Connection, passphrase: &str) -> rusqlite::Result<()> {
    conn.pragma_update(None, "key", passphrase)?;
    #[cfg(feature = "insecure-test-kdf")]
    apassy::vault::test_kdf::match_vault_kdf(conn)?;
    Ok(())
}

/// Make `item` of the unlocked `vault` a source of `kind` with `settings` after the owner
/// check of exactly those settings (`OwnerAction::ChangeShortLivedSettings`, A-L2), with
/// the passphrase `pass` as the owner check. The vault goes through an owner gate and
/// comes back with the row.
#[cfg(feature = "vault")]
pub fn make_source(
    vault: apassy::vault::Vault,
    pass: &str,
    item: u64,
    kind: apassy::vault::ShortLivedKind,
    settings: &str,
    now: u64,
) -> (apassy::vault::Vault, apassy::vault::ShortLived) {
    use apassy::broker::approvals::{OwnerAction, OwnerCheck, OwnerGate};
    let action = OwnerAction::ChangeShortLivedSettings {
        item,
        kind,
        settings_sha256: apassy::vault::ShortLivedSettings::parse(kind, settings)
            .expect("settings")
            .digest(),
    };
    let shared: apassy::broker::SharedVault = Arc::new(Mutex::new(Some(vault)));
    let gate = OwnerGate::new(Arc::clone(&shared), None);
    let proof = gate
        .authorize(action, OwnerCheck::passphrase(pass))
        .expect("owner check");
    drop(gate);
    let mut vault = shared.lock().unwrap().take().expect("vault");
    let row = vault
        .set_short_lived(item, kind, settings, proof, now)
        .expect("source");
    (vault, row)
}
