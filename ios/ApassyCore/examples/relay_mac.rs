//! A Mac on a fake relay, for a join from the iPhone app in the Simulator (development
//! only, synthetic values). It starts the in-process fake relay of the Mac's tests on
//! 127.0.0.1, makes a vault with synthetic items, puts it on the relay as a new team,
//! and prints the device link of "Add a device…". It confirms the first device that
//! asks, then syncs every 2 seconds, adds one item 20 seconds after the join, and
//! prints each change that comes from the iPhone.
//!
//!   cargo run -p apassy-core --example relay_mac -- <passphrase>
//!
//! Then launch the Simulator build with `-ApassyJoinLink <link>` and
//! `-ApassyJoinPassphrase <passphrase>`. The Simulator shares the Mac's loopback
//! address, and the app allows plain `http://` for a loopback relay with a port.

#[path = "../../../tests/common/fake_relay.rs"]
mod fake_relay;

/// The fake relay reads the app's sync module under this name.
use apassy::sync as relay_api;

use std::io::Write;
use std::time::{Duration, Instant};

use apassy::contracts::CredentialKind;
use apassy::sync::{RelayConfig, RelaySync};
use apassy::vault::{Field, ItemDraft, SecretValue, Vault};

fn field(name: &str, value: &str, secret: bool) -> Field {
    Field {
        name: name.to_owned(),
        value: SecretValue::new(value.to_owned()),
        secret,
    }
}

fn detail(label: &str) -> String {
    let mut name = String::from("x_");
    for byte in label.as_bytes() {
        name.push_str(&format!("{byte:02x}"));
    }
    name
}

fn draft(title: &str, kind: CredentialKind, notes: &str, fields: Vec<Field>) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind,
        notes: notes.to_owned(),
        tags: Vec::new(),
        fields,
    }
}

fn titles(vault: &Vault) -> Vec<String> {
    let mut titles: Vec<String> = vault
        .search("")
        .unwrap()
        .into_iter()
        .map(|s| s.title)
        .collect();
    titles.sort();
    titles
}

fn main() {
    let passphrase = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "synthetic-sim-pass".to_owned());
    let root = tempfile::TempDir::new().expect("temp dir");
    let relay = fake_relay::FakeRelay::start();
    let path = root.path().join("vault.db");
    let mac = RelaySync::new(RelayConfig::in_data_dir(
        root.path(),
        &path,
        &relay.url,
        "vault",
    ));
    let mut vault = Vault::create(&path, &passphrase).expect("create");
    vault.unlock(&passphrase).expect("unlock");
    let items = [
        draft(
            "GitHub",
            CredentialKind::Login,
            "Synthetic account for the Simulator.",
            vec![
                field("username", "octocat", false),
                field("password", "synthetic-Pw-7Hq2!kLm9x", true),
                field(&detail("Website"), "https://github.com", false),
                field(
                    &detail("One-time password"),
                    "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP",
                    true,
                ),
            ],
        ),
        draft(
            "Stripe",
            CredentialKind::ApiKey,
            "",
            vec![
                field("service", "stripe", false),
                field("token", "sk_synthetic_4eC39HqLyjWDarjtT1zdp7dc", true),
            ],
        ),
        draft(
            "Production Postgres",
            CredentialKind::Database,
            "",
            vec![
                field("host", "db.example.internal", false),
                field("database", "shop", false),
                field("username", "app", false),
                field("password", "short1", true),
            ],
        ),
        draft(
            "Netflix",
            CredentialKind::Login,
            "",
            vec![
                field("username", "family@example.com", false),
                field("password", "short1", true),
                field(&detail("Website"), "netflix.com", false),
            ],
        ),
    ];
    for item in items {
        vault.add(item).expect("add");
    }
    mac.create_team(
        &mut vault,
        "Personal",
        &relay.team_code(),
        "Synthetic MacBook",
    )
    .expect("team");
    let code = mac.create_link(&vault).expect("link");
    println!("relay {}", relay.url);
    println!("link {}", code.link.as_str());
    std::io::stdout().flush().ok();

    let start = Instant::now();
    let mut joined_at: Option<Instant> = None;
    let mut added = false;
    let mut last = titles(&vault);
    while start.elapsed() < Duration::from_secs(30 * 60) {
        std::thread::sleep(Duration::from_secs(2));
        if joined_at.is_none() {
            let links = mac.pending_links(&vault, Some(&code)).unwrap_or_default();
            if let Some(link) = links.first() {
                println!(
                    "confirm {} words {}",
                    link.device_name,
                    link.safety.as_deref().unwrap_or("-")
                );
                mac.confirm_link(&vault, link).expect("confirm");
                joined_at = Some(Instant::now());
            }
            continue;
        }
        if !added && joined_at.is_some_and(|at| at.elapsed() > Duration::from_secs(20)) {
            vault
                .add(draft(
                    "Added on the Mac",
                    CredentialKind::ApiKey,
                    "",
                    vec![field("token", "synthetic-from-mac", true)],
                ))
                .expect("add");
            added = true;
            println!("added an item on the Mac");
        }
        match mac.sync(&mut vault) {
            Ok(outcome) => {
                let now = titles(&vault);
                if now != last {
                    println!("merged: {now:?} (pushed {})", outcome.pushed);
                    last = now;
                } else if outcome.pushed {
                    println!("pushed version {}", relay.version());
                }
            }
            Err(error) => println!("sync: {error}"),
        }
        std::io::stdout().flush().ok();
    }
}
