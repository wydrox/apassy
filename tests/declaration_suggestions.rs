#![cfg(feature = "vault")]

//! Suggested declarations and their measurement (goal item B4). Synthetic values only.
//!
//! - Every file in `packs/providers/` is embedded and loads.
//! - The synthetic evaluation: each credential of
//!   `tests/fixtures/declarations/synthetic.jsonl` goes into a vault. The vault suggests
//!   a declaration. A careful owner saves the declaration of the fixture, so the vault
//!   records the outcome of each suggestion. The test compares the counts with
//!   `docs/operations/declarations.md`. Run it with `--nocapture` to see the table.
//! - The outcome record: the first save only, the changed fields, no secret value.
//!
//! The fixture values are templates. The test expands them, so the repository has no
//! text in the form of a real key: `{fake:N}` is `EXAMPLE0` repeated to N characters,
//! `{zero:N}` is N zeros, and `{jwt:ROLE}` is an unsigned Supabase JWT with that role.

use std::path::PathBuf;

use apassy::contracts::CredentialKind;
use apassy::vault::providers;
use apassy::vault::{
    Declaration, DeclarationField, Environment, Field, ItemDraft, Reversibility, RiskLevel, Scope,
    SecretValue, Vault, VaultErrorKind,
};
use serde_json::Value;
use tempfile::TempDir;

const PASS: &str = "synthetic-suggestion-pass";

/// The results in `docs/operations/declarations.md`, section 4.
const EXPECTED_ITEMS: usize = 66;
/// Suggestions that match the owner in all four fields and the provider.
const EXPECTED_ACCEPTED: u32 = 34;
/// Matches for each field: provider, environment, risk, scope, reversibility.
const EXPECTED_FIELD_MATCHES: [usize; 5] = [66, 64, 48, 48, 46];
/// Matches in all four fields, without the provider.
const EXPECTED_FOUR_FIELDS: usize = 34;
/// Matches of the most sensitive defaults alone, as before goal item B4.
const EXPECTED_DEFAULT_ONLY: usize = 17;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn every_provider_file_is_embedded_and_loads() {
    let mut files: Vec<String> = std::fs::read_dir(root().join("packs").join("providers"))
        .expect("providers directory")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    files.sort();
    let mut embedded: Vec<String> = providers::builtin_files()
        .into_iter()
        .map(str::to_owned)
        .collect();
    embedded.sort();
    assert_eq!(
        files, embedded,
        "every file in packs/providers/ must be embedded"
    );
    let catalog = providers::builtin().expect("built-in provider files load");
    for name in &files {
        let text =
            std::fs::read_to_string(root().join("packs/providers").join(name)).expect("file");
        let value: Value = serde_json::from_str(&text).expect("JSON");
        assert_eq!(value["schema_version"], providers::SCHEMA_VERSION, "{name}");
        let id = value["id"].as_str().expect("id");
        assert_eq!(format!("{id}.json"), *name);
        if value["kind"] == "provider" {
            let provider = catalog.find(id).expect("loaded");
            assert_eq!(
                provider.version,
                value["provider_version"].as_u64().expect("version")
            );
        }
    }
    // The providers of the goal item, and the general rules.
    for id in [
        "stripe",
        "supabase",
        "planetscale",
        "neon",
        "postgres",
        "aws",
        "gcp",
        "vercel",
        "netlify",
        "cloudflare",
        "github",
        "openai",
        "anthropic",
        "twilio",
        "sendgrid",
        "sentry",
        "datadog",
    ] {
        assert!(catalog.find(id).is_some(), "{id}");
    }
    assert!(files.contains(&"general.json".to_owned()));
}

// ---- Fixture ----

fn filler(kind: &str, len: usize) -> String {
    match kind {
        "fake" => "EXAMPLE0".repeat(len / 8 + 1)[..len].to_owned(),
        "zero" => "0".repeat(len),
        _ => panic!("unknown template {kind}"),
    }
}

/// Base64 with the URL alphabet and no padding.
fn b64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[(n >> (18 - 6 * i)) as usize & 63]));
        }
    }
    out
}

/// Expand the templates of one fixture value.
fn expand(template: &str) -> String {
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let Some(end) = rest[start..].find('}') else {
            break;
        };
        let inner = &rest[start + 1..start + end];
        let expanded = match inner.split_once(':') {
            Some(("jwt", role)) => format!(
                "{}.{}.unsigned-example",
                b64url(br#"{"alg":"HS256","typ":"JWT"}"#),
                b64url(
                    format!(r#"{{"iss":"supabase","ref":"exampleref","role":"{role}"}}"#)
                        .as_bytes()
                )
            ),
            Some((kind @ ("fake" | "zero"), len)) => filler(kind, len.parse().expect("length")),
            // JSON text in a value, such as a service account key.
            _ => {
                out.push_str(&rest[..=start]);
                rest = &rest[start + 1..];
                continue;
            }
        };
        out.push_str(&rest[..start]);
        out.push_str(&expanded);
        rest = &rest[start + end + 1..];
    }
    out.push_str(rest);
    out
}

struct Case {
    id: String,
    draft: ItemDraft,
    secrets: Vec<String>,
    env: Option<(String, String)>,
    provider: Option<String>,
    owner: Declaration,
}

fn cases() -> Vec<Case> {
    let text = std::fs::read_to_string(root().join("tests/fixtures/declarations/synthetic.jsonl"))
        .expect("fixture");
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let row: Value = serde_json::from_str(line).expect("fixture line");
            let text = |value: &Value| value.as_str().expect("text").to_owned();
            let kind: CredentialKind = serde_json::from_value(row["kind"].clone()).expect("kind");
            let mut secrets = Vec::new();
            let fields = row["fields"]
                .as_array()
                .expect("fields")
                .iter()
                .map(|field| {
                    let value = expand(field[1].as_str().expect("value"));
                    let secret = field[2].as_bool().expect("secret");
                    if secret {
                        secrets.push(value.clone());
                    }
                    Field {
                        name: text(&field[0]),
                        value: SecretValue::new(value),
                        secret,
                    }
                })
                .collect();
            let owner = &row["owner"];
            Case {
                id: text(&row["id"]),
                draft: ItemDraft {
                    title: text(&row["title"]),
                    kind,
                    notes: text(&row["notes"]),
                    tags: row["tags"]
                        .as_array()
                        .expect("tags")
                        .iter()
                        .map(text)
                        .collect(),
                    fields,
                },
                secrets,
                env: row["env"]
                    .as_array()
                    .map(|env| (text(&env[0]), text(&env[1]))),
                provider: owner["provider"].as_str().map(str::to_owned),
                owner: Declaration {
                    project: "synthetic".to_owned(),
                    environment: Environment::parse(owner["environment"].as_str().expect("env"))
                        .expect("environment"),
                    risk: RiskLevel::parse(owner["risk"].as_str().expect("risk")).expect("risk"),
                    scope: Scope::parse(owner["scope"].as_str().expect("scope")).expect("scope"),
                    reversibility: Reversibility::parse(
                        owner["reversibility"].as_str().expect("reversibility"),
                    )
                    .expect("reversibility"),
                },
            }
        })
        .collect()
}

fn unlocked(dir: &TempDir) -> Vault {
    let path = dir.path().join("suggestions.db");
    let mut vault = Vault::create(&path, PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    vault
}

#[test]
fn synthetic_evaluation_matches_the_recorded_numbers() {
    let cases = cases();
    assert_eq!(cases.len(), EXPECTED_ITEMS);
    assert!(
        cases.len() >= 60,
        "the evaluation needs 60 or more credentials"
    );
    let dir = TempDir::new().expect("temp dir");
    let mut vault = unlocked(&dir);
    let mut field_matches = [0usize; 5];
    let mut four_fields = 0;
    let mut default_only = 0;
    let mut conflicts = 0;
    let mut suggested_fields = [0usize; 5];
    let mut lines = Vec::new();
    for case in &cases {
        let item = vault.add(case.draft.clone()).expect("add");
        if let Some((name, field)) = &case.env {
            vault
                .set_env_binding(item.id, name, field)
                .expect("binding");
        }
        let suggestion = vault.suggest_declaration(item.id).expect("suggestion");
        let text = format!("{suggestion:?}");
        for secret in &case.secrets {
            assert!(
                !text.contains(secret.as_str()),
                "{}: a value in the suggestion",
                case.id
            );
        }
        conflicts += usize::from(
            [
                suggestion.environment.as_ref().map(|s| s.conflict),
                suggestion.risk.as_ref().map(|s| s.conflict),
                suggestion.scope.as_ref().map(|s| s.conflict),
                suggestion.reversibility.as_ref().map(|s| s.conflict),
            ]
            .contains(&Some(true)),
        );
        let form = suggestion.prefilled();
        for field in &form.from_signals {
            suggested_fields[DeclarationField::ALL
                .iter()
                .position(|f| f == field)
                .expect("field")] += 1;
        }
        // The careful owner saves the declaration of the fixture.
        let outcome = vault
            .save_declaration(item.id, &case.owner, case.provider.as_deref(), Some(&form))
            .expect("save")
            .expect("the first save records the outcome");
        for (index, field) in DeclarationField::ALL.iter().enumerate() {
            field_matches[index] += usize::from(!outcome.changed.contains(field));
        }
        four_fields += usize::from(
            outcome
                .changed
                .iter()
                .all(|field| *field == DeclarationField::Provider),
        );
        let owner = &case.owner;
        default_only += usize::from(
            owner.environment == Environment::Production
                && owner.risk == RiskLevel::High
                && owner.scope == Scope::Admin
                && owner.reversibility == Reversibility::Irreversible,
        );
        lines.push(format!(
            "{} {:<11} {:<11} {:<6} {:<10} {:<12} changed: {}",
            case.id,
            form.provider.as_deref().unwrap_or("-"),
            form.environment.as_str(),
            form.risk.as_str(),
            form.scope.as_str(),
            form.reversibility.as_str(),
            outcome
                .changed
                .iter()
                .map(|field| field.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ));
        // Free the variable name for a later case.
        vault.clear_env_binding(item.id).expect("clear");
    }
    let stats = vault.suggestion_stats().expect("stats");
    println!("{}", lines.join("\n"));
    println!(
        "items {} | accepted as-is {} | four fields {} | defaults only {} | conflicts {}",
        stats.total, stats.accepted, four_fields, default_only, conflicts
    );
    for (index, field) in DeclarationField::ALL.iter().enumerate() {
        println!(
            "{:<13} match {:>2} of {} | from a signal {:>2}",
            field.as_str(),
            field_matches[index],
            cases.len(),
            suggested_fields[index]
        );
    }
    assert_eq!(stats.total as usize, cases.len());
    assert_eq!(stats.accepted, EXPECTED_ACCEPTED);
    assert_eq!(field_matches, EXPECTED_FIELD_MATCHES);
    assert_eq!(four_fields, EXPECTED_FOUR_FIELDS);
    assert_eq!(default_only, EXPECTED_DEFAULT_ONLY);
    for (index, field) in DeclarationField::ALL.iter().enumerate() {
        let changed = stats
            .changed
            .iter()
            .find(|(f, _)| f == field)
            .map_or(0, |(_, count)| *count as usize);
        assert_eq!(
            changed + field_matches[index],
            cases.len(),
            "{}",
            field.as_str()
        );
    }
}

fn api_item(title: &str, token: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![Field {
            name: "token".to_owned(),
            value: SecretValue::new(token.to_owned()),
            secret: true,
        }],
    }
}

fn declaration(environment: Environment, risk: RiskLevel) -> Declaration {
    Declaration {
        project: "shop".to_owned(),
        environment,
        risk,
        scope: Scope::Admin,
        reversibility: Reversibility::Irreversible,
    }
}

#[test]
fn the_first_save_records_the_outcome_without_a_value() {
    let dir = TempDir::new().expect("temp dir");
    let mut vault = unlocked(&dir);
    let live_value = format!("sk_live_{}", filler("fake", 24));
    let live = vault.add(api_item("Payments", &live_value)).expect("add");
    let form = vault
        .suggest_declaration(live.id)
        .expect("suggest")
        .prefilled();
    assert_eq!(form.provider.as_deref(), Some("stripe"));
    // Accepted as it was.
    let outcome = vault
        .save_declaration(
            live.id,
            &declaration(Environment::Production, RiskLevel::High),
            Some("stripe"),
            Some(&form),
        )
        .expect("save")
        .expect("outcome");
    assert!(outcome.accepted());
    assert_eq!(
        vault
            .declaration_provider(live.id)
            .expect("provider")
            .as_deref(),
        Some("stripe")
    );
    // A later save of a stored declaration is not a new record.
    let again = vault
        .save_declaration(
            live.id,
            &declaration(Environment::Staging, RiskLevel::Low),
            None,
            Some(&form),
        )
        .expect("save again");
    assert!(again.is_none());
    assert_eq!(vault.declaration_provider(live.id).expect("provider"), None);
    assert_eq!(
        vault
            .declaration(live.id)
            .expect("declaration")
            .expect("some")
            .environment,
        Environment::Staging
    );

    // The owner changes the risk and removes the provider.
    let test = vault
        .add(api_item(
            "Payments test",
            &format!("sk_test_{}", filler("fake", 24)),
        ))
        .expect("add");
    let form = vault
        .suggest_declaration(test.id)
        .expect("suggest")
        .prefilled();
    assert_eq!(form.environment, Environment::Staging);
    let outcome = vault
        .save_declaration(
            test.id,
            &Declaration {
                project: "shop".to_owned(),
                environment: Environment::Staging,
                risk: RiskLevel::Medium,
                scope: Scope::Admin,
                reversibility: Reversibility::Reversible,
            },
            None,
            Some(&form),
        )
        .expect("save")
        .expect("outcome");
    assert_eq!(
        outcome.changed,
        vec![DeclarationField::Provider, DeclarationField::Risk]
    );
    let stats = vault.suggestion_stats().expect("stats");
    assert_eq!((stats.total, stats.accepted), (2, 1));
    assert_eq!(stats.share(), Some(0.5));
    assert!(stats.changed.contains(&(DeclarationField::Risk, 1)));
    assert!(stats.changed.contains(&(DeclarationField::Scope, 0)));
    let stored = format!("{:?}", vault.suggestion_outcomes().expect("outcomes"));
    assert!(
        !stored.contains(&live_value),
        "no secret value in the record"
    );

    // An unknown provider is refused. A declaration without a suggestion is no record.
    assert_eq!(
        vault
            .save_declaration(
                test.id,
                &declaration(Environment::Production, RiskLevel::High),
                Some("no-such-provider"),
                None,
            )
            .unwrap_err()
            .kind(),
        VaultErrorKind::InvalidInput
    );
    let plain = vault
        .add(api_item("Plain", "plain-value-0000"))
        .expect("add");
    assert!(
        vault
            .suggest_declaration(plain.id)
            .expect("suggest")
            .is_empty()
    );
    assert!(
        vault
            .save_declaration(
                plain.id,
                &declaration(Environment::Production, RiskLevel::High),
                None,
                None
            )
            .expect("save")
            .is_none()
    );
    assert_eq!(vault.suggestion_stats().expect("stats").total, 2);

    // A deleted item takes its record with it.
    vault.delete(test.id, test.revision).expect("delete");
    let stats = vault.suggestion_stats().expect("stats");
    assert_eq!((stats.total, stats.accepted), (1, 1));
}
