#![cfg(feature = "vault")]

//! Adding the credentials that the paste detection found (ADR 0025 §4): one
//! transaction for the item, the variable, the declaration with its sources and
//! provider, and the folder. Synthetic values only: a public prefix and `EXAMPLE0`
//! filler.

use apassy::contracts::CredentialKind;
use apassy::vault::detect::{Detected, detect};
use apassy::vault::{
    DeclarationSource, EnvDelivery, Environment, ItemEventKind, ItemOrigin, OriginTool, RiskLevel,
    Vault, VaultErrorKind,
};
use tempfile::TempDir;

const PASS: &str = "synthetic-add-detected-pass";

fn fake(prefix: &str, len: usize) -> String {
    format!("{prefix}{}", &"EXAMPLE0".repeat(len / 8 + 1)[..len])
}

fn vault(dir: &TempDir) -> Vault {
    let mut vault = Vault::create(&dir.path().join("add.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    vault
}

fn one(text: &str) -> Detected {
    let mut found = detect(text);
    assert_eq!(found.len(), 1, "one credential in the text");
    found.remove(0)
}

fn event_kinds(vault: &Vault, id: u64) -> Vec<ItemEventKind> {
    let mut kinds: Vec<ItemEventKind> = vault
        .item_events(id, 50)
        .expect("events")
        .into_iter()
        .map(|event| event.kind)
        .collect();
    kinds.sort_by_key(|kind| kind.as_str());
    kinds
}

#[test]
fn a_single_key_is_one_item_with_variable_provider_declaration_and_sources() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let key = fake("sk-ant-api03-", 40);
    let detected = one(&key);
    let summary = vault.add_detected(&detected, None, None).expect("add");
    assert_eq!(summary.title, "Anthropic API key");
    assert_eq!(summary.kind, CredentialKind::ApiKey);
    assert_eq!(summary.revision, 1);
    assert_eq!(vault.reveal(summary.id, "token").unwrap().expose(), key);

    let binding = vault.env_binding(summary.id).unwrap().expect("a variable");
    assert_eq!(binding.env_name, "ANTHROPIC_API_KEY");
    assert_eq!(binding.field, "token");
    assert_eq!(
        binding.delivery,
        EnvDelivery::Placeholder(vec!["api.anthropic.com".to_owned()]),
        "a known provider starts with a placeholder for its hosts (ADR 0011)"
    );

    let declaration = vault.declaration(summary.id).unwrap().expect("declared");
    assert_eq!(declaration.environment, Environment::Production);
    assert_eq!(declaration.risk, RiskLevel::Medium);
    assert_eq!(declaration.environment, detected.environment);
    assert_eq!(declaration.scope, detected.scope);
    assert_eq!(declaration.reversibility, detected.reversibility);
    assert_eq!(
        vault.declaration_provider(summary.id).unwrap().as_deref(),
        Some("anthropic")
    );
    let sources = vault.declaration_sources(summary.id).unwrap();
    assert_eq!(sources.environment, DeclarationSource::Default);
    assert_eq!(sources.risk, DeclarationSource::Signal);
    assert_eq!(vault.item_folder(summary.id).unwrap(), None);
    assert_eq!(
        event_kinds(&vault, summary.id),
        [
            ItemEventKind::Created,
            ItemEventKind::Declaration,
            ItemEventKind::Variable
        ]
    );
}

#[test]
fn a_dotenv_file_with_four_lines_is_four_items() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let github = fake("ghp_", 36);
    let text = format!(
        "GITHUB_TOKEN={github}\n\
         DATABASE_PASSWORD=fake-pass-0000\n\
         DEV_API_TOKEN=plain-dev-0000\n\
         PATH=/opt/fake/bin\n"
    );
    let found = detect(&text);
    assert_eq!(found.len(), 4);
    let added = vault.add_detected_all(&found, None, None).expect("add");
    let titles: Vec<&str> = added.iter().map(|item| item.title.as_str()).collect();
    assert_eq!(
        titles,
        ["GitHub token", "Database Password", "Dev Api Token", "Path"]
    );
    assert_eq!(vault.search("").unwrap().len(), 4);
    let variables: Vec<Option<String>> = added
        .iter()
        .map(|item| {
            vault
                .env_binding(item.id)
                .unwrap()
                .map(|binding| binding.env_name)
        })
        .collect();
    assert_eq!(
        variables,
        [
            Some("GITHUB_TOKEN".to_owned()),
            Some("DATABASE_PASSWORD".to_owned()),
            Some("DEV_API_TOKEN".to_owned()),
            None,
        ],
        "a reserved name gets no stored variable"
    );
    // A value without a provider goes to the process as it is.
    let password = vault.env_binding(added[1].id).unwrap().unwrap();
    assert_eq!(password.field, "database_password");
    assert_eq!(password.delivery, EnvDelivery::Value);
    assert_eq!(
        vault.declaration_sources(added[1].id).unwrap().environment,
        DeclarationSource::Default
    );
    let dev = vault.declaration(added[2].id).unwrap().unwrap();
    assert_eq!(dev.environment, Environment::Development);
    assert_eq!(
        vault.declaration_sources(added[2].id).unwrap().environment,
        DeclarationSource::Signal
    );
    // Without a stored name, the one secret field is delivered automatically.
    let path = vault.process_binding(added[3].id).unwrap().unwrap();
    assert_eq!(path.env_name, format!("APASSY_ITEM_{}", added[3].id));
}

#[test]
fn a_postgres_url_is_a_database_item_with_fields_and_the_url_variable() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let url = "postgresql://billing_rw:FAKE-pass@db.prod.acme.internal:5432/billing";
    let summary = vault.add_detected(&one(url), None, None).expect("add");
    assert_eq!(summary.title, "Billing database");
    assert_eq!(summary.kind, CredentialKind::Database);
    let details = vault.details(summary.id).unwrap();
    let fields: Vec<(&str, bool)> = details
        .fields
        .iter()
        .map(|field| (field.name.as_str(), field.secret))
        .collect();
    assert_eq!(
        fields,
        [
            ("host", false),
            ("database", false),
            ("username", false),
            ("password", true),
            ("url", true),
        ]
    );
    assert_eq!(
        vault.reveal(summary.id, "host").unwrap().expose(),
        "db.prod.acme.internal:5432"
    );
    assert_eq!(
        vault.reveal(summary.id, "password").unwrap().expose(),
        "FAKE-pass"
    );
    let binding = vault.env_binding(summary.id).unwrap().unwrap();
    assert_eq!(binding.env_name, "DATABASE_URL");
    assert_eq!(binding.field, "url");
    assert_eq!(
        binding.delivery,
        EnvDelivery::Value,
        "a database is not HTTP"
    );
    assert_eq!(
        vault.declaration(summary.id).unwrap().unwrap().environment,
        Environment::Production
    );
    assert_eq!(
        vault.declaration_provider(summary.id).unwrap().as_deref(),
        Some("postgres")
    );
}

#[test]
fn a_one_time_password_gets_no_variable() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let link = "otpauth://totp/Example:owner@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    let summary = vault.add_detected(&one(link), None, None).expect("add");
    assert_eq!(summary.kind, CredentialKind::Custom);
    assert_eq!(vault.env_binding(summary.id).unwrap(), None);
    assert_eq!(vault.process_binding(summary.id).unwrap(), None);
}

#[test]
fn a_folder_holds_the_new_items_and_a_missing_folder_adds_nothing() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let work = vault.create_folder(None, "Work").unwrap();
    let acme = vault.create_folder(Some(&work.uuid), "Acme").unwrap();
    let found = detect(&format!(
        "STRIPE_SECRET_KEY={}\nRESEND_API_KEY={}\n",
        fake("sk_test_", 24),
        fake("re_", 24)
    ));
    let added = vault
        .add_detected_all(&found, Some(&acme.uuid), None)
        .expect("add");
    for item in &added {
        assert_eq!(vault.item_folder(item.id).unwrap(), Some(acme.uuid.clone()));
        let moved = vault
            .item_events(item.id, 50)
            .unwrap()
            .into_iter()
            .find(|event| event.kind == ItemEventKind::Moved)
            .expect("a moved event");
        assert_eq!(moved.detail, "Work / Acme");
    }
    let mut in_acme = vault.items_in_folder(Some(&acme.uuid), false).unwrap();
    in_acme.sort_unstable();
    assert_eq!(in_acme, [added[0].id, added[1].id]);

    let missing = vault.add_detected(&found[0], Some("no-such-folder"), None);
    assert_eq!(missing.unwrap_err().kind(), VaultErrorKind::NotFound);
    assert_eq!(vault.search("").unwrap().len(), 2);
}

#[test]
fn a_title_that_exists_gets_a_number_and_a_used_variable_becomes_automatic() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let detected = one(&fake("sk-ant-api03-", 40));
    let first = vault.add_detected(&detected, None, None).unwrap();
    let second = vault.add_detected(&detected, None, None).unwrap();
    assert_eq!(first.title, "Anthropic API key");
    assert_eq!(second.title, "Anthropic API key 2");
    // Without regard to case, as the vault list.
    let mut upper = detected.clone();
    upper.title = "ANTHROPIC API KEY".to_owned();
    let third = vault.add_detected(&upper, None, None).unwrap();
    assert_eq!(third.title, "ANTHROPIC API KEY 3");

    assert_eq!(
        vault.env_binding(first.id).unwrap().unwrap().env_name,
        "ANTHROPIC_API_KEY"
    );
    let taken = vault.env_binding(second.id).unwrap().unwrap();
    assert_eq!(taken.env_name, format!("APASSY_ITEM_{}", second.id));
    assert!(matches!(taken.delivery, EnvDelivery::Placeholder(_)));

    // A title of the largest size (128 bytes) keeps the number within the limit, and
    // the base is cut on a character boundary.
    let mut long = detected.clone();
    long.title = "ł".repeat(64);
    let a = vault.add_detected(&long, None, None).unwrap();
    let b = vault.add_detected(&long, None, None).unwrap();
    assert_eq!(a.title.len(), 128);
    assert!(b.title.ends_with(" 2"), "{}", b.title);
    assert!(b.title.len() <= 128, "{}", b.title);
    assert_eq!(b.title, format!("{} 2", "ł".repeat(63)));
}

#[test]
fn no_secret_reaches_debug_output_errors_or_the_history() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let key = fake("sk_live_", 32);
    let text = format!(
        "STRIPE_SECRET_KEY={key}\nDATABASE_URL=postgres://app:FAKE-db-pass@db.example.com:5432/shop\n"
    );
    let found = detect(&text);
    let added = vault.add_detected_all(&found, None, None).unwrap();
    let origin = ItemOrigin {
        agent_id: 1,
        agent_name: "Synthetic agent".to_owned(),
        project_key: "synthetic".to_owned(),
        project_label: "Synthetic".to_owned(),
        tool: OriginTool::Save,
    };
    let mut bad = found[0].clone();
    bad.hosts = vec!["Not A Host".to_owned()];
    let error = vault.add_detected(&bad, None, Some(&origin)).unwrap_err();
    let mut output = format!("{found:?} {added:?} {vault:?} {error:?} {error} {bad:?}");
    for item in &added {
        for event in vault.item_events(item.id, 50).unwrap() {
            output.push_str(&event.detail);
        }
        output.push_str(&format!("{:?}", vault.env_binding(item.id).unwrap()));
        output.push_str(&format!("{:?}", vault.details(item.id).unwrap()));
    }
    for secret in [key.as_str(), "FAKE-db-pass"] {
        assert!(!output.contains(secret), "the output shows {secret}");
    }
}

#[test]
fn a_failing_step_rolls_back_the_whole_transaction() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let work = vault.create_folder(None, "Work").unwrap();
    let good = one(&fake("sk-ant-api03-", 40));

    // The binding step fails after the item and its fields are in.
    let mut bad_host = good.clone();
    bad_host.hosts = vec!["Not A Host".to_owned()];
    assert_eq!(
        vault
            .add_detected(&bad_host, Some(&work.uuid), None)
            .unwrap_err()
            .kind(),
        VaultErrorKind::InvalidInput
    );
    // A variable field that the item does not have.
    let mut bad_field = good.clone();
    bad_field.env_field = Some("missing".to_owned());
    assert!(vault.add_detected(&bad_field, None, None).is_err());
    // A provider that is not built in fails after the variable.
    let mut bad_provider = good.clone();
    bad_provider.provider = Some("no-such-provider".to_owned());
    assert!(vault.add_detected(&bad_provider, None, None).is_err());
    // A batch: the first item is complete, the second fails, so neither stays.
    let batch = [good.clone(), bad_host];
    assert!(
        vault
            .add_detected_all(&batch, Some(&work.uuid), None)
            .is_err()
    );

    assert!(vault.search("").unwrap().is_empty(), "no item stays");
    assert!(
        vault
            .items_in_folder(Some(&work.uuid), true)
            .unwrap()
            .is_empty()
    );
    // The variable is still free, and the title has no number.
    let summary = vault.add_detected(&good, None, None).unwrap();
    assert_eq!(summary.title, "Anthropic API key");
    assert_eq!(
        vault.env_binding(summary.id).unwrap().unwrap().env_name,
        "ANTHROPIC_API_KEY"
    );
    assert_eq!(
        event_kinds(&vault, summary.id),
        [
            ItemEventKind::Created,
            ItemEventKind::Declaration,
            ItemEventKind::Variable
        ],
        "no event of a rolled-back item"
    );
}

#[test]
fn an_agent_origin_is_accepted_and_a_locked_vault_refuses() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let origin = ItemOrigin {
        agent_id: 7,
        agent_name: "Synthetic agent".to_owned(),
        project_key: "/synthetic/project".to_owned(),
        project_label: "project".to_owned(),
        tool: OriginTool::Capture,
    };
    let detected = one(&fake("re_", 24));
    vault
        .add_detected(&detected, None, Some(&origin))
        .expect("add with an origin");
    vault.lock().unwrap();
    assert_eq!(
        vault
            .add_detected(&detected, None, None)
            .unwrap_err()
            .kind(),
        VaultErrorKind::Locked
    );
}
