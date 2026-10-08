//! Import from 1Password: the zip reader, the 1PUX and CSV parsers, and the mapping to
//! Apassy items. Synthetic data only. Each synthetic secret starts with `SYNTH-OP-`.

#[path = "support/zip_fixture.rs"]
mod zip_fixture;

use std::io::Cursor;

use apassy::contracts::CredentialKind;
use apassy::import::zip::{self, ZipError, ZipLimits};
use apassy::import::{
    Category, Format, ImportError, ImportItem, ImportPreview, MAX_DETAILS, parse_1pux_json,
    parse_csv, read_1pux, read_file,
};
use apassy::vault::Vault;
use serde_json::{Value, json};
use zip_fixture::{Method, ZipEntry, build_zip, onepux};

const CANARY: &str = "SYNTH-OP-";

// ---- Synthetic 1PUX data. ----

fn field(id: &str, title: &str, value: Value) -> Value {
    json!({ "id": id, "title": title, "value": value, "guarded": false })
}

fn item(category: &str, title: &str, details: Value) -> Value {
    json!({
        "uuid": format!("synthetic-{}", title.to_lowercase().replace(' ', "-")),
        "favIndex": 0,
        "createdAt": 1_700_000_000,
        "updatedAt": 1_700_000_000,
        "state": "active",
        "categoryUuid": category,
        "overview": { "title": title, "url": "", "tags": ["work"] },
        "details": details,
    })
}

fn sections(fields: Vec<Value>) -> Value {
    json!([{ "title": "", "name": "section", "fields": fields }])
}

fn export(vaults: Vec<(&str, Vec<Value>)>) -> String {
    let vaults: Vec<Value> = vaults
        .into_iter()
        .map(|(name, items)| json!({ "attrs": { "name": name, "type": "U" }, "items": items }))
        .collect();
    json!({ "accounts": [{ "attrs": { "name": "Synthetic account" }, "vaults": vaults }] })
        .to_string()
}

fn api_credential() -> Value {
    item(
        "112",
        "Stripe test key",
        json!({
            "notesPlain": "Test mode only.",
            "sections": sections(vec![
                field("username", "username", json!({ "string": "svc-user" })),
                field("credential", "credential", json!({ "concealed": "SYNTH-OP-api-token" })),
                field("type", "type", json!({ "menu": "bearer" })),
                field("hostname", "hostname", json!({ "string": "api.example.test" })),
                field("expires", "expires", json!({ "date": 1_767_225_600 })),
                field("x3kd9", "Org ID", json!({ "string": "SYNTH-OP-org-id" })),
                field("attach", "Contract", json!({ "file": { "fileName": "c.pdf" } })),
            ]),
        }),
    )
}

fn full_export() -> String {
    let mut login = item(
        "001",
        "GitHub",
        json!({
            "loginFields": [
                { "value": "octo", "id": "", "name": "login", "fieldType": "T", "designation": "username" },
                { "value": "SYNTH-OP-login-pass", "id": "", "name": "password", "fieldType": "P", "designation": "password" },
                { "value": "✓", "id": "", "name": "remember", "fieldType": "C" },
            ],
            "notesPlain": "Recovery codes are in the safe.",
            "sections": sections(vec![field(
                "totp1",
                "one-time password",
                json!({ "totp": "otpauth://totp/octo?secret=SYNTH-OP-TOTP" }),
            )]),
        }),
    );
    login["overview"]["url"] = json!("https://github.com/login");
    login["overview"]["urls"] = json!([
        { "label": "", "url": "https://github.com/login" },
        { "label": "api", "url": "https://api.github.com" },
    ]);
    login["overview"]["tags"] = json!(["dev", "1password", " ", "dev"]);

    let mut archived = item(
        "112",
        "Old key",
        json!({ "sections": sections(vec![field(
            "credential",
            "credential",
            json!({ "concealed": "SYNTH-OP-old" }),
        )]) }),
    );
    archived["state"] = json!("archived");
    let mut trashed = item(
        "112",
        "Trashed key",
        json!({ "sections": sections(vec![field(
            "credential",
            "credential",
            json!({ "concealed": "SYNTH-OP-trash" }),
        )]) }),
    );
    trashed["trashed"] = json!(true);

    export(vec![
        (
            "Engineering",
            vec![
                api_credential(),
                login,
                item(
                    "102",
                    "Prod DB",
                    json!({ "sections": sections(vec![
                        field("database_type", "type", json!({ "menu": "postgresql" })),
                        field("hostname", "server", json!({ "string": "db.example.test" })),
                        field("port", "port", json!({ "string": "5432" })),
                        field("database", "database", json!({ "string": "app" })),
                        field("username", "username", json!({ "string": "app_user" })),
                        field("password", "password", json!({ "concealed": "SYNTH-OP-db-pass" })),
                    ]) }),
                ),
                item(
                    "102",
                    "Cache",
                    json!({ "sections": sections(vec![
                        field("hostname", "server", json!({ "string": "cache.example.test" })),
                        field("password", "password", json!({ "concealed": "SYNTH-OP-cache" })),
                    ]) }),
                ),
                item(
                    "110",
                    "Build box",
                    json!({ "sections": [
                        { "title": "", "fields": [
                            field("url", "URL", json!({ "string": "ssh://build.example.test" })),
                            field("username", "username", json!({ "string": "deploy" })),
                            field("password", "password", json!({ "concealed": "SYNTH-OP-server" })),
                        ] },
                        { "title": "Admin Console", "fields": [
                            field("admin_console_url", "admin console URL", json!({ "string": "https://admin.example.test" })),
                            field("admin_console_password", "console password", json!({ "concealed": "SYNTH-OP-admin" })),
                        ] },
                    ] }),
                ),
                item(
                    "114",
                    "Deploy key",
                    json!({ "sections": sections(vec![field(
                        "private_key",
                        "private key",
                        json!({ "sshKey": {
                            "privateKey": "-----BEGIN PRIVATE KEY-----\nSYNTH-OP-pkcs8\n-----END PRIVATE KEY-----\n",
                            "metadata": {
                                "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTH-OP-openssh\n-----END OPENSSH PRIVATE KEY-----\n",
                                "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA synthetic",
                                "fingerprint": "SHA256:synthetic",
                                "keyType": "ed25519",
                            },
                        } }),
                    )]) }),
                ),
                archived,
                trashed,
            ],
        ),
        (
            "Personal",
            vec![
                item(
                    "005",
                    "Wi-Fi",
                    json!({ "password": "SYNTH-OP-wifi", "notesPlain": null }),
                ),
                item(
                    "003",
                    "Recovery",
                    json!({ "notesPlain": "SYNTH-OP-note-body line 1\nline 2" }),
                ),
                item(
                    "002",
                    "Visa",
                    json!({ "sections": sections(vec![field(
                        "ccnum",
                        "number",
                        json!({ "creditCardNumber": "SYNTH-OP-4111" }),
                    )]) }),
                ),
                item(
                    "006",
                    "Scan",
                    json!({ "documentAttributes": { "fileName": "scan.pdf" } }),
                ),
                item(
                    "100",
                    "IDE license",
                    json!({ "sections": sections(vec![field(
                        "reg_code",
                        "license key",
                        json!({ "concealed": "SYNTH-OP-license" }),
                    )]) }),
                ),
                item(
                    "001",
                    "No user",
                    json!({ "loginFields": [
                        { "value": "SYNTH-OP-nouser", "name": "password", "fieldType": "P", "designation": "password" },
                    ] }),
                ),
                item("001", "Empty login", json!({ "loginFields": [] })),
            ],
        ),
    ])
}

fn find<'a>(preview: &'a ImportPreview, title: &str) -> &'a ImportItem {
    preview
        .items
        .iter()
        .find(|item| item.title == title)
        .unwrap_or_else(|| panic!("no item {title}"))
}

fn value<'a>(item: &'a ImportItem, name: &str) -> (&'a str, bool) {
    let field = item
        .draft()
        .expect("ready")
        .field(name)
        .unwrap_or_else(|| panic!("{}: no field {name}", item.title));
    (field.value.expose(), field.secret)
}

fn detail<'a>(item: &'a ImportItem, label: &str) -> (&'a str, bool) {
    let field = item
        .draft()
        .expect("ready")
        .detail(label)
        .unwrap_or_else(|| panic!("{}: no detail {label}", item.title));
    (field.value.expose(), field.secret)
}

fn preview() -> ImportPreview {
    read_1pux(&mut Cursor::new(onepux(&full_export()))).expect("read")
}

// ---- Mapping. ----

#[test]
fn every_category_maps_to_its_kind() {
    let preview = preview();
    assert_eq!(preview.format, Format::OnePux);
    assert_eq!(preview.items.len(), 15);

    let api = find(&preview, "Stripe test key");
    assert_eq!(api.source_vault, "Engineering");
    assert_eq!(api.category, Category::ApiCredential);
    assert_eq!(api.category_label, "API Credential");
    assert_eq!(api.kind(), Some(CredentialKind::ApiKey));
    assert_eq!(value(api, "token"), ("SYNTH-OP-api-token", true));
    assert_eq!(detail(api, "Username"), ("svc-user", false));
    assert_eq!(detail(api, "Type"), ("bearer", false));
    assert_eq!(detail(api, "Hostname"), ("api.example.test", false));
    assert_eq!(detail(api, "Expires"), ("2026-01-01", false));
    // An unknown text field can hold a secret, so it is hidden.
    assert_eq!(detail(api, "Org ID"), ("SYNTH-OP-org-id", true));
    assert_eq!(api.draft().unwrap().notes(), "Test mode only.");
    assert!(api.warnings.iter().any(|w| w.contains("attachment")));
    assert!(api.selected_by_default());

    let login = find(&preview, "GitHub");
    assert_eq!(login.kind(), Some(CredentialKind::Login));
    assert_eq!(value(login, "username"), ("octo", false));
    assert_eq!(value(login, "password"), ("SYNTH-OP-login-pass", true));
    // ADR 0021: the first website is the website of the login, for the browser.
    assert_eq!(value(login, "website"), ("https://github.com/login", false));
    assert_eq!(
        detail(login, "Website 2"),
        ("https://api.github.com", false)
    );
    assert_eq!(
        detail(login, "One-time password"),
        ("otpauth://totp/octo?secret=SYNTH-OP-TOTP", true)
    );
    // The check box of the web form is not a credential.
    assert_eq!(login.draft().unwrap().fields().len(), 5);
    assert_eq!(login.draft().unwrap().tags(), ["dev", "1password"]);
    assert_eq!(
        login.draft().unwrap().notes(),
        "Recovery codes are in the safe."
    );
    assert!(!login.selected_by_default());

    let db = find(&preview, "Prod DB");
    assert_eq!(db.kind(), Some(CredentialKind::Database));
    assert_eq!(value(db, "host"), ("db.example.test", false));
    assert_eq!(value(db, "database"), ("app", false));
    assert_eq!(value(db, "username"), ("app_user", false));
    assert_eq!(value(db, "password"), ("SYNTH-OP-db-pass", true));
    assert_eq!(detail(db, "Type"), ("postgresql", false));
    assert_eq!(detail(db, "Port"), ("5432", false));
    assert!(db.selected_by_default());

    let cache = find(&preview, "Cache");
    assert_eq!(cache.kind(), Some(CredentialKind::Custom));
    assert_eq!(value(cache, "secret"), ("SYNTH-OP-cache", true));
    assert_eq!(detail(cache, "Server"), ("cache.example.test", false));
    assert!(cache.warnings.iter().any(|w| w.contains("database name")));

    let server = find(&preview, "Build box");
    assert_eq!(server.category, Category::Server);
    assert_eq!(server.kind(), Some(CredentialKind::Login));
    assert_eq!(value(server, "username"), ("deploy", false));
    assert_eq!(value(server, "password"), ("SYNTH-OP-server", true));
    assert_eq!(detail(server, "URL"), ("ssh://build.example.test", false));
    assert_eq!(
        detail(server, "Admin console URL"),
        ("https://admin.example.test", false)
    );
    assert_eq!(detail(server, "Console password"), ("SYNTH-OP-admin", true));
    assert!(server.selected_by_default());

    let ssh = find(&preview, "Deploy key");
    assert_eq!(ssh.kind(), Some(CredentialKind::SshKey));
    let (private, secret) = value(ssh, "private_key");
    assert!(private.contains("SYNTH-OP-openssh") && secret);
    assert!(
        !ssh.draft()
            .unwrap()
            .fields()
            .iter()
            .any(|f| f.value.expose().contains("pkcs8"))
    );
    assert_eq!(
        value(ssh, "public_key"),
        ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA synthetic", false)
    );
    assert_eq!(detail(ssh, "Fingerprint"), ("SHA256:synthetic", false));
    assert_eq!(detail(ssh, "Key type"), ("ed25519", false));
    assert!(ssh.selected_by_default());

    let archived = find(&preview, "Old key");
    assert!(archived.can_import() && archived.archived);
    assert!(!archived.selected_by_default());
    assert!(archived.warnings.iter().any(|w| w.contains("Archived")));

    let trashed = find(&preview, "Trashed key");
    assert!(!trashed.can_import());
    assert_eq!(trashed.skip_reason(), Some("In the 1Password trash."));

    let password = find(&preview, "Wi-Fi");
    assert_eq!(password.source_vault, "Personal");
    assert_eq!(password.kind(), Some(CredentialKind::Custom));
    assert_eq!(value(password, "secret"), ("SYNTH-OP-wifi", true));
    assert!(password.warnings.is_empty());
    assert!(!password.selected_by_default());

    let note = find(&preview, "Recovery");
    assert_eq!(note.kind(), Some(CredentialKind::Custom));
    assert_eq!(
        value(note, "note"),
        ("SYNTH-OP-note-body line 1\nline 2", true)
    );
    assert_eq!(note.draft().unwrap().notes(), "");
    assert!(!note.selected_by_default());

    for (title, needle) in [("Visa", "Credit Card"), ("Scan", "file")] {
        let skipped = find(&preview, title);
        assert!(!skipped.can_import(), "{title}");
        assert!(skipped.skip_reason().unwrap().contains(needle), "{title}");
    }

    let license = find(&preview, "IDE license");
    assert_eq!(license.kind(), Some(CredentialKind::Custom));
    assert_eq!(value(license, "secret"), ("SYNTH-OP-license", true));
    assert!(
        license
            .warnings
            .iter()
            .any(|w| w.contains("Software License"))
    );
    assert!(!license.selected_by_default());

    let no_user = find(&preview, "No user");
    assert_eq!(no_user.kind(), Some(CredentialKind::Custom));
    assert_eq!(value(no_user, "secret"), ("SYNTH-OP-nouser", true));
    assert!(no_user.warnings.iter().any(|w| w.contains("username")));

    let empty = find(&preview, "Empty login");
    assert!(!empty.can_import());
    assert!(empty.skip_reason().unwrap().contains("no password"));
}

#[test]
fn secrets_never_reach_title_notes_tags_or_debug_output() {
    let preview = preview();
    for item in &preview.items {
        assert!(!item.title.contains(CANARY));
        for warning in &item.warnings {
            assert!(!warning.contains(CANARY), "{warning}");
        }
        let Some(draft) = item.draft() else {
            continue;
        };
        assert!(!draft.title().contains(CANARY));
        assert!(!draft.notes().contains(CANARY), "{}", item.title);
        assert!(draft.tags().iter().all(|tag| !tag.contains(CANARY)));
        assert!(draft.tags().iter().any(|tag| tag == "1password"));
        for field in draft.fields() {
            if field.value.expose().contains(CANARY) {
                assert!(field.secret, "{}: {} is visible", item.title, field.name);
            }
        }
    }
    let debug = format!("{preview:?}");
    assert!(!debug.contains(CANARY), "Debug shows a value");
    assert!(!debug.contains("Recovery codes"), "Debug shows notes");
}

#[test]
fn every_ready_item_validates_in_a_vault() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = Vault::create(&dir.path().join("import.db"), "import-test-pass").unwrap();
    vault.unlock("import-test-pass").unwrap();
    let mut preview = preview();
    let mut added = 0;
    for item in &mut preview.items {
        let Some(draft) = item.take_draft() else {
            continue;
        };
        let summary = vault
            .add(draft.into_vault_draft())
            .unwrap_or_else(|err| panic!("{}: {err}", item.title));
        let details = vault.details(summary.id).unwrap();
        assert!(details.tags.iter().any(|tag| tag == "1password"));
        added += 1;
    }
    assert_eq!(added, 11);
    let found = vault.search("Stripe test key").unwrap();
    assert_eq!(
        vault.reveal(found[0].id, "token").unwrap().expose(),
        "SYNTH-OP-api-token"
    );
    // A secret is not searchable metadata.
    assert!(vault.search("SYNTH-OP").unwrap().is_empty());
    // The 1Password tags are searchable.
    assert_eq!(vault.search("dev").unwrap().len(), 1);
}

#[test]
fn too_many_fields_leave_out_visible_details_first() {
    let mut fields = vec![field(
        "credential",
        "credential",
        json!({ "concealed": "SYNTH-OP-main" }),
    )];
    for index in 0..7 {
        fields.push(field(
            &format!("u{index}"),
            &format!("Link {index}"),
            json!({ "url": format!("https://{index}.example.test") }),
        ));
    }
    for index in 0..6 {
        fields.push(field(
            &format!("c{index}"),
            &format!("Secret {index}"),
            json!({ "concealed": format!("SYNTH-OP-{index}") }),
        ));
    }
    let data = export(vec![(
        "Vault",
        vec![item("112", "Many", json!({ "sections": sections(fields) }))],
    )]);
    let preview = parse_1pux_json(data.as_bytes()).unwrap();
    let many = &preview.items[0];
    let labels = many.draft().unwrap().detail_labels();
    assert_eq!(labels.len(), MAX_DETAILS);
    for index in 0..6 {
        assert_eq!(
            detail(many, &format!("Secret {index}")),
            (format!("SYNTH-OP-{index}").as_str(), true)
        );
    }
    for index in 0..4 {
        assert!(labels.contains(&format!("Link {index}")));
    }
    let dropped: Vec<_> = many
        .warnings
        .iter()
        .filter(|w| w.contains("did not fit"))
        .collect();
    assert_eq!(dropped.len(), 3);
    assert!(
        dropped
            .iter()
            .all(|w| w.contains("Link ") && !w.contains("secret"))
    );

    // With only secrets, the last secrets are left out and the warning says so.
    let fields: Vec<Value> = (0..13)
        .map(|index| {
            field(
                &format!("c{index}"),
                &format!("Key {index}"),
                json!({ "concealed": format!("SYNTH-OP-k{index}") }),
            )
        })
        .collect();
    let data = export(vec![(
        "Vault",
        vec![item(
            "112",
            "Secrets",
            json!({ "sections": sections(fields) }),
        )],
    )]);
    let preview = parse_1pux_json(data.as_bytes()).unwrap();
    let secrets = &preview.items[0];
    assert_eq!(value(secrets, "token"), ("SYNTH-OP-k0", true));
    assert_eq!(secrets.draft().unwrap().detail_labels().len(), MAX_DETAILS);
    let dropped: Vec<_> = secrets
        .warnings
        .iter()
        .filter(|w| w.starts_with("The secret"))
        .collect();
    assert_eq!(dropped.len(), 2);
    assert!(dropped[0].contains("Key 11") || dropped[0].contains("Key 12"));
}

#[test]
fn long_titles_labels_notes_and_duplicate_labels_fit_the_limits() {
    let long_title = "T".repeat(200);
    let long_notes = "n".repeat(9000);
    let data = export(vec![(
        "Vault",
        vec![item(
            "112",
            &long_title,
            json!({
                "notesPlain": long_notes,
                "sections": sections(vec![
                    field("credential", "credential", json!({ "concealed": "SYNTH-OP-t" })),
                    field("a", "a very long label that goes past the limit", json!({ "url": "https://a.test" })),
                    field("b", "Port", json!({ "string": "1" })),
                    field("c", "port", json!({ "string": "2" })),
                ]),
            }),
        )],
    )]);
    let preview = parse_1pux_json(data.as_bytes()).unwrap();
    let item = &preview.items[0];
    let draft = item.draft().unwrap();
    assert_eq!(draft.title().len(), 128);
    assert_eq!(draft.notes().len(), 8192);
    let labels = draft.detail_labels();
    assert!(labels.iter().all(|label| label.len() <= 31));
    assert!(labels.contains(&"Port".to_owned()));
    assert!(labels.contains(&"Port 2".to_owned()));
    assert!(item.warnings.iter().any(|w| w.contains("title")));
    assert!(item.warnings.iter().any(|w| w.contains("notes")));
}

#[test]
fn duplicates_are_marked_and_not_selected() {
    let mut preview = preview();
    preview.mark_existing([
        ("  prod db ", CredentialKind::Database),
        ("GitHub", CredentialKind::ApiKey),
    ]);
    let db = find(&preview, "Prod DB");
    assert!(db.duplicate);
    assert!(!db.selected_by_default());
    assert!(!find(&preview, "GitHub").duplicate);
    let selection = preview.default_selection();
    let selected: Vec<&str> = preview
        .items
        .iter()
        .zip(&selection)
        .filter(|(_, on)| **on)
        .map(|(item, _)| item.title.as_str())
        .collect();
    // A database item that becomes a custom secret keeps the database default.
    assert_eq!(
        selected,
        ["Stripe test key", "Cache", "Build box", "Deploy key"]
    );
}

#[test]
fn lenient_json_and_errors_without_values() {
    let preview = parse_1pux_json(br#"{"accounts": null}"#).unwrap();
    assert!(preview.items.is_empty());
    let data = r#"{"accounts":[{"vaults":[{"attrs":null,"items":[
        {"categoryUuid":"112","overview":{"title":null,"tags":null},
         "details":{"sections":[{"fields":[
            {"id":"credential","value":{"concealed":"SYNTH-OP-x"}},
            {"id":"n","title":"Count","value":{"string":42}},
            {"id":"m","title":"When","value":{"monthYear":202512}},
            {"id":"e","title":"Email","value":{"email":{"email_address":"a@example.test","provider":null}}},
            {"id":"z","title":"Addr","value":{"address":{"street":"x"}}},
            {"id":"y","title":"Nothing","value":null}
         ]}]}}]}]}]}"#;
    let preview = parse_1pux_json(data.as_bytes()).unwrap();
    let item = &preview.items[0];
    assert_eq!(item.title, "Untitled");
    assert_eq!(detail(item, "Count"), ("42", true));
    assert_eq!(detail(item, "When"), ("2025-12", false));
    assert_eq!(detail(item, "Email"), ("a@example.test", false));
    assert!(item.warnings.iter().any(|w| w.contains("Addr")));

    for bad in [
        r#"{"accounts": [ {"vaults": "SYNTH-OP-leak"} ]}"#,
        r#"{"accounts": [ {"vaults": [ {"items": [ {"details": {"sections": "SYNTH-OP-leak"}} ]} ]} ]}"#,
        "{\"accounts\": [SYNTH-OP-leak",
        "",
    ] {
        let err = parse_1pux_json(bad.as_bytes()).unwrap_err();
        assert!(matches!(err, ImportError::Json { .. }), "{err:?}");
        assert!(!err.to_string().contains(CANARY));
        assert!(!format!("{err:?}").contains(CANARY));
    }
}

// ---- CSV. ----

const CSV_HEADER: &str =
    "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes,Recovery Code";

#[test]
fn csv_rows_map_with_quoting_line_breaks_and_unknown_columns() {
    let text = format!(
        "{CSV_HEADER}\r\n\
         \"Mail, personal\",https://mail.example.test,me@example.test,\"SYNTH-OP-pa\"\"ss,word\",otpauth://totp/m?secret=SYNTH-OP-OTP,true,false,\"home,mail\",\"line 1\nline 2\",SYNTH-OP-recovery\r\n\
         API only,,,SYNTH-OP-csv-token,,,true,,,\r\n\
         Nothing,,user,,,,,,note,\r\n"
    );
    let preview = parse_csv(&text).unwrap();
    assert_eq!(preview.format, Format::Csv);
    assert_eq!(preview.items.len(), 3);

    let mail = &preview.items[0];
    assert_eq!(mail.title, "Mail, personal");
    assert_eq!(mail.category, Category::CsvRow);
    assert_eq!(mail.kind(), Some(CredentialKind::Login));
    assert_eq!(value(mail, "username"), ("me@example.test", false));
    assert_eq!(value(mail, "password"), ("SYNTH-OP-pa\"ss,word", true));
    assert_eq!(value(mail, "website"), ("https://mail.example.test", false));
    assert_eq!(
        detail(mail, "One-time password"),
        ("otpauth://totp/m?secret=SYNTH-OP-OTP", true)
    );
    assert_eq!(detail(mail, "Recovery Code"), ("SYNTH-OP-recovery", true));
    assert_eq!(mail.draft().unwrap().notes(), "line 1\nline 2");
    assert_eq!(mail.draft().unwrap().tags(), ["home", "mail", "1password"]);
    assert!(!mail.selected_by_default());

    let api = &preview.items[1];
    assert_eq!(api.kind(), Some(CredentialKind::Custom));
    assert_eq!(value(api, "secret"), ("SYNTH-OP-csv-token", true));
    assert!(api.archived);
    assert!(api.warnings.iter().any(|w| w.contains("username")));

    let nothing = &preview.items[2];
    assert!(!nothing.can_import());
    assert!(!format!("{preview:?}").contains(CANARY));
}

#[test]
fn csv_columns_match_by_name_in_any_order_and_case() {
    let text = "notes,PASSWORD, title ,UserName,Extra\nhello,SYNTH-OP-p,Box,admin,\n";
    let preview = parse_csv(text).unwrap();
    let item = &preview.items[0];
    assert_eq!(item.title, "Box");
    assert_eq!(value(item, "username"), ("admin", false));
    assert_eq!(value(item, "password"), ("SYNTH-OP-p", true));
    assert_eq!(item.draft().unwrap().notes(), "hello");
    // An empty unknown column adds no detail.
    assert!(item.draft().unwrap().detail_labels().is_empty());
}

#[test]
fn csv_errors_name_the_row_and_no_value() {
    assert_eq!(
        parse_csv("Name2,Password\nx,SYNTH-OP-y\n").unwrap_err(),
        ImportError::NoTitleColumn
    );
    assert_eq!(parse_csv("").unwrap_err(), ImportError::NoTitleColumn);
    let err = parse_csv("Title,Password\nx,\"SYNTH-OP-unclosed\n").unwrap_err();
    assert!(err.to_string().contains("Row 2"), "{err}");
    assert!(!err.to_string().contains(CANARY));
    let err = parse_csv("Title,Password\nx,\"SYNTH-OP-a\"b\n").unwrap_err();
    assert!(err.to_string().contains("Row 2"), "{err}");
    assert!(!format!("{err:?}").contains(CANARY));
}

// ---- Zip archives. ----

fn read(zip: &[u8]) -> Result<Vec<u8>, ZipError> {
    zip::read_entry(&mut Cursor::new(zip), "export.data", &ZipLimits::EXPORT)
        .map(|data| data.to_vec())
}

#[test]
fn stored_deflated_and_descriptor_entries_are_read() {
    let data = b"{\"accounts\":[]}".repeat(40);
    for method in [Method::Stored, Method::Deflated] {
        for descriptor in [false, true] {
            let mut entry = ZipEntry::new("export.data", &data, method);
            entry.descriptor = descriptor;
            let zip = build_zip(&[
                ZipEntry::new("files/a.bin", b"attachment", Method::Stored),
                entry,
            ]);
            assert_eq!(read(&zip).unwrap(), data, "{method:?} {descriptor}");
        }
    }
    // The attachment entries are not read, and a preview needs only export.data.
    let preview = read_1pux(&mut Cursor::new(onepux(&full_export()))).unwrap();
    assert_eq!(preview.items.len(), 15);
}

#[test]
fn malformed_and_truncated_archives_are_refused() {
    let zip = onepux(&full_export());
    for cut in [0, 3, 10, 30, zip.len() / 2, zip.len() - 30, zip.len() - 1] {
        let err = read(&zip[..cut]).unwrap_err();
        assert!(
            matches!(err, ZipError::NotZip | ZipError::Corrupt(_)),
            "cut {cut}: {err:?}"
        );
    }
    assert_eq!(
        read(b"not a zip archive at all, only text").unwrap_err(),
        ZipError::NotZip
    );
    // A damaged central directory entry.
    let mut bad = zip.clone();
    let directory = bad.len()
        - 22
        - 3 * 46
        - "export.attributes".len()
        - "export.data".len()
        - "files/synthetic-attachment.txt".len();
    bad[directory] = b'X';
    assert!(matches!(read(&bad).unwrap_err(), ZipError::Corrupt(_)));
    // A changed data byte fails the checksum.
    let mut entry = ZipEntry::new("export.data", b"{\"accounts\":[]}", Method::Stored);
    let clean = build_zip(std::slice::from_ref(&entry));
    let mut flipped = clean.clone();
    flipped[30 + "export.data".len() + 2] ^= 1;
    assert_eq!(read(&flipped).unwrap_err(), ZipError::Mismatch);
    // A missing or doubled export.data.
    entry.name = "export.json".to_owned();
    assert_eq!(read(&build_zip(&[entry])).unwrap_err(), ZipError::Missing);
    let twice = ZipEntry::new("export.data", b"{}", Method::Stored);
    assert_eq!(
        read(&build_zip(&[twice.clone(), twice])).unwrap_err(),
        ZipError::Duplicate
    );
}

#[test]
fn encryption_zip64_and_other_methods_are_refused() {
    let data = b"{\"accounts\":[]}";
    let mut encrypted = ZipEntry::new("export.data", data, Method::Stored);
    encrypted.flags = 0x0001;
    assert_eq!(
        read(&build_zip(&[encrypted])).unwrap_err(),
        ZipError::Encrypted
    );
    let mut aes = ZipEntry::new("export.data", data, Method::Stored);
    aes.method_number = Some(99);
    assert_eq!(read(&build_zip(&[aes])).unwrap_err(), ZipError::Encrypted);
    let mut bzip = ZipEntry::new("export.data", data, Method::Stored);
    bzip.method_number = Some(12);
    assert_eq!(
        read(&build_zip(&[bzip])).unwrap_err(),
        ZipError::UnsupportedMethod(12)
    );
    let mut zip64 = ZipEntry::new("export.data", data, Method::Stored);
    zip64.declared_size = Some(0xFFFF_FFFF);
    assert_eq!(read(&build_zip(&[zip64])).unwrap_err(), ZipError::Zip64);
    // A zip64 end record count.
    let mut zip = build_zip(&[ZipEntry::new("export.data", data, Method::Stored)]);
    let end = zip.len() - 22;
    zip[end + 10] = 0xFF;
    zip[end + 11] = 0xFF;
    zip[end + 8] = 0xFF;
    zip[end + 9] = 0xFF;
    assert_eq!(read(&zip).unwrap_err(), ZipError::Zip64);
    // An archive in parts.
    let mut zip = build_zip(&[ZipEntry::new("export.data", data, Method::Stored)]);
    let end = zip.len() - 22;
    zip[end + 4] = 1;
    assert_eq!(read(&zip).unwrap_err(), ZipError::MultiDisk);
}

#[test]
fn limits_stop_zip_bombs_and_oversized_archives() {
    // 4 MB of spaces deflate to about 4 KB: a ratio near 1000.
    let bomb = vec![b' '; 4 * 1024 * 1024];
    let zip = build_zip(&[ZipEntry::new("export.data", &bomb, Method::Deflated)]);
    assert!(zip.len() < 32 * 1024);
    assert_eq!(read(&zip).unwrap_err(), ZipError::RatioTooHigh);

    let data = vec![b'a'; 1000];
    let zip = build_zip(&[
        ZipEntry::new("a", b"1", Method::Stored),
        ZipEntry::new("b", b"2", Method::Stored),
        ZipEntry::new("export.data", &data, Method::Stored),
    ]);
    let limits = |change: fn(&mut ZipLimits)| {
        let mut limits = ZipLimits::EXPORT;
        change(&mut limits);
        zip::read_entry(&mut Cursor::new(&zip), "export.data", &limits).unwrap_err()
    };
    assert_eq!(limits(|l| l.max_entry_bytes = 999), ZipError::EntryTooLarge);
    assert_eq!(limits(|l| l.max_entries = 2), ZipError::TooManyEntries);
    assert_eq!(
        limits(|l| l.max_archive_bytes = 100),
        ZipError::ArchiveTooLarge
    );

    // A declared size that is too small or too large does not match the data.
    for declared in [10, 1200] {
        let mut entry = ZipEntry::new("export.data", &data, Method::Deflated);
        entry.declared_size = Some(declared);
        let zip = build_zip(&[entry]);
        assert_eq!(read(&zip).unwrap_err(), ZipError::Mismatch, "{declared}");
    }
}

// ---- Files. ----

#[test]
fn read_file_picks_the_format_and_names_the_problem() {
    let dir = tempfile::tempdir().unwrap();
    let onepux_path = dir.path().join("export.1pux");
    std::fs::write(&onepux_path, onepux(&full_export())).unwrap();
    assert_eq!(read_file(&onepux_path).unwrap().items.len(), 15);
    // A zip with another extension is still a 1PUX export.
    let renamed = dir.path().join("export.zip");
    std::fs::copy(&onepux_path, &renamed).unwrap();
    assert_eq!(read_file(&renamed).unwrap().format, Format::OnePux);

    let csv_path = dir.path().join("export.CSV");
    std::fs::write(
        &csv_path,
        format!("\u{feff}{CSV_HEADER}\nA,,u,SYNTH-OP-p,,,,,,\n"),
    )
    .unwrap();
    let preview = read_file(&csv_path).unwrap();
    assert_eq!(preview.format, Format::Csv);
    assert_eq!(preview.items[0].title, "A");

    let cases = [
        ("legacy.1pif", &b"{}"[..], ImportError::Legacy),
        ("notes.txt", b"hello", ImportError::UnknownFormat),
        (
            "broken.1pux",
            b"not a zip",
            ImportError::Zip(ZipError::NotZip),
        ),
        ("binary.csv", &[0xff, 0xfe, 0x00][..], ImportError::NotText),
    ];
    for (name, bytes, expected) in cases {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(read_file(&path).unwrap_err(), expected, "{name}");
    }
    assert_eq!(
        read_file(std::path::Path::new("")).unwrap_err(),
        ImportError::NoPath
    );
    assert_eq!(
        read_file(&dir.path().join("missing.1pux")).unwrap_err(),
        ImportError::Io
    );
    assert_eq!(read_file(dir.path()).unwrap_err(), ImportError::Io);
}
