#![cfg(feature = "vault")]

//! Black-box checks of the frozen `apassy::vault` API in docs/contracts/vault-v1.md.
//! Synthetic passphrases and canaries only. This file is not a memory or isolation proof.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use apassy::contracts::CredentialKind;
use apassy::vault::{
    Field, ItemDraft, ItemSummary, SecretValue, Vault, VaultErrorKind, VaultResult,
};
use tempfile::TempDir;

const PASS: &str = "synth-vault-pass-ok";
const WRONG_PASS: &str = "synth-vault-pass-no";

const TITLE_API: &str = "VL1-TITLE-api-key-alpha";
const NOTES_API: &str = "VL1-NOTES-api-key-alpha";
const TAG_API: &str = "VL1-TAG-api-key-alpha";
const TOKEN_API: &str = "VL1-SECRET-api-token-alpha";
const EXTRA_API: &str = "VL1-META-api-extra-alpha";

const TITLE_LOGIN: &str = "VL1-TITLE-login-bravo";
const NOTES_LOGIN: &str = "VL1-NOTES-login-bravo";
const TAG_LOGIN: &str = "VL1-TAG-login-bravo";
const USER_LOGIN: &str = "VL1-META-login-user-bravo";
const PASS_LOGIN: &str = "VL1-SECRET-login-pass-bravo";

const TITLE_SSH: &str = "VL1-TITLE-ssh-charlie";
const NOTES_SSH: &str = "VL1-NOTES-ssh-charlie";
const TAG_SSH: &str = "VL1-TAG-ssh-charlie";
const PRIV_SSH: &str = "VL1-SECRET-ssh-private-charlie";
const PHRASE_SSH: &str = "VL1-SECRET-ssh-phrase-charlie";
const PUB_SSH: &str = "VL1-META-ssh-public-charlie";

const TITLE_DB: &str = "VL1-TITLE-db-delta";
const NOTES_DB: &str = "VL1-NOTES-db-delta";
const TAG_DB: &str = "VL1-TAG-db-delta";
const HOST_DB: &str = "VL1-META-db-host-delta";
const NAME_DB: &str = "VL1-META-db-name-delta";
const USER_DB: &str = "VL1-META-db-user-delta";
const PASS_DB: &str = "VL1-SECRET-db-pass-delta";
const PORT_DB: &str = "VL1-META-db-port-delta";

const TITLE_CUSTOM: &str = "VL1-TITLE-custom-echo";
const NOTES_CUSTOM: &str = "VL1-NOTES-custom-echo";
const TAG_CUSTOM_A: &str = "VL1-TAG-custom-echo-a";
const TAG_CUSTOM_B: &str = "VL1-TAG-custom-echo-b";
const FIELD_CUSTOM_PLAIN: &str = "VL1-META-custom-plain-echo";
const FIELD_CUSTOM_SECRET: &str = "VL1-SECRET-custom-value-echo";

const SEARCH_INJECT_OR: &str = "' OR 1=1 --";
const SEARCH_INJECT_DROP: &str = "foo'; DROP TABLE item; --";
const SEARCH_WILDCARD_PCT: &str = "%";
const SEARCH_WILDCARD_UNDERSCORE: &str = "_";
const ISOLATED_SPECIAL_PATH: &str = "APASSY_VAULT_ISOLATED_SPECIAL_PATH";

#[test]
fn restore_reserves_destination_before_key_validation() {
    let dir = TempDir::new().unwrap();
    let mut source = create_unlocked(&dir.path().join("reserve-source.db"), PASS);
    let backup = dir.path().join("reserve-source.bak");
    expect_ok(source.backup(&backup));
    let dest = dir.path().join("reserve-dest.db");
    let guard = fs::File::create_new(lock_sidecar(&dest)).unwrap();
    guard.try_lock().unwrap();
    expect_err(
        Vault::restore(&backup, &dest, WRONG_PASS),
        VaultErrorKind::Busy,
    );
    assert!(!dest.exists());
    drop(guard);
    expect_err(
        Vault::restore(&backup, &dest, WRONG_PASS),
        VaultErrorKind::WrongKeyOrCorrupt,
    );
    assert!(!dest.exists());
    let restored = expect_ok(Vault::restore(&backup, &dest, PASS));
    assert!(restored.is_locked());
}

#[test]
fn copy_refuses_companion_conflicts_without_changing_existing_files() {
    let dir = TempDir::new().unwrap();
    let mut source = create_unlocked(&dir.path().join("source.db"), PASS);
    expect_ok(source.add(api_key_draft()));
    for suffix in ["-journal", "-wal", "-shm"] {
        let dest = dir.path().join(format!("backup{suffix}.db"));
        let companion = dir.path().join(format!("backup{suffix}.db{suffix}"));
        fs::write(&companion, b"synthetic-companion-preserve-me").unwrap();
        expect_err(source.backup(&dest), VaultErrorKind::AlreadyExists);
        assert!(source.is_locked());
        assert!(!dest.exists());
        assert_eq!(
            fs::read(&companion).unwrap(),
            b"synthetic-companion-preserve-me"
        );
        expect_ok(source.unlock(PASS));
    }
    let backup = dir.path().join("closed.bak");
    expect_ok(source.backup(&backup));
    let original = fs::read(&backup).unwrap();
    for suffix in ["-journal", "-wal", "-shm"] {
        let dest = dir.path().join(format!("restored{suffix}.db"));
        let companion = dir.path().join(format!("restored{suffix}.db{suffix}"));
        fs::write(&companion, b"synthetic-companion-preserve-me").unwrap();
        expect_err(
            Vault::restore(&backup, &dest, PASS),
            VaultErrorKind::AlreadyExists,
        );
        assert!(!dest.exists());
        assert_eq!(
            fs::read(&companion).unwrap(),
            b"synthetic-companion-preserve-me"
        );
        let source_companion = dir.path().join(format!("closed.bak{suffix}"));
        fs::write(&source_companion, b"synthetic-companion-preserve-me").unwrap();
        let no_dest_conflict = dir.path().join(format!("refused{suffix}.db"));
        expect_err(
            Vault::restore(&backup, &no_dest_conflict, PASS),
            VaultErrorKind::InvalidInput,
        );
        assert!(!no_dest_conflict.exists());
        assert_eq!(
            fs::read(&source_companion).unwrap(),
            b"synthetic-companion-preserve-me"
        );
        assert_eq!(fs::read(&backup).unwrap(), original);
        fs::remove_file(&source_companion).unwrap();
    }
}

#[test]
fn database_names_cannot_alias_locks_or_sqlite_companions() {
    let dir = TempDir::new().unwrap();
    let mut source = create_unlocked(&dir.path().join("source.db"), PASS);
    for suffix in [
        ".lock", "-journal", "-wal", "-shm", ".LOCK", "-JOURNAL", "-WAL", "-SHM",
    ] {
        let path = dir.path().join(format!("reserved{suffix}"));
        expect_err(Vault::create(&path, PASS), VaultErrorKind::InvalidInput);
        assert!(!path.exists());
        expect_err(source.backup(&path), VaultErrorKind::InvalidInput);
        assert!(source.is_locked());
        expect_ok(source.unlock(PASS));
        fs::write(&path, b"synthetic-reserved-name-preserve-me").unwrap();
        expect_err(Vault::open(&path), VaultErrorKind::InvalidInput);
        assert_eq!(
            fs::read(&path).unwrap(),
            b"synthetic-reserved-name-preserve-me"
        );
        fs::remove_file(&path).unwrap();
    }
}

#[test]
fn new_database_refuses_existing_sqlite_companions() {
    let dir = TempDir::new().unwrap();
    for suffix in ["-journal", "-wal", "-shm"] {
        let path = dir.path().join(format!("collision{suffix}.db"));
        let companion = dir.path().join(format!("collision{suffix}.db{suffix}"));
        fs::write(&companion, b"synthetic-unrelated-file-preserve-me").unwrap();
        let result = Vault::create(&path, PASS);
        assert_eq!(
            fs::read(&companion).unwrap(),
            b"synthetic-unrelated-file-preserve-me"
        );
        expect_err(result, VaultErrorKind::AlreadyExists);
        assert!(!path.exists());
    }
}

fn all_canaries() -> Vec<&'static str> {
    vec![
        TITLE_API,
        NOTES_API,
        TAG_API,
        TOKEN_API,
        EXTRA_API,
        TITLE_LOGIN,
        NOTES_LOGIN,
        TAG_LOGIN,
        USER_LOGIN,
        PASS_LOGIN,
        TITLE_SSH,
        NOTES_SSH,
        TAG_SSH,
        PRIV_SSH,
        PHRASE_SSH,
        PUB_SSH,
        TITLE_DB,
        NOTES_DB,
        TAG_DB,
        HOST_DB,
        NAME_DB,
        USER_DB,
        PASS_DB,
        PORT_DB,
        TITLE_CUSTOM,
        NOTES_CUSTOM,
        TAG_CUSTOM_A,
        TAG_CUSTOM_B,
        FIELD_CUSTOM_PLAIN,
        FIELD_CUSTOM_SECRET,
        PASS,
        WRONG_PASS,
    ]
}

fn expect_ok<T>(result: VaultResult<T>) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("expected success, got {err} ({:?})", err.kind()),
    }
}

fn expect_err<T>(result: VaultResult<T>, kind: VaultErrorKind) {
    match result {
        Err(err) => assert_eq!(
            err.kind(),
            kind,
            "expected {kind:?}, got {:?} ({err})",
            err.kind()
        ),
        Ok(_) => panic!("expected error {kind:?}, got success"),
    }
}

fn temp_pair(name: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("create temporary directory");
    let path = dir.path().join(name);
    (dir, path)
}

fn lock_sidecar(db: &Path) -> PathBuf {
    let mut name = db.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

fn assert_refused<T>(result: VaultResult<T>, what: &str) {
    assert!(result.is_err(), "{what} must be refused");
}

fn secret_field(name: &str, value: &str) -> Field {
    Field {
        name: name.to_string(),
        value: SecretValue::new(value.to_string()),
        secret: true,
    }
}

fn plain_field(name: &str, value: &str) -> Field {
    Field {
        name: name.to_string(),
        value: SecretValue::new(value.to_string()),
        secret: false,
    }
}

fn draft(
    title: &str,
    kind: CredentialKind,
    notes: &str,
    tags: &[&str],
    fields: Vec<Field>,
) -> ItemDraft {
    ItemDraft {
        title: title.to_string(),
        kind,
        notes: notes.to_string(),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        fields,
    }
}

fn api_key_draft() -> ItemDraft {
    draft(
        TITLE_API,
        CredentialKind::ApiKey,
        NOTES_API,
        &[TAG_API],
        vec![
            secret_field("token", TOKEN_API),
            plain_field("extra", EXTRA_API),
        ],
    )
}

fn login_draft() -> ItemDraft {
    draft(
        TITLE_LOGIN,
        CredentialKind::Login,
        NOTES_LOGIN,
        &[TAG_LOGIN],
        vec![
            plain_field("username", USER_LOGIN),
            secret_field("password", PASS_LOGIN),
        ],
    )
}

fn ssh_key_draft() -> ItemDraft {
    draft(
        TITLE_SSH,
        CredentialKind::SshKey,
        NOTES_SSH,
        &[TAG_SSH],
        vec![
            secret_field("private_key", PRIV_SSH),
            secret_field("passphrase", PHRASE_SSH),
            plain_field("public_key", PUB_SSH),
        ],
    )
}

fn database_draft() -> ItemDraft {
    draft(
        TITLE_DB,
        CredentialKind::Database,
        NOTES_DB,
        &[TAG_DB],
        vec![
            plain_field("host", HOST_DB),
            plain_field("database", NAME_DB),
            plain_field("username", USER_DB),
            secret_field("password", PASS_DB),
            plain_field("port", PORT_DB),
        ],
    )
}

fn custom_draft() -> ItemDraft {
    draft(
        TITLE_CUSTOM,
        CredentialKind::Custom,
        NOTES_CUSTOM,
        &[TAG_CUSTOM_A, TAG_CUSTOM_B],
        vec![
            plain_field("label", FIELD_CUSTOM_PLAIN),
            secret_field("blob", FIELD_CUSTOM_SECRET),
        ],
    )
}

fn create_locked(path: &Path, passphrase: &str) -> Vault {
    let vault = expect_ok(Vault::create(path, passphrase));
    assert!(
        vault.is_locked(),
        "Vault::create must return a locked vault"
    );
    vault
}

fn create_unlocked(path: &Path, passphrase: &str) -> Vault {
    let mut vault = create_locked(path, passphrase);
    expect_ok(vault.unlock(passphrase));
    assert!(!vault.is_locked());
    vault
}

fn assert_omits_canaries(path: &Path, canaries: &[&str]) {
    let bytes = fs::read(path).unwrap_or_else(|err| panic!("read {} ({err})", path.display()));
    for canary in canaries {
        let needle = canary.as_bytes();
        let found = bytes.windows(needle.len()).any(|window| window == needle);
        assert!(!found, "{} contains canary {canary}", path.display());
    }
}

fn assert_file_omits(path: &Path, canaries: &[&str]) {
    let bytes = fs::read(path).unwrap_or_else(|err| panic!("read {} ({err})", path.display()));
    assert!(
        !bytes.starts_with(b"SQLite format 3"),
        "{} starts with a plaintext SQLite header",
        path.display()
    );
    for canary in canaries {
        let needle = canary.as_bytes();
        let found = bytes.windows(needle.len()).any(|window| window == needle);
        assert!(!found, "{} contains canary {canary}", path.display());
    }
}

#[cfg(unix)]
fn assert_unix_mode_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .unwrap_or_else(|err| panic!("stat {} ({err})", path.display()))
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode,
        0o600,
        "{} mode is {mode:o}, expected 0600",
        path.display()
    );
}

#[cfg(not(unix))]
fn assert_unix_mode_0600(_path: &Path) {}

fn sorted_tags(tags: &[String]) -> Vec<String> {
    let mut tags = tags.to_vec();
    tags.sort();
    tags
}

fn assert_stored(
    vault: &Vault,
    id: u64,
    title: &str,
    kind: CredentialKind,
    notes: &str,
    tags: &[&str],
    fields: &[(&str, bool, &str)],
) {
    assert!(id > 0, "ids must be positive");
    let details = expect_ok(vault.details(id));
    assert_eq!(details.summary.id, id);
    assert_eq!(details.summary.title, title);
    assert_eq!(details.summary.kind, kind);
    assert_eq!(details.notes, notes);
    let expected_tags: Vec<String> = tags.iter().map(|tag| (*tag).to_string()).collect();
    assert_eq!(sorted_tags(&details.tags), sorted_tags(&expected_tags));
    assert_eq!(details.fields.len(), fields.len());
    for (name, secret, value) in fields {
        let summary = details
            .fields
            .iter()
            .find(|field| field.name == *name)
            .unwrap_or_else(|| panic!("missing field {name}"));
        assert_eq!(summary.secret, *secret, "secret flag for {name}");
        let revealed = expect_ok(vault.reveal(id, name));
        assert_eq!(revealed.expose(), *value);
        assert_eq!(revealed, SecretValue::new((*value).to_string()));
    }
}

fn add_all_kinds(vault: &mut Vault) -> [ItemSummary; 5] {
    let api = expect_ok(vault.add(api_key_draft()));
    let login = expect_ok(vault.add(login_draft()));
    let ssh = expect_ok(vault.add(ssh_key_draft()));
    let database = expect_ok(vault.add(database_draft()));
    let custom = expect_ok(vault.add(custom_draft()));
    assert_eq!(api.kind, CredentialKind::ApiKey);
    assert_eq!(login.kind, CredentialKind::Login);
    assert_eq!(ssh.kind, CredentialKind::SshKey);
    assert_eq!(database.kind, CredentialKind::Database);
    assert_eq!(custom.kind, CredentialKind::Custom);
    assert_eq!(api.title, TITLE_API);
    assert_eq!(login.title, TITLE_LOGIN);
    assert_eq!(ssh.title, TITLE_SSH);
    assert_eq!(database.title, TITLE_DB);
    assert_eq!(custom.title, TITLE_CUSTOM);
    [api, login, ssh, database, custom]
}

fn assert_all_kinds(vault: &Vault, items: &[ItemSummary; 5]) {
    let [api, login, ssh, database, custom] = items;
    assert_stored(
        vault,
        api.id,
        TITLE_API,
        CredentialKind::ApiKey,
        NOTES_API,
        &[TAG_API],
        &[("token", true, TOKEN_API), ("extra", false, EXTRA_API)],
    );
    assert_stored(
        vault,
        login.id,
        TITLE_LOGIN,
        CredentialKind::Login,
        NOTES_LOGIN,
        &[TAG_LOGIN],
        &[
            ("username", false, USER_LOGIN),
            ("password", true, PASS_LOGIN),
        ],
    );
    assert_stored(
        vault,
        ssh.id,
        TITLE_SSH,
        CredentialKind::SshKey,
        NOTES_SSH,
        &[TAG_SSH],
        &[
            ("private_key", true, PRIV_SSH),
            ("passphrase", true, PHRASE_SSH),
            ("public_key", false, PUB_SSH),
        ],
    );
    assert_stored(
        vault,
        database.id,
        TITLE_DB,
        CredentialKind::Database,
        NOTES_DB,
        &[TAG_DB],
        &[
            ("host", false, HOST_DB),
            ("database", false, NAME_DB),
            ("username", false, USER_DB),
            ("password", true, PASS_DB),
            ("port", false, PORT_DB),
        ],
    );
    assert_stored(
        vault,
        custom.id,
        TITLE_CUSTOM,
        CredentialKind::Custom,
        NOTES_CUSTOM,
        &[TAG_CUSTOM_A, TAG_CUSTOM_B],
        &[
            ("label", false, FIELD_CUSTOM_PLAIN),
            ("blob", true, FIELD_CUSTOM_SECRET),
        ],
    );
}

fn assert_debug_omits(label: &str, debug: &str, canaries: &[&str]) {
    for canary in canaries {
        assert!(
            !debug.contains(canary),
            "{label} Debug contains canary {canary}: {debug}"
        );
    }
}

fn inject_unsupported_schema(path: &Path, passphrase: &str) {
    let conn = rusqlite::Connection::open(path).expect("open a closed vault file with rusqlite");
    conn.pragma_update(None, "key", passphrase)
        .expect("apply passphrase before schema injection");
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    })
    .expect("decrypt closed vault before schema injection");
    let names: Vec<String> = {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            )
            .expect("prepare table list");
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query user tables");
        rows.map(|row| row.expect("read table name")).collect()
    };
    for name in names {
        let ident = format!("\"{}\"", name.replace('"', "\"\""));
        conn.execute(&format!("DROP TABLE IF EXISTS {ident}"), [])
            .expect("drop user table on closed vault");
    }
    conn.pragma_update(None, "user_version", 99999i32)
        .expect("write unsupported schema version");
    conn.close()
        .map_err(|(_, err)| err)
        .expect("close rusqlite after schema injection");
}

#[test]
fn create_returns_locked_and_data_apis_need_unlock() {
    let (_dir, path) = temp_pair("locked.db");
    let mut vault = create_locked(&path, PASS);
    expect_err(vault.add(api_key_draft()), VaultErrorKind::Locked);
    expect_err(vault.search(TITLE_API), VaultErrorKind::Locked);
    expect_err(vault.details(1), VaultErrorKind::Locked);
    expect_err(vault.reveal(1, "token"), VaultErrorKind::Locked);
    expect_err(vault.update(1, 1, api_key_draft()), VaultErrorKind::Locked);
    expect_err(vault.delete(1, 1), VaultErrorKind::Locked);
    expect_err(
        vault.backup(&path.with_extension("bak")),
        VaultErrorKind::Locked,
    );
    expect_ok(vault.unlock(PASS));
    let added = expect_ok(vault.add(api_key_draft()));
    assert!(added.id > 0);
    expect_ok(vault.lock());
    assert!(vault.is_locked());
    expect_err(vault.search(TITLE_API), VaultErrorKind::Locked);
}

#[test]
fn create_refuses_existing_open_does_not_create() {
    let (dir, path) = temp_pair("exists.db");
    fs::write(&path, b"keep-bytes").expect("write placeholder");
    expect_err(Vault::create(&path, PASS), VaultErrorKind::AlreadyExists);
    assert_eq!(fs::read(&path).expect("read placeholder"), b"keep-bytes");

    let missing = dir.path().join("missing.db");
    expect_err(Vault::open(&missing), VaultErrorKind::NotFound);
    assert!(!missing.exists(), "open must not create a missing file");

    let mut vault = create_unlocked(&dir.path().join("fresh.db"), PASS);
    let _ = expect_ok(vault.add(api_key_draft()));
    drop(vault);
    expect_err(
        Vault::create(&dir.path().join("fresh.db"), PASS),
        VaultErrorKind::AlreadyExists,
    );
}

#[test]
fn passphrase_length_bounds_are_exact() {
    let (dir, _) = temp_pair("bounds.db");
    let short = dir.path().join("short.db");
    expect_err(
        Vault::create(&short, "a".repeat(11).as_str()),
        VaultErrorKind::InvalidInput,
    );
    assert!(!short.exists());
    expect_err(Vault::create(&short, ""), VaultErrorKind::InvalidInput);
    assert!(!short.exists());

    let over = dir.path().join("over.db");
    expect_err(
        Vault::create(&over, "a".repeat(1025).as_str()),
        VaultErrorKind::InvalidInput,
    );
    assert!(!over.exists());

    let min_path = dir.path().join("min.db");
    let mut min_vault = create_unlocked(&min_path, &"a".repeat(12));
    let added = expect_ok(min_vault.add(custom_draft()));
    assert!(added.id > 0);
    drop(min_vault);

    let max_path = dir.path().join("max.db");
    let mut max_vault = create_unlocked(&max_path, &"b".repeat(1024));
    let added = expect_ok(max_vault.add(custom_draft()));
    assert!(added.id > 0);
}

#[test]
fn wrong_key_keeps_locked_and_failed_repeat_unlock_does_not_stick() {
    let (_dir, path) = temp_pair("wrong-key.db");
    let mut vault = create_locked(&path, PASS);
    let epoch_locked = vault.epoch();
    expect_err(vault.unlock(WRONG_PASS), VaultErrorKind::WrongKeyOrCorrupt);
    assert!(vault.is_locked());
    expect_err(vault.search(TITLE_API), VaultErrorKind::Locked);
    expect_err(vault.unlock(WRONG_PASS), VaultErrorKind::WrongKeyOrCorrupt);
    assert!(vault.is_locked());
    expect_ok(vault.unlock(PASS));
    assert!(!vault.is_locked());
    assert_ne!(vault.epoch(), epoch_locked);
    let added = expect_ok(vault.add(api_key_draft()));
    expect_ok(vault.reveal(added.id, "token"));
    expect_ok(vault.lock());
    expect_err(vault.unlock(WRONG_PASS), VaultErrorKind::WrongKeyOrCorrupt);
    assert!(vault.is_locked());
    expect_err(vault.unlock(WRONG_PASS), VaultErrorKind::WrongKeyOrCorrupt);
    assert!(vault.is_locked());
    expect_ok(vault.unlock(PASS));
    assert_eq!(
        expect_ok(vault.reveal(added.id, "token")).expose(),
        TOKEN_API
    );
}

#[test]
fn five_kinds_persist_required_fields_across_drop_reopen() {
    let (_dir, path) = temp_pair("persist.db");
    let items = {
        let mut vault = create_unlocked(&path, PASS);
        let items = add_all_kinds(&mut vault);
        assert_all_kinds(&vault, &items);
        items
    };
    let mut vault = expect_ok(Vault::open(&path));
    assert!(vault.is_locked());
    expect_ok(vault.unlock(PASS));
    assert_all_kinds(&vault, &items);
    expect_err(vault.reveal(items[0].id, "Token"), VaultErrorKind::NotFound);
}

#[test]
fn reveal_is_explicit_and_debug_is_redacted() {
    let (_dir, path) = temp_pair("debug.db");
    let mut vault = create_unlocked(&path, PASS);
    let items = add_all_kinds(&mut vault);
    let secret = expect_ok(vault.reveal(items[0].id, "token"));
    assert_eq!(secret.expose(), TOKEN_API);
    let secrets = [
        TOKEN_API,
        PASS_LOGIN,
        PRIV_SSH,
        PHRASE_SSH,
        PASS_DB,
        FIELD_CUSTOM_SECRET,
    ];
    assert_debug_omits("SecretValue", &format!("{secret:?}"), &secrets);
    assert_debug_omits(
        "Field",
        &format!("{:?}", secret_field("token", TOKEN_API)),
        &secrets,
    );
    assert_debug_omits("ItemDraft", &format!("{:?}", api_key_draft()), &secrets);
    assert_debug_omits("Vault", &format!("{vault:?}"), &secrets);
    assert_debug_omits("Vault", &format!("{vault:?}"), &[PASS, WRONG_PASS]);

    let details = expect_ok(vault.details(items[1].id));
    let details_debug = format!("{details:?}");
    assert!(!details_debug.contains(PASS_LOGIN));
    assert!(!details_debug.contains(USER_LOGIN));
    let summary_debug = format!("{:?}", items[1]);
    assert!(!summary_debug.contains(PASS_LOGIN));
}

#[test]
fn search_is_literal_metadata_only() {
    let (_dir, path) = temp_pair("search.db");
    let mut vault = create_unlocked(&path, PASS);
    let items = add_all_kinds(&mut vault);
    let by_title = expect_ok(vault.search("vl1-title-api-key-alpha"));
    assert_eq!(by_title.len(), 1);
    assert_eq!(by_title[0].id, items[0].id);
    let by_notes = expect_ok(vault.search("VL1-NOTES-login-bravo"));
    assert_eq!(by_notes.len(), 1);
    assert_eq!(by_notes[0].id, items[1].id);
    let by_tag = expect_ok(vault.search("vl1-tag-custom-echo-b"));
    assert_eq!(by_tag.len(), 1);
    assert_eq!(by_tag[0].id, items[4].id);

    for secret_query in [
        TOKEN_API,
        PASS_LOGIN,
        PRIV_SSH,
        PHRASE_SSH,
        PASS_DB,
        FIELD_CUSTOM_SECRET,
        USER_LOGIN,
        HOST_DB,
        EXTRA_API,
        FIELD_CUSTOM_PLAIN,
    ] {
        let hits = expect_ok(vault.search(secret_query));
        assert!(
            hits.is_empty(),
            "search must not match field value {secret_query}"
        );
    }

    let before = expect_ok(vault.search(TITLE_API));
    assert_eq!(before.len(), 1);
    for inject in [
        SEARCH_INJECT_OR,
        SEARCH_INJECT_DROP,
        SEARCH_WILDCARD_PCT,
        SEARCH_WILDCARD_UNDERSCORE,
    ] {
        let hits = expect_ok(vault.search(inject));
        assert!(
            hits.is_empty(),
            "literal search must not broaden on {inject}"
        );
    }
    assert_all_kinds(&vault, &items);
    let after = expect_ok(vault.search(TITLE_API));
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].id, items[0].id);
}

#[test]
fn search_matching_over_1000_is_invalid_input() {
    let (_dir, path) = temp_pair("search-limit.db");
    let mut vault = create_unlocked(&path, PASS);
    let mut unique = None;
    for i in 0..1000 {
        let title = format!("VL1-BULK-{i:04}");
        let added = expect_ok(vault.add(draft(
            &title,
            CredentialKind::Custom,
            "bulk-notes",
            &["bulkmatch"],
            vec![plain_field("label", "bulk")],
        )));
        if i == 0 {
            unique = Some(added);
        }
    }
    let thousand = expect_ok(vault.search("bulkmatch"));
    assert_eq!(thousand.len(), 1000);
    let unique = unique.expect("first bulk item");
    let one = expect_ok(vault.search("VL1-BULK-0000"));
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].id, unique.id);

    expect_ok(vault.add(draft(
        "VL1-BULK-1000",
        CredentialKind::Custom,
        "bulk-notes",
        &["bulkmatch"],
        vec![plain_field("label", "bulk")],
    )));
    expect_err(vault.search("bulkmatch"), VaultErrorKind::InvalidInput);
    let still_one = expect_ok(vault.search("VL1-BULK-0000"));
    assert_eq!(still_one.len(), 1);
}

#[test]
fn revision_conflict_and_invalid_update_are_atomic() {
    let (_dir, path) = temp_pair("conflict.db");
    let mut vault = create_unlocked(&path, PASS);
    let added = expect_ok(vault.add(api_key_draft()));
    let revision = added.revision;
    let before = expect_ok(vault.details(added.id));
    let before_secret = expect_ok(vault.reveal(added.id, "token"));

    expect_err(
        vault.update(added.id, revision.wrapping_add(7), api_key_draft()),
        VaultErrorKind::Conflict,
    );
    expect_err(
        vault.update(added.id, 0, api_key_draft()),
        VaultErrorKind::Conflict,
    );
    let after_conflict = expect_ok(vault.details(added.id));
    assert_eq!(after_conflict, before);
    assert_eq!(
        expect_ok(vault.reveal(added.id, "token")).expose(),
        before_secret.expose()
    );

    let mut bad = api_key_draft();
    bad.title = String::new();
    expect_err(
        vault.update(added.id, revision, bad),
        VaultErrorKind::InvalidInput,
    );
    let after_bad = expect_ok(vault.details(added.id));
    assert_eq!(after_bad, before);
    assert_eq!(
        expect_ok(vault.reveal(added.id, "token")).expose(),
        TOKEN_API
    );

    let mut good = api_key_draft();
    good.title = "VL1-TITLE-api-key-edited".to_string();
    good.notes = "VL1-NOTES-api-key-edited".to_string();
    good.fields = vec![
        secret_field("token", "VL1-SECRET-api-token-edited"),
        plain_field("extra", EXTRA_API),
    ];
    let updated = expect_ok(vault.update(added.id, revision, good));
    assert_eq!(updated.id, added.id);
    assert!(updated.revision > revision, "edits must increase revision");
    assert_eq!(updated.title, "VL1-TITLE-api-key-edited");
    assert_eq!(
        expect_ok(vault.reveal(added.id, "token")).expose(),
        "VL1-SECRET-api-token-edited"
    );

    let after_reveal = expect_ok(vault.details(added.id));
    let _ = expect_ok(vault.reveal(added.id, "token"));
    let _ = expect_ok(vault.search("VL1-TITLE-api-key-edited"));
    let after_read = expect_ok(vault.details(added.id));
    assert_eq!(after_read.summary.revision, after_reveal.summary.revision);
    assert_eq!(after_read.summary.revision, updated.revision);
}

#[test]
fn delete_does_not_reuse_ids() {
    let (_dir, path) = temp_pair("delete.db");
    let mut vault = create_unlocked(&path, PASS);
    let first = expect_ok(vault.add(api_key_draft()));
    let second = expect_ok(vault.add(login_draft()));
    expect_err(
        vault.delete(first.id, first.revision.wrapping_add(3)),
        VaultErrorKind::Conflict,
    );
    assert_eq!(expect_ok(vault.details(first.id)).summary.id, first.id);
    expect_err(vault.delete(9_000_001, 1), VaultErrorKind::NotFound);
    expect_ok(vault.delete(first.id, first.revision));
    expect_err(vault.details(first.id), VaultErrorKind::NotFound);
    expect_err(vault.reveal(first.id, "token"), VaultErrorKind::NotFound);
    expect_err(
        vault.delete(first.id, first.revision),
        VaultErrorKind::NotFound,
    );
    let third = expect_ok(vault.add(custom_draft()));
    assert!(third.id > 0);
    assert_ne!(third.id, first.id);
    assert_ne!(third.id, second.id);
    assert_eq!(expect_ok(vault.details(second.id)).summary.id, second.id);
}

#[test]
fn field_type_count_and_size_validation() {
    let (_dir, path) = temp_pair("validate.db");
    let mut vault = create_unlocked(&path, PASS);
    let seed = expect_ok(vault.add(custom_draft()));
    let intact = expect_ok(vault.details(seed.id));

    expect_err(
        vault.add(draft(
            "",
            CredentialKind::Custom,
            "",
            &[],
            vec![plain_field("label", "x")],
        )),
        VaultErrorKind::InvalidInput,
    );
    expect_err(
        vault.add(draft(
            "   ",
            CredentialKind::Custom,
            "",
            &[],
            vec![plain_field("label", "x")],
        )),
        VaultErrorKind::InvalidInput,
    );
    expect_err(
        vault.add(draft(
            &"t".repeat(129),
            CredentialKind::Custom,
            "",
            &[],
            vec![plain_field("label", "x")],
        )),
        VaultErrorKind::InvalidInput,
    );
    let titled = expect_ok(vault.add(draft(
        &"t".repeat(128),
        CredentialKind::Custom,
        "",
        &[],
        vec![plain_field("label", "x")],
    )));
    assert_eq!(titled.title.len(), 128);

    expect_err(
        vault.add(draft(
            "notes-over",
            CredentialKind::Custom,
            &"n".repeat(8193),
            &[],
            vec![plain_field("label", "x")],
        )),
        VaultErrorKind::InvalidInput,
    );
    let with_notes = expect_ok(vault.add(draft(
        "notes-max",
        CredentialKind::Custom,
        &"n".repeat(8192),
        &[],
        vec![plain_field("label", "x")],
    )));
    assert_eq!(expect_ok(vault.details(with_notes.id)).notes.len(), 8192);

    let tags_33: Vec<String> = (0..33).map(|i| format!("t{i}")).collect();
    let tag_refs_33: Vec<&str> = tags_33.iter().map(String::as_str).collect();
    expect_err(
        vault.add(draft(
            "too-many-tags",
            CredentialKind::Custom,
            "",
            &tag_refs_33,
            vec![plain_field("label", "x")],
        )),
        VaultErrorKind::InvalidInput,
    );
    let tags_32: Vec<String> = (0..32).map(|i| format!("t{i}")).collect();
    let tag_refs_32: Vec<&str> = tags_32.iter().map(String::as_str).collect();
    let with_tags = expect_ok(vault.add(draft(
        "max-tags",
        CredentialKind::Custom,
        "",
        &tag_refs_32,
        vec![plain_field("label", "x")],
    )));
    assert_eq!(expect_ok(vault.details(with_tags.id)).tags.len(), 32);

    expect_err(
        vault.add(draft(
            "empty-tag",
            CredentialKind::Custom,
            "",
            &[""],
            vec![plain_field("label", "x")],
        )),
        VaultErrorKind::InvalidInput,
    );
    expect_err(
        vault.add(draft(
            "long-tag",
            CredentialKind::Custom,
            "",
            &[&"x".repeat(65)],
            vec![plain_field("label", "x")],
        )),
        VaultErrorKind::InvalidInput,
    );
    let max_tag = expect_ok(vault.add(draft(
        "max-tag",
        CredentialKind::Custom,
        "",
        &[&"x".repeat(64)],
        vec![plain_field("label", "x")],
    )));
    assert_eq!(expect_ok(vault.details(max_tag.id)).tags[0].len(), 64);

    expect_err(
        vault.add(draft(
            "bad-field-name",
            CredentialKind::Custom,
            "",
            &[],
            vec![plain_field("bad-name", "x")],
        )),
        VaultErrorKind::InvalidInput,
    );
    expect_err(
        vault.add(draft(
            "spaced-field",
            CredentialKind::Custom,
            "",
            &[],
            vec![plain_field("bad name", "x")],
        )),
        VaultErrorKind::InvalidInput,
    );
    expect_err(
        vault.add(draft(
            "empty-field-name",
            CredentialKind::Custom,
            "",
            &[],
            vec![plain_field("", "x")],
        )),
        VaultErrorKind::InvalidInput,
    );
    expect_err(
        vault.add(draft(
            "long-field-name",
            CredentialKind::Custom,
            "",
            &[],
            vec![plain_field(&"f".repeat(65), "x")],
        )),
        VaultErrorKind::InvalidInput,
    );
    let max_name = expect_ok(vault.add(draft(
        "max-field-name",
        CredentialKind::Custom,
        "",
        &[],
        vec![plain_field(&"f".repeat(64), "x")],
    )));
    assert_eq!(
        expect_ok(vault.details(max_name.id)).fields[0].name.len(),
        64
    );

    expect_err(
        vault.add(draft(
            "long-field-value",
            CredentialKind::Custom,
            "",
            &[],
            vec![plain_field("label", &"v".repeat(65537))],
        )),
        VaultErrorKind::InvalidInput,
    );
    let max_value = expect_ok(vault.add(draft(
        "max-field-value",
        CredentialKind::Custom,
        "",
        &[],
        vec![plain_field("label", &"v".repeat(65536))],
    )));
    assert_eq!(
        expect_ok(vault.reveal(max_value.id, "label"))
            .expose()
            .len(),
        65536
    );

    let fields_65: Vec<Field> = (0..65)
        .map(|i| plain_field(&format!("field_{i}"), "v"))
        .collect();
    expect_err(
        vault.add(draft(
            "too-many-fields",
            CredentialKind::Custom,
            "",
            &[],
            fields_65,
        )),
        VaultErrorKind::InvalidInput,
    );
    let fields_64: Vec<Field> = (0..64)
        .map(|i| plain_field(&format!("field_{i}"), "v"))
        .collect();
    let max_fields = expect_ok(vault.add(draft(
        "max-fields",
        CredentialKind::Custom,
        "",
        &[],
        fields_64,
    )));
    assert_eq!(expect_ok(vault.details(max_fields.id)).fields.len(), 64);

    expect_err(
        vault.add(draft(
            "dup-fields",
            CredentialKind::Custom,
            "",
            &[],
            vec![plain_field("label", "a"), plain_field("label", "b")],
        )),
        VaultErrorKind::InvalidInput,
    );

    let oversized: Vec<Field> = (0..17)
        .map(|i| plain_field(&format!("blob_{i}"), &"x".repeat(65536)))
        .collect();
    expect_err(
        vault.add(draft(
            "payload-over",
            CredentialKind::Custom,
            "",
            &[],
            oversized,
        )),
        VaultErrorKind::InvalidInput,
    );

    expect_err(
        vault.add(draft(
            "api-missing",
            CredentialKind::ApiKey,
            "",
            &[],
            vec![plain_field("extra", "x")],
        )),
        VaultErrorKind::InvalidInput,
    );
    expect_err(
        vault.add(draft(
            "api-empty-token",
            CredentialKind::ApiKey,
            "",
            &[],
            vec![secret_field("token", "")],
        )),
        VaultErrorKind::InvalidInput,
    );
    expect_err(
        vault.add(draft(
            "api-token-not-secret",
            CredentialKind::ApiKey,
            "",
            &[],
            vec![plain_field("token", "x")],
        )),
        VaultErrorKind::InvalidInput,
    );
    expect_err(
        vault.add(draft(
            "api-token-case",
            CredentialKind::ApiKey,
            "",
            &[],
            vec![secret_field("Token", "x")],
        )),
        VaultErrorKind::InvalidInput,
    );

    expect_err(
        vault.add(draft(
            "login-missing-user",
            CredentialKind::Login,
            "",
            &[],
            vec![secret_field("password", "x")],
        )),
        VaultErrorKind::InvalidInput,
    );
    expect_err(
        vault.add(draft(
            "login-pass-not-secret",
            CredentialKind::Login,
            "",
            &[],
            vec![plain_field("username", "u"), plain_field("password", "p")],
        )),
        VaultErrorKind::InvalidInput,
    );

    expect_err(
        vault.add(draft(
            "ssh-missing",
            CredentialKind::SshKey,
            "",
            &[],
            vec![plain_field("public_key", "x")],
        )),
        VaultErrorKind::InvalidInput,
    );
    expect_err(
        vault.add(draft(
            "ssh-private-not-secret",
            CredentialKind::SshKey,
            "",
            &[],
            vec![plain_field("private_key", "k")],
        )),
        VaultErrorKind::InvalidInput,
    );
    expect_err(
        vault.add(draft(
            "ssh-phrase-not-secret",
            CredentialKind::SshKey,
            "",
            &[],
            vec![
                secret_field("private_key", "k"),
                plain_field("passphrase", "p"),
            ],
        )),
        VaultErrorKind::InvalidInput,
    );
    let ssh_ok = expect_ok(vault.add(draft(
        "ssh-no-phrase",
        CredentialKind::SshKey,
        "",
        &[],
        vec![secret_field("private_key", "k")],
    )));
    assert_eq!(ssh_ok.kind, CredentialKind::SshKey);

    expect_err(
        vault.add(draft(
            "db-missing-host",
            CredentialKind::Database,
            "",
            &[],
            vec![
                plain_field("database", "d"),
                plain_field("username", "u"),
                secret_field("password", "p"),
            ],
        )),
        VaultErrorKind::InvalidInput,
    );
    expect_err(
        vault.add(draft(
            "db-pass-not-secret",
            CredentialKind::Database,
            "",
            &[],
            vec![
                plain_field("host", "h"),
                plain_field("database", "d"),
                plain_field("username", "u"),
                plain_field("password", "p"),
            ],
        )),
        VaultErrorKind::InvalidInput,
    );

    expect_err(
        vault.add(draft(
            "custom-empty",
            CredentialKind::Custom,
            "",
            &[],
            vec![],
        )),
        VaultErrorKind::InvalidInput,
    );

    let after = expect_ok(vault.details(seed.id));
    assert_eq!(after, intact);
    assert_eq!(
        expect_ok(vault.reveal(seed.id, "blob")).expose(),
        FIELD_CUSTOM_SECRET
    );
}

#[test]
fn epochs_refresh_on_lock_unlock_reopen_and_restore() {
    let (dir, path) = temp_pair("epoch.db");
    let mut vault = create_locked(&path, PASS);
    let create_epoch = vault.epoch();
    expect_ok(vault.unlock(PASS));
    let unlocked = vault.epoch();
    assert_ne!(unlocked, create_epoch);
    let _ = expect_ok(vault.add(api_key_draft()));
    expect_ok(vault.lock());
    let locked = vault.epoch();
    assert_ne!(locked, unlocked);
    assert_ne!(locked, create_epoch);
    expect_ok(vault.unlock(PASS));
    let relocked = vault.epoch();
    assert_ne!(relocked, locked);
    let backup = dir.path().join("epoch.bak");
    expect_ok(vault.backup(&backup));
    let after_backup = vault.epoch();
    assert!(vault.is_locked());
    assert_ne!(after_backup, relocked);
    drop(vault);

    let mut reopened = expect_ok(Vault::open(&path));
    let open_epoch = reopened.epoch();
    assert_ne!(open_epoch, after_backup);
    expect_ok(reopened.unlock(PASS));
    let reopen_unlocked = reopened.epoch();
    assert_ne!(reopen_unlocked, open_epoch);
    drop(reopened);

    let dest = dir.path().join("epoch-restored.db");
    let restored = expect_ok(Vault::restore(&backup, &dest, PASS));
    assert!(restored.is_locked());
    let restore_epoch = restored.epoch();
    assert_ne!(restore_epoch, open_epoch);
    assert_ne!(restore_epoch, after_backup);
    assert_ne!(restore_epoch, create_epoch);
}

#[test]
fn backup_restore_passphrase_overwrite_and_source_bytes() {
    let (dir, path) = temp_pair("src.db");
    let mut vault = create_unlocked(&path, PASS);
    let items = add_all_kinds(&mut vault);
    let backup = dir.path().join("vault.bak");
    let existing = dir.path().join("existing.bak");
    fs::write(&existing, b"keep-backup").expect("write existing backup dest");
    expect_err(vault.backup(&existing), VaultErrorKind::AlreadyExists);
    assert!(
        vault.is_locked(),
        "backup must leave the source locked on copy failure"
    );
    assert_eq!(fs::read(&existing).expect("read existing"), b"keep-backup");
    expect_err(Vault::open(&path), VaultErrorKind::Busy);

    expect_ok(vault.unlock(PASS));
    expect_ok(vault.backup(&backup));
    assert!(vault.is_locked());
    expect_err(Vault::open(&path), VaultErrorKind::Busy);
    assert_file_omits(&backup, &all_canaries());
    assert_unix_mode_0600(&backup);
    let backup_bytes = fs::read(&backup).expect("read backup");
    drop(vault);

    let mut source = expect_ok(Vault::open(&path));
    expect_ok(source.unlock(PASS));
    assert_all_kinds(&source, &items);
    drop(source);

    let dest = dir.path().join("restored.db");
    expect_err(
        Vault::restore(&backup, &dest, WRONG_PASS),
        VaultErrorKind::WrongKeyOrCorrupt,
    );
    assert!(
        !dest.exists(),
        "wrong restore passphrase must not create the destination"
    );
    assert_eq!(
        fs::read(&backup).expect("backup after wrong restore"),
        backup_bytes
    );

    fs::write(&dest, b"keep-dest").expect("write restore dest");
    expect_err(
        Vault::restore(&backup, &dest, PASS),
        VaultErrorKind::AlreadyExists,
    );
    assert_eq!(
        fs::read(&dest).expect("dest after refused restore"),
        b"keep-dest"
    );
    assert_eq!(
        fs::read(&backup).expect("backup after refused restore"),
        backup_bytes
    );

    expect_err(
        Vault::restore(&backup, &backup, PASS),
        VaultErrorKind::AlreadyExists,
    );
    assert_eq!(
        fs::read(&backup).expect("backup after self restore"),
        backup_bytes
    );

    fs::remove_file(&dest).expect("remove placeholder dest");
    let mut restored = expect_ok(Vault::restore(&backup, &dest, PASS));
    assert!(restored.is_locked());
    assert_eq!(
        fs::read(&backup).expect("backup after success"),
        backup_bytes
    );
    expect_ok(restored.unlock(PASS));
    assert_all_kinds(&restored, &items);
}

#[test]
fn corrupted_encrypted_header_refuses_unlock() {
    let (_dir, path) = temp_pair("corrupt.db");
    {
        let mut vault = create_unlocked(&path, PASS);
        let _ = expect_ok(vault.add(api_key_draft()));
    }
    let mut bytes = fs::read(&path).expect("read vault for header corruption");
    assert!(
        bytes.len() > 64,
        "vault file is too small to corrupt an encrypted header"
    );
    for byte in bytes.iter_mut().take(64).skip(16) {
        *byte ^= 0xff;
    }
    fs::write(&path, bytes).expect("write corrupted header");
    let mut vault = expect_ok(Vault::open(&path));
    assert!(vault.is_locked());
    expect_err(vault.unlock(PASS), VaultErrorKind::WrongKeyOrCorrupt);
    assert!(vault.is_locked());
    expect_err(vault.search(TITLE_API), VaultErrorKind::Locked);
}

#[test]
fn unsupported_schema_refuses_unlock() {
    let (_dir, path) = temp_pair("schema.db");
    {
        let mut vault = create_unlocked(&path, PASS);
        let _ = expect_ok(vault.add(api_key_draft()));
    }
    inject_unsupported_schema(&path, PASS);
    let mut vault = expect_ok(Vault::open(&path));
    assert!(vault.is_locked());
    expect_err(vault.unlock(PASS), VaultErrorKind::UnsupportedSchema);
    assert!(vault.is_locked());
    expect_err(vault.search(TITLE_API), VaultErrorKind::Locked);
}

#[cfg(unix)]
#[test]
fn unix_mode_0600_and_symlink_refusal() {
    use std::os::unix::fs::symlink;

    let (dir, path) = temp_pair("mode.db");
    {
        let mut vault = create_unlocked(&path, PASS);
        let _ = expect_ok(vault.add(api_key_draft()));
        assert_unix_mode_0600(&path);
        assert_unix_mode_0600(&lock_sidecar(&path));
        let backup = dir.path().join("mode.bak");
        expect_ok(vault.backup(&backup));
        assert_unix_mode_0600(&backup);
    }

    let missing_target = dir.path().join("through-link.db");
    let create_link = dir.path().join("create-link.db");
    symlink(&missing_target, &create_link).expect("create symlink for Vault::create");
    assert_refused(
        Vault::create(&create_link, PASS),
        "create on a symlink target",
    );
    assert!(
        !missing_target.exists(),
        "create must not write through a symlink"
    );
    assert!(
        create_link
            .symlink_metadata()
            .expect("stat create symlink")
            .file_type()
            .is_symlink()
    );

    let mut vault = create_unlocked(&dir.path().join("backup-src.db"), PASS);
    let _ = expect_ok(vault.add(login_draft()));
    let backup_target = dir.path().join("backup-through.db");
    let backup_link = dir.path().join("backup-link.db");
    symlink(&backup_target, &backup_link).expect("create symlink for backup dest");
    assert_refused(
        vault.backup(&backup_link),
        "backup to a symlink destination",
    );
    assert!(
        !backup_target.exists(),
        "backup must not write through a symlink"
    );
}

#[test]
fn exclusive_second_open_is_busy() {
    let (_dir, path) = temp_pair("busy.db");
    let mut vault = create_unlocked(&path, PASS);
    let _ = expect_ok(vault.add(api_key_draft()));
    expect_err(Vault::open(&path), VaultErrorKind::Busy);
    expect_ok(vault.lock());
    expect_err(Vault::open(&path), VaultErrorKind::Busy);
    drop(vault);
    let mut reopened = expect_ok(Vault::open(&path));
    assert!(reopened.is_locked());
    expect_ok(reopened.unlock(PASS));
    expect_err(Vault::open(&path), VaultErrorKind::Busy);
}

#[test]
fn encrypted_artifacts_omit_credential_and_metadata_canaries() {
    let (dir, path) = temp_pair("canary.db");
    let mut vault = create_unlocked(&path, PASS);
    let items = add_all_kinds(&mut vault);
    let canaries = all_canaries();
    assert_file_omits(&path, &canaries);
    assert_omits_canaries(&lock_sidecar(&path), &canaries);
    let backup = dir.path().join("canary.bak");
    expect_ok(vault.backup(&backup));
    assert_file_omits(&path, &canaries);
    assert_file_omits(&backup, &canaries);
    drop(vault);
    assert_file_omits(&path, &canaries);
    assert_omits_canaries(&lock_sidecar(&path), &canaries);
    let restored_path = dir.path().join("canary-restored.db");
    let mut restored = expect_ok(Vault::restore(&backup, &restored_path, PASS));
    assert_file_omits(&restored_path, &canaries);
    assert_omits_canaries(&lock_sidecar(&restored_path), &canaries);
    expect_ok(restored.unlock(PASS));
    assert_all_kinds(&restored, &items);
}

#[test]
fn update_refuses_different_category() {
    let (_dir, path) = temp_pair("kind.db");
    let mut vault = create_unlocked(&path, PASS);
    let added = expect_ok(vault.add(api_key_draft()));
    let before = expect_ok(vault.details(added.id));
    let before_secret = expect_ok(vault.reveal(added.id, "token"));
    expect_err(
        vault.update(added.id, added.revision, login_draft()),
        VaultErrorKind::InvalidInput,
    );
    let after = expect_ok(vault.details(added.id));
    assert_eq!(after, before);
    assert_eq!(after.summary.kind, CredentialKind::ApiKey);
    assert_eq!(after.summary.revision, added.revision);
    assert_eq!(
        expect_ok(vault.reveal(added.id, "token")).expose(),
        before_secret.expose()
    );
    assert_eq!(
        expect_ok(vault.reveal(added.id, "token")).expose(),
        TOKEN_API
    );
}

#[test]
fn search_uses_unicode_lowercase_not_case_folding() {
    let (_dir, path) = temp_pair("unicode.db");
    let mut vault = create_unlocked(&path, PASS);
    let added = expect_ok(vault.add(draft(
        "VL1-UNI-Title-Café",
        CredentialKind::Custom,
        "VL1-UNI-Notes-Straße",
        &["VL1-UNI-Tag-Ångström"],
        vec![plain_field("label", "VL1-UNI-Field-Δέλτα")],
    )));

    let by_title_lower = expect_ok(vault.search("vl1-uni-title-café"));
    assert_eq!(by_title_lower.len(), 1);
    assert_eq!(by_title_lower[0].id, added.id);
    let by_title_upper = expect_ok(vault.search("VL1-UNI-TITLE-CAFÉ"));
    assert_eq!(by_title_upper.len(), 1);
    assert_eq!(by_title_upper[0].id, added.id);

    let by_notes = expect_ok(vault.search("vl1-uni-notes-straße"));
    assert_eq!(by_notes.len(), 1);
    assert_eq!(by_notes[0].id, added.id);
    let folded = expect_ok(vault.search("vl1-uni-notes-strasse"));
    assert!(
        folded.is_empty(),
        "search must use Unicode lowercase mapping, not full case folding"
    );

    let by_tag = expect_ok(vault.search("vl1-uni-tag-ångström"));
    assert_eq!(by_tag.len(), 1);
    assert_eq!(by_tag[0].id, added.id);
    let by_tag_upper = expect_ok(vault.search("VL1-UNI-TAG-ÅNGSTRÖM"));
    assert_eq!(by_tag_upper.len(), 1);

    let field_hits = expect_ok(vault.search("VL1-UNI-Field-Δέλτα"));
    assert!(
        field_hits.is_empty(),
        "search must not match a non-ASCII field value"
    );
    let delta_hits = expect_ok(vault.search("Δέλτα"));
    assert!(delta_hits.is_empty());
}

#[test]
fn lock_sidecar_persists_busy_and_live_restore() {
    let (dir, path) = temp_pair("sidecar.db");
    let sidecar = lock_sidecar(&path);
    let mut vault = create_unlocked(&path, PASS);
    let added = expect_ok(vault.add(api_key_draft()));
    assert!(
        sidecar.is_file(),
        "create must add a persistent lock sidecar"
    );
    assert_unix_mode_0600(&sidecar);
    assert_file_omits(&path, &all_canaries());
    assert_omits_canaries(&sidecar, &all_canaries());

    expect_ok(vault.lock());
    expect_err(vault.unlock(WRONG_PASS), VaultErrorKind::WrongKeyOrCorrupt);
    expect_err(vault.unlock(WRONG_PASS), VaultErrorKind::WrongKeyOrCorrupt);
    assert!(vault.is_locked());
    expect_err(Vault::open(&path), VaultErrorKind::Busy);

    expect_ok(vault.unlock(PASS));
    let existing = dir.path().join("existing.bak");
    fs::write(&existing, b"keep-backup").expect("write existing backup dest");
    expect_err(vault.backup(&existing), VaultErrorKind::AlreadyExists);
    assert!(vault.is_locked());
    expect_err(Vault::open(&path), VaultErrorKind::Busy);

    let live_bytes = fs::read(&path).expect("read live source");
    let live_dest = dir.path().join("from-live.db");
    expect_err(
        Vault::restore(&path, &live_dest, PASS),
        VaultErrorKind::Busy,
    );
    assert!(
        !live_dest.exists(),
        "Busy restore must not create the destination"
    );
    assert_eq!(
        fs::read(&path).expect("source after Busy restore"),
        live_bytes
    );

    expect_ok(vault.unlock(PASS));
    let backup = dir.path().join("sidecar.bak");
    expect_ok(vault.backup(&backup));
    drop(vault);

    assert!(sidecar.is_file(), "lock sidecar must persist after drop");
    assert_unix_mode_0600(&sidecar);
    assert_omits_canaries(&sidecar, &all_canaries());
    assert_file_omits(&path, &all_canaries());

    let mut reopened = expect_ok(Vault::open(&path));
    expect_ok(reopened.unlock(PASS));
    assert_eq!(
        expect_ok(reopened.reveal(added.id, "token")).expose(),
        TOKEN_API
    );
    drop(reopened);

    let dest = dir.path().join("sidecar-restored.db");
    let restored = expect_ok(Vault::restore(&backup, &dest, PASS));
    assert!(restored.is_locked());
    assert!(
        lock_sidecar(&dest).is_file(),
        "restore must create a dest lock sidecar"
    );
    assert_unix_mode_0600(&lock_sidecar(&dest));
    assert_omits_canaries(&lock_sidecar(&dest), &all_canaries());
}

#[cfg(unix)]
#[test]
fn unix_open_restore_symlinks_and_hardlinks_refused() {
    use std::os::unix::fs::symlink;

    let (dir, path) = temp_pair("links.db");
    let backup;
    {
        let mut vault = create_unlocked(&path, PASS);
        let _ = expect_ok(vault.add(api_key_draft()));
        backup = dir.path().join("links.bak");
        expect_ok(vault.backup(&backup));
    }
    let db_bytes = fs::read(&path).expect("read database");
    let backup_bytes = fs::read(&backup).expect("read backup");
    let sidecar = lock_sidecar(&path);

    let open_link = dir.path().join("open-link.db");
    symlink(&path, &open_link).expect("symlink database for open");
    assert_refused(Vault::open(&open_link), "open of a database symlink");
    assert_eq!(
        fs::read(&path).expect("database after open symlink"),
        db_bytes
    );
    assert!(
        open_link
            .symlink_metadata()
            .expect("stat open symlink")
            .file_type()
            .is_symlink()
    );

    let restore_src_link = dir.path().join("restore-src-link.bak");
    symlink(&backup, &restore_src_link).expect("symlink backup for restore source");
    let dest_from_src_link = dir.path().join("from-src-link.db");
    assert_refused(
        Vault::restore(&restore_src_link, &dest_from_src_link, PASS),
        "restore from a source symlink",
    );
    assert!(!dest_from_src_link.exists());
    assert_eq!(
        fs::read(&backup).expect("backup after source symlink"),
        backup_bytes
    );

    let restore_target = dir.path().join("restore-target-bytes.db");
    fs::write(&restore_target, b"keep-restore-dest").expect("write restore target");
    let restore_dest_link = dir.path().join("restore-dest-link.db");
    symlink(&restore_target, &restore_dest_link).expect("symlink restore destination");
    assert_refused(
        Vault::restore(&backup, &restore_dest_link, PASS),
        "restore onto a destination symlink",
    );
    assert_eq!(
        fs::read(&restore_target).expect("target after dest symlink"),
        b"keep-restore-dest"
    );
    assert_eq!(
        fs::read(&backup).expect("backup after dest symlink"),
        backup_bytes
    );

    let db_alias = dir.path().join("db-hard-alias.db");
    fs::hard_link(&path, &db_alias).expect("hard-link database");
    assert_refused(
        Vault::open(&db_alias),
        "open of a hard-linked database alias",
    );
    fs::remove_file(&db_alias).expect("remove owned database hard link");

    let lock_alias = dir.path().join("lock-hard-alias.lock");
    fs::hard_link(&sidecar, &lock_alias).expect("hard-link lock sidecar");
    assert_refused(
        Vault::open(&path),
        "open when the lock sidecar has an extra hard link",
    );
    fs::remove_file(&lock_alias).expect("remove owned lock sidecar hard link");

    let mut reopened = expect_ok(Vault::open(&path));
    assert!(reopened.is_locked());
    expect_ok(reopened.unlock(PASS));
    let hits = expect_ok(reopened.search(TITLE_API));
    assert_eq!(hits.len(), 1);
    assert_eq!(
        expect_ok(reopened.reveal(hits[0].id, "token")).expose(),
        TOKEN_API
    );
}

#[test]
fn later_page_corruption_and_unknown_schema_restore() {
    let (dir, path) = temp_pair("pages.db");
    let backup = dir.path().join("pages.bak");
    {
        let mut vault = create_unlocked(&path, PASS);
        expect_ok(vault.add(draft(
            "VL1-LARGE-title",
            CredentialKind::Custom,
            &"N".repeat(8192),
            &["largetag"],
            vec![plain_field("blob", &"D".repeat(16_384))],
        )));
        expect_ok(vault.backup(&backup));
    }
    let page = 4096;
    let mut db_bytes = fs::read(&path).expect("read large vault");
    assert!(
        db_bytes.len() > page * 3,
        "synthetic vault must span more than 3 pages, got {}",
        db_bytes.len()
    );
    let offset = page * 2;
    for byte in db_bytes.iter_mut().skip(offset).take(64) {
        *byte ^= 0xa5;
    }
    fs::write(&path, &db_bytes).expect("write later-page corruption");
    let mut corrupted = expect_ok(Vault::open(&path));
    expect_err(corrupted.unlock(PASS), VaultErrorKind::WrongKeyOrCorrupt);
    assert!(corrupted.is_locked());
    drop(corrupted);

    let mut backup_bytes = fs::read(&backup).expect("read large backup");
    assert!(
        backup_bytes.len() > page * 3,
        "synthetic backup must span more than 3 pages, got {}",
        backup_bytes.len()
    );
    for byte in backup_bytes.iter_mut().skip(offset).take(64) {
        *byte ^= 0xa5;
    }
    fs::write(&backup, &backup_bytes).expect("write later-page backup corruption");
    let dest = dir.path().join("from-corrupt.db");
    expect_err(
        Vault::restore(&backup, &dest, PASS),
        VaultErrorKind::WrongKeyOrCorrupt,
    );
    assert!(
        !dest.exists(),
        "corrupt restore must not create the destination"
    );

    let schema_src = dir.path().join("schema-src.db");
    {
        let mut vault = create_unlocked(&schema_src, PASS);
        let _ = expect_ok(vault.add(custom_draft()));
    }
    inject_unsupported_schema(&schema_src, PASS);
    let schema_dest = dir.path().join("schema-dest.db");
    expect_err(
        Vault::restore(&schema_src, &schema_dest, PASS),
        VaultErrorKind::UnsupportedSchema,
    );
    assert!(
        !schema_dest.exists(),
        "unknown schema restore must not create the destination"
    );
}

#[test]
fn special_sqlite_names_are_regular_files() {
    if env::var_os(ISOLATED_SPECIAL_PATH).is_some() {
        special_sqlite_names_child();
        return;
    }
    let dir = TempDir::new().expect("isolated cwd");
    let exe = env::current_exe().expect("current test executable");
    let output = Command::new(exe)
        .args([
            "special_sqlite_names_are_regular_files",
            "--exact",
            "--nocapture",
        ])
        .env(ISOLATED_SPECIAL_PATH, "1")
        .current_dir(dir.path())
        .output()
        .expect("spawn isolated path child");
    assert!(
        output.status.success(),
        "isolated child failed status={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn special_sqlite_names_child() {
    let memory = Path::new(":memory:");
    let uri = Path::new("file:synth.db");
    let mut memory_vault = create_unlocked(memory, PASS);
    let memory_item = expect_ok(memory_vault.add(api_key_draft()));
    let mut uri_vault = create_unlocked(uri, PASS);
    let uri_item = expect_ok(uri_vault.add(login_draft()));

    let cwd = env::current_dir().expect("child cwd");
    let memory_abs = cwd.join(":memory:");
    let uri_abs = cwd.join("file:synth.db");
    assert!(
        memory_abs.is_file(),
        ":memory: must be a regular encrypted file"
    );
    assert!(
        uri_abs.is_file(),
        "file: URI-shaped name must be a regular encrypted file"
    );
    assert_file_omits(&memory_abs, &all_canaries());
    assert_file_omits(&uri_abs, &all_canaries());
    assert!(lock_sidecar(&memory_abs).is_file());
    assert!(lock_sidecar(&uri_abs).is_file());
    assert_omits_canaries(&lock_sidecar(&memory_abs), &all_canaries());
    assert_omits_canaries(&lock_sidecar(&uri_abs), &all_canaries());

    let other = TempDir::new().expect("later cwd");
    env::set_current_dir(other.path()).expect("change child cwd");
    assert_eq!(
        expect_ok(memory_vault.reveal(memory_item.id, "token")).expose(),
        TOKEN_API
    );
    assert_eq!(
        expect_ok(uri_vault.reveal(uri_item.id, "password")).expose(),
        PASS_LOGIN
    );
    drop(memory_vault);
    drop(uri_vault);

    let mut memory_reopen = expect_ok(Vault::open(&memory_abs));
    expect_ok(memory_reopen.unlock(PASS));
    assert_eq!(
        expect_ok(memory_reopen.reveal(memory_item.id, "token")).expose(),
        TOKEN_API
    );
    let mut uri_reopen = expect_ok(Vault::open(&uri_abs));
    expect_ok(uri_reopen.unlock(PASS));
    assert_eq!(
        expect_ok(uri_reopen.reveal(uri_item.id, "password")).expose(),
        PASS_LOGIN
    );
}
