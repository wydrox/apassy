//! A private, synthetic vault for signed desktop/browser acceptance checks.
//! Never reads an existing vault. The public test passphrase is not a user secret.

#[cfg(not(feature = "vault"))]
fn main() {
    eprintln!("passkey-native-fixture requires --features vault");
    std::process::exit(2);
}

#[cfg(feature = "vault")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use apassy::contracts::CredentialKind;
    use apassy::vault::{Field, ItemDraft, SecretValue, Vault};
    use apassy::vaults::Registry;

    const PASS: &str = "synthetic-native-acceptance-passphrase";
    let root = tempfile::Builder::new()
        .prefix("apassy-native-test-")
        .tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let path = root.path().join("synthetic.apassy");
    let mut vault = Vault::create(&path, PASS)?;
    vault.unlock(PASS)?;
    let field = |name: &str, value: &str, secret| Field {
        name: name.to_owned(),
        value: SecretValue::new(value.to_owned()),
        secret,
    };
    let code_field = "One-time password"
        .bytes()
        .fold(String::from("x_"), |mut name, byte| {
            use std::fmt::Write;
            write!(&mut name, "{byte:02x}").expect("write to string");
            name
        });
    let login = vault.add(ItemDraft {
        title: "Synthetic native code test".to_owned(),
        kind: CredentialKind::Login,
        notes: String::new(),
        tags: vec!["synthetic".to_owned()],
        fields: vec![
            field("username", "synthetic.user@example.test", false),
            field("password", "synthetic-native-password", true),
            field("website", "http://localhost", false),
            field(&code_field, "JBSWY3DPEHPK3PXP", true),
        ],
    })?;
    vault.lock()?;
    let mut registry = Registry::new();
    let id = registry.add("Synthetic native test", &path, 1)?;
    registry.mark_opened(&id, 1)?;
    registry.save(root.path())?;
    let data_dir = root.keep();
    println!(
        "{}",
        serde_json::json!({"data_dir": data_dir, "vault": path, "login_id": login.id})
    );
    Ok(())
}
