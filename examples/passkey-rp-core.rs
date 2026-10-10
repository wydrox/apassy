//! Synthetic RP verifier driver. Never opens a user's vault or exports a key.
//! This exercises cryptography and encrypted persistence, not a platform owner gate.

#[cfg(not(feature = "vault"))]
fn main() {
    eprintln!("passkey-rp-core requires --features vault");
    std::process::exit(2);
}

#[cfg(feature = "vault")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use apassy::vault::{
        Vault,
        passkey::{PasskeyCreate, PasskeyTarget},
    };
    use serde_json::{Value, json};
    use std::io::{BufRead, Write};

    const PASS: &str = "synthetic-passkey-rp-test-passphrase";
    let root = tempfile::tempdir()?;
    let path = root.path().join("synthetic.apassy");
    let mut vault = Vault::create(&path, PASS)?;
    vault.unlock(PASS)?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let request: Value = serde_json::from_str(&line?)?;
        let op = request["op"]
            .as_str()
            .ok_or("missing synthetic operation")?;
        let answer = match op {
            "create" => {
                let hash: [u8; 32] = bytes(&request["hash"])?
                    .try_into()
                    .map_err(|_| "bad hash length")?;
                let handle = bytes(&request["user_handle"])?;
                let rp = request["rp_id"].as_str().ok_or("missing rp_id")?;
                let made = vault.create_passkey(PasskeyCreate {
                    rp_id: rp,
                    user_handle: &handle,
                    user_name: "synthetic.user@example.test",
                    user_display_name: "Synthetic Test User",
                    client_data_hash: &hash,
                    algorithms: &[-7],
                    exclude: &[],
                    target: PasskeyTarget::NewItem {
                        title: "Synthetic RP".to_owned(),
                    },
                })?;
                json!({"ok": true, "id": made.item_id, "credential_id": made.credential_id,
                    "attestation_object": made.attestation_object})
            }
            "sign" => {
                let hash: [u8; 32] = bytes(&request["hash"])?
                    .try_into()
                    .map_err(|_| "bad hash length")?;
                let id = request["id"].as_u64().ok_or("missing synthetic item id")?;
                let rp = request["rp_id"].as_str().ok_or("missing rp_id")?;
                let credential_id = bytes(&request["credential_id"])?;
                match vault.sign_passkey(id, rp, &credential_id, &hash) {
                    Ok(signed) => json!({"ok": true, "credential_id": signed.credential_id,
                        "user_handle": signed.user_handle, "authenticator_data": signed.authenticator_data,
                        "signature": signed.signature}),
                    Err(_) => json!({"ok": false, "error": "sign_refused"}),
                }
            }
            "reopen" => {
                vault.lock()?;
                vault.unlock(PASS)?;
                json!({"ok": true})
            }
            "encrypted_roundtrip" => {
                let snapshot = root.path().join("synthetic-backup.apassy");
                vault.backup(&snapshot)?;
                let restored = root.path().join("synthetic-restored.apassy");
                vault = Vault::restore(&snapshot, &restored, PASS)?;
                vault.unlock(PASS)?;
                json!({"ok": true})
            }
            "quit" => break,
            _ => return Err("unknown synthetic operation".into()),
        };
        serde_json::to_writer(&mut stdout, &answer)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    vault.lock()?;
    Ok(())
}

#[cfg(feature = "vault")]
fn bytes(value: &serde_json::Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    value
        .as_array()
        .ok_or_else(|| "missing synthetic bytes".into())
        .and_then(|list| {
            list.iter()
                .map(|value| {
                    value
                        .as_u64()
                        .and_then(|n| u8::try_from(n).ok())
                        .ok_or_else(|| "invalid synthetic byte".into())
                })
                .collect()
        })
}
