//! Interactive owner operations without a display, session bus or screen lock.
//! Every invocation requires a real terminal. No secrets in argv, stdout or logs.
use apassy::broker::{
    SharedVault,
    approvals::{OwnerAction, OwnerCheck, OwnerGate},
};
use apassy::owner::terminal;
use apassy::vault::{Field, ItemDraft, SecretValue, Vault};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const HELP: &str = "Usage: apassy owner <create|unlock|shell|list|add|backup|change-passphrase|keyring-enable|keyring-disable> VAULT [DEST]\nAll operations require an interactive terminal. unlock opens a session until lock, quit or EOF.\nOptional keyring unlock: apassy owner unlock-keyring VAULT. Passphrase is always the default.";

pub fn run(args: &[String]) -> i32 {
    if args.is_empty() || args == ["--help"] {
        println!("{HELP}");
        return 0;
    }
    match execute(args) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("apassy owner: {error}");
            1
        }
    }
}
fn execute(args: &[String]) -> Result<(), String> {
    let command = args.first().map(String::as_str).ok_or(HELP)?;
    let expected = if command == "backup" { 3 } else { 2 };
    if args.len() != expected
        || !matches!(
            command,
            "create"
                | "unlock"
                | "unlock-keyring"
                | "shell"
                | "list"
                | "add"
                | "backup"
                | "change-passphrase"
                | "keyring-enable"
                | "keyring-disable"
        )
    {
        return Err(HELP.into());
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(
            "Owner operations require an interactive terminal; redirected input is refused.".into(),
        );
    }
    let path = Path::new(&args[1]);
    if command == "create" {
        let pass = terminal::read_hidden_twice("New vault passphrase: ", "Repeat passphrase: ")
            .map_err(err)?;
        let mut vault = Vault::create(path, pass.expose()).map_err(err)?;
        vault.lock().map_err(err)?;
        println!("Vault created and locked.");
        return Ok(());
    }
    let mut vault = Vault::open(path).map_err(err)?;
    #[cfg(target_os = "linux")]
    if command == "unlock-keyring" {
        let pass = apassy::native::linux::read_passphrase(path)?;
        vault.unlock(&pass).map_err(err)?;
    } else {
        unlock(&mut vault)?;
    }
    #[cfg(not(target_os = "linux"))]
    unlock(&mut vault)?;
    let shared = Arc::new(Mutex::new(Some(vault)));
    if matches!(command, "shell" | "unlock" | "unlock-keyring") {
        println!(
            "Vault unlocked for this terminal session. Commands: list, add, backup PATH, change-passphrase, lock, quit. No browser or agent service is started."
        );
        loop {
            let line = read_line("apassy owner> ")?;
            let Some(line) = line else {
                break;
            };
            let (action, rest) = line.trim().split_once(' ').unwrap_or((line.trim(), ""));
            if matches!(action, "lock" | "quit" | "exit") {
                break;
            }
            if action.is_empty() {
                continue;
            }
            if let Err(error) = operation(&shared, action, (!rest.is_empty()).then_some(rest)) {
                eprintln!("apassy owner: {error}");
            }
            // Backup and passphrase changes intentionally lock the source, including
            // some failure paths. End this session rather than leave unusable commands.
            if shared
                .lock()
                .map_err(|_| "Vault session failed")?
                .as_ref()
                .is_none_or(Vault::is_locked)
            {
                break;
            }
        }
    } else {
        operation(&shared, command, args.get(2).map(String::as_str))?;
    }
    shared
        .lock()
        .map_err(|_| "Vault session failed")?
        .as_mut()
        .ok_or("No vault")?
        .lock()
        .map_err(err)?;
    println!("Vault locked.");
    Ok(())
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn unlock(vault: &mut Vault) -> Result<(), String> {
    let pass = terminal::read_hidden("Vault passphrase: ").map_err(err)?;
    vault.unlock(pass.expose()).map_err(err)
}
fn read_line(prompt: &str) -> Result<Option<String>, String> {
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(err)?;
    tty.write_all(prompt.as_bytes())
        .and_then(|_| tty.flush())
        .map_err(err)?;
    let mut line = String::new();
    let n = io::BufReader::new(tty.take(4098))
        .read_line(&mut line)
        .map_err(err)?;
    if line.len() > 4096 {
        return Err("Input is too long".into());
    }
    Ok((n > 0).then_some(line.trim_end_matches(['\r', '\n']).to_owned()))
}
fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| !apassy::text::is_hidden_char(*c))
        .collect()
}
fn operation(shared: &SharedVault, command: &str, argument: Option<&str>) -> Result<(), String> {
    // Backup confirmation uses the same action-bound, session-bound proof as the UI.
    let backup = if command == "backup" {
        let path = PathBuf::from(argument.ok_or("backup requires a destination")?);
        let action = OwnerAction::BackupVault { path };
        terminal::tell(&format!(
            "Confirm encrypted backup to {}",
            clean(argument.unwrap_or_default())
        ));
        let pass = terminal::read_hidden("Confirm with vault passphrase: ").map_err(err)?;
        let proof = OwnerGate::new(shared.clone(), None)
            .authorize(action.clone(), OwnerCheck::passphrase(pass.expose()))
            .map_err(|e| e.message())?;
        Some((action, proof))
    } else {
        None
    };
    let mut guard = shared.lock().map_err(|_| "Vault session failed")?;
    let vault = guard.as_mut().ok_or("No vault")?;
    match command {
        "list" => {
            for item in vault.search("").map_err(err)? {
                println!("{}\t{}\t{}", item.id, item.kind.label(), clean(&item.title));
            }
        }
        "add" => {
            let title = read_line("Item name: ")?.ok_or("Cancelled")?;
            let secret = terminal::read_hidden("Secret value: ").map_err(err)?;
            let item = vault
                .add(ItemDraft {
                    title,
                    kind: apassy::contracts::CredentialKind::Custom,
                    notes: String::new(),
                    tags: vec![],
                    fields: vec![Field {
                        name: "password".into(),
                        secret: true,
                        value: SecretValue::new(secret.expose().to_owned()),
                    }],
                })
                .map_err(err)?;
            println!("Added item {}.", item.id);
        }
        "backup" => {
            let (action, proof) = backup.ok_or("Missing backup proof")?;
            proof
                .check(&action, &vault.epoch())
                .map_err(|e| e.message())?;
            if let OwnerAction::BackupVault { path } = action {
                vault.backup(&path).map_err(err)?;
            }
            println!("Encrypted backup written.");
        }
        "change-passphrase" => {
            let current = terminal::read_hidden("Current passphrase: ").map_err(err)?;
            let new = terminal::read_hidden_twice("New passphrase: ", "Repeat new passphrase: ")
                .map_err(err)?;
            vault
                .change_passphrase(current.expose(), new.expose())
                .map_err(err)?;
            #[cfg(target_os = "linux")]
            if apassy::native::linux::delete_passphrase(vault.path()).is_err() {
                terminal::tell(
                    "If a keyring unlock item exists, remove it with owner keyring-disable. It contains the old passphrase.",
                );
            }
            println!("Passphrase changed. Old backups still require the old passphrase.");
        }
        #[cfg(target_os = "linux")]
        "keyring-enable" => {
            let consent = terminal::confirm(apassy::native::linux::KEYRING_WARNING);
            if !consent {
                return Err("Keyring storage cancelled".into());
            }
            let pass = terminal::read_hidden("Confirm vault passphrase: ").map_err(err)?;
            Vault::verify_passphrase_at(vault.path(), pass.expose()).map_err(err)?;
            apassy::native::linux::store_passphrase(vault.path(), pass.expose(), consent)?;
            println!("Keyring unlock enabled by explicit consent.");
        }
        #[cfg(target_os = "linux")]
        "keyring-disable" => {
            apassy::native::linux::delete_passphrase(vault.path())?;
            println!("Keyring unlock item removed.");
        }
        _ => return Err("Unknown owner command".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backup_proof_refuses_another_destination_and_a_locked_session() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owner.db");
        let mut vault = Vault::create(&path, "synthetic-owner-passphrase").unwrap();
        vault.unlock("synthetic-owner-passphrase").unwrap();
        let shared = Arc::new(Mutex::new(Some(vault)));
        let gate = OwnerGate::new(shared.clone(), None);
        let action = OwnerAction::BackupVault {
            path: dir.path().join("backup.db"),
        };
        assert!(
            gate.authorize(action.clone(), OwnerCheck::passphrase("wrong-passphrase"))
                .is_err()
        );
        let proof = gate
            .authorize(
                action.clone(),
                OwnerCheck::passphrase("synthetic-owner-passphrase"),
            )
            .unwrap();
        let mut guard = shared.lock().unwrap();
        let vault = guard.as_mut().unwrap();
        assert!(proof.check(&action, &vault.epoch()).is_ok());
        assert!(
            proof
                .check(
                    &OwnerAction::BackupVault {
                        path: dir.path().join("other.db")
                    },
                    &vault.epoch()
                )
                .is_err()
        );
        vault.lock().unwrap();
        assert!(proof.check(&action, &vault.epoch()).is_err());
    }
    #[test]
    fn terminal_names_strip_control_and_bidi_characters() {
        assert_eq!(clean("item\x1b[2J\u{202e}name"), "item[2Jname");
    }
}
