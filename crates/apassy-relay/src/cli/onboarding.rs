//! New teams and pending device enrollment. Private keys precede network writes.

use std::time::{Duration, Instant};

use crate::api::{
    self, AccessGranted, JoinRequestRef, LinkRequestRef, Pending, TeamCreateRef, TeamCreated,
};
use crate::cli::client::{CALL_TIMEOUT, CallError, Client, Method};
use crate::cli::commands::{clean, read_secret};
use crate::cli::devicekey::{self, KeyStore};
use crate::cli::settings::{self, TeamSettings};
use crate::cli::{CliError, signin};
use crate::device::{self, DeviceKey};
use crate::ids::TeamId;
use crate::secret::SecretString;
use zeroize::Zeroizing;

fn body(value: &impl serde::Serialize) -> Result<Zeroizing<String>, CliError> {
    serde_json::to_string(value)
        .map(Zeroizing::new)
        .map_err(|_| CliError::usage("Cannot encode the request."))
}

pub fn device_name(name: Option<&str>) -> Result<String, CliError> {
    let name = match name {
        Some(name) => name.to_owned(),
        None => std::process::Command::new("/bin/hostname")
            .output()
            .ok()
            .filter(|out| out.status.success())
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|name| name.trim().to_owned())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "device".into()),
    };
    if name.is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
        return Err(CliError::usage(
            "The device name must have 1 to 64 bytes and no control character.",
        ));
    }
    Ok(name)
}

fn fresh(store: &dyn KeyStore, relay: &str, team: &TeamId) -> Result<(), CliError> {
    if settings::contains_team(team)? || store.load(relay, team)?.is_some() {
        return Err(CliError::usage(
            "This machine already has a key or settings for that team. Use another XDG_CONFIG_HOME for another member.",
        ));
    }
    Ok(())
}

pub fn create(relay: &str, team: &str, name: &str, device: Option<&str>) -> Result<i32, CliError> {
    let relay = settings::normalize_url(relay)?;
    let name_device = device_name(device)?;
    let code = read_secret(
        "the team code",
        "apassy-team create --relay URL --team NAME --name NAME < team-code-file",
    )?;
    let edge = settings::env_secret(settings::ENV_EDGE_SECRET);
    let client = Client::new(&relay, None, edge.as_ref());
    let key = DeviceKey::generate().map_err(|_| CliError::relay("Cannot make the device key."))?;
    let public = key.public_key_b64();
    // The relay assigns the real team id. Keep a recovery copy before it can create a team.
    let staging =
        TeamId::generate().map_err(|_| CliError::relay("Cannot make the recovery id."))?;
    let store = devicekey::store()?;
    store.save(&relay, &staging, &key)?;
    save_recovery(
        &staging,
        &serde_json::json!({"kind": "create", "relay_url": relay,
        "team": team, "member": name, "device_name": name_device}),
    )?;
    let payload = body(&TeamCreateRef {
        code: code.expose(),
        team,
        owner: name,
        device_name: Some(&name_device),
        public_key: Some(&public),
    })?;
    let finish = || -> Result<(TeamCreated, crate::ids::DeviceId), CliError> {
        let made: TeamCreated = client.ok(Method::Post, api::paths::TEAMS, Some(&payload))?;
        fresh(store.as_ref(), &relay, &made.team_id)?;
        let id = made
            .device_id
            .ok_or_else(|| CliError::relay("The relay did not return a device id."))?;
        store.save(&relay, &made.team_id, &key)?;
        settings::save_team(
            &made.team_id,
            &TeamSettings {
                relay_url: relay.clone(),
                team: team.into(),
                member: name.into(),
                device_id: Some(id),
                member_token: None,
                safety_verified: None,
            },
        )?;
        Ok((made, id))
    };
    let (made, id) = finish().inspect_err(|_| {
        eprintln!("The device key remains under recovery id {staging}. Ask the operator to check whether the team exists before another create request.");
    })?;
    store.remove(&relay, &staging)?;
    remove_recovery(&staging)?;
    println!(
        "Created team {} ({}). You are its owner {} (device {}).",
        clean(team),
        made.team_id,
        clean(name),
        id
    );
    Ok(0)
}

fn code_input(relay: &str, link: bool) -> Result<(SecretString, TeamId), CliError> {
    let input = read_secret(
        "the code or link",
        "apassy-team join --relay URL < code-file",
    )?;
    let text = input.expose().trim();
    let text = if text.contains("://") {
        let (origin, code) = text.split_once("/join#").ok_or_else(|| {
            CliError::usage("The link must have the form <relay URL>/join#<code>.")
        })?;
        if settings::normalize_url(origin)? != relay {
            return Err(CliError::usage(
                "The link uses another relay URL. Check --relay before you use the code.",
            ));
        }
        code
    } else {
        text
    };
    let prefix = if link { "apassy_lnk_" } else { "apassy_inv_" };
    let rest = text
        .strip_prefix(prefix)
        .ok_or_else(|| CliError::usage("The code is not valid for this command."))?;
    let (id, suffix) = rest
        .rsplit_once('_')
        .ok_or_else(|| CliError::usage("The code has no team id."))?;
    let id = TeamId::parse(id).ok_or_else(|| CliError::usage("The code has no valid team id."))?;
    if suffix.len() != 64
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(CliError::usage("The code is not valid."));
    }
    Ok((SecretString::new(text.into()), id))
}

fn save_granted(relay: &str, granted: AccessGranted) -> Result<i32, CliError> {
    settings::save_team(
        &granted.team_id,
        &TeamSettings {
            relay_url: relay.into(),
            team: granted.team.clone(),
            member: granted.member_name.clone(),
            device_id: Some(granted.device_id),
            member_token: None,
            safety_verified: None,
        },
    )?;
    remove_recovery(&granted.team_id)?;
    println!(
        "Joined {} as {} (device {})",
        clean(&granted.team),
        clean(&granted.member_name),
        granted.device_id
    );
    Ok(0)
}

fn wait(client: &Client, id: &TeamId, key: &DeviceKey, no_wait: bool) -> Result<i32, CliError> {
    if no_wait {
        eprintln!(
            "The request waits for confirmation. Use `apassy-team join --resume` to wait again."
        );
        return Ok(0);
    }
    let deadline = Instant::now() + Duration::from_secs(600);
    loop {
        let started = Instant::now();
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(CliError::denied(
                "The confirmation did not arrive within 10 minutes. Use `apassy-team join --resume` to wait again.",
            ));
        }
        match signin::sign_in_timeout(client, id, key, remaining.min(CALL_TIMEOUT)) {
            Ok(granted) => {
                if Instant::now() >= deadline {
                    return Err(CliError::denied(
                        "The confirmation did not arrive within 10 minutes. Use `apassy-team join --resume` to wait again.",
                    ));
                }
                if &granted.team_id != id {
                    return Err(CliError::relay("The relay returned another team id."));
                }
                return save_granted(client.base(), granted);
            }
            Err(CallError::Api(error)) if error.code == "join_pending" => {}
            Err(CallError::Api(error)) if error.code == "join_refused" => {
                return Err(CliError::denied(
                    "The join or device link was refused or expired. Ask for a new code.",
                ));
            }
            Err(error) => return Err(error.into_cli()),
        }
        if Instant::now() >= deadline {
            return Err(CliError::denied(
                "The confirmation did not arrive within 10 minutes. Use `apassy-team join --resume` to wait again.",
            ));
        }
        std::thread::sleep(
            Duration::from_secs(5)
                .saturating_sub(started.elapsed())
                .min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Recovery {
    name: Option<String>,
    device_name: String,
    link: bool,
    blocked: bool,
}

fn recovery_path(id: &TeamId) -> Result<std::path::PathBuf, CliError> {
    Ok(settings::settings_dir()?.join(format!("recovery-{id}.json")))
}

pub(crate) fn remove_recovery(id: &TeamId) -> Result<(), CliError> {
    match std::fs::remove_file(recovery_path(id)?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CliError::relay("Cannot remove the request recovery file.")),
    }
}

fn save_recovery(id: &TeamId, recovery: &impl serde::Serialize) -> Result<(), CliError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = recovery_path(id)?;
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|_| CliError::relay("Cannot create the request recovery file."))?;
    let payload = body(recovery)?;
    let result = file
        .write_all(payload.as_bytes())
        .and_then(|_| file.sync_all())
        .and_then(|_| std::fs::rename(&tmp, &path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(|_| CliError::relay("Cannot save the request recovery file."))
}

fn submit(
    client: &Client,
    id: &TeamId,
    key: &DeviceKey,
    code: &SecretString,
    recovery: &mut Recovery,
    no_wait: bool,
) -> Result<i32, CliError> {
    let public = key.public_key_b64();
    let (path, payload) = if recovery.link {
        (
            api::paths::DEVICE_LINK,
            body(&LinkRequestRef {
                code: code.expose(),
                device_name: &recovery.device_name,
                public_key: &public,
            })?,
        )
    } else {
        (
            api::paths::JOIN,
            body(&JoinRequestRef {
                code: code.expose(),
                name: recovery.name.as_deref(),
                device_name: &recovery.device_name,
                public_key: &public,
            })?,
        )
    };
    let pending: Pending = match client.call(Method::Post, path, Some(&payload), CALL_TIMEOUT) {
        Ok(pending) => pending,
        Err(CallError::Transport(_) | CallError::Unsent(_)) => {
            // Probe first, then replay even if confirmation already arrived. The Pending
            // response must pass the safety comparison before this process signs in.
            match signin::challenge(client, id, key) {
                Ok(_) => {}
                Err(CallError::Api(error))
                    if error.code == "join_pending" || error.code == "unauthenticated" => {}
                Err(CallError::Api(error)) if error.code == "join_refused" => {
                    return Err(CliError::denied(
                        "The join or device link was refused or expired.",
                    ));
                }
                Err(error) => return Err(error.into_cli()),
            }
            client
                .call(Method::Post, path, Some(&payload), CALL_TIMEOUT)
                .map_err(CallError::into_cli)?
        }
        Err(error) => return Err(error.into_cli()),
    };
    let safety = device::safety_words(id, code.expose(), &key.public_key());
    if &pending.team_id != id || pending.safety != safety {
        recovery.blocked = true;
        save_recovery(id, recovery)?;
        return Err(CliError::usage(
            "The relay safety words differ from this device's words. Stop and tell the person who gave you the code.",
        ));
    }
    settings::save_team(
        id,
        &TeamSettings {
            relay_url: client.base().into(),
            team: pending.team.clone(),
            member: recovery.name.as_deref().unwrap_or("").into(),
            device_id: None,
            member_token: None,
            safety_verified: Some(true),
        },
    )?;
    println!(
        "Team {} ({}), from {}. Safety words: {}",
        clean(&pending.team),
        id,
        clean(&pending.by),
        safety
    );
    eprintln!("Tell {} these words: {}", clean(&pending.by), safety);
    wait(client, id, key, no_wait)
}

// The last boolean selects /join or /devices/link. Both retain the key on retries.
#[allow(clippy::too_many_arguments)]
pub fn join(
    relay: Option<&str>,
    name: Option<&str>,
    device: Option<&str>,
    no_wait: bool,
    resume: bool,
    selected: Option<&str>,
    link: bool,
) -> Result<i32, CliError> {
    let store = devicekey::store()?;
    if resume {
        let config = settings::load_for(selected)?;
        let id = config.team_id.as_ref().ok_or_else(|| {
            CliError::usage("No team to resume. Select a saved team with --team ID.")
        })?;
        let relay = config.relay()?;
        let key = store
            .load(relay, id)?
            .ok_or_else(|| CliError::usage("No saved device key for this team."))?;
        let client = Client::new(relay, None, config.edge_secret.as_ref());
        if config.safety_verified == Some(false) {
            let text = std::fs::read_to_string(recovery_path(id)?).map_err(|_| {
                CliError::usage(
                    "The request recovery file is missing. Do not replace the saved device key.",
                )
            })?;
            let mut recovery: Recovery = serde_json::from_str(&text)
                .map_err(|_| CliError::usage("The request recovery file is not valid."))?;
            if recovery.blocked {
                return Err(CliError::usage(
                    "The safety comparison failed. Stop and tell the person who gave you the code.",
                ));
            }
            eprintln!(
                "The request needs a safety check. Supply the original code or link on stdin to resume with the saved key."
            );
            let (code, code_id) = code_input(relay, recovery.link)?;
            if &code_id != id {
                return Err(CliError::usage("The code is for another team."));
            }
            return submit(&client, id, &key, &code, &mut recovery, false);
        }
        return wait(&client, id, &key, false);
    }
    let relay =
        settings::normalize_url(relay.ok_or_else(|| CliError::usage("--relay is required."))?)?;
    let (code, id) = code_input(&relay, link)?;
    fresh(store.as_ref(), &relay, &id)?;
    let mut recovery = Recovery {
        name: name.map(str::to_owned),
        device_name: device_name(device)?,
        link,
        blocked: false,
    };
    let key = DeviceKey::generate().map_err(|_| CliError::relay("Cannot make the device key."))?;
    store.save(&relay, &id, &key)?;
    save_recovery(&id, &recovery)?;
    settings::save_team(
        &id,
        &TeamSettings {
            relay_url: relay.clone(),
            team: id.to_string(),
            member: name.unwrap_or("").into(),
            device_id: None,
            member_token: None,
            safety_verified: Some(false),
        },
    )?;
    let edge = settings::env_secret(settings::ENV_EDGE_SECRET);
    let client = Client::new(&relay, None, edge.as_ref());
    submit(&client, &id, &key, &code, &mut recovery, no_wait)
}
