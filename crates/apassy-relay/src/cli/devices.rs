//! Device and member administration. Lists never show safety words or secrets.

use serde::Serialize;
use zeroize::Zeroizing;

use crate::api::{
    self, ConfirmRequest, Created, DeviceEnroll, DeviceView, JoinConfirmed, JoinView, LinkCreated,
    LinkView, MeView, MemberView, PrincipalKind, Role, RoleChange,
};
use crate::cli::CliError;
use crate::cli::args::Command;
use crate::cli::client::{CALL_TIMEOUT, CallError, Client, Method, parse_reply};
use crate::cli::commands::{clean, fmt_time, print_json, table};
use crate::cli::devicekey;
use crate::cli::settings::{self, Settings, TeamSettings};
use crate::device::DeviceKey;

pub fn execute(settings: &Settings, command: Command) -> Result<(), CliError> {
    use api::paths;
    if let Command::DeviceEnroll { name } = command {
        return enroll(settings, name);
    }
    let client = Client::member(settings)?;
    match command {
        Command::DeviceList { json } => {
            let devices: Vec<DeviceView> = client.ok(Method::Get, paths::DEVICES, None)?;
            if json || crate::cli::output::enabled() {
                return print_json(&devices);
            }
            table(
                &[
                    "ID",
                    "MEMBER",
                    "NAME",
                    "CURRENT",
                    "KEY HOLDER",
                    "CREATED",
                    "LAST SEEN",
                ],
                devices
                    .iter()
                    .map(|d| {
                        vec![
                            d.id.to_string(),
                            clean(&d.member_name),
                            clean(&d.name),
                            yes(d.current),
                            yes(d.key_holder),
                            fmt_time(d.created_at),
                            d.last_seen_at.map_or_else(|| "-".to_owned(), fmt_time),
                        ]
                    })
                    .collect(),
            );
        }
        Command::DeviceRevoke { id } => {
            let _: Created =
                client.ok(Method::Delete, &format!("{}/{id}", paths::DEVICES), None)?;
            crate::cli::output::result(&serde_json::json!({"id":id}))?;
            println!("Revoked device {id}.");
        }
        Command::DeviceKeyHolder { id } => {
            eprintln!("Copy keys.json to the target device before you change the key holder.");
            let device: DeviceView = client.ok(
                Method::Post,
                &format!("{}/{id}/key-holder", paths::DEVICES),
                None,
            )?;
            crate::cli::output::result(&device)?;
            println!(
                "Device {} ({}) is the key holder.",
                device.id,
                clean(&device.name)
            );
        }
        Command::DeviceAdd => {
            let link: LinkCreated = client.ok(Method::Post, paths::DEVICE_LINKS, None)?;
            crate::cli::output::secret("code", link.secret.expose())?;
            eprintln!("Save the link code in a private file.");
            eprintln!(
                "On the new device, run: apassy-team device link --relay {} < link-code-file",
                clean(client.base())
            );
            eprintln!(
                "The link expires at {}. Compare the safety words before you confirm the device.",
                fmt_time(link.expires_at)
            );
        }
        Command::DevicePending { json } => {
            let links: Vec<LinkView> = client.ok(Method::Get, paths::DEVICE_LINKS, None)?;
            if json || crate::cli::output::enabled() {
                return print_json(&links);
            }
            table(
                &["ID", "DEVICE", "CREATED", "EXPIRES"],
                links
                    .iter()
                    .map(|link| {
                        vec![
                            link.id.to_string(),
                            clean(&link.device_name),
                            fmt_time(link.created_at),
                            fmt_time(link.expires_at),
                        ]
                    })
                    .collect(),
            );
        }
        Command::DeviceConfirm { id, words } => {
            let links: Vec<LinkView> = client.ok(Method::Get, paths::DEVICE_LINKS, None)?;
            let link = links
                .iter()
                .find(|link| link.id == id)
                .ok_or_else(|| CliError::usage(format!("There is no pending device link {id}.")))?;
            println!(
                "Confirm device {} with safety words: {}.",
                clean(&link.device_name),
                clean(&words)
            );
            let payload = body(&ConfirmRequest { safety: words })?;
            let device: DeviceView = client.ok(
                Method::Post,
                &format!("{}/{id}/confirm", paths::DEVICE_LINKS),
                Some(&payload),
            )?;
            crate::cli::output::result(&device)?;
            println!("Confirmed device {} ({}).", device.id, clean(&device.name));
        }
        Command::DeviceRefuse { id } => {
            let _: Created = client.ok(
                Method::Post,
                &format!("{}/{id}/refuse", paths::DEVICE_LINKS),
                None,
            )?;
            crate::cli::output::result(&serde_json::json!({"id":id}))?;
            println!("Refused device link {id}.");
        }
        Command::Joins { json } => {
            let joins: Vec<JoinView> = client.ok(Method::Get, paths::JOINS, None)?;
            if json || crate::cli::output::enabled() {
                return print_json(&joins);
            }
            table(
                &[
                    "ID",
                    "NAME",
                    "DEVICE",
                    "ROLE",
                    "SHARED",
                    "GRANTS",
                    "INVITED BY",
                    "EXPIRES",
                ],
                joins
                    .iter()
                    .map(|join| {
                        vec![
                            join.id.to_string(),
                            clean(&join.name),
                            clean(&join.device_name),
                            role_word(join.role).to_owned(),
                            yes(join.shared),
                            clean(&join.grants.join(", ")),
                            clean(&join.invited_by),
                            fmt_time(join.expires_at),
                        ]
                    })
                    .collect(),
            );
        }
        Command::Confirm { id, words } => {
            let joins: Vec<JoinView> = client.ok(Method::Get, paths::JOINS, None)?;
            let join = joins
                .iter()
                .find(|join| join.id == id)
                .ok_or_else(|| CliError::usage(format!("There is no pending join {id}.")))?;
            println!(
                "Confirm member {} on device {} with safety words: {}.",
                clean(&join.name),
                clean(&join.device_name),
                clean(&words)
            );
            let payload = body(&ConfirmRequest { safety: words })?;
            let confirmed: JoinConfirmed = client.ok(
                Method::Post,
                &format!("{}/{id}/confirm", paths::JOINS),
                Some(&payload),
            )?;
            crate::cli::output::result(
                &serde_json::json!({"member_id":confirmed.member_id,"device_id":confirmed.device_id}),
            )?;
            println!(
                "Confirmed member {} ({}) with device {}.",
                clean(&join.name),
                confirmed.member_id,
                confirmed.device_id
            );
        }
        Command::Refuse { id } => {
            let _: Created =
                client.ok(Method::Post, &format!("{}/{id}/refuse", paths::JOINS), None)?;
            crate::cli::output::result(&serde_json::json!({"id":id}))?;
            println!("Refused join {id}.");
        }
        Command::Leave => {
            let me: MeView = client.ok(Method::Get, paths::ME, None)?;
            let team = me
                .team_id
                .ok_or_else(|| CliError::usage("The relay did not return a team id."))?;
            let keys = devicekey::store()?;
            settings::migrate_legacy()?;
            let _: Created = client.ok(Method::Post, paths::LEAVE, None)?;
            keys.remove(client.base(), &team)?;
            settings::remove_team(&team)?;
            crate::cli::onboarding::remove_recovery(&team)?;
            crate::cli::output::result(&serde_json::json!({"team_id":team}))?;
            println!("Left team {} ({}).", clean(&me.team), team);
        }
        Command::MemberRole { id, role } => {
            let payload = body(&RoleChange { role })?;
            let member: MemberView = client.ok(
                Method::Put,
                &format!("{}/{id}/role", paths::MEMBERS),
                Some(&payload),
            )?;
            crate::cli::output::result(&member)?;
            println!(
                "Member {} ({}) has role {}.",
                clean(&member.name),
                member.id,
                role_word(member.role)
            );
        }
        _ => return Err(CliError::usage("This is not a device or member command.")),
    }
    Ok(())
}

fn enroll(settings: &Settings, name: Option<String>) -> Result<(), CliError> {
    let relay = settings.relay()?;
    let keys = devicekey::store()?;
    let entries = settings::list()?;
    // Probe a saved key before using a member token: a lost enrollment answer
    // can leave the file with a token that the relay already invalidated.
    let selected = settings.team_id.clone().or_else(|| {
        settings.member_token.as_ref().and_then(|token| {
            crate::secret::parse_token(token.expose()).and_then(|parsed| parsed.team)
        })
    });
    let mut candidates = entries.iter().filter(|(id, entry)| {
        if let Some(selected) = &selected {
            id == selected
        } else {
            entry.device_id.is_none() && entry.relay_url == relay
        }
    });
    let candidate = candidates.next();
    if selected.is_none() && candidates.next().is_some() {
        return Err(CliError::usage(
            "More than one team has a pending device. Use --team ID to select the team.",
        ));
    }
    let mut resumed_key = None;
    if let Some((id, entry)) = candidate {
        if entry.safety_verified == Some(false) {
            return Err(CliError::usage(
                "This key belongs to a join that needs a safety check. Use join --resume with the original code.",
            ));
        }
        if entry.device_id.is_some() {
            return Err(CliError::usage(format!(
                "This machine already has a device for team {id}. Use another XDG_CONFIG_HOME."
            )));
        }
        if let Some(key) = keys.load(relay, id)? {
            let auth = Client::new(relay, None, settings.edge_secret.as_ref());
            match crate::cli::signin::challenge(&auth, id, &key) {
                Ok(challenge) => {
                    let granted =
                        crate::cli::signin::sign_in_with_challenge(&auth, id, &key, challenge)
                            .map_err(CallError::into_cli)?;
                    let saved = TeamSettings {
                        relay_url: relay.into(),
                        team: granted.team,
                        member: granted.member_name,
                        device_id: Some(granted.device_id),
                        member_token: None,
                        safety_verified: entry.safety_verified,
                    };
                    settings::save_team(id, &saved, false)?;
                    crate::cli::output::result(
                        &serde_json::json!({"team_id":id,"device_id":granted.device_id}),
                    )?;
                    println!("Enrolled device {} for team {}.", granted.device_id, id);
                    return Ok(());
                }
                Err(CallError::Api(error))
                    if error.status == 401 && error.code == "unauthenticated" =>
                {
                    resumed_key = Some((id.clone(), key));
                }
                Err(error) => return Err(error.into_cli()),
            }
        }
    }
    // This endpoint accepts a legacy member token, not an access token.
    let client = Client::new(
        relay,
        Some(settings.member()?),
        settings.edge_secret.as_ref(),
    );
    let me: MeView = client.ok(Method::Get, api::paths::ME, None)?;
    if me.kind != PrincipalKind::Member {
        return Err(CliError::usage("Device enrollment needs a member token."));
    }
    let team = me
        .team_id
        .ok_or_else(|| CliError::usage("The relay did not return a team id."))?;
    if selected.as_ref().is_some_and(|id| id != &team) {
        return Err(CliError::usage("The member token is for another team."));
    }
    let existing = entries
        .into_iter()
        .find(|(id, _)| id == &team)
        .map(|(_, entry)| entry);
    if existing
        .as_ref()
        .is_some_and(|entry| entry.device_id.is_some())
    {
        return Err(CliError::usage(format!(
            "This machine already has a device for team {team}. Use another XDG_CONFIG_HOME."
        )));
    }
    let name = crate::cli::onboarding::device_name(name.as_deref())?;
    let key = match resumed_key {
        Some((id, key)) if id == team => key,
        Some(_) => return Err(CliError::usage("The saved key is for another team.")),
        None => match keys.load(relay, &team)? {
            Some(_) => {
                return Err(CliError::usage(
                    "Select the saved device key with --team ID, then run device enroll again.",
                ));
            }
            None => {
                let key = DeviceKey::generate()
                    .map_err(|_| CliError::relay("Cannot create the device key."))?;
                keys.save(relay, &team, &key)?;
                key
            }
        },
    };
    let payload = body(&DeviceEnroll {
        name,
        public_key: key.public_key_b64(),
    })?;
    let mut saved = existing.unwrap_or(TeamSettings {
        relay_url: relay.to_owned(),
        team: me.team,
        member: me.member_name,
        device_id: None,
        member_token: None,
        safety_verified: None,
    });
    settings::save_team(&team, &saved, false)?;
    let reply = match client.raw(
        Method::Post,
        api::paths::DEVICE_ENROLL,
        Some(&payload),
        None,
        CALL_TIMEOUT,
    ) {
        Ok(reply) => reply,
        Err(error) => {
            if error
                .status
                .is_some_and(|status| !(200..300).contains(&status))
            {
                keys.remove(relay, &team)?;
                return Err(CliError::relay(error.message));
            }
            return Err(CliError::relay(format!(
                "{} The device key is saved. Run `apassy-team device enroll` again to check enrollment for team {team}.",
                error.message
            )));
        }
    };
    if !(200..300).contains(&reply.status) {
        keys.remove(relay, &team)?;
        let error = match parse_reply::<DeviceView>(reply.status, &reply.body) {
            Err(error) => error.into_cli(),
            Ok(_) => CliError::relay(format!("The relay answered with HTTP {}.", reply.status)),
        };
        return Err(error);
    }
    let device: DeviceView = match parse_reply(reply.status, &reply.body) {
        Ok(device) => device,
        Err(error @ CallError::Api(_)) => {
            keys.remove(relay, &team)?;
            return Err(error.into_cli());
        }
        Err(error) => {
            let error = error.into_cli();
            return Err(CliError {
                message: format!(
                    "{} The device key is saved. Run `apassy-team device enroll` again to check enrollment for team {team}.",
                    error.message
                ),
                ..error
            });
        }
    };
    saved.device_id = Some(device.id);
    saved.member_token = None;
    settings::save_team(&team, &saved, false)?;
    crate::cli::output::result(&serde_json::json!({"team_id":team,"device_id":device.id}))?;
    println!(
        "Enrolled device {} ({}) for team {}.",
        device.id,
        clean(&device.name),
        team
    );
    Ok(())
}

fn body<T: Serialize>(value: &T) -> Result<Zeroizing<String>, CliError> {
    serde_json::to_string(value)
        .map(Zeroizing::new)
        .map_err(|_| CliError::usage("Cannot encode the request."))
}

fn yes(value: bool) -> String {
    if value { "yes" } else { "no" }.to_owned()
}

fn role_word(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Manager => "manager",
        Role::Member => "member",
    }
}
