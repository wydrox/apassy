//! Device and member administration. Lists never show safety words or secrets.

use serde::Serialize;
use zeroize::Zeroizing;

use crate::api::{
    self, ConfirmRequest, Created, DeviceEnroll, DeviceView, JoinConfirmed, JoinView, LinkCreated,
    LinkView, MeView, MemberView, PrincipalKind, Role, RoleChange,
};
use crate::cli::CliError;
use crate::cli::args::Command;
use crate::cli::client::{Client, Method};
use crate::cli::commands::{clean, print_json, table};
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
            if json {
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
                            d.created_at.to_string(),
                            d.last_seen_at
                                .map_or_else(|| "-".to_owned(), |at| at.to_string()),
                        ]
                    })
                    .collect(),
            );
        }
        Command::DeviceRevoke { id } => {
            let _: Created =
                client.ok(Method::Delete, &format!("{}/{id}", paths::DEVICES), None)?;
            println!("Revoked device {id}.");
        }
        Command::DeviceKeyHolder { id } => {
            eprintln!("Copy keys.json to the target device before you change the key holder.");
            let device: DeviceView = client.ok(
                Method::Post,
                &format!("{}/{id}/key-holder", paths::DEVICES),
                None,
            )?;
            println!(
                "Device {} ({}) is the key holder.",
                device.id,
                clean(&device.name)
            );
        }
        Command::DeviceAdd => {
            let link: LinkCreated = client.ok(Method::Post, paths::DEVICE_LINKS, None)?;
            println!("{}", link.secret.expose());
            eprintln!("Save the link code in a private file.");
            eprintln!(
                "On the new device, run: apassy-team device link --relay {} < link-code-file",
                clean(client.base())
            );
            eprintln!(
                "The link expires at {}. Compare the safety words before you confirm the device.",
                link.expires_at
            );
        }
        Command::DevicePending { json } => {
            let links: Vec<LinkView> = client.ok(Method::Get, paths::DEVICE_LINKS, None)?;
            if json {
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
                            link.created_at.to_string(),
                            link.expires_at.to_string(),
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
            println!("Confirmed device {} ({}).", device.id, clean(&device.name));
        }
        Command::DeviceRefuse { id } => {
            let _: Created = client.ok(
                Method::Post,
                &format!("{}/{id}/refuse", paths::DEVICE_LINKS),
                None,
            )?;
            println!("Refused device link {id}.");
        }
        Command::Joins { json } => {
            let joins: Vec<JoinView> = client.ok(Method::Get, paths::JOINS, None)?;
            if json {
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
                            join.expires_at.to_string(),
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
            println!("Left team {} ({}).", clean(&me.team), team);
        }
        Command::MemberRole { id, role } => {
            let payload = body(&RoleChange { role })?;
            let member: MemberView = client.ok(
                Method::Put,
                &format!("{}/{id}/role", paths::MEMBERS),
                Some(&payload),
            )?;
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
    // This endpoint accepts a legacy member token, not an access token.
    let relay = settings.relay()?;
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
    let keys = devicekey::store()?;
    if settings::contains_team(&team)? || keys.load(relay, &team)?.is_some() {
        return Err(CliError::usage(format!(
            "This machine already has a key or settings entry for team {team}. Use another XDG_CONFIG_HOME."
        )));
    }
    let name = crate::cli::onboarding::device_name(name.as_deref())?;
    let key =
        DeviceKey::generate().map_err(|_| CliError::relay("Cannot create the device key."))?;
    let payload = body(&DeviceEnroll {
        name,
        public_key: key.public_key_b64(),
    })?;
    // Keep the key after a lost answer: the member token may already be invalid.
    keys.save(relay, &team, &key)?;
    let mut saved = TeamSettings {
        relay_url: relay.to_owned(),
        team: me.team,
        member: me.member_name,
        device_id: None,
        member_token: None,
        safety_verified: None,
    };
    settings::save_team(&team, &saved)?;
    let device: DeviceView = client
        .ok(Method::Post, api::paths::DEVICE_ENROLL, Some(&payload))
        .map_err(|error| CliError {
            code: error.code,
            message: format!(
                "{} The device key is saved. Run `apassy-team join --resume` to check enrollment.",
                error.message
            ),
        })?;
    saved.device_id = Some(device.id);
    settings::save_team(&team, &saved)?;
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
