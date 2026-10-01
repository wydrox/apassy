//! Every admin and member command of the CLI: each one builds a request, calls the relay, and prints a short answer.
//!
//! Secrets (a member token, an invite code, an item value) come from stdin only.
//! The only places that print a secret are `invite` and `agent create`, once, on stdout.
//! An item value never goes to the relay: `item add` seals it here, and its key goes
//! to the key store of this machine (`cli::keystore`).
//! Text that an agent wrote (commands, purposes) is printed with control characters
//! escaped, so it cannot move the cursor or set the title of an approver's terminal.

use std::io::{IsTerminal, Read, Write};

use serde::Serialize;
use zeroize::Zeroizing;

use crate::api::{
    self, AccessView, AgentCreate, AgentView, ApprovalView, AuditEntry, CollectionCreate,
    CollectionView, Created, DecisionRequest, GrantCreate, GrantView, InviteRequest, InviteView,
    Issued, ItemCreated, ItemView, MeView, MemberView, NewItemRef, Policy, RunView,
};
use crate::cli::CliError;
use crate::cli::args::{Command, ItemAddArgs, USAGE};
use crate::cli::client::{CallError, Client, Method};
use crate::cli::keystore::{KeyEntry, KeyStore};
use crate::cli::settings::{self, Settings};
use crate::hostkeys;
use crate::secret::SecretString;

/// Runs one parsed command and returns the exit code.
pub fn execute(command: Command) -> Result<i32, CliError> {
    execute_for(command, None)
}

fn execute_for(command: Command, selected: Option<&str>) -> Result<i32, CliError> {
    match command {
        Command::Selected { team, command } => execute_for(*command, Some(&team)),
        Command::Help => {
            print!("{USAGE}");
            Ok(0)
        }
        Command::Version => {
            println!("apassy-team {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        Command::Init { relay } => init(&relay),
        Command::Create {
            relay,
            team,
            name,
            device,
        } => crate::cli::onboarding::create(&relay, &team, &name, device.as_deref()),
        Command::Join {
            relay,
            name,
            device,
            no_wait,
            resume,
        } => crate::cli::onboarding::join(
            relay.as_deref(),
            name.as_deref(),
            device.as_deref(),
            no_wait,
            resume,
            selected,
            false,
        ),
        Command::DeviceLink {
            relay,
            device,
            no_wait,
            resume,
        } => crate::cli::onboarding::join(
            relay.as_deref(),
            None,
            device.as_deref(),
            no_wait,
            resume,
            selected,
            true,
        ),
        Command::TeamList { json } => {
            let saved = settings::saved_teams()?;
            let teams = saved.teams;
            if json {
                let rows: Vec<_> = teams
                    .iter()
                    .map(|(id, team)| {
                        serde_json::json!({
                            "id": id, "relay_url": team.relay_url, "team": team.team,
                            "member": team.member, "device_id": team.device_id
                        })
                    })
                    .collect();
                print_json(&rows)?;
            } else {
                let current = saved.current;
                table(
                    &["CURRENT", "ID", "TEAM", "MEMBER", "RELAY"],
                    teams
                        .iter()
                        .map(|(id, team)| {
                            vec![
                                if current.as_ref() == Some(id) {
                                    "*"
                                } else {
                                    ""
                                }
                                .into(),
                                id.to_string(),
                                clean(&team.team),
                                clean(&team.member),
                                clean(&team.relay_url),
                            ]
                        })
                        .collect(),
                );
            }
            Ok(0)
        }
        Command::TeamUse { id } => {
            let id = crate::ids::TeamId::parse(&id)
                .ok_or_else(|| CliError::usage("The team id is not valid."))?;
            settings::set_current(&id)?;
            println!("Current team: {id}.");
            Ok(0)
        }
        Command::Mcp => crate::cli::mcp_stdio::run(&settings::load_for(selected)?),
        Command::Run(args) => crate::cli::exec::run(&settings::load_for(selected)?, args),
        Command::Host {
            ask_all,
            auto_limit,
            dialog,
        } => crate::cli::host::run(
            &settings::load_for(selected)?,
            crate::cli::host::HostOptions {
                ask_all,
                auto_limit: auto_limit.unwrap_or(crate::cli::host::DEFAULT_AUTO_LIMIT),
            },
            dialog,
        ),
        Command::HostInstall {
            ask_all,
            auto_limit,
        } => crate::cli::service::install(
            &settings::load_for(selected)?,
            crate::cli::host::HostOptions {
                ask_all,
                auto_limit: auto_limit.unwrap_or(crate::cli::host::DEFAULT_AUTO_LIMIT),
            },
        ),
        Command::HostUninstall => crate::cli::service::uninstall(),
        Command::HostStatus => crate::cli::service::status(),
        other => {
            let settings = settings::load_for(selected)?;
            member_command(&settings, other)?;
            Ok(0)
        }
    }
}

fn member_client(settings: &Settings) -> Result<Client, CliError> {
    Client::member(settings)
}

fn agent_client(settings: &Settings) -> Result<Client, CliError> {
    Ok(Client::new(
        settings.relay()?,
        Some(settings.agent()?),
        settings.edge_secret.as_ref(),
    ))
}

/// Reads one secret from stdin. It refuses a terminal, so the secret is never typed
/// where it would echo or land in a history. One trailing newline is removed.
pub fn read_secret(what: &str, example: &str) -> Result<SecretString, CliError> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(CliError::usage(format!(
            "Refusing to read {what} from a terminal. Pipe it on stdin, for example: {example}"
        )));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    const LIMIT: u64 = 16 * 1024;
    stdin
        .lock()
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| CliError::usage(format!("Cannot read {what} from stdin: {}.", e.kind())))?;
    if bytes.len() as u64 > LIMIT {
        return Err(CliError::usage(format!("The {what} on stdin is too long.")));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| CliError::usage(format!("The {what} on stdin is not UTF-8 text.")))?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let text = text.strip_suffix('\r').unwrap_or(text);
    if text.is_empty() {
        return Err(CliError::usage(format!("The {what} on stdin is empty.")));
    }
    Ok(SecretString::new(text.to_owned()))
}

/// A request body that holds a secret lives in a zeroizing string.
fn body<T: Serialize>(value: &T) -> Result<Zeroizing<String>, CliError> {
    serde_json::to_string(value)
        .map(Zeroizing::new)
        .map_err(|_| CliError::usage("Cannot encode the request."))
}

fn init(relay: &str) -> Result<i32, CliError> {
    let relay = settings::normalize_url(relay)?;
    let token = read_secret(
        "the member token",
        "apassy-team init --relay URL < owner-token-file",
    )?;
    if token.expose().starts_with("apassy_acc_") {
        return Err(CliError::usage(
            "Access tokens cannot be saved. Use a device key to sign in, or supply a legacy member token.",
        ));
    }
    let edge = settings::env_secret(settings::ENV_EDGE_SECRET);
    let client = Client::new(&relay, Some(&token), edge.as_ref());
    let me: MeView = client.ok(Method::Get, api::paths::ME, None)?;
    if me.kind != api::PrincipalKind::Member {
        return Err(CliError::usage(
            "That is an agent token. `init` needs a member token.",
        ));
    }
    let team_id = me.team_id.as_ref().ok_or_else(|| {
        CliError::usage("The relay did not return a team id. Update the relay first.")
    })?;
    if crate::cli::devicekey::store()?
        .load(&relay, team_id)?
        .is_some()
        || settings::list()?
            .iter()
            .any(|(id, entry)| id == team_id && entry.device_id.is_some())
    {
        return Err(CliError::usage(
            "This machine already has a device for that team. Use `team use ID`.",
        ));
    }
    let path = settings::save_team(
        team_id,
        &settings::TeamSettings {
            relay_url: relay,
            team: me.team.clone(),
            member: me.member_name.clone(),
            device_id: None,
            member_token: Some(token),
            safety_verified: None,
        },
    )?;
    println!(
        "Saved settings for {} ({}) of team {} in {}.",
        clean(&me.member_name),
        role_word(me.role),
        clean(&me.team),
        path.display()
    );
    Ok(0)
}

fn member_command(settings: &Settings, command: Command) -> Result<(), CliError> {
    use api::paths;
    match command {
        Command::Me { json } => {
            let client = if settings.device_id.is_some() || settings.member_token.is_some() {
                member_client(settings)?
            } else {
                agent_client(settings)?
            };
            let me: MeView = client.ok(Method::Get, paths::ME, None)?;
            if json {
                return print_json(&me);
            }
            match (&me.agent_name, &me.agent_id) {
                (Some(agent), Some(id)) => println!(
                    "team {}{}: agent {} (id {}) of member {} ({})",
                    clean(&me.team),
                    team_id_note(&me),
                    clean(agent),
                    id,
                    clean(&me.member_name),
                    role_word(me.role)
                ),
                _ => println!(
                    "team {}{}: member {} (id {}, {})",
                    clean(&me.team),
                    team_id_note(&me),
                    clean(&me.member_name),
                    me.member_id,
                    role_word(me.role)
                ),
            }
            Ok(())
        }
        Command::Invite {
            role,
            hours,
            name,
            grants,
            shared,
        } => {
            let client = member_client(settings)?;
            let payload = body(&InviteRequest {
                role,
                expires_hours: hours,
                name,
                grants: grants.into_iter().map(crate::ids::CollectionId).collect(),
                shared,
            })?;
            let issued: Issued = client.ok(Method::Post, paths::INVITES, Some(&payload))?;
            // The one-time output: the code alone on stdout, the rest on stderr.
            println!("{}/join#{}", client.base(), issued.secret.expose());
            eprintln!(
                "Invite {} for role {}, expires {}. The code works once. Send it over a private channel.",
                issued.id,
                role_word(role),
                issued
                    .expires_at
                    .map(fmt_time)
                    .unwrap_or_else(|| "?".into())
            );
            Ok(())
        }
        Command::Invites { json } => {
            let items: Vec<InviteView> =
                member_client(settings)?.ok(Method::Get, paths::INVITES, None)?;
            if json {
                return print_json(&items);
            }
            let rows = items
                .iter()
                .map(|i| {
                    vec![
                        i.id.to_string(),
                        role_word(i.role).to_owned(),
                        fmt_time(i.expires_at),
                        i.used_by
                            .map_or("unused".to_owned(), |m| format!("used by member {m}")),
                    ]
                })
                .collect();
            table(&["ID", "ROLE", "EXPIRES", "STATE"], rows);
            Ok(())
        }
        Command::Members { json } => {
            let items: Vec<MemberView> =
                member_client(settings)?.ok(Method::Get, paths::MEMBERS, None)?;
            if json {
                return print_json(&items);
            }
            let rows = items
                .iter()
                .map(|m| {
                    vec![
                        m.id.to_string(),
                        clean(&m.name),
                        role_word(m.role).to_owned(),
                        if m.revoked { "revoked" } else { "active" }.to_owned(),
                    ]
                })
                .collect();
            table(&["ID", "NAME", "ROLE", "STATE"], rows);
            Ok(())
        }
        Command::MemberRevoke { id } => {
            let done: Created = member_client(settings)?.ok(
                Method::Delete,
                &format!("{}/{id}", paths::MEMBERS),
                None,
            )?;
            println!("Revoked member {}.", done.id);
            Ok(())
        }
        Command::CollectionCreate { name, policy } => {
            let payload = body(&CollectionCreate {
                name,
                policy: policy.into_policy(),
            })?;
            let done: Created =
                member_client(settings)?.ok(Method::Post, paths::COLLECTIONS, Some(&payload))?;
            println!("{}", done.id);
            Ok(())
        }
        Command::CollectionList { json } => {
            let items: Vec<CollectionView> =
                member_client(settings)?.ok(Method::Get, paths::COLLECTIONS, None)?;
            if json {
                return print_json(&items);
            }
            let rows = items
                .iter()
                .map(|c| {
                    vec![
                        c.id.to_string(),
                        clean(&c.name),
                        c.item_count.to_string(),
                        policy_words(&c.policy),
                    ]
                })
                .collect();
            table(&["ID", "NAME", "ITEMS", "POLICY"], rows);
            Ok(())
        }
        Command::CollectionPolicy { id, policy } => {
            let payload = body(&policy.into_policy())?;
            let view: CollectionView = member_client(settings)?.ok(
                Method::Put,
                &format!("{}/{id}/policy", paths::COLLECTIONS),
                Some(&payload),
            )?;
            println!(
                "Collection {} ({}): {}",
                view.id,
                clean(&view.name),
                policy_words(&view.policy)
            );
            Ok(())
        }
        Command::ItemAdd(args) => item_add(settings, &args),
        Command::ItemList { collection, json } => {
            let path = match collection {
                Some(id) => format!("{}?collection={id}", paths::ITEMS),
                None => paths::ITEMS.to_owned(),
            };
            let items: Vec<ItemView> = member_client(settings)?.ok(Method::Get, &path, None)?;
            if json {
                return print_json(&items);
            }
            let rows = items
                .iter()
                .map(|i| {
                    vec![
                        i.id.to_string(),
                        clean(&i.collection),
                        clean(&i.name),
                        clean(&i.env_name),
                        clean(&i.environment),
                        clean(&i.hosts.join(",")),
                    ]
                })
                .collect();
            table(
                &["ID", "COLLECTION", "NAME", "ENV", "ENVIRONMENT", "HOSTS"],
                rows,
            );
            Ok(())
        }
        Command::ItemArchive { id } => {
            let done: Created = member_client(settings)?.ok(
                Method::Delete,
                &format!("{}/{id}", paths::ITEMS),
                None,
            )?;
            println!("Archived item {}.", done.id);
            Ok(())
        }
        Command::Grant { collection, member } => {
            let payload = body(&GrantCreate {
                collection_id: crate::ids::CollectionId(collection),
                member_id: crate::ids::MemberId(member),
            })?;
            let done: Created =
                member_client(settings)?.ok(Method::Post, paths::GRANTS, Some(&payload))?;
            println!("{}", done.id);
            Ok(())
        }
        Command::Grants { json } => {
            let items: Vec<GrantView> =
                member_client(settings)?.ok(Method::Get, paths::GRANTS, None)?;
            if json {
                return print_json(&items);
            }
            let rows = items
                .iter()
                .map(|g| {
                    vec![
                        g.id.to_string(),
                        format!("{} ({})", g.collection_id, clean(&g.collection)),
                        format!("{} ({})", g.member_id, clean(&g.member)),
                        fmt_time(g.created_at),
                    ]
                })
                .collect();
            table(&["ID", "COLLECTION", "MEMBER", "SINCE"], rows);
            Ok(())
        }
        Command::GrantRevoke { id } => {
            let done: Created = member_client(settings)?.ok(
                Method::Delete,
                &format!("{}/{id}", paths::GRANTS),
                None,
            )?;
            println!("Revoked grant {}.", done.id);
            Ok(())
        }
        Command::AgentCreate { name, days } => {
            let payload = body(&AgentCreate {
                name: name.clone(),
                days,
            })?;
            let issued: Issued =
                member_client(settings)?.ok(Method::Post, paths::AGENTS, Some(&payload))?;
            // The one-time output: the token alone on stdout, the rest on stderr.
            println!("{}", issued.secret.expose());
            eprintln!(
                "Agent {} (id {}), expires {}. The token is shown once. Set it as APASSY_TOKEN.",
                clean(&name),
                issued.id,
                issued
                    .expires_at
                    .map(fmt_time)
                    .unwrap_or_else(|| "?".into())
            );
            Ok(())
        }
        Command::AgentList { json } => {
            let items: Vec<AgentView> =
                member_client(settings)?.ok(Method::Get, paths::AGENTS, None)?;
            if json {
                return print_json(&items);
            }
            let rows = items
                .iter()
                .map(|a| {
                    vec![
                        a.id.to_string(),
                        clean(&a.name),
                        a.member_id.to_string(),
                        fmt_time(a.expires_at),
                        if a.revoked { "revoked" } else { "active" }.to_owned(),
                    ]
                })
                .collect();
            table(&["ID", "NAME", "MEMBER", "EXPIRES", "STATE"], rows);
            Ok(())
        }
        Command::AgentRevoke { id } => {
            let done: Created = member_client(settings)?.ok(
                Method::Delete,
                &format!("{}/{id}", paths::AGENTS),
                None,
            )?;
            println!("Revoked agent {}.", done.id);
            Ok(())
        }
        Command::Pending { json } => {
            let items: Vec<ApprovalView> =
                member_client(settings)?.ok(Method::Get, paths::APPROVALS, None)?;
            if json {
                return print_json(&items);
            }
            if items.is_empty() {
                println!("No runs are waiting.");
            }
            for run in &items {
                print_pending(run);
            }
            Ok(())
        }
        Command::Approve { run, reason } => decide(settings, run, reason, "approve"),
        Command::Deny { run, reason } => decide(settings, run, reason, "deny"),
        Command::Audit { after, limit, json } => {
            let mut query = Vec::new();
            if let Some(after) = after {
                query.push(format!("after={after}"));
            }
            if let Some(limit) = limit {
                query.push(format!("limit={limit}"));
            }
            let path = if query.is_empty() {
                paths::AUDIT.to_owned()
            } else {
                format!("{}?{}", paths::AUDIT, query.join("&"))
            };
            let entries: Vec<AuditEntry> = member_client(settings)?.ok(Method::Get, &path, None)?;
            if json {
                return print_json(&entries);
            }
            for e in &entries {
                let run = e.run_id.map_or(String::new(), |r| format!(" run {r}"));
                println!(
                    "{} {} {} {}{run} {}",
                    e.id,
                    fmt_time(e.at),
                    clean(&e.actor),
                    clean(&e.action),
                    clean(&e.detail.to_string())
                );
            }
            Ok(())
        }
        Command::Access { json } => {
            let view: AccessView = agent_client(settings)?.ok(Method::Get, paths::ACCESS, None)?;
            if json {
                return print_json(&view);
            }
            println!(
                "agent {} of member {}",
                clean(&view.agent),
                clean(&view.member)
            );
            let rows = view
                .items
                .iter()
                .map(|i| {
                    vec![
                        i.item_id.to_string(),
                        clean(&i.collection),
                        clean(&i.item_name),
                        clean(&i.env_name),
                        clean(&i.environment),
                        clean(&i.hosts.join(",")),
                        clean(&i.approval),
                    ]
                })
                .collect();
            table(
                &[
                    "ID",
                    "COLLECTION",
                    "NAME",
                    "ENV",
                    "ENVIRONMENT",
                    "HOSTS",
                    "APPROVAL",
                ],
                rows,
            );
            if !view.note.is_empty() {
                println!("{}", clean(&view.note));
            }
            Ok(())
        }
        command @ (Command::DeviceEnroll { .. }
        | Command::DeviceList { .. }
        | Command::DeviceRevoke { .. }
        | Command::DeviceKeyHolder { .. }
        | Command::DeviceAdd
        | Command::DevicePending { .. }
        | Command::DeviceConfirm { .. }
        | Command::DeviceRefuse { .. }
        | Command::Joins { .. }
        | Command::Confirm { .. }
        | Command::Refuse { .. }
        | Command::Leave
        | Command::MemberRole { .. }) => crate::cli::devices::execute(settings, command),
        _ => Err(CliError::usage(
            "This command cannot run as a member command.",
        )),
    }
}

/// ` (t_...)` after the team name, when the relay has teams.
fn team_id_note(me: &MeView) -> String {
    me.team_id
        .as_ref()
        .map_or_else(String::new, |id| format!(" ({id})"))
}

/// `item add`: checks the value, seals it with a new item key, keeps the key in
/// `keys.json`, and sends only the sealed text to the relay.
///
/// The key is written to disk before the upload, so an item that exists on the relay
/// never loses its key. After the relay took the item, the entry gets the item id.
/// When the relay refuses the item, or the request certainly did not reach it, the
/// entry is removed again. When the outcome is unknown (a timeout), the entry stays.
fn item_add(settings: &Settings, args: &ItemAddArgs) -> Result<(), CliError> {
    let client = member_client(settings)?;
    let value = read_secret(
        "the item value",
        "apassy-team item add --collection 1 --name NAME --env ENV_NAME --environment staging < value-file",
    )?;
    // The relay cannot read the value, so this is the one place that checks it.
    hostkeys::check_value(value.expose()).map_err(|p| CliError::usage(p.message()))?;
    // The relay stores the name and the hosts in clear and cannot mask the value in
    // them: a value in a name would be a leak.
    if std::iter::once(&args.name)
        .chain(&args.hosts)
        .chain(args.provider.iter())
        .any(|text| text.contains(value.expose()))
    {
        return Err(CliError::usage(
            "The name, the provider, and the hosts of an item must not contain its value.",
        ));
    }
    let me: MeView = client.ok(Method::Get, api::paths::ME, None)?;
    let store = KeyStore::open()?;

    let crypto = |_| CliError::relay("Cannot seal the value: the system has no random source.");
    let uid = hostkeys::new_uid().map_err(crypto)?;
    let key = hostkeys::new_key().map_err(crypto)?;
    let sealed = hostkeys::seal_item(&key, &uid, value.expose().as_bytes()).map_err(crypto)?;
    let sealed_text = hostkeys::encode_b64(&sealed);
    drop(value);

    let entry = KeyEntry {
        relay_url: client.base().to_owned(),
        team: me.team.clone(),
        uid: uid.clone(),
        item_id: None,
        name: args.name.trim().to_owned(),
        env_name: args.env_name.clone(),
        environment: args.environment.clone(),
        hosts: local_hosts(args),
        risk: args.risk.clone().unwrap_or_else(|| "high".to_owned()),
        scope: args.scope.clone().unwrap_or_else(|| "admin".to_owned()),
        reversibility: args
            .reversibility
            .clone()
            .unwrap_or_else(|| "irreversible".to_owned()),
        key: SecretString::new(hostkeys::encode_key(&key).to_string()),
        created_at: crate::now_unix(),
    };
    drop(key);
    store.add(entry)?;

    let payload = body(&NewItemRef {
        collection_id: crate::ids::CollectionId(args.collection),
        name: &args.name,
        env_name: &args.env_name,
        uid: &uid,
        sealed: &sealed_text,
        provider: args.provider.as_deref(),
        hosts: args.hosts.clone(),
        environment: &args.environment,
        risk: args.risk.as_deref(),
        scope: args.scope.as_deref(),
        reversibility: args.reversibility.as_deref(),
        allow_broad_host: args.allow_broad_host,
    })?;
    let uploaded = client.call::<ItemCreated>(
        Method::Post,
        api::paths::ITEMS,
        Some(&payload),
        crate::cli::client::CALL_TIMEOUT,
    );
    let done = match uploaded {
        Ok(done) => done,
        Err(error @ (CallError::Api(_) | CallError::Unsent(_) | CallError::Usage(_))) => {
            // The relay did not take the item: no item, so no key to keep.
            if store.remove(&uid).is_err() {
                eprintln!(
                    "apassy-team: warning: the key of the refused item is still in {}.",
                    store.path().display()
                );
            }
            return Err(error.into_cli());
        }
        Err(error) => {
            let cli = error.into_cli();
            return Err(CliError::relay(format!(
                "{} The relay may have taken the item, so its key stays in {}.",
                cli.message,
                store.path().display()
            )));
        }
    };
    if let Err(error) = store.finish(&uid, done.id, &done.hosts) {
        eprintln!(
            "apassy-team: warning: the item is on the relay, but its entry in {} was not updated: {}",
            store.path().display(),
            error.message
        );
    }
    println!("{}", done.id);
    // The id goes to stdout for scripts. The rest goes to stderr.
    for host in &done.hosts {
        eprintln!("The value may go to {}.", coverage(host));
    }
    eprintln!(
        "The key of this item is in {}. Back that file up: without it the item cannot be used, and you add it again.",
        store.path().display()
    );
    Ok(())
}

/// The hosts that the relay will store for the item: the `--host` values, or the known
/// hosts of the provider, in the form that `HostRule` shows. The relay answers with
/// the final list, and the entry takes that when the item is stored.
fn local_hosts(args: &ItemAddArgs) -> Vec<String> {
    let texts: Vec<String> = if args.hosts.is_empty() {
        args.provider
            .as_deref()
            .map(|id| apassy::vault::providers::known_hosts(id).to_vec())
            .unwrap_or_default()
    } else {
        args.hosts.clone()
    };
    let mut hosts: Vec<String> = Vec::new();
    for text in texts {
        let shown = apassy::broker::proxy::HostRule::parse(&text)
            .map(|rule| rule.to_string())
            .unwrap_or(text);
        if !hosts.contains(&shown) {
            hosts.push(shown);
        }
    }
    hosts
}

/// What a host rule covers, in words: `api.example.com and every subdomain of it`, and
/// the port when it is not 443.
pub fn coverage(host: &str) -> String {
    let host = clean(host);
    match host.rsplit_once(':') {
        Some((name, port)) => format!("{name} and every subdomain of it, on port {port}"),
        None => format!("{host} and every subdomain of it"),
    }
}

fn decide(
    settings: &Settings,
    run: u64,
    reason: Option<String>,
    verb: &str,
) -> Result<(), CliError> {
    let payload = body(&DecisionRequest { reason })?;
    let answer: Result<RunView, CallError> = member_client(settings)?.call(
        Method::Post,
        &format!("{}/{run}/{verb}", api::paths::APPROVALS),
        Some(&payload),
        crate::cli::client::CALL_TIMEOUT,
    );
    let view = match answer {
        Ok(view) => view,
        // Nobody approves on the relay: the keys are on the owner's host.
        Err(CallError::Api(e)) if e.code == crate::error::codes::APPROVE_ON_HOST => {
            return Err(CliError::usage(clean(&e.message)));
        }
        Err(error) => return Err(error.into_cli()),
    };
    println!(
        "Run {}: {}. {}",
        view.run_id,
        status_word(view.status),
        clean(&view.note)
    );
    Ok(())
}

fn print_pending(run: &ApprovalView) {
    println!(
        "run {}  agent {} of {}  asked {}  times out {}",
        run.run_id,
        clean(&run.agent),
        clean(&run.member),
        fmt_time(run.created_at),
        fmt_time(run.expires_at)
    );
    println!("  command:  {}", clean(&shell_words(&run.command)));
    println!("  purpose:  {}", clean(&run.purpose));
    match &run.user_request {
        Some(text) => println!("  request:  {}", clean(text)),
        None => println!("  request:  (none)"),
    }
    if let Some(cwd) = &run.cwd {
        println!("  cwd:      {}", clean(cwd));
    }
    for item in &run.items {
        println!(
            "  item {}:  {} ({}, {})",
            item.id,
            clean(&item.name),
            clean(&item.collection),
            clean(&item.environment)
        );
    }
    if !run.flags.is_empty() {
        println!("  flags:    {}", clean(&run.flags.join(", ")));
    }
    println!("  note:     {}", clean(&run.note));
}

pub(crate) fn print_json<T: Serialize>(value: &T) -> Result<(), CliError> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|_| CliError::relay("Cannot encode the answer."))?;
    println!("{text}");
    Ok(())
}

/// Prints rows in aligned columns. An empty list prints only the header.
pub(crate) fn table(header: &[&str], rows: Vec<Vec<String>>) {
    let mut widths: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let mut out = std::io::stdout().lock();
    let mut line = |cells: Vec<&str>| {
        let text: Vec<String> = cells
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{c:<width$}", width = widths[i]))
            .collect();
        let _ = writeln!(out, "{}", text.join("  ").trim_end());
    };
    line(header.to_vec());
    for row in &rows {
        line(row.iter().map(String::as_str).collect());
    }
}

/// Escapes control characters, so that text from an agent cannot drive a terminal.
pub fn clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// The argv as one line, with quotes around words that need them.
pub fn shell_words(argv: &[String]) -> String {
    argv.iter()
        .map(|word| {
            let plain = !word.is_empty()
                && word
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./:=@%+,".contains(c));
            if plain {
                word.clone()
            } else {
                format!("'{}'", word.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn role_word(role: api::Role) -> &'static str {
    match role {
        api::Role::Owner => "owner",
        api::Role::Manager => "manager",
        api::Role::Member => "member",
    }
}

fn status_word(status: api::RunStatus) -> &'static str {
    match status {
        api::RunStatus::Pending => "pending",
        api::RunStatus::Ready => "ready",
        api::RunStatus::Denied => "denied",
        api::RunStatus::TimedOut => "timed out",
        api::RunStatus::Ended => "ended",
    }
}

fn policy_words(policy: &Policy) -> String {
    let mut parts = vec![match policy.mode {
        api::PolicyMode::Bouncer => "mode bouncer".to_owned(),
        api::PolicyMode::Ask => "mode ask".to_owned(),
    }];
    let rule = &policy.rule;
    if !rule.allowed_prefixes.is_empty() {
        parts.push(format!("allow {}", rule.allowed_prefixes.join("|")));
    }
    if !rule.forbidden_words.is_empty() {
        parts.push(format!("forbid {}", rule.forbidden_words.join("|")));
    }
    if let Some(n) = rule.max_runs_per_hour {
        parts.push(format!("max {n}/hour"));
    }
    if let Some(t) = rule.expires_at {
        parts.push(format!("until {}", fmt_time(t)));
    }
    clean(&parts.join(", "))
}

/// Unix seconds as `YYYY-MM-DD HH:MM:SSZ` (UTC).
pub fn fmt_time(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil date from a day count (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_is_utc_calendar() {
        assert_eq!(fmt_time(0), "1970-01-01 00:00:00Z");
        assert_eq!(fmt_time(951_782_400), "2000-02-29 00:00:00Z");
        assert_eq!(fmt_time(1_790_726_400 + 3_661), "2026-09-30 01:01:01Z");
    }

    #[test]
    fn control_characters_are_escaped() {
        assert_eq!(clean("a\u{1b}[31mb\nc"), "a\\u{1b}[31mb\\nc");
        assert_eq!(clean("plain text é"), "plain text é");
    }

    #[test]
    fn argv_is_quoted_for_display() {
        let argv = ["sh", "-c", "echo 'hi there'", ""].map(String::from);
        assert_eq!(shell_words(&argv), "sh -c 'echo '\\''hi there'\\''' ''");
    }
}
