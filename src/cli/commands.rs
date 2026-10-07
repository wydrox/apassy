//! The commands that talk to the app.

use std::fmt::Write as _;
use std::io::Write;

use super::args::{Args, usage};
use super::import::{self, Format};
use super::print::{self, Block, Table, clean};
use super::terminal;
use super::{Cli, Failure, Outcome, expect_owner_check, print_json};
use crate::contracts::CredentialKind;
use crate::owner::wire::{
    Command, Data, DeclarationInput, DetailInput, GrantMode, ItemInput, ItemRow, ItemView,
    Response, RuleInput, SESSION_ENV, SecretText, StatusView, VariableInput, VaultState,
};

pub const SESSION_HELP: &str = "\
Session commands

  apassy status               The vault, the broker, the session, and what waits for you.
  apassy login [--raw] [--shell sh|fish]
                              Ask the window for a session. Confirm with Touch ID or the
                              passphrase. Prints a shell line that sets APASSY_SESSION:
                                eval \"$(apassy login)\"
                              --raw prints only the token. A session ends after 30 idle
                              minutes, after 12 hours, at a lock, and when Apassy quits.
  apassy logout               End the session: eval \"$(apassy logout)\"

Do not start an agent from a shell that has APASSY_SESSION. apassy-sandbox removes it.
";

pub const ITEM_HELP: &str = "\
Credential commands. ITEM is an ID or the exact name.

  apassy item list [QUERY] [--archived]
  apassy item show ITEM
  apassy item add NAME --kind KIND [FIELDS] [SECRET]
  apassy item edit ITEM [--name NEW] [FIELDS] [SECRET] [--remove-detail LABEL]...
  apassy item delete ITEM [--yes]
  apassy item archive ITEM            Agents cannot use it. No owner check.
  apassy item unarchive ITEM          Owner check.
  apassy item history ITEM [--limit N]

Agent settings (each asks for the owner check in the window):
  apassy item env ITEM NAME [--field FIELD] [--placeholder-host HOST]...
  apassy item env ITEM --clear        Also removes every process grant of the item.
  apassy item declare ITEM [--project P] [--environment local|development|staging|production]
                      [--risk low|medium|high] [--scope read-only|read-write|admin]
                      [--reversibility reversible|partial|irreversible] [--provider ID|none]
  apassy item connector ITEM URL      apassy item connector ITEM --clear
  apassy item review ITEM             Confirm the agent settings after a restore.

KIND: api-key, login, ssh-key, database, custom.
FIELDS: --service S --project P --notes TEXT --username U --host H --database D
        --field NAME (custom) --public-key TEXT (ssh-key)
        --detail LABEL=VALUE (visible)  --secret-detail LABEL (hidden, asked on the terminal)
SECRET: the token, password, private key, or custom value. add asks on the terminal with
        the echo off, or reads stdin when it is not a terminal. edit changes it only with
        --secret (ask), --secret-stdin, or --secret-file PATH. --key-passphrase asks for
        the passphrase of an SSH key.
";

pub const IMPORT_HELP: &str = "\
apassy import FILE [--format env|1password|bitwarden|csv] [--kind KIND]
              [--project P] [--service S] [--dry-run] [--allow-duplicates] [--bind]

Adds each entry as a credential. The command never prints a value.
  .env        KEY=value lines. Each key is one credential named KEY, an API key by
              default (--kind custom stores it in a field named after the key).
  1password   A 1Password CSV export (Title, Url, Username, Password, OTPAuth, Notes).
  bitwarden   A Bitwarden CSV export. Custom fields become hidden details.
A row with a username and a password is a login, a password alone is an API key, and a
note alone is a custom credential. A one-time code secret is a hidden detail.
A credential with the same name is left out unless --allow-duplicates.
--bind binds each added credential that has a variable name to that variable, with one
owner check in the window for all of them. A .env key is the variable name. A 1Password
or Bitwarden row has one only when its title is a variable name, such as STRIPE_API_KEY.
The window lists each credential and its variable. Programs get the real values. A name
that is not valid, or that another credential uses, is refused and reported.
Delete the export file after the import: it holds every password in plain text.
";

pub const AGENT_HELP: &str = "\
Agent commands. AGENT is an ID or the exact name.

  apassy agent list
  apassy agent show AGENT             Grants, operations, and requests.
  apassy agent add NAME               Register. Prints the token one time.
  apassy agent revoke AGENT [--yes]
  apassy agent rotate AGENT           Owner check. Prints the new token one time.
  apassy agent see-all AGENT on|off   on: owner check.
  apassy agent lifetime [DAYS]        Read, or set (owner check), the token lifetime.
  apassy setup claude|codex           Register and connect an agent host. See apassy help setup.
";

pub const GRANT_HELP: &str = "\
Grant commands. Each change that gives access asks for the owner check in the window.

  apassy grant set AGENT ITEM... [--folder DIR | --any-folder] [--mode ask|bouncer]
                              Process access. The default folder is the current one, and
                              the default mode is ask (you approve each run). Each ITEM
                              needs a variable: apassy item env.
  apassy grant remove AGENT ITEM      No owner check.
  apassy grant rule AGENT ITEM [--allow PREFIX]... [--forbid WORD]... [--expires HOURS]
                              [--max-runs N] [--instruction TEXT]
                              Replaces the rule of the grant.
  apassy grant operation AGENT ITEM OPERATION [--remove]
                              A connector operation, for example get_sales_summary.
";

pub const REQUEST_HELP: &str = "\
Access requests of agents.

  apassy request list [--all]
  apassy request grant ID [--folder DIR | --any-folder] [--mode ask|bouncer]   Owner check.
  apassy request deny ID
";

pub const RUNS_HELP: &str = "\
Runs that wait for you.

  apassy runs [list]
  apassy runs approve ID [--remember]   Owner check. The window shows the run as it waits.
  apassy runs deny ID
";

pub const PATTERN_HELP: &str = "\
Remembered approvals (\"Approve and remember\").

  apassy pattern list
  apassy pattern remove ID            Matching runs ask you again.
";

pub const ACTIVITY_HELP: &str = "\
  apassy activity [--agent AGENT] [--item ITEM] [--limit N]
  apassy decisions export [--output FILE]
                              All bouncer decisions as JSON Lines. They hold commands and
                              user requests, no secret values. FILE gets mode 0600.
";

pub const VAULT_HELP: &str = "\
Vault commands.

  apassy lock                         Lock the vault. Every session ends. No session needed.
  apassy unlock                       Bring the window to the front. Unlock it there.
  apassy vault backup PATH            Write an encrypted backup. The vault locks after it.
  apassy vault change-passphrase      Asks for the current and the new passphrase.
  apassy vault restore BACKUP         Opens the restore sheet in the window. You type the
                                      passphrase of the backup there.
";

/// Ask for confirmation unless `--yes`. Without a terminal, `--yes` is required.
fn confirmed(args: &mut Args, question: &str) -> Result<bool, Failure> {
    if args.flag(&["-y", "--yes"]) {
        return Ok(true);
    }
    if !terminal::stdin_is_terminal() {
        return Err(Failure::Usage(usage(
            "Add --yes to confirm without a terminal.",
        )));
    }
    Ok(terminal::confirm(question))
}

pub fn simple(cli: &Cli, args: Args, command: Command) -> Outcome {
    args.finish()?;
    let response = cli.call(command)?;
    cli.print_message(&response);
    Ok(())
}

// ---- Session ----

pub fn status(cli: &Cli, args: Args) -> Outcome {
    args.finish()?;
    let response = cli.call(Command::Status)?;
    if cli.json {
        print_json(&response);
        return Ok(());
    }
    let Data::Status(status) = response.data else {
        return Err(Failure::Other("Apassy sent no status.".to_owned()));
    };
    print!("{}", status_block(&status, cli.has_session()).render());
    Ok(())
}

pub fn status_block(status: &StatusView, has_token: bool) -> Block {
    let mut block = Block::new();
    block.line("Apassy", format!("running, version {}", status.version));
    block.line(
        "Vault",
        match status.vault {
            VaultState::None => "no vault file is open".to_owned(),
            VaultState::Locked => "locked".to_owned(),
            VaultState::Unlocked => "unlocked".to_owned(),
        },
    );
    block.line("Vault file", status.vault_path.clone().unwrap_or_default());
    block.line("Broker", status.broker.clone());
    block.line(
        "Broker socket",
        status.broker_socket.clone().unwrap_or_default(),
    );
    block.line(
        "Touch ID",
        if status.touch_id {
            "available"
        } else {
            "not available: the window asks for the passphrase"
        },
    );
    block.line(
        "Session",
        match (status.session, has_token) {
            (true, _) => "open".to_owned(),
            (false, true) => {
                format!("{SESSION_ENV} is set, but the session ended. Run apassy login.")
            }
            (false, false) => "none. Run: eval \"$(apassy login)\"".to_owned(),
        },
    );
    if let Some(count) = status.waiting_runs {
        block.line("Runs waiting", count.to_string());
    }
    if let Some(count) = status.open_requests {
        block.line("Open requests", count.to_string());
    }
    if let Some(count) = status.items_to_review {
        block.line("To review", count.to_string());
    }
    block
}

/// The shell line that sets or clears the session variable.
fn shell_line(shell: &str, token: Option<&str>) -> String {
    let fish = shell.rsplit('/').next() == Some("fish");
    match (fish, token) {
        (true, Some(token)) => format!("set -gx {SESSION_ENV} '{token}'"),
        (false, Some(token)) => format!("export {SESSION_ENV}='{token}'"),
        (true, None) => format!("set -e {SESSION_ENV}"),
        (false, None) => format!("unset {SESSION_ENV}"),
    }
}

pub fn login(cli: &Cli, mut args: Args) -> Outcome {
    let raw = args.flag(&["--raw"]);
    let force = args.flag(&["--force"]);
    let shell = args
        .value(&["--shell"])?
        .or_else(|| std::env::var("SHELL").ok())
        .unwrap_or_default();
    args.finish()?;
    if !raw && !force && !cli.json && terminal::stdout_is_terminal() {
        return Err(Failure::Usage(usage(
            "apassy login prints a shell line with the session token. Run it as: eval \"$(apassy login)\". Use --raw to print only the token.",
        )));
    }
    expect_owner_check();
    let response = cli.call(Command::Login)?;
    let Data::Session {
        token,
        idle_minutes,
    } = &response.data
    else {
        return Err(Failure::Other("Apassy sent no session.".to_owned()));
    };
    if cli.json {
        print_json(&response);
    } else if raw {
        println!("{}", token.expose());
    } else {
        println!("{}", shell_line(&shell, Some(token.expose())));
    }
    terminal::tell(&format!(
        "Session open. It ends after {idle_minutes} idle minutes, after 12 hours, or when the vault locks."
    ));
    Ok(())
}

pub fn logout(cli: &Cli, mut args: Args) -> Outcome {
    let shell = args
        .value(&["--shell"])?
        .or_else(|| std::env::var("SHELL").ok())
        .unwrap_or_default();
    args.finish()?;
    if cli.has_session() {
        let response = cli.send(Command::Logout)?;
        if !response.ok && response.code != "session_required" {
            return Err(Failure::App {
                code: response.code,
                message: response.message,
            });
        }
    }
    if terminal::stdout_is_terminal() {
        println!(
            "The session is closed. Clear the variable too: {}",
            shell_line(&shell, None)
        );
    } else {
        println!("{}", shell_line(&shell, None));
    }
    Ok(())
}

// ---- Items ----

fn parse_kind(text: &str) -> Result<CredentialKind, Failure> {
    match text.trim().to_lowercase().replace('-', "_").as_str() {
        "api_key" | "apikey" | "api" | "token" | "key" => Ok(CredentialKind::ApiKey),
        "login" | "password" => Ok(CredentialKind::Login),
        "ssh_key" | "ssh" => Ok(CredentialKind::SshKey),
        "database" | "db" => Ok(CredentialKind::Database),
        "custom" => Ok(CredentialKind::Custom),
        _ => Err(Failure::Usage(usage(
            "The kind is api-key, login, ssh-key, database, or custom.",
        ))),
    }
}

fn kind_label(kind: CredentialKind) -> &'static str {
    kind.label()
}

/// How the main secret of an add or an edit is read.
enum SecretSource {
    None,
    Ask,
    Stdin,
    File(String),
}

/// Read the plain fields, details, and secrets of an add or an edit.
fn item_input(args: &mut Args, adding: bool) -> Result<(ItemInput, SecretSource), Failure> {
    let mut input = ItemInput {
        name: args.value(&["--name"])?,
        kind: args
            .value(&["--kind"])?
            .map(|kind| parse_kind(&kind))
            .transpose()?,
        service: args.value(&["--service"])?,
        project: args.value(&["--project"])?,
        notes: args.value(&["--notes"])?,
        username: args.value(&["--username", "--user"])?,
        host: args.value(&["--host"])?,
        database: args.value(&["--database", "--db"])?,
        field_name: args.value(&["--field"])?,
        public_key: args.value(&["--public-key"])?,
        ..ItemInput::default()
    };
    for detail in args.values(&["--detail"])? {
        let (label, value) = detail
            .split_once('=')
            .ok_or_else(|| usage("--detail needs LABEL=VALUE."))?;
        input.details.push(DetailInput {
            label: label.trim().to_owned(),
            value: SecretText::new(value.to_owned()),
            hidden: false,
        });
    }
    let hidden_labels = args.values(&["--secret-detail"])?;
    input.remove_details = args.values(&["--remove-detail"])?;
    let file = args.value(&["--secret-file"])?;
    let stdin = args.flag(&["--secret-stdin"]);
    let ask = args.flag(&["--secret"]);
    let key_passphrase = args.flag(&["--key-passphrase"]);
    let source = match (file, stdin, ask) {
        (Some(path), false, false) => SecretSource::File(path),
        (None, true, false) => SecretSource::Stdin,
        (None, false, true) => SecretSource::Ask,
        (None, false, false) if adding => {
            if terminal::stdin_is_terminal() {
                SecretSource::Ask
            } else {
                SecretSource::Stdin
            }
        }
        (None, false, false) => SecretSource::None,
        _ => {
            return Err(Failure::Usage(usage(
                "Use one of --secret, --secret-stdin, and --secret-file.",
            )));
        }
    };
    for label in hidden_labels {
        let value = terminal::read_hidden(&format!("Value of \"{}\" (hidden): ", clean(&label)))?;
        input.details.push(DetailInput {
            label: label.trim().to_owned(),
            value,
            hidden: true,
        });
    }
    if key_passphrase {
        input.key_passphrase = Some(terminal::read_hidden(
            "Passphrase of the SSH key (hidden): ",
        )?);
    }
    Ok((input, source))
}

fn secret_prompt(kind: Option<CredentialKind>) -> &'static str {
    match kind {
        Some(CredentialKind::ApiKey) | None => "API token (hidden): ",
        Some(CredentialKind::Login | CredentialKind::Database) => "Password (hidden): ",
        Some(CredentialKind::SshKey) => "Private key (hidden): ",
        Some(CredentialKind::Custom) => "Secret value (hidden): ",
    }
}

fn read_secret(
    source: SecretSource,
    kind: Option<CredentialKind>,
) -> Result<Option<SecretText>, Failure> {
    let secret = match source {
        SecretSource::None => return Ok(None),
        SecretSource::Stdin => terminal::read_stdin_secret()?,
        SecretSource::File(path) => terminal::read_file_secret(&path)
            .map_err(|err| Failure::Other(format!("Cannot read {path}: {err}")))?,
        SecretSource::Ask => {
            if kind == Some(CredentialKind::SshKey) {
                return Err(Failure::Usage(usage(
                    "A private key has many lines. Use --secret-file PATH or --secret-stdin.",
                )));
            }
            terminal::read_hidden(secret_prompt(kind))?
        }
    };
    if secret.is_empty() {
        return Err(Failure::Usage(usage("The secret value is empty.")));
    }
    Ok(Some(secret))
}

pub fn item(cli: &Cli, mut args: Args) -> Outcome {
    let action = args.positional().unwrap_or_else(|| "list".to_owned());
    match action.as_str() {
        "list" | "ls" | "search" => {
            let archived = args.flag(&["--archived", "--all"]);
            let query = args.rest().join(" ");
            args.finish()?;
            let response = cli.call(Command::ItemList { query, archived })?;
            if cli.json {
                print_json(&response);
                return Ok(());
            }
            let Data::Items { items } = response.data else {
                return Ok(());
            };
            print_items(&items);
            Ok(())
        }
        "show" | "get" | "info" => {
            let item = args.required("credential")?;
            args.finish()?;
            let response = cli.call(Command::ItemShow { item })?;
            if cli.json {
                print_json(&response);
                return Ok(());
            }
            if let Data::Item(view) = response.data {
                print!("{}", item_block(&view).render());
            }
            Ok(())
        }
        "add" | "new" | "create" => {
            let name = args.positional();
            let (mut input, source) = item_input(&mut args, true)?;
            args.finish()?;
            if input.name.is_none() {
                input.name = name;
            }
            if input
                .name
                .as_deref()
                .is_none_or(|name| name.trim().is_empty())
            {
                return Err(Failure::Usage(usage("Name the credential.")));
            }
            if input.kind.is_none() {
                return Err(Failure::Usage(usage(
                    "Name the kind: --kind api-key, login, ssh-key, database, or custom.",
                )));
            }
            input.secret = read_secret(source, input.kind)?;
            let response = cli.call(Command::ItemAdd { item: input })?;
            cli.print_message(&response);
            Ok(())
        }
        "edit" | "set" | "update" => {
            let item = args.required("credential")?;
            let revision = args.number(&["--revision"])?;
            let (mut changes, source) = item_input(&mut args, false)?;
            args.finish()?;
            changes.secret = read_secret(source, changes.kind)?;
            let response = cli.call(Command::ItemEdit {
                item,
                revision,
                changes,
            })?;
            cli.print_message(&response);
            Ok(())
        }
        "delete" | "rm" | "remove" => {
            let item = args.required("credential")?;
            let revision = args.number(&["--revision"])?;
            if !confirmed(
                &mut args,
                &format!("Delete \"{}\"? This cannot be undone.", clean(&item)),
            )? {
                println!("Nothing was deleted.");
                return Ok(());
            }
            args.finish()?;
            let response = cli.call(Command::ItemDelete { item, revision })?;
            cli.print_message(&response);
            Ok(())
        }
        "archive" => {
            let item = args.required("credential")?;
            args.finish()?;
            simple_call(cli, Command::ItemArchive { item })
        }
        "unarchive" | "restore" => {
            let item = args.required("credential")?;
            args.finish()?;
            owner_check_call(cli, Command::ItemUnarchive { item })
        }
        "history" => {
            let item = args.required("credential")?;
            let limit = args.number(&["--limit", "-n"])?;
            args.finish()?;
            let response = cli.call(Command::ItemHistory { item, limit })?;
            if cli.json {
                print_json(&response);
                return Ok(());
            }
            if let Data::Events { events } = response.data {
                let mut table = Table::new(&["WHEN", "EVENT", "DETAIL"]);
                for event in events {
                    table.row(vec![print::time(event.at), event.kind, event.detail]);
                }
                print!("{}", table.render());
            }
            Ok(())
        }
        "env" | "variable" | "var" => {
            let item = args.required("credential")?;
            if args.flag(&["--clear", "--remove"]) {
                args.finish()?;
                return simple_call(cli, Command::ItemClearVariable { item });
            }
            let name = args.required("variable name")?;
            let field = args.value(&["--field"])?;
            let hosts = args.values(&["--placeholder-host", "--host"])?;
            args.finish()?;
            owner_check_call(
                cli,
                Command::ItemSetVariable {
                    item,
                    name,
                    field,
                    hosts,
                },
            )
        }
        "declare" | "declaration" => {
            let item = args.required("credential")?;
            let declaration = DeclarationInput {
                project: args.value(&["--project"])?,
                environment: args.value(&["--environment", "--env"])?,
                risk: args.value(&["--risk"])?,
                scope: args.value(&["--scope"])?,
                reversibility: args.value(&["--reversibility"])?,
                provider: args.value(&["--provider"])?.map(|provider| {
                    if provider == "none" {
                        String::new()
                    } else {
                        provider
                    }
                }),
            };
            args.finish()?;
            owner_check_call(cli, Command::ItemSetDeclaration { item, declaration })
        }
        "connector" => {
            let item = args.required("credential")?;
            if args.flag(&["--clear", "--remove"]) {
                args.finish()?;
                return simple_call(cli, Command::ItemClearConnector { item });
            }
            let base_url = args.required("connector address")?;
            args.finish()?;
            owner_check_call(cli, Command::ItemSetConnector { item, base_url })
        }
        "review" | "confirm-review" => {
            let item = args.required("credential")?;
            args.finish()?;
            owner_check_call(cli, Command::ItemConfirmReview { item })
        }
        other => Err(Failure::Usage(usage(format!(
            "Unknown item command \"{other}\". Run apassy help item."
        )))),
    }
}

fn print_items(items: &[ItemRow]) {
    if items.is_empty() {
        println!("No credentials.");
        return;
    }
    let mut table = Table::new(&["ID", "NAME", "KIND", "SERVICE", "PROJECT", "VARIABLE"]);
    for item in items {
        let mut name = item.name.clone();
        if item.archived {
            name.push_str(" (archived)");
        }
        table.row(vec![
            item.id.to_string(),
            name,
            kind_label(item.kind).to_owned(),
            item.service.clone(),
            item.project.clone(),
            item.variable.clone().unwrap_or_default(),
        ]);
    }
    print!("{}", table.render());
}

fn item_block(view: &ItemView) -> Block {
    let mut block = Block::new();
    block.line(
        "Credential",
        format!(
            "{} (ID {}, {}, revision {})",
            view.name,
            view.id,
            kind_label(view.kind),
            view.revision
        ),
    );
    if view.archived {
        block.line("Archived", "yes: agents cannot use it");
    }
    block.line("Service", view.service.clone());
    block.line("Project", view.project.clone());
    block.line("Username", view.username.clone());
    block.line("Host", view.host.clone());
    block.line("Database", view.database.clone());
    block.line("Custom field", view.field_name.clone());
    block.line("Public key", view.public_key.clone());
    block.line(
        "Secret fields",
        if view.secret_fields.is_empty() {
            String::new()
        } else {
            format!("{} (values hidden)", view.secret_fields.join(", "))
        },
    );
    let details: Vec<String> = view
        .details
        .iter()
        .map(|detail| match &detail.value {
            Some(value) if !detail.hidden => format!("{}: {value}", detail.label),
            _ => format!("{}: (hidden)", detail.label),
        })
        .collect();
    block.line("Details", details.join("\n"));
    block.line(
        "Variable",
        view.variable.as_ref().map_or_else(
            || "none. Agents cannot use it in a process.".to_owned(),
            |variable| {
                if variable.placeholder_hosts.is_empty() {
                    format!("{} from {} (the real value)", variable.name, variable.field)
                } else {
                    format!(
                        "{} from {} (a placeholder; the real value goes only to {})",
                        variable.name,
                        variable.field,
                        variable.placeholder_hosts.join(", ")
                    )
                }
            },
        ),
    );
    let declaration = &view.declaration;
    block.line(
        "Declaration",
        format!(
            "{}{}, {}, {} risk, {}, {}{}",
            if declaration.suggested {
                "suggested, not saved: "
            } else {
                ""
            },
            if declaration.project.is_empty() {
                "no project"
            } else {
                &declaration.project
            },
            declaration.environment,
            declaration.risk,
            declaration.scope,
            declaration.reversibility,
            declaration
                .provider
                .as_ref()
                .map_or_else(String::new, |provider| format!(", provider {provider}"))
        ),
    );
    block.line("Connector", view.connector.clone().unwrap_or_default());
    if view.needs_review {
        block.line(
            "Review",
            "waits for your review after a restore: apassy item review",
        );
    }
    block.line("Added", view.added.map(print::time).unwrap_or_default());
    block.line("Changed", view.changed.map(print::time).unwrap_or_default());
    block.line("Last used", view.used.map(print::time).unwrap_or_default());
    block.line("Notes", view.notes.clone());
    block
}

/// A command without an owner check that prints the message.
fn simple_call(cli: &Cli, command: Command) -> Outcome {
    let response = cli.call(command)?;
    cli.print_message(&response);
    Ok(())
}

/// A command that asks for the owner check in the window.
fn owner_check_call(cli: &Cli, command: Command) -> Outcome {
    expect_owner_check();
    simple_call(cli, command)
}

// ---- Import ----

pub fn import(cli: &Cli, mut args: Args) -> Outcome {
    let path = args.required("file to import")?;
    let format = args
        .value(&["--format"])?
        .map(|text| {
            Format::parse(&text).ok_or_else(|| {
                Failure::Usage(usage("The format is env, 1password, bitwarden, or csv."))
            })
        })
        .transpose()?;
    let options = import::Options {
        env_kind: args
            .value(&["--kind"])?
            .map(|kind| parse_kind(&kind))
            .transpose()?,
        project: args.value(&["--project"])?,
        service: args.value(&["--service"])?,
    };
    let dry_run = args.flag(&["--dry-run", "-n"]);
    let duplicates = args.flag(&["--allow-duplicates"]);
    let bind = args.flag(&["--bind"]);
    args.finish()?;
    let mut text = zeroize::Zeroizing::new(
        std::fs::read_to_string(&path)
            .map_err(|err| Failure::Other(format!("Cannot read {path}: {err}")))?,
    );
    let format = format.or_else(|| import::detect(&path, &text)).ok_or_else(|| {
        Failure::Usage(usage(
            "Apassy cannot tell the format of the file. Add --format env, 1password, bitwarden, or csv.",
        ))
    })?;
    let (entries, skipped) = import::parse(format, &text, &options);
    use zeroize::Zeroize;
    text.zeroize();
    drop(text);

    let existing: Vec<String> = if duplicates || dry_run && !cli.has_session() {
        Vec::new()
    } else {
        match cli
            .call(Command::ItemList {
                query: String::new(),
                archived: true,
            })?
            .data
        {
            Data::Items { items } => items
                .into_iter()
                .map(|item| item.name.to_lowercase())
                .collect(),
            _ => Vec::new(),
        }
    };
    let mut rows = Vec::new();
    let mut counts = ImportCounts::default();
    // The added items with a variable: the report row, the item ID, the variable.
    let mut to_bind: Vec<(usize, u64, String)> = Vec::new();
    for entry in entries {
        let name = entry.item.name.clone().unwrap_or_default();
        let kind = entry.item.kind.map_or("?", kind_label);
        let variable = entry.variable.filter(|_| bind);
        if existing.contains(&name.to_lowercase()) {
            counts.left_out += 1;
            rows.push(ImportRow::new(
                entry.line,
                name,
                kind,
                "left out: the name exists".to_owned(),
                None,
            ));
            continue;
        }
        if dry_run {
            let result = match &variable {
                Some(variable) => format!("would add and bind {variable}"),
                None => "would add".to_owned(),
            };
            rows.push(ImportRow::new(entry.line, name, kind, result, variable));
            continue;
        }
        match cli.send(Command::ItemAdd { item: entry.item })? {
            response if response.ok => {
                counts.added += 1;
                if let (Some(variable), Data::Items { items }) = (&variable, &response.data)
                    && let Some(row) = items.first()
                {
                    to_bind.push((rows.len(), row.id, variable.clone()));
                }
                rows.push(ImportRow::new(
                    entry.line,
                    name,
                    kind,
                    "added".to_owned(),
                    variable,
                ));
            }
            response => {
                counts.failed += 1;
                rows.push(ImportRow::new(
                    entry.line,
                    name,
                    kind,
                    format!("failed: {}", response.message),
                    None,
                ));
            }
        }
    }

    // One owner check for every variable (ADR 0017, D1).
    let mut bind_error = None;
    if !to_bind.is_empty() {
        expect_owner_check();
        let variables = to_bind
            .iter()
            .map(|(_, item_id, name)| VariableInput {
                item_id: *item_id,
                name: name.clone(),
            })
            .collect();
        let response = cli.send(Command::ItemBindVariables { variables })?;
        let results = match response.data {
            Data::Bindings { results } if response.ok => results,
            _ => Vec::new(),
        };
        for (row, item_id, variable) in &to_bind {
            let row = &mut rows[*row];
            match results.iter().find(|result| result.item_id == *item_id) {
                Some(result) if result.bound => {
                    counts.bound += 1;
                    row.result = format!("added, bound to {variable}");
                }
                result => {
                    counts.not_bound += 1;
                    row.result = format!("added, {variable} not bound");
                    row.reason =
                        Some(result.map_or_else(
                            || response.message.clone(),
                            |result| result.reason.clone(),
                        ));
                }
            }
        }
        if !response.ok {
            bind_error = Some((response.code, response.message));
        }
    }
    let failure = import_failure(&counts, bind_error);
    if cli.json {
        print_json(&import_json(
            format,
            &rows,
            &skipped,
            &counts,
            bind,
            dry_run,
            failure.as_ref(),
        ));
        // The answer holds the failure, so the failure is not printed again.
        return failure.map_or(Ok(()), |_| Err(Failure::Printed));
    }
    print!("{}", import_text(&rows, &skipped));
    let left_out = counts.left_out + skipped.len();
    if dry_run {
        println!(
            "{}: {} to add, {left_out} left out. Nothing was added (--dry-run).",
            format.label(),
            rows.iter()
                .filter(|row| row.result.starts_with("would add"))
                .count(),
        );
    } else {
        let ImportCounts {
            added,
            failed,
            bound,
            not_bound,
            ..
        } = counts;
        println!(
            "{}: {added} added, {failed} failed, {left_out} left out.",
            format.label(),
        );
        if bind && added > 0 {
            println!("Variables: {bound} bound, {not_bound} not bound.");
        }
        if added > bound {
            println!(
                "Bind variables for agents with apassy item env ITEM NAME. Delete {path} if it was an export: it holds the values in plain text."
            );
        } else if added > 0 {
            println!("Delete {path} if it was an export: it holds the values in plain text.");
        }
    }
    failure.map_or(Ok(()), |(code, message)| {
        Err(Failure::App { code, message })
    })
}

/// One row of the import report. The reason says why a variable is not bound.
struct ImportRow {
    line: usize,
    name: String,
    kind: &'static str,
    result: String,
    variable: Option<String>,
    reason: Option<String>,
}

impl ImportRow {
    fn new(
        line: usize,
        name: String,
        kind: &'static str,
        result: String,
        variable: Option<String>,
    ) -> Self {
        Self {
            line,
            name,
            kind,
            result,
            variable,
            reason: None,
        }
    }
}

/// The counts of an import. Left out counts the names that exist.
#[derive(Default)]
struct ImportCounts {
    added: usize,
    failed: usize,
    left_out: usize,
    bound: usize,
    not_bound: usize,
}

/// The code and message of an import that did not do everything, if any.
fn import_failure(
    counts: &ImportCounts,
    bind_error: Option<(String, String)>,
) -> Option<(String, String)> {
    if counts.failed > 0 {
        return Some((
            "partial".to_owned(),
            format!("{} entries were not added.", counts.failed),
        ));
    }
    if bind_error.is_some() {
        return bind_error;
    }
    (counts.not_bound > 0).then(|| {
        (
            "partial".to_owned(),
            format!("{} variables were not bound.", counts.not_bound),
        )
    })
}

/// The one JSON answer of an import. A failure adds its code and message, so `--json`
/// prints one document.
fn import_json(
    format: Format,
    rows: &[ImportRow],
    skipped: &[import::Skipped],
    counts: &ImportCounts,
    bind: bool,
    dry_run: bool,
    failure: Option<&(String, String)>,
) -> serde_json::Value {
    let entries: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            let mut entry = serde_json::json!({
                "line": row.line,
                "name": row.name,
                "kind": row.kind,
                "result": row.result,
            });
            if let Some(variable) = &row.variable {
                entry["variable"] = variable.clone().into();
            }
            if let Some(reason) = &row.reason {
                entry["reason"] = reason.clone().into();
            }
            entry
        })
        .chain(skipped.iter().map(|skip| {
            serde_json::json!({ "line": skip.line, "result": format!("left out: {}", skip.reason) })
        }))
        .collect();
    let mut summary = serde_json::json!({
        "ok": failure.is_none(),
        "format": format.label(),
        "added": counts.added,
        "failed": counts.failed,
        "left_out": counts.left_out + skipped.len(),
        "dry_run": dry_run,
        "entries": entries,
    });
    if bind {
        summary["bound"] = counts.bound.into();
        summary["not_bound"] = counts.not_bound.into();
    }
    if let Some((code, message)) = failure {
        summary["code"] = code.clone().into();
        summary["message"] = message.clone().into();
    }
    summary
}

/// The text answer of an import: the table, then why each variable is not bound. A
/// table cell is cut at its width, so the reasons are full lines under it.
fn import_text(rows: &[ImportRow], skipped: &[import::Skipped]) -> String {
    let mut table = Table::new(&["LINE", "NAME", "KIND", "RESULT"]);
    for row in rows {
        table.row(vec![
            row.line.to_string(),
            row.name.clone(),
            row.kind.to_owned(),
            row.result.clone(),
        ]);
    }
    for skip in skipped {
        table.row(vec![
            skip.line.to_string(),
            String::new(),
            String::new(),
            format!("left out: {}", skip.reason),
        ]);
    }
    let mut text = if table.is_empty() {
        String::new()
    } else {
        table.render()
    };
    for row in rows {
        if let (Some(variable), Some(reason)) = (&row.variable, &row.reason) {
            let _ = writeln!(
                text,
                "{} is not bound (line {}): {}",
                clean(variable),
                row.line,
                clean(reason)
            );
        }
    }
    text
}

// ---- Agents ----

pub fn agent(cli: &Cli, mut args: Args) -> Outcome {
    let action = args.positional().unwrap_or_else(|| "list".to_owned());
    match action.as_str() {
        "list" | "ls" => {
            args.finish()?;
            let response = cli.call(Command::AgentList)?;
            if cli.json {
                print_json(&response);
                return Ok(());
            }
            if let Data::Agents { agents } = response.data {
                if agents.is_empty() {
                    println!("No agents. Register one: apassy agent add NAME");
                    return Ok(());
                }
                let mut table = Table::new(&["ID", "NAME", "STATE", "TOKEN EXPIRES", "SEES ALL"]);
                for agent in agents {
                    let state = if agent.revoked {
                        "revoked"
                    } else if agent.token_expired {
                        "token expired"
                    } else {
                        "active"
                    };
                    table.row(vec![
                        agent.id.to_string(),
                        agent.name,
                        state.to_owned(),
                        print::time(agent.token_expires_at),
                        if agent.sees_all { "yes" } else { "no" }.to_owned(),
                    ]);
                }
                print!("{}", table.render());
            }
            Ok(())
        }
        "show" | "info" => {
            let agent = args.required("agent")?;
            args.finish()?;
            let response = cli.call(Command::AgentShow { agent })?;
            if cli.json {
                print_json(&response);
                return Ok(());
            }
            let Data::Agent(view) = response.data else {
                return Ok(());
            };
            let mut block = Block::new();
            block.line(
                "Agent",
                format!(
                    "{} (ID {}){}",
                    view.agent.name,
                    view.agent.id,
                    if view.agent.revoked { ", revoked" } else { "" }
                ),
            );
            block.line("Registered", print::time(view.agent.created_at));
            block.line(
                "Token expires",
                format!(
                    "{}{}",
                    print::time(view.agent.token_expires_at),
                    if view.agent.token_expired {
                        " (expired: apassy agent rotate)"
                    } else {
                        ""
                    }
                ),
            );
            block.line(
                "Sees all",
                if view.agent.sees_all {
                    "yes: names and plain fields of every credential"
                } else {
                    "no: only the credentials it can use"
                },
            );
            print!("{}", block.render());
            if !view.grants.is_empty() {
                println!("\nProcess access:");
                let mut table = Table::new(&["ITEM", "NAME", "FOLDER", "DECIDES", "RULE"]);
                for grant in &view.grants {
                    let mut rule = Vec::new();
                    if !grant.rule.allow.is_empty() {
                        rule.push(format!("allow {}", grant.rule.allow.join(" | ")));
                    }
                    if !grant.rule.forbid.is_empty() {
                        rule.push(format!("forbid {}", grant.rule.forbid.join(" | ")));
                    }
                    if let Some(at) = grant.rule.expires_at {
                        rule.push(format!("until {}", print::time(at)));
                    }
                    if let Some(max) = grant.rule.max_runs_per_hour {
                        rule.push(format!("{max} runs/h"));
                    }
                    if !grant.rule.instruction.is_empty() {
                        rule.push(format!("\"{}\"", grant.rule.instruction));
                    }
                    table.row(vec![
                        grant.item_id.to_string(),
                        grant.item_name.clone(),
                        grant
                            .folder
                            .clone()
                            .unwrap_or_else(|| "any folder".to_owned()),
                        match grant.mode {
                            GrantMode::Ask => "you",
                            GrantMode::Bouncer => "bouncer",
                        }
                        .to_owned(),
                        rule.join("; "),
                    ]);
                }
                print!("{}", table.render());
            }
            if !view.operations.is_empty() {
                println!("\nConnector operations:");
                let mut table = Table::new(&["ITEM", "NAME", "OPERATION"]);
                for operation in &view.operations {
                    table.row(vec![
                        operation.item_id.to_string(),
                        operation.item_name.clone(),
                        operation.operation.clone(),
                    ]);
                }
                print!("{}", table.render());
            }
            if !view.requests.is_empty() {
                println!("\nAccess requests:");
                print_requests(&view.requests);
            }
            Ok(())
        }
        "add" | "register" | "new" => {
            let name = args.rest().join(" ");
            args.finish()?;
            if name.trim().is_empty() {
                return Err(Failure::Usage(usage("Name the agent.")));
            }
            let response = cli.call(Command::AgentAdd { name })?;
            print_token(cli, &response);
            Ok(())
        }
        "revoke" => {
            let agent = args.required("agent")?;
            if !confirmed(
                &mut args,
                &format!("Revoke \"{}\"? Its token stops working.", clean(&agent)),
            )? {
                println!("Nothing was revoked.");
                return Ok(());
            }
            args.finish()?;
            simple_call(cli, Command::AgentRevoke { agent })
        }
        "rotate" => {
            let agent = args.required("agent")?;
            args.finish()?;
            expect_owner_check();
            let response = cli.call(Command::AgentRotate { agent })?;
            print_token(cli, &response);
            Ok(())
        }
        "see-all" | "seeall" => {
            let agent = args.required("agent")?;
            let state = args.required("state: on or off")?;
            args.finish()?;
            let on = match state.as_str() {
                "on" | "yes" | "true" => true,
                "off" | "no" | "false" => false,
                _ => return Err(Failure::Usage(usage("Use on or off."))),
            };
            if on {
                owner_check_call(cli, Command::AgentSeeAll { agent, on })
            } else {
                simple_call(cli, Command::AgentSeeAll { agent, on })
            }
        }
        "lifetime" => {
            let days = args.positional().map(|days| {
                days.parse::<u32>()
                    .map_err(|_| Failure::Usage(usage("The lifetime is a whole number of days.")))
            });
            let days = days.transpose()?;
            args.finish()?;
            if days.is_some() {
                owner_check_call(cli, Command::TokenLifetime { days })
            } else {
                simple_call(cli, Command::TokenLifetime { days })
            }
        }
        "setup" => super::setup::run(cli, args),
        other => Err(Failure::Usage(usage(format!(
            "Unknown agent command \"{other}\". Run apassy help agent."
        )))),
    }
}

/// Print a new agent token. With `--json`, the token is in the JSON.
fn print_token(cli: &Cli, response: &Response) {
    if cli.json {
        print_json(response);
        return;
    }
    if let Data::Token { agent, token } = &response.data {
        terminal::tell(&format!(
            "{} (ID {}). Save the token now. Apassy does not show it again:",
            agent.name, agent.id
        ));
        println!("{}", token.expose());
        let _ = std::io::stdout().flush();
        terminal::tell(
            "Set it as APASSY_AGENT_TOKEN of the MCP server, or run apassy setup claude|codex.",
        );
    } else {
        println!("{}", clean(&response.message));
    }
}

// ---- Grants, requests, runs, patterns ----

fn grant_mode(args: &mut Args) -> Result<GrantMode, Failure> {
    match args.value(&["--mode"])?.as_deref() {
        None | Some("ask") | Some("owner") => Ok(GrantMode::Ask),
        Some("bouncer") | Some("auto") => Ok(GrantMode::Bouncer),
        Some(_) => Err(Failure::Usage(usage("The mode is ask or bouncer."))),
    }
}

/// `--folder DIR`, `--any-folder`, or the current directory.
fn grant_folder(args: &mut Args) -> Result<Option<String>, Failure> {
    let any = args.flag(&["--any-folder", "--anywhere"]);
    let folder = args.value(&["--folder", "--dir"])?;
    match (any, folder) {
        (true, Some(_)) => Err(Failure::Usage(usage(
            "Use --folder or --any-folder, not both.",
        ))),
        (true, None) => Ok(None),
        (false, Some(folder)) => {
            let path = std::path::Path::new(&folder);
            let absolute = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()?.join(path)
            };
            Ok(Some(absolute.display().to_string()))
        }
        (false, None) => Ok(Some(std::env::current_dir()?.display().to_string())),
    }
}

pub fn grant(cli: &Cli, mut args: Args) -> Outcome {
    let action = args
        .positional()
        .ok_or_else(|| usage("Name a grant command: set, remove, rule, or operation."))?;
    match action.as_str() {
        "set" | "add" | "give" => {
            let agent = args.required("agent")?;
            let mode = grant_mode(&mut args)?;
            let folder = grant_folder(&mut args)?;
            let items = args.rest();
            args.finish()?;
            if items.is_empty() {
                return Err(Failure::Usage(usage("Name at least one credential.")));
            }
            terminal::tell(&format!(
                "Folder: {}. Decides: {}.",
                folder.as_deref().unwrap_or("any folder"),
                match mode {
                    GrantMode::Ask => "you, for each run",
                    GrantMode::Bouncer => "the bouncer; a risky run waits for you",
                }
            ));
            owner_check_call(
                cli,
                Command::GrantSet {
                    agent,
                    items,
                    folder,
                    mode,
                },
            )
        }
        "remove" | "rm" | "revoke" => {
            let agent = args.required("agent")?;
            let item = args.required("credential")?;
            args.finish()?;
            simple_call(cli, Command::GrantRemove { agent, item })
        }
        "rule" => {
            let agent = args.required("agent")?;
            let item = args.required("credential")?;
            let rule = RuleInput {
                allow: args.values(&["--allow"])?,
                forbid: args.values(&["--forbid"])?,
                expires_hours: args.number(&["--expires"])?,
                max_runs_per_hour: args.number(&["--max-runs"])?,
                instruction: args.value(&["--instruction"])?.unwrap_or_default(),
            };
            args.finish()?;
            owner_check_call(cli, Command::GrantRule { agent, item, rule })
        }
        "operation" | "op" => {
            let agent = args.required("agent")?;
            let item = args.required("credential")?;
            let operation = args.required("operation")?;
            let remove = args.flag(&["--remove"]);
            args.finish()?;
            if remove {
                simple_call(
                    cli,
                    Command::OperationRemove {
                        agent,
                        item,
                        operation,
                    },
                )
            } else {
                owner_check_call(
                    cli,
                    Command::OperationAllow {
                        agent,
                        item,
                        operation,
                    },
                )
            }
        }
        other => Err(Failure::Usage(usage(format!(
            "Unknown grant command \"{other}\". Run apassy help grant."
        )))),
    }
}

fn print_requests(requests: &[crate::owner::wire::RequestRow]) {
    let mut table = Table::new(&[
        "ID",
        "STATE",
        "AGENT",
        "CREDENTIAL",
        "WHEN",
        "REASON (from the agent)",
    ]);
    for request in requests {
        table.row(vec![
            request.id.to_string(),
            request.state.clone(),
            request.agent_name.clone(),
            request.item_name.clone(),
            print::time(request.created_at),
            request.reason.clone(),
        ]);
    }
    print!("{}", table.render());
}

fn parse_id(text: &str, what: &str) -> Result<u64, Failure> {
    text.trim()
        .parse()
        .map_err(|_| Failure::Usage(usage(format!("The {what} ID is a number."))))
}

pub fn request(cli: &Cli, mut args: Args) -> Outcome {
    let action = args.positional().unwrap_or_else(|| "list".to_owned());
    match action.as_str() {
        "list" | "ls" => {
            let all = args.flag(&["--all"]);
            args.finish()?;
            let response = cli.call(Command::RequestList { all })?;
            if cli.json {
                print_json(&response);
                return Ok(());
            }
            if let Data::Requests { requests } = response.data {
                if requests.is_empty() {
                    println!(
                        "{}",
                        if all {
                            "No requests."
                        } else {
                            "No open requests."
                        }
                    );
                } else {
                    print_requests(&requests);
                }
            }
            Ok(())
        }
        "grant" | "approve" => {
            let request = parse_id(&args.required("request ID")?, "request")?;
            let mode = grant_mode(&mut args)?;
            let folder = grant_folder(&mut args)?;
            args.finish()?;
            owner_check_call(
                cli,
                Command::RequestGrant {
                    request,
                    folder,
                    mode,
                },
            )
        }
        "deny" => {
            let request = parse_id(&args.required("request ID")?, "request")?;
            args.finish()?;
            simple_call(cli, Command::RequestDeny { request })
        }
        other => Err(Failure::Usage(usage(format!(
            "Unknown request command \"{other}\". Run apassy help request."
        )))),
    }
}

pub fn runs(cli: &Cli, mut args: Args) -> Outcome {
    let action = args.positional().unwrap_or_else(|| "list".to_owned());
    match action.as_str() {
        "list" | "ls" => {
            args.finish()?;
            let response = cli.call(Command::RunList)?;
            if cli.json {
                print_json(&response);
                return Ok(());
            }
            let Data::Runs { runs } = response.data else {
                return Ok(());
            };
            if runs.is_empty() {
                println!("No run waits for you.");
                return Ok(());
            }
            for run in runs {
                let mut block = Block::new();
                block.line(
                    "Run",
                    format!(
                        "{} from {}, waits {}",
                        run.id,
                        run.agent,
                        print::duration(run.waiting_secs)
                    ),
                );
                block.line("Command", run.command.join(" "));
                block.line("Folder", run.cwd);
                block.line("Variables", run.variables.join(", "));
                block.line("Purpose", run.purpose);
                block.line(
                    "User request",
                    if run.user_request.is_empty() {
                        String::new()
                    } else {
                        format!("\"{}\" ({})", run.user_request, run.request_source)
                    },
                );
                block.line("Check", run.risk);
                block.line(
                    "Approve",
                    format!(
                        "apassy runs approve {}{}",
                        run.id,
                        if run.can_remember {
                            " [--remember]"
                        } else {
                            ""
                        }
                    ),
                );
                println!("{}", block.render());
            }
            Ok(())
        }
        "approve" => {
            let run = parse_id(&args.required("run ID")?, "run")?;
            let remember = args.flag(&["--remember"]);
            args.finish()?;
            owner_check_call(cli, Command::RunApprove { run, remember })
        }
        "deny" => {
            let run = parse_id(&args.required("run ID")?, "run")?;
            args.finish()?;
            simple_call(cli, Command::RunDeny { run })
        }
        other => Err(Failure::Usage(usage(format!(
            "Unknown runs command \"{other}\". Run apassy help runs."
        )))),
    }
}

pub fn pattern(cli: &Cli, mut args: Args) -> Outcome {
    let action = args.positional().unwrap_or_else(|| "list".to_owned());
    match action.as_str() {
        "list" | "ls" => {
            args.finish()?;
            let response = cli.call(Command::PatternList)?;
            if cli.json {
                print_json(&response);
                return Ok(());
            }
            if let Data::Patterns { patterns } = response.data {
                if patterns.is_empty() {
                    println!("No remembered patterns.");
                    return Ok(());
                }
                let mut table = Table::new(&["ID", "STATE", "RUNS", "LAST USED", "PATTERN"]);
                for pattern in patterns {
                    table.row(vec![
                        pattern.id.to_string(),
                        pattern.state,
                        pattern.uses.to_string(),
                        print::time(pattern.last_used_at),
                        pattern.display,
                    ]);
                }
                print!("{}", table.render());
            }
            Ok(())
        }
        "remove" | "rm" | "forget" => {
            let pattern = parse_id(&args.required("pattern ID")?, "pattern")?;
            args.finish()?;
            simple_call(cli, Command::PatternRemove { pattern })
        }
        other => Err(Failure::Usage(usage(format!(
            "Unknown pattern command \"{other}\". Run apassy help pattern."
        )))),
    }
}

// ---- History ----

pub fn activity(cli: &Cli, mut args: Args) -> Outcome {
    let limit = args.number(&["--limit", "-n"])?;
    let agent = args.value(&["--agent"])?;
    let item = args.value(&["--item"])?;
    args.finish()?;
    let response = cli.call(Command::Activity { limit, agent, item })?;
    if cli.json {
        print_json(&response);
        return Ok(());
    }
    if let Data::Activity { entries } = response.data {
        if entries.is_empty() {
            println!("No activity.");
            return Ok(());
        }
        let mut table = Table::new(&[
            "WHEN",
            "AGENT",
            "CREDENTIAL",
            "OPERATION",
            "DECISION",
            "REASON",
        ]);
        for entry in entries {
            table.row(vec![
                print::time(entry.at),
                entry.agent,
                entry.item,
                entry.operation,
                entry.decision,
                entry.reason,
            ]);
        }
        print!("{}", table.render());
    }
    Ok(())
}

pub fn decisions(cli: &Cli, mut args: Args) -> Outcome {
    let action = args.positional().unwrap_or_else(|| "export".to_owned());
    if action != "export" {
        return Err(Failure::Usage(usage("Use apassy decisions export.")));
    }
    let output = args.value(&["--output", "-o"])?;
    args.finish()?;
    let response = cli.call(Command::DecisionExport)?;
    let Data::Export { jsonl } = response.data else {
        return Err(Failure::Other("Apassy sent no export.".to_owned()));
    };
    match output {
        None => print!("{jsonl}"),
        Some(path) => {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|err| Failure::Other(format!("Cannot create {path}: {err}")))?;
            file.write_all(jsonl.as_bytes())?;
            terminal::tell(&format!("{} written to {path}.", response.message));
        }
    }
    Ok(())
}

// ---- Vault ----

pub fn backup(cli: &Cli, mut args: Args) -> Outcome {
    let path = args.required("backup file")?;
    args.finish()?;
    let path = std::path::Path::new(&path);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    simple_call(
        cli,
        Command::Backup {
            path: absolute.display().to_string(),
        },
    )
}

pub fn vault(cli: &Cli, mut args: Args) -> Outcome {
    let action = args.positional().ok_or_else(|| {
        usage("Name a vault command: backup, change-passphrase, restore, lock, or unlock.")
    })?;
    match action.as_str() {
        "backup" => backup(cli, args),
        "lock" => simple(cli, args, Command::Lock),
        "unlock" | "show" => simple(cli, args, Command::Show),
        "change-passphrase" | "passphrase" => {
            args.finish()?;
            let current = terminal::read_hidden("Current passphrase (hidden): ")?;
            let new = terminal::read_hidden_twice(
                "New passphrase (hidden): ",
                "New passphrase again (hidden): ",
            )?;
            simple_call(cli, Command::ChangePassphrase { current, new })
        }
        "restore" => {
            let backup = args.required("backup file")?;
            args.finish()?;
            let path = std::path::Path::new(&backup);
            let absolute = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()?.join(path)
            };
            simple_call(
                cli,
                Command::Restore {
                    backup: absolute.display().to_string(),
                },
            )
        }
        other => Err(Failure::Usage(usage(format!(
            "Unknown vault command \"{other}\". Run apassy help vault."
        )))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_lines_set_and_clear_the_session() {
        assert_eq!(
            shell_line("/bin/zsh", Some("apassy_cli_x")),
            "export APASSY_SESSION='apassy_cli_x'"
        );
        assert_eq!(
            shell_line("/opt/homebrew/bin/fish", Some("t")),
            "set -gx APASSY_SESSION 't'"
        );
        assert_eq!(shell_line("bash", None), "unset APASSY_SESSION");
        assert_eq!(shell_line("fish", None), "set -e APASSY_SESSION");
    }

    #[test]
    fn kinds_have_short_names() {
        assert_eq!(parse_kind("api-key").unwrap(), CredentialKind::ApiKey);
        assert_eq!(parse_kind("SSH").unwrap(), CredentialKind::SshKey);
        assert_eq!(parse_kind("db").unwrap(), CredentialKind::Database);
        assert!(parse_kind("card").is_err());
    }

    fn not_bound(line: usize, variable: &str, reason: &str) -> ImportRow {
        ImportRow {
            reason: Some(reason.to_owned()),
            ..ImportRow::new(
                line,
                format!("{variable} item"),
                "api-key",
                format!("added, {variable} not bound"),
                Some(variable.to_owned()),
            )
        }
    }

    /// A cancel or a refused name ends `import --json` with one document, not two.
    #[test]
    fn import_json_holds_the_failure_in_one_document() {
        let rows = [
            not_bound(1, "CANCELLED_KEY", "The owner cancelled."),
            ImportRow::new(
                2,
                "BOUND".to_owned(),
                "api-key",
                "added, bound to BOUND".to_owned(),
                Some("BOUND".to_owned()),
            ),
        ];
        let counts = ImportCounts {
            added: 2,
            bound: 1,
            not_bound: 1,
            ..ImportCounts::default()
        };
        let failure = import_failure(
            &counts,
            Some(("cancelled".to_owned(), "The owner cancelled.".to_owned())),
        );
        let summary = import_json(
            Format::Env,
            &rows,
            &[],
            &counts,
            true,
            false,
            failure.as_ref(),
        );
        assert_eq!(summary["ok"], false);
        assert_eq!(summary["code"], "cancelled");
        assert_eq!(summary["message"], "The owner cancelled.");
        assert_eq!(summary["not_bound"], 1);
        assert_eq!(summary["entries"][0]["reason"], "The owner cancelled.");
        assert!(summary["entries"][1].get("reason").is_none());
        // The failure is in the document, so the command line prints nothing more.
        assert_eq!(
            super::super::report(Failure::Printed, true),
            super::super::EXIT_FAILED
        );

        let refused = ImportCounts {
            added: 1,
            not_bound: 1,
            ..ImportCounts::default()
        };
        assert_eq!(
            import_failure(&refused, None),
            Some((
                "partial".to_owned(),
                "1 variables were not bound.".to_owned()
            ))
        );
        let done = ImportCounts {
            added: 1,
            bound: 1,
            ..ImportCounts::default()
        };
        let summary = import_json(Format::Env, &rows[1..], &[], &done, true, false, None);
        assert_eq!(summary["ok"], true);
        assert!(summary.get("code").is_none());
    }

    /// The table cuts a long cell, so the reason of a variable that is not bound is a
    /// full line under the table.
    #[test]
    fn import_text_shows_the_full_reason_of_each_variable_not_bound() {
        let invalid = "The name is not valid: use A-Z, 0-9, and _, start with a letter or _, and no system name such as PATH.";
        let title = "T".repeat(200);
        let taken = format!("{title} uses this variable.");
        let rows = [
            not_bound(5, "PATH", invalid),
            not_bound(6, "TAKEN_KEY", &taken),
        ];
        let text = import_text(&rows, &[]);
        assert!(
            text.contains(&format!("PATH is not bound (line 5): {invalid}")),
            "{text}"
        );
        assert!(
            text.contains(&format!("TAKEN_KEY is not bound (line 6): {taken}")),
            "{text}"
        );
        assert!(text.contains("added, PATH not bound"), "{text}");
    }
}
