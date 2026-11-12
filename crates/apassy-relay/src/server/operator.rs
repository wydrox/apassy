//! The socket of the operator: `<data dir>/admin.sock` (ADR 0019, section 10).
//!
//! The operator works on the server only: `apassy-relay admin ...` in the container
//! sends one JSON line to the running relay and reads one JSON line back. There is no
//! operator endpoint on HTTP. The socket has mode 0600 in a directory of mode 0700, so
//! only the user of the relay can use it. No command shows members, items, runs, or the
//! audit of a team.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::Envelope;
use crate::error::{RelayError, RelayResult};
use crate::ids::TeamId;
use crate::server::directory::TeamLimitsUpdate;
use crate::server::hub::Hub;

/// The longest request line.
const MAX_LINE: u64 = 4096;

/// One command of the operator. One at a time, read from a line: the size of the
/// `Limits` variant does not matter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// A one-time code that makes one team (`apassy-team create`).
    TeamCode {
        hours: u64,
    },
    /// A node pairing code (`apassy pair`, node-pairing-v1 section 6): a team code of
    /// kind `node` for 1 to 10 minutes. Only a node takes it at `POST /v1/teams`.
    NodeCode {
        minutes: u64,
    },
    /// The teams: id, name, state, counts, last activity.
    Teams,
    /// Private readiness: active team databases and capacity, separate from liveness.
    Readiness,
    /// Reads or changes the limits of one team.
    Limits {
        team: TeamId,
        set: Option<TeamLimitsUpdate>,
    },
    /// Tokens stop, sessions and waiting runs end, the file closes.
    Suspend {
        team: TeamId,
    },
    Resume {
        team: TeamId,
    },
    /// Deletes a suspended team: its file and its key. No undo. `free_connect_key`: the
    /// device key of a Connect team may make a new team (docs/SPEC.md section 27.10).
    Delete {
        team: TeamId,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        free_connect_key: bool,
    },
    /// A consistent copy of `relay.db` and every team file, with a manifest.
    Backup,
    /// Suspends idle Connect teams and deletes those suspended long enough (SPEC 26.5).
    ConnectSweep {
        idle_days: u64,
        delete_days: u64,
        dry_run: bool,
    },
    /// Connect billing (SPEC 34.6): the open problems and the clock of the deletion pass;
    /// `resume_deletions` takes the current clock as right after a held pass; `resolve`
    /// marks one problem handled in the Stripe dashboard.
    Billing {
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        resume_deletions: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resolve: Option<u64>,
    },
}

/// Runs one command.
pub fn run(hub: &Hub, command: &Command, now: u64) -> RelayResult<Value> {
    // `connect` mode has no operator team and no node (docs/SPEC.md section 37): a code
    // would only make a team that the relay never serves.
    if hub.config.connect.plain_files()
        && matches!(command, Command::TeamCode { .. } | Command::NodeCode { .. })
    {
        return Err(RelayError::invalid(
            "APASSY_RELAY_MODE=connect makes no team codes: teams run on their own Apassy node (ADR 0037).",
        ));
    }
    match command {
        Command::TeamCode { hours } => {
            let (code, expires_at) = hub.directory.new_team_code(*hours, now)?;
            Ok(json!({"code": code.expose(), "expires_at": expires_at}))
        }
        Command::NodeCode { minutes } => {
            let (code, expires_at) = hub.directory.new_node_code(*minutes, now)?;
            Ok(json!({"code": code.expose(), "expires_at": expires_at}))
        }
        Command::Readiness => hub.readiness(),
        Command::Teams => serde_json::to_value(hub.team_infos()?)
            .map_err(|_| RelayError::internal("A result cannot be written.")),
        Command::Limits { team, set } => serde_json::to_value(hub.limits(team, *set, now)?)
            .map_err(|_| RelayError::internal("A result cannot be written.")),
        Command::Suspend { team } => {
            hub.suspend(team, now)?;
            Ok(json!({"team": team, "state": "suspended"}))
        }
        Command::Resume { team } => {
            hub.resume(team, now)?;
            Ok(json!({"team": team, "state": "active"}))
        }
        Command::Delete {
            team,
            free_connect_key,
        } => {
            let freed = hub.delete(team, *free_connect_key, now)?;
            if *free_connect_key {
                let key = if freed { "freed" } else { "none" };
                return Ok(json!({"team": team, "state": "deleted", "connect_key": key}));
            }
            Ok(json!({"team": team, "state": "deleted"}))
        }
        Command::Backup => hub.backup(now),

        Command::ConnectSweep {
            idle_days,
            delete_days,
            dry_run,
        } => serde_json::to_value(hub.connect_sweep(*idle_days, *delete_days, *dry_run, now)?)
            .map_err(|_| RelayError::internal("A result cannot be written.")),
        Command::Billing {
            resume_deletions,
            resolve,
        } => crate::server::billing_store::operator(hub, *resume_deletions, *resolve, now),
    }
}

/// Binds the socket and serves it in a thread until `stop` is set.
pub fn listen(hub: Arc<Hub>, stop: Arc<AtomicBool>) -> RelayResult<JoinHandle<()>> {
    let path = hub.config.admin_socket_path();
    remove_stale(&path)?;
    let listener = UnixListener::bind(&path)
        .map_err(|_| RelayError::internal("The operator socket cannot be bound."))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| RelayError::internal("The operator socket mode cannot be set to 0600."))?;
    listener
        .set_nonblocking(true)
        .map_err(|_| RelayError::internal("The operator socket cannot be set up."))?;
    std::thread::Builder::new()
        .name("relay-operator".to_string())
        .spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => serve_one(&hub, stream),
                    Err(_) => std::thread::sleep(Duration::from_millis(200)),
                }
            }
            let _ = std::fs::remove_file(&path);
        })
        .map_err(|_| RelayError::internal("The operator thread cannot start."))
}

/// Removes a socket left by a relay that did not stop cleanly. Refuses any other file.
pub(crate) fn remove_stale(path: &Path) -> RelayResult<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path)
            .map_err(|_| RelayError::internal("The old operator socket cannot be removed.")),
        Ok(_) => Err(RelayError::internal(
            "admin.sock in the data directory is not a socket.",
        )),
        Err(_) => Ok(()),
    }
}

fn serve_one(hub: &Hub, stream: UnixStream) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let mut line = String::new();
    let read = BufReader::new((&stream).take(MAX_LINE)).read_line(&mut line);
    let envelope = match read {
        Ok(_) => match serde_json::from_str::<Command>(line.trim()) {
            Ok(command) => match run(hub, &command, crate::now_unix()) {
                Ok(result) => Envelope::success(result),
                Err(error) => error.to_envelope(),
            },
            Err(_) => RelayError::invalid("The command is not known.").to_envelope(),
        },
        Err(_) => RelayError::invalid("The command cannot be read.").to_envelope(),
    };
    let mut text = serde_json::to_string(&envelope).unwrap_or_default();
    text.push('\n');
    let _ = (&stream).write_all(text.as_bytes());
}

/// Sends one command to the socket of a running relay and returns its result.
pub fn send(socket: &Path, command: &Command) -> RelayResult<Value> {
    let mut stream = UnixStream::connect(socket).map_err(|_| {
        RelayError::internal(
            "The relay is not running here, or the operator socket cannot be reached.",
        )
    })?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let mut text = serde_json::to_string(command)
        .map_err(|_| RelayError::internal("The command cannot be written."))?;
    text.push('\n');
    stream
        .write_all(text.as_bytes())
        .map_err(|_| RelayError::internal("The command cannot be sent."))?;
    let mut answer = String::new();
    BufReader::new(stream)
        .read_line(&mut answer)
        .map_err(|_| RelayError::internal("The relay did not answer."))?;
    let envelope: Value = serde_json::from_str(answer.trim())
        .map_err(|_| RelayError::internal("The answer of the relay is not JSON."))?;
    if envelope["ok"] == true {
        Ok(envelope["result"].clone())
    } else {
        Err(RelayError::internal(format!(
            "{} ({})",
            envelope["error"]["message"]
                .as_str()
                .unwrap_or("The command failed."),
            envelope["error"]["code"].as_str().unwrap_or("relay_error"),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_have_one_json_form() {
        let team = TeamId::parse("t_abcdefgh23").unwrap();
        for (command, text) in [
            (
                Command::TeamCode { hours: 72 },
                r#"{"command":"team_code","hours":72}"#,
            ),
            (Command::Teams, r#"{"command":"teams"}"#),
            (
                Command::NodeCode { minutes: 10 },
                r#"{"command":"node_code","minutes":10}"#,
            ),
            (
                Command::Limits {
                    team: team.clone(),
                    set: None,
                },
                r#"{"command":"limits","team":"t_abcdefgh23","set":null}"#,
            ),
            (
                Command::Limits {
                    team: team.clone(),
                    set: Some(TeamLimitsUpdate {
                        members: Some(7),
                        ..Default::default()
                    }),
                },
                r#"{"command":"limits","team":"t_abcdefgh23","set":{"members":7}}"#,
            ),
            (
                Command::Suspend { team: team.clone() },
                r#"{"command":"suspend","team":"t_abcdefgh23"}"#,
            ),
            (
                Command::Delete {
                    team: team.clone(),
                    free_connect_key: false,
                },
                r#"{"command":"delete","team":"t_abcdefgh23"}"#,
            ),
            (
                Command::Delete {
                    team,
                    free_connect_key: true,
                },
                r#"{"command":"delete","team":"t_abcdefgh23","free_connect_key":true}"#,
            ),
            (
                Command::ConnectSweep {
                    idle_days: 30,
                    delete_days: 30,
                    dry_run: true,
                },
                r#"{"command":"connect_sweep","idle_days":30,"delete_days":30,"dry_run":true}"#,
            ),
        ] {
            assert_eq!(serde_json::to_string(&command).unwrap(), text);
            assert_eq!(serde_json::from_str::<Command>(text).unwrap(), command);
        }
        assert!(
            serde_json::from_str::<Command>(r#"{"command":"members","team":"t_abcdefgh23"}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<Command>(r#"{"command":"suspend","team":"bad"}"#).is_err());
        assert!(matches!(
            serde_json::from_str::<Command>(r#"{"command":"limits","team":"t_abcdefgh23"}"#)
                .unwrap(),
            Command::Limits { set: None, .. }
        ));
        assert!(
            serde_json::from_str::<Command>(
                r#"{"command":"limits","team":"t_abcdefgh23","set":{"unknown":1}}"#
            )
            .is_err()
        );
    }
}
