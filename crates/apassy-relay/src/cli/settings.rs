//! The settings file of the CLI (relay URL and member token), mode 0600, and the environment variables that override it.
//!
//! Variables win over the file. An empty variable counts as unset.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::cli::CliError;
use crate::secret::SecretString;

pub const ENV_RELAY_URL: &str = "APASSY_RELAY_URL";
pub const ENV_TEAM_TOKEN: &str = "APASSY_TEAM_TOKEN";
pub const ENV_AGENT_TOKEN: &str = "APASSY_TOKEN";
pub const ENV_EDGE_SECRET: &str = "APASSY_EDGE_SECRET";

/// The variables that a child of `run` must not inherit.
pub const CREDENTIAL_VARS: [&str; 3] = [ENV_AGENT_TOKEN, ENV_TEAM_TOKEN, ENV_EDGE_SECRET];

/// One saved team. Device keys and access tokens are never stored here.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TeamSettings {
    pub relay_url: String,
    #[serde(default)]
    pub team: String,
    #[serde(default)]
    pub member: String,
    #[serde(default)]
    pub device_id: Option<crate::ids::DeviceId>,
    #[serde(default)]
    pub safety_verified: Option<bool>,
    #[serde(default)]
    pub member_token: Option<SecretString>,
}

#[derive(Debug, Default, Deserialize)]
struct FileSettings {
    #[serde(default)]
    version: Option<u32>,
    #[serde(default)]
    current: Option<crate::ids::TeamId>,
    #[serde(default)]
    teams: std::collections::BTreeMap<crate::ids::TeamId, TeamSettings>,
    #[serde(default)]
    relay_url: Option<String>,
    #[serde(default)]
    member_token: Option<SecretString>,
}

/// The selected team after the variables and file are merged.
#[derive(Debug, Default)]
pub struct Settings {
    pub relay_url: Option<String>,
    pub member_token: Option<SecretString>,
    pub agent_token: Option<SecretString>,
    pub edge_secret: Option<SecretString>,
    pub team_id: Option<crate::ids::TeamId>,
    pub device_id: Option<crate::ids::DeviceId>,
    pub safety_verified: Option<bool>,
    pub team: Option<String>,
    pub member: Option<String>,
}

pub const ENV_TEAM: &str = "APASSY_TEAM";

fn env_text(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

pub fn env_secret(name: &str) -> Option<SecretString> {
    env_text(name).map(SecretString::new)
}

/// `$XDG_CONFIG_HOME/apassy-team` or `~/.config/apassy-team`.
pub fn settings_dir() -> Result<PathBuf, CliError> {
    if let Some(xdg) = env_text("XDG_CONFIG_HOME") {
        let path = PathBuf::from(xdg);
        if path.is_absolute() {
            return Ok(path.join("apassy-team"));
        }
    }
    match env_text("HOME") {
        Some(home) => Ok(PathBuf::from(home).join(".config").join("apassy-team")),
        None => Err(CliError::usage(
            "Neither XDG_CONFIG_HOME nor HOME is set, so there is no place for the settings file.",
        )),
    }
}

pub fn settings_path() -> Result<PathBuf, CliError> {
    Ok(settings_dir()?.join("settings.json"))
}

fn read_file() -> Result<FileSettings, CliError> {
    let path = settings_path()?;
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => zeroize::Zeroizing::new(text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(FileSettings::default());
        }
        Err(err) => {
            return Err(CliError::usage(format!(
                "Cannot read the settings file {}: {}.",
                path.display(),
                err.kind()
            )));
        }
    };
    if let Ok(meta) = std::fs::metadata(&path)
        && meta.permissions().mode() & 0o077 != 0
    {
        eprintln!(
            "apassy-team: warning: {} is readable by others. Run: chmod 600 {}",
            path.display(),
            path.display()
        );
    }
    let file: FileSettings = serde_json::from_str(&text).map_err(|_| {
        CliError::usage(format!(
            "The settings file {} is not valid.",
            path.display()
        ))
    })?;
    if file.version.is_some_and(|v| v != 1 && v != 2) {
        return Err(CliError::usage("The settings version is not supported."));
    }
    Ok(file)
}

/// Loads the current team. A missing file is permitted.
pub fn load() -> Result<Settings, CliError> {
    load_for(None)
}

/// An explicit selector wins over APASSY_TEAM, which wins over current.
pub fn load_for(team: Option<&str>) -> Result<Settings, CliError> {
    let mut file = read_file()?;
    let selector = team.map(str::to_owned).or_else(|| env_text(ENV_TEAM));
    if selector.is_some() && file.version != Some(2) {
        migrate(&mut file)?;
    }
    let team_id = match selector {
        Some(text) => Some(
            crate::ids::TeamId::parse(&text)
                .ok_or_else(|| CliError::usage("The team id is not valid."))?,
        ),
        None => file.current.clone(),
    };
    let entry = match &team_id {
        Some(id) => Some(file.teams.get(id).ok_or_else(|| {
            CliError::usage(format!("There is no settings entry for team {id}."))
        })?),
        None => None,
    };
    let relay_url = env_text(ENV_RELAY_URL)
        .or_else(|| entry.map(|t| t.relay_url.clone()))
        .or(file.relay_url);
    let relay_url = relay_url.map(|url| normalize_url(&url)).transpose()?;
    Ok(Settings {
        relay_url,
        member_token: env_secret(ENV_TEAM_TOKEN)
            .or_else(|| entry.and_then(|t| t.member_token.clone()))
            .or(file.member_token),
        agent_token: env_secret(ENV_AGENT_TOKEN),
        edge_secret: env_secret(ENV_EDGE_SECRET),
        team_id,
        device_id: entry.and_then(|t| t.device_id),
        safety_verified: entry.and_then(|t| t.safety_verified),
        team: entry.map(|t| t.team.clone()),
        member: entry.map(|t| t.member.clone()),
    })
}

impl Settings {
    pub fn relay(&self) -> Result<&str, CliError> {
        self.relay_url.as_deref().ok_or_else(|| {
            CliError::usage(
                "No relay URL. Set APASSY_RELAY_URL, or run `apassy-team init --relay URL`.",
            )
        })
    }

    pub fn member(&self) -> Result<&SecretString, CliError> {
        self.member_token.as_ref().ok_or_else(|| {
            CliError::usage(
                "No member token. Set APASSY_TEAM_TOKEN, or run `apassy-team init` or `apassy-team join`.",
            )
        })
    }

    pub fn agent(&self) -> Result<&SecretString, CliError> {
        self.agent_token
            .as_ref()
            .ok_or_else(|| CliError::usage("No agent token. Set APASSY_TOKEN."))
    }
}

/// Checks a relay origin: `https://host[:port]`, or `http://` for a loopback host only,
/// so a token never crosses a network in clear. Removes trailing slashes.
pub fn normalize_url(text: &str) -> Result<String, CliError> {
    let text = text.trim().trim_end_matches('/');
    let (scheme, rest) = text.split_once("://").ok_or_else(|| {
        CliError::usage("The relay URL must start with https:// (or http://127.0.0.1).")
    })?;
    if rest.is_empty()
        || rest.contains(['/', '?', '#', '@'])
        || rest.chars().any(char::is_whitespace)
    {
        return Err(CliError::usage(
            "The relay URL must be an origin: scheme, host, and an optional port, with no path.",
        ));
    }
    let host = if let Some(inner) = rest.strip_prefix('[') {
        inner.split(']').next().unwrap_or("")
    } else {
        rest.split(':').next().unwrap_or("")
    };
    let loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    match scheme {
        "https" => {}
        "http" if loopback => {}
        "http" => {
            return Err(CliError::usage(
                "Plain http:// is allowed only for 127.0.0.1 or localhost. Use https://.",
            ));
        }
        _ => return Err(CliError::usage("The relay URL must start with https://.")),
    }
    Ok(format!("{scheme}://{rest}"))
}

/// Makes the directory (and its parents) with mode 0700, and sets 0700 on it.
pub fn ensure_private_dir(dir: &std::path::Path) -> Result<(), CliError> {
    let fail = |what: &str, err: std::io::Error| {
        CliError::relay(format!("Cannot {what}: {}.", err.kind()))
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| fail("create the settings directory", e))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| fail("protect the settings directory", e))
}

/// Resolves the old single-team entry without applying environment overrides.
fn migrate(file: &mut FileSettings) -> Result<(), CliError> {
    if file.version == Some(2) {
        return Ok(());
    }
    if let (Some(relay), Some(token)) = (&file.relay_url, &file.member_token) {
        let relay = normalize_url(relay)?;
        let edge = env_secret(ENV_EDGE_SECRET);
        let client = crate::cli::client::Client::new(&relay, Some(token), edge.as_ref());
        let me: crate::api::MeView = client.ok(crate::cli::client::Method::Get, "/v1/me", None)?;
        let id = me.team_id.ok_or_else(|| {
            CliError::usage("The relay did not return a team id. Update the relay.")
        })?;
        file.teams.insert(
            id.clone(),
            TeamSettings {
                relay_url: relay,
                team: me.team,
                member: me.member_name,
                device_id: me.device_id,
                safety_verified: None,
                member_token: Some(token.clone()),
            },
        );
        file.current = Some(id);
    }
    file.version = Some(2);
    file.relay_url = None;
    file.member_token = None;
    Ok(())
}

fn write_file(file: &FileSettings) -> Result<PathBuf, CliError> {
    if file.teams.values().any(|team| {
        team.member_token
            .as_ref()
            .is_some_and(|token| token.expose().starts_with("apassy_acc_"))
    }) {
        return Err(CliError::usage(
            "Access tokens cannot be saved in settings.json.",
        ));
    }
    let dir = settings_dir()?;
    ensure_private_dir(&dir)?;
    #[derive(Serialize)]
    struct TeamRef<'a> {
        relay_url: &'a str,
        team: &'a str,
        member: &'a str,
        device_id: Option<crate::ids::DeviceId>,
        #[serde(skip_serializing_if = "Option::is_none")]
        safety_verified: Option<bool>,
        member_token: Option<&'a str>,
    }
    #[derive(Serialize)]
    struct FileRef<'a> {
        version: u32,
        current: &'a Option<crate::ids::TeamId>,
        teams: std::collections::BTreeMap<&'a crate::ids::TeamId, TeamRef<'a>>,
    }
    let teams = file
        .teams
        .iter()
        .map(|(id, t)| {
            (
                id,
                TeamRef {
                    relay_url: &t.relay_url,
                    team: &t.team,
                    member: &t.member,
                    device_id: t.device_id,
                    safety_verified: t.safety_verified,
                    member_token: t.member_token.as_ref().map(SecretString::expose),
                },
            )
        })
        .collect();
    let body = zeroize::Zeroizing::new(
        serde_json::to_string_pretty(&FileRef {
            version: 2,
            current: &file.current,
            teams,
        })
        .map_err(|_| CliError::relay("Cannot encode the settings."))?,
    );
    let path = dir.join("settings.json");
    let tmp = dir.join(format!("settings.json.{}.tmp", std::process::id()));
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|_| CliError::relay("Cannot create the settings file."))?;
    let result = output
        .write_all(body.as_bytes())
        .and_then(|_| output.write_all(b"\n"))
        .and_then(|_| output.sync_all())
        .and_then(|_| std::fs::rename(&tmp, &path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(|_| CliError::relay("Cannot write the settings file."))?;
    Ok(path)
}

/// Writes a member-token entry after GET /v1/me identifies the team.
pub fn save(relay_url: &str, member_token: &SecretString) -> Result<PathBuf, CliError> {
    let relay = normalize_url(relay_url)?;
    let edge = env_secret(ENV_EDGE_SECRET);
    let client = crate::cli::client::Client::new(&relay, Some(member_token), edge.as_ref());
    let me: crate::api::MeView = client.ok(crate::cli::client::Method::Get, "/v1/me", None)?;
    let id = me
        .team_id
        .ok_or_else(|| CliError::usage("The relay did not return a team id. Update the relay."))?;
    save_team(
        &id,
        &TeamSettings {
            relay_url: relay,
            team: me.team,
            member: me.member_name,
            device_id: me.device_id,
            safety_verified: None,
            member_token: Some(member_token.clone()),
        },
    )
}

pub fn save_team(id: &crate::ids::TeamId, entry: &TeamSettings) -> Result<PathBuf, CliError> {
    normalize_url(&entry.relay_url)?;
    let mut file = read_file()?;
    migrate(&mut file)?;
    file.teams.insert(id.clone(), entry.clone());
    file.current = Some(id.clone());
    write_file(&file)
}

pub struct SavedTeams {
    pub current: Option<crate::ids::TeamId>,
    pub teams: Vec<(crate::ids::TeamId, TeamSettings)>,
}

pub fn saved_teams() -> Result<SavedTeams, CliError> {
    let mut file = read_file()?;
    migrate(&mut file)?;
    Ok(SavedTeams {
        current: file.current,
        teams: file.teams.into_iter().collect(),
    })
}

pub fn list() -> Result<Vec<(crate::ids::TeamId, TeamSettings)>, CliError> {
    Ok(saved_teams()?.teams)
}

pub fn contains_team(id: &crate::ids::TeamId) -> Result<bool, CliError> {
    Ok(list()?.iter().any(|(saved, _)| saved == id))
}

/// Complete migration before a remote operation can invalidate the legacy token.
pub fn migrate_legacy() -> Result<(), CliError> {
    let mut file = read_file()?;
    if file.version != Some(2) && file.member_token.is_some() {
        migrate(&mut file)?;
        write_file(&file)?;
    }
    Ok(())
}

pub fn remove_team(id: &crate::ids::TeamId) -> Result<(), CliError> {
    let mut file = read_file()?;
    migrate(&mut file)?;
    file.teams.remove(id);
    if file.current.as_ref() == Some(id) {
        file.current = file.teams.keys().next().cloned();
    }
    write_file(&file)?;
    Ok(())
}

pub fn set_current(id: &crate::ids::TeamId) -> Result<(), CliError> {
    let mut file = read_file()?;
    migrate(&mut file)?;
    if !file.teams.contains_key(id) {
        return Err(CliError::usage(format!(
            "There is no settings entry for team {id}."
        )));
    }
    file.current = Some(id.clone());
    write_file(&file)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_origins_and_http_is_loopback_only() {
        assert_eq!(
            normalize_url("https://a.example/").unwrap(),
            "https://a.example"
        );
        assert_eq!(
            normalize_url(" http://127.0.0.1:8080 ").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(normalize_url("http://[::1]:9").unwrap(), "http://[::1]:9");
        assert!(normalize_url("http://a.example").is_err());
        assert!(normalize_url("https://a.example/v1").is_err());
        assert!(normalize_url("https://user@a.example").is_err());
        assert!(normalize_url("http://127.evil.example").is_err());
        assert!(normalize_url("a.example").is_err());
        assert!(normalize_url("ftp://a.example").is_err());
        assert!(normalize_url("https://").is_err());
    }
}
