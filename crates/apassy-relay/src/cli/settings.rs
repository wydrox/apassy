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

/// Read side of the file.
#[derive(Debug, Default, Deserialize)]
struct FileSettings {
    #[serde(default)]
    relay_url: Option<String>,
    #[serde(default)]
    member_token: Option<SecretString>,
}

/// Write side of the file.
#[derive(Serialize)]
struct FileSettingsRef<'a> {
    relay_url: &'a str,
    member_token: &'a str,
}

/// The settings after the variables and the file are merged.
#[derive(Debug, Default)]
pub struct Settings {
    pub relay_url: Option<String>,
    pub member_token: Option<SecretString>,
    pub agent_token: Option<SecretString>,
    pub edge_secret: Option<SecretString>,
}

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
    serde_json::from_str(&text).map_err(|_| {
        CliError::usage(format!(
            "The settings file {} is not valid. Run `apassy-team init` again.",
            path.display()
        ))
    })
}

/// Loads the variables and the file. A missing file is fine.
pub fn load() -> Result<Settings, CliError> {
    let file = read_file()?;
    let relay_url = match env_text(ENV_RELAY_URL).or(file.relay_url) {
        Some(url) => Some(normalize_url(&url)?),
        None => None,
    };
    Ok(Settings {
        relay_url,
        member_token: env_secret(ENV_TEAM_TOKEN).or(file.member_token),
        agent_token: env_secret(ENV_AGENT_TOKEN),
        edge_secret: env_secret(ENV_EDGE_SECRET),
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

/// Writes the settings file: directory 0700, file 0600, replaced atomically.
pub fn save(relay_url: &str, member_token: &SecretString) -> Result<PathBuf, CliError> {
    let dir = settings_dir()?;
    let fail = |what: &str, err: std::io::Error| {
        CliError::relay(format!("Cannot {what}: {}.", err.kind()))
    };
    ensure_private_dir(&dir)?;
    let body = zeroize::Zeroizing::new(
        serde_json::to_string_pretty(&FileSettingsRef {
            relay_url,
            member_token: member_token.expose(),
        })
        .map_err(|_| CliError::relay("Cannot encode the settings."))?,
    );
    let path = dir.join("settings.json");
    let tmp = dir.join("settings.json.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| fail("create the settings file", e))?;
    file.write_all(body.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|e| fail("write the settings file", e))?;
    std::fs::rename(&tmp, &path).map_err(|e| fail("replace the settings file", e))?;
    Ok(path)
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
