//! The configuration of the relay server, from the environment.
//!
//! | Variable | Meaning | Default |
//! | --- | --- | --- |
//! | `APASSY_RELAY_DATA` | Data directory: `relay.db`, `teams/<team id>.db`, `admin.sock` | `/data` |
//! | `APASSY_RELAY_LISTEN` | Address of the plain HTTP listener | `0.0.0.0:8080` |
//! | `APASSY_RELAY_PUBLIC_URL` | The public `https://` origin, no trailing slash | required |
//! | `APASSY_RELAY_EDGE_SECRET` or `APASSY_RELAY_EDGE_SECRET_FILE` | The secret the Worker adds as `X-Apassy-Edge`; at least 32 bytes | required |
//! | `APASSY_RELAY_KEY` or `APASSY_RELAY_KEY_FILE` | The master key: it opens `relay.db`, which holds the key of each team file; at least 16 bytes | required |
//! | `APASSY_RELAY_SESSION_TTL` | Seconds a proxy session lives; 60 to 3600 | `900` |
//! | `APASSY_RELAY_APPROVAL_TIMEOUT` | Seconds a run waits for the owner's host; 30 to 86400 | `600` |
//! | `APASSY_RELAY_BACKUP_DIR` | Where `admin backup` writes a new dated folder | `/backups` |
//! | `APASSY_RELAY_BLOCKED_ADDRESSES` | Public addresses or networks the proxy refuses too, comma-separated (the relay's own) | none |
//!
//! A `_FILE` variable names a file whose content (trailing newline removed) is the
//! value. It wins over the plain variable.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use crate::error::{RelayError, RelayResult};
use crate::secret::SecretString;

pub const MIN_EDGE_SECRET_BYTES: usize = 32;
pub const MIN_KEY_BYTES: usize = 16;
pub const DEFAULT_SESSION_TTL_SECS: u64 = 900;
pub const MAX_SESSION_TTL_SECS: u64 = 3600;
pub const DEFAULT_APPROVAL_TIMEOUT_SECS: u64 = 600;
/// The directory of the relay in the data directory: the teams and their keys.
pub const DIRECTORY_FILE: &str = "relay.db";
/// The folder of the team files in the data directory.
pub const TEAMS_DIR: &str = "teams";
/// The one team vault of a relay from before teams (ADR 0019). `apassy-relay migrate`
/// moves it into `teams/`.
pub const LEGACY_VAULT_FILE: &str = "team.db";
/// The Unix socket of the operator in the data directory.
pub const ADMIN_SOCKET: &str = "admin.sock";
/// The lock file of the data directory: one relay process at a time.
pub const LOCK_FILE: &str = "relay.lock";
/// The old `team.db` after `apassy-relay migrate`. It opens with the old key only.
pub const LEGACY_BACKUP_FILE: &str = "team.db.pre-teams";

/// How the proxy reaches upstream hosts.
#[derive(Debug, Clone)]
pub struct UpstreamOptions {
    /// Extra trusted root certificates (DER), next to the system roots. Tests only.
    pub extra_roots_der: Vec<Vec<u8>>,
    /// Fixed addresses for `(host, port)`, instead of DNS. Tests only.
    pub resolve: Vec<(String, u16, SocketAddr)>,
    /// Public networks that the proxy also refuses, for example the relay's own
    /// addresses (`APASSY_RELAY_BLOCKED_ADDRESSES`). Private ones are always refused.
    pub blocked: Vec<IpNet>,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
}

impl Default for UpstreamOptions {
    fn default() -> Self {
        Self {
            extra_roots_der: Vec::new(),
            resolve: Vec::new(),
            blocked: Vec::new(),
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(120),
        }
    }
}

/// An address with a prefix length: `9.9.9.117` or `2620:fe::/32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl IpNet {
    /// `ip` or `ip/prefix`.
    pub fn parse(text: &str) -> Option<Self> {
        let (addr, prefix) = match text.trim().split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text.trim(), None),
        };
        let addr: IpAddr = addr.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(text) => text.parse::<u8>().ok().filter(|p| *p <= max)?,
            None => max,
        };
        Some(Self { addr, prefix })
    }

    /// True when `ip` is in this network. An IPv4-mapped IPv6 address counts as IPv4.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// The limits of the HTTP layer. Not read from the environment. Tests set small ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The most requests handled at once. More get 503 `busy`.
    pub max_active: usize,
    /// Slots that agent requests (the proxy, `/mcp`, `/v1/runs`, `/v1/access`) never
    /// take, so members, approvers, and `/healthz` always get an answer.
    pub member_reserve: usize,
    /// The most long polls of one agent at once. A poll over this is answered at
    /// once, as with `wait=0`.
    pub long_polls_per_agent: usize,
    /// The most long polls of the owner's host at once (`GET /v1/host/requests`). A
    /// poll over this is answered at once, as with `wait=0`.
    pub host_long_polls: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_active: 256,
            member_reserve: 32,
            long_polls_per_agent: 4,
            host_long_polls: 2,
        }
    }
}

/// Everything the relay server needs to start.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub data_dir: PathBuf,
    pub listen: SocketAddr,
    /// For example `https://apassy-relay.wyderka.cc`. Base URLs start with it.
    pub public_url: String,
    pub edge_secret: SecretString,
    /// Opens the directory `relay.db`. Each team file has its own random key, kept in
    /// the directory.
    pub master_key: SecretString,
    pub session_ttl_secs: u64,
    pub approval_timeout_secs: u64,
    pub upstream: UpstreamOptions,
    pub limits: Limits,
    /// Where `apassy-relay admin backup` writes (`APASSY_RELAY_BACKUP_DIR`).
    pub backup_dir: PathBuf,
}

impl RelayConfig {
    pub fn directory_path(&self) -> PathBuf {
        self.data_dir.join(DIRECTORY_FILE)
    }

    pub fn teams_dir(&self) -> PathBuf {
        self.data_dir.join(TEAMS_DIR)
    }

    /// The file of one team.
    pub fn team_path(&self, team: &crate::ids::TeamId) -> PathBuf {
        self.teams_dir().join(format!("{team}.db"))
    }

    /// The vault of a relay from before teams.
    pub fn legacy_vault_path(&self) -> PathBuf {
        self.data_dir.join(LEGACY_VAULT_FILE)
    }

    pub fn admin_socket_path(&self) -> PathBuf {
        self.data_dir.join(ADMIN_SOCKET)
    }

    /// Reads the process environment.
    pub fn from_env() -> RelayResult<Self> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Reads the configuration through `lookup`, which returns a variable or `None`.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> RelayResult<Self> {
        let data_dir =
            PathBuf::from(lookup("APASSY_RELAY_DATA").unwrap_or_else(|| "/data".to_string()));
        let listen_text =
            lookup("APASSY_RELAY_LISTEN").unwrap_or_else(|| "0.0.0.0:8080".to_string());
        let listen = listen_text.parse::<SocketAddr>().map_err(|_| {
            RelayError::invalid("APASSY_RELAY_LISTEN is not an address such as 0.0.0.0:8080.")
        })?;
        let public_url = lookup("APASSY_RELAY_PUBLIC_URL")
            .ok_or_else(|| RelayError::invalid("APASSY_RELAY_PUBLIC_URL is required."))?;
        let public_url = checked_public_url(&public_url)?;
        let edge_secret = secret_from(&lookup, "APASSY_RELAY_EDGE_SECRET")?;
        if edge_secret.len() < MIN_EDGE_SECRET_BYTES {
            return Err(RelayError::invalid(format!(
                "The edge secret must have at least {MIN_EDGE_SECRET_BYTES} bytes."
            )));
        }
        let master_key = secret_from(&lookup, "APASSY_RELAY_KEY")?;
        if master_key.len() < MIN_KEY_BYTES {
            return Err(RelayError::invalid(format!(
                "The master key must have at least {MIN_KEY_BYTES} bytes."
            )));
        }
        let session_ttl_secs = number(
            &lookup,
            "APASSY_RELAY_SESSION_TTL",
            DEFAULT_SESSION_TTL_SECS,
            60,
            MAX_SESSION_TTL_SECS,
        )?;
        let approval_timeout_secs = number(
            &lookup,
            "APASSY_RELAY_APPROVAL_TIMEOUT",
            DEFAULT_APPROVAL_TIMEOUT_SECS,
            30,
            86_400,
        )?;
        let mut upstream = UpstreamOptions::default();
        if let Some(text) = lookup("APASSY_RELAY_BLOCKED_ADDRESSES") {
            for part in text.split(',').filter(|part| !part.trim().is_empty()) {
                upstream.blocked.push(IpNet::parse(part).ok_or_else(|| {
                    RelayError::invalid(
                        "APASSY_RELAY_BLOCKED_ADDRESSES is a comma-separated list of addresses or networks, such as 203.0.113.7,2001:db8::/64.",
                    )
                })?);
            }
        }
        Ok(Self {
            data_dir,
            listen,
            public_url,
            edge_secret,
            master_key,
            session_ttl_secs,
            approval_timeout_secs,
            upstream,
            limits: Limits::default(),
            backup_dir: PathBuf::from(
                lookup("APASSY_RELAY_BACKUP_DIR").unwrap_or_else(|| "/backups".to_string()),
            ),
        })
    }
}

/// An `http://` or `https://` origin without a path, query, or trailing slash.
pub fn checked_public_url(text: &str) -> RelayResult<String> {
    let trimmed = text.trim().trim_end_matches('/');
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .ok_or_else(|| {
            RelayError::invalid("The public URL starts with https:// (or http:// in tests).")
        })?;
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', ' ']) {
        return Err(RelayError::invalid(
            "The public URL is an origin such as https://relay.example.com.",
        ));
    }
    Ok(trimmed.to_string())
}

/// The key of the vault from before teams, for `apassy-relay migrate`:
/// `APASSY_RELAY_OLD_KEY` or `APASSY_RELAY_OLD_KEY_FILE`.
pub fn old_key_from_env() -> RelayResult<SecretString> {
    secret_from(
        &|name: &str| std::env::var(name).ok(),
        "APASSY_RELAY_OLD_KEY",
    )
}

fn secret_from(lookup: &impl Fn(&str) -> Option<String>, name: &str) -> RelayResult<SecretString> {
    if let Some(path) = lookup(&format!("{name}_FILE")) {
        let text = std::fs::read_to_string(&path)
            .map_err(|_| RelayError::invalid(format!("{name}_FILE cannot be read.")))?;
        let text = zeroize::Zeroizing::new(text);
        return Ok(SecretString::new(
            text.trim_end_matches(['\n', '\r']).to_string(),
        ));
    }
    lookup(name)
        .map(SecretString::new)
        .ok_or_else(|| RelayError::invalid(format!("{name} or {name}_FILE is required.")))
}

fn number(
    lookup: &impl Fn(&str) -> Option<String>,
    name: &str,
    default: u64,
    min: u64,
    max: u64,
) -> RelayResult<u64> {
    let Some(text) = lookup(name) else {
        return Ok(default);
    };
    match text.trim().parse::<u64>() {
        Ok(n) if (min..=max).contains(&n) => Ok(n),
        _ => Err(RelayError::invalid(format!(
            "{name} is a number from {min} to {max}."
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name| map.get(name).cloned()
    }

    const EDGE: &str = "edge-secret-for-tests-0123456789abcdef";

    #[test]
    fn reads_required_and_defaults() {
        let config = RelayConfig::from_lookup(lookup(&[
            ("APASSY_RELAY_PUBLIC_URL", "https://relay.example.test/"),
            ("APASSY_RELAY_EDGE_SECRET", EDGE),
            ("APASSY_RELAY_KEY", "a synthetic vault passphrase"),
        ]))
        .unwrap();
        assert_eq!(config.public_url, "https://relay.example.test");
        assert_eq!(config.listen.to_string(), "0.0.0.0:8080");
        assert_eq!(config.directory_path(), PathBuf::from("/data/relay.db"));
        assert_eq!(config.legacy_vault_path(), PathBuf::from("/data/team.db"));
        let team = crate::ids::TeamId::parse("t_abcdefgh23").unwrap();
        assert_eq!(
            config.team_path(&team),
            PathBuf::from("/data/teams/t_abcdefgh23.db")
        );
        assert_eq!(config.session_ttl_secs, DEFAULT_SESSION_TTL_SECS);
        assert_eq!(config.edge_secret.expose(), EDGE);
    }

    #[test]
    fn refuses_short_secrets_and_bad_values() {
        let short = RelayConfig::from_lookup(lookup(&[
            ("APASSY_RELAY_PUBLIC_URL", "https://relay.example.test"),
            ("APASSY_RELAY_EDGE_SECRET", "short"),
            ("APASSY_RELAY_KEY", "a synthetic vault passphrase"),
        ]));
        assert!(short.is_err());
        let ttl = RelayConfig::from_lookup(lookup(&[
            ("APASSY_RELAY_PUBLIC_URL", "https://relay.example.test"),
            ("APASSY_RELAY_EDGE_SECRET", EDGE),
            ("APASSY_RELAY_KEY", "a synthetic vault passphrase"),
            ("APASSY_RELAY_SESSION_TTL", "99999"),
        ]));
        assert!(ttl.is_err());
        assert!(checked_public_url("https://relay.example.test/path").is_err());
        assert!(checked_public_url("ftp://relay.example.test").is_err());
    }

    #[test]
    fn blocked_networks_parse_and_match() {
        let config = RelayConfig::from_lookup(lookup(&[
            ("APASSY_RELAY_PUBLIC_URL", "https://relay.example.test"),
            ("APASSY_RELAY_EDGE_SECRET", EDGE),
            ("APASSY_RELAY_KEY", "a synthetic vault passphrase"),
            (
                "APASSY_RELAY_BLOCKED_ADDRESSES",
                "9.9.9.117, 2620:fe:0:7491::/64",
            ),
        ]))
        .unwrap();
        let blocked = &config.upstream.blocked;
        assert_eq!(blocked.len(), 2);
        let hit = |ip: &str| blocked.iter().any(|net| net.contains(ip.parse().unwrap()));
        assert!(hit("9.9.9.117"));
        assert!(hit("::ffff:9.9.9.117"));
        assert!(!hit("9.9.9.118"));
        assert!(hit("2620:fe:0:7491::1"));
        assert!(hit("2620:fe:0:7491:ffff::9"));
        assert!(!hit("2620:fe:0:7492::1"));
        assert!(
            IpNet::parse("10.0.0.0/8")
                .unwrap()
                .contains("10.9.8.7".parse().unwrap())
        );
        assert!(
            IpNet::parse("0.0.0.0/0")
                .unwrap()
                .contains("8.8.8.8".parse().unwrap())
        );
        for bad in ["x", "1.2.3.4/33", "::/129", "1.2.3.4/"] {
            assert!(IpNet::parse(bad).is_none(), "{bad}");
        }
        assert!(
            RelayConfig::from_lookup(lookup(&[
                ("APASSY_RELAY_PUBLIC_URL", "https://relay.example.test"),
                ("APASSY_RELAY_EDGE_SECRET", EDGE),
                ("APASSY_RELAY_KEY", "a synthetic vault passphrase"),
                ("APASSY_RELAY_BLOCKED_ADDRESSES", "not-an-ip"),
            ]))
            .is_err()
        );
    }

    #[test]
    fn file_variable_wins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, "passphrase from a file\n").unwrap();
        let config = RelayConfig::from_lookup(lookup(&[
            ("APASSY_RELAY_PUBLIC_URL", "https://relay.example.test"),
            ("APASSY_RELAY_EDGE_SECRET", EDGE),
            ("APASSY_RELAY_KEY", "the plain variable passphrase"),
            ("APASSY_RELAY_KEY_FILE", path.to_str().unwrap()),
        ]))
        .unwrap();
        assert_eq!(config.master_key.expose(), "passphrase from a file");
    }
}
