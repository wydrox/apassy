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
//! | `APASSY_RELAY_PUSH_URL` | The Worker's push route, such as `https://apassy-relay.wyderka.cc/internal/push` | none: push is off |
//! | `APASSY_RELAY_PUSH_TOPIC` | The bundle id of the iPhone app, such as `com.wydrox.apassy.companion` | none: push is off |
//! | `APASSY_RELAY_PUSH_SECRET` or `APASSY_RELAY_PUSH_SECRET_FILE` | The secret the relay sends to the push route as `X-Apassy-Push` (the Worker's `PUSH_SECRET`); at least 32 bytes | none: push is off |
//! | `APASSY_RELAY_QUESTIONS_TO_APPROVERS` | `1`: take questions with `to: "approvers"`; `0`: refuse them with 403 `not_routed` (until shared vaults) | `0` |
//! | `APASSY_RELAY_CONNECT_TEAMS_PER_DAY` | Connect teams (`POST /v1/connect`) the whole relay makes in 24 hours, 0 to 100000; over it 503 `busy`; `0` turns Connect off | `50` |
//! | `APASSY_RELAY_CONNECT_TEAMS_MAX` | Connect teams the relay holds at once (active or suspended), 0 to 1000000; at it `POST /v1/connect` is 503 `busy`; `0` turns Connect off | `100` |
//! | `APASSY_RELAY_CONNECT_LONG_POLLS` | Long polls that all Connect teams hold at once, 0 to 1024; a poll over it answers at once; `0`: every Connect poll answers at once | `96` |
//!
//! Push needs all three push values; none of them turns it off. Some but not all is a
//! configuration error, so a typo does not turn push off without a word.
//!
//! A `_FILE` variable names a file whose content (trailing newline removed) is the
//! value. It wins over the plain variable.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use crate::error::{RelayError, RelayResult};
use crate::secret::SecretString;

pub const MIN_EDGE_SECRET_BYTES: usize = 32;
pub const MIN_PUSH_SECRET_BYTES: usize = 32;
pub const MIN_KEY_BYTES: usize = 16;
pub const DEFAULT_SESSION_TTL_SECS: u64 = 900;
pub const MAX_SESSION_TTL_SECS: u64 = 3600;
pub const DEFAULT_APPROVAL_TIMEOUT_SECS: u64 = 600;
/// Connect teams of the whole relay in 24 hours (docs/SPEC.md section 26).
pub const DEFAULT_CONNECT_TEAMS_PER_DAY: u64 = 50;
pub const MAX_CONNECT_TEAMS_PER_DAY: u64 = 100_000;
/// Connect teams the relay holds at once, active or suspended (docs/SPEC.md section 26).
/// Each costs one open file and its connection (with a page cache of
/// `server::connect::CACHE_KIB`), and up to `TeamLimits::file_bytes` of disk, so this bounds
/// them. The default fits the production container (2 cores, 512 MiB, docs/OPERATIONS.md
/// section 20.5).
pub const DEFAULT_CONNECT_TEAMS_MAX: u64 = 100;
pub const MAX_CONNECT_TEAMS_MAX: u64 = 1_000_000;
/// The long polls that all Connect teams hold at once (`Limits::connect_long_polls`): the
/// 128 threads of the question lane less the 32 of one team's share, so Connect teams
/// always leave an operator team its share of the lane, and well under the member lane.
pub const DEFAULT_CONNECT_LONG_POLLS: usize = 96;
pub const MAX_CONNECT_LONG_POLLS: usize = 1024;
/// The feed long polls of all teams at once (`Limits::feed_long_polls`, docs/SPEC.md
/// section 27.7): threads of their own, apart from the question lane, so feed polls never
/// take the place of a question or an answer poll.
pub const DEFAULT_FEED_LONG_POLLS: usize = 64;
/// The feed long polls of one operator team at once, out of `feed_long_polls`.
pub const DEFAULT_FEED_LONG_POLLS_PER_TEAM: usize = 16;
/// The feed long polls of all Connect teams at once (`Limits::connect_feed_long_polls`):
/// the feed lane less one operator team's share, as `DEFAULT_CONNECT_LONG_POLLS` is for
/// the question lane.
pub const DEFAULT_CONNECT_FEED_LONG_POLLS: usize = 48;
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

/// The limits of the HTTP layer. Only `connect_long_polls` is read from the environment
/// (`APASSY_RELAY_CONNECT_LONG_POLLS`). Tests set small ones.
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
    /// The most snapshot transfers (pushes and downloads) of all teams at once. One
    /// more gets 503 `busy`. Each team also has its own `sync_transfers` limit.
    pub sync_transfers_total: usize,
    /// The question long polls of all teams at once (`GET /v1/questions` and
    /// `GET /v1/questions/{qid}/answers` with a `wait`). They have their own threads,
    /// apart from `max_active`, so they never take the member reserve. A poll over this
    /// runs in the member lane and is answered at once, as with `wait=0`.
    pub question_long_polls: usize,
    /// The question long polls of one team at once, out of `question_long_polls`, so
    /// one team cannot fill the lane. A poll over this is answered at once.
    pub question_long_polls_per_team: usize,
    /// The long polls that Connect teams hold at once, all of them together, in any lane
    /// (docs/SPEC.md section 26), so anonymous teams cannot fill the member lane or the
    /// question lane. A poll over this is answered at once, as with `wait=0`.
    /// Feed polls do not count in it: they have `connect_feed_long_polls`.
    pub connect_long_polls: usize,
    /// The feed long polls of all teams at once (`GET /v1/feed`, `GET /v1/feed/actions`,
    /// and `GET /v1/feed/actions/{id}` with a `wait`). Threads of their own, apart from
    /// `max_active` and from `question_long_polls`. A poll over this runs in the member
    /// lane and is answered at once.
    pub feed_long_polls: usize,
    /// The feed long polls of one operator team at once, out of `feed_long_polls`. A
    /// quarter of it (at least one seat) is kept for the action polls of the Macs.
    pub feed_long_polls_per_team: usize,
    /// The feed long polls that Connect teams hold at once, all of them together, out of
    /// `feed_long_polls`. A poll over this is answered at once.
    pub connect_feed_long_polls: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_active: 256,
            member_reserve: 32,
            long_polls_per_agent: 4,
            host_long_polls: 2,
            sync_transfers_total: 16,
            question_long_polls: 128,
            question_long_polls_per_team: 32,
            connect_long_polls: DEFAULT_CONNECT_LONG_POLLS,
            feed_long_polls: DEFAULT_FEED_LONG_POLLS,
            feed_long_polls_per_team: DEFAULT_FEED_LONG_POLLS_PER_TEAM,
            connect_feed_long_polls: DEFAULT_CONNECT_FEED_LONG_POLLS,
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
    /// Absolute transport deadlines, including body draining on refusal.
    pub request_read_timeout: Duration,
    pub request_handle_timeout: Duration,
    /// Where `apassy-relay admin backup` writes (`APASSY_RELAY_BACKUP_DIR`).
    pub backup_dir: PathBuf,
    /// The push trigger (docs/SPEC.md section 25.6). `None`: push is off.
    pub push: Option<PushConfig>,
    /// Questions with `to: "approvers"` are taken (`APASSY_RELAY_QUESTIONS_TO_APPROVERS`).
    /// Off until shared vaults (integrator decision 1): such a post is 403 `not_routed`.
    pub questions_to_approvers: bool,
    /// Connect teams the relay makes in any 24 hours (`APASSY_RELAY_CONNECT_TEAMS_PER_DAY`).
    /// Over it, `POST /v1/connect` is 503 `busy`; `0` turns Connect off.
    pub connect_teams_per_day: u64,
    /// Connect teams the relay holds at once, active or suspended
    /// (`APASSY_RELAY_CONNECT_TEAMS_MAX`). At it, `POST /v1/connect` is 503 `busy`.
    pub connect_teams_max: u64,
}

/// Where and how the relay asks the Worker to send pushes.
#[derive(Debug, Clone)]
pub struct PushConfig {
    /// The Worker's push route: `https://`, or `http://` to a loopback address (tests).
    pub url: String,
    /// The bundle id of the iPhone app (the APNs topic). A push token names it.
    pub topic: String,
    /// Sent as `X-Apassy-Push`. Never logged.
    pub secret: SecretString,
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

    /// The vault snapshots of one team (docs/SPEC.md section 24).
    pub fn sync_dir(&self, team: &crate::ids::TeamId) -> PathBuf {
        self.teams_dir().join(format!("{team}.sync"))
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
        let connect_teams_per_day = number(
            &lookup,
            "APASSY_RELAY_CONNECT_TEAMS_PER_DAY",
            DEFAULT_CONNECT_TEAMS_PER_DAY,
            0,
            MAX_CONNECT_TEAMS_PER_DAY,
        )?;
        let connect_teams_max = number(
            &lookup,
            "APASSY_RELAY_CONNECT_TEAMS_MAX",
            DEFAULT_CONNECT_TEAMS_MAX,
            0,
            MAX_CONNECT_TEAMS_MAX,
        )?;
        let connect_long_polls = number(
            &lookup,
            "APASSY_RELAY_CONNECT_LONG_POLLS",
            DEFAULT_CONNECT_LONG_POLLS as u64,
            0,
            MAX_CONNECT_LONG_POLLS as u64,
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
            request_read_timeout: Duration::from_secs(30),
            request_handle_timeout: Duration::from_secs(90),
            limits: Limits {
                connect_long_polls: usize::try_from(connect_long_polls)
                    .unwrap_or(DEFAULT_CONNECT_LONG_POLLS),
                ..Limits::default()
            },
            backup_dir: PathBuf::from(
                lookup("APASSY_RELAY_BACKUP_DIR").unwrap_or_else(|| "/backups".to_string()),
            ),
            push: push_from(&lookup)?,
            questions_to_approvers: match lookup("APASSY_RELAY_QUESTIONS_TO_APPROVERS").as_deref() {
                None | Some("0") => false,
                Some("1") => true,
                Some(_) => {
                    return Err(RelayError::invalid(
                        "APASSY_RELAY_QUESTIONS_TO_APPROVERS is 0 or 1.",
                    ));
                }
            },
            connect_teams_per_day,
            connect_teams_max,
        })
    }
}

/// The push values: all three, or none (push off).
fn push_from(lookup: &impl Fn(&str) -> Option<String>) -> RelayResult<Option<PushConfig>> {
    let url = lookup("APASSY_RELAY_PUSH_URL");
    let topic = lookup("APASSY_RELAY_PUSH_TOPIC");
    let has_secret = lookup("APASSY_RELAY_PUSH_SECRET").is_some()
        || lookup("APASSY_RELAY_PUSH_SECRET_FILE").is_some();
    if url.is_none() && topic.is_none() && !has_secret {
        return Ok(None);
    }
    let (Some(url), Some(topic), true) = (url, topic, has_secret) else {
        return Err(RelayError::invalid(
            "Push needs APASSY_RELAY_PUSH_URL, APASSY_RELAY_PUSH_TOPIC, and APASSY_RELAY_PUSH_SECRET (or _FILE), or none of them.",
        ));
    };
    let url = checked_push_url(&url)?;
    let topic = topic.trim().to_string();
    if !is_bundle_id(&topic) {
        return Err(RelayError::invalid(
            "APASSY_RELAY_PUSH_TOPIC is a bundle id such as com.example.app.",
        ));
    }
    let secret = secret_from(lookup, "APASSY_RELAY_PUSH_SECRET")?;
    if secret.len() < MIN_PUSH_SECRET_BYTES {
        return Err(RelayError::invalid(format!(
            "The push secret must have at least {MIN_PUSH_SECRET_BYTES} bytes."
        )));
    }
    Ok(Some(PushConfig { url, topic, secret }))
}

/// An `https://` URL, or an `http://` URL to a loopback address (tests). The secret
/// goes with every call, so it never goes in clear over a network.
fn checked_push_url(text: &str) -> RelayResult<String> {
    let text = text.trim();
    let invalid = || {
        RelayError::invalid(
            "APASSY_RELAY_PUSH_URL is an https:// URL such as https://apassy-relay.example.com/internal/push.",
        )
    };
    if text.contains(['?', '#', '@', ' ']) {
        return Err(invalid());
    }
    let rest = if let Some(rest) = text.strip_prefix("https://") {
        rest
    } else if let Some(rest) = text.strip_prefix("http://") {
        let host = rest.split(['/', ':']).next().unwrap_or_default();
        if !matches!(host, "127.0.0.1" | "localhost") {
            return Err(invalid());
        }
        rest
    } else {
        return Err(invalid());
    };
    if rest.split('/').next().is_none_or(str::is_empty) {
        return Err(invalid());
    }
    Ok(text.to_string())
}

/// A bundle id: letters, digits, `.` and `-`, 1 to 155 bytes, no empty part.
pub fn is_bundle_id(text: &str) -> bool {
    (1..=155).contains(&text.len())
        && text.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
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
        assert_eq!(config.connect_teams_per_day, DEFAULT_CONNECT_TEAMS_PER_DAY);
        assert_eq!(config.connect_teams_max, DEFAULT_CONNECT_TEAMS_MAX);
        assert_eq!(
            (config.connect_teams_per_day, config.connect_teams_max),
            (50, 100)
        );
        assert_eq!(config.limits.connect_long_polls, DEFAULT_CONNECT_LONG_POLLS);
        assert_eq!(config.limits, Limits::default());
    }

    #[test]
    fn connect_long_polls_is_0_to_1024() {
        let with = |value: &str| {
            RelayConfig::from_lookup(lookup(&[
                ("APASSY_RELAY_PUBLIC_URL", "https://relay.example.test"),
                ("APASSY_RELAY_EDGE_SECRET", EDGE),
                ("APASSY_RELAY_KEY", "a synthetic vault passphrase"),
                ("APASSY_RELAY_CONNECT_LONG_POLLS", value),
            ]))
            .map(|config| config.limits)
        };
        assert_eq!(with("0").unwrap().connect_long_polls, 0);
        let most = with("1024").unwrap();
        assert_eq!(most.connect_long_polls, 1024);
        // Only this field of the limits comes from the environment.
        assert_eq!(
            Limits {
                connect_long_polls: DEFAULT_CONNECT_LONG_POLLS,
                ..most
            },
            Limits::default()
        );
        assert!(with("1025").is_err());
        assert!(with("-1").is_err());
        assert!(with("some").is_err());
    }

    #[test]
    fn connect_teams_per_day_is_0_to_100000() {
        let with = |value: &str| {
            RelayConfig::from_lookup(lookup(&[
                ("APASSY_RELAY_PUBLIC_URL", "https://relay.example.test"),
                ("APASSY_RELAY_EDGE_SECRET", EDGE),
                ("APASSY_RELAY_KEY", "a synthetic vault passphrase"),
                ("APASSY_RELAY_CONNECT_TEAMS_PER_DAY", value),
            ]))
            .map(|config| config.connect_teams_per_day)
        };
        assert_eq!(with("0").unwrap(), 0);
        assert_eq!(with("100000").unwrap(), 100_000);
        assert!(with("100001").is_err());
        assert!(with("-1").is_err());
        assert!(with("many").is_err());
    }

    #[test]
    fn connect_teams_max_is_0_to_1000000() {
        let with = |value: &str| {
            RelayConfig::from_lookup(lookup(&[
                ("APASSY_RELAY_PUBLIC_URL", "https://relay.example.test"),
                ("APASSY_RELAY_EDGE_SECRET", EDGE),
                ("APASSY_RELAY_KEY", "a synthetic vault passphrase"),
                ("APASSY_RELAY_CONNECT_TEAMS_MAX", value),
            ]))
            .map(|config| config.connect_teams_max)
        };
        assert_eq!(with("0").unwrap(), 0);
        assert_eq!(with("1000000").unwrap(), 1_000_000);
        assert!(with("1000001").is_err());
        assert!(with("-1").is_err());
        assert!(with("lots").is_err());
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
    fn push_is_all_three_values_or_none() {
        let base = [
            ("APASSY_RELAY_PUBLIC_URL", "https://relay.example.test"),
            ("APASSY_RELAY_EDGE_SECRET", EDGE),
            ("APASSY_RELAY_KEY", "a synthetic vault passphrase"),
        ];
        let with = |extra: &[(&'static str, &'static str)]| {
            let mut pairs = base.to_vec();
            pairs.extend_from_slice(extra);
            RelayConfig::from_lookup(lookup(&pairs))
        };
        assert!(with(&[]).unwrap().push.is_none());
        assert!(!with(&[]).unwrap().questions_to_approvers);
        let approvers = |value: &'static str| {
            with(&[("APASSY_RELAY_QUESTIONS_TO_APPROVERS", value)])
                .map(|config| config.questions_to_approvers)
        };
        assert!(!approvers("0").unwrap());
        assert!(approvers("1").unwrap());
        assert!(approvers("yes").is_err());
        let url = (
            "APASSY_RELAY_PUSH_URL",
            "https://relay.example.test/internal/push",
        );
        let topic = ("APASSY_RELAY_PUSH_TOPIC", "com.wydrox.apassy.companion");
        let secret = (
            "APASSY_RELAY_PUSH_SECRET",
            "push-secret-for-tests-0123456789abcdef",
        );
        let push = with(&[url, topic, secret]).unwrap().push.unwrap();
        assert_eq!(push.url, "https://relay.example.test/internal/push");
        assert_eq!(push.topic, "com.wydrox.apassy.companion");
        assert_eq!(push.secret.expose(), secret.1);
        // Some but not all is an error, and so is a value out of its form.
        for partial in [vec![url], vec![topic, secret], vec![url, topic]] {
            assert!(with(&partial).is_err());
        }
        for bad_url in [
            "http://relay.example.test/internal/push",
            "ftp://relay.example.test/x",
            "https://",
            "https://relay.example.test/x?y=1",
        ] {
            assert!(
                with(&[("APASSY_RELAY_PUSH_URL", bad_url), topic, secret]).is_err(),
                "{bad_url}"
            );
        }
        assert!(
            with(&[
                ("APASSY_RELAY_PUSH_URL", "http://127.0.0.1:9/internal/push"),
                topic,
                secret
            ])
            .is_ok()
        );
        assert!(with(&[url, ("APASSY_RELAY_PUSH_TOPIC", "com..x"), secret]).is_err());
        assert!(with(&[url, ("APASSY_RELAY_PUSH_TOPIC", "com x"), secret]).is_err());
        assert!(with(&[url, topic, ("APASSY_RELAY_PUSH_SECRET", "short")]).is_err());
        assert!(is_bundle_id("com.wydrox.apassy.companion"));
        assert!(!is_bundle_id(""));
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
