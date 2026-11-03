//! The files and the settings of the node without a window, and its relay configuration.
//!
//! The node directory (`<data>/node`, mode 0700) holds:
//!
//! | File | What |
//! | --- | --- |
//! | `settings.json` | `NodeSettings`: the port, the route, the push gateway, the last origin |
//! | `master.key` | The master key, 0600, when systemd gives no credential (`keys`) |
//! | `front/cert.der`, `front/key.sealed` | The node certificate and its sealed key (`apassy::net::certificate`) |
//! | `relay/` | The relay's directory: `relay.db`, `teams/`, `admin.sock`, `relay.lock` |
//! | `state.json` | `ServeState` of the running `serve`, 0600; removed when it stops |
//! | `serve.sock` | The control socket of the running `serve` (`serve --stop`) |
//!
//! Nothing in `settings.json` and `state.json` is secret: the pin is public.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::NodeCliError;
use super::keys::KeySource;
use crate::config::{DEFAULT_NODE_PORT, DEFAULT_PUSH_GATEWAY, EmbeddedOptions, RelayConfig};
use crate::error::RelayResult;
use crate::secret::SecretString;

/// The node directory under the Apassy data directory.
pub const NODE_DIR: &str = "node";
/// The directory of the TLS front: the certificate and its sealed key.
pub const FRONT_DIR: &str = "front";
/// The relay's own data directory inside the node directory.
pub const RELAY_DIR: &str = "relay";
pub const SETTINGS_FILE: &str = "settings.json";
pub const STATE_FILE: &str = "state.json";
pub const CONTROL_SOCKET: &str = "serve.sock";
/// The longest settings or state file.
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// How the tailnet reaches the front (plan, risk 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Route {
    /// The front binds the tailnet addresses of this machine.
    #[default]
    Direct,
    /// The front binds `127.0.0.1` and Tailscale Serve in TCP mode forwards the tailnet
    /// port to it. Serve does not end TLS, so the pin holds end to end.
    ServeTcp,
}

impl Route {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "direct" => Some(Self::Direct),
            "serve-tcp" => Some(Self::ServeTcp),
            _ => None,
        }
    }

    pub fn text(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::ServeTcp => "serve-tcp",
        }
    }
}

fn default_port() -> u16 {
    DEFAULT_NODE_PORT
}

fn default_gateway() -> Option<String> {
    Some(DEFAULT_PUSH_GATEWAY.to_owned())
}

/// `settings.json` of the node. A missing file is the default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSettings {
    /// The port of the front on the tailnet: 8444. A change after the first pairing
    /// changes the origin: every device pairs again.
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub route: Route,
    /// The push gateway (push-gateway-v1); `null`: no push.
    #[serde(default = "default_gateway")]
    pub push_gateway: Option<String>,
    /// The node origin of the last start. `serve` writes it; `doctor` compares it with
    /// the origin of now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_origin: Option<String>,
}

impl Default for NodeSettings {
    fn default() -> Self {
        Self {
            port: default_port(),
            route: Route::Direct,
            push_gateway: default_gateway(),
            last_origin: None,
        }
    }
}

impl NodeSettings {
    /// Checks the values: a port that is not 0, 443, or a Funnel port, and a gateway
    /// origin (`crate::config::checked_gateway`).
    pub fn check(&self) -> Result<(), NodeCliError> {
        if matches!(self.port, 0 | 443 | 8443 | 10000) {
            return Err(NodeCliError::usage(
                "The node port cannot be 0, 443, 8443, or 10000 (Tailscale Serve and Funnel use them).",
            ));
        }
        if let Some(gateway) = &self.push_gateway {
            crate::config::checked_gateway(gateway)
                .map_err(|error| NodeCliError::usage(error.message))?;
        }
        Ok(())
    }

    /// Reads `settings.json` of `dir`; the default when it is missing.
    pub fn load(dir: &Path) -> Result<Self, NodeCliError> {
        let path = dir.join(SETTINGS_FILE);
        let Some(bytes) = read_small(&path)? else {
            return Ok(Self::default());
        };
        let settings: Self = serde_json::from_slice(&bytes).map_err(|error| {
            NodeCliError::usage(format!(
                "{} is not valid: {error}. Fix or remove it.",
                path.display()
            ))
        })?;
        settings.check()?;
        Ok(settings)
    }

    /// Writes `settings.json` of `dir` (0600, through a temporary file).
    pub fn save(&self, dir: &Path) -> Result<(), NodeCliError> {
        self.check()?;
        let text = serde_json::to_vec_pretty(self)
            .map_err(|_| NodeCliError::failed("The node settings cannot be written."))?;
        write_private(&dir.join(SETTINGS_FILE), &text)
    }
}

/// The files of one node (plan L1 interface).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeFiles {
    /// The node directory, mode 0700.
    pub data_dir: PathBuf,
    /// Where the master key comes from.
    pub key_source: KeySource,
    /// `front/`: the certificate and its sealed key.
    pub front_dir: PathBuf,
}

impl NodeFiles {
    /// The relay's directory: `relay/`.
    pub fn relay_dir(&self) -> PathBuf {
        self.data_dir.join(RELAY_DIR)
    }
}

/// The operator socket of the relay of the node in `dir`.
pub fn admin_socket(dir: &Path) -> PathBuf {
    dir.join(RELAY_DIR).join(crate::config::ADMIN_SOCKET)
}

/// What the relay of a node without a window needs besides its directory and key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadlessOptions {
    /// `https://<Tailscale IPv4>:<port>`: the origin that devices store and sign.
    pub node_origin: String,
    /// The loopback address of the tailnet listener (`127.0.0.1:0`): the front's target.
    pub tailnet_listen: SocketAddr,
    /// The push gateway, or `None` for no push.
    pub push_gateway: Option<String>,
    /// The port of the front: the port of the origin.
    pub port: u16,
}

/// The node origin of a host and a port: `https://<host>:<port>`.
pub fn node_origin(host: std::net::Ipv4Addr, port: u16) -> String {
    format!("https://{host}:{port}")
}

/// The relay configuration of `apassy serve` (plan D8): `RelayConfig::embedded` with the
/// node origin as the public URL and the only sign-in origin, no public listener, the
/// tailnet listener with the team routes (`Scope::Tailnet { agents: true }`), push through
/// the gateway, team vaults on, and no MCP authorization flow (agents of a Linux node use
/// the tokens of `apassy team`; the OAuth endpoints are never on the tailnet listener).
pub fn relay_config(
    relay_dir: PathBuf,
    master_key: SecretString,
    options: &HeadlessOptions,
) -> RelayResult<RelayConfig> {
    let mut config = RelayConfig::embedded(EmbeddedOptions {
        data_dir: relay_dir,
        master_key,
        public_url: options.node_origin.clone(),
        public_listen: None,
        node_origin: Some(options.node_origin.clone()),
        tailnet_listen: Some(options.tailnet_listen),
        tailnet_agents: true,
        push_gateway: options.push_gateway.clone(),
    })?;
    config.oauth = None;
    Ok(config)
}

/// Makes `dir` (and its parents) a real directory of this user with mode 0700. A link or
/// a file there is refused.
pub fn ensure_private_dir(dir: &Path) -> Result<(), NodeCliError> {
    let fail = |why: &str| NodeCliError::failed(format!("{}: {why}.", dir.display()));
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
            if meta.mode() & 0o077 != 0 {
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                    .map_err(|_| fail("the directory cannot be made private"))?;
            }
            Ok(())
        }
        Ok(_) => Err(fail("not a directory")),
        Err(error) if error.kind() == ErrorKind::NotFound => fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|_| fail("the directory cannot be made")),
        Err(_) => Err(fail("the directory cannot be read")),
    }
}

/// A plain file of at most 64 KiB, or `None` when it is missing.
pub fn read_small(path: &Path) -> Result<Option<Vec<u8>>, NodeCliError> {
    let fail = |why: &str| NodeCliError::failed(format!("{}: {why}.", path.display()));
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(fail("cannot be read")),
    };
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(fail("not a plain file"));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| fail("cannot be read"))?;
    if u64::try_from(bytes.len()).is_ok_and(|length| length > MAX_FILE_BYTES) {
        return Err(fail("is too long"));
    }
    Ok(Some(bytes))
}

/// Writes `bytes` to a new 0600 file next to `path` and renames it over `path`.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), NodeCliError> {
    let temporary = path.with_extension("tmp");
    let _ = fs::remove_file(&temporary);
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .and_then(|mut file| file.write_all(bytes).and_then(|()| file.sync_all()))
        .and_then(|()| fs::rename(&temporary, path));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(NodeCliError::failed(format!(
            "{} cannot be written.",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_default_and_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let settings = NodeSettings::load(dir.path()).unwrap();
        assert_eq!(settings, NodeSettings::default());
        assert_eq!(settings.port, 8444);
        assert_eq!(settings.push_gateway.as_deref(), Some(DEFAULT_PUSH_GATEWAY));
        let changed = NodeSettings {
            port: 9444,
            route: Route::ServeTcp,
            push_gateway: None,
            last_origin: Some("https://100.64.0.7:9444".to_owned()),
        };
        changed.save(dir.path()).unwrap();
        let mode = fs::metadata(dir.path().join(SETTINGS_FILE)).unwrap().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(NodeSettings::load(dir.path()).unwrap(), changed);
        let text = fs::read_to_string(dir.path().join(SETTINGS_FILE)).unwrap();
        assert!(text.contains("\"serve-tcp\""), "{text}");
        assert!(text.contains("\"push_gateway\": null"), "{text}");
    }

    #[test]
    fn settings_refuse_bad_values_and_unknown_keys() {
        let dir = tempfile::tempdir().unwrap();
        for text in [
            r#"{"port": 443}"#,
            r#"{"port": 8443}"#,
            r#"{"push_gateway": "http://push.example.com"}"#,
            r#"{"colour": "blue"}"#,
            r#"{"route": "lan"}"#,
        ] {
            fs::write(dir.path().join(SETTINGS_FILE), text).unwrap();
            assert!(NodeSettings::load(dir.path()).is_err(), "{text}");
        }
    }

    #[test]
    fn the_headless_relay_is_a_tailnet_node_without_a_public_listener() {
        let dir = tempfile::tempdir().unwrap();
        let options = HeadlessOptions {
            node_origin: "https://100.64.0.7:8444".to_owned(),
            tailnet_listen: "127.0.0.1:0".parse().unwrap(),
            push_gateway: Some(DEFAULT_PUSH_GATEWAY.to_owned()),
            port: 8444,
        };
        let config = relay_config(
            dir.path().join(RELAY_DIR),
            SecretString::new("0123456789abcdef0123456789abcdef".to_owned()),
            &options,
        )
        .unwrap();
        assert!(config.is_node());
        assert!(config.tailnet_agents);
        assert!(config.public_listen.is_none());
        assert!(config.oauth.is_none());
        assert!(config.team_vaults);
        assert!(config.listen.ip().is_loopback());
        assert_eq!(config.sign_in_origins(), vec!["https://100.64.0.7:8444"]);
        assert!(matches!(
            config.push,
            Some(crate::config::PushConfig::Gateway { .. })
        ));
        let no_push = relay_config(
            dir.path().join(RELAY_DIR),
            SecretString::new("0123456789abcdef0123456789abcdef".to_owned()),
            &HeadlessOptions {
                push_gateway: None,
                ..options
            },
        )
        .unwrap();
        assert!(no_push.push.is_none());
    }

    #[test]
    fn private_dirs_are_0700() {
        let dir = tempfile::tempdir().unwrap();
        let node = dir.path().join("a/b/node");
        ensure_private_dir(&node).unwrap();
        assert_eq!(fs::metadata(&node).unwrap().mode() & 0o777, 0o700);
        fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&node).unwrap();
        assert_eq!(fs::metadata(&node).unwrap().mode() & 0o777, 0o700);
        let file = dir.path().join("file");
        fs::write(&file, b"x").unwrap();
        assert!(ensure_private_dir(&file).is_err());
    }
}
