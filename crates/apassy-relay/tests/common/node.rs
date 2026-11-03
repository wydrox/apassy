//! A node on the tailnet in process for tests (docs/SPEC.md section 32): an embedded
//! relay with a tailnet listener on a free loopback port, the node origin
//! `NODE_ORIGIN`, and optionally the team routes and a push gateway. Nothing listens on a
//! tailnet address: the tests call the tailnet listener on the loopback, as the TLS front
//! would, and sign with the node origin. Synthetic values only.
//!
//! A file that includes this module includes `common/relay.rs` as `relay` too.
#![allow(dead_code)]

use std::net::SocketAddr;

use apassy::node::backend::{NodeTeamId, RunningNode};
use apassy_relay::config::{EmbeddedOptions, RelayConfig};
use apassy_relay::device::{self, DeviceKey};
use apassy_relay::embedded::EmbeddedNode;
use apassy_relay::hostkeys;
use apassy_relay::ids::TeamId;
use apassy_relay::secret::SecretString;
use serde_json::{Value, json};

pub const MASTER_KEY: &str = "a synthetic node master key for the tailnet tests";
/// The Funnel origin of the node. Nothing listens there.
pub const PUBLIC_URL: &str = "https://node.example.ts.net:8443";
/// The node origin of node-pairing-v1 section 12.
pub const NODE_ORIGIN: &str = "https://100.64.0.7:8444";

pub fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

/// What a node is started with.
#[derive(Clone, Default)]
pub struct NodeOptions {
    /// The tailnet listener serves the team routes (the Linux node).
    pub agents: bool,
    /// The push gateway, such as `http://127.0.0.1:<port>` of a fake gateway.
    pub gateway: Option<String>,
    /// No tailnet route at all: a Mac node of before this plan.
    pub no_tailnet: bool,
}

pub fn node_config(dir: &std::path::Path, options: &NodeOptions) -> RelayConfig {
    let tailnet = !options.no_tailnet;
    RelayConfig::embedded(EmbeddedOptions {
        data_dir: dir.join("node"),
        master_key: SecretString::new(MASTER_KEY.to_string()),
        public_url: PUBLIC_URL.to_string(),
        public_listen: Some(loopback()),
        node_origin: tailnet.then(|| NODE_ORIGIN.to_string()),
        tailnet_listen: tailnet.then(loopback),
        tailnet_agents: options.agents,
        push_gateway: options.gateway.clone(),
    })
    .expect("node config")
}

/// A started node.
pub struct Node {
    pub node: Option<EmbeddedNode>,
    pub config: RelayConfig,
    pub dir: tempfile::TempDir,
}

/// A signed-in device: its access token, its id, its team, and its key.
pub struct Device {
    pub token: String,
    pub id: u64,
    pub team: TeamId,
    pub key: DeviceKey,
}

pub fn team_id(team: &NodeTeamId) -> TeamId {
    TeamId::parse(&team.0).expect("team id")
}

impl Node {
    pub fn start(options: NodeOptions) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = node_config(dir.path(), &options);
        let node = EmbeddedNode::start(config.clone()).expect("start");
        Self {
            node: Some(node),
            config,
            dir,
        }
    }

    pub fn node(&self) -> &EmbeddedNode {
        self.node.as_ref().expect("running")
    }

    /// `http://<tailnet listener>`: where the TLS front forwards to.
    pub fn tailnet(&self) -> String {
        self.node()
            .running()
            .tailnet_listener_url()
            .expect("a tailnet listener")
    }

    /// `http://<node listener>`: the app's own loopback listener (every route).
    pub fn local(&self) -> String {
        self.node().running().url()
    }

    /// `http://<public listener>`: what Funnel reaches.
    pub fn public(&self) -> String {
        self.node()
            .running()
            .public_listener_url()
            .expect("a public listener")
    }

    /// One request without the edge header. Returns the status and the JSON body.
    pub fn call(
        &self,
        base: &str,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (u16, Value) {
        crate::relay::call_url(base, None, method, path, token, body)
    }

    /// The result of a call that must answer 200.
    pub fn ok(
        &self,
        base: &str,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Value {
        let (status, value) = self.call(base, method, path, token, body);
        assert_eq!(status, 200, "{method} {path}: {value}");
        value["result"].clone()
    }

    /// Signs `key` in to `team` through `base`, with a signature over `origin`. Returns
    /// the access token, or the status and body of the refused token step.
    pub fn sign_in_with(
        &self,
        base: &str,
        team: &TeamId,
        key: &DeviceKey,
        origin: &str,
    ) -> Result<String, (u16, Value)> {
        let public_key = key.public_key_b64();
        let challenge = self.ok(
            base,
            "POST",
            "/v1/auth/challenge",
            None,
            Some(&json!({"team_id": team, "public_key": public_key})),
        );
        let nonce = challenge["nonce"].as_str().expect("nonce").to_string();
        let signature = key
            .sign(&device::sign_in_message(origin, team, &public_key, &nonce))
            .expect("sign");
        let (status, value) = self.call(
            base,
            "POST",
            "/v1/auth/token",
            None,
            Some(
                &json!({"team_id": team, "public_key": public_key, "nonce": nonce,
                "signature": hostkeys::encode_b64(&signature)}),
            ),
        );
        if status == 200 {
            Ok(value["result"]["token"]
                .as_str()
                .expect("token")
                .to_string())
        } else {
            Err((status, value))
        }
    }

    /// Signs in through the tailnet listener with the node origin.
    pub fn sign_in(&self, team: &TeamId, key: &DeviceKey) -> String {
        self.sign_in_with(&self.tailnet(), team, key, NODE_ORIGIN)
            .expect("sign-in with the node origin")
    }

    fn device(&self, team: TeamId, key: DeviceKey) -> Device {
        let token = self.sign_in(&team, &key);
        let me = self.ok(&self.tailnet(), "GET", "/v1/me", Some(&token), None);
        Device {
            id: me["device_id"].as_u64().expect("device id"),
            token,
            team,
            key,
        }
    }

    /// A team of devices made in process, with the Mac as its first device, signed in
    /// through the tailnet listener.
    pub fn device_team(&self, name: &str) -> (NodeTeamId, Device) {
        let key = DeviceKey::generate().expect("key");
        let (team, id) = self
            .node()
            .create_device_team(name, "Mac mini", &key.public_key_b64())
            .expect("device team");
        let mac = self.device(team_id(&team), key);
        assert_eq!(mac.id, id);
        (team, mac)
    }

    /// Another device of the same member through a confirmed device link, all through
    /// the tailnet listener.
    pub fn add_device(&self, first: &Device, name: &str) -> Device {
        let base = self.tailnet();
        let key = DeviceKey::generate().expect("key");
        let made = self.ok(&base, "POST", "/v1/devices/links", Some(&first.token), None);
        let code = made["secret"].as_str().expect("link code").to_string();
        let pending = self.ok(
            &base,
            "POST",
            "/v1/devices/link",
            None,
            Some(&json!({"code": code, "device_name": name, "public_key": key.public_key_b64()})),
        );
        let words = device::safety_words(&first.team, &code, &key.public_key());
        self.ok(
            &base,
            "POST",
            &format!("/v1/devices/links/{}/confirm", pending["id"]),
            Some(&first.token),
            Some(&json!({"safety": words})),
        );
        self.device(first.team.clone(), key)
    }

    /// Opens the file of a team with its key, read from the directory.
    pub fn team_file(&self, team: &TeamId) -> rusqlite::Connection {
        crate::relay::open_team_file(&self.config, team)
    }

    /// The relay audit of the directory: action and detail.
    pub fn relay_audit(&self) -> Vec<(String, String)> {
        let conn = rusqlite::Connection::open(self.config.directory_path()).expect("open");
        conn.execute_batch(&format!("PRAGMA key = '{MASTER_KEY}';"))
            .expect("key");
        let mut statement = conn
            .prepare("SELECT action, detail FROM audit ORDER BY id")
            .expect("prepare");
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("rows")
            .collect::<Result<_, _>>()
            .expect("collect")
    }

    pub fn stop(&mut self) {
        if let Some(node) = self.node.take() {
            Box::new(node).stop();
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The audit rows of a team file: action and detail.
pub fn team_audit(conn: &rusqlite::Connection) -> Vec<(String, Value)> {
    let mut statement = conn
        .prepare("SELECT action, detail FROM audit ORDER BY id")
        .expect("prepare");
    statement
        .query_map([], |row| {
            let action: String = row.get(0)?;
            let detail: String = row.get(1)?;
            Ok((action, serde_json::from_str(&detail).unwrap_or(Value::Null)))
        })
        .expect("rows")
        .collect::<Result<_, _>>()
        .expect("collect")
}

/// The error code of an error envelope.
pub fn code(value: &Value) -> &str {
    value["error"]["code"].as_str().unwrap_or_default()
}
