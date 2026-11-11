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
//! | `APASSY_RELAY_TEAM_VAULTS` | `1`: shared team vaults, runs, MCP, and the proxy (way B); `0`: refuse them with 410 `team_vaults_retired`, keep devices, relay sync, questions, feed, and push (ADR 0037, D8). The hosted image sets `0` | `1` |
//! | `APASSY_RELAY_QUESTIONS_TO_APPROVERS` | `1`: take questions with `to: "approvers"`; `0`: refuse them with 403 `not_routed` (until shared vaults) | `0` |
//! | `APASSY_RELAY_CONNECT_TEAMS_PER_DAY` | Connect teams (`POST /v1/connect`) the whole relay makes in 24 hours, 0 to 100000; over it 503 `busy`; `0` turns Connect off | `50` |
//! | `APASSY_RELAY_CONNECT_TEAMS_MAX` | Connect teams the relay holds at once (active or suspended), 0 to 1000000; at it `POST /v1/connect` is 503 `busy`; `0` turns Connect off | `100` |
//! | `APASSY_RELAY_CONNECT_SYNC_BYTES` | The largest vault snapshot of a new Connect team (its `sync_bytes`): `0` (no relay sync; a push is 403 `plan_required`) or 1048576 to 67108864. Existing teams keep theirs (`admin limits --sync-bytes`). The hosted relay sets 67108864 until Apassy Connect starts | `0` |
//! | `APASSY_RELAY_FREE_CONNECT` | `1`: the free Connect paths of ADR 0032 (`POST /v1/connect`, questions, feed, and push of free Connect teams); `0` (the transition before the cutover, ADR 0037 D14): `POST /v1/connect` and its challenge answer 410 `free_connect_ended`, and so do the questions, feed, and push routes of every free Connect team; with `APASSY_RELAY_CONNECT_SYNC_BYTES` 0 too, their pushes and receipts are 403 `plan_required` whatever their own `sync_bytes`. Operator teams and vault stores never change. Forced to `0` in `connect` mode | `1` |
//! | `APASSY_RELAY_CONNECT_LONG_POLLS` | Long polls that all Connect teams hold at once, 0 to 1024; a poll over it answers at once; `0`: every Connect poll answers at once | `96` |
//! | `APASSY_RELAY_CONNECT_ACCOUNTS` | `1`: the routes of Apassy Connect accounts (connect-account-v1) on this relay, beside every other route (the transition); `0`: every account route is 404 `not_found` | `0` |
//! | `APASSY_RELAY_MODE` | `relay` (every route of the relay), or `connect`: Apassy Connect only (ADR 0037 stage 7). In `connect` mode the master key is refused (`APASSY_RELAY_KEY` and `_FILE` must not be set), `relay.db` and the vault stores are plain SQLite files (`Store::open_plain`), shared team vaults are off, the account routes are on, the push settings are refused, no proxy is built, and every other route of the relay answers 410 `hosted_retired` (docs/SPEC.md section 37) | `relay` |
//! | `APASSY_CONNECT_SIGNING_KEY_FILE` | The Ed25519 signing key of the entitlement token: a PKCS#8 file (DER or PEM). Without it `GET /v1/account/entitlement` is 503 `busy` for an entitled account and the well-known document lists no key. A key that this relay did not have before signs one hour after its first start (it is published first), unless it is the relay's first key | none |
//! | `APASSY_CONNECT_PUBLISHED_KEYS_FILE` | More Ed25519 public keys for the well-known document, a JSON file `{"keys":[{"kid","public_key"}]}` (`kid` is `entitlement::key_id` of the key): the next signing key before a rotation, the previous one for a day after it. The signing key and these are the only published keys | none |
//! | `APASSY_RELAY_CONNECT_ACCOUNTS_PER_DAY` | New Connect accounts (`POST /v1/account`) of the whole relay in 24 hours, 0 to 100000; over it 503 `busy`; `0`: no new account | `1000` |
//! | `APASSY_RELAY_CONNECT_ACCOUNTS_MAX` | Connect accounts the relay holds, 0 to 10000000; at it `POST /v1/account` is 503 `busy` | `100000` |
//! | `APASSY_CONNECT_SITE_URL` | The `https://` origin of the site: the Stripe return pages and the group invites | `https://apassy.wyderka.cc` |
//! | `STRIPE_SECRET_KEY_FILE` | With the account routes on: a file with the restricted Stripe key (`rk_live_…`; `rk_test_…` or `sk_test_…` in a sandbox; `sk_live_…` is refused). Set it and the next one together, or neither: without them the billing routes answer 503 `busy` and no account has a plan | none |
//! | `STRIPE_WEBHOOK_SECRET_FILE` | A file with the signing secret of the Stripe webhook endpoint (`whsec_…`) | none |
//! | `APASSY_CONNECT_FAMILY_EXTRA_CENTS`, `APASSY_CONNECT_FAMILY_EXTRA_YEAR_CENTS` | Tier 2 of the Family prices that a checkout expects (cents, VAT included); a Family checkout is 503 `busy` while Stripe's price differs | `100`, `1000` |
//! | `APASSY_CONNECT_GRACE_DAYS` | Entitled days after the first failed payment, 1 to 60 | `14` |
//! | `APASSY_CONNECT_READ_ONLY_DAYS` | Read-only days after the end of a plan, 1 to 365 | `30` |
//! | `APASSY_CONNECT_DELETE_DAYS` | Days from the end of a plan to the deletion of its vault stores, above the read-only days, at most 730 | `90` |
//! | `APASSY_CONNECT_INGRESS_LISTEN` | With the account routes: the address of the SNI ingress of the tunnel (connect-tunnel-v1 section 7.1; hosted `0.0.0.0:443`) | none: no ingress |
//! | `APASSY_CONNECT_ACME_LISTEN` | With the account routes: the address of the ACME HTTP-01 listener of the tunnel (section 7.2; hosted `0.0.0.0:80`) | none: no ACME listener |
//! | `APASSY_CONNECT_NODE_ZONE` | The DNS zone of the nodes' public names (`<10 characters>.<zone>`) | `node.apassy.wyderka.cc` |
//! | `APASSY_CONNECT_TUNNEL_STREAMS` | Open tunnel streams of one account, 1 to 4096 | `64` |
//! | `APASSY_CONNECT_TUNNEL_NODES` | Nodes of one account, 1 to 64 | `8` |
//! | `APASSY_CONNECT_TUNNEL_DIALS_PER_MINUTE` | Dials of one account in one minute, 1 to 6000 | `60` |
//! | `APASSY_CONNECT_TUNNEL_GIB_PER_MONTH` | Tunnel GiB of one account in one UTC month for each person (Family) or member (Team), 1 to 10240 | `20` |
//! | `APASSY_CONNECT_TUNNEL_PING_SECS` | Connect pings each node WebSocket this often, 5 to 300 seconds | `30` |
//! | `APASSY_CONNECT_TUNNEL_IDLE_SECS` | A tunnel WebSocket with no message for this long closes, 10 to 3600 seconds and above the ping interval | `90` |
//! | `APASSY_CONNECT_TUNNEL_STREAM_IDLE_SECS` | A stream with no byte for this long is reset, 60 to 86400 seconds | `900` |
//! | `APASSY_CONNECT_TUNNEL_STREAM_BUFFER_KIB` | KiB buffered toward one client of a stream; over it the stream is reset, 64 to 16384 | `256` |
//!
//! Push needs all three push values; none of them turns it off. Some but not all is a
//! configuration error, so a typo does not turn push off without a word.
//!
//! The environment always asks for the edge secret (`EdgeMode::Required`). A Mac's own
//! node (`RelayConfig::embedded`, docs/SPEC.md section 30) has no edge: `EdgeMode::Off`,
//! which `RelayConfig::check_listeners` permits only when every listener is on the
//! loopback. A node on the tailnet (docs/SPEC.md section 32) has a third loopback
//! listener that its TLS front forwards to (`Scope::Tailnet`), a set of sign-in origins,
//! and push through the push gateway (`PushConfig::Gateway`). The environment keeps the
//! hosted relay's one origin and the Worker push (`PushConfig::Worker`).
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
/// `sync_bytes` of a new Connect team (`APASSY_RELAY_CONNECT_SYNC_BYTES`, docs/SPEC.md
/// section 26.4): 0, no relay sync, so a snapshot push is 403 `plan_required`.
pub const DEFAULT_CONNECT_SYNC_BYTES: u64 = 0;
/// The smallest `APASSY_RELAY_CONNECT_SYNC_BYTES` above 0: 1 MiB, as `TeamLimits::validate`.
pub const MIN_CONNECT_SYNC_BYTES: u64 = 1_048_576;
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
/// The site of Apassy Connect (`APASSY_CONNECT_SITE_URL`): the Stripe return pages and the
/// group invites.
pub const DEFAULT_CONNECT_SITE_URL: &str = "https://apassy.wyderka.cc";
/// The zone of the nodes' public names (`APASSY_CONNECT_NODE_ZONE`, connect-tunnel-v1 section 2).
pub const DEFAULT_CONNECT_NODE_ZONE: &str = "node.apassy.wyderka.cc";
/// The largest signing key file of `APASSY_CONNECT_SIGNING_KEY_FILE`.
const MAX_SIGNING_KEY_FILE_BYTES: u64 = 4096;
/// The largest file of `APASSY_CONNECT_PUBLISHED_KEYS_FILE`, and its most keys.
const MAX_PUBLISHED_KEYS_FILE_BYTES: u64 = 16_384;
pub const MAX_PUBLISHED_KEYS: usize = 8;
/// New Connect accounts of the whole relay in 24 hours (`APASSY_RELAY_CONNECT_ACCOUNTS_PER_DAY`).
pub const DEFAULT_CONNECT_ACCOUNTS_PER_DAY: u64 = 1000;
pub const MAX_CONNECT_ACCOUNTS_PER_DAY: u64 = 100_000;
/// Connect accounts the relay holds at once (`APASSY_RELAY_CONNECT_ACCOUNTS_MAX`).
pub const DEFAULT_CONNECT_ACCOUNTS_MAX: u64 = 100_000;
pub const MAX_CONNECT_ACCOUNTS_MAX: u64 = 10_000_000;
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
/// The push gateway of the Apassy project (push-gateway-v1 section 2): the default gateway
/// of a node. A self-hoster names their own.
pub const DEFAULT_PUSH_GATEWAY: &str = "https://push.apassy.wyderka.cc";
/// The default port of a node origin (node-pairing-v1 section 3).
pub const DEFAULT_NODE_PORT: u16 = 8444;
/// The session lifetime of an embedded node (docs/SPEC.md section 30).
pub const EMBEDDED_SESSION_TTL_SECS: u64 = 600;
/// How long a run of an embedded node waits for the owner: the broker's question wait.
pub const EMBEDDED_APPROVAL_TIMEOUT_SECS: u64 = 300;
/// The machine that this relay runs on, as the pages of its embedded node name it: "Mac"
/// on macOS (the node of the Mac app), "computer" on Linux (the Linux node and
/// `apassy owner serve`). The relay cannot use the app's wording macros
/// (`src/wording.rs`), so it has its own; a string literal, for `concat!`.
#[cfg(not(target_os = "linux"))]
macro_rules! host_word {
    () => {
        "Mac"
    };
}
/// On Linux: "computer".
#[cfg(target_os = "linux")]
macro_rules! host_word {
    () => {
        "computer"
    };
}
pub(crate) use host_word;

/// [`host_word!`] as a value: "Mac" on macOS, "computer" on Linux.
pub const HOST_WORD: &str = host_word!();

/// The name of the computer on the connect page: "your Mac" on macOS, "your computer"
/// on Linux ([`HOST_WORD`]). The page is public (anyone with its address reads it), so
/// it never shows the computer name; only the owner's own prompts, on the computer and
/// the iPhone, name it.
pub const EMBEDDED_MAC_NAME: &str = concat!("your ", host_word!());
/// The requests that the public listener of an embedded node handles at once. It has
/// no member reserve: only agents use it (`Scope::Public`).
pub const PUBLIC_MAX_ACTIVE: usize = 32;
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

/// How the relay knows that a request came through its edge.
#[derive(Debug, Clone)]
pub enum EdgeMode {
    /// Every request but `GET /healthz` carries `X-Apassy-Edge` with this secret: the
    /// Worker in front of the hosted relay adds it. At least `MIN_EDGE_SECRET_BYTES`.
    Required(SecretString),
    /// No edge header is checked. Only for a relay whose every listener is on the
    /// loopback (`RelayConfig::check_listeners`): an embedded node, which `tailscaled` on
    /// the same Mac reaches from the loopback after it ends TLS.
    Off,
}

impl EdgeMode {
    /// The edge secret, or `None` without an edge.
    pub fn secret(&self) -> Option<&SecretString> {
        match self {
            Self::Required(secret) => Some(secret),
            Self::Off => None,
        }
    }
}

/// What the relay serves (`APASSY_RELAY_MODE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RelayMode {
    /// Every route of the relay (the default).
    #[default]
    Relay,
    /// Apassy Connect only (ADR 0037 stage 7): no master key, plain files, the account
    /// routes. The retired routes are the cutover unit's (C5).
    Connect,
}

/// The Ed25519 signing key of the entitlement token, as the PKCS#8 DER of its file. Debug
/// is redacted; the bytes are zeroized on drop.
#[derive(Clone)]
pub struct ConnectSigningKey(std::sync::Arc<zeroize::Zeroizing<Vec<u8>>>);

impl std::fmt::Debug for ConnectSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConnectSigningKey(<redacted>)")
    }
}

impl ConnectSigningKey {
    /// A key from the bytes of a PKCS#8 file: DER, or PEM (`-----BEGIN PRIVATE KEY-----`,
    /// as `openssl genpkey -algorithm ed25519` writes it). Refuses anything that `ring`
    /// does not take as an Ed25519 key.
    pub fn from_file_bytes(bytes: &[u8]) -> RelayResult<Self> {
        let invalid = || {
            RelayError::invalid(
                "APASSY_CONNECT_SIGNING_KEY_FILE is not an Ed25519 key in PKCS#8 (DER or PEM).",
            )
        };
        let der = if bytes.starts_with(b"-----BEGIN") {
            use base64::prelude::{BASE64_STANDARD, Engine as _};
            let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
            let body: String = text
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<Vec<_>>()
                .concat();
            let body = zeroize::Zeroizing::new(body);
            zeroize::Zeroizing::new(
                BASE64_STANDARD
                    .decode(body.trim().as_bytes())
                    .map_err(|_| invalid())?,
            )
        } else {
            zeroize::Zeroizing::new(bytes.to_vec())
        };
        ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der).map_err(|_| invalid())?;
        Ok(Self(std::sync::Arc::new(der)))
    }

    /// The PKCS#8 DER. Do not log it.
    pub fn pkcs8(&self) -> &[u8] {
        &self.0
    }
}

/// The settings of Apassy Connect (ADR 0037 stage 7, connect-account-v1).
#[derive(Debug, Clone)]
pub struct ConnectConfig {
    pub mode: RelayMode,
    /// The account routes are served (`APASSY_RELAY_CONNECT_ACCOUNTS=1`, or `connect` mode).
    pub accounts: bool,
    /// The signing key of the entitlement token (`APASSY_CONNECT_SIGNING_KEY_FILE`).
    pub signing_key: Option<ConnectSigningKey>,
    /// The other published keys of the well-known document
    /// (`APASSY_CONNECT_PUBLISHED_KEYS_FILE`): the next key and the previous one.
    pub published_keys: Vec<crate::server::entitlement::PublishedKey>,
    /// New accounts of the relay in 24 hours (`APASSY_RELAY_CONNECT_ACCOUNTS_PER_DAY`).
    pub accounts_per_day: u64,
    /// Accounts the relay holds at once (`APASSY_RELAY_CONNECT_ACCOUNTS_MAX`).
    pub accounts_max: u64,
    /// The site origin (`APASSY_CONNECT_SITE_URL`), for billing and groups.
    pub site_url: String,
    /// Stripe billing (`STRIPE_SECRET_KEY_FILE`, `STRIPE_WEBHOOK_SECRET_FILE`), or `None`:
    /// the billing routes answer 503 `busy` and no account has a plan.
    pub billing: Option<BillingSettings>,
    /// The tunnel and its ingress (connect-tunnel-v1), used only with the account routes.
    pub tunnel: TunnelSettings,
}

/// The settings of Connect billing (docs/SPEC.md section 34.7).
#[derive(Clone)]
pub struct BillingSettings {
    /// The restricted Stripe key (`STRIPE_SECRET_KEY_FILE`).
    pub secret_key: SecretString,
    /// The webhook endpoint secret (`STRIPE_WEBHOOK_SECRET_FILE`).
    pub webhook_secret: SecretString,
    /// The site, the Family extra price, and the durations of the plan state.
    pub config: crate::server::billing::BillingConfig,
    /// The Stripe API base: always `https://api.stripe.com` from the environment. Only
    /// code sets another one, and `Relay::start` takes no other than a loopback `http://`
    /// base (the fake Stripe server of the tests).
    pub stripe_api_base: String,
}

impl std::fmt::Debug for BillingSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BillingSettings")
            .field("config", &self.config)
            .field("stripe_api_base", &self.stripe_api_base)
            .finish_non_exhaustive()
    }
}

impl BillingSettings {
    /// Settings with the default configuration, for tests and a self-hosted Connect.
    pub fn new(secret_key: SecretString, webhook_secret: SecretString) -> Self {
        Self {
            secret_key,
            webhook_secret,
            config: crate::server::billing::BillingConfig::default(),
            stripe_api_base: crate::server::stripe::API_BASE.to_string(),
        }
    }

    /// The Stripe base that `Relay::start` accepts: the real API, or a loopback `http://`
    /// address.
    pub fn check_api_base(&self) -> RelayResult<()> {
        let base = self.stripe_api_base.trim_end_matches('/');
        let loopback = ["http://127.0.0.1:", "http://[::1]:", "http://localhost:"]
            .iter()
            .any(|prefix| base.starts_with(prefix));
        if base == crate::server::stripe::API_BASE || loopback {
            Ok(())
        } else {
            Err(RelayError::invalid(
                "The Stripe API base is https://api.stripe.com, or a loopback http:// address in a test.",
            ))
        }
    }
}

impl Default for ConnectConfig {
    /// No accounts: every account route is 404.
    fn default() -> Self {
        Self {
            mode: RelayMode::Relay,
            accounts: false,
            signing_key: None,
            published_keys: Vec::new(),
            accounts_per_day: DEFAULT_CONNECT_ACCOUNTS_PER_DAY,
            accounts_max: DEFAULT_CONNECT_ACCOUNTS_MAX,
            site_url: DEFAULT_CONNECT_SITE_URL.to_string(),
            billing: None,
            tunnel: TunnelSettings::default(),
        }
    }
}

impl ConnectConfig {
    /// The settings of a relay with the account routes on and the signing key `key`, for
    /// tests and for a self-hosted Connect.
    pub fn accounts(signing_key: Option<ConnectSigningKey>) -> Self {
        Self {
            accounts: true,
            signing_key,
            ..Self::default()
        }
    }

    /// True in `connect` mode: no master key, plain files.
    pub fn plain_files(&self) -> bool {
        self.mode == RelayMode::Connect
    }
}

/// The Connect settings from the environment. `master_key_set`: `APASSY_RELAY_KEY` or
/// `APASSY_RELAY_KEY_FILE` is set, which `connect` mode refuses.
fn connect_from(
    lookup: &impl Fn(&str) -> Option<String>,
    master_key_set: bool,
) -> RelayResult<ConnectConfig> {
    let mode = match lookup("APASSY_RELAY_MODE").as_deref().map(str::trim) {
        None | Some("relay") => RelayMode::Relay,
        Some("connect") => RelayMode::Connect,
        Some(_) => {
            return Err(RelayError::invalid(
                "APASSY_RELAY_MODE is relay or connect.",
            ));
        }
    };
    if mode == RelayMode::Connect && master_key_set {
        return Err(RelayError::invalid(
            "APASSY_RELAY_MODE=connect refuses a master key: unset APASSY_RELAY_KEY and APASSY_RELAY_KEY_FILE (Connect keeps no secret, ADR 0037 stage 7).",
        ));
    }
    let accounts = match lookup("APASSY_RELAY_CONNECT_ACCOUNTS").as_deref() {
        None => mode == RelayMode::Connect,
        Some("0") => false,
        Some("1") => true,
        Some(_) => {
            return Err(RelayError::invalid(
                "APASSY_RELAY_CONNECT_ACCOUNTS is 0 or 1.",
            ));
        }
    };
    if mode == RelayMode::Connect && !accounts {
        return Err(RelayError::invalid(
            "APASSY_RELAY_MODE=connect serves the account routes: APASSY_RELAY_CONNECT_ACCOUNTS cannot be 0 there.",
        ));
    }
    let signing_key = match lookup("APASSY_CONNECT_SIGNING_KEY_FILE") {
        None => None,
        Some(path) => {
            let unreadable =
                || RelayError::invalid("APASSY_CONNECT_SIGNING_KEY_FILE cannot be read.");
            let file = std::fs::File::open(path.trim()).map_err(|_| unreadable())?;
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            std::io::Read::read_to_end(
                &mut std::io::Read::take(file, MAX_SIGNING_KEY_FILE_BYTES + 1),
                &mut bytes,
            )
            .map_err(|_| unreadable())?;
            if bytes.len() as u64 > MAX_SIGNING_KEY_FILE_BYTES {
                return Err(unreadable());
            }
            Some(ConnectSigningKey::from_file_bytes(&bytes)?)
        }
    };
    let published_keys = match lookup("APASSY_CONNECT_PUBLISHED_KEYS_FILE") {
        None => Vec::new(),
        Some(path) => {
            let unreadable =
                || RelayError::invalid("APASSY_CONNECT_PUBLISHED_KEYS_FILE cannot be read.");
            let file = std::fs::File::open(path.trim()).map_err(|_| unreadable())?;
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(
                &mut std::io::Read::take(file, MAX_PUBLISHED_KEYS_FILE_BYTES + 1),
                &mut bytes,
            )
            .map_err(|_| unreadable())?;
            if bytes.len() as u64 > MAX_PUBLISHED_KEYS_FILE_BYTES {
                return Err(unreadable());
            }
            published_keys_from(&bytes)?
        }
    };
    let accounts_per_day = number(
        lookup,
        "APASSY_RELAY_CONNECT_ACCOUNTS_PER_DAY",
        DEFAULT_CONNECT_ACCOUNTS_PER_DAY,
        0,
        MAX_CONNECT_ACCOUNTS_PER_DAY,
    )?;
    let accounts_max = number(
        lookup,
        "APASSY_RELAY_CONNECT_ACCOUNTS_MAX",
        DEFAULT_CONNECT_ACCOUNTS_MAX,
        0,
        MAX_CONNECT_ACCOUNTS_MAX,
    )?;
    let site_url = match lookup("APASSY_CONNECT_SITE_URL") {
        None => DEFAULT_CONNECT_SITE_URL.to_string(),
        Some(text) => {
            let url = checked_public_url(&text)?;
            if !url.starts_with("https://") {
                return Err(RelayError::invalid(
                    "APASSY_CONNECT_SITE_URL is an https:// origin.",
                ));
            }
            url
        }
    };
    let billing = billing_from(lookup, &site_url)?;
    let tunnel = tunnel_from(lookup)?;
    Ok(ConnectConfig {
        mode,
        accounts,
        signing_key,
        published_keys,
        accounts_per_day,
        accounts_max,
        site_url,
        billing,
        tunnel,
    })
}

/// The keys of `APASSY_CONNECT_PUBLISHED_KEYS_FILE`: `{"keys":[{"kid","public_key"}]}`,
/// at most `MAX_PUBLISHED_KEYS`, each an Ed25519 public key (b64u, 32 bytes) named by its
/// own `entitlement::key_id`, no kid twice.
pub fn published_keys_from(
    bytes: &[u8],
) -> RelayResult<Vec<crate::server::entitlement::PublishedKey>> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct File {
        keys: Vec<Entry>,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Entry {
        kid: String,
        public_key: String,
    }
    let invalid = |why: &str| {
        RelayError::invalid(format!(
            "APASSY_CONNECT_PUBLISHED_KEYS_FILE is not valid: {why}"
        ))
    };
    let file: File = serde_json::from_slice(bytes)
        .map_err(|_| invalid("it is JSON {\"keys\":[{\"kid\",\"public_key\"}]}."))?;
    if file.keys.len() > MAX_PUBLISHED_KEYS {
        return Err(invalid("it has more than 8 keys."));
    }
    let mut keys: Vec<crate::server::entitlement::PublishedKey> = Vec::new();
    for entry in file.keys {
        let text = entry.public_key.trim();
        let public_key: [u8; 32] = crate::hostkeys::decode_b64(text, 32)
            .ok()
            .filter(|_| text.len() == 43)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| invalid("a public key is not b64u of 32 bytes."))?;
        if entry.kid != crate::server::entitlement::key_id(&public_key) {
            return Err(invalid("a kid is not the key id of its public key."));
        }
        if keys.iter().any(|key| key.kid == entry.kid) {
            return Err(invalid("a kid is there twice."));
        }
        keys.push(crate::server::entitlement::PublishedKey {
            kid: entry.kid,
            public_key,
        });
    }
    Ok(keys)
}

/// The settings of the Connect tunnel (connect-tunnel-v1 sections 7 and 8). Only a relay
/// with the account routes uses them: `Relay::start` makes the broker then, and each
/// ingress listener only when its address is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelSettings {
    /// The SNI ingress (`APASSY_CONNECT_INGRESS_LISTEN`), or none.
    pub ingress_listen: Option<SocketAddr>,
    /// The ACME HTTP-01 listener (`APASSY_CONNECT_ACME_LISTEN`), or none.
    pub acme_listen: Option<SocketAddr>,
    /// The zone of the public names, lowercase, without a trailing dot.
    pub node_zone: String,
    /// Open streams of one account (its nodes, all kinds).
    pub streams_per_account: usize,
    /// Nodes of one account (registered, and online at once).
    pub nodes_per_account: usize,
    /// Dials of one account in one minute.
    pub dials_per_minute: u32,
    /// Bytes of one account in one UTC month for each person (Family) or member (Team).
    pub bytes_per_month: u64,
    /// Connect pings each tunnel WebSocket this often.
    pub ping_interval: Duration,
    /// A tunnel WebSocket with no message for this long closes.
    pub idle_timeout: Duration,
    /// A stream with no byte for this long is reset.
    pub stream_idle: Duration,
    /// Bytes buffered toward one client of a stream.
    pub stream_buffer: usize,
}

impl Default for TunnelSettings {
    /// The contract's defaults (section 8), no ingress listener.
    fn default() -> Self {
        Self {
            ingress_listen: None,
            acme_listen: None,
            node_zone: DEFAULT_CONNECT_NODE_ZONE.to_string(),
            streams_per_account: 64,
            nodes_per_account: 8,
            dials_per_minute: 60,
            bytes_per_month: 20 * 1024 * 1024 * 1024,
            ping_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(90),
            stream_idle: Duration::from_secs(15 * 60),
            stream_buffer: 256 * 1024,
        }
    }
}

/// A DNS zone for public names: labels of `a-z`, `0-9`, and `-` (1 to 63 characters, no
/// `-` at either end), at least two labels, and room for the 11 characters of a node's
/// label and its dot within 253. Lowercased, without a trailing dot.
fn checked_zone(text: &str) -> Option<String> {
    let zone = text.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = zone.split('.').collect();
    let label_ok = |label: &&str| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    (labels.len() >= 2 && zone.len() <= 242 && labels.iter().all(label_ok)).then_some(zone)
}

/// The tunnel settings from the environment: none of the keys set is the default.
fn tunnel_from(lookup: &impl Fn(&str) -> Option<String>) -> RelayResult<TunnelSettings> {
    let address = |name: &str| -> RelayResult<Option<SocketAddr>> {
        lookup(name)
            .map(|text| {
                text.trim().parse::<SocketAddr>().map_err(|_| {
                    RelayError::invalid(format!("{name} is an address such as 0.0.0.0:443."))
                })
            })
            .transpose()
    };
    let ingress_listen = address("APASSY_CONNECT_INGRESS_LISTEN")?;
    let acme_listen = address("APASSY_CONNECT_ACME_LISTEN")?;
    let node_zone = match lookup("APASSY_CONNECT_NODE_ZONE") {
        None => DEFAULT_CONNECT_NODE_ZONE.to_string(),
        Some(text) => checked_zone(&text).ok_or_else(|| {
            RelayError::invalid("APASSY_CONNECT_NODE_ZONE is a DNS name such as node.example.com.")
        })?,
    };
    let streams_per_account =
        number(lookup, "APASSY_CONNECT_TUNNEL_STREAMS", 64, 1, 4096)? as usize;
    let nodes_per_account = number(lookup, "APASSY_CONNECT_TUNNEL_NODES", 8, 1, 64)? as usize;
    let dials_per_minute = number(
        lookup,
        "APASSY_CONNECT_TUNNEL_DIALS_PER_MINUTE",
        60,
        1,
        6000,
    )? as u32;
    let gib = number(lookup, "APASSY_CONNECT_TUNNEL_GIB_PER_MONTH", 20, 1, 10_240)?;
    let ping = number(lookup, "APASSY_CONNECT_TUNNEL_PING_SECS", 30, 5, 300)?;
    let idle = number(lookup, "APASSY_CONNECT_TUNNEL_IDLE_SECS", 90, 10, 3600)?;
    if idle <= ping {
        return Err(RelayError::invalid(
            "APASSY_CONNECT_TUNNEL_IDLE_SECS is above APASSY_CONNECT_TUNNEL_PING_SECS.",
        ));
    }
    let stream_idle = number(
        lookup,
        "APASSY_CONNECT_TUNNEL_STREAM_IDLE_SECS",
        900,
        60,
        86_400,
    )?;
    let buffer_kib = number(
        lookup,
        "APASSY_CONNECT_TUNNEL_STREAM_BUFFER_KIB",
        256,
        64,
        16_384,
    )?;
    Ok(TunnelSettings {
        ingress_listen,
        acme_listen,
        node_zone,
        streams_per_account,
        nodes_per_account,
        dials_per_minute,
        bytes_per_month: gib * 1024 * 1024 * 1024,
        ping_interval: Duration::from_secs(ping),
        idle_timeout: Duration::from_secs(idle),
        stream_idle: Duration::from_secs(stream_idle),
        stream_buffer: buffer_kib as usize * 1024,
    })
}

/// The billing settings from the environment: both Stripe files or neither, and the five
/// settings of `BillingConfig::from_lookup` (checked even without the files, so a typo
/// stops the start). The site is `APASSY_CONNECT_SITE_URL` as checked above.
fn billing_from(
    lookup: &impl Fn(&str) -> Option<String>,
    site_url: &str,
) -> RelayResult<Option<BillingSettings>> {
    let mut config = crate::server::billing::BillingConfig::from_lookup(&|name| lookup(name))?;
    config.site_url = site_url.trim_end_matches('/').to_string();
    let key = lookup("STRIPE_SECRET_KEY_FILE");
    let webhook = lookup("STRIPE_WEBHOOK_SECRET_FILE");
    let (key, webhook) = match (key, webhook) {
        (None, None) => return Ok(None),
        (Some(key), Some(webhook)) => (key, webhook),
        _ => {
            return Err(RelayError::invalid(
                "Set STRIPE_SECRET_KEY_FILE and STRIPE_WEBHOOK_SECRET_FILE together, or neither.",
            ));
        }
    };
    Ok(Some(BillingSettings {
        secret_key: crate::server::stripe::read_secret_key_file(std::path::Path::new(key.trim()))?,
        webhook_secret: crate::server::stripe::read_webhook_secret_file(std::path::Path::new(
            webhook.trim(),
        ))?,
        config,
        stripe_api_base: crate::server::stripe::API_BASE.to_string(),
    }))
}

/// What an embedded node needs (`RelayConfig::embedded`, docs/SPEC.md section 30).
#[derive(Debug, Clone)]
pub struct EmbeddedOptions {
    /// The node's own data directory, such as `<app data>/node`.
    pub data_dir: PathBuf,
    /// Opens `relay.db`. At least `MIN_KEY_BYTES`.
    pub master_key: SecretString,
    /// The origin that agents use: the Funnel origin `https://<name>:8443`. Base URLs
    /// start with it. A node without Funnel (the Linux node) gives its node origin.
    pub public_url: String,
    /// The loopback address of the public listener (`Scope::Public`), or `None` for no
    /// public route.
    pub public_listen: Option<SocketAddr>,
    /// The node origin `https://<Tailscale IPv4>:<port>` (node-pairing-v1 section 3): the
    /// origin that devices store, sign, and show. `None`: no tailnet route (the devices of
    /// this node reach it only through the app, in process). With it, `tailnet_listen` is
    /// required.
    pub node_origin: Option<String>,
    /// The loopback address of the tailnet listener (`Scope::Tailnet`), the target of the
    /// TLS front, such as `127.0.0.1:0`. Required with `node_origin`, refused without it.
    pub tailnet_listen: Option<SocketAddr>,
    /// The tailnet listener also serves the team routes (`/v1/runs`, `/mcp`, the host
    /// lane, ...): the Linux node. The Mac node serves the device routes only.
    pub tailnet_agents: bool,
    /// The push gateway of the node (`DEFAULT_PUSH_GATEWAY` unless the owner names
    /// another), the one that its devices may name at `PUT /v1/push/handle`. `None`: no
    /// push (409 `push_unavailable`). Needs `node_origin`.
    pub push_gateway: Option<String>,
}

/// Everything the relay server needs to start.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub data_dir: PathBuf,
    /// The listener of every route (`Scope::Node`).
    pub listen: SocketAddr,
    /// A second listener that serves only `POST /mcp` and `/p/` (`Scope::Public`, an
    /// embedded node). `None` on the hosted relay.
    pub public_listen: Option<SocketAddr>,
    /// A third listener for the TLS front of a node on the tailnet (`Scope::Tailnet`,
    /// docs/SPEC.md section 32): the device routes, and with `tailnet_agents` the team
    /// routes. On the loopback. `None` on the hosted relay. A relay with it is a node: it
    /// takes node pairing codes at `POST /v1/teams`.
    pub tailnet_listen: Option<SocketAddr>,
    /// The tailnet listener also serves the team routes (the Linux node).
    pub tailnet_agents: bool,
    /// For example `https://apassy-relay.wyderka.cc`. Base URLs start with it.
    pub public_url: String,
    /// The origins that a device may sign at sign-in (docs/SPEC.md section 23.2, 32.3).
    /// Empty: `public_url` alone, as the hosted relay. A node: its node origin first, and
    /// with the public route on, the Funnel `public_url`. Read it with
    /// `RelayConfig::sign_in_origins`.
    pub sign_in_origins: Vec<String>,
    pub edge: EdgeMode,
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
    /// The push trigger (docs/SPEC.md section 25.6): the Worker of the hosted relay, or
    /// the push gateway of a node (section 32.5). `None`: push is off.
    pub push: Option<PushConfig>,
    /// Shared team vaults, runs, MCP, and the proxy are served (`APASSY_RELAY_TEAM_VAULTS`).
    /// Off on the hosted relay (ADR 0037, D8): those requests are 410 `team_vaults_retired`,
    /// and devices, relay sync, questions, feed, and push go on. A user's own node keeps it on.
    pub team_vaults: bool,
    /// Questions with `to: "approvers"` are taken (`APASSY_RELAY_QUESTIONS_TO_APPROVERS`).
    /// Off until shared vaults (integrator decision 1): such a post is 403 `not_routed`.
    pub questions_to_approvers: bool,
    /// Connect teams the relay makes in any 24 hours (`APASSY_RELAY_CONNECT_TEAMS_PER_DAY`).
    /// Over it, `POST /v1/connect` is 503 `busy`; `0` turns Connect off.
    pub connect_teams_per_day: u64,
    /// Connect teams the relay holds at once, active or suspended
    /// (`APASSY_RELAY_CONNECT_TEAMS_MAX`). At it, `POST /v1/connect` is 503 `busy`.
    pub connect_teams_max: u64,
    /// The `sync_bytes` of each new Connect team (`APASSY_RELAY_CONNECT_SYNC_BYTES`): 0
    /// (no relay sync, 403 `plan_required`) or 1 MiB to 64 MiB. A team keeps the value
    /// it was made with; `admin limits` changes it for one team.
    pub connect_sync_bytes: u64,
    /// The free Connect paths of ADR 0032 are served (`APASSY_RELAY_FREE_CONNECT`, 1 by
    /// default). Off (the transition before the cutover, ADR 0037 D14): `POST /v1/connect`
    /// and the questions, feed, and push routes of free Connect teams are 410
    /// `free_connect_ended`, and with `connect_sync_bytes` 0 their pushes and receipts are
    /// 403 `plan_required` (`free_sync_ended`). Operator teams and vault stores never see
    /// it. Always off in `connect` mode.
    pub free_connect: bool,
    /// Each listener counts bad bearer tokens and session keys: after
    /// `http::AUTH_FAILURES_MAX` in `http::AUTH_FAILURE_WINDOW_SECS`, the listener answers
    /// 429 `rate_limited` until the window ends (docs/SPEC.md section 30.5). On for an
    /// embedded node; off on the hosted relay, whose edge limits callers.
    pub auth_limiter: bool,
    /// The operator socket `admin.sock` is served (`server::operator`, docs/SPEC.md
    /// section 22). On for the hosted relay. Off for an embedded node: its data
    /// directory belongs to the Mac user, and the coding agents of that Mac run as the
    /// same user, so a socket of mode 0600 would let them suspend or delete the personal
    /// team or make team codes (review 0.5.16, docs/SPEC.md section 30.4).
    pub operator_socket: bool,
    /// The MCP authorization flow of an embedded node (OAuth 2.1, docs/SPEC.md section
    /// 31): its metadata, `/oauth/...`, and `WWW-Authenticate` on a 401 of `/mcp`. `None`
    /// on the hosted relay: every OAuth path is 404 there.
    pub oauth: Option<OAuthConfig>,
    /// Apassy Connect: the account routes, the mode, the entitlement signing key
    /// (connect-account-v1). The default has no accounts.
    pub connect: ConnectConfig,
}

/// The settings of the MCP authorization flow of an embedded node (docs/SPEC.md section
/// 31). The defaults are the product's; tests shorten the times.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthConfig {
    /// The name of the Mac on the connect page: `EMBEDDED_MAC_NAME` ("your Mac") on a node
    /// of the app. Never the computer name: the page is public.
    pub mac_name: String,
    /// The lifetime of an access token (`oauth::ACCESS_TOKEN_SECS`).
    pub access_token_secs: u64,
    /// The lifetime of a refresh token (`oauth::REFRESH_TOKEN_SECS`).
    pub refresh_token_secs: u64,
    /// How long a connect request waits for the owner (`oauth::CONNECT_SECS`).
    pub connect_secs: u64,
    /// How long an authorization code can be redeemed (`oauth::CODE_SECS`).
    pub code_secs: u64,
}

impl OAuthConfig {
    /// The product's times, with the name of the Mac on the connect page.
    pub fn new(mac_name: &str) -> Self {
        Self {
            mac_name: mac_name.to_string(),
            access_token_secs: crate::server::oauth::ACCESS_TOKEN_SECS,
            refresh_token_secs: crate::server::oauth::REFRESH_TOKEN_SECS,
            connect_secs: crate::server::oauth::CONNECT_SECS,
            code_secs: crate::server::oauth::CODE_SECS,
        }
    }
}

/// Where and how the relay sends pushes.
#[derive(Debug, Clone)]
pub enum PushConfig {
    /// The hosted relay: the relay asks the Worker to send pushes to the push tokens of
    /// its devices (docs/SPEC.md section 25.6). `from_env` makes only this form.
    Worker {
        /// The Worker's push route: `https://`, or `http://` to a loopback address (tests).
        url: String,
        /// The bundle id of the iPhone app (the APNs topic). A push token names it.
        topic: String,
        /// Sent as `X-Apassy-Push`. Never logged.
        secret: SecretString,
        /// One call to the Worker, from the connection to the last byte of the answer:
        /// 10 s.
        timeout: Duration,
        /// The unit of the retry backoff (1, 2, 4 … 60 units, plus 0..2 units of jitter):
        /// one second.
        backoff_unit: Duration,
    },
    /// A node: the relay asks a push gateway to push to the handles of its devices, one
    /// request per handle, with the proof of push-gateway-v1 section 7 (docs/SPEC.md
    /// section 32.5). No token reaches the node.
    Gateway {
        /// The gateways that a device may name at `PUT /v1/push/handle`, as origins
        /// (`checked_gateway`): the node calls no other address.
        gateways: Vec<String>,
        /// One call to a gateway, from the connection to the last byte of the answer:
        /// 10 s. No retry.
        timeout: Duration,
        /// Kept for the shape of `Worker`: the gateway mode does not retry.
        backoff_unit: Duration,
    },
}

impl PushConfig {
    /// The Worker push of the relay with the deadlines of docs/SPEC.md section 25.6.
    pub fn new(url: String, topic: String, secret: SecretString) -> Self {
        Self::Worker {
            url,
            topic,
            secret,
            timeout: crate::server::push::TIMEOUT,
            backoff_unit: crate::server::push::BACKOFF_UNIT,
        }
    }

    /// The gateway push of a node with the deadline of push-gateway-v1 section 10. Each
    /// gateway is an origin (`checked_gateway`); at least one.
    pub fn gateway(gateways: Vec<String>) -> RelayResult<Self> {
        if gateways.is_empty() {
            return Err(RelayError::invalid(
                "A node with push names a push gateway.",
            ));
        }
        let gateways = gateways
            .iter()
            .map(|gateway| checked_gateway(gateway))
            .collect::<RelayResult<Vec<_>>>()?;
        Ok(Self::Gateway {
            gateways,
            timeout: crate::server::push::TIMEOUT,
            backoff_unit: crate::server::push::BACKOFF_UNIT,
        })
    }

    /// One call to the Worker or a gateway, at most.
    pub fn timeout(&self) -> Duration {
        match self {
            Self::Worker { timeout, .. } | Self::Gateway { timeout, .. } => *timeout,
        }
    }

    /// The unit of the retry backoff of the Worker mode.
    pub fn backoff_unit(&self) -> Duration {
        match self {
            Self::Worker { backoff_unit, .. } | Self::Gateway { backoff_unit, .. } => *backoff_unit,
        }
    }

    /// The APNs topic of the Worker mode (`PUT /v1/push/token`); `None` for a gateway.
    pub fn topic(&self) -> Option<&str> {
        match self {
            Self::Worker { topic, .. } => Some(topic),
            Self::Gateway { .. } => None,
        }
    }
}

/// A push gateway origin (push-gateway-v1 section 10): `https://` with a host and an
/// optional port, lowercase, no path, query, fragment, user, or trailing slash; or
/// `http://` to `127.0.0.1` or `localhost` (tests). The text is compared as it is: a
/// device names a gateway with exactly this text.
pub fn checked_gateway(text: &str) -> RelayResult<String> {
    let invalid = || {
        RelayError::invalid(
            "A push gateway is an origin such as https://push.example.com, with no path.",
        )
    };
    let text = text.trim();
    let (rest, loopback_only) = if let Some(rest) = text.strip_prefix("https://") {
        (rest, false)
    } else if let Some(rest) = text.strip_prefix("http://") {
        (rest, true)
    } else {
        return Err(invalid());
    };
    if rest.is_empty()
        || rest.len() > 261
        || rest.bytes().any(|b| {
            !(b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b':'))
        })
    {
        return Err(invalid());
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (rest, None),
    };
    if host.is_empty()
        || host.contains(':')
        || port.is_some_and(|port| {
            port.starts_with('0') || port.parse::<u16>().is_err() || port.is_empty()
        })
    {
        return Err(invalid());
    }
    if loopback_only && !matches!(host, "127.0.0.1" | "localhost") {
        return Err(invalid());
    }
    Ok(text.to_string())
}

/// A node origin (node-pairing-v1 section 3): `https://<host>:<port>`, lowercase, an
/// explicit port that is not 443, and nothing else. The text is the value that devices
/// sign, so it is kept exactly.
pub fn checked_node_origin(text: &str) -> RelayResult<String> {
    let invalid = || {
        RelayError::invalid(
            "The node origin is https://<Tailscale IPv4>:<port>, such as https://100.64.0.7:8444.",
        )
    };
    let rest = text.strip_prefix("https://").ok_or_else(invalid)?;
    let (host, port) = rest.rsplit_once(':').ok_or_else(invalid)?;
    let port_ok = !port.is_empty()
        && !port.starts_with('0')
        && port.parse::<u16>().is_ok_and(|port| port != 443);
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'));
    if !port_ok || !host_ok {
        return Err(invalid());
    }
    Ok(text.to_string())
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

    /// The origins that a device may sign at sign-in, in order: `sign_in_origins`, or
    /// `public_url` alone when it is empty. The first is the one a challenge names when
    /// the request's `Host` names none of them (`devices::challenge_for`).
    pub fn sign_in_origins(&self) -> Vec<&str> {
        if self.sign_in_origins.is_empty() {
            vec![self.public_url.as_str()]
        } else {
            self.sign_in_origins.iter().map(String::as_str).collect()
        }
    }

    /// True for a node on the tailnet: a relay with a tailnet listener. Only a node takes
    /// a node pairing code (directory 1005).
    pub fn is_node(&self) -> bool {
        self.tailnet_listen.is_some()
    }

    /// Refuses `EdgeMode::Off` unless every listener is on the loopback: without the
    /// edge, nothing else keeps a caller from the network away. The tailnet listener is
    /// on the loopback in every mode: only the TLS front of the node reaches it.
    pub fn check_listeners(&self) -> RelayResult<()> {
        if self
            .tailnet_listen
            .is_some_and(|addr| !addr.ip().is_loopback())
        {
            return Err(RelayError::invalid(
                "The tailnet listener must be on a loopback address: only the TLS front forwards to it.",
            ));
        }
        if matches!(self.edge, EdgeMode::Off) {
            let loopback = std::iter::once(self.listen)
                .chain(self.public_listen)
                .chain(self.tailnet_listen)
                .all(|addr| addr.ip().is_loopback());
            if !loopback {
                return Err(RelayError::invalid(
                    "A relay without the edge listens on loopback addresses only.",
                ));
            }
        }
        Ok(())
    }

    /// True when the free relay sync of Connect teams is over (the transition before the
    /// cutover, ADR 0037 D14): `APASSY_RELAY_FREE_CONNECT=0` and
    /// `APASSY_RELAY_CONNECT_SYNC_BYTES` 0. A push or a receipt of a free Connect team is
    /// then 403 `plan_required` whatever its own `sync_bytes`; its pulls and downloads
    /// still work, so its devices can move their vault. Operator teams and vault stores
    /// never see it.
    pub fn free_sync_ended(&self) -> bool {
        !self.free_connect && self.connect_sync_bytes == 0
    }

    /// Refuses a configuration that `connect` mode cannot run (docs/SPEC.md section 37):
    /// a master key, push, shared team vaults, the public or tailnet listener of a node,
    /// the MCP authorization flow, or no account routes (`free_connect` has no effect
    /// there: every free Connect route is 410 `hosted_retired` before it is read). The
    /// environment cannot make one (`from_lookup` refuses it first); this keeps a
    /// configuration made in code (a test, a self-hosted Connect) to the same rules. Any
    /// configuration in `relay` mode passes.
    pub fn check_mode(&self) -> RelayResult<()> {
        if !self.connect.plain_files() {
            return Ok(());
        }
        let refused = |what: &str| {
            Err(RelayError::invalid(format!(
                "APASSY_RELAY_MODE=connect cannot run with {what} (docs/SPEC.md section 37)."
            )))
        };
        if !self.master_key.is_empty() {
            return refused("a master key");
        }
        if self.push.is_some() {
            return refused("push");
        }
        if self.team_vaults {
            return refused("shared team vaults");
        }
        if self.public_listen.is_some() || self.tailnet_listen.is_some() {
            return refused("the public or tailnet listener of a node");
        }
        if self.oauth.is_some() {
            return refused("the MCP authorization flow");
        }
        if !self.connect.accounts {
            return refused("the account routes off");
        }
        Ok(())
    }

    /// Refuses `what` (an operator command that opens the files with their keys) in
    /// `connect` mode, where the files are plain and no image before Connect can read them:
    /// the way back from Connect is the backup made before the cutover and the previous
    /// image (docs/operations/connect.md).
    pub fn refuse_connect_mode(&self, what: &str) -> RelayResult<()> {
        if self.connect.plain_files() {
            return Err(RelayError::invalid(format!(
                "{what} does not apply in APASSY_RELAY_MODE=connect: relay.db and the vault stores are plain files that no image before Apassy Connect opens. Roll back with the backup made before the cutover and the previous image (docs/operations/connect.md)."
            )));
        }
        Ok(())
    }

    /// The configuration of a Mac's own node (docs/SPEC.md section 30): the node
    /// listener on `127.0.0.1:0`, the public listener of `options`, no edge, shared team
    /// vaults on, Connect off, sessions of `EMBEDDED_SESSION_TTL_SECS`, runs that wait
    /// `EMBEDDED_APPROVAL_TIMEOUT_SECS`, the failed-auth limiter on, the MCP authorization
    /// flow on (`OAuthConfig::new` with `EMBEDDED_MAC_NAME`, "your Mac", also for the app),
    /// and no operator socket (`operator_socket` false; the Linux node turns it on in
    /// `node::config::relay_config`). With `node_origin`, the tailnet
    /// listener of `options` (docs/SPEC.md section 32), the sign-in origins (the node
    /// origin, then `public_url` when the public route is on), and push through
    /// `push_gateway`; without it, one sign-in origin (`public_url`) and no push.
    pub fn embedded(options: EmbeddedOptions) -> RelayResult<Self> {
        let public_url = checked_public_url(&options.public_url)?;
        if options.master_key.len() < MIN_KEY_BYTES {
            return Err(RelayError::invalid(format!(
                "The master key must have at least {MIN_KEY_BYTES} bytes."
            )));
        }
        let node_origin = options
            .node_origin
            .as_deref()
            .map(checked_node_origin)
            .transpose()?;
        if node_origin.is_some() != options.tailnet_listen.is_some() {
            return Err(RelayError::invalid(
                "A node origin and a tailnet listener go together.",
            ));
        }
        if node_origin.is_none() && (options.tailnet_agents || options.push_gateway.is_some()) {
            return Err(RelayError::invalid(
                "The team routes and push of a node need its node origin.",
            ));
        }
        let mut sign_in_origins = Vec::new();
        if let Some(origin) = &node_origin {
            sign_in_origins.push(origin.clone());
            if options.public_listen.is_some() && public_url != *origin {
                sign_in_origins.push(public_url.clone());
            }
        }
        let push = options
            .push_gateway
            .map(|gateway| PushConfig::gateway(vec![gateway]))
            .transpose()?;
        let config = Self {
            backup_dir: options.data_dir.join("backups"),
            data_dir: options.data_dir,
            listen: SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
            public_listen: options.public_listen,
            tailnet_listen: options.tailnet_listen,
            tailnet_agents: options.tailnet_agents,
            public_url,
            sign_in_origins,
            edge: EdgeMode::Off,
            master_key: options.master_key,
            session_ttl_secs: EMBEDDED_SESSION_TTL_SECS,
            approval_timeout_secs: EMBEDDED_APPROVAL_TIMEOUT_SECS,
            upstream: UpstreamOptions::default(),
            limits: Limits::default(),
            request_read_timeout: Duration::from_secs(30),
            request_handle_timeout: Duration::from_secs(90),
            push,
            team_vaults: true,
            questions_to_approvers: false,
            connect_teams_per_day: 0,
            connect_teams_max: 0,
            connect_sync_bytes: DEFAULT_CONNECT_SYNC_BYTES,
            free_connect: true,
            auth_limiter: true,
            operator_socket: false,
            oauth: Some(OAuthConfig::new(EMBEDDED_MAC_NAME)),
            connect: ConnectConfig::default(),
        };
        config.check_listeners()?;
        Ok(config)
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
        let master_key_set =
            lookup("APASSY_RELAY_KEY").is_some() || lookup("APASSY_RELAY_KEY_FILE").is_some();
        let connect = connect_from(&lookup, master_key_set)?;
        // `connect` mode has no master key: its files are plain (`Store::open_plain`).
        let master_key = if connect.plain_files() {
            SecretString::new(String::new())
        } else {
            secret_from(&lookup, "APASSY_RELAY_KEY")?
        };
        if !connect.plain_files() && master_key.len() < MIN_KEY_BYTES {
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
        let connect_sync_bytes = number(
            &lookup,
            "APASSY_RELAY_CONNECT_SYNC_BYTES",
            DEFAULT_CONNECT_SYNC_BYTES,
            0,
            crate::sync_head::MAX_SNAPSHOT_BYTES,
        )?;
        if connect_sync_bytes != 0 && connect_sync_bytes < MIN_CONNECT_SYNC_BYTES {
            return Err(RelayError::invalid(
                "APASSY_RELAY_CONNECT_SYNC_BYTES must be 0 (no relay sync) or 1048576 to 67108864.",
            ));
        }
        let connect_long_polls = number(
            &lookup,
            "APASSY_RELAY_CONNECT_LONG_POLLS",
            DEFAULT_CONNECT_LONG_POLLS as u64,
            0,
            MAX_CONNECT_LONG_POLLS as u64,
        )?;
        let free_connect = match lookup("APASSY_RELAY_FREE_CONNECT")
            .as_deref()
            .map(str::trim)
        {
            // Connect has no free path: everything of ADR 0032 is retired there.
            _ if connect.plain_files() => false,
            None | Some("1") => true,
            Some("0") => false,
            Some(_) => {
                return Err(RelayError::invalid("APASSY_RELAY_FREE_CONNECT is 0 or 1."));
            }
        };
        // Connect sends no push: the nodes push through the push gateway (ADR 0037 D7),
        // and the Worker's push route is off there. A push value left in the compose file
        // would otherwise start the push thread of a relay that has no question.
        if connect.plain_files()
            && [
                "APASSY_RELAY_PUSH_URL",
                "APASSY_RELAY_PUSH_TOPIC",
                "APASSY_RELAY_PUSH_SECRET",
                "APASSY_RELAY_PUSH_SECRET_FILE",
            ]
            .iter()
            .any(|name| lookup(name).is_some())
        {
            return Err(RelayError::invalid(
                "APASSY_RELAY_MODE=connect sends no push: unset APASSY_RELAY_PUSH_URL, APASSY_RELAY_PUSH_TOPIC, and APASSY_RELAY_PUSH_SECRET (or _FILE).",
            ));
        }
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
            public_listen: None,
            tailnet_listen: None,
            tailnet_agents: false,
            public_url,
            sign_in_origins: Vec::new(),
            edge: EdgeMode::Required(edge_secret),
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
            team_vaults: match lookup("APASSY_RELAY_TEAM_VAULTS").as_deref() {
                // Shared team vaults hold item keys: never in `connect` mode.
                _ if connect.plain_files() => false,
                None | Some("1") => true,
                Some("0") => false,
                Some(_) => {
                    return Err(RelayError::invalid("APASSY_RELAY_TEAM_VAULTS is 0 or 1."));
                }
            },
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
            connect_sync_bytes,
            free_connect,
            auth_limiter: false,
            operator_socket: true,
            oauth: None,
            connect,
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
    Ok(Some(PushConfig::new(url, topic, secret)))
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
        assert_eq!(config.edge.secret().map(SecretString::expose), Some(EDGE));
        assert!(config.public_listen.is_none());
        assert!(!config.auth_limiter);
        assert!(config.operator_socket);
        assert!(config.oauth.is_none());
        config.check_listeners().unwrap();
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
    fn connect_sync_bytes_is_0_or_1_mib_to_64_mib() {
        let with = |value: Option<&str>| {
            let mut pairs = vec![
                ("APASSY_RELAY_PUBLIC_URL", "https://relay.example.test"),
                ("APASSY_RELAY_EDGE_SECRET", EDGE),
                ("APASSY_RELAY_KEY", "a synthetic vault passphrase"),
            ];
            if let Some(value) = value {
                pairs.push(("APASSY_RELAY_CONNECT_SYNC_BYTES", value));
            }
            RelayConfig::from_lookup(lookup(&pairs)).map(|config| config.connect_sync_bytes)
        };
        // Off by default: a new Connect team gets no relay sync.
        assert_eq!(with(None).unwrap(), 0);
        assert_eq!(with(Some("0")).unwrap(), 0);
        assert_eq!(with(Some("1048576")).unwrap(), 1_048_576);
        assert_eq!(with(Some("67108864")).unwrap(), 67_108_864);
        for bad in ["1", "1048575", "67108865", "-1", "64MiB"] {
            assert!(with(Some(bad)).is_err(), "{bad}");
        }
        // Every value that passes makes valid Connect limits.
        for good in ["0", "1048576", "67108864"] {
            crate::server::directory::TeamLimits::connect_with(with(Some(good)).unwrap())
                .validate()
                .unwrap();
        }
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
    fn connect_accounts_per_day_is_0_to_100000_and_max_0_to_10000000() {
        let with = |name: &str, value: &str| {
            RelayConfig::from_lookup(lookup(&[
                ("APASSY_RELAY_PUBLIC_URL", "https://relay.example.test"),
                ("APASSY_RELAY_EDGE_SECRET", EDGE),
                ("APASSY_RELAY_KEY", "a synthetic vault passphrase"),
                (name, value),
            ]))
            .map(|config| (config.connect.accounts_per_day, config.connect.accounts_max))
        };
        let defaults = with("APASSY_RELAY_SESSION_TTL", "900").unwrap();
        assert_eq!(
            defaults,
            (
                DEFAULT_CONNECT_ACCOUNTS_PER_DAY,
                DEFAULT_CONNECT_ACCOUNTS_MAX
            )
        );
        assert_eq!(defaults, (1000, 100_000));
        let per_day = "APASSY_RELAY_CONNECT_ACCOUNTS_PER_DAY";
        assert_eq!(with(per_day, "0").unwrap().0, 0);
        assert_eq!(with(per_day, "100000").unwrap().0, 100_000);
        assert!(with(per_day, "100001").is_err());
        assert!(with(per_day, "-1").is_err());
        assert!(with(per_day, "many").is_err());
        let max = "APASSY_RELAY_CONNECT_ACCOUNTS_MAX";
        assert_eq!(with(max, "0").unwrap().1, 0);
        assert_eq!(with(max, "10000000").unwrap().1, 10_000_000);
        assert!(with(max, "10000001").is_err());
        assert!(with(max, "lots").is_err());
    }

    #[test]
    fn published_keys_come_from_their_file_with_their_own_key_ids() {
        use crate::server::entitlement::key_id;
        let key = |byte: u8| {
            let public = [byte; 32];
            (key_id(&public), crate::hostkeys::encode_b64(&public))
        };
        let (kid_a, key_a) = key(1);
        let (kid_b, key_b) = key(2);
        let file = format!(
            r#"{{"keys":[{{"kid":"{kid_a}","public_key":"{key_a}"}},{{"kid":"{kid_b}","public_key":"{key_b}"}}]}}"#
        );
        let keys = published_keys_from(file.as_bytes()).unwrap();
        assert_eq!(
            keys.iter().map(|k| k.kid.as_str()).collect::<Vec<_>>(),
            [kid_a.as_str(), kid_b.as_str()]
        );
        assert_eq!(keys[1].public_key, [2u8; 32]);
        assert!(published_keys_from(br#"{"keys":[]}"#).unwrap().is_empty());
        for bad in [
            "{}".to_string(),
            "not json".to_string(),
            format!(r#"{{"keys":[{{"kid":"ek_0000000000000000","public_key":"{key_a}"}}]}}"#),
            format!(r#"{{"keys":[{{"kid":"{kid_a}","public_key":"AAAA"}}]}}"#),
            format!(
                r#"{{"keys":[{{"kid":"{kid_a}","public_key":"{key_a}"}},{{"kid":"{kid_a}","public_key":"{key_a}"}}]}}"#
            ),
            format!(r#"{{"keys":[{{"kid":"{kid_a}","public_key":"{key_a}","alg":"Ed25519"}}]}}"#),
        ] {
            assert!(published_keys_from(bad.as_bytes()).is_err(), "{bad}");
        }
        // From the environment: the file is read once at start.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("published.json");
        std::fs::write(&path, &file).unwrap();
        let config = RelayConfig::from_lookup(lookup(&[
            ("APASSY_RELAY_PUBLIC_URL", "https://relay.example.test"),
            ("APASSY_RELAY_EDGE_SECRET", EDGE),
            ("APASSY_RELAY_KEY", "a synthetic vault passphrase"),
            ("APASSY_CONNECT_PUBLISHED_KEYS_FILE", path.to_str().unwrap()),
        ]))
        .unwrap();
        assert_eq!(config.connect.published_keys, keys);
        assert!(
            RelayConfig::from_lookup(lookup(&[
                ("APASSY_RELAY_PUBLIC_URL", "https://relay.example.test"),
                ("APASSY_RELAY_EDGE_SECRET", EDGE),
                ("APASSY_RELAY_KEY", "a synthetic vault passphrase"),
                (
                    "APASSY_CONNECT_PUBLISHED_KEYS_FILE",
                    dir.path().join("missing.json").to_str().unwrap()
                ),
            ]))
            .is_err()
        );
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
        assert!(with(&[]).unwrap().team_vaults);
        let vaults = |value: &'static str| {
            with(&[("APASSY_RELAY_TEAM_VAULTS", value)]).map(|config| config.team_vaults)
        };
        assert!(!vaults("0").unwrap());
        assert!(vaults("1").unwrap());
        assert!(vaults("off").is_err());
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
        let PushConfig::Worker {
            url: push_url,
            topic: push_topic,
            secret: push_secret,
            ..
        } = &push
        else {
            panic!("the environment makes the Worker form");
        };
        assert_eq!(push_url, "https://relay.example.test/internal/push");
        assert_eq!(push_topic, "com.wydrox.apassy.companion");
        assert_eq!(push_secret.expose(), secret.1);
        assert_eq!(push.topic(), Some("com.wydrox.apassy.companion"));
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

    fn embedded_options(public_listen: Option<&str>) -> EmbeddedOptions {
        EmbeddedOptions {
            data_dir: PathBuf::from("/tmp/node"),
            master_key: SecretString::new("a synthetic node master key".into()),
            public_url: "https://mac.example.ts.net:8443/".into(),
            public_listen: public_listen.map(|addr| addr.parse().unwrap()),
            node_origin: None,
            tailnet_listen: None,
            tailnet_agents: false,
            push_gateway: None,
        }
    }

    fn tailnet_options() -> EmbeddedOptions {
        EmbeddedOptions {
            node_origin: Some("https://100.64.0.7:8444".into()),
            tailnet_listen: Some("127.0.0.1:0".parse().unwrap()),
            push_gateway: Some(DEFAULT_PUSH_GATEWAY.into()),
            ..embedded_options(Some("127.0.0.1:49200"))
        }
    }

    #[test]
    fn a_node_on_the_tailnet_has_a_third_listener_two_origins_and_gateway_push() {
        let config = RelayConfig::embedded(tailnet_options()).unwrap();
        assert!(config.is_node());
        assert_eq!(config.tailnet_listen, Some("127.0.0.1:0".parse().unwrap()));
        assert!(!config.tailnet_agents);
        assert_eq!(
            config.sign_in_origins(),
            ["https://100.64.0.7:8444", "https://mac.example.ts.net:8443"]
        );
        let Some(PushConfig::Gateway {
            gateways, timeout, ..
        }) = &config.push
        else {
            panic!("a node pushes through the gateway");
        };
        assert_eq!(gateways, &[DEFAULT_PUSH_GATEWAY.to_string()]);
        assert_eq!(*timeout, Duration::from_secs(10));
        assert_eq!(config.push.as_ref().unwrap().topic(), None);
        config.check_listeners().unwrap();
        // Without the public route, the node origin alone; without a gateway, no push.
        let config = RelayConfig::embedded(EmbeddedOptions {
            public_listen: None,
            push_gateway: None,
            tailnet_agents: true,
            ..tailnet_options()
        })
        .unwrap();
        assert_eq!(config.sign_in_origins(), ["https://100.64.0.7:8444"]);
        assert!(config.push.is_none());
        assert!(config.tailnet_agents);
        // The hosted relay and a node without the tailnet: `public_url` alone.
        let config = RelayConfig::embedded(embedded_options(None)).unwrap();
        assert!(!config.is_node());
        assert_eq!(
            config.sign_in_origins(),
            ["https://mac.example.ts.net:8443"]
        );
        let hosted = RelayConfig::from_lookup(lookup(&[
            ("APASSY_RELAY_PUBLIC_URL", "https://relay.example.test"),
            ("APASSY_RELAY_EDGE_SECRET", EDGE),
            ("APASSY_RELAY_KEY", "a synthetic vault passphrase"),
        ]))
        .unwrap();
        assert_eq!(hosted.sign_in_origins(), ["https://relay.example.test"]);
        assert!(hosted.tailnet_listen.is_none() && !hosted.is_node());
    }

    #[test]
    fn the_tailnet_options_are_checked() {
        let refused = |options: EmbeddedOptions| {
            RelayConfig::embedded(options).unwrap_err().code == crate::error::codes::INVALID_REQUEST
        };
        // The origin and the listener go together; the team routes and push need them.
        assert!(refused(EmbeddedOptions {
            tailnet_listen: None,
            ..tailnet_options()
        }));
        assert!(refused(EmbeddedOptions {
            node_origin: None,
            push_gateway: None,
            ..tailnet_options()
        }));
        assert!(refused(EmbeddedOptions {
            push_gateway: Some(DEFAULT_PUSH_GATEWAY.into()),
            ..embedded_options(None)
        }));
        assert!(refused(EmbeddedOptions {
            tailnet_agents: true,
            ..embedded_options(None)
        }));
        // The tailnet listener is on the loopback.
        for listen in ["0.0.0.0:8444", "100.64.0.7:8444", "[::]:8444"] {
            assert!(
                refused(EmbeddedOptions {
                    tailnet_listen: Some(listen.parse().unwrap()),
                    ..tailnet_options()
                }),
                "{listen}"
            );
        }
        // The node origin of node-pairing-v1 section 3.
        for origin in [
            "http://100.64.0.7:8444",
            "https://100.64.0.7",
            "https://100.64.0.7:443",
            "https://100.64.0.7:8444/",
            "https://100.64.0.7:08444",
            "https://100.64.0.7:70000",
            "https://Mac.example:8444",
            "https://user@100.64.0.7:8444",
        ] {
            assert!(checked_node_origin(origin).is_err(), "{origin}");
        }
        assert_eq!(
            checked_node_origin("https://100.64.0.7:8444").unwrap(),
            "https://100.64.0.7:8444"
        );
        assert!(checked_node_origin("https://apassy-mini.tail0123.ts.net:8444").is_ok());
        // A gateway is an origin.
        for gateway in [
            "https://push.apassy.wyderka.cc",
            "https://push.example.com:8443",
            "http://127.0.0.1:9",
        ] {
            assert_eq!(checked_gateway(gateway).unwrap(), gateway);
        }
        for gateway in [
            "https://push.example.com/",
            "https://push.example.com/v1/push",
            "http://push.example.com",
            "https://Push.example.com",
            "https://push.example.com:",
            "https://push.example.com:0443",
            "https://user@push.example.com",
            "https://push.example.com?x",
            "ftp://push.example.com",
            "https://",
        ] {
            assert!(checked_gateway(gateway).is_err(), "{gateway}");
        }
        assert!(PushConfig::gateway(Vec::new()).is_err());
    }

    #[test]
    fn an_embedded_node_has_no_edge_and_listens_on_the_loopback() {
        let config = RelayConfig::embedded(embedded_options(Some("127.0.0.1:49200"))).unwrap();
        assert!(config.edge.secret().is_none());
        assert_eq!(config.listen.to_string(), "127.0.0.1:0");
        assert_eq!(config.public_url, "https://mac.example.ts.net:8443");
        assert_eq!(config.session_ttl_secs, 600);
        assert_eq!(config.approval_timeout_secs, 300);
        assert!(config.push.is_none());
        assert!(config.team_vaults);
        assert_eq!(
            (config.connect_teams_per_day, config.connect_teams_max),
            (0, 0)
        );
        assert!(config.auth_limiter);
        // No operator socket: the agents of the Mac run as its user (review 0.5.16).
        assert!(!config.operator_socket);
        let oauth = config.oauth.as_ref().expect("an embedded node has OAuth");
        assert_eq!(oauth.mac_name, EMBEDDED_MAC_NAME);
        // The public page never names the computer (security review finding 5), only
        // the platform word of the machine the relay runs on.
        assert_eq!(
            EMBEDDED_MAC_NAME,
            if cfg!(target_os = "linux") {
                "your computer"
            } else {
                "your Mac"
            }
        );
        assert_eq!(oauth.access_token_secs, 86_400);
        assert_eq!(oauth.refresh_token_secs, 90 * 86_400);
        assert_eq!((oauth.connect_secs, oauth.code_secs), (300, 300));
        assert_eq!(
            config.admin_socket_path(),
            PathBuf::from("/tmp/node/admin.sock")
        );
        assert!(RelayConfig::embedded(embedded_options(None)).is_ok());
        assert!(RelayConfig::embedded(embedded_options(Some("[::1]:49200"))).is_ok());
    }

    #[test]
    fn edge_off_with_a_listener_off_the_loopback_is_refused() {
        for public in ["0.0.0.0:49200", "192.0.2.7:49200", "[::]:49200"] {
            let error = RelayConfig::embedded(embedded_options(Some(public))).unwrap_err();
            assert_eq!(error.code, crate::error::codes::INVALID_REQUEST, "{public}");
        }
        let mut config = RelayConfig::embedded(embedded_options(None)).unwrap();
        config.listen = "0.0.0.0:8080".parse().unwrap();
        assert!(config.check_listeners().is_err());
        // The same listener is fine with the edge secret.
        config.edge = EdgeMode::Required(SecretString::new(EDGE.into()));
        config.public_listen = Some("0.0.0.0:8443".parse().unwrap());
        config.check_listeners().unwrap();
        let short = RelayConfig::embedded(EmbeddedOptions {
            master_key: SecretString::new("short".into()),
            ..embedded_options(None)
        });
        assert!(short.is_err());
    }
    #[test]
    fn the_tunnel_keys_have_the_contract_defaults_and_bounds() {
        let base = [
            ("APASSY_RELAY_PUBLIC_URL", "https://relay.example.test"),
            ("APASSY_RELAY_EDGE_SECRET", EDGE),
            ("APASSY_RELAY_KEY", "a synthetic vault passphrase"),
        ];
        let with = |extra: &[(&str, &str)]| {
            let mut pairs = base.to_vec();
            pairs.extend_from_slice(extra);
            RelayConfig::from_lookup(lookup(&pairs)).map(|config| config.connect.tunnel)
        };
        let none = with(&[]).unwrap();
        assert_eq!(none, TunnelSettings::default());
        assert_eq!(none.ingress_listen, None);
        assert_eq!(none.acme_listen, None);
        assert_eq!(none.node_zone, "node.apassy.wyderka.cc");
        assert_eq!(
            (
                none.streams_per_account,
                none.nodes_per_account,
                none.dials_per_minute
            ),
            (64, 8, 60)
        );
        assert_eq!(none.bytes_per_month, 20 * 1024 * 1024 * 1024);
        assert_eq!(none.stream_buffer, 256 * 1024);
        let set = with(&[
            ("APASSY_CONNECT_INGRESS_LISTEN", "0.0.0.0:443"),
            ("APASSY_CONNECT_ACME_LISTEN", "[::]:80"),
            ("APASSY_CONNECT_NODE_ZONE", "Node.Example.TEST."),
            ("APASSY_CONNECT_TUNNEL_STREAMS", "16"),
            ("APASSY_CONNECT_TUNNEL_NODES", "2"),
            ("APASSY_CONNECT_TUNNEL_DIALS_PER_MINUTE", "5"),
            ("APASSY_CONNECT_TUNNEL_GIB_PER_MONTH", "1"),
            ("APASSY_CONNECT_TUNNEL_PING_SECS", "10"),
            ("APASSY_CONNECT_TUNNEL_IDLE_SECS", "40"),
            ("APASSY_CONNECT_TUNNEL_STREAM_IDLE_SECS", "120"),
            ("APASSY_CONNECT_TUNNEL_STREAM_BUFFER_KIB", "64"),
        ])
        .unwrap();
        assert_eq!(set.ingress_listen, Some("0.0.0.0:443".parse().unwrap()));
        assert_eq!(set.acme_listen, Some("[::]:80".parse().unwrap()));
        assert_eq!(set.node_zone, "node.example.test");
        assert_eq!(
            (
                set.streams_per_account,
                set.nodes_per_account,
                set.dials_per_minute
            ),
            (16, 2, 5)
        );
        assert_eq!(set.bytes_per_month, 1024 * 1024 * 1024);
        assert_eq!(set.ping_interval, Duration::from_secs(10));
        assert_eq!(set.idle_timeout, Duration::from_secs(40));
        assert_eq!(set.stream_idle, Duration::from_secs(120));
        assert_eq!(set.stream_buffer, 64 * 1024);
        for bad in [
            ("APASSY_CONNECT_INGRESS_LISTEN", "443"),
            ("APASSY_CONNECT_ACME_LISTEN", "localhost:80"),
            ("APASSY_CONNECT_NODE_ZONE", "localhost"),
            ("APASSY_CONNECT_NODE_ZONE", "-bad.example.com"),
            ("APASSY_CONNECT_NODE_ZONE", "under_score.example.com"),
            ("APASSY_CONNECT_NODE_ZONE", "a..example.com"),
            ("APASSY_CONNECT_TUNNEL_STREAMS", "0"),
            ("APASSY_CONNECT_TUNNEL_STREAMS", "4097"),
            ("APASSY_CONNECT_TUNNEL_NODES", "65"),
            ("APASSY_CONNECT_TUNNEL_DIALS_PER_MINUTE", "0"),
            ("APASSY_CONNECT_TUNNEL_GIB_PER_MONTH", "0"),
            ("APASSY_CONNECT_TUNNEL_PING_SECS", "4"),
            ("APASSY_CONNECT_TUNNEL_IDLE_SECS", "30"),
            ("APASSY_CONNECT_TUNNEL_STREAM_IDLE_SECS", "59"),
            ("APASSY_CONNECT_TUNNEL_STREAM_BUFFER_KIB", "16385"),
        ] {
            assert!(with(&[bad]).is_err(), "{bad:?}");
        }
        let label = "a".repeat(63);
        let long = format!("{label}.{label}.{label}.{label}.example.com");
        assert!(with(&[("APASSY_CONNECT_NODE_ZONE", long.as_str())]).is_err());
    }
}
