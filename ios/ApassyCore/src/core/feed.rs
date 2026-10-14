//! The agent feeds of the Macs on the iPhone (contract relay-feed-v1; contract ios-core-v1
//! section 5.12).
//!
//! Each Mac publishes a sealed feed of the agents of a vault through the questions team of
//! that vault. The iPhone reads the feeds of every vault that has a questions context
//! (`questions.rs`), opens each with the question key of that vault, checks it (section
//! 7.4), and shows the agents. It sends one kind of action back: remove an exception of an
//! agent. An action that gives authority back (`never`, `always_ask`) is signed in Swift
//! by the Secure Enclave answer key after Face ID; the core builds the exact string first
//! (`feed_action_string`) and checks the signature before it posts. The removal of an
//! "only these items" row takes authority away: the core signs it with the relay key of
//! the membership.
//!
//! What a feed shows lives in the questions context of its vault, so a `lock`, a
//! `suspend`, and `remove_vault` drop it with the context. The highest `seq` accepted
//! of each Mac (section 8) is kept on disk in [`MARKS_FILE`], with no secret: a relay
//! cannot bring back an older feed, also after a restart.
//!
//! The relay calls run without the vault mutex. A lock ends them ([`Core::close`]).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use apassy::sync::{
    Cancel, RelayCallError, RelayMember, SyncError, decode_b64u, encode_b64u, verify_signature,
};
use apassy::vault::{TrustedDevice, TrustedDeviceKind, Vault};

use super::config::write_private;
use super::errors::{CoreError, CoreResult};
use super::questions::envelope;
use super::questions::{Keys, Selected, State, not_open};
use super::wire::{ok, params};
use super::{Core, Role, guard, now};

/// The tag of every AAD (section 6.1).
const AAD_TAG: &str = "apassy-feed-v1";
/// The tag of the action string (section 9.3).
const ACTION_TAG: &str = "apassy-feed-action-v1";
/// The largest plaintexts and the largest feed ciphertext (section 6.3).
const MAX_FEED_BYTES: usize = 262_128;
const MAX_FEED_CIPHERTEXT: usize = 262_144;
const MAX_ACTION_BYTES: usize = 4_096;
const MAX_SETTLE_BYTES: usize = 1_024;
/// The largest `seq` (section 4).
const MAX_SEQ: u64 = (1 << 53) - 1;
/// A feed older than this on the iPhone's clock is stale (section 8).
const STALE_SECONDS: u64 = 24 * 60 * 60;
/// A retry of an action keeps its signature while its time is younger than this
/// (section 10.6).
const ACTION_RETRY_SECONDS: u64 = 55;
/// The target refuses a `time` more than this ahead (section 9.4).
const ACTION_WINDOW_SECONDS: u64 = 60;
/// A list call reads at most this many answers of `GET /v1/feed`.
const MAX_PAGES: usize = 16;
/// The actions of this process that a context remembers for `feed_action_wait`.
const KEEP_ACTIONS: usize = 64;
/// The Face ID prompt shows at most this many characters of the agent name (section 9.4).
const PROMPT_NAME_CHARS: usize = 40;
/// The highest `seq` of each Mac, by team and relay device id: no secret.
const MARKS_FILE: &str = "feed-seq.json";

/// The limits of the plaintext of a feed (section 7.1).
const MAX_AGENTS: usize = 64;
const MAX_PROJECTS: usize = 16;
const MAX_ACTIONS: usize = 4;
const MAX_EXCEPTIONS: usize = 256;
const MAX_RECENT: usize = 20;

// ---- The state. ----

/// The feeds of one questions team, kept in the context of its vault.
#[derive(Default)]
pub(super) struct Mirror {
    /// The last `change` of the team's feeds seen (section 10.4).
    since: u64,
    /// The last good feed of each Mac, by relay device id.
    shown: BTreeMap<u64, Arc<Feed>>,
    /// The text of the failed step of the last feed of a Mac (section 7.4, steps 1 to 3).
    problems: BTreeMap<u64, Problem>,
    /// The titles of the items of the vault on this iPhone, by item UUID (32 lowercase hex
    /// characters), from its last unlock in this session. None: not read yet.
    pub(super) titles: Option<BTreeMap<String, String>>,
    /// The actions that this process posted, by `action_id`.
    actions: BTreeMap<String, Posted>,
    /// The exceptions that an applied action removed, hidden until the next feed of their
    /// Mac (section 9.6: "The row leaves the list at once").
    hidden: Vec<Target>,
    /// The code of the last failed relay call, until one works.
    error: Option<&'static str>,
}

/// The highest feed `seq` accepted of each Mac, by team ID and relay device id (section 8).
#[derive(Default, Serialize, Deserialize)]
pub(super) struct Marks {
    teams: BTreeMap<String, BTreeMap<u64, u64>>,
}

#[derive(Serialize, Deserialize)]
struct MarksFile {
    version: u32,
    teams: BTreeMap<String, BTreeMap<u64, u64>>,
}

impl Marks {
    /// The marks of [`MARKS_FILE`]; a missing or damaged file is no mark.
    pub(super) fn load(data_dir: &Path) -> Self {
        let teams = std::fs::read(data_dir.join(MARKS_FILE))
            .ok()
            .and_then(|text| serde_json::from_slice::<MarksFile>(&text).ok())
            .filter(|file| file.version == 1)
            .map(|file| {
                file.teams
                    .into_iter()
                    .filter(|(team, _)| !team.is_empty() && team.len() <= 64)
                    .collect()
            })
            .unwrap_or_default();
        Self { teams }
    }

    fn get(&self, team: &str, device_id: u64) -> u64 {
        self.teams
            .get(team)
            .and_then(|devices| devices.get(&device_id))
            .copied()
            .unwrap_or(0)
    }

    /// Raise the mark of `device_id` to `seq`. Returns whether it rose.
    fn raise(&mut self, team: &str, device_id: u64, seq: u64) -> bool {
        let mark = self
            .teams
            .entry(team.to_owned())
            .or_default()
            .entry(device_id)
            .or_insert(0);
        if seq > *mark {
            *mark = seq;
            true
        } else {
            false
        }
    }
}

/// Why the last feed of a Mac is not on the screen (section 7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Problem {
    /// Step 1: the envelope does not open (another key, or a damaged one).
    Sync,
    /// Steps 2 and 3: the plaintext is not of this version.
    Update,
}

impl Problem {
    fn text(self, mac: &str) -> String {
        match self {
            Self::Sync => format!("Sync this vault to see the agents of {mac}."),
            Self::Update => format!("Update Apassy to see the agents of {mac}."),
        }
    }
}

/// An action that this process posted.
struct Posted {
    to_device: u64,
    target: Target,
}

/// The exception that an action removes, on the feed that showed it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    device_id: u64,
    feed_seq: u64,
    agent: String,
    item: String,
    kind: String,
    created_at: u64,
}

// ---- The feed plaintext (section 7.1). ----

/// A value that must be present and may be null.
fn required<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Feed {
    v: u64,
    mac: FeedMac,
    seq: u64,
    generated_at: u64,
    truncated: bool,
    week: Week,
    agents: Vec<Agent>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FeedMac {
    device: String,
    name: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Week {
    by_you: u32,
    automatic: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Agent {
    id: String,
    name: String,
    host: String,
    #[serde(rename = "where")]
    place: String,
    revoked: bool,
    token_expires_at: u64,
    #[serde(deserialize_with = "required")]
    last_use_at: Option<u64>,
    uses_this_week: u32,
    projects: Vec<String>,
    note: String,
    restricted: bool,
    actions: Vec<ActionUse>,
    exceptions: Vec<Exception>,
    recent: Vec<Recent>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionUse {
    action: String,
    allowed: u64,
    not_allowed: u64,
    projects: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Exception {
    #[serde(deserialize_with = "required")]
    item: Option<String>,
    item_title: String,
    kind: String,
    created_at: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recent {
    at: u64,
    #[serde(deserialize_with = "required")]
    item: Option<String>,
    item_title: String,
    action: String,
    project: String,
    command: String,
    outcome: String,
    decided_by: String,
    answered_on: String,
}

fn bytes_within(text: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&text.len())
}

fn valid_projects(projects: &[String]) -> bool {
    projects.len() <= MAX_PROJECTS && projects.iter().all(|p| bytes_within(p, 1, 256))
}

fn valid_action_kind(action: &str) -> bool {
    matches!(action, "read" | "change" | "deploy" | "delete")
}

fn valid_exception_kind(kind: &str) -> bool {
    matches!(kind, "never" | "always_ask" | "only")
}

/// An agent id: decimal text without a leading zero, at most 20 characters.
fn valid_agent_id(id: &str) -> bool {
    bytes_within(id, 1, 20)
        && id.bytes().all(|b| b.is_ascii_digit())
        && (id == "0" || !id.starts_with('0'))
}

/// An item reference: the contract's 36 characters `8-4-4-4-12`, or the 32 lowercase hex
/// characters that `item.uuid` holds in the vault.
fn valid_item(item: &str) -> bool {
    envelope::valid_device_uuid(item)
        || (item.len() == 32 && item.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// The form of an item UUID that the vault stores: without hyphens.
fn plain_uuid(item: &str) -> String {
    item.chars().filter(|c| *c != '-').collect()
}

impl Exception {
    fn is_valid(&self) -> bool {
        self.item.as_deref().is_none_or(valid_item)
            && self.item_title.len() <= 128
            && valid_exception_kind(&self.kind)
    }
}

impl Recent {
    fn is_valid(&self) -> bool {
        self.item.as_deref().is_none_or(valid_item)
            && self.item_title.len() <= 128
            && valid_action_kind(&self.action)
            && self.project.len() <= 256
            && self.command.len() <= 256
            && matches!(
                self.outcome.as_str(),
                "allowed" | "denied" | "refused" | "timed_out"
            )
            && matches!(
                self.decided_by.as_str(),
                "bouncer" | "pattern" | "answer" | "owner" | "rule"
            )
            && self.answered_on.len() <= 64
    }
}

impl Agent {
    fn is_valid(&self) -> bool {
        let mut seen = BTreeSet::new();
        valid_agent_id(&self.id)
            && bytes_within(&self.name, 1, 64)
            && matches!(self.host.as_str(), "claude" | "codex" | "t3" | "other")
            && self.place == "mac"
            && valid_projects(&self.projects)
            && self.note.len() <= 500
            && self.actions.len() <= MAX_ACTIONS
            && self.actions.iter().all(|use_| {
                valid_action_kind(&use_.action)
                    && valid_projects(&use_.projects)
                    && seen.insert(use_.action.clone())
            })
            && self.exceptions.len() <= MAX_EXCEPTIONS
            && self.exceptions.iter().all(Exception::is_valid)
            && self.recent.len() <= MAX_RECENT
            && self.recent.iter().all(Recent::is_valid)
    }
}

impl Feed {
    fn is_valid(&self) -> bool {
        let mut ids = BTreeSet::new();
        self.v == 1
            && envelope::valid_device_uuid(&self.mac.device)
            && bytes_within(&self.mac.name, 1, 64)
            && (1..=MAX_SEQ).contains(&self.seq)
            && self.agents.len() <= MAX_AGENTS
            && self
                .agents
                .iter()
                .all(|agent| agent.is_valid() && ids.insert(agent.id.as_str()))
    }
}

/// The feed of `plaintext` when it has exactly the fields of section 7.1 within their
/// limits (section 7.4, step 2).
fn parse_feed(plaintext: &[u8]) -> Option<Feed> {
    if plaintext.len() > MAX_FEED_BYTES {
        return None;
    }
    serde_json::from_slice::<Feed>(plaintext)
        .ok()
        .filter(Feed::is_valid)
}

// ---- The envelopes (section 6). ----

fn aad(parts: &[&str]) -> Vec<u8> {
    parts.join("\0").into_bytes()
}

fn feed_aad(team: &str, device_id: u64, seq: u64, key_id: &str) -> Vec<u8> {
    aad(&[
        AAD_TAG,
        "feed",
        team,
        &device_id.to_string(),
        &seq.to_string(),
        key_id,
    ])
}

fn action_aad(team: &str, action_id: &str, key_id: &str, from: u64, to: u64) -> Vec<u8> {
    aad(&[
        AAD_TAG,
        "action",
        team,
        action_id,
        key_id,
        &from.to_string(),
        &to.to_string(),
    ])
}

fn settle_aad(team: &str, action_id: &str, key_id: &str, outcome: &str) -> Vec<u8> {
    aad(&[AAD_TAG, "settle", team, action_id, key_id, outcome])
}

/// An `action_id`: 22 characters of b64u that decode to 16 bytes.
fn valid_action_id(action_id: &str) -> bool {
    action_id.len() == 22 && decode_b64u(action_id).is_some_and(|bytes| bytes.len() == 16)
}

/// The action string of section 9.3: eight lines, no newline at the end.
fn action_string(
    by: &str,
    to: &str,
    team: &str,
    action_id: &str,
    target: &Target,
    time: u64,
) -> String {
    [
        ACTION_TAG,
        by,
        to,
        team,
        action_id,
        &format!(
            "remove_exception:{}:{}:{}:{}",
            target.agent, target.item, target.kind, target.created_at
        ),
        &target.feed_seq.to_string(),
        &time.to_string(),
    ]
    .join("\n")
}

/// The plaintext of an action (section 9.2), its fields in the contract's order.
#[derive(Serialize)]
struct ActionPlain<'a> {
    v: u8,
    action_id: &'a str,
    by: &'a str,
    to: &'a str,
    kind: &'static str,
    agent: &'a str,
    item: &'a str,
    exception: ExceptionRef<'a>,
    feed_seq: u64,
    time: u64,
    signature: &'a str,
}

#[derive(Serialize)]
struct ExceptionRef<'a> {
    kind: &'a str,
    created_at: u64,
}

fn action_plaintext(
    action_id: &str,
    by: &str,
    to: &str,
    target: &Target,
    time: u64,
    signature: &str,
) -> Vec<u8> {
    serde_json::to_vec(&ActionPlain {
        v: 1,
        action_id,
        by,
        to,
        kind: "remove_exception",
        agent: &target.agent,
        item: &target.item,
        exception: ExceptionRef {
            kind: &target.kind,
            created_at: target.created_at,
        },
        feed_seq: target.feed_seq,
        time,
        signature,
    })
    .unwrap_or_default()
}

/// The plaintext of a settle (section 9.6).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settle {
    v: u64,
    action_id: String,
    outcome: String,
    reason: String,
    #[serde(deserialize_with = "required")]
    feed_seq: Option<u64>,
    at: u64,
}

fn parse_settle(plaintext: &[u8], action_id: &str, outcome: &str) -> Option<Settle> {
    if plaintext.len() > MAX_SETTLE_BYTES {
        return None;
    }
    serde_json::from_slice::<Settle>(plaintext)
        .ok()
        .filter(|settle| {
            settle.v == 1
                && settle.action_id == action_id
                && settle.outcome == outcome
                && settle.reason.len() <= 200
        })
}

/// The prompt reason of Face ID for an action on the agent `name` (section 9.4).
fn face_id_reason(name: &str) -> String {
    let name: String = name
        .chars()
        .filter(|c| !c.is_control() && *c != '"')
        .take(PROMPT_NAME_CHARS)
        .collect();
    format!("remove an exception of agent \"{name}\"")
}

// ---- The relay records (section 10). ----

#[derive(Debug, Clone, Deserialize)]
struct Record {
    device_id: u64,
    seq: u64,
    change: u64,
    key_id: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct FeedAnswer {
    change: u64,
    #[serde(default)]
    more: bool,
    present: Vec<u64>,
    #[serde(default)]
    feeds: Vec<Record>,
}

#[derive(Deserialize)]
struct SealedWire {
    key_id: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct ActionState {
    action_id: String,
    to_device: u64,
    state: String,
    expires_at: u64,
    #[serde(default)]
    outcome: Option<String>,
    #[serde(default)]
    settle: Option<SealedWire>,
}

#[derive(Deserialize)]
struct PostedWire {
    seq: u64,
    created_at: u64,
    expires_at: u64,
}

/// What a record of `GET /v1/feed` gives after the checks of section 7.4 that need no
/// state (steps 1 to 3).
enum Read {
    Good(Arc<Feed>),
    Problem(Problem),
    /// Not of the forms of the relay: no text.
    Ignore,
}

impl Keys {
    /// Open and check the feed of `record` (section 7.4, steps 1 to 3).
    fn read_feed(&self, record: &Record) -> Read {
        if !(1..=MAX_SEQ).contains(&record.seq) || !envelope::valid_key_id(&record.key_id) {
            return Read::Ignore;
        }
        let Some((key_id, key)) = &self.key else {
            return Read::Problem(Problem::Sync);
        };
        if *key_id != record.key_id {
            return Read::Problem(Problem::Sync);
        }
        let (Some(nonce), Some(ciphertext)) =
            (decode_b64u(&record.nonce), decode_b64u(&record.ciphertext))
        else {
            return Read::Problem(Problem::Sync);
        };
        if ciphertext.len() > MAX_FEED_CIPHERTEXT {
            return Read::Problem(Problem::Sync);
        }
        let aad = feed_aad(&self.team_id, record.device_id, record.seq, key_id);
        let Some(plaintext) = envelope::open(key, &nonce, &aad, &ciphertext) else {
            return Read::Problem(Problem::Sync);
        };
        match parse_feed(&plaintext) {
            Some(feed) if feed.seq == record.seq => Read::Good(Arc::new(feed)),
            _ => Read::Problem(Problem::Update),
        }
    }

    /// The publisher of a feed of the relay device `device_id` that names `uuid`: a live
    /// trusted Mac of this vault whose device number in this team, when set, is
    /// `device_id` (section 7.4, step 4).
    fn publisher(&self, uuid: &str, device_id: u64) -> Option<&TrustedDevice> {
        self.devices.iter().find(|device| {
            device.kind == TrustedDeviceKind::Mac
                && device.uuid == uuid
                && device
                    .relay_devices
                    .get(&self.team_id)
                    .is_none_or(|id| *id == device_id)
        })
    }

    /// The live trusted Mac with the device number `device_id` in this team.
    fn mac_of(&self, device_id: u64) -> Option<&TrustedDevice> {
        self.devices.iter().find(|device| {
            device.kind == TrustedDeviceKind::Mac
                && device.relay_devices.get(&self.team_id) == Some(&device_id)
        })
    }
}

fn is_stale(generated_at: u64, at: u64) -> bool {
    generated_at.saturating_add(STALE_SECONDS) < at
}

// ---- Answers of the calls. ----

#[derive(Serialize)]
struct ListOut {
    vaults: Vec<VaultOut>,
}

#[derive(Serialize)]
struct VaultOut {
    vault_id: String,
    vault_name: String,
    team_id: String,
    /// The vault holds the row of this iPhone: it can send actions.
    registered: bool,
    /// The row of this iPhone has an answer key: it can send the Face ID actions.
    answer_key: bool,
    /// The code of the last failed relay call of this vault, until one works.
    error: Option<&'static str>,
    macs: Vec<MacOut>,
}

#[derive(Serialize)]
struct MacOut {
    /// The `trusted_device` UUID of the Mac.
    device: String,
    relay_device_id: u64,
    /// The name of its `trusted_device` row.
    name: String,
    /// Null when no feed of this Mac opened in this session (then `problem` says why).
    seq: Option<u64>,
    generated_at: Option<u64>,
    stale: bool,
    truncated: bool,
    /// The text of section 7.4 when the last feed of this Mac could not be shown.
    problem: Option<String>,
    week: Option<Week>,
    agents: Vec<AgentOut>,
}

#[derive(Serialize)]
struct AgentOut {
    id: String,
    name: String,
    host: String,
    #[serde(rename = "where")]
    place: String,
    revoked: bool,
    token_expires_at: u64,
    last_use_at: Option<u64>,
    uses_this_week: u32,
    projects: Vec<String>,
    note: String,
    restricted: bool,
    actions: Vec<ActionUseOut>,
    exceptions: Vec<ExceptionOut>,
    recent: Vec<RecentOut>,
}

#[derive(Serialize)]
struct ActionUseOut {
    action: String,
    allowed: u64,
    not_allowed: u64,
    projects: Vec<String>,
}

#[derive(Serialize)]
struct ExceptionOut {
    item: Option<String>,
    item_title: String,
    /// The title of the item in the vault on this iPhone.
    title: Option<String>,
    /// Whether the vault on this iPhone holds the item; null when its items are not known
    /// in this session.
    here: Option<bool>,
    kind: String,
    created_at: u64,
}

#[derive(Serialize)]
struct RecentOut {
    at: u64,
    item: Option<String>,
    item_title: String,
    title: Option<String>,
    here: Option<bool>,
    action: String,
    project: String,
    command: String,
    outcome: String,
    decided_by: String,
    answered_on: String,
}

#[derive(Serialize)]
struct Waited {
    changed: bool,
}

#[derive(Serialize)]
struct Prepared {
    vault_id: String,
    team_id: String,
    action_id: String,
    time: u64,
    feed_seq: u64,
    action_string: String,
    needs_face_id: bool,
    /// The reason of the Face ID prompt.
    face_id_reason: String,
}

#[derive(Serialize)]
struct SentOut {
    action_id: String,
    /// Null when the relay had the action already (a retry).
    seq: Option<u64>,
    created_at: Option<u64>,
    expires_at: Option<u64>,
}

#[derive(Serialize)]
struct OutcomeOut {
    action_id: String,
    /// `pending`, `applied`, `refused`, `stale`, or `expired`.
    outcome: String,
    /// The settle opened with the question key and names this outcome.
    verified: bool,
    reason: Option<String>,
    feed_seq: Option<u64>,
    at: Option<u64>,
}

// ---- Requests. ----

#[derive(Deserialize)]
struct ActionIn {
    vault_id: String,
    mac_device: String,
    agent: String,
    item: String,
    kind: String,
    created_at: u64,
    #[serde(default)]
    action_id: Option<String>,
    #[serde(default)]
    time: Option<u64>,
    /// b64u DER, by the answer key (Swift, after Face ID).
    #[serde(default)]
    signature: Option<String>,
}

// ---- Errors. ----

fn feed_unavailable() -> CoreError {
    CoreError::new(
        "feed_unavailable",
        "The relay does not show agents on the iPhone yet. The agents stay on the Mac.",
    )
}

fn list_gone() -> CoreError {
    CoreError::new(
        "not_found",
        "This list of the Mac changed. Look at it again.",
    )
}

/// The error of a relay call of the feed for the owner.
fn call_error(error: RelayCallError) -> CoreError {
    match error {
        RelayCallError::Unreachable => SyncError::RelayUnreachable.into(),
        RelayCallError::Sync(error) => error.into(),
        RelayCallError::Relay { status, code } => match (status, code.as_str()) {
            (403, "not_routed") => CoreError::new(
                "not_routed",
                "This Mac does not take actions from this iPhone.",
            ),
            (403, "too_many_actions") => CoreError::new(
                "too_many_actions",
                "Too many actions in a short time. Try again later.",
            ),
            (404, _) => feed_unavailable(),
            (401, _) => SyncError::RemovedFromRelay.into(),
            (413, _) => CoreError::new("too_large", "The action is too large for the relay."),
            (429, _) => CoreError::new(
                "rate_limited",
                "The relay asks Apassy to wait. Try again later.",
            ),
            (500..=599, _) => SyncError::RelayUnreachable.into(),
            _ => CoreError::internal("The relay refused the request."),
        },
    }
}

/// The titles of the items of `vault` by item UUID (without hyphens).
pub(super) fn item_titles(vault: &Vault) -> CoreResult<BTreeMap<String, String>> {
    let titles: BTreeMap<u64, String> = vault
        .search("")?
        .into_iter()
        .map(|summary| (summary.id, summary.title))
        .collect();
    Ok(vault
        .item_uuids()?
        .into_iter()
        .filter_map(|(id, uuid)| Some((plain_uuid(&uuid), titles.get(&id)?.clone())))
        .collect())
}

/// The title of `item` in the vault on this iPhone, and whether the vault holds it.
fn local(
    titles: Option<&BTreeMap<String, String>>,
    item: Option<&str>,
) -> (Option<String>, Option<bool>) {
    match (titles, item) {
        (_, None) => (None, Some(false)),
        (None, Some(_)) => (None, None),
        (Some(titles), Some(item)) => match titles.get(&plain_uuid(item)) {
            Some(title) => (Some(envelope::shown(title, usize::MAX)), Some(true)),
            None => (None, Some(false)),
        },
    }
}

fn text(value: &str) -> String {
    envelope::shown(value, usize::MAX)
}

fn agent_out(
    agent: &Agent,
    titles: Option<&BTreeMap<String, String>>,
    hidden: impl Fn(&Exception) -> bool,
) -> AgentOut {
    AgentOut {
        id: agent.id.clone(),
        name: text(&agent.name),
        host: agent.host.clone(),
        place: agent.place.clone(),
        revoked: agent.revoked,
        token_expires_at: agent.token_expires_at,
        last_use_at: agent.last_use_at,
        uses_this_week: agent.uses_this_week,
        projects: agent.projects.iter().map(|p| text(p)).collect(),
        note: text(&agent.note),
        restricted: agent.restricted,
        actions: agent
            .actions
            .iter()
            .map(|use_| ActionUseOut {
                action: use_.action.clone(),
                allowed: use_.allowed,
                not_allowed: use_.not_allowed,
                projects: use_.projects.iter().map(|p| text(p)).collect(),
            })
            .collect(),
        exceptions: agent
            .exceptions
            .iter()
            .filter(|exception| !hidden(exception))
            .map(|exception| {
                let (title, here) = local(titles, exception.item.as_deref());
                ExceptionOut {
                    item: exception.item.clone(),
                    item_title: text(&exception.item_title),
                    title,
                    here,
                    kind: exception.kind.clone(),
                    created_at: exception.created_at,
                }
            })
            .collect(),
        recent: agent
            .recent
            .iter()
            .map(|recent| {
                let (title, here) = local(titles, recent.item.as_deref());
                RecentOut {
                    at: recent.at,
                    item: recent.item.clone(),
                    item_title: text(&recent.item_title),
                    title,
                    here,
                    action: recent.action.clone(),
                    project: text(&recent.project),
                    command: text(&recent.command),
                    outcome: recent.outcome.clone(),
                    decided_by: recent.decided_by.clone(),
                    answered_on: text(&recent.answered_on),
                }
            })
            .collect(),
    }
}

/// The context of one feed call: the device, the keys, and the vault.
struct Using {
    vault_id: String,
    member: Arc<RelayMember>,
    keys: Arc<Keys>,
}

/// An action that passed the checks, ready to sign and seal.
struct Ready {
    using: Using,
    own: TrustedDevice,
    to: String,
    to_device: u64,
    target: Target,
    stale: bool,
    prepared: Prepared,
}

impl Core {
    pub(super) fn feed_call(&self, op: &str, request: &str) -> CoreResult<String> {
        match op {
            "feed_list" => Ok(ok(&self.feed_list()?)),
            "feed_wait" => {
                #[derive(Deserialize)]
                struct Wait {
                    timeout: u64,
                }
                let Wait { timeout } = params(request)?;
                let changed = self.feed_wait(Duration::from_secs(timeout.clamp(1, 25)))?;
                Ok(ok(&Waited { changed }))
            }
            "feed_action_string" => {
                let input: ActionIn = params(request)?;
                let action_id = match &input.action_id {
                    Some(id) => id.clone(),
                    None => {
                        let mut bytes = [0u8; 16];
                        getrandom::fill(&mut bytes).map_err(|_| CoreError::io())?;
                        encode_b64u(&bytes)
                    }
                };
                let time = input.time.unwrap_or_else(now);
                Ok(ok(&self.prepare_action(&input, &action_id, time)?.prepared))
            }
            "feed_action" => {
                let input: ActionIn = params(request)?;
                Ok(ok(&self.feed_action(&input)?))
            }
            // `feed_action_status` is the name of relay-feed-v1 section 2.
            "feed_action_wait" | "feed_action_status" => {
                #[derive(Deserialize)]
                struct Status {
                    action_id: String,
                    #[serde(default)]
                    vault_id: Option<String>,
                    #[serde(default)]
                    timeout: Option<u64>,
                }
                let Status {
                    action_id,
                    vault_id,
                    timeout,
                } = params(request)?;
                let wait = Duration::from_secs(timeout.unwrap_or(0).min(25));
                Ok(ok(&self.feed_action_wait(
                    &action_id,
                    vault_id.as_deref(),
                    wait,
                )?))
            }
            _ => Err(CoreError::invalid("This call is not known.")),
        }
    }

    /// Keep the titles of the items of the selected vault in its context. Called under the
    /// vault mutex.
    pub(super) fn feed_capture(&self, vault: &Vault) {
        if self.role != Role::App {
            return;
        }
        let Some(vault_id) = guard(&self.list).selected.clone() else {
            return;
        };
        let titles = item_titles(vault).ok();
        if let Some(context) = guard(&self.questions).contexts.get_mut(&vault_id) {
            context.feed.titles = titles;
        }
    }

    /// The selected vault, with its context and its titles read again from it while it is
    /// unlocked.
    fn feed_refresh(&self) -> CoreResult<Selected> {
        let slot = guard(&self.vault);
        let selected = guard(&self.list).selected.clone();
        let Some(id) = selected else {
            return Ok(Selected::None);
        };
        match slot.as_ref() {
            Some(vault) if !vault.is_locked() => {
                self.questions_capture(vault)?;
                self.feed_capture(vault);
                Ok(Selected::Unlocked(id))
            }
            _ => Ok(Selected::Locked(id)),
        }
    }

    /// The context of `vault_id`.
    fn feed_context(&self, vault_id: &str, selected: &Selected) -> CoreResult<Using> {
        let found = guard(&self.questions)
            .contexts
            .get(vault_id)
            .map(|context| Using {
                vault_id: vault_id.to_owned(),
                member: Arc::clone(&context.member),
                keys: Arc::clone(&context.keys),
            });
        match found {
            Some(using) => Ok(using),
            None if selected.id() == Some(vault_id) => Err(selected.missing()),
            None => Err(not_open(guard(&self.list).get(vault_id).is_some())),
        }
    }

    /// Write [`MARKS_FILE`]. The app only; a failure keeps the marks in memory.
    fn save_marks(&self, state: &State) {
        if self.role != Role::App {
            return;
        }
        let file = MarksFile {
            version: 1,
            teams: state.feed_marks.teams.clone(),
        };
        if let Ok(text) = serde_json::to_vec(&file) {
            let _ = write_private(&self.paths.data_dir, MARKS_FILE, &text);
        }
    }

    // ---- Reading the feeds. ----

    /// `feed_wait`: one long poll for each context at the same time; the first that brings
    /// news ends the others.
    fn feed_wait(&self, wait: Duration) -> CoreResult<bool> {
        let selected = self.feed_refresh()?;
        if guard(&self.questions).contexts.is_empty() {
            return match selected {
                Selected::Unlocked(_) => Ok(false),
                other => Err(other.missing()),
            };
        }
        self.feed_fetch(wait, true)
    }

    /// Read the feeds of every context from its last `change`, with a long poll of
    /// `wait`. With `early`, the first context with news ends the long polls of the
    /// others. Returns whether any came; an error only when every context failed.
    fn feed_fetch(&self, wait: Duration, early: bool) -> CoreResult<bool> {
        let targets = self.fetch_targets();
        let drops = guard(&self.questions).drops;
        let results: Vec<(String, Arc<RelayMember>, CoreResult<bool>)> = match targets.as_slice() {
            [] => return Ok(false),
            // One context: a lock ends its call through the device.
            [(id, member)] => {
                let result = self.feed_fetch_one(id, member, wait, None);
                vec![(id.clone(), Arc::clone(member), result)]
            }
            _ => {
                let cancel = Arc::new(Cancel::default());
                guard(&self.questions).waits.push(Arc::clone(&cancel));
                let results = std::thread::scope(|scope| {
                    let running: Vec<_> = targets
                        .iter()
                        .map(|(id, member)| {
                            let cancel = &cancel;
                            scope.spawn(move || {
                                let result = self.feed_fetch_one(id, member, wait, Some(cancel));
                                if early && matches!(result, Ok(true)) {
                                    cancel.close();
                                }
                                match result {
                                    // Ended by the news of another context.
                                    Err(_) if cancel.is_closed() => Ok(false),
                                    other => other,
                                }
                            })
                        })
                        .collect();
                    running
                        .into_iter()
                        .zip(&targets)
                        .map(|(running, (id, member))| {
                            let result = running.join().unwrap_or_else(|_| {
                                Err(CoreError::internal("The agents could not be read."))
                            });
                            (id.clone(), Arc::clone(member), result)
                        })
                        .collect()
                });
                guard(&self.questions)
                    .waits
                    .retain(|held| !Arc::ptr_eq(held, &cancel));
                results
            }
        };
        let mut state = guard(&self.questions);
        if state.drops != drops {
            return Err(CoreError::locked());
        }
        let mut changed = false;
        let mut worked = false;
        let mut failed = None;
        for (id, member, result) in results {
            let error = match result {
                Ok(news) => {
                    changed |= news;
                    worked = true;
                    None
                }
                Err(error) => {
                    let code = error.code;
                    failed.get_or_insert(error);
                    Some(code)
                }
            };
            if let Ok(context) = state.context_mut(&id, &member) {
                context.feed.error = error;
            }
        }
        match failed {
            Some(error) if !worked => Err(error),
            _ => Ok(changed),
        }
    }

    /// The feeds of one context, as [`Self::feed_fetch`].
    fn feed_fetch_one(
        &self,
        vault_id: &str,
        member: &Arc<RelayMember>,
        wait: Duration,
        cancel: Option<&Cancel>,
    ) -> CoreResult<bool> {
        let mut changed = false;
        let mut wait = wait;
        for _ in 0..MAX_PAGES {
            let (since, keys) = {
                let mut state = guard(&self.questions);
                let context = state.context_mut(vault_id, member)?;
                (context.feed.since, Arc::clone(&context.keys))
            };
            let path = format!("/v1/feed?since={since}&wait={}", wait.as_secs());
            let answer = member
                .call_until("GET", &path, None, wait, cancel)
                .map_err(call_error)?;
            let answer: FeedAnswer = serde_json::from_value(answer)
                .map_err(|_| CoreError::from(SyncError::RelayUnreachable))?;
            // The envelopes open without the mutex.
            let reads: Vec<(Record, Read)> = answer
                .feeds
                .into_iter()
                .map(|record| {
                    let read = keys.read_feed(&record);
                    (record, read)
                })
                .collect();
            let mut state = guard(&self.questions);
            let State {
                contexts,
                feed_marks,
                ..
            } = &mut *state;
            // A close or another membership in between: this answer is of the old one.
            let context = contexts
                .get_mut(vault_id)
                .filter(|context| Arc::ptr_eq(&context.member, member))
                .ok_or_else(CoreError::locked)?;
            let keys = Arc::clone(&context.keys);
            let mirror = &mut context.feed;
            if answer.change < since {
                // A relay restored from a backup: read everything again.
                mirror.since = 0;
                changed = true;
                wait = Duration::ZERO;
                continue;
            }
            let mut dirty = false;
            let mut last = since;
            for (record, read) in reads {
                last = last.max(record.change);
                let device_id = record.device_id;
                let mark = feed_marks.get(&keys.team_id, device_id);
                match read {
                    Read::Good(feed) => {
                        // Step 4: a live trusted Mac of this vault.
                        if keys.publisher(&feed.mac.device, device_id).is_none() {
                            continue;
                        }
                        // Step 5: above the highest `seq` accepted. The same `seq` is the
                        // same feed (the AAD binds it): it shows again after a lock or a
                        // restart, when this process does not show it.
                        let showing = mirror.shown.get(&device_id).map(|shown| shown.seq);
                        if feed.seq < mark || (feed.seq == mark && showing.is_some()) {
                            continue;
                        }
                        if showing.is_some_and(|seq| seq >= feed.seq) {
                            continue;
                        }
                        dirty |= feed_marks.raise(&keys.team_id, device_id, feed.seq);
                        mirror.hidden.retain(|hidden| hidden.device_id != device_id);
                        mirror.problems.remove(&device_id);
                        mirror.shown.insert(device_id, feed);
                        changed = true;
                    }
                    Read::Problem(problem) => {
                        // The last good feed stays; the text says why the new one does not
                        // show. A record at or below the mark is an old one.
                        let known = mirror.shown.contains_key(&device_id)
                            || keys.mac_of(device_id).is_some();
                        if known && record.seq > mark {
                            changed |= mirror.problems.insert(device_id, problem) != Some(problem);
                        }
                    }
                    Read::Ignore => {}
                }
            }
            // A device without a feed on the relay leaves the list (section 10.4).
            let present: BTreeSet<u64> = answer.present.iter().copied().collect();
            let before = mirror.shown.len() + mirror.problems.len();
            mirror.shown.retain(|id, _| present.contains(id));
            mirror.problems.retain(|id, _| present.contains(id));
            changed |= mirror.shown.len() + mirror.problems.len() != before;
            let next = if answer.more {
                last
            } else {
                answer.change.max(last)
            };
            mirror.since = mirror.since.max(next);
            if dirty {
                self.save_marks(&state);
            }
            if !answer.more {
                break;
            }
            wait = Duration::ZERO;
        }
        Ok(changed)
    }

    fn feed_list(&self) -> CoreResult<ListOut> {
        let selected = self.feed_refresh()?;
        if guard(&self.questions).contexts.is_empty() {
            return match selected {
                Selected::Unlocked(_) => Ok(ListOut { vaults: Vec::new() }),
                other => Err(other.missing()),
            };
        }
        self.feed_fetch(Duration::ZERO, false)?;
        let names: BTreeMap<String, String> = guard(&self.list)
            .vaults
            .iter()
            .map(|entry| (entry.id.clone(), entry.name.clone()))
            .collect();
        struct Snapshot {
            vault_id: String,
            keys: Arc<Keys>,
            shown: BTreeMap<u64, Arc<Feed>>,
            problems: BTreeMap<u64, Problem>,
            titles: Option<BTreeMap<String, String>>,
            hidden: Vec<Target>,
            error: Option<&'static str>,
        }
        let copies: Vec<Snapshot> = guard(&self.questions)
            .contexts
            .iter()
            .map(|(id, context)| Snapshot {
                vault_id: id.clone(),
                keys: Arc::clone(&context.keys),
                shown: context.feed.shown.clone(),
                problems: context.feed.problems.clone(),
                titles: context.feed.titles.clone(),
                hidden: context.feed.hidden.clone(),
                error: context.feed.error,
            })
            .collect();
        let at = now();
        let mut vaults = Vec::new();
        for copy in copies {
            let keys = &copy.keys;
            let mut macs = Vec::new();
            // A removed iPhone shows nothing of that vault.
            if !keys.is_removed() {
                for (device_id, feed) in &copy.shown {
                    // A Mac removed from the vault leaves at once (section 8).
                    let Some(row) = keys.publisher(&feed.mac.device, *device_id) else {
                        continue;
                    };
                    let hidden = |agent: &str, exception: &Exception| {
                        copy.hidden.iter().any(|hidden| {
                            hidden.device_id == *device_id
                                && hidden.feed_seq == feed.seq
                                && hidden.agent == agent
                                && exception.item.as_deref() == Some(hidden.item.as_str())
                                && exception.kind == hidden.kind
                                && exception.created_at == hidden.created_at
                        })
                    };
                    let name = text(&row.name);
                    macs.push(MacOut {
                        device: feed.mac.device.clone(),
                        relay_device_id: *device_id,
                        problem: copy.problems.get(device_id).map(|p| p.text(&name)),
                        name,
                        seq: Some(feed.seq),
                        generated_at: Some(feed.generated_at),
                        stale: is_stale(feed.generated_at, at),
                        truncated: feed.truncated,
                        week: Some(feed.week),
                        agents: feed
                            .agents
                            .iter()
                            .map(|agent| {
                                agent_out(agent, copy.titles.as_ref(), |exception| {
                                    hidden(&agent.id, exception)
                                })
                            })
                            .collect(),
                    });
                }
                for (device_id, problem) in &copy.problems {
                    if copy.shown.contains_key(device_id) {
                        continue;
                    }
                    let Some(row) = keys.mac_of(*device_id) else {
                        continue;
                    };
                    let name = text(&row.name);
                    macs.push(MacOut {
                        device: row.uuid.clone(),
                        relay_device_id: *device_id,
                        problem: Some(problem.text(&name)),
                        name,
                        seq: None,
                        generated_at: None,
                        stale: false,
                        truncated: false,
                        week: None,
                        agents: Vec::new(),
                    });
                }
            }
            macs.sort_by(|a, b| (&a.name, &a.device).cmp(&(&b.name, &b.device)));
            let own = keys.own.as_ref();
            vaults.push(VaultOut {
                vault_name: names.get(&copy.vault_id).cloned().unwrap_or_default(),
                vault_id: copy.vault_id,
                team_id: keys.team_id.clone(),
                registered: own.is_some(),
                answer_key: own.is_some_and(|own| own.answer_key.is_some()),
                error: copy.error,
                macs,
            });
        }
        Ok(ListOut { vaults })
    }

    // ---- Actions. ----

    /// The action of `input` at `time` with `action_id`, checked against the feed that
    /// this iPhone shows.
    fn prepare_action(&self, input: &ActionIn, action_id: &str, time: u64) -> CoreResult<Ready> {
        if !valid_action_id(action_id) {
            return Err(CoreError::invalid("The action ID is not valid."));
        }
        if !valid_exception_kind(&input.kind) {
            return Err(CoreError::invalid(
                "The kind of the exception is not known.",
            ));
        }
        if guard(&self.list).get(&input.vault_id).is_none() {
            return Err(not_open(false));
        }
        let selected = self.feed_refresh()?;
        let using = self.feed_context(&input.vault_id, &selected)?;
        let own = using.keys.own_row()?;
        let shown = |core: &Self| {
            guard(&core.questions)
                .contexts
                .get(&input.vault_id)
                .filter(|context| Arc::ptr_eq(&context.member, &using.member))
                .and_then(|context| {
                    context
                        .feed
                        .shown
                        .iter()
                        .find(|(device_id, feed)| {
                            feed.mac.device == input.mac_device
                                && using
                                    .keys
                                    .publisher(&feed.mac.device, **device_id)
                                    .is_some()
                        })
                        .map(|(device_id, feed)| (*device_id, Arc::clone(feed)))
                })
        };
        let mut found = shown(self);
        if found.is_none() && !using.keys.is_removed() {
            // Not read in this session yet.
            self.feed_fetch_one(&using.vault_id, &using.member, Duration::ZERO, None)?;
            found = shown(self);
        }
        let (to_device, feed) = found.ok_or_else(list_gone)?;
        let agent = feed
            .agents
            .iter()
            .find(|agent| agent.id == input.agent)
            .ok_or_else(list_gone)?;
        if agent.revoked {
            return Err(CoreError::invalid("This agent is disconnected on the Mac."));
        }
        let exception = agent
            .exceptions
            .iter()
            .find(|exception| {
                exception
                    .item
                    .as_deref()
                    .is_some_and(|item| plain_uuid(item) == plain_uuid(&input.item))
                    && exception.kind == input.kind
                    && exception.created_at == input.created_at
            })
            .ok_or_else(list_gone)?;
        let item = exception.item.clone().ok_or_else(list_gone)?;
        let needs_face_id = exception.kind != "only";
        if needs_face_id && own.answer_key.is_none() {
            return Err(CoreError::new(
                "not_registered",
                "Connect this iPhone again on a Mac to use Face ID here.",
            ));
        }
        let target = Target {
            device_id: to_device,
            feed_seq: feed.seq,
            agent: agent.id.clone(),
            item,
            kind: exception.kind.clone(),
            created_at: exception.created_at,
        };
        let action_string = action_string(
            &own.uuid,
            &feed.mac.device,
            &using.keys.team_id,
            action_id,
            &target,
            time,
        );
        let prepared = Prepared {
            vault_id: using.vault_id.clone(),
            team_id: using.keys.team_id.clone(),
            action_id: action_id.to_owned(),
            time,
            feed_seq: feed.seq,
            action_string,
            needs_face_id,
            face_id_reason: face_id_reason(&agent.name),
        };
        Ok(Ready {
            stale: is_stale(feed.generated_at, now()),
            to: feed.mac.device.clone(),
            to_device,
            target,
            own,
            using,
            prepared,
        })
    }

    fn feed_action(&self, input: &ActionIn) -> CoreResult<SentOut> {
        let at = now();
        let time = input
            .time
            .ok_or_else(|| CoreError::invalid("The action needs its time."))?;
        let action_id = input
            .action_id
            .as_deref()
            .ok_or_else(|| CoreError::invalid("The action needs its ID."))?;
        if time + ACTION_RETRY_SECONDS < at {
            return Err(CoreError::new(
                "stale_action",
                "This action is too old to send. Do it again.",
            ));
        }
        if time > at + ACTION_WINDOW_SECONDS {
            return Err(CoreError::invalid("The action has a time in the future."));
        }
        let ready = self.prepare_action(input, action_id, time)?;
        if ready.stale {
            return Err(CoreError::new(
                "stale_feed",
                "The Mac has not reported for a day. Act on it when it reports again.",
            ));
        }
        let member = &ready.using.member;
        let keys = &ready.using.keys;
        let text = ready.prepared.action_string.as_bytes();
        let signature = if ready.prepared.needs_face_id {
            let answer_key = ready.own.answer_key.as_deref().ok_or_else(|| {
                CoreError::new(
                    "not_registered",
                    "Connect this iPhone again on a Mac to use Face ID here.",
                )
            })?;
            let signature = input
                .signature
                .as_deref()
                .and_then(decode_b64u)
                .ok_or_else(|| CoreError::invalid("This action needs Face ID."))?;
            if !verify_signature(answer_key, text, &signature) {
                return Err(CoreError::new(
                    "not_registered",
                    "The answer key of this iPhone changed. Connect this iPhone again on a Mac.",
                ));
            }
            signature
        } else {
            if input.signature.is_some() {
                return Err(CoreError::invalid("This action is signed by the core."));
            }
            if member.public_key() != ready.own.sign_key.as_slice() {
                return Err(CoreError::new(
                    "not_registered",
                    "This iPhone cannot send actions yet: the vault must sync to this iPhone first.",
                ));
            }
            member.sign(text)?
        };
        let (key_id, key) = keys
            .key
            .as_ref()
            .ok_or_else(|| CoreError::new("unreadable", "Sync this vault to act on its agents."))?;
        let plaintext = Zeroizing::new(action_plaintext(
            action_id,
            &ready.own.uuid,
            &ready.to,
            &ready.target,
            time,
            &encode_b64u(&signature),
        ));
        if plaintext.is_empty() || plaintext.len() > MAX_ACTION_BYTES {
            return Err(CoreError::new(
                "too_large",
                "The action is too large for the relay.",
            ));
        }
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(|_| CoreError::io())?;
        let aad = action_aad(
            &keys.team_id,
            action_id,
            key_id,
            keys.device_id,
            ready.to_device,
        );
        let sealed = envelope::seal(key, &nonce, &aad, &plaintext)
            .ok_or_else(|| CoreError::internal("The action cannot be sealed."))?;
        let body = json!({
            "v": 1,
            "action_id": action_id,
            "to_device": ready.to_device,
            "key_id": key_id,
            "nonce": encode_b64u(&nonce),
            "ciphertext": encode_b64u(&sealed),
        });
        let posted = match member.call("POST", "/v1/feed/actions", Some(&body), Duration::ZERO) {
            Ok(result) => Some(
                serde_json::from_value::<PostedWire>(result)
                    .map_err(|_| CoreError::from(SyncError::RelayUnreachable))?,
            ),
            // A retry of an action that landed (section 10.6).
            Err(RelayCallError::Relay { status: 409, code }) if code == "conflict" => None,
            Err(RelayCallError::Relay { status: 404, .. }) => {
                return Err(CoreError::new(
                    "not_found",
                    "This Mac has no list on the relay now. It may be locked.",
                ));
            }
            Err(error) => return Err(call_error(error)),
        };
        {
            let mut state = guard(&self.questions);
            if let Ok(context) = state.context_mut(&ready.using.vault_id, member) {
                let actions = &mut context.feed.actions;
                actions.insert(
                    action_id.to_owned(),
                    Posted {
                        to_device: ready.to_device,
                        target: ready.target.clone(),
                    },
                );
                while actions.len() > KEEP_ACTIONS {
                    actions.pop_first();
                }
            }
        }
        Ok(SentOut {
            action_id: action_id.to_owned(),
            seq: posted.as_ref().map(|posted| posted.seq),
            created_at: posted.as_ref().map(|posted| posted.created_at),
            expires_at: posted.as_ref().map(|posted| posted.expires_at),
        })
    }

    /// `feed_action_wait`: the state of an action that this process posted, with a long
    /// poll of `wait` while it is open.
    fn feed_action_wait(
        &self,
        action_id: &str,
        vault_id: Option<&str>,
        wait: Duration,
    ) -> CoreResult<OutcomeOut> {
        if !valid_action_id(action_id) {
            return Err(CoreError::invalid("The action ID is not valid."));
        }
        let selected = self.feed_refresh()?;
        let owner = match vault_id {
            Some(id) => Some(id.to_owned()),
            None => guard(&self.questions)
                .contexts
                .iter()
                .find(|(_, context)| context.feed.actions.contains_key(action_id))
                .map(|(id, _)| id.clone()),
        };
        let unknown = || CoreError::new("not_found", "This action is not known on this iPhone.");
        let owner = owner.ok_or_else(unknown)?;
        let using = self.feed_context(&owner, &selected)?;
        let expected = guard(&self.questions)
            .contexts
            .get(&owner)
            .and_then(|context| context.feed.actions.get(action_id))
            .map(|posted| posted.to_device);
        let drops = guard(&self.questions).drops;
        let path = format!("/v1/feed/actions/{action_id}?wait={}", wait.as_secs());
        let answer = match using.member.call("GET", &path, None, wait) {
            Ok(answer) => answer,
            Err(RelayCallError::Relay { status: 404, .. }) => {
                return Err(CoreError::new(
                    "not_found",
                    "This action is not on the relay any more.",
                ));
            }
            Err(error) => return Err(call_error(error)),
        };
        if guard(&self.questions).drops != drops {
            return Err(CoreError::locked());
        }
        let answer: ActionState = serde_json::from_value(answer)
            .map_err(|_| CoreError::from(SyncError::RelayUnreachable))?;
        if answer.action_id != action_id || expected.is_some_and(|to| to != answer.to_device) {
            return Err(CoreError::from(SyncError::RelayUnreachable));
        }
        let mut out = OutcomeOut {
            action_id: action_id.to_owned(),
            outcome: "pending".to_owned(),
            verified: false,
            reason: None,
            feed_seq: None,
            at: None,
        };
        match answer.state.as_str() {
            "settled" => {
                let outcome = answer
                    .outcome
                    .filter(|outcome| matches!(outcome.as_str(), "applied" | "refused" | "stale"))
                    .ok_or_else(|| CoreError::from(SyncError::RelayUnreachable))?;
                let keys = &using.keys;
                let settle = answer.settle.as_ref().and_then(|sealed| {
                    let (key_id, key) = keys.key.as_ref()?;
                    if *key_id != sealed.key_id {
                        return None;
                    }
                    let aad = settle_aad(&keys.team_id, action_id, key_id, &outcome);
                    let plaintext = envelope::open(
                        key,
                        &decode_b64u(&sealed.nonce)?,
                        &aad,
                        &decode_b64u(&sealed.ciphertext)?,
                    )?;
                    parse_settle(&plaintext, action_id, &outcome)
                });
                if let Some(settle) = settle {
                    out.verified = true;
                    out.reason = Some(text(&settle.reason)).filter(|reason| !reason.is_empty());
                    out.feed_seq = settle.feed_seq;
                    out.at = Some(settle.at);
                    if outcome == "applied" {
                        let mut state = guard(&self.questions);
                        if let Ok(context) = state.context_mut(&owner, &using.member) {
                            let mirror = &mut context.feed;
                            if let Some(posted) = mirror.actions.get(action_id) {
                                let target = posted.target.clone();
                                // Hidden while the Mac shows the feed that the action saw.
                                if mirror.shown.get(&target.device_id).map(|feed| feed.seq)
                                    == Some(target.feed_seq)
                                    && !mirror.hidden.contains(&target)
                                {
                                    mirror.hidden.push(target);
                                }
                            }
                        }
                    }
                }
                out.outcome = outcome;
            }
            "expired" => out.outcome = "expired".to_owned(),
            _ if now() >= answer.expires_at => out.outcome = "expired".to_owned(),
            _ => {}
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    //! The test vectors of contract relay-feed-v1, section 17.

    use super::*;

    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const TEAM: &str = "t_7k2m5q4x3c";
    const KEY_ID: &str = "630dcd2966c43366";
    const MAC: &str = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d";
    const PHONE: &str = "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b";
    const ACTION_ID: &str = "sLGys7S1tre4ubq7vL2-vw";
    const ANSWER_PUBLIC: &str =
        "BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts";
    const SIGNATURE: &str = "MEUCIQDL-JNMgp74rl6v619inkFkPNgRVDLWyCjH-QdHFiLgSgIgZwwg3N2Z_lW1AQ9nXjx57eGcxJ9e32f5VG3SJbV2qic";
    const FEED: &str = r#"{"v":1,"mac":{"device":"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d","name":"MacBook Pro"},"seq":1790000040,"generated_at":1790000040,"truncated":false,"week":{"by_you":3,"automatic":128},"agents":[{"id":"4","name":"Claude Code","host":"claude","where":"mac","revoked":false,"token_expires_at":1797776000,"last_use_at":1790000010,"uses_this_week":12,"projects":["synthetic-shop"],"note":"Deploys only from the main branch.","restricted":false,"actions":[{"action":"deploy","allowed":2,"not_allowed":1,"projects":["synthetic-shop"]}],"exceptions":[{"item":"3c9e1f7a-2b4d-4c6e-8f0a-1b3d5e7f9a2c","item_title":"Shop database","kind":"never","created_at":1789990000}],"recent":[{"at":1790000010,"item":"8d2a4c6e-1f3b-4d5a-9c7e-0b2d4f6a8c1e","item_title":"API token","action":"deploy","project":"synthetic-shop","command":"npm run deploy -- --token [apassy:secret]","outcome":"allowed","decided_by":"owner","answered_on":"Test iPhone"}]}]}"#;
    const ACTION: &str = r#"{"v":1,"action_id":"sLGys7S1tre4ubq7vL2-vw","by":"6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b","to":"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d","kind":"remove_exception","agent":"4","item":"3c9e1f7a-2b4d-4c6e-8f0a-1b3d5e7f9a2c","exception":{"kind":"never","created_at":1789990000},"feed_seq":1790000040,"time":1790000060,"signature":"MEUCIQDL-JNMgp74rl6v619inkFkPNgRVDLWyCjH-QdHFiLgSgIgZwwg3N2Z_lW1AQ9nXjx57eGcxJ9e32f5VG3SJbV2qic"}"#;
    const SETTLE: &str = r#"{"v":1,"action_id":"sLGys7S1tre4ubq7vL2-vw","outcome":"applied","reason":"","feed_seq":1790000070,"at":1790000061}"#;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn sha256(bytes: &[u8]) -> String {
        hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
    }

    fn nonce(first: u8) -> [u8; 12] {
        std::array::from_fn(|at| first + at as u8)
    }

    fn vector_target() -> Target {
        Target {
            device_id: 2,
            feed_seq: 1_790_000_040,
            agent: "4".to_owned(),
            item: "3c9e1f7a-2b4d-4c6e-8f0a-1b3d5e7f9a2c".to_owned(),
            kind: "never".to_owned(),
            created_at: 1_789_990_000,
        }
    }

    #[test]
    fn the_feed_vector_seals_opens_and_parses() {
        assert_eq!(FEED.len(), 927);
        assert_eq!(
            sha256(FEED.as_bytes()),
            "9419276eb6a004d6496e626b439d01c94c24d19e0f3844e765b01da58cd0af98"
        );
        let aad = feed_aad(TEAM, 2, 1_790_000_040, KEY_ID);
        assert_eq!(
            hex(&aad),
            "6170617373792d666565642d7631006665656400745f376b326d357134783363003200313739303030303034300036333064636432393636633433333636"
        );
        let key = unhex(KEY);
        let sealed = envelope::seal(&key, &nonce(0x30), &aad, FEED.as_bytes()).unwrap();
        assert_eq!(sealed.len(), 943);
        assert_eq!(
            sha256(&sealed),
            "3a5a92a71d541af1263f3e90d4db82827fd8674f671e109b47752dbb61f61043"
        );
        assert_eq!(
            hex(&sealed[sealed.len() - 16..]),
            "57cdef5d1ead09fbb024b3b879af3d10"
        );
        let opened = envelope::open(&key, &nonce(0x30), &aad, &sealed).unwrap();
        let feed = parse_feed(&opened).expect("the vector parses");
        assert_eq!(feed.seq, 1_790_000_040);
        assert_eq!(feed.mac.device, MAC);
        assert_eq!(feed.agents[0].exceptions[0].kind, "never");
        // Another device, seq, team, key_id, or part does not open it.
        for aad in [
            feed_aad(TEAM, 3, 1_790_000_040, KEY_ID),
            feed_aad(TEAM, 2, 1_790_000_039, KEY_ID),
            feed_aad("t_0000000000", 2, 1_790_000_040, KEY_ID),
            feed_aad(TEAM, 2, 1_790_000_040, "0000000000000000"),
            aad_with_part("action"),
        ] {
            assert!(envelope::open(&key, &nonce(0x30), &aad, &sealed).is_none());
        }
    }

    fn aad_with_part(part: &str) -> Vec<u8> {
        aad(&[AAD_TAG, part, TEAM, "2", "1790000040", KEY_ID])
    }

    #[test]
    fn a_feed_outside_the_schema_is_refused() {
        let mut value: serde_json::Value = serde_json::from_str(FEED).unwrap();
        let check = |value: &serde_json::Value| parse_feed(value.to_string().as_bytes()).is_some();
        assert!(check(&value));
        // A missing nullable field.
        let mut missing = value.clone();
        missing["agents"][0]
            .as_object_mut()
            .unwrap()
            .remove("last_use_at");
        assert!(!check(&missing));
        let mut null = value.clone();
        null["agents"][0]["last_use_at"] = serde_json::Value::Null;
        assert!(check(&null));
        // An unknown field, another `v`, a bad host, a long name, a numeric item id.
        value["extra"] = json!(1);
        assert!(!check(&value));
        let mut other = serde_json::from_str::<serde_json::Value>(FEED).unwrap();
        other["v"] = json!(2);
        assert!(!check(&other));
        let mut host = serde_json::from_str::<serde_json::Value>(FEED).unwrap();
        host["agents"][0]["host"] = json!("cursor");
        assert!(!check(&host));
        let mut name = serde_json::from_str::<serde_json::Value>(FEED).unwrap();
        name["mac"]["name"] = json!("M".repeat(65));
        assert!(!check(&name));
        let mut item = serde_json::from_str::<serde_json::Value>(FEED).unwrap();
        item["agents"][0]["exceptions"][0]["item"] = json!("7");
        assert!(!check(&item));
        // The vault's own form of an item UUID is accepted.
        let mut plain = serde_json::from_str::<serde_json::Value>(FEED).unwrap();
        plain["agents"][0]["exceptions"][0]["item"] = json!("3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c");
        assert!(check(&plain));
    }

    #[test]
    fn the_action_string_and_envelope_match_the_vectors() {
        let text = action_string(PHONE, MAC, TEAM, ACTION_ID, &vector_target(), 1_790_000_060);
        assert_eq!(text.len(), 226);
        assert_eq!(
            sha256(text.as_bytes()),
            "bf7b086d31906cba873ce5545b64b042f2ea8e67bd2ffd2be5b5d26058e87a0d"
        );
        let public = decode_b64u(ANSWER_PUBLIC).unwrap();
        let signature = decode_b64u(SIGNATURE).unwrap();
        assert!(verify_signature(&public, text.as_bytes(), &signature));
        let changed = text.replace(":never:", ":only:");
        assert!(!verify_signature(&public, changed.as_bytes(), &signature));

        let plaintext = action_plaintext(
            ACTION_ID,
            PHONE,
            MAC,
            &vector_target(),
            1_790_000_060,
            SIGNATURE,
        );
        assert_eq!(String::from_utf8(plaintext.clone()).unwrap(), ACTION);
        assert_eq!(
            sha256(&plaintext),
            "356dde394e065c67bc16add23183836e7bf005749627ca31a596e32f8e81d51e"
        );
        let aad = action_aad(TEAM, ACTION_ID, KEY_ID, 3, 2);
        assert_eq!(
            hex(&aad),
            "6170617373792d666565642d763100616374696f6e00745f376b326d35713478336300734c4779733753317472653475627137764c322d7677003633306463643239363663343333363600330032"
        );
        let sealed = envelope::seal(&unhex(KEY), &nonce(0x40), &aad, &plaintext).unwrap();
        assert_eq!(sealed.len(), 435);
        assert_eq!(
            sha256(&sealed),
            "db227d023e5a931dd5e96208eb78381f27a452c0db6dc453dc9922f29f4b93a8"
        );
        for aad in [
            action_aad(TEAM, ACTION_ID, KEY_ID, 3, 5),
            action_aad(TEAM, ACTION_ID, KEY_ID, 4, 2),
        ] {
            assert!(envelope::open(&unhex(KEY), &nonce(0x40), &aad, &sealed).is_none());
        }
    }

    #[test]
    fn the_settle_vector_opens_with_its_outcome_only() {
        let key = unhex(KEY);
        let aad = settle_aad(TEAM, ACTION_ID, KEY_ID, "applied");
        assert_eq!(
            hex(&aad),
            "6170617373792d666565642d763100736574746c6500745f376b326d35713478336300734c4779733753317472653475627137764c322d76770036333064636432393636633433333636006170706c696564"
        );
        let sealed = unhex(
            "45c1455083097076570a95408f49b1f62de9b76b09a5c47982c1f3b5c77807a3639e5ecf86f3776b677093db298da725bfe2853c8688b69ad7b4a7832e77d73b1ac2ecd226b7cb5a4afdf3983e7e2acf4d006065b984d08880aaa87d41d13ec7fb54c8e0c1f5a9e420b91c0814b97d13b6e076ff2594ee2ba2c7d39ddfaea96b2a1c",
        );
        let opened = envelope::open(&key, &nonce(0x50), &aad, &sealed).unwrap();
        assert_eq!(opened, SETTLE.as_bytes());
        let settle = parse_settle(&opened, ACTION_ID, "applied").unwrap();
        assert_eq!(settle.feed_seq, Some(1_790_000_070));
        assert!(parse_settle(&opened, ACTION_ID, "refused").is_none());
        let refused = settle_aad(TEAM, ACTION_ID, KEY_ID, "refused");
        assert!(envelope::open(&key, &nonce(0x50), &refused, &sealed).is_none());
    }

    #[test]
    fn the_face_id_reason_is_cut_and_clean() {
        assert_eq!(
            face_id_reason("Claude \"Code\"\n"),
            "remove an exception of agent \"Claude Code\""
        );
        let long = face_id_reason(&"a".repeat(80));
        assert_eq!(long.matches('a').count(), 40 + 2);
    }

    #[test]
    fn marks_rise_only() {
        let mut marks = Marks::default();
        assert!(marks.raise(TEAM, 2, 10));
        assert!(!marks.raise(TEAM, 2, 10));
        assert!(!marks.raise(TEAM, 2, 9));
        assert_eq!(marks.get(TEAM, 2), 10);
        assert_eq!(marks.get(TEAM, 3), 0);
    }

    #[test]
    fn relay_refusals_have_their_codes() {
        let code = |status, code: &str| {
            call_error(RelayCallError::Relay {
                status,
                code: code.to_owned(),
            })
            .code
        };
        assert_eq!(code(403, "not_routed"), "not_routed");
        assert_eq!(code(403, "too_many_actions"), "too_many_actions");
        assert_eq!(code(404, "not_found"), "feed_unavailable");
        assert_eq!(code(503, "busy"), "relay_unreachable");
    }
}
