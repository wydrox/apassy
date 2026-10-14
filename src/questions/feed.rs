//! The feed of the agents of this Mac for the iPhone (contract relay-feed-v1).
//!
//! The agents of a vault, their use, and their exceptions are local rows of the Mac
//! (`LOCAL_TABLES`): they never sync. This Mac publishes them as one sealed **feed**
//! through the questions team of the vault, and takes one kind of **action** back from
//! an iPhone of the vault: remove an exception of an agent.
//!
//! - [`build_feed`] reads the same figures as the Agents page of the Mac
//!   (`Vault::agent_facts`, `Vault::week_counts`), names each item by its sync UUID (in
//!   the vault's own form: 32 lowercase hex characters, no hyphens) and its title,
//!   masks each command again with the current secret values of every item of the
//!   vault, and sends project labels only. [`fit`] keeps the feed within its size
//!   (section 7.3).
//! - The publisher (`Shared::feed_step`) seals the feed with the question key and puts it
//!   on the relay with `seq = max(last + 1, now)` (section 8): after a change, at most
//!   once per 10 s, and every 15 minutes, while the vault is unlocked, the questions are
//!   on, the vault has a live iPhone in the team, and "Show agents on the iPhone" is on.
//!   A locked Mac publishes nothing. The feed leaves the relay when the setting goes off,
//!   when the questions go off, and when the last iPhone goes.
//! - The action handler (`Shared::actions_step`) long-polls the actions to this Mac and
//!   checks at most 20 of an answer, each id once (marked before its first check, so one
//!   id gets one settle), as section 9.5 says, in order: it opens (an action that does
//!   not open writes no Activity line of its own), it has the form, it is for this Mac,
//!   from a live iPhone of the vault, in its 60 s window, for an agent and
//!   an item that are here, signed by the right key of the iPhone (through the owner gate,
//!   [`OwnerCheck::RemoteAction`], for a removal that gives authority back), for an
//!   exception as the feed showed it. Then it removes the row as the Mac's own "Remove
//!   exception" does, settles the action, and publishes a new feed.
//!
//! The relay sees the routing only: it never gets a feed, an action, or the question key.
//!
//! [`OwnerCheck::RemoteAction`]: crate::broker::approvals::OwnerCheck::RemoteAction

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer, Serialize};
use zeroize::Zeroizing;

use super::client::{FeedActionRecord, FeedRecord, MAX_WAIT, QuestionsError};
use super::envelope::{Sealed, new_nonce, parse_decimal, valid_qid};
use super::worker::{Active, Shared, lock, unix_now};
use crate::broker::approvals::{OwnerAction, OwnerAuthError, OwnerCheck, verify_remote_action};
use crate::sync::decode_b64u;
use crate::sync::relay_http::Cancel;
use crate::vault::exceptions::{AgentException, ExceptionKind, MAX_AGENT_NOTE_BYTES};
use crate::vault::overview::{DAY, valid_item_uuid};
use crate::vault::usage::{InteractionKind, MAX_COMMAND_SUMMARY_BYTES, clean};
use crate::vault::{
    ActivityDecision, NewActivity, QuestionKey, TrustedDevice, TrustedDeviceKind, Vault,
    VaultResult,
};

/// The tag of every AAD of the feed (section 6.1).
pub const FEED_TAG: &str = "apassy-feed-v1";
/// The first line of the action string (section 9.3).
pub const ACTION_TAG: &str = "apassy-feed-action-v1";
/// The version of every feed, action, settle, and request body.
pub const VERSION: u32 = 1;
/// The only action kind of v1.
pub const REMOVE_EXCEPTION: &str = "remove_exception";

/// The largest plaintexts (section 6.3).
pub const MAX_FEED_BYTES: usize = 262_128;
pub const MAX_ACTION_BYTES: usize = 4096;
pub const MAX_SETTLE_BYTES: usize = 1024;
/// The plaintext of a feed behind a Worker older than the contract (section 14.2): 95 KiB,
/// so the body (the b64u of the ciphertext and the other fields) stays within the old
/// Worker's 128 KiB.
pub const OLD_WORKER_FEED_BYTES: usize = 95 * 1024;
/// The largest `seq`: 2^53 − 1.
pub const MAX_SEQ: u64 = 9_007_199_254_740_991;
/// The window of an action's `time` around the target's clock, both ways (section 9.4).
pub const ACTION_WINDOW: u64 = 60;

/// The limits of the fields of a feed (section 7.1).
pub const MAX_AGENTS: usize = 64;
pub const MAX_PROJECTS: usize = 16;
pub const MAX_PROJECT_BYTES: usize = 256;
pub const MAX_NAME_BYTES: usize = 64;
pub const MAX_TITLE_BYTES: usize = 128;
pub const MAX_ACTIONS: usize = 4;
pub const MAX_EXCEPTIONS: usize = 256;
pub const MAX_RECENT: usize = 20;
const MAX_REASON_BYTES: usize = 200;
/// An agent with no exception and no use for this long may be left out first.
const IDLE_AGENT: u64 = 90 * DAY;
/// The ids of the handled actions stay this long (section 9.4).
const HANDLED_FOR: Duration = Duration::from_secs(10 * 60);
/// The waits between two puts of a feed that failed for a reason that can pass.
const RETRY_WAITS: [u64; 5] = [2, 4, 8, 16, 30];
/// The target handles at most this many actions of one answer (section 10.7).
pub const ACTIONS_PER_ANSWER: usize = 20;
/// The read-back of the own feed follows `more` at most this many times.
const MAX_FEED_PAGES: usize = 64;
/// At most one Activity line about actions that could not be read in this time.
const UNREADABLE_LINE_EVERY: Duration = Duration::from_secs(10 * 60);
/// The Activity line about actions that could not be read (section 9.5 step 1).
pub const UNREADABLE_LINE: &str =
    "Actions through the relay could not be read. They did not count.";
/// The name of a sender in Activity when the action does not name a device of the vault.
const SOME_DEVICE: &str = "a device of this vault";
/// After an early empty answer of the action long poll: 5 s, doubling to 60 s.
const EARLY_WAIT_FIRST: Duration = Duration::from_secs(5);
const EARLY_WAIT_MOST: Duration = Duration::from_secs(60);
/// After a `404` of the feed routes, the loops ask the relay again this much later.
const UNSUPPORTED_WAIT: Duration = Duration::from_secs(5 * 60);
/// `/v1/feed` answered `404`: the relay has no team schema 6 (section 14.2).
pub const UNSUPPORTED: &str =
    "The relay does not show agents on the iPhone yet — update the relay.";
/// The operation of an Activity line about an action through the relay.
pub const ACTIVITY_OPERATION: &str = "action through the relay";

// ---- Forms and AADs (sections 4 and 6). ----

fn aad(parts: &[&str]) -> Vec<u8> {
    parts.join("\0").into_bytes()
}

/// The AAD of a feed: the team, the relay device id of the publisher, `seq`, the key.
pub fn feed_aad(team_id: &str, device_id: u64, seq: u64, key_id: &str) -> Vec<u8> {
    aad(&[
        FEED_TAG,
        "feed",
        team_id,
        &device_id.to_string(),
        &seq.to_string(),
        key_id,
    ])
}

/// The AAD of an action: the stamped relay device id of the sender and the one of the
/// target.
pub fn action_aad(team_id: &str, action_id: &str, key_id: &str, from: u64, to: u64) -> Vec<u8> {
    aad(&[
        FEED_TAG,
        "action",
        team_id,
        action_id,
        key_id,
        &from.to_string(),
        &to.to_string(),
    ])
}

/// The AAD of a settle, with the outcome that the relay keeps in clear.
pub fn settle_aad(team_id: &str, action_id: &str, key_id: &str, outcome: &str) -> Vec<u8> {
    aad(&[FEED_TAG, "settle", team_id, action_id, key_id, outcome])
}

/// The `seq` of the next feed (section 8): `max(last + 1, now)`, within 1 to 2^53 − 1.
pub fn next_seq(last: u64, now: u64) -> u64 {
    last.saturating_add(1).max(now).clamp(1, MAX_SEQ)
}

/// A UUID of the contract form: 36 lowercase characters `8-4-4-4-12`.
pub fn valid_uuid(text: &str) -> bool {
    text.len() == 36
        && text.char_indices().all(|(at, c)| match at {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_digit() || ('a'..='f').contains(&c),
        })
}

/// The host of an agent from its name, for the icon: the rule of `ConnectHost::guess`
/// on the Agents page.
pub fn host_of(name: &str) -> &'static str {
    let name = name.to_ascii_lowercase();
    if name.contains("codex") {
        "codex"
    } else if name.contains("t3") {
        "t3"
    } else if name.contains("claude") {
        "claude"
    } else {
        "other"
    }
}

/// A nullable field that must be present: `null` or a value, never missing.
fn required<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

// ---- The feed (section 7). ----

/// The plaintext of a feed, with exactly the fields of section 7.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Feed {
    pub v: u32,
    pub mac: FeedMac,
    pub seq: u64,
    pub generated_at: u64,
    pub truncated: bool,
    pub week: FeedWeek,
    pub agents: Vec<FeedAgent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedMac {
    pub device: String,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedWeek {
    pub by_you: u64,
    pub automatic: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedAgent {
    pub id: String,
    pub name: String,
    pub host: String,
    #[serde(rename = "where")]
    pub place: String,
    pub revoked: bool,
    pub token_expires_at: u64,
    #[serde(deserialize_with = "required")]
    pub last_use_at: Option<u64>,
    pub uses_this_week: u64,
    pub projects: Vec<String>,
    pub note: String,
    pub restricted: bool,
    pub actions: Vec<FeedActionUse>,
    pub exceptions: Vec<FeedException>,
    pub recent: Vec<FeedUse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedActionUse {
    pub action: String,
    pub allowed: u64,
    pub not_allowed: u64,
    pub projects: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedException {
    #[serde(deserialize_with = "required")]
    pub item: Option<String>,
    pub item_title: String,
    pub kind: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedUse {
    pub at: u64,
    #[serde(deserialize_with = "required")]
    pub item: Option<String>,
    pub item_title: String,
    pub action: String,
    pub project: String,
    pub command: String,
    pub outcome: String,
    pub decided_by: String,
    pub answered_on: String,
}

const U32_MAX: u64 = u32::MAX as u64;

fn text_ok(text: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&text.len()) && !text.chars().any(char::is_control)
}

fn projects_ok(projects: &[String]) -> bool {
    projects.len() <= MAX_PROJECTS
        && projects
            .iter()
            .all(|project| text_ok(project, 1, MAX_PROJECT_BYTES))
}

/// An item reference of a feed or an action: the vault's own form of an item UUID, 32
/// lowercase hex characters (section 4). Exactly one form, so a reader and a target
/// compare it byte for byte.
pub fn valid_item_ref(text: &str) -> bool {
    valid_item_uuid(text)
}

fn item_ok(item: Option<&String>) -> bool {
    item.is_none_or(|uuid| valid_item_ref(uuid))
}

impl Feed {
    /// The plaintext: one JSON object, the fields in the order of the contract.
    pub fn to_plaintext(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(serde_json::to_vec(self).unwrap_or_default())
    }

    /// Parse a feed plaintext with the reader's checks of section 7.4 step 2 and `v`.
    pub fn parse(plaintext: &[u8]) -> Option<Self> {
        if plaintext.len() > MAX_FEED_BYTES {
            return None;
        }
        let feed: Self = serde_json::from_slice(plaintext).ok()?;
        (feed.v == VERSION && feed.within_limits()).then_some(feed)
    }

    /// Every field within its form and limit (section 7.1).
    pub fn within_limits(&self) -> bool {
        let agents_ok = self.agents.len() <= MAX_AGENTS
            && self.agents.iter().all(|agent| {
                let mut kinds: Vec<&str> = agent
                    .actions
                    .iter()
                    .map(|action| action.action.as_str())
                    .collect();
                kinds.sort_unstable();
                kinds.dedup();
                parse_decimal(&agent.id).is_some()
                    && text_ok(&agent.name, 1, MAX_NAME_BYTES)
                    && ["claude", "codex", "t3", "other"].contains(&agent.host.as_str())
                    && agent.place == "mac"
                    && agent.uses_this_week <= U32_MAX
                    && projects_ok(&agent.projects)
                    && agent.note.len() <= MAX_AGENT_NOTE_BYTES
                    && agent.actions.len() <= MAX_ACTIONS
                    && kinds.len() == agent.actions.len()
                    && agent.actions.iter().all(|action| {
                        ["read", "change", "deploy", "delete"].contains(&action.action.as_str())
                            && projects_ok(&action.projects)
                    })
                    && agent.exceptions.len() <= MAX_EXCEPTIONS
                    && agent.exceptions.iter().all(|exception| {
                        item_ok(exception.item.as_ref())
                            && exception.item_title.len() <= MAX_TITLE_BYTES
                            && ExceptionKind::parse(&exception.kind).is_some()
                    })
                    && agent.recent.len() <= MAX_RECENT
                    && agent.recent.iter().all(|recent| {
                        item_ok(recent.item.as_ref())
                            && recent.item_title.len() <= MAX_TITLE_BYTES
                            && ["read", "change", "deploy", "delete"]
                                .contains(&recent.action.as_str())
                            && recent.project.len() <= MAX_PROJECT_BYTES
                            && recent.command.len() <= MAX_COMMAND_SUMMARY_BYTES
                            && ["allowed", "denied", "refused", "timed_out"]
                                .contains(&recent.outcome.as_str())
                            && ["bouncer", "pattern", "answer", "owner", "rule"]
                                .contains(&recent.decided_by.as_str())
                            && recent.answered_on.len() <= MAX_NAME_BYTES
                    })
            });
        valid_uuid(&self.mac.device)
            && text_ok(&self.mac.name, 1, MAX_NAME_BYTES)
            && (1..=MAX_SEQ).contains(&self.seq)
            && self.week.by_you <= U32_MAX
            && self.week.automatic <= U32_MAX
            && agents_ok
    }

    /// The digest of what the feed says, without `seq`, `generated_at`, and `truncated`,
    /// with the key that seals it: a new feed goes out only when this changes or at the
    /// beat.
    fn content_digest(&self, key_id: &str) -> [u8; 32] {
        let mut copy = self.clone();
        copy.seq = 0;
        copy.generated_at = 0;
        copy.truncated = false;
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        ctx.update(key_id.as_bytes());
        ctx.update(b"\0");
        ctx.update(&copy.to_plaintext());
        let mut out = [0u8; 32];
        out.copy_from_slice(ctx.finish().as_ref());
        out
    }
}

fn cut_clean(text: &str, max: usize) -> String {
    clean(text, max)
}

fn short_u32(value: u64) -> u64 {
    value.min(U32_MAX)
}

fn projects_of(projects: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for project in projects {
        let project = cut_clean(project, MAX_PROJECT_BYTES);
        if !project.is_empty() && !out.contains(&project) {
            out.push(project);
        }
        if out.len() >= MAX_PROJECTS {
            break;
        }
    }
    out
}

/// The feed of the agents of this vault on this Mac (section 7.1), every field at its
/// limit, before [`fit`]. `me` is the trusted device of this Mac; `seq` and `now` go in
/// the feed as they are. It reads the vault only: no value, no item notes, no project
/// key, no host list, no token.
pub fn build_feed(vault: &Vault, me: &TrustedDevice, seq: u64, now: u64) -> VaultResult<Feed> {
    let week = vault.week_counts(now)?;
    let refs = vault.item_refs()?;
    let mask = vault.vault_command_mask()?;
    let mut agents = Vec::new();
    for agent in vault.list_agents()? {
        let facts = vault.agent_facts(agent.id, now)?;
        let mut exceptions: Vec<FeedException> = facts
            .exceptions
            .iter()
            .map(|exception| {
                let item = refs.get(&exception.item_id);
                FeedException {
                    item: item.map(|item| item.uuid.clone()),
                    item_title: item
                        .map_or_else(String::new, |item| cut_clean(&item.title, MAX_TITLE_BYTES)),
                    kind: exception.kind.as_str().to_owned(),
                    created_at: exception.created_at,
                }
            })
            .collect();
        exceptions.sort_by(|a, b| {
            a.item_title
                .cmp(&b.item_title)
                .then_with(|| a.kind.cmp(&b.kind))
        });
        let mut recent = Vec::new();
        for item_use in facts.uses.iter().take(MAX_RECENT) {
            let item = refs.get(&item_use.item_id);
            // Masked again with the values of every item of the vault now, whatever the
            // item of the row: a value set after the row was written, a value of another
            // item, and a value of an item without a sync UUID are masked too.
            let command = mask.summary(&item_use.command_summary, MAX_COMMAND_SUMMARY_BYTES);
            recent.push(FeedUse {
                at: item_use.at,
                item: item.map(|item| item.uuid.clone()),
                item_title: item
                    .map_or_else(String::new, |item| cut_clean(&item.title, MAX_TITLE_BYTES)),
                action: item_use.action.as_str().to_owned(),
                project: cut_clean(&item_use.project_label, MAX_PROJECT_BYTES),
                command,
                outcome: item_use.outcome.as_str().to_owned(),
                decided_by: item_use.decided_by.as_str().to_owned(),
                answered_on: cut_clean(&item_use.answered_on, MAX_NAME_BYTES),
            });
        }
        let name = match cut_clean(&agent.name, MAX_NAME_BYTES) {
            name if name.is_empty() => "Agent".to_owned(),
            name => name,
        };
        agents.push(FeedAgent {
            id: agent.id.to_string(),
            host: host_of(&agent.name).to_owned(),
            name,
            place: "mac".to_owned(),
            revoked: agent.revoked,
            token_expires_at: agent.token_expires_at,
            last_use_at: facts.last_use_at(),
            uses_this_week: short_u32(facts.uses_this_week as u64),
            projects: projects_of(&facts.projects),
            note: cut_clean(&facts.note, MAX_AGENT_NOTE_BYTES),
            restricted: facts.restricted,
            actions: facts
                .actions
                .iter()
                .take(MAX_ACTIONS)
                .map(|action| FeedActionUse {
                    action: action.action.as_str().to_owned(),
                    allowed: short_u32(action.allowed as u64),
                    not_allowed: short_u32(action.not_allowed as u64),
                    projects: projects_of(&action.projects),
                })
                .collect(),
            exceptions,
            recent,
        });
    }
    // Newest use first, never used last, then by id.
    agents.sort_by(|a, b| {
        b.last_use_at
            .is_some()
            .cmp(&a.last_use_at.is_some())
            .then(b.last_use_at.cmp(&a.last_use_at))
            .then_with(|| {
                parse_decimal(&a.id)
                    .unwrap_or(u64::MAX)
                    .cmp(&parse_decimal(&b.id).unwrap_or(u64::MAX))
            })
    });
    let name = match cut_clean(&me.name, MAX_NAME_BYTES) {
        name if name.is_empty() => "Mac".to_owned(),
        name => name,
    };
    Ok(Feed {
        v: VERSION,
        mac: FeedMac {
            device: me.uuid.clone(),
            name,
        },
        seq,
        generated_at: now,
        truncated: false,
        week: FeedWeek {
            by_you: short_u32(week.by_you),
            automatic: short_u32(week.automatic),
        },
        agents,
    })
}

/// The index of the agent to leave out next among those with `revoked`: the oldest
/// `last_use_at` (never used counts as the oldest). The list is newest first, so it is
/// the last one.
fn oldest(agents: &[FeedAgent], revoked: bool) -> Option<usize> {
    agents.iter().rposition(|agent| agent.revoked == revoked)
}

fn size(feed: &Feed) -> usize {
    feed.to_plaintext().len()
}

/// Fit `feed` to `max_bytes` of plaintext (section 7.3) and return the plaintext. It
/// leaves out, in this order, and sets `truncated`: an agent with no exception and no
/// use for 90 days; `recent` cut to 10, 5, then 0 per agent; the revoked agents, the
/// oldest first; the other agents, the oldest first. An exception list is never cut:
/// an agent with more than [`MAX_EXCEPTIONS`] is left out whole. `None` when nothing
/// fits.
pub fn fit(feed: &mut Feed, max_bytes: usize, now: u64) -> Option<Zeroizing<Vec<u8>>> {
    let before = feed.agents.len();
    feed.agents
        .retain(|agent| agent.exceptions.len() <= MAX_EXCEPTIONS);
    let idle = |agent: &FeedAgent| {
        agent.exceptions.is_empty()
            && agent
                .last_use_at
                .is_none_or(|at| at.saturating_add(IDLE_AGENT) < now)
    };
    if feed.agents.len() > MAX_AGENTS {
        feed.agents.retain(|agent| !idle(agent));
    }
    while feed.agents.len() > MAX_AGENTS {
        let Some(index) = oldest(&feed.agents, true).or_else(|| oldest(&feed.agents, false)) else {
            break;
        };
        feed.agents.remove(index);
    }
    if feed.agents.len() != before {
        feed.truncated = true;
    }
    if size(feed) > max_bytes {
        feed.truncated = true;
        feed.agents.retain(|agent| !idle(agent));
    }
    for keep in [10, 5, 0] {
        if size(feed) <= max_bytes {
            break;
        }
        for agent in &mut feed.agents {
            agent.recent.truncate(keep);
        }
    }
    for revoked in [true, false] {
        while size(feed) > max_bytes {
            let Some(index) = oldest(&feed.agents, revoked) else {
                break;
            };
            feed.agents.remove(index);
        }
    }
    let plaintext = feed.to_plaintext();
    (plaintext.len() <= max_bytes).then_some(plaintext)
}

// ---- Actions (section 9). ----

/// The exception that an action names, as the feed showed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionException {
    pub kind: String,
    pub created_at: u64,
}

/// The plaintext of an action, with exactly the fields of section 9.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionBody {
    pub v: u32,
    pub action_id: String,
    pub by: String,
    pub to: String,
    pub kind: String,
    pub agent: String,
    pub item: String,
    pub exception: ActionException,
    pub feed_seq: u64,
    pub time: u64,
    /// The DER ECDSA signature over the action string, as b64u.
    pub signature: String,
}

impl ActionBody {
    /// The body of `removal`, signed with `signature` (DER).
    pub fn new(removal: &RemovalAction, signature: &[u8]) -> Self {
        Self {
            v: VERSION,
            action_id: removal.action_id.clone(),
            by: removal.by.clone(),
            to: removal.to.clone(),
            kind: REMOVE_EXCEPTION.to_owned(),
            agent: removal.agent_id.to_string(),
            item: removal.item_uuid.clone(),
            exception: ActionException {
                kind: removal.kind.as_str().to_owned(),
                created_at: removal.created_at,
            },
            feed_seq: removal.feed_seq,
            time: removal.time,
            signature: crate::sync::encode_b64u(signature),
        }
    }

    /// The plaintext: one JSON object, at most [`MAX_ACTION_BYTES`].
    pub fn to_plaintext(&self) -> Option<Zeroizing<Vec<u8>>> {
        let bytes = Zeroizing::new(serde_json::to_vec(self).ok()?);
        (bytes.len() <= MAX_ACTION_BYTES).then_some(bytes)
    }

    /// Parse an action plaintext: exactly the fields, `v` 1, the kind of v1.
    pub fn parse(plaintext: &[u8]) -> Option<Self> {
        if plaintext.len() > MAX_ACTION_BYTES {
            return None;
        }
        let body: Self = serde_json::from_slice(plaintext).ok()?;
        (body.v == VERSION && body.kind == REMOVE_EXCEPTION).then_some(body)
    }

    /// The signed fields of the body for `team_id`, when each has its form. The
    /// signature stays apart.
    pub fn removal(&self, team_id: &str) -> Option<RemovalAction> {
        let removal = RemovalAction {
            by: self.by.clone(),
            to: self.to.clone(),
            team_id: team_id.to_owned(),
            action_id: self.action_id.clone(),
            agent_id: parse_decimal(&self.agent)?,
            item_uuid: self.item.clone(),
            kind: ExceptionKind::parse(&self.exception.kind)?,
            created_at: self.exception.created_at,
            feed_seq: self.feed_seq,
            time: self.time,
        };
        (valid_uuid(&self.by)
            && valid_uuid(&self.to)
            && valid_item_ref(&self.item)
            && valid_qid(&self.action_id)
            && (1..=MAX_SEQ).contains(&self.feed_seq))
        .then_some(removal)
    }
}

/// What an action to remove an exception signs (section 9.3): the sender, the target,
/// the team, the action, the exception, the feed it saw, and the sender's clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalAction {
    pub by: String,
    pub to: String,
    pub team_id: String,
    pub action_id: String,
    pub agent_id: u64,
    pub item_uuid: String,
    pub kind: ExceptionKind,
    pub created_at: u64,
    pub feed_seq: u64,
    pub time: u64,
}

impl RemovalAction {
    /// The action string: eight lines joined with `\n`, no trailing newline. `None` when
    /// a field is empty or holds `:` or a control character.
    pub fn string(&self) -> Option<String> {
        let fields = [
            self.by.as_str(),
            self.to.as_str(),
            self.team_id.as_str(),
            self.action_id.as_str(),
            self.item_uuid.as_str(),
        ];
        if fields
            .iter()
            .any(|field| field.is_empty() || field.chars().any(|c| c == ':' || c.is_control()))
        {
            return None;
        }
        Some(format!(
            "{ACTION_TAG}\n{}\n{}\n{}\n{}\n{REMOVE_EXCEPTION}:{}:{}:{}:{}\n{}\n{}",
            self.by,
            self.to,
            self.team_id,
            self.action_id,
            self.agent_id,
            self.item_uuid,
            self.kind.as_str(),
            self.created_at,
            self.feed_seq,
            self.time
        ))
    }

    /// Whether removing this exception gives authority back: `never` and `always_ask`
    /// need the owner check (Face ID, the answer key); `only` takes authority away and
    /// is signed with the device key.
    pub fn gives_authority(&self) -> bool {
        self.kind != ExceptionKind::Only
    }
}

// ---- The settle (section 9.6). ----

/// How an action ended at the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    Refused,
    Stale,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Refused => "refused",
            Self::Stale => "stale",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "applied" => Some(Self::Applied),
            "refused" => Some(Self::Refused),
            "stale" => Some(Self::Stale),
            _ => None,
        }
    }
}

/// The plaintext of a settle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettleBody {
    pub v: u32,
    pub action_id: String,
    pub outcome: String,
    pub reason: String,
    #[serde(deserialize_with = "required")]
    pub feed_seq: Option<u64>,
    pub at: u64,
}

impl SettleBody {
    pub fn to_plaintext(&self) -> Option<Zeroizing<Vec<u8>>> {
        let bytes = Zeroizing::new(serde_json::to_vec(self).ok()?);
        (bytes.len() <= MAX_SETTLE_BYTES).then_some(bytes)
    }

    pub fn parse(plaintext: &[u8]) -> Option<Self> {
        if plaintext.len() > MAX_SETTLE_BYTES {
            return None;
        }
        let body: Self = serde_json::from_slice(plaintext).ok()?;
        (body.v == VERSION && Outcome::parse(&body.outcome).is_some()).then_some(body)
    }
}

// ---- The checks of the target (section 9.5). ----

/// An action that did not count: the outcome and the text of the failed step, for the
/// settle and Activity. Never a key, a value, or a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    pub outcome: Outcome,
    pub reason: &'static str,
}

const fn refused(reason: &'static str) -> Refusal {
    Refusal {
        outcome: Outcome::Refused,
        reason,
    }
}

const fn stale(reason: &'static str) -> Refusal {
    Refusal {
        outcome: Outcome::Stale,
        reason,
    }
}

pub const UNREADABLE: Refusal = refused("it could not be read");
pub const BAD_FORM: Refusal = refused("it has a bad form");
pub const OTHER_TARGET: Refusal = refused("it is for another Mac");
pub const NOT_A_DEVICE: Refusal = refused("the device is not an iPhone of this vault");
pub const TOO_OLD: Refusal = refused("too old");
pub const GONE: Refusal = stale("the agent or the credential is not on this Mac");
pub const BAD_SIGNATURE: Refusal = refused("its signature does not verify");
pub const CHANGED: Refusal = stale("the list on this Mac changed");
pub const LOCKED: Refusal = refused("the vault was locked during the check");
pub const NOT_REMOVED: Refusal = refused("the exception could not be removed");

/// This Mac as the target of the actions of one team.
#[derive(Debug, Clone)]
pub struct Target {
    pub team_id: String,
    /// The trusted device of this Mac.
    pub me: TrustedDevice,
    /// The relay device id of this Mac in the team.
    pub device_id: u64,
}

/// An action that passed steps 1 to 5: what it signs, its signature, and its sender.
#[derive(Debug, Clone)]
pub struct OpenedAction {
    pub removal: RemovalAction,
    pub signature: Vec<u8>,
    pub sender: TrustedDevice,
}

/// The time `time` is within the window around `now` (section 9.4).
pub fn in_window(time: u64, now: u64) -> bool {
    time.saturating_add(ACTION_WINDOW) >= now && time <= now.saturating_add(ACTION_WINDOW)
}

/// Steps 1 to 5 of section 9.5 at the clock `now`: the action opens with `key` and the
/// AAD of the stamped sender and this Mac, has exactly the fields of v1 and the relay's
/// `action_id`, is for this Mac, comes from a live iPhone of the vault whose device
/// number in the team (when set) is the stamped one, and is within its window.
/// `devices` are the live trusted devices of the vault.
pub fn open_action(
    record: &FeedActionRecord,
    target: &Target,
    key: Option<&QuestionKey>,
    devices: &[TrustedDevice],
    now: u64,
) -> Result<OpenedAction, Refusal> {
    let key = key.ok_or(UNREADABLE)?;
    let aad = action_aad(
        &target.team_id,
        &record.action_id,
        &record.key_id,
        record.from_device_id,
        target.device_id,
    );
    let plaintext = record.sealed().open(key, &aad).ok_or(UNREADABLE)?;
    let body = ActionBody::parse(&plaintext).ok_or(BAD_FORM)?;
    if body.action_id != record.action_id {
        return Err(BAD_FORM);
    }
    let removal = body.removal(&target.team_id).ok_or(BAD_FORM)?;
    let signature = decode_b64u(&body.signature)
        .filter(|signature| !signature.is_empty() && signature.len() <= 72)
        .ok_or(BAD_FORM)?;
    if removal.to != target.me.uuid {
        return Err(OTHER_TARGET);
    }
    let sender = devices
        .iter()
        .find(|device| {
            device.uuid == removal.by
                && device.kind == TrustedDeviceKind::Iphone
                && device
                    .relay_devices
                    .get(&target.team_id)
                    .is_none_or(|id| *id == record.from_device_id)
        })
        .cloned()
        .ok_or(NOT_A_DEVICE)?;
    if !in_window(removal.time, now) {
        return Err(TOO_OLD);
    }
    Ok(OpenedAction {
        removal,
        signature,
        sender,
    })
}

/// Step 9 of section 9.5: the action names a feed that this Mac published (at most
/// `last_seq`), and the row `(agent, item, kind)` is in `exceptions` with the
/// `created_at` that the feed showed.
pub fn still_shown(
    removal: &RemovalAction,
    item_id: u64,
    exceptions: &[AgentException],
    last_seq: u64,
) -> Result<(), Refusal> {
    let shown = removal.feed_seq <= last_seq
        && exceptions.iter().any(|exception| {
            exception.agent_id == removal.agent_id
                && exception.item_id == item_id
                && exception.kind == removal.kind
                && exception.created_at == removal.created_at
        });
    if shown { Ok(()) } else { Err(CHANGED) }
}

/// The words of an exception kind in Activity.
fn kind_words(kind: ExceptionKind) -> &'static str {
    match kind {
        ExceptionKind::Never => "“Not for this agent”",
        ExceptionKind::AlwaysAsk => "“Always ask for this agent”",
        ExceptionKind::Only => "“Only these items”",
    }
}

fn reason_of(error: &OwnerAuthError) -> Refusal {
    match error {
        OwnerAuthError::RemoteStale => TOO_OLD,
        OwnerAuthError::SessionChanged | OwnerAuthError::VaultLocked => LOCKED,
        _ => BAD_SIGNATURE,
    }
}

// ---- The publisher and the action handler, threads of the questions waiter. ----

/// The state of the feed of this Mac in the questions team of the open vault.
#[derive(Default)]
pub(super) struct FeedState {
    /// The team of the numbers below. Another team starts again.
    team_id: Option<String>,
    /// The highest `seq` that this Mac published in the team, once known: after a start
    /// it reads its own feed back first (section 8).
    last_seq: Option<u64>,
    /// When the relay took the last feed of this run.
    last_put: Option<Instant>,
    /// The digest of the last feed and its key, without `seq` and `generated_at`.
    last_digest: Option<[u8; 32]>,
    /// The change count and the session of the vault when the publisher last looked.
    seen: Option<(u64, [u8; 32])>,
    /// A change waits for the 10 s limit.
    dirty: bool,
    /// A feed that a network error left, with its `seq` and digest: sent again as it is.
    unsent: Option<(u64, Sealed, [u8; 32])>,
    tries: usize,
    next_try: Option<Instant>,
    /// `/v1/feed` answered `404`: no feed call before this time.
    unsupported_until: Option<Instant>,
    unsupported_logged: Option<String>,
    /// A Worker refused a feed body over 128 KiB: fit to 95 KiB until the next start.
    old_worker: bool,
    /// The relay may hold a feed of this Mac in the team: one landed in this run, or the
    /// read-back found one.
    live: bool,
    /// The feed must leave the relay (`DELETE /v1/feed`, section 10.5): the owner turned
    /// "Show agents on the iPhone" off, or the last iPhone left the vault.
    delete_pending: bool,
    /// The last action `seq` handled (section 10.7).
    after: u64,
    /// The action ids handled in the last 10 minutes, each marked before its first check:
    /// one id gets at most one settle.
    handled: HashMap<String, Instant>,
    /// The wait after an early empty answer of the action long poll, or after an answer
    /// whose every action was refused.
    early_wait: Option<Duration>,
    /// When Activity last said that actions could not be read.
    unreadable_logged: Option<Instant>,
}

impl FeedState {
    fn for_team(&mut self, team_id: &str) {
        if self.team_id.as_deref() != Some(team_id) {
            *self = Self {
                team_id: Some(team_id.to_owned()),
                handled: std::mem::take(&mut self.handled),
                old_worker: self.old_worker,
                unreadable_logged: self.unreadable_logged,
                ..Self::default()
            };
        }
    }

    fn unsupported(&self) -> bool {
        self.unsupported_until
            .is_some_and(|until| Instant::now() < until)
    }
}

/// What the publisher reads of the vault before it decides.
struct Look {
    iphone: bool,
    changes: u64,
    epoch: [u8; 32],
}

/// A small random jitter of up to a quarter of `wait`.
fn jitter(wait: Duration) -> Duration {
    let mut byte = [0u8; 1];
    let _ = getrandom::fill(&mut byte);
    wait + wait / 4 * u32::from(byte[0]) / 255
}

impl Shared {
    /// The session of the open vault when the feed is on for it.
    fn feed_session(&self) -> Option<Active> {
        if !self.config.feed || !self.feed_on.load(Ordering::SeqCst) {
            return None;
        }
        let active = lock(&self.state).active.clone()?;
        let mut feed = lock(&self.feed);
        feed.for_team(&active.team_id);
        (!feed.unsupported()).then_some(active)
    }

    /// Whether the vault has a live iPhone in the questions team, its change count, and
    /// its session. `None`: the vault is locked or is another one now.
    fn look(&self, active: &Active) -> Option<Look> {
        let mut guard = lock(&self.vault);
        let vault = Self::vault_of(&mut guard, active)?;
        let iphone = vault.trusted_devices().ok()?.iter().any(|device| {
            device.kind == TrustedDeviceKind::Iphone
                && (device.relay_devices.contains_key(&active.team_id)
                    || device.relay_devices.is_empty())
        });
        Some(Look {
            iphone,
            changes: vault.change_count().ok()?,
            epoch: vault.epoch(),
        })
    }

    /// One step of the publisher (section 8).
    pub(super) fn feed_step(&self) {
        let tick = self.config.tick.max(Duration::from_millis(50));
        if lock(&self.feed).delete_pending {
            self.delete_step(tick);
            return;
        }
        let Some(active) = self.feed_session() else {
            self.sleep(Duration::from_secs(1).min(tick * 4));
            return;
        };
        let Some(look) = self.look(&active) else {
            self.sleep(tick);
            return;
        };
        if !look.iphone {
            // The last iPhone left the vault: the feed leaves the relay.
            let mut feed = lock(&self.feed);
            if feed.live {
                feed.delete_pending = true;
            }
            drop(feed);
            self.sleep(tick);
            return;
        }
        let wait = {
            let mut feed = lock(&self.feed);
            let changed = feed.dirty || feed.seen != Some((look.changes, look.epoch));
            let beat = feed
                .last_put
                .is_none_or(|at| at.elapsed() >= self.config.feed_beat);
            let waiting = feed.next_try.is_some_and(|at| Instant::now() < at);
            if waiting || !(changed || beat || feed.unsent.is_some()) {
                Some(tick)
            } else if let Some(left) = feed.last_put.and_then(|at| {
                self.config
                    .feed_every
                    .checked_sub(at.elapsed())
                    .filter(|left| !left.is_zero())
            }) {
                // A change waits for the 10 s limit.
                feed.dirty |= changed;
                feed.seen = Some((look.changes, look.epoch));
                Some(left.min(tick))
            } else {
                feed.seen = Some((look.changes, look.epoch));
                feed.dirty = false;
                None
            }
        };
        if let Some(wait) = wait {
            self.sleep(wait);
            return;
        }
        let beat = lock(&self.feed)
            .last_put
            .is_none_or(|at| at.elapsed() >= self.config.feed_beat);
        self.publish_feed(&active, beat);
        self.sleep(tick);
    }

    /// A feed that must leave the relay: `DELETE /v1/feed` with the client of the
    /// session, again later when it fails for a reason that can pass.
    fn delete_step(&self, tick: Duration) {
        let active = lock(&self.state).active.clone();
        let Some(active) = active.filter(|_| self.config.feed) else {
            self.sleep(tick);
            return;
        };
        {
            let mut feed = lock(&self.feed);
            if feed.team_id.as_deref() != Some(active.team_id.as_str()) {
                // Another team now: the feed to delete was of the team before.
                feed.delete_pending = false;
                return;
            }
            if feed.next_try.is_some_and(|at| Instant::now() < at) {
                drop(feed);
                self.sleep(tick);
                return;
            }
        }
        if !self.delete_feed_now(&active) {
            back_off(&mut lock(&self.feed));
        }
        self.sleep(tick);
    }

    /// `DELETE /v1/feed` for the session `active`. True when the feed is gone or cannot
    /// be deleted at all (a relay without the feed answers `404`); false when it may
    /// work later.
    pub(super) fn delete_feed_now(&self, active: &Active) -> bool {
        let gone = match active.client.delete_feed() {
            Ok(()) => true,
            Err(error) => error.status() == Some(404) || !error.can_pass(),
        };
        if gone {
            let mut feed = lock(&self.feed);
            feed.delete_pending = false;
            feed.live = false;
            feed.last_put = None;
            feed.last_digest = None;
            feed.unsent = None;
            feed.dirty = false;
            feed.tries = 0;
            feed.next_try = None;
            drop(feed);
            lock(&self.view).feed_seq = None;
        }
        gone
    }

    /// Read the own feed back (`GET /v1/feed?since=0&wait=0`, following `more`): its
    /// `seq` and the digest of its envelope, or `(0, None)` when this Mac has none.
    /// `None`: the relay did not answer.
    fn own_feed(&self, active: &Active) -> Option<(u64, Option<[u8; 32]>)> {
        let me = active.client.device_id()?;
        let mut since = 0;
        let mut own: Option<FeedRecord> = None;
        for _ in 0..MAX_FEED_PAGES {
            let list = match active.client.feeds(since, Duration::ZERO) {
                Ok(list) => list,
                Err(error) => {
                    self.feed_error(active, &error);
                    return None;
                }
            };
            for feed in list.feeds.iter().filter(|feed| feed.device_id == me) {
                if own.as_ref().is_none_or(|own| feed.seq > own.seq) {
                    own = Some(feed.clone());
                }
            }
            match list.feeds.iter().map(|feed| feed.change).max() {
                Some(next) if list.more && next > since => since = next,
                _ => break,
            }
        }
        if own.is_some() {
            lock(&self.feed).live = true;
        }
        Some(own.map_or((0, None), |own| {
            (own.seq, Some(envelope_digest(&own.sealed())))
        }))
    }

    /// Build, fit, seal, and put the feed of the open vault. With `force`, also when its
    /// content did not change (the beat, an applied action). Returns the `seq` of the
    /// feed on the relay that shows the vault as it is now, if any.
    pub(super) fn publish_feed(&self, active: &Active, force: bool) -> Option<u64> {
        let _one = lock(&self.publishing);
        let device_id = active.client.device_id()?;
        let known = lock(&self.feed).last_seq;
        let mut last = match known {
            Some(last) => last,
            None => {
                let (last, _) = self.own_feed(active)?;
                lock(&self.feed).last_seq = Some(last);
                last
            }
        };
        // A body that a network error left goes again as it is.
        let unsent = lock(&self.feed).unsent.take();
        let mut prepared = None;
        if let Some((seq, sealed, digest)) = unsent {
            let current = {
                let mut guard = lock(&self.vault);
                Self::vault_of(&mut guard, active)
                    .and_then(|vault| vault.question_key().ok().flatten())
                    .map(|key| key.key_id())
            };
            if current.as_deref() == Some(sealed.key_id.as_str()) && seq > last {
                prepared = Some((seq, sealed, digest));
            }
        }
        for _ in 0..3 {
            let (seq, sealed, digest) = match prepared.take() {
                Some(ready) => ready,
                None => {
                    let built = self.seal_feed(active, device_id, last, force)?;
                    match built {
                        Sealing::Same => return Some(last),
                        Sealing::Ready(ready) => ready,
                    }
                }
            };
            match active.client.put_feed(seq, &sealed) {
                Ok(_) => return Some(self.feed_landed(seq, digest)),
                Err(error) if error.code() == Some("seq_not_newer") => {
                    // The first put may have landed: read the own feed back. It landed
                    // only when the relay holds this `seq` with this envelope.
                    let (own, landed) = self.own_feed(active)?;
                    if own == seq && landed == Some(envelope_digest(&sealed)) {
                        return Some(self.feed_landed(seq, digest));
                    }
                    // Another feed at or above this `seq`: a new one goes above it, also
                    // when the content did not change.
                    last = own.max(last);
                    let mut feed = lock(&self.feed);
                    feed.last_seq = Some(last);
                    feed.last_digest = None;
                }
                Err(error) if error.status() == Some(413) => {
                    let mut feed = lock(&self.feed);
                    if feed.old_worker {
                        feed.next_try = Some(Instant::now() + UNSUPPORTED_WAIT);
                        return None;
                    }
                    feed.old_worker = true;
                }
                Err(error) if error.code() == Some("feed_limit") => {
                    let mut feed = lock(&self.feed);
                    feed.dirty = true;
                    feed.next_try = Some(Instant::now() + self.config.feed_every);
                    return None;
                }
                Err(error) if error.can_pass() => {
                    let mut feed = lock(&self.feed);
                    back_off(&mut feed);
                    feed.unsent = Some((seq, sealed, digest));
                    return None;
                }
                Err(error) => {
                    self.feed_error(active, &error);
                    return None;
                }
            }
        }
        // Three answers in a row that did not land (`seq_not_newer`): the next try
        // waits, as after a put that failed, and the change is not lost.
        let mut feed = lock(&self.feed);
        back_off(&mut feed);
        feed.dirty = true;
        None
    }

    /// Build and seal the next feed with `seq = max(last + 1, now)`.
    fn seal_feed(
        &self,
        active: &Active,
        device_id: u64,
        last: u64,
        force: bool,
    ) -> Option<Sealing> {
        let now = unix_now();
        let seq = next_seq(last, now);
        let (mut feed, key) = {
            let mut guard = lock(&self.vault);
            let vault = Self::vault_of(&mut guard, active)?;
            let key = vault.question_key().ok().flatten()?;
            (build_feed(vault, &active.me, seq, now).ok()?, key)
        };
        let key_id = key.key_id();
        let digest = feed.content_digest(&key_id);
        let (same, old_worker) = {
            let feed = lock(&self.feed);
            (
                feed.last_digest == Some(digest) && feed.last_seq == Some(last),
                feed.old_worker,
            )
        };
        if same && !force {
            return Some(Sealing::Same);
        }
        let max = if old_worker {
            OLD_WORKER_FEED_BYTES
        } else {
            MAX_FEED_BYTES
        };
        let plaintext = fit(&mut feed, max, now)?;
        let aad = feed_aad(&active.team_id, device_id, seq, &key_id);
        let nonce = new_nonce()?;
        Some(Sealing::Ready((
            seq,
            Sealed::with_nonce(&key, &nonce, &aad, &plaintext),
            digest,
        )))
    }

    /// The relay took the feed `seq`.
    fn feed_landed(&self, seq: u64, digest: [u8; 32]) -> u64 {
        {
            let mut feed = lock(&self.feed);
            feed.last_seq = Some(seq);
            feed.last_put = Some(Instant::now());
            feed.last_digest = Some(digest);
            feed.live = true;
            feed.tries = 0;
            feed.next_try = None;
            feed.unsupported_until = None;
        }
        let mut view = lock(&self.view);
        let problem = view.feed_problem.is_some();
        view.feed_seq = Some(seq);
        view.feed_problem = None;
        drop(view);
        if problem {
            self.changed();
        }
        seq
    }

    /// A feed call failed for a reason that does not pass by itself.
    fn feed_error(&self, active: &Active, error: &QuestionsError) {
        if error.status() == Some(404) {
            self.feed_unsupported(active);
        } else if error.can_pass() {
            back_off(&mut lock(&self.feed));
        }
    }

    /// `/v1/feed` answered `404` (section 14.2): the loops wait 5 minutes, Settings says
    /// so, and Activity says it once for the team.
    fn feed_unsupported(&self, active: &Active) {
        let first = {
            let mut feed = lock(&self.feed);
            feed.unsupported_until = Some(Instant::now() + UNSUPPORTED_WAIT);
            let first = feed.unsupported_logged.as_deref() != Some(active.team_id.as_str());
            feed.unsupported_logged = Some(active.team_id.clone());
            first
        };
        lock(&self.view).feed_problem = Some(UNSUPPORTED.to_owned());
        if first {
            self.feed_activity(active, None, "Apassy", UNSUPPORTED);
        }
        self.changed();
    }

    fn feed_activity(&self, active: &Active, agent: Option<(u64, String)>, name: &str, line: &str) {
        let mut guard = lock(&self.vault);
        if let Some(vault) = Self::vault_of(&mut guard, active) {
            let (agent_id, agent_name) = match agent {
                Some((id, name)) => (Some(id), name),
                None => (None, name.to_owned()),
            };
            let _ = vault.record_activity(&NewActivity {
                agent_id,
                agent_name,
                item_id: None,
                operation: ACTIVITY_OPERATION.to_owned(),
                decision: ActivityDecision::Error,
                reason: line.to_owned(),
            });
        }
    }

    /// "Show agents on the iPhone" went off or on. Off: the publisher deletes the feed
    /// (`DELETE /v1/feed`, section 10.5) on its own thread, so the caller never waits for
    /// the relay. On: a delete that still waits goes, and the next feed goes at once.
    pub(super) fn feed_switched(&self, on: bool) {
        let mut feed = lock(&self.feed);
        feed.delete_pending = !on && self.config.feed;
        feed.last_put = None;
        feed.last_digest = None;
        feed.unsent = None;
        feed.next_try = None;
        feed.tries = 0;
    }

    /// The questions go off for the vault, or this Mac may no longer ask through the
    /// relay: its feed leaves the relay now, with the client of the session, once.
    pub(super) fn feed_stand_down(&self, active: &Active) {
        if self.config.feed {
            let _ = self.delete_feed_now(active);
            lock(&self.feed).delete_pending = false;
        }
    }

    // ---- The action handler. ----

    /// End the action long poll, so the handler plans again.
    pub(super) fn end_feed_poll(&self) {
        if let Some(cancel) = lock(&self.feed_poll).take() {
            cancel.close();
        }
    }

    /// One step of the action handler: one long poll of `GET /v1/feed/actions`, then at
    /// most [`ACTIONS_PER_ANSWER`] actions, each once, in `seq` order (section 9.5).
    pub(super) fn actions_step(&self) {
        let Some(active) = self.feed_session() else {
            self.sleep(Duration::from_secs(1));
            return;
        };
        // The relay keeps actions only for a device that has a feed.
        let (after, published) = {
            let feed = lock(&self.feed);
            (feed.after, feed.live && !feed.delete_pending)
        };
        if !published {
            self.sleep(Duration::from_millis(500));
            return;
        }
        let cancel = Arc::new(Cancel::default());
        *lock(&self.feed_poll) = Some(Arc::clone(&cancel));
        let started = Instant::now();
        let result = active
            .client
            .feed_actions_with(after, MAX_WAIT, Some(&cancel));
        {
            let mut poll = lock(&self.feed_poll);
            if poll.as_ref().is_some_and(|held| Arc::ptr_eq(held, &cancel)) {
                *poll = None;
            }
        }
        let list = match result {
            Ok(list) => list,
            Err(error) if error.status() == Some(404) => {
                self.feed_unsupported(&active);
                return;
            }
            Err(error) => {
                if !matches!(error, QuestionsError::Closed)
                    && !cancel.is_closed()
                    && !self.stop.load(Ordering::SeqCst)
                {
                    self.sleep(Duration::from_secs(2));
                }
                return;
            }
        };
        if list.seq < after {
            // A relay restored from a backup: read again from the start.
            lock(&self.feed).after = 0;
            return;
        }
        let mut actions = list.actions;
        actions.sort_by_key(|action| action.seq);
        if actions.is_empty() {
            let early = started.elapsed() + Duration::from_secs(2) < MAX_WAIT;
            if early {
                self.wait_early();
            } else {
                lock(&self.feed).early_wait = None;
            }
            return;
        }
        let mut opened = false;
        for record in actions
            .iter()
            .filter(|record| record.seq > after)
            .take(ACTIONS_PER_ANSWER)
        {
            match self.handle_action(&active, record) {
                // The vault locked during the check: the action stays after `after`,
                // and is checked again after the unlock.
                Handled::Aborted => {
                    self.sleep(Duration::from_millis(500));
                    return;
                }
                Handled::Opened => opened = true,
                Handled::Unopened | Handled::Seen => {}
            }
            let mut feed = lock(&self.feed);
            feed.after = feed.after.max(record.seq);
        }
        if opened {
            lock(&self.feed).early_wait = None;
        } else {
            // No action of the answer opened: only the relay or the path makes such a
            // list (actions that do not open, or ones handled before), and the Mac waits
            // as after an early empty answer before it asks again.
            self.wait_early();
        }
    }

    /// The wait after an early empty answer: 5 s, doubling to 60 s, with jitter.
    fn wait_early(&self) {
        let wait = {
            let mut feed = lock(&self.feed);
            let wait = feed
                .early_wait
                .map_or(EARLY_WAIT_FIRST, |wait| (wait * 2).min(EARLY_WAIT_MOST));
            feed.early_wait = Some(wait);
            wait
        };
        self.sleep(jitter(wait));
    }

    /// Check one action (section 9.5) and apply it when it passes; settle it. Its id is
    /// marked handled before the first step, so one id gets at most one settle; an action
    /// that the lock of the vault cut short is not marked and gets no settle.
    fn handle_action(&self, active: &Active, record: &FeedActionRecord) -> Handled {
        // 6. Once: a second time is nothing, with no second settle.
        {
            let mut feed = lock(&self.feed);
            feed.handled.retain(|_, at| at.elapsed() < HANDLED_FOR);
            if feed.handled.contains_key(&record.action_id) {
                return Handled::Seen;
            }
            feed.handled
                .insert(record.action_id.clone(), Instant::now());
        }
        let handled = self.check_action(active, record);
        if handled == Handled::Aborted {
            lock(&self.feed).handled.remove(&record.action_id);
        }
        handled
    }

    /// Steps 1 to 5 and 7 to 10 of section 9.5 for an action marked handled.
    fn check_action(&self, active: &Active, record: &FeedActionRecord) -> Handled {
        let Some(device_id) = active.client.device_id() else {
            return Handled::Aborted;
        };
        let (key, devices) = {
            let mut guard = lock(&self.vault);
            let Some(vault) = Self::vault_of(&mut guard, active) else {
                // Locked: the action is not handled now.
                return Handled::Aborted;
            };
            (
                vault.question_key().ok().flatten(),
                vault.trusted_devices().unwrap_or_default(),
            )
        };
        let target = Target {
            team_id: active.team_id.clone(),
            me: active.me.clone(),
            device_id,
        };
        // Steps 1 to 5.
        let opened = match open_action(record, &target, key.as_ref(), &devices, unix_now()) {
            Ok(opened) => opened,
            Err(refusal) if refusal == UNREADABLE => {
                // Anyone on the path can make an action that does not open: one Activity
                // line in 10 minutes, and a settle that the sender cannot open.
                self.unreadable_line(active);
                self.settle_action(
                    active,
                    record,
                    key.as_ref(),
                    refusal.outcome,
                    refusal.reason,
                    None,
                );
                return Handled::Unopened;
            }
            Err(refusal) => {
                // It opened: the device that it names, never the one the relay stamped.
                let name = named_sender(record, &target, key.as_ref(), &devices);
                return self.refuse_action(active, record, key.as_ref(), &name, None, refusal);
            }
        };
        let name = opened.sender.name.clone();
        let removal = &opened.removal;
        // 7. An agent of this vault on this Mac that is not revoked, and a live item.
        let resolved = {
            let mut guard = lock(&self.vault);
            let Some(vault) = Self::vault_of(&mut guard, active) else {
                return Handled::Aborted;
            };
            let agent = vault
                .list_agents()
                .ok()
                .and_then(|agents| {
                    agents
                        .into_iter()
                        .find(|agent| agent.id == removal.agent_id)
                })
                .filter(|agent| !agent.revoked);
            let item = vault.item_by_uuid(&removal.item_uuid).ok().flatten();
            agent.zip(item)
        };
        let Some((agent, item_id)) = resolved else {
            return self.refuse_action(active, record, key.as_ref(), &name, None, GONE);
        };
        let agent_line = Some((agent.id, agent.name.clone()));
        let action = OwnerAction::RemoveAgentException {
            agent_id: agent.id,
            item_id,
            kind: removal.kind,
        };
        // 8. The signature: through the owner gate for a removal that gives authority
        // back, with the device key for an `only` row.
        let proof = if removal.gives_authority() {
            let check = OwnerCheck::RemoteAction {
                signed: Box::new(removal.clone()),
                signature: opened.signature.clone(),
            };
            match self.gate.authorize(action.clone(), check) {
                Ok(proof) => Some(proof),
                Err(OwnerAuthError::SessionChanged | OwnerAuthError::VaultLocked) => {
                    return Handled::Aborted;
                }
                Err(error) => {
                    return self.refuse_action(
                        active,
                        record,
                        key.as_ref(),
                        &name,
                        agent_line,
                        reason_of(&error),
                    );
                }
            }
        } else {
            if let Err(error) =
                verify_remote_action(&opened.sender, removal, &opened.signature, unix_now())
            {
                return self.refuse_action(
                    active,
                    record,
                    key.as_ref(),
                    &name,
                    agent_line,
                    reason_of(&error),
                );
            }
            None
        };
        // 9 and 10 under one vault lock: the row as the feed showed it, then the removal
        // as the Mac's own "Remove exception" does after its owner check.
        let last_seq = lock(&self.feed).last_seq.unwrap_or(0);
        let done = {
            let mut guard = lock(&self.vault);
            let Some(vault) = Self::vault_of(&mut guard, active) else {
                return Handled::Aborted;
            };
            if let Some(proof) = &proof
                && proof.check(&action, &vault.epoch()).is_err()
            {
                return Handled::Aborted;
            }
            let exceptions = vault.agent_exceptions(agent.id).unwrap_or_default();
            still_shown(removal, item_id, &exceptions, last_seq).and_then(|()| {
                match vault.remove_agent_exception(agent.id, item_id, removal.kind) {
                    Ok(true) => {
                        let title = vault
                            .item_refs()
                            .ok()
                            .and_then(|refs| refs.get(&item_id).map(|r| r.title.clone()))
                            .unwrap_or_default();
                        let _ = vault.record_activity(&NewActivity {
                            agent_id: Some(agent.id),
                            agent_name: agent.name.clone(),
                            item_id: Some(item_id),
                            operation: ACTIVITY_OPERATION.to_owned(),
                            decision: ActivityDecision::Allow,
                            reason: format!(
                                "Removed on {name}: {} for {} and {title}",
                                kind_words(removal.kind),
                                agent.name
                            ),
                        });
                        if removal.gives_authority() {
                            let _ = vault.record_interaction(
                                InteractionKind::OwnerCheck,
                                &action.reason(),
                                &[item_id],
                            );
                        }
                        Ok(())
                    }
                    Ok(false) => Err(CHANGED),
                    Err(_) => Err(NOT_REMOVED),
                }
            })
        };
        if let Err(refusal) = done {
            return self.refuse_action(active, record, key.as_ref(), &name, agent_line, refusal);
        }
        // A new feed shows the result, as soon as the 10 s limit allows.
        let feed_seq = self.publish_after_action(active);
        self.settle_action(active, record, key.as_ref(), Outcome::Applied, "", feed_seq);
        self.changed();
        Handled::Opened
    }

    /// At most one Activity line in 10 minutes about actions that could not be read.
    fn unreadable_line(&self, active: &Active) {
        let due = {
            let mut feed = lock(&self.feed);
            let due = feed
                .unreadable_logged
                .is_none_or(|at| at.elapsed() >= UNREADABLE_LINE_EVERY);
            if due {
                feed.unreadable_logged = Some(Instant::now());
            }
            due
        };
        if due {
            self.feed_activity(active, None, "Apassy", UNREADABLE_LINE);
        }
    }

    /// Publish the feed after an applied action: wait for the 10 s limit, then put it.
    /// When the publisher put a feed with the result meanwhile, that feed's `seq`.
    fn publish_after_action(&self, active: &Active) -> Option<u64> {
        loop {
            let left = lock(&self.feed).last_put.and_then(|at| {
                self.config
                    .feed_every
                    .checked_sub(at.elapsed())
                    .filter(|left| !left.is_zero())
            });
            match left {
                None => break,
                Some(left) => {
                    std::thread::sleep(left.min(Duration::from_millis(200)));
                    if self.stop.load(Ordering::SeqCst) {
                        return None;
                    }
                }
            }
        }
        self.publish_feed(active, false)
    }

    /// An action that opened and did not count: Activity and a settle.
    fn refuse_action(
        &self,
        active: &Active,
        record: &FeedActionRecord,
        key: Option<&QuestionKey>,
        device: &str,
        agent: Option<(u64, String)>,
        refusal: Refusal,
    ) -> Handled {
        self.feed_activity(
            active,
            agent,
            "Apassy",
            &format!("An action from {device} did not count: {}.", refusal.reason),
        );
        self.settle_action(active, record, key, refusal.outcome, refusal.reason, None);
        Handled::Opened
    }

    /// Seal and post the settle of `record` under the current key, best effort.
    fn settle_action(
        &self,
        active: &Active,
        record: &FeedActionRecord,
        key: Option<&QuestionKey>,
        outcome: Outcome,
        reason: &str,
        feed_seq: Option<u64>,
    ) {
        let Some(key) = key else {
            return;
        };
        let body = SettleBody {
            v: VERSION,
            action_id: record.action_id.clone(),
            outcome: outcome.as_str().to_owned(),
            reason: clean(reason, MAX_REASON_BYTES),
            feed_seq,
            at: unix_now(),
        };
        let Some(plaintext) = body.to_plaintext() else {
            return;
        };
        let aad = settle_aad(
            &active.team_id,
            &record.action_id,
            &key.key_id(),
            outcome.as_str(),
        );
        let Some(sealed) = Sealed::new(key, &aad, &plaintext) else {
            return;
        };
        for _ in 0..2 {
            match active
                .client
                .settle_feed_action(&record.action_id, outcome.as_str(), &sealed)
            {
                Err(error) if error.can_pass() => continue,
                _ => break,
            }
        }
    }
}

/// What became of one action of an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Handled {
    /// It opened: applied, or settled `stale` or `refused`.
    Opened,
    /// It did not open: settled `refused`, with no Activity line of its own.
    Unopened,
    /// Its id was handled before: nothing, no second settle.
    Seen,
    /// The vault locked during the check: no settle; it is checked again after the
    /// unlock.
    Aborted,
}

/// The waits of the publisher after a call that failed for a reason that can pass.
fn back_off(feed: &mut FeedState) {
    let wait = RETRY_WAITS[feed.tries.min(RETRY_WAITS.len() - 1)];
    feed.tries += 1;
    feed.next_try = Some(Instant::now() + Duration::from_secs(wait));
}

/// The digest of an envelope as the relay holds it: its key, nonce, and ciphertext.
fn envelope_digest(sealed: &Sealed) -> [u8; 32] {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    for part in [&sealed.nonce, &sealed.ciphertext] {
        let bytes = decode_b64u(part).unwrap_or_else(|| part.as_bytes().to_vec());
        ctx.update(&(bytes.len() as u64).to_be_bytes());
        ctx.update(&bytes);
    }
    ctx.update(sealed.key_id.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// The name of the device that an action names in its `by`, when the action opens and
/// `by` is a device of the vault; else [`SOME_DEVICE`]. The device id that the relay
/// stamped never names it.
fn named_sender(
    record: &FeedActionRecord,
    target: &Target,
    key: Option<&QuestionKey>,
    devices: &[TrustedDevice],
) -> String {
    let aad = action_aad(
        &target.team_id,
        &record.action_id,
        &record.key_id,
        record.from_device_id,
        target.device_id,
    );
    key.and_then(|key| record.sealed().open(key, &aad))
        .and_then(|plaintext| serde_json::from_slice::<serde_json::Value>(&plaintext).ok())
        .and_then(|body| body.get("by")?.as_str().map(str::to_owned))
        .and_then(|by| devices.iter().find(|device| device.uuid == by))
        .map_or_else(|| SOME_DEVICE.to_owned(), |device| device.name.clone())
}

/// A sealed feed, or the same content as the last one.
enum Sealing {
    Same,
    Ready((u64, Sealed, [u8; 32])),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn the_aads_have_the_contract_bytes() {
        assert_eq!(
            hex(&feed_aad(
                "t_7k2m5q4x3c",
                2,
                1_790_000_040,
                "630dcd2966c43366"
            )),
            "6170617373792d666565642d7631006665656400745f376b326d357134783363003200313739303030303034300036333064636432393636633433333636"
        );
        assert_eq!(
            hex(&action_aad(
                "t_7k2m5q4x3c",
                "sLGys7S1tre4ubq7vL2-vw",
                "630dcd2966c43366",
                3,
                2
            )),
            "6170617373792d666565642d763100616374696f6e00745f376b326d35713478336300734c4779733753317472653475627137764c322d7677003633306463643239363663343333363600330032"
        );
        assert_eq!(
            hex(&settle_aad(
                "t_7k2m5q4x3c",
                "sLGys7S1tre4ubq7vL2-vw",
                "630dcd2966c43366",
                "applied"
            )),
            "6170617373792d666565642d763100736574746c6500745f376b326d35713478336300734c4779733753317472653475627137764c322d76770036333064636432393636633433333636006170706c696564"
        );
    }

    #[test]
    fn seq_goes_up_with_the_clock_and_after_the_last() {
        assert_eq!(next_seq(0, 1_790_000_040), 1_790_000_040);
        assert_eq!(next_seq(1_790_000_040, 1_790_000_040), 1_790_000_041);
        assert_eq!(next_seq(1_790_009_999, 1_790_000_040), 1_790_010_000);
        assert_eq!(next_seq(0, 0), 1);
        assert_eq!(next_seq(MAX_SEQ, MAX_SEQ + 5), MAX_SEQ);
    }

    #[test]
    fn the_window_is_sixty_seconds_both_ways() {
        let time = 1_790_000_060;
        assert!(in_window(time, 1_790_000_000));
        assert!(in_window(time, 1_790_000_120));
        assert!(!in_window(time, 1_790_000_121));
        assert!(!in_window(time, 1_789_999_999));
    }

    #[test]
    fn hosts_follow_the_agents_page() {
        assert_eq!(host_of("Claude Code"), "claude");
        assert_eq!(host_of("codex-cli"), "codex");
        assert_eq!(host_of("T3 Code"), "t3");
        assert_eq!(host_of("aider"), "other");
    }

    fn agent(id: u64, revoked: bool, last_use_at: Option<u64>, recent: usize) -> FeedAgent {
        FeedAgent {
            id: id.to_string(),
            name: format!("agent {id}"),
            host: "other".to_owned(),
            place: "mac".to_owned(),
            revoked,
            token_expires_at: 1,
            last_use_at,
            uses_this_week: 0,
            projects: Vec::new(),
            note: String::new(),
            restricted: false,
            actions: Vec::new(),
            exceptions: vec![FeedException {
                item: None,
                item_title: String::new(),
                kind: "never".to_owned(),
                created_at: 1,
            }],
            recent: (0..recent)
                .map(|at| FeedUse {
                    at: at as u64,
                    item: None,
                    item_title: String::new(),
                    action: "read".to_owned(),
                    project: String::new(),
                    command: "x".repeat(200),
                    outcome: "allowed".to_owned(),
                    decided_by: "bouncer".to_owned(),
                    answered_on: String::new(),
                })
                .collect(),
        }
    }

    fn feed(agents: Vec<FeedAgent>) -> Feed {
        Feed {
            v: 1,
            mac: FeedMac {
                device: "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d".to_owned(),
                name: "MacBook Pro".to_owned(),
            },
            seq: 5,
            generated_at: 5,
            truncated: false,
            week: FeedWeek {
                by_you: 0,
                automatic: 0,
            },
            agents,
        }
    }

    #[test]
    fn fitting_cuts_recent_then_revoked_then_the_oldest_agents() {
        let full = feed(vec![
            agent(1, false, Some(300), 20),
            agent(2, true, Some(200), 20),
            agent(3, false, Some(100), 20),
            agent(4, true, None, 20),
        ]);
        // Everything fits: nothing changes.
        let mut same = full.clone();
        assert!(fit(&mut same, MAX_FEED_BYTES, 400).is_some());
        assert_eq!(same, full);
        // Recent cut to 10 per agent.
        let mut cut = full.clone();
        let size_10 = {
            let mut probe = full.clone();
            probe.truncated = true;
            for agent in &mut probe.agents {
                agent.recent.truncate(10);
            }
            size(&probe)
        };
        let plaintext = fit(&mut cut, size_10, 400).unwrap();
        assert!(cut.truncated);
        assert!(cut.agents.iter().all(|agent| agent.recent.len() == 10));
        assert_eq!(cut.agents.len(), 4);
        assert_eq!(Feed::parse(&plaintext).unwrap(), cut);
        // Without recent at all and without the revoked agents.
        let mut small = full.clone();
        let mut probe = full.clone();
        probe.truncated = true;
        probe.agents.retain(|agent| !agent.revoked);
        for agent in &mut probe.agents {
            agent.recent.clear();
        }
        fit(&mut small, size(&probe), 400).unwrap();
        assert_eq!(small, probe);
        // One agent left: the newest.
        let mut one = full.clone();
        probe.agents.truncate(1);
        fit(&mut one, size(&probe), 400).unwrap();
        assert_eq!(one.agents.len(), 1);
        assert_eq!(one.agents[0].id, "1");
        // An exception list is never cut.
        let mut many = feed(vec![agent(9, false, Some(1), 0)]);
        many.agents[0].exceptions = vec![many.agents[0].exceptions[0].clone(); MAX_EXCEPTIONS + 1];
        fit(&mut many, MAX_FEED_BYTES, 400).unwrap();
        assert!(many.agents.is_empty() && many.truncated);
    }

    /// Section 14.2: behind a Worker older than the contract, the fitted feed's body of
    /// `PUT /v1/feed` (the b64u of its ciphertext and the other fields, with the longest
    /// `seq`) stays within the old Worker's 128 KiB.
    #[test]
    fn a_feed_fitted_for_an_old_worker_has_a_body_within_128_kib() {
        let agents = (1..=64)
            .map(|id| {
                let mut agent = agent(id, id % 3 == 0, Some(1_000 + id), 20);
                for recent in &mut agent.recent {
                    recent.command = "c".repeat(MAX_COMMAND_SUMMARY_BYTES);
                    recent.project = "p".repeat(MAX_PROJECT_BYTES);
                }
                agent
            })
            .collect();
        let mut full = feed(agents);
        full.seq = MAX_SEQ;
        assert!(size(&full) > OLD_WORKER_FEED_BYTES);
        let plaintext = fit(&mut full, OLD_WORKER_FEED_BYTES, 2_000).expect("it fits");
        assert!(plaintext.len() <= OLD_WORKER_FEED_BYTES);
        assert!(full.truncated);
        // The largest plaintext that fits, sealed: the body of the put.
        let key = QuestionKey::from_bytes([7; 32]);
        let largest = vec![b'x'; OLD_WORKER_FEED_BYTES];
        let sealed = Sealed::new(&key, b"aad", &largest).unwrap();
        let body = serde_json::to_vec(&serde_json::json!({
            "v": 1,
            "seq": MAX_SEQ,
            "key_id": sealed.key_id,
            "nonce": sealed.nonce,
            "ciphertext": sealed.ciphertext,
        }))
        .unwrap();
        assert!(body.len() <= 131_072, "{}", body.len());
    }

    #[test]
    fn item_references_have_one_form() {
        assert!(valid_item_ref("3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c"));
        for bad in [
            "3c9e1f7a-2b4d-4c6e-8f0a-1b3d5e7f9a2c",
            "3C9E1F7A2B4D4C6E8F0A1B3D5E7F9A2C",
            "7",
            "",
        ] {
            assert!(!valid_item_ref(bad), "{bad}");
        }
    }

    #[test]
    fn a_feed_with_an_unknown_or_missing_field_is_refused() {
        let good = feed(vec![agent(1, false, None, 1)]);
        let text = String::from_utf8(good.to_plaintext().to_vec()).unwrap();
        assert_eq!(Feed::parse(text.as_bytes()), Some(good.clone()));
        assert!(Feed::parse(text.replace(r#""truncated":false,"#, "").as_bytes()).is_none());
        assert!(
            Feed::parse(text.replace(r#""last_use_at":null,"#, "").as_bytes()).is_none(),
            "a null field must be present"
        );
        assert!(
            Feed::parse(
                text.replace(r#""truncated":false"#, r#""truncated":false,"x":1"#)
                    .as_bytes()
            )
            .is_none()
        );
        assert!(Feed::parse(text.replace(r#""v":1"#, r#""v":2"#).as_bytes()).is_none());
        assert!(
            Feed::parse(
                text.replace(r#""where":"mac""#, r#""where":"phone""#)
                    .as_bytes()
            )
            .is_none()
        );
    }

    #[test]
    fn the_action_string_refuses_a_colon_or_a_control_character() {
        let removal = RemovalAction {
            by: "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b".to_owned(),
            to: "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d".to_owned(),
            team_id: "t_7k2m5q4x3c".to_owned(),
            action_id: "sLGys7S1tre4ubq7vL2-vw".to_owned(),
            agent_id: 4,
            item_uuid: "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c".to_owned(),
            kind: ExceptionKind::Never,
            created_at: 1_789_990_000,
            feed_seq: 1_790_000_040,
            time: 1_790_000_060,
        };
        assert_eq!(removal.string().unwrap().len(), 222);
        let mut bad = removal.clone();
        bad.item_uuid = "a:b".to_owned();
        assert_eq!(bad.string(), None);
        let mut bad = removal;
        bad.team_id = "t\n".to_owned();
        assert_eq!(bad.string(), None);
    }
}
