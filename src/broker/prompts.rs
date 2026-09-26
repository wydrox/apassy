//! User requests from host hooks (goal item B6, ADR 0009 "A trusted user request").
//!
//! `apassy-hook` sends each user prompt of a Claude Code or Codex session to the
//! broker (`submit_user_request`). The broker keeps the newest prompt per agent and
//! host session in memory. A later run uses it as the user request:
//!
//! 1. A run with a host session (Claude Code gives it to `apassy-mcp`) uses the prompt
//!    of the same session.
//! 2. Otherwise the run uses the newest prompt of the agent whose host directory
//!    contains the run directory, or is inside it. Codex gives its MCP servers no
//!    session ID, so Codex runs always use this step.
//! 3. Without a hook prompt, the run uses the text from the agent, as before.
//!
//! A hook prompt replaces the agent text. If the two differ, the log and the approval
//! card show both. Before the broker trusts a hook prompt, it checks the host
//! transcript: the prompt must be the newest user message in the transcript file of
//! the same session, in a host transcript directory. A failed check is a rule flag,
//! so the owner decides.
//!
//! The hook runs in the same sandbox as the agent. An agent can run `apassy-hook`
//! itself, or write to the host transcript. The built-in rule pack `host-hooks`
//! (`packs/host-hooks.json`) makes a run with a command that names the hook channel wait
//! for the owner: the command analysis adds [`FLAG_HOOK_CHANNEL`]. See
//! `docs/operations/host-hooks.md` for what these checks do not stop.
//!
//! The prompts stay in memory. The broker writes a prompt only to the activity log
//! in the encrypted vault, and only when a run uses it.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::decide::{BrokerContext, authenticate, lock, locked_response};
use crate::agent::wire::{MAX_HOOK_PROMPT_BYTES, WireResponse};
use crate::vault::{ActivityDecision, NewActivity};

/// A hook prompt older than this is not used.
pub const MAX_AGE: Duration = Duration::from_secs(4 * 60 * 60);
/// The store keeps at most this many prompts. The oldest goes first.
pub const MAX_ENTRIES: usize = 256;
/// The broker reads at most this many bytes from the end of a transcript.
const MAX_TRANSCRIPT_SCAN: u64 = 16 * 1024 * 1024;
/// The host writes the transcript asynchronously. The check tries again this often.
const TRANSCRIPT_ATTEMPTS: u32 = 3;
const TRANSCRIPT_RETRY: Duration = Duration::from_millis(200);
const MAX_SESSION_BYTES: usize = 128;
const MAX_HOST_BYTES: usize = 32;
const MAX_PATH_BYTES: usize = 4096;
/// The activity reason has at most 700 bytes. The request gets this much of it.
const LOGGED_REQUEST_BYTES: usize = 240;
const LOGGED_AGENT_BYTES: usize = 120;
/// Open a transcript without a wait on a FIFO.
#[cfg(target_os = "macos")]
const O_NONBLOCK: i32 = 0x0004;
#[cfg(not(target_os = "macos"))]
const O_NONBLOCK: i32 = 0o4000;

/// Rule flag: the hook prompt is not the newest user message in the host transcript.
pub const FLAG_UNVERIFIED: &str = "hook_unverified";
/// Rule flag: hook prompts from more than one host session match the run.
pub const FLAG_AMBIGUOUS: &str = "hook_ambiguous";
/// Rule flag: the command names the hook program, the host settings, or a transcript.
/// The rules are in the built-in pack `host-hooks`. The host settings hold the hook
/// configuration. `.claude/projects` and `.codex/sessions` hold the transcripts.
pub const FLAG_HOOK_CHANNEL: &str = "hook_channel";

/// Newest hook prompts, in memory.
pub struct PromptStore {
    entries: Mutex<Vec<Entry>>,
    /// Host transcript directories. A transcript outside them is not trusted.
    transcript_roots: Vec<PathBuf>,
}

impl std::fmt::Debug for PromptStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PromptStore")
            .field("transcript_roots", &self.transcript_roots)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct Entry {
    agent_id: u64,
    /// Vault session of the submit. A lock, an unlock, or a restore ends its use.
    epoch: [u8; 32],
    host: String,
    session: Option<String>,
    cwd: PathBuf,
    prompt: String,
    transcript: Option<PathBuf>,
    truncated: bool,
    received: Instant,
}

/// `$HOME/.claude/projects` and `$HOME/.codex/sessions`, and the same directories
/// under `CLAUDE_CONFIG_DIR` and `CODEX_HOME` when they are set.
pub fn default_transcript_roots() -> Vec<PathBuf> {
    let var = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty());
    let mut roots = Vec::new();
    if let Some(home) = var("HOME").map(PathBuf::from) {
        roots.push(home.join(".claude").join("projects"));
        roots.push(home.join(".codex").join("sessions"));
    }
    if let Some(dir) = var("CLAUDE_CONFIG_DIR") {
        roots.push(PathBuf::from(dir).join("projects"));
    }
    if let Some(dir) = var("CODEX_HOME") {
        roots.push(PathBuf::from(dir).join("sessions"));
    }
    roots
}

/// A `submit_user_request` action from the wire.
#[derive(Debug)]
pub(super) struct Submission<'a> {
    pub host: &'a str,
    pub host_session: Option<&'a str>,
    pub cwd: &'a str,
    pub prompt: &'a str,
    pub transcript_path: Option<&'a str>,
    pub truncated: bool,
}

impl Submission<'_> {
    fn validate(&self) -> Result<(), &'static str> {
        let host_ok = !self.host.is_empty()
            && self.host.len() <= MAX_HOST_BYTES
            && self
                .host
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !host_ok {
            return Err("The host name is not valid.");
        }
        if let Some(session) = self.host_session {
            let session_ok = !session.is_empty()
                && session.len() <= MAX_SESSION_BYTES
                && session
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
            if !session_ok {
                return Err("The host session ID is not valid.");
            }
        }
        let path_ok = |path: &str| {
            path.starts_with('/') && path.len() <= MAX_PATH_BYTES && !path.contains('\0')
        };
        if !path_ok(self.cwd) {
            return Err("The host directory must be an absolute path.");
        }
        if self.transcript_path.is_some_and(|path| !path_ok(path)) {
            return Err("The transcript path must be an absolute path.");
        }
        if self.prompt.trim().is_empty()
            || self.prompt.len() > MAX_HOOK_PROMPT_BYTES
            || self.prompt.contains('\0')
        {
            return Err("The user prompt is empty, too long, or has a NUL byte.");
        }
        Ok(())
    }
}

/// Store the user prompt from a host hook. The prompt is not in the activity log.
pub(super) fn submit(
    ctx: &BrokerContext,
    token: &str,
    submission: &Submission<'_>,
) -> WireResponse {
    const OPERATION: &str = "user request from a host hook";
    let (agent_id, epoch) = {
        let mut guard = lock(&ctx.vault);
        let Some(vault) = guard.as_mut().filter(|vault| !vault.is_locked()) else {
            return locked_response();
        };
        let agent = match authenticate(vault, token, OPERATION) {
            Ok(agent) => agent,
            Err(response) => return response,
        };
        if let Err(reason) = submission.validate() {
            let _ = vault.record_activity(&NewActivity {
                agent_id: Some(agent.id),
                agent_name: agent.name.clone(),
                item_id: None,
                operation: OPERATION.to_owned(),
                decision: ActivityDecision::Deny,
                reason: reason.to_owned(),
            });
            return WireResponse::failure("invalid_request", reason);
        }
        (agent.id, vault.epoch())
    };
    let cwd = fs::canonicalize(submission.cwd).unwrap_or_else(|_| PathBuf::from(submission.cwd));
    ctx.prompts.insert(Entry {
        agent_id,
        epoch,
        host: submission.host.to_owned(),
        session: submission.host_session.map(str::to_owned),
        cwd,
        prompt: submission.prompt.to_owned(),
        transcript: submission.transcript_path.map(PathBuf::from),
        truncated: submission.truncated,
        received: Instant::now(),
    });
    WireResponse::success(json!({ "stored": true }))
}

/// The user request of one run, with its source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Resolved {
    /// The user request for the bouncer and the owner. Empty when there is none.
    pub text: String,
    /// Where the text comes from, for example "from the agent". The approval card
    /// and the activity log show it.
    pub source: String,
    /// The agent text, when a hook prompt replaced it and the two differ.
    pub agent_text: Option<String>,
    /// Rule flags: [`FLAG_UNVERIFIED`], [`FLAG_AMBIGUOUS`].
    pub flags: Vec<String>,
}

impl Resolved {
    /// Text for the activity log. The log is in the encrypted vault.
    pub fn log_note(&self) -> String {
        if self.text.is_empty() {
            return "No user request.".to_owned();
        }
        let mut note = format!(
            "User request {}: \"{}\".",
            self.source,
            bounded(&self.text, LOGGED_REQUEST_BYTES)
        );
        if let Some(agent) = &self.agent_text {
            note.push_str(&format!(
                " The agent sent: \"{}\".",
                bounded(agent, LOGGED_AGENT_BYTES)
            ));
        }
        note
    }
}

/// How the run found the hook prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchedBy {
    Session,
    Directory,
}

/// The result of the transcript check.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Check {
    Verified,
    NoTranscript,
    Failed(&'static str),
}

impl PromptStore {
    pub fn new(transcript_roots: Vec<PathBuf>) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            transcript_roots,
        }
    }

    fn entries(&self) -> MutexGuard<'_, Vec<Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Number of stored prompts.
    pub fn len(&self) -> usize {
        self.entries().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove every prompt. The desktop app can call this after a lock.
    pub fn clear(&self) {
        self.entries().clear();
    }

    /// Keep the newest prompt per agent and session. Without a session, per agent and
    /// directory.
    fn insert(&self, entry: Entry) {
        let mut entries = self.entries();
        let now = entry.received;
        entries.retain(|old| {
            let same_key = old.agent_id == entry.agent_id
                && old.session == entry.session
                && (entry.session.is_some() || old.cwd == entry.cwd);
            !same_key && now.saturating_duration_since(old.received) < MAX_AGE
        });
        entries.push(entry);
        if entries.len() > MAX_ENTRIES {
            let extra = entries.len() - MAX_ENTRIES;
            // Entries are in the order of arrival.
            entries.drain(..extra);
        }
    }

    /// Find the user request of a run. `cwd` is the canonical run directory.
    pub(super) fn resolve(
        &self,
        agent_id: u64,
        epoch: &[u8; 32],
        host_session: Option<&str>,
        cwd: &Path,
        agent_text: &str,
    ) -> Resolved {
        self.resolve_at(
            agent_id,
            epoch,
            host_session,
            cwd,
            agent_text,
            Instant::now(),
        )
    }

    fn resolve_at(
        &self,
        agent_id: u64,
        epoch: &[u8; 32],
        host_session: Option<&str>,
        cwd: &Path,
        agent_text: &str,
        now: Instant,
    ) -> Resolved {
        let agent_text = agent_text.trim();
        let Some((entry, matched_by, ambiguous)) =
            self.find(agent_id, epoch, host_session, cwd, now)
        else {
            let source = if host_session.is_some() {
                "from the agent, no hook request for this host session"
            } else {
                "from the agent"
            };
            return Resolved {
                text: agent_text.to_owned(),
                source: source.to_owned(),
                agent_text: None,
                flags: Vec::new(),
            };
        };
        let check = self.check_transcript(&entry);
        let mut flags = Vec::new();
        let result = match check {
            Check::Verified => "verified in the host transcript".to_owned(),
            Check::NoTranscript => "no host transcript to check".to_owned(),
            Check::Failed(reason) => {
                flags.push(FLAG_UNVERIFIED.to_owned());
                format!("NOT verified: {reason}")
            }
        };
        if ambiguous {
            flags.push(FLAG_AMBIGUOUS.to_owned());
        }
        let matched = match matched_by {
            MatchedBy::Session => "",
            MatchedBy::Directory => ", matched by the project directory",
        };
        let text = entry.prompt.trim().to_owned();
        let differs = !agent_text.is_empty() && agent_text != text;
        Resolved {
            source: format!(
                "from the {} hook{matched}, {result}",
                host_label(&entry.host)
            ),
            agent_text: differs.then(|| agent_text.to_owned()),
            text,
            flags,
        }
    }

    /// The hook prompt for a run, how it matched, and whether another session has a
    /// competing prompt.
    fn find(
        &self,
        agent_id: u64,
        epoch: &[u8; 32],
        host_session: Option<&str>,
        cwd: &Path,
        now: Instant,
    ) -> Option<(Entry, MatchedBy, bool)> {
        let entries = self.entries();
        let live = || {
            entries.iter().filter(|entry| {
                entry.agent_id == agent_id
                    && entry.epoch == *epoch
                    && now.saturating_duration_since(entry.received) < MAX_AGE
            })
        };
        let by_directory: Vec<&Entry> = live()
            .filter(|entry| cwd.starts_with(&entry.cwd) || entry.cwd.starts_with(cwd))
            .collect();
        if let Some(session) = host_session
            && let Some(own) = live()
                .filter(|entry| entry.session.as_deref() == Some(session))
                .max_by_key(|entry| entry.received)
        {
            // A newer prompt from another session in the same directory can mean that
            // this session is stale, for example after `/clear` in Claude Code.
            let competing = by_directory
                .iter()
                .any(|entry| entry.session != own.session && entry.received > own.received);
            return Some((own.clone(), MatchedBy::Session, competing));
        }
        let chosen = by_directory
            .iter()
            .max_by_key(|entry| entry.received)
            .copied()?;
        let sessions: BTreeSet<&Option<String>> =
            by_directory.iter().map(|entry| &entry.session).collect();
        Some((chosen.clone(), MatchedBy::Directory, sessions.len() > 1))
    }

    /// The hook prompt must be the newest user message in the transcript file of its
    /// session, in a host transcript directory.
    fn check_transcript(&self, entry: &Entry) -> Check {
        let Some(path) = &entry.transcript else {
            return Check::NoTranscript;
        };
        let Ok(path) = fs::canonicalize(path) else {
            return Check::Failed("the transcript file does not exist");
        };
        let inside = self
            .transcript_roots
            .iter()
            .filter_map(|root| fs::canonicalize(root).ok())
            .any(|root| path.starts_with(root));
        if !inside {
            return Check::Failed("the transcript is not in a host transcript directory");
        }
        if let Some(session) = &entry.session {
            let named = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(&format!("{session}.jsonl")));
            if !named {
                return Check::Failed("the transcript file is not for this session");
            }
        }
        for attempt in 0..TRANSCRIPT_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(TRANSCRIPT_RETRY);
            }
            match newest_user_prompt(&path) {
                Err(reason) => return Check::Failed(reason),
                Ok(Some(text)) if same_prompt(&text, &entry.prompt, entry.truncated) => {
                    return Check::Verified;
                }
                Ok(_) => {}
            }
        }
        Check::Failed("the prompt is not the newest user message in the transcript")
    }
}

fn host_label(host: &str) -> &'static str {
    match host {
        "claude-code" => "Claude Code",
        "codex" => "Codex",
        _ => "host",
    }
}

fn same_prompt(transcript: &str, prompt: &str, truncated: bool) -> bool {
    let transcript = transcript.trim();
    let prompt = prompt.trim();
    if truncated {
        transcript.starts_with(prompt)
    } else {
        transcript == prompt
    }
}

/// The newest user prompt in a host transcript (JSON lines). `Ok(None)` when the
/// scanned part has none.
fn newest_user_prompt(path: &Path) -> Result<Option<String>, &'static str> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(path)
        .map_err(|_| "the transcript cannot be read")?;
    let meta = file
        .metadata()
        .map_err(|_| "the transcript cannot be read")?;
    if !meta.is_file() {
        return Err("the transcript is not a regular file");
    }
    let start = meta.len().saturating_sub(MAX_TRANSCRIPT_SCAN);
    let tail = read_from(&mut file, start).map_err(|_| "the transcript cannot be read")?;
    let mut lines: Vec<&[u8]> = tail.split(|byte| *byte == b'\n').collect();
    if start > 0 && !lines.is_empty() {
        // The first line of a tail is only a part of a line.
        lines.remove(0);
    }
    Ok(lines
        .iter()
        .rev()
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .find_map(|line| user_prompt(&line)))
}

fn read_from(file: &mut File, start: u64) -> std::io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.take(MAX_TRANSCRIPT_SCAN).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The text of a user prompt record, measured on the host versions in
/// `docs/operations/host-hooks.md`. Tool results, meta records, and records of
/// subagents are not user prompts.
///
/// - Claude Code: `{"type":"user","message":{"role":"user","content":"..."}}`. The
///   content can also be a list of blocks.
/// - Codex: `{"type":"event_msg","payload":{"type":"item_completed","item":{"type":"UserMessage","content":[{"type":"text","text":"..."}]}}}`.
fn user_prompt(line: &Value) -> Option<String> {
    let kind = line.get("type").and_then(Value::as_str);
    let flag = |name: &str| line.get(name).and_then(Value::as_bool) == Some(true);
    if kind == Some("user") {
        if flag("isMeta") || flag("isSidechain") || flag("isCompactSummary") {
            return None;
        }
        let message = line.get("message")?;
        if message.get("role").and_then(Value::as_str) != Some("user") {
            return None;
        }
        return match message.get("content")? {
            Value::String(text) => Some(text.clone()),
            Value::Array(blocks) => {
                let tool_result = blocks
                    .iter()
                    .any(|block| block.get("type").and_then(Value::as_str) == Some("tool_result"));
                if tool_result {
                    None
                } else {
                    block_text(blocks)
                }
            }
            _ => None,
        };
    }
    let payload = line.get("payload")?;
    let item = payload.get("item")?;
    let user_message = kind == Some("event_msg")
        && payload.get("type").and_then(Value::as_str) == Some("item_completed")
        && item.get("type").and_then(Value::as_str) == Some("UserMessage");
    if !user_message {
        return None;
    }
    block_text(item.get("content")?.as_array()?)
}

/// The text blocks of a message, joined with a newline.
fn block_text(blocks: &[Value]) -> Option<String> {
    let texts: Vec<&str> = blocks
        .iter()
        .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|block| block.get("text").and_then(Value::as_str))
        .collect();
    (!texts.is_empty()).then(|| texts.join("\n"))
}

/// The hook channel check before goal item B7. The rule is now data: the built-in pack
/// `host-hooks` (`packs/host-hooks.json`). The command analysis adds
/// [`FLAG_HOOK_CHANNEL`] for such a command on every run (`shell_risk::analyze`), so this
/// function gives no second flag. It stays only for its call in `run.rs`; remove both
/// together.
pub(super) fn hook_channel_flag(_command: &[String]) -> Option<String> {
    None
}

/// The first `max` bytes of `text` at a character boundary, with "..." when cut.
fn bounded(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    const EPOCH: [u8; 32] = [7; 32];
    /// Test time in seconds after a fixed start. A later second is a newer prompt.
    const NOW: u64 = 100;

    fn at(second: u64) -> Instant {
        static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        *START.get_or_init(Instant::now) + Duration::from_secs(second)
    }

    fn entry(session: Option<&str>, cwd: &str, prompt: &str, second: u64) -> Entry {
        Entry {
            agent_id: 1,
            epoch: EPOCH,
            host: "claude-code".to_owned(),
            session: session.map(str::to_owned),
            cwd: PathBuf::from(cwd),
            prompt: prompt.to_owned(),
            transcript: None,
            truncated: false,
            received: at(second),
        }
    }

    fn store() -> PromptStore {
        PromptStore::new(Vec::new())
    }

    fn resolve(store: &PromptStore, session: Option<&str>, cwd: &str, agent: &str) -> Resolved {
        store.resolve_at(1, &EPOCH, session, Path::new(cwd), agent, at(NOW))
    }

    #[test]
    fn a_session_match_wins_and_replaces_the_agent_text() {
        let store = store();
        store.insert(entry(Some("s1"), "/p", "Fix the tests.", 10));
        store.insert(entry(Some("s1"), "/p", "Run the migration.", 20));
        assert_eq!(store.len(), 1, "one prompt per agent and session");
        let resolved = resolve(&store, Some("s1"), "/p/sub", "Deploy all.");
        assert_eq!(resolved.text, "Run the migration.");
        assert_eq!(resolved.agent_text.as_deref(), Some("Deploy all."));
        assert!(resolved.source.contains("Claude Code hook"));
        assert!(resolved.source.contains("no host transcript"));
        assert!(resolved.flags.is_empty());
        let note = resolved.log_note();
        assert!(note.contains("\"Run the migration.\""), "{note}");
        assert!(note.contains("The agent sent: \"Deploy all.\""), "{note}");
        // The same text from the agent is not a difference.
        let same = resolve(&store, Some("s1"), "/p", "Run the migration.");
        assert!(same.agent_text.is_none());
    }

    #[test]
    fn other_agents_epochs_and_old_prompts_do_not_match() {
        let store = store();
        store.insert(entry(Some("s1"), "/p", "Old.", 0));
        let mut other = entry(Some("s2"), "/p", "Other agent.", 50);
        other.agent_id = 2;
        store.insert(other);
        let mut locked = entry(Some("s3"), "/p", "Before a lock.", 50);
        locked.epoch = [8; 32];
        store.insert(locked);
        assert_eq!(resolve(&store, Some("s1"), "/p", "").text, "Old.");
        let late = at(MAX_AGE.as_secs() + 1);
        let resolved =
            store.resolve_at(1, &EPOCH, Some("s1"), Path::new("/p"), "Agent text.", late);
        assert_eq!(resolved.text, "Agent text.");
        assert!(resolved.source.starts_with("from the agent"));
        let none = resolve(&store, None, "/elsewhere", "");
        assert_eq!(none.log_note(), "No user request.");
        // A later submit removes prompts older than the maximum age.
        let mut fresh = entry(Some("s4"), "/q", "New.", MAX_AGE.as_secs() + 1);
        fresh.agent_id = 3;
        store.insert(fresh);
        assert_eq!(store.len(), 3);
    }

    #[test]
    fn directory_match_for_hosts_without_a_session() {
        let store = store();
        store.insert(entry(Some("c1"), "/work/app", "Check the build.", 10));
        let resolved = resolve(&store, None, "/work/app/web", "");
        assert_eq!(resolved.text, "Check the build.");
        assert!(resolved.source.contains("matched by the project directory"));
        assert!(resolved.flags.is_empty());
        // A run in another project does not use this prompt.
        let other = resolve(&store, None, "/work/other", "Agent.");
        assert_eq!(other.text, "Agent.");
    }

    #[test]
    fn competing_sessions_are_ambiguous() {
        let store = store();
        store.insert(entry(Some("a"), "/p", "Old session.", 10));
        store.insert(entry(Some("b"), "/p", "New session.", 90));
        // Session "a" has a prompt, but session "b" in the same directory is newer.
        let stale = resolve(&store, Some("a"), "/p", "");
        assert_eq!(stale.text, "Old session.");
        assert_eq!(stale.flags, vec![FLAG_AMBIGUOUS.to_owned()]);
        let fresh = resolve(&store, Some("b"), "/p", "");
        assert!(fresh.flags.is_empty());
        // Without a session, two sessions in one directory are ambiguous.
        let codex = resolve(&store, None, "/p", "");
        assert_eq!(codex.text, "New session.");
        assert_eq!(codex.flags, vec![FLAG_AMBIGUOUS.to_owned()]);
    }

    #[test]
    fn the_store_is_bounded() {
        let store = store();
        for n in 0..(MAX_ENTRIES + 10) {
            store.insert(entry(Some(&format!("s{n}")), "/p", "x", 10));
        }
        assert_eq!(store.len(), MAX_ENTRIES);
        let first = resolve(&store, Some("s0"), "/elsewhere", "");
        assert!(
            first.source.starts_with("from the agent"),
            "the oldest went first"
        );
        store.clear();
        assert!(store.is_empty());
    }

    fn transcript(dir: &Path, name: &str, lines: &[Value]) -> PathBuf {
        let path = dir.join(name);
        let mut file = File::create(&path).expect("transcript");
        for line in lines {
            writeln!(file, "{line}").expect("write");
        }
        path
    }

    fn claude_user(text: &str) -> Value {
        json!({"type": "user", "sessionId": "s1", "message": {"role": "user", "content": text}})
    }

    #[test]
    fn transcript_check() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("projects");
        fs::create_dir_all(root.join("-p")).expect("root");
        let store = PromptStore::new(vec![root.clone()]);
        let lines = [
            claude_user("An older prompt."),
            json!({"type": "user", "isMeta": true, "message": {"role": "user", "content": "Caveat."}}),
            claude_user("Run the checks."),
            json!({"type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": "OK"}]}}),
            json!({"type": "user", "message": {"role": "user", "content": [{"type": "tool_result", "content": "done"}]}}),
        ];
        let path = transcript(&root.join("-p"), "s1.jsonl", &lines);
        let mut good = entry(Some("s1"), "/p", "Run the checks.", 10);
        good.transcript = Some(path.clone());
        assert_eq!(store.check_transcript(&good), Check::Verified);

        // An older prompt is not the newest user message: a replay fails.
        let mut replay = good.clone();
        replay.prompt = "An older prompt.".to_owned();
        assert!(matches!(store.check_transcript(&replay), Check::Failed(_)));
        // A prompt that the user did not write fails.
        let mut forged = good.clone();
        forged.prompt = "Deploy production.".to_owned();
        assert!(matches!(store.check_transcript(&forged), Check::Failed(_)));
        // A cut prompt matches the start of the transcript text.
        let mut cut = good.clone();
        cut.prompt = "Run the".to_owned();
        cut.truncated = true;
        assert_eq!(store.check_transcript(&cut), Check::Verified);
        // The file name must be the session.
        let mut other_session = good.clone();
        other_session.session = Some("s2".to_owned());
        assert_eq!(
            store.check_transcript(&other_session),
            Check::Failed("the transcript file is not for this session")
        );
        // A transcript outside the host directories is not trusted.
        let outside = transcript(dir.path(), "s1.jsonl", &lines);
        let mut elsewhere = good.clone();
        elsewhere.transcript = Some(outside);
        assert_eq!(
            store.check_transcript(&elsewhere),
            Check::Failed("the transcript is not in a host transcript directory")
        );
        let mut missing = good;
        missing.transcript = Some(root.join("-p").join("absent-s1.jsonl"));
        assert!(matches!(store.check_transcript(&missing), Check::Failed(_)));
    }

    #[test]
    fn codex_transcript_records() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("sessions");
        fs::create_dir_all(&root).expect("root");
        let item = |text: &str| {
            json!({"type": "event_msg", "payload": {"type": "item_completed", "thread_id": "t1",
                "item": {"type": "UserMessage", "content": [{"type": "text", "text": text}]}}})
        };
        let lines = [
            item("First."),
            // Codex also writes context as user messages. They are not prompts.
            json!({"type": "response_item", "payload": {"type": "message", "role": "user",
                "content": [{"type": "input_text", "text": "<environment_context/>"}]}}),
            item("Deploy staging."),
            json!({"type": "response_item", "payload": {"type": "message", "role": "user",
                "content": [{"type": "input_text", "text": "<turn_context/>"}]}}),
        ];
        let path = transcript(&root, "rollout-2026-09-26T02-32-47-t1.jsonl", &lines);
        assert_eq!(
            newest_user_prompt(&path).expect("read"),
            Some("Deploy staging.".to_owned())
        );
        let store = PromptStore::new(vec![root]);
        let mut codex = entry(Some("t1"), "/p", "Deploy staging.", 10);
        codex.host = "codex".to_owned();
        codex.transcript = Some(path);
        assert_eq!(store.check_transcript(&codex), Check::Verified);
    }

    /// The `host-hooks` pack in the command analysis flags the hook channel, and the old
    /// check in this file gives no second flag.
    #[test]
    fn hook_channel_commands_are_flagged() {
        let flagged = |args: &[&str]| {
            let command: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
            assert_eq!(hook_channel_flag(&command), None);
            let analysis = crate::broker::shell_risk::analyze(&command, "", &[]);
            analysis.flags.iter().any(|flag| flag == FLAG_HOOK_CHANNEL)
        };
        assert!(flagged(&[
            "sh",
            "-c",
            "echo {} | /usr/local/bin/apassy-hook"
        ]));
        assert!(flagged(&["cat", "/Users/me/.claude/projects/-p/s1.jsonl"]));
        assert!(flagged(&["sh", "-c", "cd ~/.claude && ls"]));
        assert!(flagged(&["cp", "x.json", "/Users/me/.claude.json"]));
        assert!(flagged(&["ls", "/Users/me/.codex/sessions"]));
        assert!(flagged(&[
            "sh",
            "-c",
            "echo x >> \"$CODEX_HOME/hooks.json\""
        ]));
        assert!(flagged(&["sh", "-c", "cd $HOME/.codex; cat config.toml"]));
        assert!(flagged(&["sh", "-c", "cat ~/.cla\"\"ude/projects/x.jsonl"]));
        assert!(flagged(&[
            "env",
            "CLAUDE_CONFIG_DIR=/tmp/c",
            "claude",
            "-p",
            "hi"
        ]));
        assert!(!flagged(&["npm", "run", "migrate"]));
        assert!(!flagged(&["cat", "CLAUDE.md", "docs/codex-notes.md"]));
    }

    #[test]
    fn submission_validation() {
        let good = Submission {
            host: "claude-code",
            host_session: Some("1dbe1639-f522-4744-a3dc-7a76626af241"),
            cwd: "/p",
            prompt: "Fix it.",
            transcript_path: Some("/t/x.jsonl"),
            truncated: false,
        };
        assert!(good.validate().is_ok());
        for bad in [
            Submission {
                host: "Claude Code",
                ..good
            },
            Submission {
                host_session: Some("../x"),
                ..good
            },
            Submission { cwd: "p", ..good },
            Submission {
                transcript_path: Some("x.jsonl"),
                ..good
            },
            Submission {
                prompt: " ",
                ..good
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }
}
