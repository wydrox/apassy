//! Host hook adapter for the user request (goal item B6, ADR 0009).
//!
//! Claude Code and Codex run a `UserPromptSubmit` hook before the model sees a user
//! prompt. The host writes one JSON object to the hook's stdin. The object has the
//! prompt, the session ID, the working directory, and the transcript path.
//! `apassy-hook` reads the object and sends the prompt to the broker with the agent
//! token. The broker then uses this prompt as the user request of later runs.
//!
//! The adapter never writes to stdout. On both hosts, stdout of this hook becomes
//! model context, so an empty stdout keeps the prompt unchanged. A broker that is
//! down or slow must not block the user: the adapter waits at most
//! [`HOOK_TIMEOUT`] and always exits with code 0.
//!
//! Claude Code 2.1.3xx also runs the hook for turns that the user did not write: a
//! task notification, a peer or channel message, an auto-continuation (`source`
//! `system`), a `/loop` or scheduled wakeup (`loop_wakeup`, `schedule_wakeup`: a prompt
//! that the agent scheduled), and a poll event. The adapter sends only a turn of the
//! user ([`USER_SOURCES`]). The broker keeps the newest prompt of each session, so a
//! machine turn would replace the request of the user, and an agent could make its
//! own scheduled text look like a verified request.
//!
//! An Agent SDK turn (`sdk`) stays accepted: T3 Code and other SDK hosts deliver the
//! owner's real messages this way. But an agent that starts its own SDK session sends
//! its own text as an `sdk` turn too, so the adapter sends the `source` along, and the
//! broker names the request "Agent SDK turn" for the bouncer and on the question card
//! (`docs/operations/host-hooks.md`).

use std::path::Path;
use std::time::Duration;

use serde_json::Value;

use super::client::{self, SendOptions};
use super::wire::{Action, MAX_HOOK_PROMPT_BYTES};

/// The host event that carries the user prompt.
pub const EVENT: &str = "UserPromptSubmit";
/// Largest hook input that the adapter reads. A pasted text can be large.
pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
/// How long the adapter waits for the broker.
pub const HOOK_TIMEOUT: Duration = Duration::from_secs(2);
/// The `source` values of a prompt that the user wrote: `user` (the Claude Code
/// composer) and `sdk` (`claude -p` and the Agent SDK, for example T3 Code). A hook
/// input without `source` (Codex, older Claude Code) counts as the user's.
pub const USER_SOURCES: &[&str] = &["user", "sdk"];
/// Claude Code puts the text of a task notification in this tag. It marks a
/// notification when the hook input has no `source`.
pub const TASK_NOTIFICATION_TAG: &str = "<task-notification>";

/// One user prompt from the host.
#[derive(Clone, PartialEq, Eq)]
pub struct HookInput {
    /// `claude-code` or `codex`. A label for the owner only.
    pub host: &'static str,
    pub session_id: Option<String>,
    pub cwd: String,
    pub prompt: String,
    pub transcript_path: Option<String>,
    /// The prompt was longer than [`MAX_HOOK_PROMPT_BYTES`] and is cut.
    pub truncated: bool,
    /// The `source` of the hook input: `user` or `sdk` ([`USER_SOURCES`]). `None` for a
    /// host that sends none. The broker keeps it with the prompt: an Agent SDK turn
    /// (`sdk`) is the provenance that the bouncer and the question card name.
    pub source: Option<String>,
}

impl std::fmt::Debug for HookInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The prompt stays out of logs.
        f.debug_struct("HookInput")
            .field("host", &self.host)
            .field("session_id", &self.session_id)
            .field("cwd", &self.cwd)
            .field("prompt_bytes", &self.prompt.len())
            .field("transcript_path", &self.transcript_path)
            .field("truncated", &self.truncated)
            .field("source", &self.source)
            .finish()
    }
}

/// Read the host hook input. `Ok(None)` means that there is nothing to send: another
/// event, an empty prompt, or a turn that the user did not write (see the module
/// documentation). The error text never contains the prompt.
pub fn parse(bytes: &[u8]) -> Result<Option<HookInput>, &'static str> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err("the hook input is too large");
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "the hook input is not valid JSON")?;
    let object = value
        .as_object()
        .ok_or("the hook input is not a JSON object")?;
    let text = |name: &str| object.get(name).and_then(Value::as_str);
    if text("hook_event_name") != Some(EVENT) {
        return Ok(None);
    }
    let Some(prompt) = text("prompt").filter(|prompt| !prompt.trim().is_empty()) else {
        return Ok(None);
    };
    // Only an allow-list is a turn of the user: `user`, `sdk`, or no `source` with a
    // prompt that is not a task notification. Any other value, or form, is not.
    let source = match object.get("source") {
        None | Some(Value::Null) => {
            if prompt.trim_start().starts_with(TASK_NOTIFICATION_TAG) {
                return Ok(None);
            }
            None
        }
        Some(Value::String(source)) if USER_SOURCES.contains(&source.as_str()) => {
            Some(source.clone())
        }
        // An unknown value or form is not a known turn of the user.
        Some(_) => return Ok(None),
    };
    let cwd = text("cwd")
        .filter(|cwd| cwd.starts_with('/'))
        .ok_or("the hook input has no absolute cwd")?;
    // Codex adds `turn_id` to its turn events. Claude Code does not send it.
    let host = if object.contains_key("turn_id") {
        "codex"
    } else {
        "claude-code"
    };
    let (prompt, truncated) = cut(prompt, MAX_HOOK_PROMPT_BYTES);
    Ok(Some(HookInput {
        host,
        session_id: text("session_id")
            .filter(|id| !id.is_empty())
            .map(str::to_owned),
        cwd: cwd.to_owned(),
        prompt: prompt.to_owned(),
        transcript_path: text("transcript_path")
            .filter(|path| !path.is_empty())
            .map(str::to_owned),
        truncated,
        source,
    }))
}

/// The first `max` bytes of `text` at a character boundary.
fn cut(text: &str, max: usize) -> (&str, bool) {
    if text.len() <= max {
        return (text, false);
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], true)
}

/// Send the prompt to the broker. The error text never contains the prompt or the token.
pub fn submit(socket: &Path, token: &str, input: HookInput) -> Result<(), String> {
    let options = SendOptions {
        host_session: input.session_id.as_deref(),
        timeout: Some(HOOK_TIMEOUT),
    };
    let action = Action::SubmitUserRequest {
        host: input.host.to_owned(),
        cwd: input.cwd.clone(),
        prompt: input.prompt.clone(),
        transcript_path: input.transcript_path.clone(),
        truncated: input.truncated,
        source: input.source.clone(),
    };
    match client::send_with(socket, token, action, options) {
        Ok(response) if response.ok => Ok(()),
        Ok(response) => Err(format!(
            "the broker refused the user request: {}",
            response
                .error
                .map_or_else(|| "broker_error".to_owned(), |error| error.code)
        )),
        Err(err) => Err(format!("the broker did not answer ({})", err.kind())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_claude_code_input() {
        // Measured on Claude Code 2.1.283 (docs/operations/host-hooks.md).
        let input = br#"{"session_id":"1dbe1639-f522-4744-a3dc-7a76626af241","transcript_path":"/Users/me/.claude/projects/-p/1dbe1639-f522-4744-a3dc-7a76626af241.jsonl","cwd":"/private/tmp/p","prompt_id":"ea64","permission_mode":"default","hook_event_name":"UserPromptSubmit","prompt":"Run the checks."}"#;
        let parsed = parse(input).expect("valid").expect("prompt");
        assert_eq!(parsed.host, "claude-code");
        assert_eq!(
            parsed.session_id.as_deref(),
            Some("1dbe1639-f522-4744-a3dc-7a76626af241")
        );
        assert_eq!(parsed.cwd, "/private/tmp/p");
        assert_eq!(parsed.prompt, "Run the checks.");
        assert!(!parsed.truncated);
        assert!(!format!("{parsed:?}").contains("Run the checks."));
    }

    #[test]
    fn reads_codex_input() {
        // Measured on Codex 0.156.1. `transcript_path` can be null.
        let input = br#"{"session_id":"01a0db20-fcae-7151-b2e6-b590a8175ded","turn_id":"01a0db21","transcript_path":null,"cwd":"/private/tmp/p","hook_event_name":"UserPromptSubmit","model":"m","permission_mode":"default","prompt":"Deploy staging."}"#;
        let parsed = parse(input).expect("valid").expect("prompt");
        assert_eq!(parsed.host, "codex");
        assert!(parsed.transcript_path.is_none());
    }

    /// Claude Code 2.1.317 runs `UserPromptSubmit` also for turns that the host injects,
    /// with `source` (`system` for a task notification). Before 0.5.16 the adapter sent
    /// them, so a finished background task replaced the request of the user.
    #[test]
    fn a_turn_that_the_user_did_not_write_is_not_sent() {
        let input = |source: Option<&str>, prompt: &str| {
            let mut input = serde_json::json!({
                "session_id": "1dbe1639-f522-4744-a3dc-7a76626af241",
                "transcript_path": "/Users/me/.claude/projects/-p/1dbe1639-f522-4744-a3dc-7a76626af241.jsonl",
                "cwd": "/private/tmp/p",
                "hook_event_name": "UserPromptSubmit",
                "prompt": prompt,
            });
            if let Some(source) = source {
                input["source"] = source.into();
            }
            parse(input.to_string().as_bytes()).expect("valid")
        };
        let notification = "<task-notification><task-id>b1</task-id><status>completed</status></task-notification>";
        for source in [
            "system",
            "loop_wakeup",
            "schedule_wakeup",
            "poll_event",
            "other",
        ] {
            assert_eq!(input(Some(source), "Run the checks."), None, "{source}");
        }
        assert_eq!(input(Some("system"), notification), None);
        // An older host sends no `source`: a task notification is known by its tag.
        assert_eq!(input(None, notification), None);
        assert_eq!(input(None, &format!("  \n{notification}")), None);
        // A form that no host sends is not a turn of the user either.
        let mut odd = serde_json::json!({"hook_event_name": "UserPromptSubmit", "cwd": "/p",
            "prompt": "Run the checks.", "source": 1});
        assert_eq!(parse(odd.to_string().as_bytes()), Ok(None));
        odd["source"] = serde_json::Value::Null;
        assert!(parse(odd.to_string().as_bytes()).expect("valid").is_some());
        // Turns of the user are sent as before, with their `source` (finding 4 of the
        // 0.5.16 review: the broker names an Agent SDK turn as such).
        for source in [Some("user"), Some("sdk"), None] {
            let parsed = input(source, "Run the checks.").expect("a prompt of the user");
            assert_eq!(parsed.prompt, "Run the checks.");
            assert_eq!(parsed.host, "claude-code");
            assert_eq!(parsed.source.as_deref(), source);
        }
        // Finding 5: an allow-list. A `source` close to a known one is not the user's.
        for source in ["User", "SDK", "sdk ", "typed", ""] {
            assert_eq!(input(Some(source), "Run the checks."), None, "{source:?}");
        }
        // The tag only counts at the start: a request that quotes it is the user's.
        assert!(input(None, &format!("Explain this: {notification}")).is_some());
    }

    #[test]
    fn ignores_other_events_and_refuses_bad_input() {
        let other = br#"{"hook_event_name":"PreToolUse","cwd":"/p","prompt":"x"}"#;
        assert_eq!(parse(other), Ok(None));
        let empty = br#"{"hook_event_name":"UserPromptSubmit","cwd":"/p","prompt":"  "}"#;
        assert_eq!(parse(empty), Ok(None));
        let relative = br#"{"hook_event_name":"UserPromptSubmit","cwd":"p","prompt":"x"}"#;
        assert!(parse(relative).is_err());
        assert!(parse(b"not json").is_err());
        assert!(parse(b"[1]").is_err());
    }

    #[test]
    fn a_long_prompt_is_cut_at_a_character_boundary() {
        let prompt = "é".repeat(MAX_HOOK_PROMPT_BYTES);
        let input = serde_json::json!({
            "hook_event_name": "UserPromptSubmit", "cwd": "/p", "prompt": prompt,
        })
        .to_string();
        let parsed = parse(input.as_bytes()).expect("valid").expect("prompt");
        assert!(parsed.truncated);
        assert!(parsed.prompt.len() <= MAX_HOOK_PROMPT_BYTES);
        assert!(prompt.starts_with(&parsed.prompt));
    }

    #[test]
    fn a_missing_broker_is_an_error_without_the_prompt() {
        let input = HookInput {
            host: "claude-code",
            session_id: Some("s".to_owned()),
            cwd: "/p".to_owned(),
            prompt: "secret-looking prompt text".to_owned(),
            transcript_path: None,
            truncated: false,
            source: Some("sdk".to_owned()),
        };
        let err = submit(Path::new("/nonexistent/apassy.sock"), "apassy_agt_x", input)
            .expect_err("no broker");
        assert!(err.starts_with("the broker did not answer"));
        assert!(!err.contains("prompt text") && !err.contains("apassy_agt_x"));
    }
}
