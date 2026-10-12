//! The kind of action of a command (ADR 0025 §3a).
//!
//! The list is fixed: *read*, *change*, *deploy*, *delete or irreversible*. Hard rules
//! on the words of the command classify first. When several rules match, the most
//! dangerous class counts. A command that no rule recognizes is a *change*, never a
//! *read*: only a known read-only word, with no write marker, makes a *read*.
//! The model never lowers the class here.

use super::shell_risk::Analysis;

/// What a command does, from the least to the most dangerous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionKind {
    /// Looks at state and changes nothing.
    Read,
    /// Changes state that is easy to repair, or an unclear command.
    Change,
    /// Sends work to a shared or live place: a deploy, a push, a publish.
    Deploy,
    /// Deletes data or cannot be undone.
    Delete,
}

impl ActionKind {
    /// The stable name that is stored and shown.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Change => "change",
            Self::Deploy => "deploy",
            Self::Delete => "delete",
        }
    }

    /// The kind for a stored name. `None` for any other text.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "change" => Some(Self::Change),
            "deploy" => Some(Self::Deploy),
            "delete" => Some(Self::Delete),
            _ => None,
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Read => 0,
            Self::Change => 1,
            Self::Deploy => 2,
            Self::Delete => 3,
        }
    }

    /// The more dangerous of two kinds: Delete, then Deploy, then Change, then Read.
    pub fn more_dangerous(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

/// Words that delete data or cannot be undone. SQL keywords match in any case.
const DELETE_WORDS: &[&str] = &[
    "delete", "drop", "truncate", "destroy", "prune", "rm", "rmdir", "unlink", "shred",
];
/// Words that send work to a shared or live place.
const DEPLOY_WORDS: &[&str] = &["deploy", "push", "publish", "apply", "release", "rollout"];
/// Words that only look at state.
const READ_WORDS: &[&str] = &[
    "list", "get", "show", "status", "describe", "ls", "cat", "view", "whoami", "version",
    "select", "help",
];
/// Words that write, even next to a read word (`get` then `set`).
const WRITE_WORDS: &[&str] = &[
    "create", "update", "set", "add", "install", "remove", "mv", "cp", "write", "post", "put",
    "patch", "insert", "upsert", "edit", "run", "exec", "start", "stop", "restart", "kill",
    "mkdir", "touch", "chmod", "chown", "tee", "sed", "dd", "ln", "merge", "commit", "checkout",
    "import", "restore", "rename", "replace", "send", "upload", "sudo", "sh", "bash", "zsh",
    "eval", "xargs", "curl", "wget",
];
/// Flags of the analysis that mean a loss of data.
const DELETE_FLAGS: &[&str] = &["data_loss", "irreversible"];

/// The kind of action of `command` (its words, with the program first) by the hard
/// rules, and by the flags of its analysis.
///
/// - *Delete*: `DELETE`, `drop`, `truncate`, `destroy`, `prune`, `rm`, `rmdir`,
///   `delete` as a word or a flag, `--force`, `-f` after `push`, `reset --hard`, or an
///   analysis flag for data loss.
/// - *Deploy*: `deploy`, `push`, `publish`, `apply`, `release`, `rollout`.
/// - *Read*: a read-only word (`list`, `get`, `show`, `status`, `select`, ...) with
///   no other rule, no write word, no redirect or pipe, and no known write.
/// - *Change*: everything else.
pub fn classify(command: &[String], analysis: &Analysis) -> ActionKind {
    let (words, raw) = words_of(command);
    let has = |word: &str| words.iter().any(|w| w == word);
    let has_any = |list: &[&str]| list.iter().any(|word| has(word));

    let mut kind = ActionKind::Change;
    let mut read = false;
    if has_any(DELETE_WORDS)
        || analysis
            .flags
            .iter()
            .any(|flag| DELETE_FLAGS.contains(&flag.as_str()))
        || words.iter().any(|w| w.starts_with("force"))
        || (has("reset") && has("hard"))
        || (has("push") && raw.iter().any(|w| w == "-f"))
    {
        return ActionKind::Delete;
    }
    if has_any(DEPLOY_WORDS) {
        kind = kind.more_dangerous(ActionKind::Deploy);
    } else if has_any(READ_WORDS)
        && !has_any(WRITE_WORDS)
        && !analysis.known_write
        && !raw
            .iter()
            .any(|w| w.contains(['>', '|', '&', '`']) || w.contains("$("))
    {
        read = true;
    }
    if read { ActionKind::Read } else { kind }
}

/// The lowercase words of a command: each argument split at spaces, quotes, `;`,
/// `=`, and similar, with a path cut to its last part and leading dashes removed.
/// Also the plain lowercase arguments, to see flags such as `-f` and shell marks.
fn words_of(command: &[String]) -> (Vec<String>, Vec<String>) {
    let mut words = Vec::new();
    let mut raw = Vec::new();
    for arg in command {
        let lower = arg.to_lowercase();
        for piece in lower.split(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    '"' | '\''
                        | ';'
                        | '|'
                        | '&'
                        | '('
                        | ')'
                        | '<'
                        | '>'
                        | '='
                        | ','
                        | '`'
                        | '{'
                        | '}'
                )
        }) {
            raw.push(piece.to_owned());
            let name = piece.rsplit('/').next().unwrap_or(piece);
            let name = name.trim_start_matches('-');
            if !name.is_empty() {
                words.push(name.to_owned());
            }
        }
        // Keep shell marks that the split removed, for the read check.
        for mark in ['>', '|', '&', '`'] {
            if lower.contains(mark) {
                raw.push(mark.to_string());
            }
        }
        if lower.contains("$(") {
            raw.push("$(".to_owned());
        }
    }
    (words, raw)
}
