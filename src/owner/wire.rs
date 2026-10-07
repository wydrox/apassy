//! Owner wire version 1 (ADR 0017, `docs/contracts/owner-cli-v1.md`).
//!
//! One JSON object per line in each direction. The client sends one [`Request`] on a
//! new connection and reads one [`Response`]. Item and agent references are text: an
//! ID, or the exact name without regard to case.
//!
//! A response never has a secret value of an item. It has a token only when the owner
//! just made one: a command-line session after the owner check, or an agent token
//! after a registration or a rotation.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use crate::contracts::CredentialKind;

pub const OWNER_WIRE_VERSION: u32 = 1;
/// Largest request line. An item has at most 15 secret values of 64 KiB.
pub const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
/// Largest response line. The decision export is the largest response.
pub const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
/// Environment variable with the session token of `apassy login`.
pub const SESSION_ENV: &str = "APASSY_SESSION";
/// Environment variable that overrides the owner socket path.
pub const SOCKET_ENV: &str = "APASSY_OWNER_SOCKET";
/// The first characters of an agent token (`AGENT_TOKEN_PREFIX` of the vault).
pub const AGENT_TOKEN_PREFIX: &str = "apassy_agt_";

/// Text with a secret value: a session token, an agent token, a passphrase, or an item
/// secret. Debug output is redacted. The buffer is erased on drop.
#[derive(Default, PartialEq, Eq)]
pub struct SecretText(String);

impl SecretText {
    pub fn new(text: String) -> Self {
        Self(text)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretText {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretText([redacted])")
    }
}

impl Serialize for SecretText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

/// One request.
#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub v: u32,
    /// The token of `apassy login`. Only [`Command::needs_session`] commands use it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SecretText>,
    pub command: Command,
}

/// Who decides a run of a process grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantMode {
    /// The owner approves each run.
    Ask,
    /// The bouncer decides. A risky run waits for the owner.
    Bouncer,
}

impl GrantMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::Bouncer => "bouncer",
        }
    }
}

/// Fields of an item. In an add, `None` is an empty field. In an edit, `None` keeps the
/// field, and an empty text clears a plain field.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ItemInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<CredentialKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    /// The field name of a custom item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_name: Option<String>,
    /// The public key of an SSH key item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// The main secret: the token, the password, the private key, or the custom value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretText>,
    /// The passphrase of an SSH private key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_passphrase: Option<SecretText>,
    /// Custom details to add, or to replace when the label exists.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<DetailInput>,
    /// Labels of custom details to remove.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove_details: Vec<String>,
}

/// One custom detail. A hidden detail is a secret field.
#[derive(Debug, Serialize, Deserialize)]
pub struct DetailInput {
    pub label: String,
    pub value: SecretText,
    #[serde(default)]
    pub hidden: bool,
}

/// Declaration fields (ADR 0008). `None` keeps the stored value, or the suggestion.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DeclarationInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reversibility: Option<String>,
    /// A provider ID, or an empty text for no provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

/// One variable of [`Command::ItemBindVariables`]: an item ID and a variable name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariableInput {
    pub item_id: u64,
    pub name: String,
}

/// The rule of a process grant (ADR 0007). It replaces the stored rule.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RuleInput {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub forbid: Vec<String>,
    #[serde(default)]
    pub expires_hours: Option<u32>,
    #[serde(default)]
    pub max_runs_per_hour: Option<u32>,
    #[serde(default)]
    pub instruction: String,
}

/// A command. The comment names the owner check that the app asks for, if any.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    /// The state of the app. No session.
    Status,
    /// Open a command-line session. Owner check.
    Login,
    /// End the session of the request.
    Logout,
    /// Lock the vault. No session: it only takes authority away.
    Lock,
    /// Bring the Apassy window to the front, for example to unlock. No session.
    Show,

    ItemList {
        #[serde(default)]
        query: String,
        #[serde(default)]
        archived: bool,
    },
    ItemShow {
        item: String,
    },
    ItemAdd {
        item: ItemInput,
    },
    ItemEdit {
        item: String,
        #[serde(default)]
        revision: Option<u64>,
        changes: ItemInput,
    },
    ItemDelete {
        item: String,
        #[serde(default)]
        revision: Option<u64>,
    },
    ItemArchive {
        item: String,
    },
    /// Owner check.
    ItemUnarchive {
        item: String,
    },
    ItemHistory {
        item: String,
        #[serde(default)]
        limit: Option<u32>,
    },
    /// Bind a secret field to an environment variable. Owner check. No hosts: programs
    /// get the real value. Hosts: programs get a placeholder (ADR 0011).
    ItemSetVariable {
        item: String,
        name: String,
        #[serde(default)]
        field: Option<String>,
        #[serde(default)]
        hosts: Vec<String>,
    },
    ItemClearVariable {
        item: String,
    },
    /// Bind the main secret of several items to variables with one owner check (ADR
    /// 0017, D1). Programs get the real values. The app refuses each invalid name, each
    /// name that another item uses, and each item without a secret value, and asks the
    /// owner for the rest. `data.bindings` has one row for each variable.
    ItemBindVariables {
        variables: Vec<VariableInput>,
    },
    /// Owner check.
    ItemSetDeclaration {
        item: String,
        declaration: DeclarationInput,
    },
    /// Owner check.
    ItemSetConnector {
        item: String,
        base_url: String,
    },
    ItemClearConnector {
        item: String,
    },
    /// Confirm the agent settings of a restored item. Owner check.
    ItemConfirmReview {
        item: String,
    },

    AgentList,
    AgentShow {
        agent: String,
    },
    /// Register an agent. The response has its token, one time.
    AgentAdd {
        name: String,
    },
    AgentRevoke {
        agent: String,
    },
    /// Owner check. The response has the new token, one time.
    AgentRotate {
        agent: String,
    },
    /// On: owner check. Off: none, it takes authority away.
    AgentSeeAll {
        agent: String,
        on: bool,
    },
    /// Read the token lifetime, or set it (owner check).
    TokenLifetime {
        #[serde(default)]
        days: Option<u32>,
    },

    /// Process access to one or more items. Owner check. No folder: any folder.
    GrantSet {
        agent: String,
        items: Vec<String>,
        #[serde(default)]
        folder: Option<String>,
        mode: GrantMode,
    },
    GrantRemove {
        agent: String,
        item: String,
    },
    /// Owner check.
    GrantRule {
        agent: String,
        item: String,
        rule: RuleInput,
    },
    /// A connector operation. Owner check.
    OperationAllow {
        agent: String,
        item: String,
        operation: String,
    },
    OperationRemove {
        agent: String,
        item: String,
        operation: String,
    },

    RequestList {
        #[serde(default)]
        all: bool,
    },
    /// Owner check.
    RequestGrant {
        request: u64,
        #[serde(default)]
        folder: Option<String>,
        mode: GrantMode,
    },
    RequestDeny {
        request: u64,
    },

    RunList,
    /// Owner check. The app shows the run exactly as it waits.
    RunApprove {
        run: u64,
        #[serde(default)]
        remember: bool,
    },
    RunDeny {
        run: u64,
    },

    PatternList,
    PatternRemove {
        pattern: u64,
    },

    Activity {
        #[serde(default)]
        limit: Option<u32>,
        #[serde(default)]
        agent: Option<String>,
        #[serde(default)]
        item: Option<String>,
    },
    DecisionExport,

    /// Write an encrypted backup. The vault locks after it, as in the app.
    Backup {
        path: String,
    },
    ChangePassphrase {
        current: SecretText,
        new: SecretText,
    },
    /// Open the restore sheet in the app with the backup path. The owner types the
    /// passphrase of the backup there.
    Restore {
        backup: String,
    },
}

impl Command {
    /// False for the commands that work without a session: they show no vault content
    /// and give no authority.
    pub fn needs_session(&self) -> bool {
        !matches!(self, Self::Status | Self::Login | Self::Lock | Self::Show)
    }
}

/// One response.
#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    /// `ok`, or an error code.
    pub code: String,
    /// Text for the owner. It has no secret value.
    pub message: String,
    #[serde(default)]
    pub data: Data,
}

impl Response {
    pub fn ok(message: impl Into<String>, data: Data) -> Self {
        Self {
            ok: true,
            code: "ok".to_owned(),
            message: message.into(),
            data,
        }
    }

    pub fn error(code: &str, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            code: code.to_owned(),
            message: message.into(),
            data: Data::None,
        }
    }
}

/// The data of a response.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Data {
    #[default]
    None,
    Status(StatusView),
    Session {
        token: SecretText,
        idle_minutes: u64,
    },
    Items {
        items: Vec<ItemRow>,
    },
    Item(Box<ItemView>),
    Events {
        events: Vec<EventRow>,
    },
    Agents {
        agents: Vec<AgentRow>,
    },
    Agent(Box<AgentView>),
    /// A new agent token. The app shows it one time only.
    Token {
        agent: AgentRow,
        token: SecretText,
    },
    Lifetime {
        days: u32,
    },
    Requests {
        requests: Vec<RequestRow>,
    },
    Runs {
        runs: Vec<RunRow>,
    },
    Patterns {
        patterns: Vec<PatternRow>,
    },
    Activity {
        entries: Vec<ActivityRow>,
    },
    Export {
        jsonl: String,
    },
    /// The result of [`Command::ItemBindVariables`] for each variable.
    Bindings {
        results: Vec<BindingRow>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultState {
    /// No vault file is open.
    None,
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusView {
    pub version: String,
    pub vault: VaultState,
    pub vault_path: Option<String>,
    /// `running`, or the reason the broker is not running.
    pub broker: String,
    pub broker_socket: Option<String>,
    pub touch_id: bool,
    /// The session of the request is valid.
    pub session: bool,
    /// Counts for the owner. Only with a valid session.
    pub waiting_runs: Option<usize>,
    pub open_requests: Option<usize>,
    pub items_to_review: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemRow {
    pub id: u64,
    pub name: String,
    pub kind: CredentialKind,
    pub service: String,
    pub project: String,
    pub revision: u64,
    pub archived: bool,
    /// The environment variable of the item.
    pub variable: Option<String>,
}

/// One variable of a batch binding. `reason` says why it is not bound, and is empty
/// when it is bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingRow {
    pub item_id: u64,
    pub name: String,
    pub bound: bool,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetailView {
    pub label: String,
    /// `None` for a hidden detail.
    pub value: Option<String>,
    pub hidden: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariableView {
    pub name: String,
    pub field: String,
    /// Empty: programs get the real value. Else the hosts of the placeholder.
    pub placeholder_hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclarationView {
    pub project: String,
    pub environment: String,
    pub risk: String,
    pub scope: String,
    pub reversibility: String,
    pub provider: Option<String>,
    /// The values come from a suggestion. The owner did not save them yet.
    pub suggested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemView {
    pub id: u64,
    pub name: String,
    pub kind: CredentialKind,
    pub service: String,
    pub project: String,
    pub notes: String,
    pub username: String,
    pub host: String,
    pub database: String,
    pub field_name: String,
    pub public_key: String,
    pub revision: u64,
    pub archived: bool,
    /// The names of the secret fields. Never their values.
    pub secret_fields: Vec<String>,
    pub details: Vec<DetailView>,
    pub variable: Option<VariableView>,
    pub declaration: DeclarationView,
    pub connector: Option<String>,
    pub needs_review: bool,
    pub added: Option<u64>,
    pub changed: Option<u64>,
    pub used: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRow {
    pub id: u64,
    pub at: u64,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRow {
    pub id: u64,
    pub name: String,
    pub created_at: u64,
    pub revoked: bool,
    pub token_expires_at: u64,
    pub token_expired: bool,
    pub sees_all: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleView {
    pub allow: Vec<String>,
    pub forbid: Vec<String>,
    pub expires_at: Option<u64>,
    pub max_runs_per_hour: Option<u32>,
    pub instruction: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRow {
    pub item_id: u64,
    pub item_name: String,
    /// `None`: any folder.
    pub folder: Option<String>,
    pub mode: GrantMode,
    pub rule: RuleView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRow {
    pub item_id: u64,
    pub item_name: String,
    pub operation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentView {
    pub agent: AgentRow,
    pub grants: Vec<GrantRow>,
    pub operations: Vec<OperationRow>,
    pub requests: Vec<RequestRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestRow {
    pub id: u64,
    pub agent_id: u64,
    pub agent_name: String,
    pub item_id: u64,
    pub item_name: String,
    /// The words of the agent. A claim, not a fact.
    pub reason: String,
    pub cwd: String,
    pub created_at: u64,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRow {
    pub id: u64,
    pub agent: String,
    pub command: Vec<String>,
    pub cwd: String,
    pub variables: Vec<String>,
    pub purpose: String,
    pub risk: String,
    pub user_request: String,
    pub request_source: String,
    pub waiting_secs: u64,
    /// "Approve and remember" can teach a pattern for this run.
    pub can_remember: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternRow {
    pub id: u64,
    pub display: String,
    pub state: String,
    pub approvals: u32,
    pub uses: u64,
    pub last_used_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityRow {
    pub id: u64,
    pub at: u64,
    pub agent: String,
    pub item: String,
    pub operation: String,
    pub decision: String,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_and_redact_secrets() {
        let request = Request {
            v: OWNER_WIRE_VERSION,
            session: Some(SecretText::new("apassy_cli_session-canary".to_owned())),
            command: Command::ItemAdd {
                item: ItemInput {
                    name: Some("Stripe test".to_owned()),
                    kind: Some(CredentialKind::ApiKey),
                    secret: Some(SecretText::new("sk_test_wire-canary".to_owned())),
                    ..ItemInput::default()
                },
            },
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains("canary"), "{debug}");
        let line = serde_json::to_string(&request).expect("serialize");
        assert!(line.contains(r#""cmd":"item_add""#), "{line}");
        let back: Request = serde_json::from_str(&line).expect("parse");
        let Command::ItemAdd { item } = back.command else {
            panic!("wrong command");
        };
        assert_eq!(item.secret.expect("secret").expose(), "sk_test_wire-canary");
        assert_eq!(item.kind, Some(CredentialKind::ApiKey));
    }

    #[test]
    fn commands_without_vault_content_need_no_session() {
        for command in [
            Command::Status,
            Command::Login,
            Command::Lock,
            Command::Show,
        ] {
            assert!(!command.needs_session(), "{command:?}");
        }
        for command in [
            Command::Logout,
            Command::ItemList {
                query: String::new(),
                archived: false,
            },
            Command::AgentList,
            Command::RunList,
            Command::Restore {
                backup: "/tmp/x".to_owned(),
            },
        ] {
            assert!(command.needs_session(), "{command:?}");
        }
    }

    #[test]
    fn responses_round_trip_with_tagged_data() {
        let response = Response::ok(
            "1 item",
            Data::Items {
                items: vec![ItemRow {
                    id: 7,
                    name: "Synthetic".to_owned(),
                    kind: CredentialKind::Login,
                    service: "example.com".to_owned(),
                    project: String::new(),
                    revision: 2,
                    archived: false,
                    variable: Some("EXAMPLE_PASSWORD".to_owned()),
                }],
            },
        );
        let line = serde_json::to_string(&response).expect("serialize");
        assert!(line.contains(r#""type":"items""#), "{line}");
        let back: Response = serde_json::from_str(&line).expect("parse");
        assert!(back.ok);
        let Data::Items { items } = back.data else {
            panic!("wrong data");
        };
        assert_eq!(items[0].variable.as_deref(), Some("EXAMPLE_PASSWORD"));
        let error: Response =
            serde_json::from_str(r#"{"ok":false,"code":"vault_locked","message":"Locked."}"#)
                .expect("parse an error without data");
        assert!(matches!(error.data, Data::None));
    }
}
