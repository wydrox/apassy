# Implementation plan: ADR 0025 + ADR 0026

Date: 2026-10-12. Branch: `feat/low-friction-access`. No release; `main` is not touched by this work.

Decisions taken by the integrator for open points (record in the ADRs when the code lands):

- An owner answer is remembered per `(item, project, action kind)` for every item, not only for production (ADR 0025 §3). The button reads "Allow ACTION in PROJECT" also for non-production items.
- "A value that exists returns the existing item" (ADR 0025 §6) applies only among the agent's own items (`item_origin`), so it is not a membership oracle.
- Action kinds are rules-only in Wave 1 (unclear → Change, never Read). The model prompt stays contract v7; project and agent context is applied deterministically in Rust.

## 0. Facts (verified in the code)

- Schema 17 = `SCHEMA_VERSION` (`src/vault/types.rs:22`). Migration chain: `migrate_to_current` / `initialize_new_db` / `verify_user_version` / `verify_expected_columns_in` in `src/vault/mod.rs:942-1252`. `passkey::add_schema_v17` runs unguarded at the end of the chain.
- Merge (`src/vault/merge.rs`): one credential = `item` + `CHILD_TABLES` (:44); `LOCAL_TABLES` (:55) / `SYNCED_TABLES` (:82) with a test (:2183) that every table is in one list; `UPGRADABLE_SCHEMA = 16` with `const _: () = assert!(SCHEMA_VERSION == UPGRADABLE_SCHEMA + 1)` (:116-120); `load_records` (:559) reads child tables by name, so a schema-17 copy without a new table fails unless the read is version-aware. `sync::content_digest` hashes whatever tables exist.
- Authority today = `exec_grant` + `agent.see_all`; `run.rs:check` (:790) returns `not_granted`; first use is forced to wait at `run.rs:315-367` and `:440-468`; `approval_timeout` 120 s (`server.rs:58`); "one waiting per agent" exists only for first-use offers (`approvals.rs` `wait`). The model prompt (`bouncer.rs:state_text`) never sees agent, project, hosts or declaration.
- UI: 2 columns (`ui/shell.rs`), `OwnerView` (`desktop/mod.rs:62`), `Sheet` (`ui.rs:338`), `OwnerSession::with_vault` (`owner_store.rs:527`), no `ViewportBuilder`, Settings is a view, no paste detection. Detection building blocks: `providers::suggest(&ItemFacts)`, `cli/import.rs::parse_env`, `otp::parse`, `swap.rs::KNOWN_PREFIXES`.
- The iPhone app is in this repo (`ios/`, `ios/ApassyCore` depends on `apassy` by path; CI runs `cargo test -p apassy-core`). Only `apassy-relay` is external.

## 1. Rules for every stream

- Own worktree from `feat/low-friction-access`. `export CARGO_TARGET_DIR=/Users/rafalw/Dev/apassy/target` (shared; builds wait on the cargo lock). Check `df -h /System/Volumes/Data` before a full build; stop if less than 4 GB is free.
- No `Cargo.toml` / `Cargo.lock` change through Wave 2. No CHANGELOG or ADR edits (the integrator writes them).
- Only edit the files your stream owns. Read anything.
- Targeted tests while working. Before asking to merge: `cargo clippy --locked --all-features --all-targets -- -D warnings`, `cargo test --locked --features desktop,vault`, `cargo check --features desktop --bin apassy` (demo build), `cargo test -p apassy-core`.
- Synthetic data only. Never touch a real vault, the Keychain, real profiles, or production services.

## 2. Waves

### Wave 0 (2 parallel)

**F0 Foundation (schema 18)** — implementer.
Owns: `src/vault/types.rs`, `src/vault/mod.rs`, `src/vault/merge.rs`, `src/vault/sync.rs`, `src/vault/history.rs` (adds `ItemEventKind::Moved`, kind `"moved"` in `SYNCED_EVENT_KINDS`), new `src/vault/schema18.rs`, `src/vault/folders.rs`, `src/vault/policy.rs`, empty stub modules `src/vault/{exceptions,answers,usage,agent_items}.rs` (doc comment only, `pub mod` lines in mod.rs), `src/desktop/owner_store.rs` only for `mod add; mod decisions;` + two empty files `src/desktop/owner_store/{add,decisions}.rs`, `tests/vault_migration.rs`, `tests/sync_schema_upgrade.rs`, new `tests/folder_sync.rs`, and `ios/ApassyCore` only if the schema bump needs a mechanical change there.
Provides: §3 DDL, migration, merge support, folders API, policy API.
Acceptance: new tests `version_18_migration_derives_exceptions_and_is_atomic`, `a_17_copy_merges_and_is_replaced_by_an_18_copy`, `folders_merge_last_writer_wins_and_tombstone_wins`; "every table is in SYNCED or LOCAL" still passes; `cargo test --all-features --test it -- vault_migration:: sync_schema_upgrade:: relay_sync:: folder_sync::`, `cargo test --all-features --lib vault::`, `cargo test -p apassy-core`.
Out of scope: any UI, broker, CRUD for local tables beyond the DDL.

**F1 Broker helpers** — worker.
Owns: new `src/broker/project.rs`, `src/broker/action_kind.rs`, two `pub mod` lines in `src/broker/mod.rs`, new `tests/project_key.rs`, `tests/action_kind.rs`.
Provides: `pub struct Project { pub key: String, pub label: String, pub root: PathBuf }`; `pub fn project_of(cwd: &Path, home: Option<&Path>) -> Option<Project>` (git common dir via `.git` file → `gitdir:` → `commondir`, no git2; root/home/parents → `None`, reuse `approvals::folder_is_broad_with`); `pub enum ActionKind { Read, Change, Deploy, Delete }` with `as_str`/`parse`; `pub fn classify(command: &[String], analysis: &Analysis) -> ActionKind` (hard words `DELETE|drop|--force|rm|destroy|prune|reset --hard` → Delete; `deploy|push|publish|apply|release` → Deploy; unknown → Change, never Read).
Acceptance: table tests incl. a worktree fixture and `/`, `$HOME`, `/System/Volumes/Data/Users/x`; `cargo test --all-features --test it -- project_key:: action_kind::`.

### Wave 1 (3 parallel), after Gate 0

**S1 Shell UI (mockup layout, no new business logic)** — owns `src/desktop/mod.rs` (`OwnerView` → `Place { Folder(Option<String>), Shared(String), Decisions, Agents }` + `settings_open: bool`), `src/desktop/ui.rs` (new `Sheet` variants with stub arms: `NewCredential`, `MoveToFolder{item_id}`, `NewFolder{parent}`, `RenameFolder{uuid}`, `DeleteFolder{uuid}`, `Share{item_id}`; per-view state), `ui/shell.rs`, new `ui/sidebar.rs`, `ui/columns.rs`, `ui/settings_window.rs` (egui viewport hosting `settings::draw` unchanged), stubs `ui/decisions.rs` (temporarily draws `activity::draw` + `learning_ui::draw`), `ui/new_credential.rs`, `ui/folders.rs` (New/Rename/Delete/Move sheets, real, via the folders API), `ui/kit.rs`, `ui/items.rs` and `ui/agents.rs` layout-only edits, `ui/demo.rs`, `ui/focus.rs`, `ui_prefs.rs`, `ui/keyboard_tests.rs`, `ui/vault_tests.rs`, `docs/operations/desktop-ui.md`. Acceptance: every `Place` draws at default and minimum sizes in 3 columns plus the Settings viewport; ⌘1 Credentials, ⌘2 Decisions, ⌘3 Agents, ⌘, Settings window; sidebar toggle ⌃⌘S and the narrow-window rail/float behaviour of the mockup; demo build compiles.

**D1 Detection engine + CLI `apassy add`** — owns new `src/vault/detect.rs` (pure), `src/vault/providers.rs` (per-provider `variable` and `prefixes` in the pack schema; `swap.rs` gets a test that its table is a superset of pack prefixes), `packs/providers/*.json`, `packs/schema/*provider*`, `src/bin/apassy-packs.rs`, `src/cli/*`, `src/owner/wire.rs` (`Command::Add { secret: SecretText, folder: Option<String> }`), `src/desktop/owner_cli.rs`, `src/desktop/owner_store/add.rs` (`OwnerSession::add_detected`), `ui/cli_tests.rs`, `tests/cli_ux.rs`, new `tests/detect.rs`, `docs/operations/cli.md`, `docs/operations/declarations.md`. Provides `detect(text) -> Vec<Detected>`, `summary_line`, `Vault::add_detected(d, folder, origin) -> ItemSummary` (one transaction: item + env binding with provider hosts as placeholder hosts when known + declaration + `declaration_source` + folder; no owner check at creation).

**B1 Broker core: the bouncer decides from first use (security stage)** — owns `src/broker/run.rs`, `bouncer.rs`, `decide.rs`, `approvals.rs`, `approvals/owner_auth.rs`, `server.rs` (timeout 300 s), `learning.rs`, `src/vault/{exceptions,answers,usage}.rs`, `src/vault/access.rs` (catalog filtering + `folder` path), `src/agent/wire.rs` (error codes, `folder` in catalog; no new actions), `tests/first_use.rs`, `tests/access_model.rs`, `tests/agent_run.rs`, `tests/learning.rs`, new `tests/exceptions.rs`, `tests/owner_answers.rs`, `docs/contracts/broker-v0.md`, `docs/operations/{agent-path,bouncer,learning}.md`. May edit only `PendingRun { .. }` constructor lines elsewhere (new fields in one `question: QuestionInfo` struct with `Default`). Provides new `OwnerAction` variants (`ApproveInProject`, `AllowProduction`, `RemoveAgentException`, `RemoveOwnerAnswer`), `PendingRun.question`, stricter-deny queue methods, `question_waiting`, re-attach of an identical run, `record_interaction`. Hard rules of ADR 0025 §3 stay; `exec_grant` is no longer authority.

### Wave 2 (4 parallel), after Gate 1

- **U2 Decisions + Agents views** (`ui/decisions.rs`, deletes `ui/activity.rs` and `src/desktop/inbox.rs`, `owner_check.rs` new `OwnerRequest` variants, `owner_store/decisions.rs`, read-only `ui/agents.rs`, `ui/agent_onboarding.rs`, `ui/agent_setup.rs`, `notify.rs`, related tests).
- **I2 Item detail + New Credential + folders UI** (`ui/items.rs`, `ui/new_credential.rs`, `ui/folders.rs`, `src/desktop/model.rs`, OTP UI files, new tests).
- **P2 Settings window tabs** (`ui/settings.rs`, `ui/settings_window.rs`, `learning_ui.rs` → Advanced panel, `ui/companion.rs`, `ui/browser_settings.rs`, `ui/cli_tools.rs`, `ui/updates.rs`, `ui/vaults.rs`, `ui/sync.rs`, `ui/sync/relay.rs`, `ui/sync_tests.rs`).
- **T2 Agent tools + corrections** (`src/agent/mcp.rs`, `src/agent/wire.rs` new actions, `decide.rs` dispatch arms, new `src/broker/agent_items.rs`, `src/broker/corrections.rs`, `src/vault/agent_items.rs`, `src/broker/exec.rs` capture mode, tests, contract docs). Create only; update/describe only own items; name suffixing; 10 new items per agent per hour; capture refuses the Apassy data dir and vault files; the value never appears in any response or log.

### Wave 3 (app side) and Wave 4 (external)

- **N3** questions through the relay (client, E2E envelope, worker) off by default; **M3** iPhone questions tab; **V3** shared vaults (design spike first); **R4** `apassy-relay` questions endpoint, team schema 5, APNs (needs the owner's APNs key; deploy only after owner confirmation).

## 3. Schema 18

```sql
-- SYNCED (add to SYNCED_TABLES; *_child also to CHILD_TABLES → triggers via triggers_sql)
CREATE TABLE folder (uuid TEXT PRIMARY KEY, parent_uuid TEXT, name TEXT NOT NULL,
  position INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL, deleted_at INTEGER);
CREATE INDEX folder_parent ON folder(parent_uuid, position);
CREATE TABLE item_folder (item_id INTEGER PRIMARY KEY, folder_uuid TEXT NOT NULL);     -- child
CREATE TABLE item_policy (item_id INTEGER PRIMARY KEY,
  always_ask INTEGER NOT NULL DEFAULT 0 CHECK (always_ask IN (0,1)));                  -- child
CREATE TABLE declaration_source (item_id INTEGER PRIMARY KEY,
  environment TEXT NOT NULL, risk TEXT NOT NULL, scope TEXT NOT NULL, reversibility TEXT NOT NULL
  /* each IN ('owner','signal','usage','default'), CHECK per column */);               -- child
CREATE TABLE shared_vault (uuid TEXT PRIMARY KEY, name TEXT NOT NULL, color TEXT NOT NULL DEFAULT '',
  relay_url TEXT NOT NULL, team_id TEXT NOT NULL, created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL, deleted_at INTEGER);
CREATE TABLE item_share (item_id INTEGER NOT NULL, shared_vault_uuid TEXT NOT NULL,
  PRIMARY KEY (item_id, shared_vault_uuid));                                            -- child
CREATE TABLE vault_secret (name TEXT PRIMARY KEY, value BLOB NOT NULL,
  updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL);
-- LOCAL (add to LOCAL_TABLES)
ALTER TABLE agent ADD COLUMN note TEXT NOT NULL DEFAULT '';            -- MAX_AGENT_NOTE_BYTES 500
CREATE TABLE agent_exception (agent_id INTEGER NOT NULL, item_id INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('never','always_ask','only')), created_at INTEGER NOT NULL,
  PRIMARY KEY (agent_id, item_id, kind));
CREATE INDEX agent_exception_item ON agent_exception(item_id);
CREATE TABLE owner_answer (id INTEGER PRIMARY KEY AUTOINCREMENT, item_id INTEGER NOT NULL,
  project_key TEXT NOT NULL, project_label TEXT NOT NULL,
  action_kind TEXT NOT NULL CHECK (action_kind IN ('read','change','deploy','delete')),
  scope TEXT NOT NULL CHECK (scope IN ('project','production')),
  created_at INTEGER NOT NULL, answered_on TEXT NOT NULL,
  UNIQUE (item_id, project_key, action_kind, scope));
CREATE INDEX owner_answer_item ON owner_answer(item_id);
CREATE TABLE item_use (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
  item_id INTEGER NOT NULL, agent_id INTEGER, agent_name TEXT NOT NULL,
  project_key TEXT NOT NULL, project_label TEXT NOT NULL, action_kind TEXT NOT NULL,
  command_summary TEXT NOT NULL, hosts TEXT NOT NULL /* JSON array */,
  outcome TEXT NOT NULL CHECK (outcome IN ('allowed','denied','refused','timed_out')),
  decided_by TEXT NOT NULL CHECK (decided_by IN ('bouncer','pattern','answer','owner','rule')),
  answered_on TEXT NOT NULL DEFAULT '', decision_log_id INTEGER);
CREATE INDEX item_use_item ON item_use(item_id, at); CREATE INDEX item_use_agent ON item_use(agent_id, at);
CREATE TABLE item_origin (item_id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL, agent_name TEXT NOT NULL,
  project_key TEXT NOT NULL, project_label TEXT NOT NULL,
  tool TEXT NOT NULL CHECK (tool IN ('capture','generate','save','ask_owner')), created_at INTEGER NOT NULL);
CREATE INDEX item_origin_agent ON item_origin(agent_id, created_at);
CREATE TABLE credential_request (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER NOT NULL,
  agent_name TEXT NOT NULL, project_key TEXT NOT NULL, project_label TEXT NOT NULL, name TEXT NOT NULL,
  purpose TEXT NOT NULL, where_to_get TEXT NOT NULL, folder_uuid TEXT, created_at INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('open','saved','dismissed')), item_id INTEGER, decided_at INTEGER);
CREATE INDEX credential_request_state ON credential_request(state, id);
CREATE TABLE correction (id INTEGER PRIMARY KEY AUTOINCREMENT, item_id INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('environment','project')), proposed TEXT NOT NULL,
  facts TEXT NOT NULL /* JSON */, created_at INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('open','accepted','ignored')), decided_at INTEGER,
  UNIQUE (item_id, kind, proposed));
CREATE TABLE owner_interaction (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('question','approval','owner_check','correction')), detail TEXT NOT NULL);
CREATE INDEX owner_interaction_at ON owner_interaction(at);
-- data migration (ADR 0025 §3f), in the same batch
INSERT INTO agent_exception SELECT g.agent_id, g.item_id, 'only', g.created_at FROM exec_grant g
  JOIN agent a ON a.id = g.agent_id WHERE a.see_all = 0 AND a.revoked_at IS NULL;
INSERT INTO agent_exception SELECT g.agent_id, g.item_id, 'always_ask', g.created_at FROM exec_grant g
  JOIN agent a ON a.id = g.agent_id WHERE g.mode = 'ask' AND a.revoked_at IS NULL;
UPDATE vault_meta SET schema_version = 18 WHERE id = 1; PRAGMA user_version = 18;
```

Check the real column names of `exec_grant`, `agent` and `vault_meta` before writing the SQL; the plan names may differ.

Migration rules: `agent.see_all = 0` keeps its meaning as the exception "only these items". `exec_grant`, `grant_rule`, `access_request`, `remembered_pattern` rows stay as history; nothing is deleted. In `mod.rs`: add `PASSKEY_SCHEMA_VERSION = 17` to `verify_user_version`, guard `add_schema_v17` with `from < 17`, append `schema18::add_schema_v18(&tx)` (SQL batch, then `verify_expected_columns`) in both `migrate_to_current` and `initialize_new_db`, add `SCHEMA_V18_COLUMNS`. In `merge.rs`: `UPGRADABLE_SCHEMA = 17`; `load_records(conn, schema, scope, remote_version)` reads the four new child tables only when `remote_version >= 18`; `Record` gains `folder: Option<String>, always_ask: bool, sources: Option<[String;4]>, shares: Vec<String>` and `content_hash` covers them; `write_children`/`replace_record`/`delete_children` handle them; new `merge_lww(tx, table, key_col, remote_version)` for `folder`, `shared_vault`, `vault_secret` (later `(updated_at, updated_by)` wins; a row with `deleted_at` beats an older edit); the 16→17 body of `upgrade_records` is removed. Items whose `folder_uuid` is unknown or deleted display at the root.

### Rust API

```rust
// vault/folders.rs (F0)
pub struct Folder { pub uuid: String, pub parent: Option<String>, pub name: String, pub position: i64 }
pub const MAX_FOLDER_NAME_BYTES: usize = 64; pub const MAX_FOLDER_DEPTH: usize = 4;
impl Vault {
  pub fn folders(&self) -> VaultResult<Vec<Folder>>;
  pub fn create_folder(&mut self, parent: Option<&str>, name: &str) -> VaultResult<Folder>;
  pub fn rename_folder(&mut self, uuid: &str, name: &str) -> VaultResult<()>;
  pub fn move_folder(&mut self, uuid: &str, parent: Option<&str>) -> VaultResult<()>; // refuses cycles/depth
  pub fn delete_folder(&mut self, uuid: &str) -> VaultResult<usize>;   // items go to the parent
  pub fn item_folder(&self, item_id: u64) -> VaultResult<Option<String>>;
  pub fn set_item_folder(&mut self, item_id: u64, folder: Option<&str>) -> VaultResult<()>; // event Moved
  pub fn folder_path(&self, folder: Option<&str>) -> VaultResult<Vec<String>>;
  pub fn items_in_folder(&self, folder: Option<&str>, recursive: bool) -> VaultResult<Vec<u64>>;
}
// vault/policy.rs (F0)
pub enum DeclarationSource { Owner, Signal, Usage, Default }
pub struct DeclarationSources { pub environment: DeclarationSource, pub risk: DeclarationSource, pub scope: DeclarationSource, pub reversibility: DeclarationSource }
impl Vault {
  pub fn always_ask(&self, item_id: u64) -> VaultResult<bool>;
  pub fn set_always_ask(&mut self, item_id: u64, on: bool) -> VaultResult<()>;
  pub fn declaration_sources(&self, item_id: u64) -> VaultResult<DeclarationSources>; // Owner when no row
  pub fn set_declaration_sources(&mut self, item_id: u64, s: &DeclarationSources) -> VaultResult<()>;
}
// vault/exceptions.rs (B1)
pub enum ExceptionKind { Never, AlwaysAsk, Only }  pub enum Standing { Normal, AlwaysAsk, Never }
pub struct AgentException { pub agent_id: u64, pub item_id: u64, pub kind: ExceptionKind, pub created_at: u64 }
impl Vault {
  pub fn agent_note(&self, agent_id: u64) -> VaultResult<String>;
  pub fn set_agent_note(&mut self, agent_id: u64, note: &str) -> VaultResult<()>;
  pub fn add_agent_exception(&mut self, agent_id: u64, item_id: u64, kind: ExceptionKind) -> VaultResult<()>;
  pub fn remove_agent_exception(&mut self, agent_id: u64, item_id: u64, kind: ExceptionKind) -> VaultResult<bool>;
  pub fn agent_exceptions(&self, agent_id: u64) -> VaultResult<Vec<AgentException>>;
  pub fn item_exceptions(&self, item_id: u64) -> VaultResult<Vec<AgentException>>;
  pub fn agent_item_standing(&self, agent_id: u64, item_id: u64) -> VaultResult<Standing>;
  pub fn visible_items_for_agent(&self, agent_id: u64) -> VaultResult<Option<BTreeSet<u64>>>; // None = all
}
// vault/answers.rs (B1)
pub struct ProjectRef { pub key: String, pub label: String }  pub enum AnswerScope { Project, Production }
pub struct OwnerAnswer { pub id: u64, pub item_id: u64, pub project: ProjectRef, pub action: ActionKind,
  pub scope: AnswerScope, pub created_at: u64, pub answered_on: String }
impl Vault {
  pub fn remember_answer(&mut self, item_id: u64, p: &ProjectRef, a: ActionKind, on: &str) -> VaultResult<u64>;
  pub fn allow_production(&mut self, item_id: u64, p: &ProjectRef, a: ActionKind, on: &str) -> VaultResult<u64>;
  pub fn answer_for(&self, item_id: u64, project_key: &str, a: ActionKind, s: AnswerScope) -> VaultResult<Option<OwnerAnswer>>;
  pub fn answers_for_item(&self, item_id: u64) -> VaultResult<Vec<OwnerAnswer>>;
  pub fn remove_answer(&mut self, id: u64) -> VaultResult<bool>;
}
// vault/usage.rs (B1)
impl Vault {
  pub fn record_item_use(&mut self, u: &NewItemUse) -> VaultResult<u64>;
  pub fn item_uses(&self, item_id: u64, limit: usize) -> VaultResult<Vec<ItemUse>>;
  pub fn agent_uses(&self, agent_id: u64, limit: usize) -> VaultResult<Vec<ItemUse>>;
  pub fn item_use_summary(&self, item_id: u64) -> VaultResult<UseSummary>;
  pub fn record_interaction(&mut self, kind: InteractionKind, detail: &str) -> VaultResult<()>;
  pub fn interactions_per_week(&self, weeks: usize) -> VaultResult<Vec<(u64, u64)>>;
}
// vault/agent_items.rs (T2): set_item_origin / item_origin / items_created_by(agent_id, since)
//   open_credential_request / credential_requests(open_only) / settle_credential_request
//   propose_correction / corrections(open_only) / settle_correction
```

## 4. Conflicts and merge order

- `Sheet`/`Place` variants are pre-added by S1 with stub arms; `OwnerAction` variants by B1; `OwnerRequest` only by U2; wire `Action` variants only by T2.
- `PendingRun` has 11 construction sites; only B1 touches them, only those lines.
- Merge order: F0 → F1 → (B1, D1, S1, each rebased and re-tested) → Gate 1 → T2 → I2 → U2 → P2 → Gate 2 → N3 → M3 → V3 → R4.
- iPhone sync stops at schema 18 until `ios/` is rebuilt. A 17 phone copy still merges into the Mac; the Mac copy is `UnsupportedSchema` on the phone.
- Hard to reverse: schema 18 and the exception derivation; the `exec_grant` authority removal; the 300 s wait (re-check host tool timeouts in `docs/operations/host-hooks.md`).

## 5. Review gates

- **Gate 0** (after F0+F1): one judge — migration atomicity on a failing step, 17-copy merge, "nothing gets looser" in the exception derivation, `apassy-core` builds, no new dependency.
- **Gate 1** (after B1; D1/S1 a lighter single-judge pass): panel 2× opus + 1× fable on the hard rules of ADR 0025 §3 with adversarial tests.
- **Gate 2** (after Wave 2): panel on T2 (value never leaves, ownership, rate limit, capture refusals, oracle) and one UI judge on U2/I2.
- **Gate 3** (after N3+R4+M3): panel on the relay channel (E2E envelope, signature verification, replay, first valid answer, APNs payload without content, team routing).
