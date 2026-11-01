# PR 44 independent security review

Reviewed starting head `8ecc822c65bd88cfdc06ecee9aa8bf9706a19f0e` on
2026-11-01. Main was already merged. This review permits fixes, push and CI,
but no merge. All evidence below is source inspection or synthetic regression
fixtures. No owner vault, keychain, running app, agent configuration, LaunchAgent,
MCP tool or browser was accessed. No local compilation or test execution occurred.

## Confirmed defects and repairs

| Severity | Original attack | Repair and regression |
| --- | --- | --- |
| P1 | An unsandboxed agent inherits `APASSY_SESSION`, sends `code` to the owner socket during an open owner window, and receives a code without a new owner decision. The socket has no peer check; its bearer token does not attest the owner. | `ask_owner_for_cli` always takes the fresh path. No `LocalWindowSource` permits `CliCode`. UI fixtures assert both show and copy still wait inside a seeded window; proof fixtures check exact item, field and show/copy binding and revocation. |
| P1 | A connector token contains an `otpauth://totp` URI. `use_credential` reads that field directly, without `process_binding`; a destination receives the seed and can return just its extracted key, evading a whole-value echo check. | `read_call_secret` refuses setup keys before HTTP execution, with a constant error. A synthetic connector fixture retains its grant and bouncer and must receive `setup_key_refused`, without an owner question or seed in response/activity. |
| P2 | Output collection cuts a complete printed code at 64 KiB before literal masking, exposing up to five leading digits. | Truncated streams also redact a matching trailing prefix. A process fixture prints its generated code across both stdout and stderr limits; an ordinary untruncated partial number stays unchanged. |
| P1 | A run selects a code and a placeholder credential, then puts the code into an HTTP path, method or hostname. `network.requests` returns these fields without the generated-code mask. | Code runs erase event free text before proxy-log retention and release only aggregate network counts. Separate fixtures verify event erasure and the response allowlist. Ordinary runs retain their existing request detail. |

CLI window reuse is deliberately deferred. Every current CLI caller is unverified
as an interactive owner, including a legitimate terminal. The supported launcher
removes `APASSY_SESSION`, and its Seatbelt profile denies the owner socket; those
protections do not identify an unsandboxed shell caller. MCP/hook wrapper agent
tokens authenticate those adapters only. TTY state, environment markers and flags
are not owner attestation. The fresh check remains exact and local, with delivery
revocation; UI show/copy remain fresh. ADRs 0030/0034 and CLI/security/wire docs
record this restriction rather than claiming unsafe window reuse.

## Every execution route in `src/broker/run.rs`

| Route or alternate entry | Code authority |
| --- | --- |
| `check` / `RunRequest::validate` | Codes are explicit item IDs. Empty union, duplicates, more than 16 items, absent/ambiguous OTP settings, hidden/archived/restored items, missing ordinary bindings and environment collisions refuse before execution. No client skip-auth flag exists. |
| ADR 0033 `access_request_id` admission | `validate` refuses combining it with codes before the access-consent permit is consumed. It cannot become code execution approval. |
| `hard_rules` | Each code requires `known.answer[index]`; otherwise the owner question precedes model readiness, patterns and all later routes. Always ask, command flags, foreign database hosts and production vetoes still apply. |
| `known_state` / remembered `Route::Answer` | Exact item, canonical project, action and destination checks. Code coverage and stored-value coverage are independent; old password answers have `includes_codes = false`. Code-only answers cannot authorize a password. |
| No bouncer, no project, missing user request/declaration | Each returns `Route::Ask`, even with a remembered answer. |
| Unfit remembered answer, foreign destination/project | Each returns `Route::Ask`. A code-covering answer is necessary but does not waive other vetoes. |
| `Route::Pattern` | Reached only after the per-code hard veto. Code runs cannot offer or save a legacy item-only pattern. A password pattern cannot grant code authority. |
| `Route::Model` | Reached only after the same code veto. An allowing model cannot create code authority. Model rejection asks/refuses normally. |
| `Route::Ask` / local or signed remote answer | The exact pending question names code-bearing items and variables. Allow once applies to that pending run. In-project/production answers save explicit code/value bits after unchanged-state checks. The Touch ID window can satisfy a check only after an exact Allow once click; it never answers a question itself. |
| Joined/retried waiting questions | Pending-run identity includes code variable names, code-bearing item labels and the authorization baseline, including `code_field` and `includes_value`. A password approval cannot join a code run as the same request. |
| Retained evaluation scope | Not read as routing authority. The old-scope/pattern fixture asserts the code veto before model readiness. |
| Internal `evaluate_run` | Uses normal routing/approval checks, then stops before secret preparation, proxy creation or spawn. There is no agent evaluation action. |
| Final delivery | Reauthentication, unchanged item/binding/policy/project/command state and epoch checks precede seed parsing. Codes are generated after proxy setup, inside the live session delivery guard immediately before spawn. No cached code is injected into a later run. |

## Tool and exposure boundaries

- `list_access`: `catalog_for_agent` filters secret fields, notes, hidden details,
  passkeys and OTP setup fields/URIs. Added `has_code`/`code_env_name` are metadata.
- `describe_credential`: changes metadata of an agent-owned usable item; it neither
  selects a seed field nor returns a value. `item_answer` uses `process_binding`.
- `use_credential`: the connector seed refusal above closes its separate read path.
- `run_with_secrets`: both automatic and explicit legacy bindings refuse setup keys;
  selecting an OTP detail as an ordinary secret returns `needs_field`. Only explicit
  `codes` selection reaches `totp` after approval checks.
- Capture, generate, save and ask-owner tools return `item_answer`, never captured
  values. Capture has no vault-secret selector, denies protected Apassy/keychain
  paths/commands and executes with a cleared environment. Raw captured output is
  stored internally, not returned. An agent-owned update replaces a value, returns
  metadata and cannot read the previous value or relabel an owner's OTP field.
- Error text for OTP parsing/refusal is constant or item/field metadata, without
  seed or code values. The agent action enum exposes no seed export, owner `Code`
  action, owner-window token or clipboard API. Owner backup/export remains fresh.
- Code generation follows construction of model inputs, approval/relay cards and
  log entries. Activity records aggregate proxy counts, not request text. Operation
  status/receipts whitelist outcome metadata, excluding output and network details.
  stdout/stderr are masked, including embedded matches and collection-cut prefixes.
  Encoded, transformed or deliberately fragmented output remains outside the
  documented literal-masking guarantee.

## Timing and schema

`Totp::run_code_at` takes an injected clock and selects the next period at at most
five whole seconds remaining; CLI/UI use the current period. Existing boundary
fixtures include custom digits/periods. Each new spawn generates again, so a code
prepared before a wait cannot be reused after expiry. Idempotency retries return
metadata receipts rather than repeating an injection. A service may reject the
future code until its boundary; provider acceptance is unverified.

Schema 23 only adds checked `includes_codes DEFAULT 0` and
`includes_values DEFAULT 1` columns to local `owner_answer`, in the migration
transaction. Schema 21 migrates through 22; schema 22 adds these columns directly.
`merge::LOCAL_TABLES` excludes answers from sync; new readers accept 21/22 copies
under their existing merge rules without importing remote local authority.
`verify_user_version` in older 21/22 builds rejects 23 instead of interpreting its
answers. Restore clears local authority. The schema-22 fixture checks default
password-only authority and prevents password destination history from expanding
code coverage. CI owns migration and sync fixture execution.

## Validation

Locally permitted checks: `cargo fmt --all` and `git diff --check` only; passed.
Compilation, lint, builds, typechecks and Rust tests must run in GitHub CI for the
exact pushed head. Physical Touch ID, signed clipboard, Seatbelt runtime behavior,
real OTP-provider acceptance and device/relay delivery are unverified.

If the top-level agent needs focused local validation, recommended commands are:

```sh
~/.local/bin/heavy-check cargo test --locked --all-features --lib cli_code
~/.local/bin/heavy-check cargo test --locked --all-features --lib generated_code
~/.local/bin/heavy-check cargo test --locked --all-features --lib code_run
~/.local/bin/heavy-check cargo test --locked --all-features --test it a_connector_never_sends_a_totp_setup_uri
```

These commands were not run by this review worker. Full validation stays in CI.
