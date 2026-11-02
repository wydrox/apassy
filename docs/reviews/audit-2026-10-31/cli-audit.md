# Apassy CLI and agent interface audit — 2026-10-31

Audited source: `af738b3c398782402db48fca47ed73b3580417b1`, fetched `origin/main`, checked out as `audit/cli` in `/Users/rafalw/.t3/worktrees/apassy/t3-ac5aecfa`. Findings below refer to this checkout, not to potentially different files in the report destination checkout. Main includes the October 31 fixes; the fixed CSV Website/trailing-data/unterminated-quote issues, MCP frame bound, and unsandboxed onboarding command are excluded.

**Result: P0 0, P1 2, P2 7, P3 4 (13 findings).** The highest-value repair is terminal setup: its new agent does not see existing credentials, despite the success instructions saying it does. The other P1 is the mismatch between a blocking stdio adapter, timeout configuration, and immediate retry guidance.

## Verification boundary

Read-only source review covered `src/cli/`, `src/desktop/owner_cli.rs`, `src/main.rs`, the requested ADR and operations guide, README, Settings CLI installation, onboarding/setup, all five requested agent/developer binaries, `src/agent/`, and the sandbox profile. Targeted reads of vault registration/visibility and broker waiting/execution established cross-layer mechanisms. No source edits, cargo, builds, installs, vault access, unlock, owner command execution, broker connections, or Apassy MCP tool calls were performed. Only this report was written; the branch/fetch operation was explicitly requested.

Installed help checks used `/Applications/Apassy.app/Contents/MacOS/`: `apassy --help`, plus 60 owner command/group/subcommand help paths, all nonempty stdout and exit 0. The latter covered status/login/logout/lock/unlock/add/import, every advertised item/agent/grant/request/runs/pattern action, activity, decisions export, vault backup/change-passphrase/restore, doctor, setup claude/codex/browser, and completion shells. `apassy-mcp --help`: exit 2, 0 stdout bytes, 80 stderr bytes. `apassy-hook --help`: exit 0, 0 stdout bytes, 73 stderr bytes. `apassy-sandbox --help`: exit 0, 1,707 stdout bytes. Packs/eval were reviewed statically; neither was run. Help checks do not establish installed/source version equivalence or functional acceptance. Proposed reproduction cases below were traced in source, not run against the owner.

## Ranked findings

### F01 — P1: terminal setup connects an agent with an empty catalog

**Locations:** `src/cli/setup.rs:280`, `src/desktop/owner_cli.rs:785`, `src/desktop/owner_cli.rs:1981`; supporting `src/vault/agents.rs:163`, `src/vault/agents.rs:618`, `src/vault/exceptions.rs:135`.

**Impact:** Following `apassy setup claude --write` or `codex --write` on an existing vault can yield a working MCP connection with none of the owner's existing credentials visible. The success message says the opposite (`setup.rs:330`). An agent may ask the owner to add a credential already present.

**Evidence:** Setup uses `Command::AgentAdd`; checked registration inserts an agent without setting `see_all` (schema default 0). The agent view is restricted unless `see_all == 1`; new agents have no listed items/grants. GUI onboarding explicitly requests `ConnectAgent { show_all: sees_nothing }` (`agent_onboarding.rs:144–160`), which this path never does. Broker catalog visibility follows that view (`src/broker/decide.rs:359`).

**Fix sketch:** Add an explicit checked connection operation for terminal setup that includes catalog visibility in the fresh owner approval, matching GUI connection semantics for a new agent. Preserve deliberately restricted existing agents. Do not change the global registration default or silently broaden visibility. Immediate documented workaround: `apassy agent see-all NAME on`, with its separate owner check. Acceptance: synthetic populated vault; both setup hosts can list existing items after one connection approval, while raw registration and restricted reconnect remain restricted.

### F02 — P1: timeout/retry instructions conflict with the serial MCP adapter

**Locations:** `src/agent/mcp.rs:95`, `src/agent/mcp.rs:163`, `src/agent/mcp.rs:217`, `src/cli/setup.rs:598`; supporting `src/broker/server.rs:31`, `src/broker/server.rs:62`.

**Impact:** An owner wait followed by a valid command can exceed the configured host timeout. A host timeout is then presented as something to fix by repeating a potentially mutating command. The adapter cannot process that repeat while the original synchronous call is still running.

**Evidence:** `run_stdio` reads a frame, calls `handle_message` synchronously, and only then reads another. Calls block in `send_with` for up to 600 seconds. Host setup specifies 330 seconds, whereas broker defaults permit 300 seconds of owner waiting plus 300 seconds of command execution, before other overhead. A 290-second owner response plus a 60-second command is already 350 seconds. Cancellation notifications and retry frames remain unread until the original call finishes. Broker question reattachment exists, but cannot be reached promptly through this blocked stdio loop. `question_waiting` also means a *different* outstanding question in broker paths (`src/broker/run.rs:120`), while the run description says simply repeat. Duplicate side effects are a risk if a completed original is retried; they were not reproduced here.

**Fix sketch:** For 0.5.8, set a conservative host timeout above the full supported broker budget (for example 660 seconds), update existing managed configs through an explicit compatible migration, and distinguish pending owner question from uncertain execution outcome in instructions. Do not promise safe replay of an executed command. Later: concurrent bounded MCP dispatch, cancellation semantics, execution IDs and retrieval/idempotency. Acceptance: delayed synthetic approval plus a 60-second command; ensure host receives the original outcome once, and a second question gets actionable busy guidance.

### F03 — P2: `--json` does not reliably produce one machine-readable response

**Locations:** `src/cli/doctor.rs:294`, `src/cli/doctor.rs:310`, `src/cli/mod.rs:249`, `src/cli/setup.rs:293`, `src/cli/commands.rs:323`, `src/cli/commands.rs:1746`.

**Impact:** Scripts following `docs/operations/cli.md:249` cannot use one consistent success/error parser.

**Evidence:** Failed doctor first prints its JSON report, then returns `Failure::App`, causing the outer reporter to print a second JSON document. Setup success always prints prose/config snippets, without consulting `cli.json`; a late failure appends JSON to prose. Logout ignores JSON and emits shell syntax or a sentence. Decisions export emits JSONL or no stdout for a file, even with `--json`. Help/version/completion text is also deliberately non-JSON but has no documented exception contract.

**Fix sketch:** Return `Failure::Printed` after a failed JSON doctor report; add structured setup/logout results with human progress on stderr; make export JSON return an envelope containing JSONL or output metadata, preserving normal JSONL export. Define text-only help/version/completion exceptions explicitly. Acceptance: exact single-document parsing for success, local failure, broker refusal and partial setup; assert exit status too. No owner data needed in fixtures.

### F04 — P2: setup recovery creates new agents and changes credentials before all preflight checks

**Locations:** `src/cli/setup.rs:254`, `src/cli/setup.rs:280`, `src/cli/setup.rs:291`, `src/cli/setup.rs:575`, `src/cli/setup.rs:663`, `src/cli/setup.rs:364`.

**Impact:** Repeating the suggested setup command accumulates registrations and replaces the per-host token wrappers. Failure can leave a registered agent, replaced wrappers, MCP settings saved, and hook missing; an error can nevertheless say “Nothing was changed.” Existing host processes may still use the earlier agent token.

**Evidence:** Every non-`--token-stdin` invocation sends AgentAdd. Wrapper names depend on host, not agent identity. Hook validation occurs inside `merge_hook`, after registration/wrapper writes and after MCP setup. Existing MCP preflight is helpful but does not cover hook validity/disabled state. Even without `--write`, registration and wrapper writes happen; “print configuration” is not a side-effect-free preview (the detailed help does mention wrapper writes).

**Fix sketch:** Preflight both host and hook configuration, binary executability, and destination writability before registration or replacement. Report stages and partial state truthfully. Warn explicitly that setup without `--write` still registers/writes wrappers. For 0.5.8, avoid a complicated automatic reuse policy: provide a repair path that uses the existing managed token without reading it into output; later make connection/reconnect identity explicit and transactional. Acceptance: malformed/disabled hook config leaves existing wrappers and registrations intact; retry does not silently orphan a connection.

### F05 — P2: “installed” links and copied onboarding command do not establish shell readiness

**Locations:** `src/desktop/ui/settings.rs:1383`, `src/desktop/ui/settings.rs:1427`, `src/desktop/ui/cli_tools.rs:23`, `src/desktop/ui/agent_onboarding.rs:301`, `src/desktop/ui/agent_onboarding.rs:336`.

**Impact:** A successful GUI connection can end at `command not found: apassy-sandbox`. Settings tells a new user to “Add it to PATH” without supplying the shell command there. Moving the app can instead produce stale links and a generic conflict.

**Evidence:** The status checks exact symlinks and executable target bits, not the terminal environment. GUI connection does not install these links; its launch command uses a bare launcher name. The installer correctly avoids overwriting other commands, but its conflict remedy offers “choose another installation folder” although the UI exposes none (`cli_tools.rs:65`).

**Fix sketch:** Show separate link-installation and terminal-readiness explanations. Supply a copyable current-session PATH command and persistent shell-specific instructions; keep shell-file changes explicit. Copy an absolute, shell-quoted bundle launcher path from onboarding so GUI-only setup can work without CLI installation. Offer precise stale-Apassy-link repair guidance while preserving arbitrary files. Acceptance: Finder launch, no `.local/bin` in PATH, home/app path with spaces, conflicting regular file, and app relocation.

### F06 — P2: doctor can label a broken host setup healthy

**Locations:** `src/cli/doctor.rs:56`, `src/cli/doctor.rs:260`, `src/cli/doctor.rs:273`, `src/cli/doctor.rs:318`, `src/cli/setup.rs:450`.

**Impact:** The natural diagnostic can say “MCP server and prompt hook set” for comments, disabled configuration, missing wrappers, or unusable permissions. Recovery then becomes trial and error.

**Evidence:** Doctor reads configs as strings (errors become empty strings) and uses substring presence. It does not parse the effective server/hook definitions or check wrapper executable bits. It reads default Claude paths while setup honors `CLAUDE_CONFIG_DIR`. A missing hook with MCP present is only Note. Sandbox `--print` success is correctly described as profile “found”, but proves neither compilation nor enforcement.

**Fix sketch:** Reuse setup's config readers/managed-server validation with custom directory support; check referenced files and modes without displaying token-containing script contents. Distinguish unreadable/invalid/disabled/unverified. Keep enforcement explicitly unknown unless a separate synthetic self-test is requested. Acceptance: comments-only config, disabled hooks, custom Claude directory, and missing/non-executable wrapper fixtures.

### F07 — P2: unrelated MCP failures all tell the user to open the app

**Locations:** `src/agent/mcp.rs:396`, `src/agent/client.rs:65`, `src/agent/client.rs:79`, `src/agent/mcp.rs:768`.

**Impact:** Agents ask users to restart an already-running app for invalid-size requests, permission errors, timeouts, or malformed responses. Automation must parse text for all error codes.

**Evidence:** Every client `Err` becomes `broker_unavailable` with one generic next step; client errors include local `InvalidInput` before any connection and incomplete/invalid broker responses. Error tool results contain only text and `isError`, while success has `structuredContent`. In particular, a near-64-KiB saved value can exceed the serialized wire bound due to envelope/escaping overhead; this is an error-classification issue, not the already-fixed MCP line-bound defect.

**Fix sketch:** Classify local validation, missing/refused socket, permission, timeout/unknown outcome, and invalid response using allowlisted messages. Return structured `{code, message, next_step, retryable}` without token/value/serialized request data. Include socket-override guidance where relevant. Acceptance: synthetic socket/client errors and oversized input; assert no secret-bearing payload in diagnostics.

### F08 — P2: request-access description promises an owner channel that is CLI-only

**Locations:** `src/agent/mcp.rs:234`, `src/cli/commands.rs:135`, `src/broker/decide.rs:536`, `docs/operations/cli.md:234`.

**Impact:** An agent can think it has asked the owner while the normal GUI user never sees a pending note. It also cannot use this tool to discover an invisible existing credential: the tool requires a known catalog item ID.

**Evidence:** Description calls it a note to the owner, but omits the CLI-only inbox. The broker's success note finally names `apassy request list`; owner help/docs explicitly say the app does not show these notes. No run approval is granted by resolving a note.

**Fix sketch:** State up front that this is a legacy CLI-only note, requires a visible catalog ID, gives no permission, and produces no Decisions question. Prefer direct run/ask-owner guidance. Later decide whether to add a GUI inbox or retire this tool. Acceptance: description alone makes delivery/action expectations clear.

### F09 — P2: README first-run instructions have material drift

**Locations:** `README.md:127`, `README.md:128`, `README.md:132`; `docs/operations/cli.md:91`, `docs/operations/cli.md:249`; `docs/adr/0017-owner-command-line.md` authority table.

**Impact:** Users are directed toward source builds for a bundled hook, believe setup is finished before sandbox launch/trust checks, and overestimate the JSON contract. Old authority wording is particularly confusing after fresh-check changes.

**Evidence:** README says the hook needs `--hook PATH` from a source build, whereas setup auto-selects its sibling. It says nothing else is needed, then lists hook/sandbox as recommended; GUI now explicitly requires the sandbox launch and connection verification. Operations docs correctly include an October 31 superseding fresh-check note, but retain older session/authority wording, and JSON claims do not cover F03.

**Fix sketch:** One canonical installed-app walkthrough, linked from README: install/PATH, open/unlock, connect, launch sandbox, Codex trust, `/mcp`, synthetic first use. Remove obsolete source-hook requirement and reconcile session-free local commands and JSON exceptions. Mark ADR's old authority table as superseded at the table, linking ADR 0030. Acceptance: literal comparison of documented commands and current help/dispatch.

### F10 — P3: helper/developer binaries lack a consistent discovery contract

**Locations:** `src/bin/apassy-mcp.rs:10`, `src/bin/apassy-hook.rs:19`, `src/bin/apassy-packs.rs:44`, `src/bin/apassy-eval.rs:158`.

**Impact/evidence:** Installed MCP rejects help with exit 2; hook rejects help but exits 0. Packs has useful help but no version/JSON and uses exit 1 for both usage and validation failure. Eval treats `--help` as a filename and `expect`s its read; additional arguments are ignored, and startup/model/dump options live in comments/environment rather than discoverable help. Eval was not executed.

**Fix sketch:** Offline `--help`/`--version` before stdin, filesystem, vault fixture creation or network activity; usage exit 2; normal data/validation failure exit 1. Add packs JSON when practical. Hook runtime must retain its deliberate fail-open exit 0 contract; document a separate diagnostic/help contract rather than breaking prompt delivery.

### F11 — P3: sandbox's printed command cannot safely be pasted

**Location:** `src/bin/apassy-sandbox.rs:551`.

**Impact/evidence:** `--print` prints profile, `-D KEY=VALUE` paths, and host arguments without shell quoting. The default data path contains `Application Support`; spaces split arguments and shell metacharacters change meaning. Actual execution uses argument arrays and is not subject to this formatting bug. No sandbox invocation beyond help was run.

**Fix sketch:** Quote every shell word, or output an explicit JSON argv format and label human output non-executable. Show that APASSY_SESSION is removed; copying the printed raw sandbox-exec command currently loses that environment-removal behavior too. Acceptance: spaces, quotes, dollars, semicolons, and a placeholder inherited session in an isolated fixture.

### F12 — P3: tool schemas allow avoidable invalid first calls

**Locations:** `src/agent/mcp.rs:250`, `src/agent/mcp.rs:318`, `src/agent/mcp.rs:370`, `src/agent/mcp.rs:490`, `src/agent/mcp.rs:631`.

**Impact/evidence:** Capture schema requires neither command nor file and does not exclude both. Update requires only item_id, permitting missing or multiple sources. List ignores supplied arguments although its schema disallows them. Required run `user_request` becomes optional at adapter validation (wrong types also become None). The broker validates many of these inputs later; this is contract drift and wasted calls, not evidence of authorization bypass.

**Fix sketch:** Encode exactly one capture/update source with `oneOf`, enforce adapter/schema agreement, and surface byte/argument limits where agents can choose correct input. Preserve legacy wire compatibility separately if needed. Acceptance: malformed tool calls fail locally with one useful remedy and do not contact a broker.

### F13 — P3: redaction wording is stronger than the actual output guarantee

**Locations:** `src/agent/mcp.rs:217`, `src/broker/run.rs:1379`, `src/broker/exec.rs:349`.

**Impact/evidence:** Agents are told they never receive values and that secrets in output are replaced. Output masking matches the supplied literal values (longest-first, with boundary rules for short values); it cannot generally recognize an encoding, fragmentation, or an unrelated secret printed by a program. The existing “do not print them” instruction is good but does not state this boundary. No leak was reproduced.

**Fix sketch:** Say supplied literal secret values are masked, masking is not a guarantee for transformed/unrelated output, and commands should return only needed non-secret fields. Keep capture/generate preferred over transcript save. Broader output-control work belongs later; do not attempt ad hoc universal redaction in 0.5.8.

## First-run steps and friction

These are source-derived walkthrough counts, not observed user timings or native acceptance. Baseline: installed app, existing vault with a test credential, host CLI already installed, app initially closed, `.local/bin` absent from PATH, no CLI links/session/host connection. A step is a user action/command or approval; opening Settings > Tools counts as one navigation action, project selection plus pasted launch counts as one action, and checking the first test result plus Decisions counts as one verification action. A new vault/credential adds at least two conceptual actions; native setup/password interactions may add more. Documentation's four numbered paragraphs are not a four-action onboarding.

**GUI route with owner CLI installation: 12 actions for Claude, 13 for Codex.** (1) Open app; (2) unlock; (3) Settings > Tools; (4) install links; (5) set current terminal PATH; (6) persist PATH for later shells; (7) Agents > +; (8) select host (selection submits connection); (9) owner approval; (10) select project/start copied sandbox command; (11) `/mcp`; (12) test request and inspect Decisions. Codex adds `/hooks` trust before test use. Host login/trust prompts are additional conditional work. GUI connection itself does not need `apassy login`.

**Terminal setup route: 15 actions for Claude, 16 for Codex.** First six actions as above, then (7) `eval "$(apassy login)"`; (8) session owner approval; (9) `apassy setup HOST --write`; (10) registration owner approval; (11) `apassy agent see-all NAME on`; (12) visibility owner approval; (13) project/sandbox launch; (14) `/mcp`; (15) test and Decisions. Steps 11–12 are the currently necessary, undocumented F01 workaround. The advertised route omits them and is shorter but fails the existing-credential objective.

**After the proposed 0.5.8 fixes:** terminal route **13/14** (Claude/Codex), removing the extra visibility command and approval by including catalog consent in the connection check. GUI + CLI installation remains **12/13**; clearer copy removes guesswork rather than artificially claiming clicks disappear. GUI-only connection can be **8/9**, omitting the four CLI-installation/PATH actions when onboarding copies an absolute bundle launcher path; this does not constitute installing the owner CLI. No proposal removes owner consent, unlock, Codex hook trust, or verification.

Principal friction: GUI status measures links, not PATH; a running unlocked app is required for agent use; owner CLI needs a separate session and some actions need another fresh check; helper paths/modes/config errors can create partial setup; a saved host configuration is not evidence of broker reachability or a successful first request. Socket errors should distinguish missing app from wrong path, permission, timeout and protocol failures. Ordinary owner socket missing/refused errors already name the path and suggest opening the app (`src/owner/client.rs:43`); retain that useful behavior.

## Command and agent-tool coverage notes

- **Owner commands:** help/dispatch covers all advertised groups. Item/agent/grant/request/runs/pattern lists default to list; decisions defaults to export. Item and agent identifiers accept IDs or exact names; ambiguity must remain explicit. Global JSON/socket/help/version and aliases are convenient. Args refuses leftovers, but `required()` does not consume positionals after `--` (`src/cli/args.rs:110`), so leading-dash item names do not get normal separator handling; a later parser cleanup should support this and avoid consuming another option as a missing value.
- **Secrets/session:** add and item mutations use hidden prompts/stdin/files; login refuses casual terminal token output unless explicitly requested and supports shell output. Owner exit codes are centralized (0/1/2/3); doctor intentionally uses 1 for failed diagnostics, unlike a direct missing-app call's 3. No runtime refusal/exit path was tested against the owner. Backup/export/token issuance fresh approvals must stay intact.
- **Import/history/vault:** recent fixes are excluded. Bind partial failures have a deliberate single-response path; apply that pattern to doctor. Export has secure create-new output but F03 JSON inconsistency. Vault restore is a GUI operation, not headless restore. No file was imported or exported.
- **Completions/setup browser:** completions include commands/subcommands/global flags, not every command-specific flag or dynamic vault names. Browser setup is local/session-free but has the same prose-only JSON gap because it does not receive Cli. Do not call these missing-session errors in documentation.
- **MCP list/use/run:** list describes catalog IDs/env names and needs-field correctly; use names operations and returns permitted fields; run correctly requires argv, absolute cwd, purpose and quoted user request. It should say clearly that a nonzero child exit or `timed_out` in a successful tool response means the operation failed; `isError:false` alone is insufficient (`src/broker/run.rs:1371`, `src/agent/mcp.rs:722`).
- **Capture/generate/ask/save/update/describe:** preference order is strong: capture or generate, then owner paste, transcript save only as last resort. Extract is hidden; generation gives no value; update explicitly restricts creator ownership and preserves history; describe explains narrowing placeholder scope. Capture/update source schemas need F12. Limits are partly prose-only and spread across tools. Ask-owner explains `waiting`, dismissed and other pending questions more accurately than the generic run retry guidance. Use it as the wording model.
- **Waiting/redaction:** five-minute owner wait is real; it is not the whole run duration. Question reattachment and superseded waits exist in broker code; F02 is specifically the adapter/host contract. Structured error metadata is absent (F07). Literal masking and hidden capture are present; F13 is a guarantee-wording boundary, not a demonstrated secret leak.
- **Hook/sandbox:** hook limits input, wipes its byte buffer after parsing, avoids prompt/token diagnostics, and deliberately lets prompts proceed on failure with stderr only and a two-second broker timeout. Users who do not see host stderr have no durable hook-health indication; later add a non-secret last-success state. Sandbox fails closed on unreadable/invalid vault lists and excess protected paths, strips APASSY_SESSION and denies owner/app/helper routes while allowing MCP/hook and broker. Its profile intentionally blocks browser opening/automation and startup-file writes; onboarding should link those expected limitations. `--print` is not enforcement verification. No native sandbox enforcement was exercised.

## Ship in 0.5.8 — seven bounded work packets for one implementer

Estimates are planning ranges, not commitments; approximately 6–10 focused implementer-days plus integration review. No coordinated release or publication is authorized by this report.

1. **Fix terminal connection catalog consent (F01, 1–2 days).** Reuse GUI checked connection semantics for new setup agents, preserving raw registration and existing restrictions. This is the first merge priority.
2. **Make JSON output one documented contract (F03, 1–2 days).** Doctor first; then setup/browser/logout/export. Keep progress on stderr, structured stage/partial-state data in stdout, secrets excluded except deliberately requested issued tokens.
3. **Preflight setup and report partial changes truthfully (F04, 1 day).** Validate hook and managed host configs before registrations/wrapper replacement; explicit side effects without `--write`. Defer full reconnection transactions.
4. **Provide runnable first-run commands (F05/F11, 0.5–1 day).** Absolute quoted bundle launcher in GUI, copyable PATH instructions, correct shell quoting/environment semantics for sandbox print. Do not overwrite arbitrary conflicting commands.
5. **Contain timeout/retry confusion and preserve error cause (F02/F07, 1–2 days).** Raise managed host budget above owner+execution duration with a compatible config migration; improve question-waiting/unknown-outcome instructions; structured sanitized error categories. Do not claim this completes concurrent dispatch or replay safety.
6. **Make static doctor checks truthful (F06, 0.5–1 day).** Honor Claude config directory; parse effective entries and referenced executable paths; label connection/enforcement unverified.
7. **Align documentation and agent descriptions (F08/F09/F12/F13, 0.5–1 day).** Remove obsolete source-hook setup, document CLI-only notes and output bounds, add source-selection schemas and first-use checklist. Small offline MCP/hook help can fit here; broad eval UX can wait.

Each packet should have small synthetic contract tests covering the listed trigger and recovery, then a fresh integrated review. Native/installed acceptance should separately verify first connection, locked-vault recovery, rotated token, hook trust, custom paths, delayed owner response and first successful test request. This audit did not perform those checks.

## Later

- Bounded concurrent MCP dispatcher with cancellation handling, progress/status IDs, reconnect outcome retrieval and explicit deduplication guarantees; no blind replay of mutating commands.
- Transactional host connection/reconnect/repair tied to agent identity, with staged files, rollback, orphan handling and explicit custom-config migration. Do not silently broaden existing catalog access.
- Owner-visible hook health and a genuine sandbox/connection diagnostic using isolated synthetic fixtures. Keep plain doctor read-only and do not automatically exercise secrets.
- Decide the future of CLI-only access notes and obsolete grant-rule/mode flags that no longer authorize runs. Prefer explicit deprecation over a silent meaning change.
- Consistent offline help/version/usage codes and structured packs/eval output; clear eval environment/model/dump prerequisites and bounded input errors rather than panics.
- Parser separator/missing-value handling, command-specific completions, and discoverable untruncated metadata output where table truncation obscures names.
- Stronger output policy for transformed/unrelated secrets, assessed separately from literal masking; avoid overclaiming what arbitrary child stdout can guarantee.
