# Host hooks for the user request

Date: 2026-09-26. Decisions: [ADR 0008](../adr/0008-declarations-and-model-decisions.md) ("User request"), [ADR 0009](../adr/0009-general-by-default-and-learning.md) ("A trusted user request"), [ADR 0010](../adr/0010-closing-open-decisions.md).
Scope: goal item B6 in [goal.md](../goal.md). Use only synthetic values.

## 1. What the hook does

The bouncer compares each command with the user request (ADR 0008). Before this change, the agent sent the user request in the `user_request` argument of `apassy_run_with_secrets`. An agent can invent or change that text.

With the hook, the agent host sends the user request to Apassy directly:

1. The user submits a prompt. The host starts `apassy-hook` (a `UserPromptSubmit` hook) and writes the hook JSON to its stdin.
2. `apassy-hook` sends the prompt to the broker (`submit_user_request`, [broker contract](../contracts/broker-v0.md) section 3). It uses the agent token, like `apassy-mcp`.
3. The broker keeps the newest prompt for each agent and host session in memory.
4. When the agent calls `apassy_run_with_secrets`, the broker finds the hook prompt for the run. The hook prompt replaces the text from the agent. The bouncer gets the hook prompt.
5. Before the broker trusts the hook prompt, it checks the host transcript. The prompt must be the newest user message in the transcript file of the same session.
6. The approval card and the activity log show the request, its source, and a different text from the agent.

`apassy-hook` never writes to stdout, and it always exits with code 0. On both hosts, stdout of this hook becomes model context. So the hook does not change the prompt. If the broker is down or slow, the hook waits a maximum of 2 seconds, writes one line to stderr, and exits. The line does not contain the prompt.

Code: `src/bin/apassy-hook.rs`, `src/agent/hook.rs`, `src/broker/prompts.rs`, and a local step in `src/broker/run.rs`.

## 2. What the hosts give

Measured on 2026-09-26 on macOS 27.0, arm64, with a probe hook and a probe MCP server that recorded their input and environment. The goal names Claude Code 2.1.280. The installed version on the measurement day was 2.1.283.

| Item | Claude Code 2.1.283 | Codex 0.156.1 |
| --- | --- | --- |
| Hook configuration | `hooks` in `~/.claude/settings.json`, `.claude/settings.json`, `.claude/settings.local.json`, or `--settings` | `~/.codex/hooks.json`, `<repo>/.codex/hooks.json`, `[hooks]` in `config.toml`, or `-c` |
| Hook trust | none | Codex runs a hook that is not managed only after the owner trusts it in `/hooks`. `--dangerously-bypass-hook-trust` skips this for one run. |
| Hook input (stdin) | `session_id`, `transcript_path`, `cwd`, `prompt_id`, `permission_mode`, `hook_event_name`, `prompt` | `session_id`, `turn_id`, `transcript_path`, `cwd`, `hook_event_name`, `model`, `permission_mode`, `prompt` |
| Transcript path | `~/.claude/projects/<cwd with dashes>/<session_id>.jsonl` | `~/.codex/sessions/YYYY/MM/DD/rollout-<time>-<session_id>.jsonl`. The documentation says that it can be `null`. |
| Hook stdout on exit 0 | added to the model context | added to the model context as developer context |
| Hook environment | inherits the host environment, with `CLAUDE_CODE_SESSION_ID` and `CLAUDE_PROJECT_DIR` | inherits the host environment. No session variable. |
| Session ID for a stdio MCP server | `CLAUDE_CODE_SESSION_ID`, equal to the hook `session_id` | none. The server environment has only `CPATH`, `HOME`, `LANG`, `LIBRARY_PATH`, `LOGNAME`, `MANPATH`, `PATH`, `SDKROOT`, `SHELL`, `TMPDIR`, `USER`, `__CF_USER_TEXT_ENCODING`, and the `env` of the server configuration. `initialize` and `tools/list` have no session ID. |
| User prompt in the transcript | `{"type":"user","message":{"role":"user","content":"<prompt>"}}`. A tool result is also `"type":"user"`, with `tool_result` blocks. | `{"type":"event_msg","payload":{"type":"item_completed","item":{"type":"UserMessage","content":[{"type":"text","text":"<prompt>"}]}}}`. Codex also writes context as `role: user` messages. |

Notes:

- Claude Code documentation (`env-vars`): after `/clear`, the hook gets a new session ID. An MCP server keeps the ID that it started with. After `--continue` or `--resume` without an ID, an MCP server can get the first session ID.
- Codex documentation (`hooks`): the transcript format "isn't a stable interface for hooks and may change over time".
- A Codex hook started from a terminal of a Claude Code session had `CLAUDE_CODE_SESSION_ID` of that Claude Code session in its environment. So `apassy-hook` reads the session only from the hook JSON. `apassy-mcp` reads `CLAUDE_CODE_SESSION_ID`, because Claude Code sets it for its own MCP servers, and Codex gives its MCP servers a clean environment.
- The Codex `tools/call` request was not measured, because the account was at its usage limit. So it is not known if Codex sends a session ID in `_meta`.

## 3. How the broker finds the hook prompt for a run

Code: `PromptStore::resolve` in `src/broker/prompts.rs`.

1. `apassy-mcp` sends `CLAUDE_CODE_SESSION_ID` as `host_session` with each request. If the store has a prompt of the same agent and session, the run uses it.
2. Otherwise, the run uses the newest prompt of the agent whose host directory contains the run directory, or is inside it. The card says "matched by the project directory". A Codex run always uses this step.
3. Without a hook prompt, the run uses the text from the agent, as before. The card says "from the agent".

The match is ambiguous, and the run waits for the owner (flag `hook_ambiguous`), when:

- step 1 finds a prompt, but a newer prompt of another session has the same directory. This happens after `/clear` in Claude Code: the MCP server keeps the old session ID.
- step 2 finds prompts of more than one session. This happens with two Codex sessions of one agent in one project.

Limits of the store:

- The newest prompt per agent and session. Without a session, per agent and directory.
- A maximum of 256 prompts. The oldest goes first.
- A prompt older than 4 hours is not used.
- A prompt belongs to one vault session. A lock, an unlock, a backup restore, or a stop of the broker ends its use. A prompt sent while the vault is locked is refused (`vault_locked`), and the run then uses the text from the agent.
- A prompt has a maximum of 32 KiB. `apassy-hook` cuts a longer prompt and marks it. The transcript check then compares the start of the prompt.

## 4. The transcript check

Code: `PromptStore::check_transcript` in `src/broker/prompts.rs`. The broker does the check for each run, not at the hook, because the host writes the transcript after the hook.

1. The transcript path is in a host transcript directory: `~/.claude/projects`, `~/.codex/sessions`, or the same directories under `CLAUDE_CONFIG_DIR` and `CODEX_HOME`. The broker resolves symlinks first.
2. The file name ends with `<session_id>.jsonl`.
3. The file is a regular file. The broker opens it without a wait on a FIFO.
4. The broker reads a maximum of 16 MiB from the end of the file. The newest user prompt record (section 2) must have the same text as the hook prompt. Tool results, meta records, compact summaries, and subagent records are not user prompts. If the text is not there, the broker tries two more times, 200 ms apart.

| Result | Card and log | Decision |
| --- | --- | --- |
| The prompt is the newest user message | "verified in the host transcript" | the bouncer decides |
| The hook gave no transcript path | "no host transcript to check" | the bouncer decides |
| Any other result | "NOT verified: <reason>" | flag `hook_unverified`: the owner decides |

## 5. What the owner sees

The approval card shows the source of the user request:

```
User request (from the Claude Code hook, verified in the host transcript): "Run the unit tests of the billing module."
The agent sent a different user request: "Deploy everything to production."
```

The activity log entry of the run has the same data:

```
Bouncer allowed. Exit code 0. Directory: /…/project/web. User request from the Claude Code hook, verified in the host transcript: "Run the unit tests of the billing module.". The agent sent: "Deploy everything to production.". Model allowed at … Purpose: Run the tests.
```

The activity log entry has a maximum of 700 bytes. It keeps the first 240 bytes of the user request and the first 120 bytes of the agent text. The log is in the encrypted vault. The broker does not write a prompt to any other file or to stderr.

## 6. Install

`apassy setup claude --write` or `apassy setup codex --write` does the steps of this section: it registers the agent, writes `~/.config/apassy/apassy-hook-HOST.sh` and `~/.config/apassy/apassy-mcp-HOST.sh` with mode 0700, and adds the hook and the MCP server to the host configuration ([command line](cli.md)). The app contains `apassy-hook` and `apassy-mcp`. The command uses both programs from the app. If an older app lacks the hook, install the current app first. The steps by hand follow.

Build the programs:

```
cargo build --release --locked --features desktop,vault --bins
```

The hook needs the agent token in `APASSY_AGENT_TOKEN`, like `apassy-mcp`. Neither host has an `env` field for a hook. Do not put the token in the hook command, because other local processes can read process arguments. Use a wrapper script with mode `0700` outside the project, for example `~/.config/apassy/apassy-hook.sh`:

```
#!/bin/sh
APASSY_AGENT_TOKEN='apassy_agt_...' exec /path/to/target/release/apassy-hook
```

```
chmod 700 ~/.config/apassy/apassy-hook.sh
```

Keep `apassy-hook` in the name of the wrapper. The `hook_channel` flag (section 7) looks for this name. After "Rotate token" in Agents, put the new token in the wrapper and in the MCP server configuration.

### Claude Code

Add the hook to `~/.claude/settings.json`, or to `.claude/settings.local.json` in the project. Do not commit a file that contains a token.

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          { "type": "command", "command": "/Users/me/.config/apassy/apassy-hook.sh", "timeout": 5 }
        ]
      }
    ]
  }
}
```

In the Apassy profile, also set `"sandbox": { "enabled": false }` ([isolation.md](isolation.md) section 3).
Set the MCP server as in [agent-path.md](agent-path.md) section 4. `apassy-mcp` reads the session ID itself.

### Codex

Put the hook in `~/.codex/hooks.json`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          { "type": "command", "command": "/Users/me/.config/apassy/apassy-hook.sh", "timeout": 5 }
        ]
      }
    ]
  }
}
```

Start Codex, open `/hooks`, and trust the hook. Codex does not run the hook before that. After a change of the hook, trust it again.

Set the MCP server in `~/.codex/config.toml`:

```toml
[mcp_servers.apassy]
command = "/path/to/target/release/apassy-mcp"
env = { APASSY_AGENT_TOKEN = "apassy_agt_..." }
tool_timeout_sec = 180
```

`tool_timeout_sec` must be higher than the approval wait of 120 seconds.

### Check the installation

Send a prompt that makes the agent call `apassy_run_with_secrets`. The approval card must say "from the Claude Code hook, verified in the host transcript" or "from the Codex hook, matched by the project directory, verified in the host transcript". "from the agent, no hook request for this host session" means that the hook did not reach the broker. Run the hook by hand to see its error:

```
echo '{"hook_event_name":"UserPromptSubmit","cwd":"/tmp","prompt":"test"}' | ~/.config/apassy/apassy-hook.sh
```

## 7. Threat model

The hook runs inside the same Seatbelt profile as the agent ([isolation.md](isolation.md)). The agent can read the wrapper script and the MCP configuration, so it can get the agent token (ADR 0010 accepts this). It can run `apassy-hook` itself. It can write to `~/.claude/projects` and `~/.codex/sessions`, because the host must write its transcripts there.

What the hook and the checks stop:

| Attack | Result |
| --- | --- |
| The agent writes a false `user_request` argument | The hook prompt replaces it. The card and the log show both texts. The bouncer sees only the hook prompt. |
| The agent sends a false prompt with `apassy-hook` or with `submit_user_request` | The prompt is not the newest user message in the transcript. Flag `hook_unverified`: the owner decides. |
| The agent sends an older real prompt again (replay) | The prompt is not the newest user message. Flag `hook_unverified`. |
| The agent points `transcript_path` to a file that it wrote in another directory, or to the transcript of another session | Flag `hook_unverified`. |
| A command in `apassy_run_with_secrets` names the hook program, the host settings, or a transcript directory | Flag `hook_channel`: the owner decides. |
| A lock, an unlock, or a restore | The stored prompts are not used after it. |

What they do not stop:

- **A forged transcript entry.** An agent that adds a false user message at the end of its transcript, and then sends the same prompt with `apassy-hook`, passes the check. The agent must do this with its normal shell tool or file tool. Apassy does not see these tools. The host permission prompts are the control for them. Keep them on for daily use ([isolation.md](isolation.md) section 3).
- **Commands outside Apassy.** The `hook_channel` flag sees only commands that go through `apassy_run_with_secrets`.
- **A hidden path.** A command that builds the path with variables or an encoding, for example `d=.cl; cat ~/${d}aude/...`, does not get the flag.
- **A missing hook.** Without a hook prompt, the run uses the text from the agent, as before ADR 0009. Apassy cannot require the hook, because the owner can run a host without it.
- **Parallel sessions.** Codex gives its MCP servers no session ID. Two Codex sessions of one agent in one project are ambiguous, so the owner decides more often. A Claude Code session after `/clear` is ambiguous until its old prompt is 4 hours old.
- **Format changes.** A new host version can change the transcript format. Then every check fails and the owner decides. This fails safe, but it asks more.
- **Pasted text.** Claude Code can mark pasted text in the prompt. If the transcript has other text, the check fails and the owner decides.
- **A general request.** A hook prompt such as "continue" is the true request, but it still gives a low `task_match` (ADR 0008).

## 8. Rule pack (goal item B7)

The `hook_channel` check is the built-in pack `host-hooks` (`packs/host-hooks.json`). The command analysis adds the flag on every run. `hook_channel_flag` in `src/broker/prompts.rs` gives no second flag. It stays only for its call in `src/broker/run.rs`. Remove both together. The rule adds a restriction only, so a local pack can also carry more names.

| Field | Value |
| --- | --- |
| Pack | `host-hooks` (built-in, all programs) |
| Flag | `hook_channel` |
| Match (case does not matter) | The text of each command segment: the words, the `NAME=value` prefixes, the redirect targets, and the here-document. The text contains `apassy-hook`, `.claude/`, `.claude.json`, `.codex/`, `claude_config_dir`, or `codex_home`; or a word ends with `.claude` or `.codex` (after a trailing `/` is removed). |
| Effect | ask the owner |
| Reason | the command can send a false user request or change a host transcript or hook setting |
| Difference to the old check | The old check read the argument list as one text. The pack reads the parsed segments, so it also finds a name after the shell removes quotes, for example `~/.cla""ude/`. A usage request of a known tool, for example `git --help ~/.claude`, does not get the flag, because it only prints usage. |
| Tests | `hook_channel_commands_are_flagged` in `src/broker/prompts.rs` (through the analysis), `a_command_that_names_the_hook_channel_waits_for_the_owner` in `tests/host_hook.rs`, and the hook lines of `tests/fixtures/rule_packs/coverage.tsv` |

## 9. Measured results

### Tests

`cargo test --locked --features desktop,vault --test host_hook` starts a real broker and runs the real `apassy-hook` program. The transcripts are synthetic files in the formats of section 2.

| Test | Shows |
| --- | --- |
| `hook_request_replaces_the_agent_text_and_matches_the_transcript` | The request in the activity log is equal to the newest user prompt of the transcript (read by the test itself). The bouncer state has the hook prompt, not the agent text. The log also has the agent text. |
| `approval_card_shows_the_source_and_the_difference` | The card data: request, source, and the different agent text |
| `a_false_hook_request_waits_for_the_owner` | A false prompt, a replay, and a transcript outside the host directories give `hook_unverified`. The model is not called. |
| `a_command_that_names_the_hook_channel_waits_for_the_owner` | `apassy-hook`, a transcript file, and `.codex/hooks.json` in a command give `hook_channel` |
| `codex_hook_request_matches_by_project_directory` | A Codex hook prompt and a run without a session: match by directory, verified in a Codex transcript |
| `a_lock_ends_the_hook_request` | After a lock and an unlock, the run uses the agent text. A locked vault refuses the hook request, and the hook exits with 0. |
| `the_hook_never_blocks_the_prompt` | No broker, a broker that does not answer (the hook ends after about 2 s), no token, bad JSON, and another event: exit code 0, empty stdout, no prompt on stderr |

Unit tests: `src/broker/prompts.rs` (9) and `src/agent/hook.rs` (5).

Checks on 2026-09-26, macOS 27.0, arm64:

| Command | Result |
| --- | --- |
| `cargo fmt --check` | PASS |
| `cargo clippy --locked --all-targets --features desktop,vault -- -D warnings` | PASS |
| `cargo test --locked --features desktop,vault` | PASS: 229 passed, 0 failed, 7 ignored (the two real-host tests of this document and 5 earlier manual tests) |

### Real Claude Code session

Test: `cargo test --locked --features vault --test host_hook real_claude_code_session_sends_the_user_request -- --ignored --nocapture`. It is ignored by default, because it needs the `claude` program, an account, and the network.

On 2026-09-26, Claude Code 2.1.283 (`--model haiku`, headless) ran inside the Apassy profile through `apassy-sandbox`, with the Bash sandbox off. The hook was the wrapper script of section 6. The vault, the item `DEMO_KEY`, and the command `sh -c 'test -n "$DEMO_KEY" && echo key-present'` were synthetic. The grant was in "ask" mode. The test approved the run.

| Check | Result |
| --- | --- |
| Approval card source | `from the Claude Code hook, verified in the host transcript` |
| Approval card request | equal to the prompt |
| Newest user message in `~/.claude/projects/…/c84128b8-77db-4c00-9f2f-b2e3b356478e.jsonl` | equal to the prompt |
| Activity log | `Owner approved. Exit code 0. … User request from the Claude Code hook, verified in the host transcript: "<prompt>".` |
| Agent text | equal to the prompt, so the card showed no difference |
| Agent reply | `key-present`. No secret value in the output or the log. |
| Duration | 12 seconds |

### Real Codex session

Test: `cargo test --locked --features vault --test host_hook real_codex_session_sends_the_user_request -- --ignored --nocapture`.

On 2026-09-26, Codex 0.156.1 (`codex exec`) ran inside the Apassy profile with `sandbox_mode="danger-full-access"`, the hook as a `-c` override, and `--dangerously-bypass-hook-trust`.

| Check | Result |
| --- | --- |
| Hook in the profile | ran and reached the broker |
| Transcript check | verified in `~/.codex/sessions/…/rollout-…jsonl` (record `item_completed` / `UserMessage`) |
| Model turn | did not run: "You've hit your usage limit." Exit code 1. |
| Run | The test sent the run as `apassy-mcp` does under Codex: no host session, agent text "check the key" |
| Approval card source | `from the Codex hook, matched by the project directory, verified in the host transcript` |
| Activity log | the prompt, and `The agent sent: "check the key".` |

The test ran again on 2026-09-26 at 18:00, after the usage limit reset. The Codex agent itself called `apassy_run_with_secrets` through `apassy-mcp`.

| Check | Result |
| --- | --- |
| Model turn | ran; the agent called the tool once |
| Approval card source | `from the Codex hook, matched by the project directory, verified in the host transcript` |
| Activity log | "Owner approved. Exit code 0." The user request is the hook prompt, verified in the host transcript. |
| Model facts in the log | `task_match` 95%, `writes` 2%, `remote` 2%, `leak` 2%, `destroy` 2% |
| Test result | `1 passed; 0 failed`, 25.5 seconds |

Goal item B6 is done for both hosts.

## 10. Limits

- The measurements used one Claude Code version and one Codex version. A host update can change the hook input or the transcript format.
- The real-host tests are manual. The synthetic tests run in every `cargo test`.
- The broker does not require the hook. See section 7.
- The real-secret gate stays BLOCKED until the goal marks its gate items done.
