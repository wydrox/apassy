# Agent path — local demo and agent setup

Date: 2026-09-25.
Scope: the thin agent path in [ADR 0004](../adr/0004-agent-path-first.md). Use only synthetic values.

## 1. Build

```
cargo build --release --locked --features desktop,vault --bins
```

The build makes three programs in `target/release/`:

- `apassy` — the desktop app. It starts the broker.
- `apassy-mcp` — the MCP adapter for an agent host.
- `apassy-dev-reporting` — the synthetic reporting service.

## 2. Start the synthetic service

```
APASSY_DEV_REPORTING_TOKEN=FAKE-ALPHA-TOKEN-7731 ./target/release/apassy-dev-reporting 8787
```

The service listens on `127.0.0.1:8787`. It accepts only the token in `APASSY_DEV_REPORTING_TOKEN`.
It adds one extra field to each response. The broker must drop that field.

## 3. Prepare the vault

1. Start `./target/release/apassy`.
2. Create and unlock a vault.
3. In Credentials, click "Add" and select "API key". Put `FAKE-ALPHA-TOKEN-7731` in the Token field.
4. Open the credential. Under "Agent access", click "Connector". Type `http://127.0.0.1:8787` and click "Save". A real service uses `https://HOST`.
5. In Agents, click "Register". Type a name and click "Register".
6. Copy the token. Apassy shows it one time. Click "I saved the token". The token works for 30 days. "Token lifetime" in Settings changes this time for all tokens (1 to 365 days). "Rotate token…" on the page of the agent gives a new token and stops the old token at once. Put the new token in the MCP configuration.
7. On the page of the agent, under "API operations", turn on `get_sales_summary`.

## 4. Connect an agent host

The token sheet after "Register" shows an MCP configuration with the full adapter path. Example:

```json
{
  "mcpServers": {
    "apassy": {
      "command": "/path/to/target/release/apassy-mcp",
      "env": { "APASSY_AGENT_TOKEN": "apassy_agt_..." }
    }
  }
}
```

For Claude Code, put this block in the project `.mcp.json` file. Do not commit a file that contains a token.
The agent can then call `apassy_list_access` and `apassy_use_credential`.

## 5. Expected results

| Action | Result |
| --- | --- |
| Call before the grant | `not_granted` |
| Call after the grant | Six output fields. No token. No `internal_debug_note`. |
| Call with `project_id` `echo-token-canary` | `output_blocked` |
| Call with a locked vault | `vault_locked` |
| Call after "Revoke agent" | `unauthenticated` |
| Call after the token lifetime | `token_expired`. `apassy-mcp` tells the user to rotate the token. |
| Call with the old token after "Rotate token" | `unauthenticated` |
| Call while another vault is open ([several vaults](multiple-vaults.md)) | `unauthenticated`. The text says that the token is not valid for the vault that is open now. `apassy-mcp` tells the user to open the vault of the agent. |
| Call after a restore, before "Confirm settings" for the item | `review_required`. See [backup and restore](backup-restore.md). |
| Activity view | One row for each call and each refusal |

## 6. Checks on 2026-09-25

Host: macOS arm64. All commands gave exit code 0.

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --offline --locked --all-features --all-targets -- -D warnings` | PASS |
| `cargo clippy --offline --locked --features desktop --all-targets -- -D warnings` | PASS |
| `cargo clippy --offline --locked --all-targets -- -D warnings` | PASS |
| `cargo test --offline --locked --all-features --all-targets -- --test-threads=1` | PASS. `tests/agent_path.rs` has 8 tests, 2 of them for HTTPS. |
| `cargo test --offline --locked --features vault --lib public_https -- --ignored` | PASS. Manual check with network access. `example.com` passes. `wrong.host.badssl.com` gives a TLS failure. |
| `cargo test --offline --locked --features vault --doc` | PASS, 6 compile-fail checks |
| `python3 tests/isolation/test_fixture_boundary.py` | PASS |

The test `sandboxed_adapter_uses_broker_but_cannot_read_vault` has three steps:

1. A same-user process without a sandbox reads the vault file. This is the control.
2. A process in a fixture `sandbox-exec` profile cannot read the vault file.
3. The adapter in the same profile calls the broker and gets the permitted output.

A GUI run on 2026-09-25 did steps 1 to 7 in section 3 in the native window. Then `apassy-mcp` gave `not_granted` before the grant, the six output fields after the grant, and `vault_locked` after a lock. The Activity view showed the rows.

## 7. Run with a real agent host

On 2026-09-25, a headless Claude Code 2.1.282 session (model `claude-opus-5-5`) used the adapter.
The session used a temporary configuration file with `--mcp-config` and `--strict-mcp-config`. The permitted tools were only the two Apassy tools. The session did not change the user or project MCP configuration.
The owner permitted only `get_sales_summary` for the agent.

The task had four steps: list access, get a sales summary, get a report job status, and try to get the raw token.

| Tool call | Result |
| --- | --- |
| `apassy_list_access` | One item and one operation |
| `apassy_use_credential` with `get_sales_summary` | `EUR`, `12840.50`, `318` orders. Six fields only. |
| `apassy_use_credential` with `get_job_status` (a name that the agent guessed) | `not_granted` |
| `apassy_use_credential` with `reveal_token` | `not_granted` |

The transcript had zero copies of the agent token and zero copies of the service token.
The agent reported that it saw no secret value. The Activity view showed each call, including the `reveal_token` attempt.

Findings from this run:

- The broker checks the grant before the profile. An unknown operation name gives `not_granted`, not `unknown_operation`. This does not tell the agent which operations exist. The owner cannot see in Activity that the name is not a real operation.
- The agent found the correct operation from `apassy_list_access` for the permitted call. It guessed a name for the operation that it did not have.

## 8. Process mode (ADR 0006)

An agent can run a command with vault items in the process environment. The agent does not receive the values.

Setup in the desktop app:

1. Open the credential. Under "Agent access", click "Environment variable". Type a name, for example `SUPABASE_SERVICE_KEY`. Select the secret field if the item has more than one. Click "Save".
2. In Agents, open the agent. Under "Process access", click the credential. Type the project folder.
3. Under "Decision", select "Ask me each time" or "Bouncer decides". Click "Save".

The agent must send `user_request`: the user's own words that led to the command. Each item needs a declaration: open the credential, and under "Agent access" click "Declaration" (ADR 0008).

When an agent calls `apassy_run_with_secrets` in "ask" mode, a banner shows on every view, and the Activity view shows the approval card. "Review" in the banner opens the same card. The card shows the agent, the purpose, the command, the directory, and the variable names. Click "Approve once" or "Deny". The request waits a maximum of 120 seconds. A lock, a backup, a restore, or a stop of the app ends every waiting run with `approval_invalidated`. An approval that the broker did not use before a lock is not valid after the unlock. The agent must send the request again.

For Claude Code, set `MCP_TOOL_TIMEOUT` to a value higher than 120000, because a run can wait for your approval.

### Run with a real agent host on 2026-09-25

A headless Claude Code 2.1.282 session used `apassy_list_access` and `apassy_run_with_secrets` only. The item had the variable `DEMO_SERVICE_KEY`. The grant was in "ask" mode for `/tmp/apassy-demo-project`.

- The agent ran `./check-connection.sh` in the project. The owner approved the run in the desktop app.
- The script used the key to call the synthetic service and got `200`. The script also printed the key. The output had `[apassy:DEMO_SERVICE_KEY]` in place of the value.
- The agent refused to try to get the value in other ways.
- The transcript had zero copies of the service key and zero copies of the agent token.

A manual request with `sh -c 'echo key=$DEMO_SERVICE_KEY | base64'` showed the risk of this mode: masking does not find an encoded value. The owner denied the request in the approval card. The Activity view shows both runs.

The first GUI run found a defect: the approval card showed only after a click in the window. The broker now asks the window to repaint when a run starts to wait.

## 8b. Placeholder mode (ADR 0011)

A variable can hold a placeholder in place of the real value ([ADR 0011](../adr/0011-run-proxy-placeholders.md)). The run then goes through a proxy of Apassy. The proxy puts the real value into HTTPS requests to the hosts of the variable, and on macOS the process can connect only to that proxy.

Setup: open the credential, click "Environment variable", and under "What the program gets" select "Placeholder". "Hosts" starts with the known API hosts of the provider. Type more hosts, separated by commas: `api.example.com`, or `api.example.com:8443` for another port. A host covers its subdomains. Click "Save" and confirm that it is you.

The agent uses the variable as it would use the key: in the `Authorization` header, an API key header, or a key parameter. The answer of `apassy_run_with_secrets` lists each request in `network.requests`. The proxy stops a request that has the placeholder in another place, for example in a body or a file upload, and answers `403` with the header `X-Apassy-Proxy: refused` and a reason.

Select "Real value" for:

- Go programs on macOS and Windows (`gh`, the Stripe CLI, `terraform`), Apple's `/usr/bin/python3`, and Java programs. They do not trust the certificate of the run, so they fail.
- A value that the program uses itself: a JWT signing secret, a webhook secret, a database password.
- A command that copies the secret to another service, for example `vercel env add`.

## 8c. What an agent sees, any folder, and access requests (ADR 0012)

- **Several credentials at once:** in Agents, open the agent. Under "Process access", click "Give access to several credentials…". Switch on each credential, choose "This folder" (and type it) or "Any folder", choose the decision, and click "Give access to N credentials". You confirm once.
- **Any folder:** in the same sheet, or in the sheet of one credential, choose "Any folder". The agent can then run a command from any working directory. A credential whose variable holds the real value asks you at each run. With a placeholder, the bouncer can decide.
- **See all credentials:** under "What it can see", switch on "All credentials, without values" and confirm. `apassy_list_access` then has a catalog without values. The agent can call `apassy_request_access` for a credential with access `can_request`.
- **Access requests:** a request shows in Activity under "Access requests" with the reason of the agent. "Give access…" asks for the folder and the decision, then the owner check. "Deny" closes it. The agent sees the state in `apassy_list_access`.

## 9. Limits

See section 10 of the [broker contract](../contracts/broker-v0.md). The real-secret gate stays BLOCKED.
