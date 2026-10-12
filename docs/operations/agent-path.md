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
5. In Agents, click "Connect agent". Select the host, enter a name, and click "Continue".
6. For this manual demo, open "Advanced setup" and copy the token. Click "I saved the token". The token works for 30 days. "Token lifetime" in Settings changes this time for all tokens (1 to 365 days). Under "Token and manual setup", "Rotate token…" gives a new token and stops the old token at once. Put the new token in the MCP configuration.
7. On the page of the agent, under "API operations", turn on `get_sales_summary`.

## 4. Connect an agent host

For Claude Code or Codex, use the guided setup ([ADR 0024](../adr/0024-access-at-first-use.md), changed by [ADR 0025](../adr/0025-low-friction-access.md)):

1. Click "Connect agent", select the host, and click "Continue".
2. Keep "Let the agent see credential names, without values" on. Click "Connect Claude Code…" or "Connect Codex…". One owner check gives the new token and the names. Then click "Connect Claude Code" or "Connect Codex" in the token sheet to save the host settings.
3. Optional: in "2. Access (optional)", select credentials and click "Set access…" to give a rule before the first use. A connected agent does not need it: it can use every credential that is not archived, and the bouncer decides (section 8d).
4. Start the host from the project folder: `MCP_TOOL_TIMEOUT=330000 claude` or `codex`. The Apassy sandbox is optional ("More protection").
5. In Codex, use `/hooks` to trust the hook. Use `/mcp` to check the connection.
6. Ask the agent for a task that needs a credential. When the bouncer cannot allow the run, Apassy shows a question in Activity (section 8d).

A process grant is no longer needed for a run. The bouncer decides each use. It asks you when a hard rule applies, when this agent has no history with the credential in the project, or when it is not sure. Your answer is remembered for the credential, the project, the kind of action, and the hosts of the run. A production credential waits for you at each run, unless you allowed production for the project and the kind of action, and Apassy is sure of that kind. A model never approves the first use of a credential by an agent without history, unless its declaration is development or local with low risk. History only lets a run reach the model; it never starts a run by itself.

The guide stays on the agent page while you select credentials and set access. Detailed rules remain under each credential's process access. Saved settings do not prove a connection. The test prompt lists permitted credentials without secret values; it does not test a command that uses a secret. An Allowed activity entry does not prove that a command succeeded.

For another host, open "Advanced setup" and "Other hosts: manual MCP configuration" in the token sheet. Example:

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
| Connector call before the connector grant | `not_granted` |
| Run with a credential that an exception hides from the agent ("Not for this agent", or not on the list of "Only these items"), or with an unknown credential | `not_granted` |
| Run with a credential without history in the project | The run waits for a question (section 8d), at most 300 seconds |
| Second different request while a question of the agent waits | `question_waiting` |
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

Access belongs to the credential. A variable name is an optional command setting. Without a saved binding, Apassy uses an internal name and tells the agent that name in `apassy_list_access`. The agent does not ask the owner to configure it. The default secret field is `token` for API keys, `password` for logins and databases, and `private_key` for SSH keys. A custom credential must have one nonempty secret field, or the owner must select a field. Other hidden fields, such as recovery codes, are not included automatically. Existing explicit names and placeholder restrictions stay in effect.

The broker checks access again after a pending decision. A changed secret field, delivery mode, credential revision, declaration or its source, exception, or "Always ask me" invalidates the earlier decision. Removing explicit command settings also removes existing process grants.

Without setup, an agent can name any credential of its `catalog` in `apassy_run_with_secrets`. The bouncer decides, and it can ask the owner (section 8d, ADR 0025). A process grant is not the authority for a run, and the broker does not read it. The upgrade to schema 18 turned each grant in "Ask me each time", and each grant with a rule or an instruction, into "Always ask for this agent".

Setup in the desktop app, to add a rule for a credential and a folder:

1. Select the credential in Agents. A saved environment variable is not required. For a custom credential with several secret fields, select the field under "Command settings". Leave the variable name empty for automatic use.
2. In Agents, open the agent. Under "Process access", click the credential. Type the project folder.
3. Under "Decision", select "Ask me each time" or "Bouncer decides". Click "Save".

The agent must send `user_request`: the user's own words that led to the command. For a decision of the bouncer, each item needs a declaration (ADR 0008). Apassy suggests one when you add the credential. To change it, open the credential, and under "Agent access" click "Declaration". A declaration value that is only a default makes the bouncer ask.

When an agent calls `apassy_run_with_secrets` in "ask" mode, a banner shows on every view, and the Activity view shows the approval card. "Review" in the banner opens the same card. The card shows the agent, the purpose, the command, the directory, and the variable names. Click "Approve once" or "Deny". The request waits a maximum of 300 seconds. A lock, a backup, a restore, or a stop of the app ends every waiting run with `approval_invalidated`. An approval that the broker did not use before a lock is not valid after the unlock. The agent must send the request again.

For Claude Code, set `MCP_TOOL_TIMEOUT` to a value higher than 300000, because a run can wait 300 seconds (5 minutes) for your answer. The setup command uses 330000. If the host ends the call first, the agent calls again with the same request: it joins the waiting question (section 8d).

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

A credential that the paste detection or an agent tool adds (ADR 0025 §4, §6) gets a placeholder for the known hosts of its provider, except for the providers below. Their provider file has `"real_value": true`, so the new credential gets the real value, and the known hosts stay recorded for the bouncer and the `foreign_host` check. The owner can still select "Placeholder" for one credential.

| Provider | Why the real value |
| --- | --- |
| AWS, Google Cloud | The SDKs and CLIs sign each request with the secret (SigV4, a service account key). A placeholder cannot sign. |
| GitHub | `gh` is a Go program and does not trust the certificate of the run on macOS. `git` over HTTPS often gets the token through `gh` as its credential helper, so a push or a clone fails with a placeholder. |
| Stripe | The Stripe CLI (`stripe`) is a Go program. |
| Supabase | The Supabase CLI (`supabase`, a Go program) uses the access token (`sbp_`). `supabase secrets set` copies keys to another service. |
| PlanetScale | `pscale` is a Go program, and a database password (`pscale_pw_`) goes over the MySQL protocol, not HTTPS. |

The other providers (Anthropic, OpenAI, Resend, SendGrid, Slack, Twilio, Sentry, Datadog, Netlify, Vercel, Neon) are mostly used with HTTP clients and Node.js or Python tools that read `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, or `REQUESTS_CA_BUNDLE`, so they keep the placeholder. Cloudflare keeps it too: Wrangler (Node.js) works with it. For `terraform`, `cloudflared`, or `flarectl` (Go programs), choose "Real value" on the credential.

## 8c. What an agent sees, any folder, and access requests (ADR 0012)

- **Several credentials at once:** in Agents, open the agent. Under "Process access", click "Give access to several credentials…". Switch on each credential, choose "This folder" (and type it) or "Any folder", choose the decision, and click "Give access to N credentials". You confirm once.
- **Any folder:** in the same sheet, or in the sheet of one credential, choose "Any folder". The agent can then run a command from any working directory. A credential whose variable holds the real value asks you at each run. With a placeholder, the bouncer can decide.
- **What the agent sees (ADR 0025):** `apassy_list_access` always has a `catalog` without values, for every agent. Each entry has `folder`: the folder names from the root. An exception hides a credential from the catalog and from runs: "Not for this agent", or "Only these items" (the agent sees only its list). Each credential with a secret field has access `can_use`: the agent runs a command with it at once, and the bouncer decides.
- **Access requests:** a request shows in Activity under "Access requests" with the reason of the agent. "Give access…" asks for the folder and the decision, then the owner check. "Deny" closes it. The agent sees the state in `apassy_list_access`.

## 8d. Questions and answers (ADR 0025)

The bouncer decides each use of each credential in this order (full list: [the bouncer](bouncer.md), section 3): hard rules and security vetoes, no running bouncer, a folder that is no project, an unconfirmed production credential, a remembered answer that fits the hosts and the kind of action, a credential declared for another project, a missing user request or declaration, a remembered pattern, a default declaration, a credential without history of this agent, and then the model. Anything unclear asks you.

A question waits for you up to 300 seconds. The card says why you are asked. Your answers:

- **Allow once**: the run starts. Nothing is remembered. An iPhone can only give this answer.
- **Allow ACTION in PROJECT**: the run starts, and Apassy remembers the answer for each credential of the run, the project, and the kind of action, for all agents. Later uses start without a question.
- **Allow production for PROJECT: ACTION**: the same for a production credential. This is the only way to a production allowance.
- **Deny**: the run does not start. A denial blocks the pattern of the request.
- **Not for this agent**, **Always ask for this agent**, or **Disconnect the agent**: these deny the run and make the agent stricter. They need no owner check.

Each answer that gives access needs an owner check (Touch ID or the passphrase). Apassy saves the answer after it checks the vault, the agent, and the rules a second time, in the same vault session. If the save fails, the agent gets `answer_failed` and the command does not start. A run that starts after such an answer has the field `remembered` in its result.

An agent has at most one waiting question. A second, different request gets `question_waiting`. The same request of the same agent again, in the same vault session, joins the waiting question. The newest call gets the answer. The older call ends at once with `question_waiting` and the text that a newer call took over the question. A call never joins the question of another agent. So an agent host that ends a call after its time-out can send the request again without a second question.

Removing a remembered answer makes Apassy stricter, so it needs no owner check. Removing an exception of an agent ("Not for this agent" or "Always ask for this agent") gives authority back, so it needs an owner check (`OwnerAction::RemoveAgentException`). A restore from a backup removes every remembered answer, production allowances included.

Apassy writes one row for each decided use of each credential: allowed, denied, refused, or timed out, and who decided (bouncer, pattern, answer, owner, or rule). The row has no secret value. Apassy also counts each owner check and each new question.

## 8e. Agents add credentials (ADR 0025 §6)

An agent stores a new credential without seeing it. The full rules are in section 4c of the [broker contract](../contracts/broker-v0.md).

| Tool | What it does |
| --- | --- |
| `apassy_capture_credential` | Runs one program in `cwd` (no shell, no secret, no host or URL in the arguments), for example `["gh", "auth", "token"]`, or reads one file, and stores the trimmed output. |
| `apassy_generate_credential` | Apassy makes a random value: `length` 16 to 128 (default 32), `alphabet` `alnum`, `hex`, `base64url`, or `symbols`. |
| `apassy_save_credential` | Stores a value that the agent has. The value is already in its transcript; capture is better. |
| `apassy_ask_owner_for_credential` | Asks you to paste a credential: name, purpose, where to get it. The call waits up to 5 minutes, then `waiting`; the same call again waits again. |
| `apassy_update_credential` | A new value (capture or generation) for a credential that this agent made. |
| `apassy_describe_credential` | A new name, notes, variable, or narrower hosts for a credential that this agent made. |

What to expect:

- The agent gets `item_id`, `name`, `env_name`, and a one-line summary such as `GitHub token · GH_TOKEN · production`. Never the value: not in the answer, the activity, the history, or an error.
- The paste detection (ADR 0025 §4) finds the provider, the variable, the hosts, and the declaration. A value without a signal is production by default, so its first use in a project asks you.
- The item history says `Added by AGENT in PROJECT (capture).` The bouncer decides each use of the item as for any other item.
- An agent changes only the credentials that it made with capture, generate, or save. Any other credential gives `not_owner`.
- The same value again returns the agent's own credential. Values of other credentials are not compared.
- At most 10 new credentials per agent per hour (`too_many_items`).
- Capture refuses the Apassy data folder, the vault file, the Keychain folders, a folder, a FIFO, a device, more than 64 KiB, an empty output, and a failed command (`capture_refused`).
- A request of `apassy_ask_owner_for_credential` waits in the app (`Vault::credential_requests`). Save it (the agent gets the item) or dismiss it (the agent gets `dismissed`).

Corrections: after each allowed run, Apassy compares the use log with the declaration and proposes a correction once: "development" when every use went to a development or test host, "production" when a value declared development has a live prefix (the item is production at once until you answer), and a project when every use was in one project. An ignored correction never comes again.

## 9. Limits

See section 10 of the [broker contract](../contracts/broker-v0.md). The real-secret gate stays BLOCKED.
