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
3. Click "+" (New Credential), then "More kinds…", and select "API key". Name it `Reporting`, and put `FAKE-ALPHA-TOKEN-7731` in the Token field.
4. Open the credential. Under "Hosts and risk", click "Connector". Type `http://127.0.0.1:8787` and click "Save". A real service uses `https://HOST`.
5. In Agents, click "+" ("Connect an Agent"). Select "Other", type a name, and click "Connect Other". Confirm with Touch ID or the passphrase.
6. The token sheet shows the token and the MCP configuration one time. Copy the token, then click "Done". The token works for 30 days. `apassy agent lifetime DAYS` changes this time for all tokens (1 to 365 days). "Reconnect…" on the page of the agent gives a new token and stops the old token at once. Put the new token in the MCP configuration.
7. Allow the connector operation from the command line; the app has no switch for it. Run `eval "$(apassy login)"`, then `apassy grant operation AGENT Reporting get_sales_summary`. Confirm in the window.

## 4. Connect an agent host

For Claude Code or Codex, use the guided setup ([ADR 0024](../adr/0024-access-at-first-use.md), changed by [ADR 0025](../adr/0025-low-friction-access.md)):

1. In Agents, click "+" ("Connect an Agent"). Select Claude Code, Codex, or T3 Code. T3 Code uses the settings of Claude Code.
2. Click "Connect Claude Code" (or "Connect Codex", "Connect T3 Code"). One owner check gives the new token. Apassy saves the host settings and shows "Connection settings saved." There is nothing else to set: the agent sees the names of your credentials without values, and the bouncer decides each use (section 8d).
3. Start the host from the project folder: `MCP_TOOL_TIMEOUT=660000 apassy-sandbox -- claude --settings '{"sandbox":{"enabled":false}}'` or `apassy-sandbox -- codex -c sandbox_mode=danger-full-access`. The desktop handoff uses these macOS sandbox launch commands. Configuration saved does not prove that an existing host is sandboxed or connected.
4. In Codex, use `/hooks` to trust the hook. Use `/mcp` to check the connection.
5. Ask the agent for a task that needs a credential. When the bouncer cannot allow the run, Apassy shows a question in Decisions (section 8d).

A process grant and an evaluation scope are not needed for a run. The bouncer
evaluates each use after the hard checks, including first use, staging, default
production and default-source environment/risk. Defaults need 80% task match even
for safe commands and reads. Uncertainty asks the owner with its exact reason.
Confirmed production without a fitting allowance, Always ask, foreign project/DB
host, missing context and failed readiness retain their vetoes. A model allow and
Allow once each permit one run and create no grant or scope. Existing explicit
project/production answers and owner-taught patterns keep their semantics.
See [ADR 0031](../adr/0031-bouncer-decides-by-default.md).

Saved settings do not prove a connection. Check it with `/mcp` in the host. An allowed use in "Agent use" of a credential does not prove that the command succeeded.

For another host, select "Other" in "Connect an Agent": the token sheet shows the token and the MCP configuration one time. For Claude Code and Codex, "Advanced setup" in the token sheet shows the same under "Other hosts: manual MCP configuration". Example:

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
| Connector call before `apassy grant operation` | `not_granted` |
| Run with a credential that an exception hides from the agent ("Not for this agent", or not on the list of "Only these items"), or with an unknown credential | `not_granted` |
| First use or no evaluation scope, after hard checks | Fresh model decision; uncertainty asks (section 8d), at most 300 seconds |
| Second different request while a question of the agent waits | `question_waiting` |
| Call after `apassy grant operation` | Six output fields. No token. No `internal_debug_note`. |
| Call with `project_id` `echo-token-canary` | `output_blocked` |
| Call with a locked vault | `vault_locked` |
| Call after "Disconnect AGENT…" | `unauthenticated` |
| Call after the token lifetime | `token_expired`. `apassy-mcp` tells the user to rotate the token. |
| Call with the old token after "Reconnect…" | `unauthenticated` |
| Call while another vault is open ([several vaults](multiple-vaults.md)) | `unauthenticated`. The text says that the token is not valid for the vault that is open now. `apassy-mcp` tells the user to open the vault of the agent. |
| Call after a restore, before "Confirm settings" for the item | `review_required`. See [backup and restore](backup-restore.md). |
| `apassy activity` | One row for each call and each refusal |

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

The desktop app has no access to set up. On the page of a credential, "Hosts and risk" > "Command settings" sets an optional variable name, the secret field of a custom credential with several secret fields, and the delivery; leave the variable name empty for automatic use. "Always ask me" on the page makes each use wait for you. To make one agent stricter, answer a question with "Never for AGENT" or "Always Ask for AGENT" in its "⋯" menu.

The agent must send `user_request`: the user's own words that led to the command. For a decision of the bouncer, each item needs a declaration (ADR 0008). Apassy suggests one when you add the credential. To change it, open the credential, and under "Hosts and risk" click "Declaration". A default-source environment or risk makes the model check stricter: 80% task match, even for a safe command or read.

When the bouncer asks you about a call of `apassy_run_with_secrets`, a banner shows on every view, and Decisions shows the question. "Review" in the banner opens it. The question shows the agent, the purpose, the command, the directory, the variable names, and why you are asked. Choose "Deny", "Allow Once", or an offered execution answer (section 8d). Evaluation setup is no longer offered. The request waits a maximum of 300 seconds. A lock, a backup, a restore, or a stop of the app ends every waiting run with `approval_invalidated`. An approval that the broker did not use before a lock is not valid after the unlock. The agent must send the request again.

Managed setup uses `MCP_TOOL_TIMEOUT=660000` for Claude Code and 660 seconds for Codex, covering the 300-second owner wait plus the default 300-second run budget. Supply a unique `idempotency_key` before a mutating/run call. With a progress token, the adapter reports its operation ID immediately and sends progress every 15 seconds. After a timeout or reconnect, use `apassy_list_access` with `operation_id` to retrieve the outcome. An identical key and identical arguments retrieve the original receipt during retention; they do not start another run. Never blindly replay an unknown outcome. See the [MCP contract](cli.md#concurrent-mcp-calls-and-recovery) for concurrency, cancellation, bounded retention, and retry rules.

The adapter permits four concurrent tool calls, reserving one slot for catalog/status reads. Tool descriptions, ping, and cancellation remain available during a long run. Cancellation withdraws a pending owner question. An executing command may already have changed external state: cancellation does not undo it, and the final outcome remains retrievable. Closing stdin cancels waiting calls. Receipts contain outcome metadata, without output or secret-bearing free text, and stay for 15 minutes after completion in broker memory for the same authenticated agent and unlocked vault session. A restart, a vault session change, or expiry ends the retrieval and deduplication guarantee.

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

Setup: open the credential, click "Hosts and risk", then "Command settings", and under "What the program gets" select "Placeholder". "Hosts" starts with the known API hosts of the provider. Type more hosts, separated by commas: `api.example.com`, or `api.example.com:8443` for another port. A host covers its subdomains. Click "Save" and confirm that it is you.

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

## 8c. What an agent sees, folders, and access requests (ADR 0012, ADR 0025)

- **No access to give:** since 0.5.0 there are no grants, decision modes, or folders to set for an agent. The bouncer reads the project of the working directory: a git repository with all its worktrees, or a folder without git. The root, the home folder, and its parents are never a project, so a run there asks you.
- **What the agent sees (ADR 0025):** `apassy_list_access` always has a `catalog` without values, for every agent. Each entry has `folder`: the folder names from the root. An exception hides a credential from the catalog and from runs: "Not for this agent", or "Only these items" (the agent sees only its list). Each credential with a secret field has access `can_use`: the agent runs a command with it at once, and the bouncer decides.
- **Exceptions:** the answers "Never for AGENT" and "Always Ask for AGENT" add an exception. The upgrade from 0.4.1 gave "Only these items" to each agent that did not see all credentials; `apassy agent see-all AGENT on` removes it (owner check). The page of the agent lists its exceptions under "Exceptions". "Remove" of "Never" or "Always ask" gives authority back, so it needs the owner check.
- **Access requests:** an agent does not need one: each credential of its catalog is `can_use`. `apassy_request_access` only records a note for you and returns at once. The app does not show these notes; `apassy request list` does. To ask you for a credential that is not in Apassy, the agent uses `apassy_ask_owner_for_credential` (section 8e), which shows in Decisions > Requests.

## 8d. Questions and answers (ADR 0025)

The bouncer decides after hard rules/security vetoes, successful inference
readiness, a usable project, fitting execution answers, the foreign-project check,
a user request and declaration, and owner-taught patterns. Every remaining request
reaches the model, including default-source classification and missing evaluation
scope. Defaults require 80% task match. Low confidence asks with the exact failed
check. A stored evaluation scope cannot cover a foreign declared project. See
[the bouncer](bouncer.md), section 3.0, and ADR 0031.

A question waits for you up to 300 seconds. The card says why you are asked. Your answers:

- **Allow Once**: approves this run only, without confirming classification, creating a remembered answer or scope, or teaching a pattern. An iPhone paired on the local network can only give this answer; relay answers retain their existing choices ([questions](questions.md)).
- **Allow ACTION in PROJECT**: the run starts, and Apassy remembers the answer for each credential of the run, the project, and the kind of action, for all agents. Later uses start without a question.
- **Allow production: ACTION in PROJECT**: the same for a production credential. This is the only way to a production allowance.
- **Deny**: the run does not start. A denial blocks the pattern of the request.
- **Never for AGENT**, **Always Ask for AGENT**, or **Disconnect AGENT…** (in the "⋯" menu): these deny the run and make the agent stricter ("Not for this agent", "Always ask for this agent"). They need no owner check.

Each answer that gives access needs an owner check (Touch ID or the passphrase). Apassy saves the answer after it checks the vault, the agent, and the rules a second time, in the same vault session. If the save fails, the agent gets `answer_failed` and the command does not start. An explicit project/production execution answer is reported separately from one-time approval and a model decision. The CLI pattern route remains `apassy runs approve ID --remember` and requires 3 explicit remembers; neither ordinary one-time approval nor a model allowance increments it.

An agent has at most one waiting question. A second, different request gets `question_waiting`. The same request of the same agent again, in the same vault session, joins the waiting question. The newest call gets the answer. The older call ends at once with `question_waiting` and the text that a newer call took over the question. A call never joins the question of another agent. This reattachment describes untracked broker calls. MCP calls with an idempotency key retrieve the original operation receipt instead; they do not supersede the original waiter. After a timeout, retrieve the operation before considering another execution. When the credential or a supported command binding changed after the question showed (an edit, sync conflict, or changed script/execution context), the same request does not join: the old question goes away, a new one shows, and you answer again.

Stored evaluation scopes are legacy schema-20 records. They do not authorize or
block routing and are no longer offered in Decisions. On the credential page,
"Stored bouncer scopes" identifies their lack of routing effect. Their existing
local storage, invalidation, sync and restore rules remain for compatibility.
Supported command bindings still check exact argv, canonical working directory,
`PATH`, executable resolution and directly selected project script bytes during a
decision. A change during inference invalidates the run before credential delivery.
A fresh request is evaluated again without scope setup. Imports, sourced files,
dependencies and future external executable behavior are not a sandboxed or fully
pinned execution graph.

Removing a remembered answer makes Apassy stricter, so it needs no owner check. Stored evaluation scopes are retained for compatibility and have no routing effect. Removing an exception of an agent ("Not for this agent" or "Always ask for this agent") gives authority back, so it needs an owner check (`OwnerAction::RemoveAgentException`). A restore from a backup removes every remembered answer, production allowances included.

Apassy writes one row for each decided use of each credential: allowed, denied, refused, or timed out, and who decided (bouncer, pattern, answer, owner, or rule). The row has no secret value. Apassy also counts each owner check and each new question.

## 8e. Agents add credentials (ADR 0025 §6)

An agent stores a new credential without seeing it. The full rules are in section 4c of the [broker contract](../contracts/broker-v0.md).

| Tool | What it does |
| --- | --- |
| `apassy_capture_credential` | Runs a command in `cwd` (no secret in its environment) or reads one file, and stores the trimmed output, or the part that `extract` names (`{"json": "a.b"}`, `{"line": 2}`, `{"after": "Token:"}`). A known token command runs at once; any other command, and a file outside the project, asks you first. |
| `apassy_generate_credential` | Apassy makes a random value: `length` 16 to 128 (default 32), `alphabet` `alnum`, `hex`, `base64url`, or `symbols`. |
| `apassy_save_credential` | Stores a value that the agent has. The value is already in its transcript; capture and generate are better, and the tool says so. |
| `apassy_ask_owner_for_credential` | Asks you to paste a credential: name, purpose, where to get it. The call waits up to 5 minutes, then `waiting`; a deliberate new operation with the same name in the same project waits again; a retained idempotency key returns its first outcome. |
| `apassy_update_credential` | A new value (capture or generation) for a credential that this agent made. The previous value stays for you to restore. |
| `apassy_describe_credential` | A new name, notes, variable, or narrower placeholder hosts for a credential that this agent made. |

Known token commands (they run without a question; exact shapes and options in section 4c of the [broker contract](../contracts/broker-v0.md)): `gh auth token`, `op read op://…`, `aws configure get NAME`, `aws sts get-session-token`, `aws ecr get-login-password`, `gcloud auth print-access-token`, `gcloud auth print-identity-token`, `gcloud auth application-default print-access-token`, `az account get-access-token`, `fly auth token` / `flyctl auth token`, `heroku auth:token`, `doppler secrets get NAME --plain`, `vault kv get -field=FIELD PATH`, `vault print token`. The program comes only from `/usr/bin`, `/bin`, `/usr/sbin`, `/opt/homebrew/bin`, or `/usr/local/bin`: the `PATH` and the folder of the agent do not change it.

A capture question ("Tool agent wants to capture the output of: /opt/homebrew/bin/npx some-cli token in shop", or "… the file: /Users/me/.config/x/token in shop") shows the program as the agent's `PATH` finds it. Answer "Allow once" or "Deny"; nothing is remembered, so the same command asks again next time. It waits up to 300 seconds like a run question, and the same request again joins it.

What to expect:

- The agent gets `item_id`, `name`, `env_name`, and a one-line summary such as `GitHub token · GH_TOKEN · production`. Never the value: not in the answer, a question, the activity, the history, or an error.
- The paste detection (ADR 0025 §4) finds the provider, the variable, the hosts, and the declaration. A value without a signal is unconfirmed production by default; it reaches the model with the stricter 80% task-match check.
- The item history and the activity log say `Added by AGENT in PROJECT (capture).` The bouncer decides each use of the item as for any other item.
- An agent changes only the credentials that it made with capture, generate, or save. Any other credential gives `not_owner`.
- A new value keeps the old one on the item for you (`Vault::restore_previous_value`; the item page will offer it). It goes after the next allowed use of the item, or after 7 days. The declaration becomes the stricter of the old one and the one that the new value shows, with the weaker sources.
- A variable name of an agent's credential cannot be the name of another credential or the variable of its provider (`STRIPE_SECRET_KEY` of your Stripe key). Placeholder hosts are only for an API key or a login.
- The same value again returns the agent's own credential. Values of other credentials are not compared.
- At most 10 new or changed credentials per agent per hour; above it Apassy refuses (`too_many_items`) and tells the agent to ask you.
- Capture refuses, without a question: the Apassy data folder, each vault file and its backup and synced copy, the Apassy folder in iCloud Drive, the Keychain folders, `security`, a folder, a FIFO, a device, more than 64 KiB, an empty output, and a failed command (`capture_refused`).
- A request of `apassy_ask_owner_for_credential` waits in the app (`Vault::credential_requests`; `where_domain` is the domain of "where to get it"). Save it (`Vault::save_for_request`: the agent gets the item) or dismiss it (the agent gets `dismissed`). At most 5 open or new requests per agent per hour (`too_many_requests`).

What this does not protect: a known token command runs outside the agent's sandbox and uses the network to reach its service, without a question. A process of your user can replace a program in the Homebrew folders. An allowed command runs as it is when it runs; you see its arguments, not what it does.

Corrections: after each allowed run, Apassy compares the use log with the declaration and proposes a correction once: "development" when every use went to a development or test host, "production" when a value declared development has a live prefix (the item is production at once until you answer), and a project when every use was in one project. An ignored correction never comes again.

## 9. Limits

See section 10 of the [broker contract](../contracts/broker-v0.md). The real-secret gate stays BLOCKED.

Agent command execution refuses nonempty secret values shorter than four bytes,
including real values behind proxy placeholders, before starting the command.
Whole-token masking cannot safely conceal those values when embedded in output.

MCP stdio input is limited to 64 KiB while reading. An oversized frame sends a JSON-RPC error with code -32600 and a null request ID, then terminates the adapter, including when the sender never writes a newline. Restart the host connection after correcting the input.
