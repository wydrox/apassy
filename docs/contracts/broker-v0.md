# Broker wire contract v0

Date: 2026-09-25.
Status: experimental. This contract supports the thin agent path in [ADR 0004](../adr/0004-agent-path-first.md). It does not satisfy the P2b, P3, P4a, or P4c acceptance checks.

## 1. Parts

| Part | Location | Feature |
| --- | --- | --- |
| Wire types and socket client | `src/agent/wire.rs`, `src/agent/client.rs` | none |
| MCP adapter | `src/agent/mcp.rs`, `src/bin/apassy-mcp.rs` | none |
| Broker checks and execution | `src/broker/decide.rs` | `vault` |
| Socket server | `src/broker/server.rs` | `vault` |
| Connector profile | `src/broker/profile.rs` | `vault` |
| HTTP client with TLS (ADR 0005) | `src/broker/http.rs` | `vault` |
| Agent, grant, destination, and activity records | `src/vault/agents.rs` | `vault` |
| Synthetic reporting service | `src/bin/apassy-dev-reporting.rs` | none |
| Host hook for the user request (goal item B6) | `src/agent/hook.rs`, `src/bin/apassy-hook.rs` | none |
| Store and transcript check of hook requests | `src/broker/prompts.rs` | `vault` |

The adapter does not link the vault into its logic. It does not open the vault file.

## 2. Socket

- Default path: `~/Library/Application Support/Apassy/broker.sock`.
- The `APASSY_BROKER_SOCKET` environment variable changes the path.
- The broker makes the directory with mode `0700` if the directory does not exist. It refuses a directory with group or other permissions.
- The socket has mode `0600`.
- If a socket file exists and no process accepts connections on it, the broker removes it. If a process accepts connections, the broker does not start.
- The desktop app starts the broker with the native window. Tests and `--smoke-test` do not start it.
- There is no peer-credential check in this phase.

## 3. Messages

Each message is one JSON object on one line. A line has a maximum of 65536 bytes.
One connection can send a maximum of 64 requests. The broker accepts a maximum of 16 connections at the same time.

Request:

```json
{"v":0,"token":"apassy_agt_<64 hex>","action":{"kind":"list_access"}}
{"v":0,"token":"apassy_agt_<64 hex>","action":{"kind":"call","item_id":1,"operation":"get_sales_summary","params":{"project_id":"project-a-synthetic","period_start":"2026-09-01","period_end":"2026-09-30"}}}
```

- Unknown fields cause `bad_request`.
- Parameter values must be strings. Objects and arrays cause `bad_request`.
- The request has no URL, header, SQL, or secret field.

```json
{"v":0,"token":"apassy_agt_<64 hex>","action":{"kind":"run","items":[1],"command":["npm","run","migrate"],"cwd":"/Users/me/Dev/odealo","purpose":"Apply the new migration.","path":"/usr/bin:/bin"}}
```

The `run` action is in [ADR 0006](../adr/0006-process-secrets.md). Its check order is in `src/broker/run.rs`. A run response has `exit_code`, `timed_out`, `truncated`, `stdout`, `stderr`, and `secrets_in_environment`. Each output stream keeps a maximum of 64 KiB. A response line has a maximum of 1 MiB. The program name (`command[0]`) cannot start with `-`.

A run with a variable in placeholder mode ([ADR 0011](../adr/0011-run-proxy-placeholders.md)) also has `placeholders` (the variable names) and `network`: `proxy` (true), `only_proxy` (true when the macOS network rule was on), and `requests`. Each request has `host`, `port`, `method`, `path` (without the query), `status`, `outcome` (`swapped`, `passed`, `tunneled`, `refused`, or `failed`), `secrets` (the variables whose value went in), and `reason`. When the run proxy cannot start, the code is `proxy_failed` and the command does not run. In `list_access`, each `process_access` entry has `env_holds` ("the real value" or "a placeholder") and `real_value_only_for_hosts`.

[ADR 0012](../adr/0012-agent-visibility-and-access-requests.md) adds to `list_access`: `sees_all_credentials`; for each `process_access` entry `any_folder`, with `project_dir` null for any folder; `catalog` (`item_id`, `item_name`, `kind`, `details`, `access`); and `access_requests` (`request_id`, `item_id`, `state`: `open`, `granted`, or `denied`).

[ADR 0025](../adr/0025-low-friction-access.md) changes the catalog:

- `catalog` is always present, for every agent. It lists each credential that is not archived and that no exception hides from the agent (section 4b).
- Each entry has `folder`: the names of the folders of the credential, from the root. The array is empty for a credential in the root.
- `access` is `needs_field` (the credential has no secret field to use in a command) or `can_use`. A process grant is no authority, so each other credential is `can_use`: the bouncer decides each use, and it can ask the owner. `requested` and `can_request` are no longer made.
- `sees_all_credentials` is `false` also for an agent that an exception limits to a list ("only these items").
- `process_access` and `items` do not list a credential that is hidden from the agent. The action `request_access` has `item_id`, `reason`, and an optional `cwd`. It answers at once with `request_id`, `state`, and `new`. Its codes are `not_visible`, `invalid_request`, `already_granted`, and `too_many_requests`. The request is only a note for the owner (`apassy request list`); the app does not show it, and the agent does not need it.
- `approval` of a `process_access` entry follows the standing rules, not the mode of the grant: "the owner approves each run" for "Always ask me" or "Always ask for this agent", a production text for a production credential, and otherwise "the bouncer decides each run; when it is not sure, it asks the owner in Decisions".

```json
{"v":0,"token":"apassy_agt_<64 hex>","action":{"kind":"request_access","item_id":7,"reason":"The user asked me to deploy the staging app.","cwd":"/Users/me/Dev/shop"}}
```

A request can have `host_session`: the session ID of the agent host. `apassy-mcp` sends `CLAUDE_CODE_SESSION_ID` here. `apassy-hook` sends the `session_id` of the hook input. In `submit_user_request`, the value must have 1 to 128 characters: `A-Z`, `a-z`, `0-9`, `-`, `_`, or `.`.

```json
{"v":0,"token":"apassy_agt_<64 hex>","host_session":"1dbe1639-f522-4744-a3dc-7a76626af241","action":{"kind":"submit_user_request","host":"claude-code","cwd":"/Users/me/Dev/odealo","prompt":"Run the unit tests.","transcript_path":"/Users/me/.claude/projects/-Users-me-Dev-odealo/1dbe1639-f522-4744-a3dc-7a76626af241.jsonl"}}
```

The `submit_user_request` action carries the user prompt from a host hook (goal item B6, [host hooks](../operations/host-hooks.md)):

- `host` is a label: `claude-code` or `codex`. `cwd` is the absolute directory of the host session. `transcript_path` is optional. `truncated` is `true` when the hook cut a prompt longer than 32 KiB.
- The broker checks the vault and the token, as for other actions. A field that is not valid gives `invalid_request`, and the activity log records it. The response is `{"ok":true,"result":{"stored":true}}`.
- The broker keeps the newest prompt per agent and host session in memory: a maximum of 256 prompts for 4 hours, in the current vault session only. It does not record the prompt in the activity log at this step.
- A later `run` uses the hook prompt in place of `user_request` and checks it in the host transcript. See [host hooks](../operations/host-hooks.md) sections 3 and 4.

Response:

```json
{"ok":true,"result":{...}}
{"ok":false,"error":{"code":"not_granted","message":"..."}}
```

## 4. Check order

The broker does the checks in this order:

1. The vault is open and unlocked. If not, the code is `vault_locked`.
2. The token belongs to an active agent of the open vault. If not, the code is `unauthenticated`; the text says that the token is not valid for the vault that is open now, and names no other vault ([ADR 0013](../adr/0013-multiple-vaults.md)). If the token is older than the token lifetime, the code is `token_expired`. The activity log names the agent.
3. The agent has a grant for the item and the operation (a connector call), and no exception hides the item from the agent. If not, the code is `not_granted`. A run does not need a process grant: see section 4b.
3a. If the item came from a restored backup, the owner confirmed its agent settings. If not, the code is `review_required` (goal item V4, [backup and restore](../operations/backup-restore.md)).
3b. The item is not archived. If it is, the code is `item_archived` (schema version 10). A process run makes the same check for each item.
4. The item has a destination. The destination profile is known and has the operation.
5. The parameters match the operation.
6. The destination is `https://HOST[:PORT]`, or `http://` on a loopback address. See [ADR 0005](../adr/0005-connector-tls.md).
7. The item category matches the profile.
7a. The standing rules of ADR 0025 §3: "Always ask me", "Always ask for this agent", and a production declaration make the call wait for the owner as a question of the agent (`question_waiting`, `approval_denied`, `approval_timeout`, `approval_invalidated` as for a run). The broker then checks steps 1 to 7 again; a change gives `authorization_changed`. Each decided use is in the use log.
8. The broker reads the secret field. Then it releases the vault lock and calls the destination.
9. For `https://`, the TLS handshake and the certificate check finish before the broker sends a request byte.

After step 2, the broker records each refusal and each result in the activity log.
A locked vault cannot record. The broker does not record requests with an unknown token when the vault is locked.

### 4b. Access without a process grant, and questions (ADR 0025)

A process grant is no longer the authority for a run. Every connected agent can use every item that is not archived through `run`, unless an exception of the agent for the item says otherwise (table `agent_exception`):

- `never` ("Not for this agent"): the catalog hides the item and a run gets `not_granted`.
- `always_ask` ("Always ask for this agent"): each use waits for the owner.
- `only` ("Only these items"): the agent can use only the items on its list. The row with item 0 is only the marker of the restriction. An agent that does not see all credentials is limited in the same way, and its process grants and connector grants count as items of the list.

An item that does not exist also gives `not_granted`, so the code does not tell which items exist. A connector call (`apassy_use_credential`) still needs a connector grant, and an exception that hides the item wins (`not_granted`).

A process grant is not read for a run: the codes `rule_expired`, `rule_command_not_permitted`, `rule_forbidden_word`, and `rule_rate_limit` are no longer made. The upgrade to schema 18 turned each grant that asked or had a rule into `always_ask`. The order of the bouncer is in [the bouncer](../operations/bouncer.md), section 3.

When the bouncer cannot allow a run, a question waits for the owner:

- The wait is at most 300 seconds (5 minutes). After that the code is `approval_timeout`.
- An agent has at most one waiting question. A second, different request gets `question_waiting`; the agent waits, then calls again with the same request.
- When the host of the agent ends the call earlier, the question stays open; the same request again joins it. Two calls are the same request when the run is the same except for the text of the bouncer and the pattern offer.
- The same request of the same agent, in the same vault session, joins the waiting question. The newest call gets the answer. The older call ends at once with `question_waiting` and the text that a newer call took over the question. A call never joins the question of another agent.
- A call joins only when the credentials of the run are as they were at the first check of the call that asked (each credential's revision, variable, declaration, and hosts, the folder, and the project: what the broker checks again after the answer). When one changed (an edit, or a merge of a sync), the waiting question ends, the older call ends with the same `question_waiting` text, and the new call asks again with a new question and a new time limit. So an answer never starts a run with a credential that changed after its question showed.
- The code `first_use_waiting` and the offer "Allow in FOLDER" (ADR 0024) are no longer made.
- The question names the answers that can take effect (`valid_answers`). If the owner answers "Allow ACTION in PROJECT" or "Allow production for PROJECT: ACTION", the broker saves the answer after its second check, in the same vault session, with the destination hosts of the run and the known hosts of each item. A production item that already has its allowance is skipped, and the failed save of one item does not stop the others. If the project changed, the code is `answer_failed` and the command does not start.
- A success response then has `remembered`: a text that says what the owner allowed.

### 4c. Agents add credentials (ADR 0025 §6)

Six actions add or change credentials. The code is in `src/broker/agent_items.rs`, the vault part in `src/vault/agent_items.rs`.

```json
{"v":0,"token":"apassy_agt_<64 hex>","action":{"kind":"capture_credential","command":["gh","auth","token"],"cwd":"/Users/me/Dev/shop","name":"GitHub token","path":"/usr/bin:/bin"}}
{"v":0,"token":"apassy_agt_<64 hex>","action":{"kind":"capture_credential","command":["aws","sts","get-session-token"],"extract":{"json":"Credentials.SessionToken"}}}
{"v":0,"token":"apassy_agt_<64 hex>","action":{"kind":"capture_credential","file":"/Users/me/Dev/shop/.secrets/key.pem"}}
{"v":0,"token":"apassy_agt_<64 hex>","action":{"kind":"generate_credential","name":"Staging database password","length":32,"alphabet":"alnum","cwd":"/Users/me/Dev/shop"}}
{"v":0,"token":"apassy_agt_<64 hex>","action":{"kind":"save_credential","value":"<secret>","name":"Webhook secret"}}
{"v":0,"token":"apassy_agt_<64 hex>","action":{"kind":"ask_owner_for_credential","name":"Sentry token","purpose":"Upload source maps.","where_to_get":"https://sentry.io/settings/auth-tokens/"}}
{"v":0,"token":"apassy_agt_<64 hex>","action":{"kind":"update_credential","item_id":12,"generate":{"length":40}}}
{"v":0,"token":"apassy_agt_<64 hex>","action":{"kind":"describe_credential","item_id":12,"env_name":"STAGING_API_KEY","placeholder_hosts":["api.example.com"]}}
```

Each optional field: `name`, `cwd` (absolute; the working directory of a command and the project of the item), `folder` (a folder path as the catalog shows it, `Work / Stripe`; `unknown_folder` when no folder has it), `purpose`, `path` (the `PATH` of a command that the owner allows; a known token command never uses it), `extract` (capture and update with `command` or `file`). `capture_credential` has exactly one of `command` and `file`; `update_credential` exactly one of `command`, `file`, and `generate`.

A success has `item_id`, `name`, `env_name` (null for a one-time-code setup key), `env_holds`, `real_value_only_for_hosts`, `summary` (such as `Stripe live · STRIPE_SECRET_KEY · production`), `created`, and `note`; `update_credential` adds `updated: true`. **No answer, error text, question, activity entry, decision log entry, item history event, use row, request, correction, or Debug output has the value.** A `save_credential` value is erased on drop and redacted in Debug.

Rules:

- The value goes through the paste detection (ADR 0025 §4): provider, variable, hosts, and a declaration with sources; a value without a signal gets the most careful default. A value with more than one credential (a `.env` text, a JSON answer) is refused; `extract` picks one. Without a detected variable, a `name` gives one (`Staging database password` → `STAGING_DATABASE_PASSWORD`).
- A title that exists gets a number. The item history says `Added by AGENT in PROJECT (TOOL).`, and so does the activity entry; the item origin (`item_origin`) names the agent, the project, and the tool.
- An agent's **own** items are those whose value it made: `capture`, `generate`, or `save`. A value that an own item has returns that item with `created: false` and creates nothing. Only own items are compared, so the answer tells nothing about other items.
- An agent adds or changes at most 10 items in one hour: each new item and each `update_credential` counts. Above it, Apassy refuses with `too_many_items`, and the text tells the agent to ask the owner (`ask_owner_for_credential`). The check comes before a capture runs or asks.
- `update_credential` and `describe_credential` work only on own items that are not archived and not waiting for a review. Any other item, also one that does not exist, gives `not_owner`. This version makes no proposal to the owner for another item. An item that the owner saved for `ask_owner_for_credential` is not an own item.
- `update_credential` keeps the replaced value as the item's previous value: never delivered, not in the catalog or the details, local to this Mac. The owner can put it back (`Vault::restore_previous_value(item_id)`, owner only, after the owner check of the app). It is dropped after the next allowed use of the item, or after 7 days (`Vault::previous_value`, `prune_previous_values`). The new value is detected again: each declaration value becomes the stricter of the old and the detected one, and each source the weaker one (`owner` > `signal` > `usage` > `default`), so a value without a signal never keeps "development from a signal". A changed declaration goes to the history.
- `describe_credential`: `name`, `notes`, `env_name`, and `placeholder_hosts`. `env_name` must be valid and not reserved (`invalid_request`; `APASSY_*` is reserved, so an automatic name `APASSY_ITEM_<id>` too), and not the variable of another item: its own name or the variable of its provider (`STRIPE_SECRET_KEY` of a Stripe item; `env_name_taken`). `placeholder_hosts` is only for an API key or a login (`invalid_request` for a custom value, a database, or an SSH key), and only narrows where the value goes: a placeholder for these hosts instead of the real value (the value must be long enough, and the provider must not sign requests), or a subset of the placeholder hosts.
- An agent with "only these items" gets its new item on its list.
- The new item is a normal item: the bouncer decides each use.

Capture runs as the broker, outside the sandbox of the agent host, so it is mediated:

- **A known token command** runs at once. The shape is exact: these words in this order, only these options (`--name VALUE` or `--name=VALUE`), in any order:

  | Command | Options |
  | --- | --- |
  | `gh auth token` | `--hostname`, `-h`, `--user`, `-u` |
  | `op read op://…` | `--account`; flag `--no-newline`, `-n` |
  | `aws configure get NAME` | `--profile` |
  | `aws sts get-session-token` (JSON: use `extract`) | `--profile`, `--region`, `--duration-seconds`, `--output`, `--query` |
  | `aws ecr get-login-password` | `--profile`, `--region` |
  | `gcloud auth print-access-token` | `--account` |
  | `gcloud auth print-identity-token` | `--account`, `--audiences` |
  | `gcloud auth application-default print-access-token` | — |
  | `az account get-access-token` | `--resource`, `--scope`, `--tenant`, `--subscription`, `--query`, `--output`, `-o` |
  | `fly auth token`, `flyctl auth token` | — |
  | `heroku auth:token` | — |
  | `doppler secrets get NAME --plain` | `--project`, `-p`, `--config`, `-c` |
  | `vault kv get -field=FIELD PATH` | `-mount` |
  | `vault print token` | — |

  The program comes only from `/usr/bin`, `/bin`, `/usr/sbin`, `/opt/homebrew/bin`, `/usr/local/bin` (in this order), never from the `PATH` or the `cwd` of the agent; an absolute program must be in one of them. It gets `PATH=/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin`. It may use the network. Not in the list on purpose: `stripe config --list` (it prints a whole configuration), `npm token` (it lists or creates; it does not print a usable token).
- **Any other command** does not run until the owner allows it. The program is found in the `PATH` of the agent (absolute entries only; a name with `/` is a path from `cwd`); not found: `start_failed`. A question waits like a run question (section 4b): "AGENT wants to capture the output of: ARGV in PROJECT", with the absolute program, `item_ids` empty, the kind of action `read`, and only "Allow once" (`valid_answers` = `Once`; a remembered answer is refused, `remember` is none) or "Deny". The same request again joins it; another question of the agent, or a credential request younger than the question time, gives `question_waiting`. Answers: denied `approval_denied`, no answer `approval_timeout`, a lock `approval_invalidated`. Each new question counts as one owner interaction. The program then runs with the agent's `path`.
- **A file** in the project of the agent (the root of the project of `cwd`, else `cwd`) is read at once. Any other file waits for the owner the same way: "AGENT wants to capture the file: PATH in PROJECT".
- **Never, also not after an answer** (`capture_refused`, no question): the Keychain tool `security`; a path of Apassy as the file or in an argument (also `file://…`): the data folder, the open vault file and each vault of the vault list with `.backup` and their synced files (each covers the paths that start with it: `-wal`, `-shm`, `.lock`, `.push.nosync`), the Apassy folder in iCloud Drive, and the Keychain folders — the deny list of `apassy-sandbox` (`docs/operations/isolation.md`, section 1). `op://…` and other URLs are no paths.
- The output: the standard output, trimmed: UTF-8, at most 64 KiB, not empty, exit code 0, within the run time limit. The standard error is erased. A file: a regular file of at most 64 KiB (a folder, a FIFO, a device, or a socket is refused before a question), opened without blocking and without following a last symbolic link, and the file that was checked.
- `extract` picks the credential in the broker, before the detection: `{"json":"a.b.0.c"}` (a dot path; numbers index arrays; the end is text or a number), `{"line":N}` (from 1), or `{"after":"Token:"}` (the rest of the first line with this label; the label ends with `:` or `=` and has only letters, digits, spaces, `_ - . /` before it, so it cannot test a part of the value). An error names the rule or the path, never the output.

`ask_owner_for_credential` stores a credential request (`credential_request`, state `open`) and waits like a question (section 4b), at most the question time:

- The same request is the agent, the project, and the name (without regard to case and spaces): a retry with other words for the purpose or the place to get it joins it. The owner saves the credential: the answer is the item. The owner dismisses it: `dismissed`. No answer in time: `waiting`, with the request ID; the request stays open, and the same request again waits again. The same request after a save returns the item; after a dismissal within one hour, `dismissed`.
- A different request while a request of the agent younger than the question time is open, or while a run or capture question of the agent waits, gives `question_waiting`; the text names the waiting request (`Credential request N ("NAME")`). An agent has at most 5 requests that are open or that it made in the last hour (`too_many_requests`).
- `where_to_get` is plain text (control characters removed); `CredentialRequest::where_domain` is its registrable domain (`resend.com`) for the UI, from the public suffix list.
- A locked vault ends the wait with `waiting`.

Vault API for the app: `Vault::credential_requests(open_only)`, `credential_request(id)`, `save_for_request(request_id, detected, folder)` (the detected items with the origin of the request, each listed for an agent with "only these items", and the request settled as saved with the first item, in one transaction; one owner interaction), `CredentialRequest::origin()` (pass it to `add_detected`), `settle_credential_request(id, RequestOutcome::Saved { item_id } | Dismissed)` (one owner interaction; a saved item is listed for an agent with "only these items"), `previous_value(item_id)`, `restore_previous_value(item_id)`, `prune_previous_values()`.

Corrections (ADR 0025 §5, `src/broker/corrections.rs`): after each allowed run, the broker proposes `correction` rows: `environment` `development` (production only by default, at least 3 uses, each to a development or test host such as `*.sandbox.*`, `dev.*`, `*.test`; `localhost` counts for nothing), `environment` `production` (a declaration that is not production and a value with a production prefix of its provider; the environment becomes production at once with the source `usage`, and an ignore gives the old environment back), and `project` (no project in the declaration, at least 5 uses, all in one project). Each `(item, kind, proposed)` exists once, so an ignored correction never comes again. API: `propose_correction`, `corrections(open_only)`, `item_corrections`, `settle_correction(id, Accepted | Ignored)` (accepting sets the environment as the owner's answer, or the project; one owner interaction; the caller does the owner check). `needs_owner_check_for_correction(id, answer)` says when that check is needed: accepting an environment looser than the declaration now (no declaration counts as production), or ignoring a correction whose `raised_from` environment is looser than now; a correction that does not exist or does not read gives true.

### 4a. Vault sessions and owner approvals (goal item V3)

- The desktop app starts with no open vault. An opened, created, or restored vault starts locked. The broker refuses every request with `vault_locked` until the owner unlocks the vault.
- Each lock and each unlock gives the vault a new random epoch. A run records the epoch at its first check.
- A run that waits for the owner ends with `approval_invalidated` when the vault is locked, backed up, restored, or replaced, or when the broker stops. The waiting thread checks the vault about every 100 ms. The desktop app also ends the waiting runs at once after these actions.
- After a decision, the broker checks the epoch again. If the epoch changed, the run does not start. An approval from before a lock is not valid after the unlock. The code is `approval_invalidated`. A run without an approval gets `vault_locked`.
- A stopped broker takes no new waits and closes each connection after the current request. A new broker has a new queue. Its run IDs start at a random value, so an ID from an earlier queue matches no run.

## 5. Output rules

- The broker returns only the output fields of the operation. It drops all other fields.
- String values have a maximum of 256 bytes. The broker removes control characters.
- The broker drops arrays and objects in output fields.
- If the output contains the stored secret, the broker returns `output_blocked` and no output.
- A TLS failure gives `tls_failed`. A `3xx` status gives `destination_error`. The broker does not follow redirects.
- Destination status `401` or `403` gives `destination_refused`. Status `404` gives `destination_not_found`. Other errors give `destination_error`. The broker never forwards the destination body.

## 6. Error codes

`rule_expired`, `rule_command_not_permitted`, `rule_forbidden_word`, `rule_rate_limit`, `invalid_request`, `outside_project`, `no_env_binding`, `approval_denied`, `approval_timeout`, `approval_invalidated`, `start_failed`, `bad_request`, `unsupported_version`, `busy`, `vault_locked`, `unauthenticated`, `not_granted`, `no_destination`, `unknown_profile`, `unknown_operation`, `invalid_params`, `destination_not_permitted`, `wrong_credential_kind`, `missing_secret`, `destination_unreachable`, `tls_failed`, `destination_refused`, `destination_not_found`, `destination_error`, `bad_output`, `output_blocked`, `broker_error`, `token_expired`, `review_required`, `item_archived`, `proxy_failed`, `not_visible`, `already_granted`, `too_many_requests`, `question_waiting`, `answer_failed`, `not_owner`, `too_many_items`, `capture_refused`, `waiting`, `dismissed`, `unknown_folder`, `env_name_taken`.

- `not_owner`, `too_many_items`, `too_many_requests`, `capture_refused`, `waiting`, `dismissed`, `unknown_folder`, `env_name_taken`: the agent tools of section 4c. A capture question also gives `question_waiting`, `approval_denied`, `approval_timeout`, and `approval_invalidated`.

- `not_granted`: the agent may not use the item. A connector call has no grant for the operation, or an exception hides the item (`never`, or the item is not on the list of an agent with "only these items"), or the item does not exist. The text is the same in each case.
- `question_waiting`: another question of the agent waits for the owner, or a newer identical call took over the waiting question (section 4b).
- `answer_failed`: the owner answered "Allow ACTION in PROJECT" or "Allow production", and Apassy could not save the answer. The command did not run.
- `outside_project`: older code. The broker does not make it for a grant outside its folder any more: such a grant gives nothing, and the bouncer decides (section 4b). The code stays in the list for older clients.

## 7. Connector profile `reporting-api-v0`

This profile follows candidate A in [P0 candidates](p0-candidates.md). It is synthetic.

| Operation | Parameters | Request | Output fields |
| --- | --- | --- | --- |
| `get_sales_summary` | `project_id` (slug), `period_start` (date), `period_end` (date) | `GET /v1/projects/{project_id}/sales-summary?period_start=..&period_end=..` | `project_id`, `period_start`, `period_end`, `currency`, `total_amount`, `order_count` |
| `get_report_job_status` | `job_id` (slug) | `GET /v1/report-jobs/{job_id}` | `job_id`, `state`, `completed_at` |

A slug has 1 to 64 characters: `a-z`, `0-9`, `-`, or `_`. A date has the form `YYYY-MM-DD` and must be a real calendar date. `period_end` cannot be before `period_start`.
The broker sends `Authorization: Bearer <token field>`. The agent cannot set a header.

## 8. MCP adapter

- Program: `apassy-mcp`. It takes no arguments.
- `APASSY_AGENT_TOKEN` holds the agent token. The adapter does not accept the token as an argument, because other local processes can read process arguments.
- Protocol versions: `2025-06-18`, `2025-03-26`, `2024-11-05`.
- Methods: `initialize`, `ping`, `tools/list`, `tools/call`. Other methods give JSON-RPC error `-32601`.
- Tools: `apassy_list_access`, `apassy_use_credential`, `apassy_run_with_secrets`, `apassy_request_access`, and the tools that add credentials (section 4c): `apassy_capture_credential`, `apassy_generate_credential`, `apassy_save_credential`, `apassy_ask_owner_for_credential`, `apassy_update_credential`, and `apassy_describe_credential`. Without `cwd`, the adapter sends its own working directory (the agent host starts it in the project). A call that can wait (a run, a capture, an update, a request to the owner) reads the answer for up to 10 minutes.
- A broker refusal is a tool result with `isError: true`. The text starts with the error code.
- For `token_expired`, the text also tells the user the next step: rotate the token in the Apassy app, put the new token in `APASSY_AGENT_TOKEN`, and restart the MCP server.
- For `review_required`, the text tells the user to confirm the agent settings of the restored item in the app.
- For `item_archived`, the text tells the user that only the user can bring the credential back from the archive in the app.
- `apassy_list_access` shows `owner_review_needed` for each item. It does not list an archived item.
- If `CLAUDE_CODE_SESSION_ID` is set, the adapter sends it as `host_session` with each request (goal item B6).

The hook program `apassy-hook` takes no arguments. It reads the host hook JSON on stdin and sends `submit_user_request` with the token in `APASSY_AGENT_TOKEN`. It waits a maximum of 2 seconds, never writes to stdout, and always exits with code 0.

## 9. Vault schema versions 2 and 3

Schema version 2 adds the tables `agent`, `destination`, `grant_rule`, and `activity`.
Unlock migrates a version 1 file in one immediate transaction. Create writes version 2.

- An agent token is 32 random bytes from `getrandom`. The vault stores the bytes. The owner sees `apassy_agt_` and 64 lowercase hex digits one time.
- Token comparison uses constant time over all active agents.
- Revoke sets `revoked_at` and removes the grants of the agent.
- Item delete removes the grants and the destination of the item in the same transaction.
- Restore revokes all agents and removes all grants and rules. It also removes every remembered answer of the owner (`owner_answer`), production allowances included. The use history of agents that restore revoked does not count. The owner must register the agents again. Restore also marks each item with a declaration, an environment variable, or a connector for review (table `restore_review`, schema version 6). The broker refuses a run or a call with a marked item with `review_required` until the owner clicks "Confirm settings".
- The activity log keeps the newest 500 entries.
- Schema version 4 adds the `rule` column to `exec_grant` and the `run_log` table (ADR 0007). A version 3 grant in "allow" mode becomes "bouncer" mode.
- Schema version 3 adds `env_binding` and `exec_grant`. Unlock migrates version 1 and 2 files. Item delete, agent revoke, and restore also remove the process grants.
- Schema version 5 adds the `declaration` table (ADR 0008).
- Schema version 6 adds `agent.token_issued_at` and `vault_meta.token_lifetime_days` (goal item P1). A token works from its issue time for the token lifetime: 30 days by default, 1 to 365 days. A change of the lifetime applies to every token from its issue time. A rotation replaces the token bytes and sets a new issue time. The old token stops working at once. The migration uses the registration time as the issue time, so a token older than 30 days is expired after the migration. Unlock migrates files of versions 1 to 5 in one transaction.

Schema version 18 (ADR 0025) adds the tables `agent_exception`, `owner_answer`, `item_use`, and `owner_interaction`, with folders and the item policy. `item_use` has one row for each decided use of each item: the outcome (`allowed`, `denied`, `refused`, or `timed_out`), who decided (`bouncer`, `pattern`, `answer`, `owner`, or `rule`), a short summary of the command, and the hosts of its URLs. It has no secret value. `owner_interaction` counts each owner check (`owner_check`) and each new question (`question`).

## 10. Limits

- A same-user process without a sandbox can read the vault file and connect to the socket. The token is the only control on the socket.
- The fixture sandbox test shows one profile. It is not the product isolation profile. The real-secret gate stays BLOCKED.
- The broker holds the secret in process memory during a call. There is no memory erasure proof.
- A token works until it expires, or until the owner rotates or revokes it, or restores a backup. The broker does not check the peer process (ADR 0010).
- Capture (section 4c) runs a known token command outside the sandbox of the agent host, with the network, without asking: the CLI reaches its own service, and the token goes into the vault. A process of the same user can replace a program in `/opt/homebrew/bin` or `/usr/local/bin` (Homebrew folders belong to the user); the broker then runs that program. A command or a file that the owner allowed runs or is read as it is at that moment; a change between the answer and the run is not seen. The owner sees the argument list, not what the program does. The `PATH` that the agent sends is used only for a command that the owner allowed.
- A backup that the owner saved outside the known paths is not on the deny list of capture. It is an encrypted SQLite file: not text and larger than 64 KiB, so capture refuses it as output.
- The previous value of an updated item lives in `item_origin`, in columns that the vault adds when it first needs them; no schema version names them yet.
- There is no rate limit per agent.
- The owner selects each destination. There is no certificate pinning and no list of known providers.
