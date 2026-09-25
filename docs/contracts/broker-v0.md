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

The `run` action is in [ADR 0006](../adr/0006-process-secrets.md). Its check order is in `src/broker/run.rs`. A run response has `exit_code`, `timed_out`, `truncated`, `stdout`, `stderr`, and `secrets_in_environment`. Each output stream keeps a maximum of 64 KiB. A response line has a maximum of 1 MiB.

Response:

```json
{"ok":true,"result":{...}}
{"ok":false,"error":{"code":"not_granted","message":"..."}}
```

## 4. Check order

The broker does the checks in this order:

1. The vault is open and unlocked. If not, the code is `vault_locked`.
2. The token belongs to an active agent. If not, the code is `unauthenticated`.
3. The agent has a grant for the item and the operation. If not, the code is `not_granted`.
4. The item has a destination. The destination profile is known and has the operation.
5. The parameters match the operation.
6. The destination is `https://HOST[:PORT]`, or `http://` on a loopback address. See [ADR 0005](../adr/0005-connector-tls.md).
7. The item category matches the profile.
8. The broker reads the secret field. Then it releases the vault lock and calls the destination.
9. For `https://`, the TLS handshake and the certificate check finish before the broker sends a request byte.

After step 2, the broker records each refusal and each result in the activity log.
A locked vault cannot record. The broker does not record requests with an unknown token when the vault is locked.

## 5. Output rules

- The broker returns only the output fields of the operation. It drops all other fields.
- String values have a maximum of 256 bytes. The broker removes control characters.
- The broker drops arrays and objects in output fields.
- If the output contains the stored secret, the broker returns `output_blocked` and no output.
- A TLS failure gives `tls_failed`. A `3xx` status gives `destination_error`. The broker does not follow redirects.
- Destination status `401` or `403` gives `destination_refused`. Status `404` gives `destination_not_found`. Other errors give `destination_error`. The broker never forwards the destination body.

## 6. Error codes

`invalid_request`, `outside_project`, `no_env_binding`, `approval_denied`, `approval_timeout`, `start_failed`, `bad_request`, `unsupported_version`, `busy`, `vault_locked`, `unauthenticated`, `not_granted`, `no_destination`, `unknown_profile`, `unknown_operation`, `invalid_params`, `destination_not_permitted`, `wrong_credential_kind`, `missing_secret`, `destination_unreachable`, `tls_failed`, `destination_refused`, `destination_not_found`, `destination_error`, `bad_output`, `output_blocked`, `broker_error`.

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
- Tools: `apassy_list_access` and `apassy_use_credential`.
- A broker refusal is a tool result with `isError: true`. The text starts with the error code.

## 9. Vault schema versions 2 and 3

Schema version 2 adds the tables `agent`, `destination`, `grant_rule`, and `activity`.
Unlock migrates a version 1 file in one immediate transaction. Create writes version 2.

- An agent token is 32 random bytes from `getrandom`. The vault stores the bytes. The owner sees `apassy_agt_` and 64 lowercase hex digits one time.
- Token comparison uses constant time over all active agents.
- Revoke sets `revoked_at` and removes the grants of the agent.
- Item delete removes the grants and the destination of the item in the same transaction.
- Restore revokes all agents and removes all grants. The owner must register the agents again.
- The activity log keeps the newest 500 entries.
- Schema version 3 adds `env_binding` and `exec_grant`. Unlock migrates version 1 and 2 files. Item delete, agent revoke, and restore also remove the process grants.

## 10. Limits

- A same-user process without a sandbox can read the vault file and connect to the socket. The token is the only control on the socket.
- The fixture sandbox test shows one profile. It is not the product isolation profile. The real-secret gate stays BLOCKED.
- The broker holds the secret in process memory during a call. There is no memory erasure proof.
- A token is valid until revoke or restore. There is no expiry or rotation.
- There is no rate limit per agent.
- The owner selects each destination. There is no certificate pinning and no list of known providers.
