# Owner wire version 1

Date: 2026-10-01. Decision: [ADR 0017](../adr/0017-owner-command-line.md). Code: `src/owner/wire.rs` (types), `src/owner/client.rs` (client), `src/desktop/owner_socket.rs` (listener), `src/desktop/owner_cli.rs` (commands).

## 1. Transport

- A Unix socket: `owner.sock` in the data directory ([`paths::data_dir`](../../src/paths.rs)), or `APASSY_OWNER_SOCKET`. The directory has mode `0700`, the socket `0600`. There is no peer-credential check.
- One request per connection: one line of JSON, at most 2 MiB, then one line of JSON back, at most 32 MiB. The client waits up to 240 s, because an owner check waits up to 180 s for Touch ID.
- At most 8 connections at one time. The 9th gets `busy`.
- The agent profile denies the socket (ADR 0017, section 4).

## 2. Request

```json
{ "v": 1, "session": "apassy_cli_…", "command": { "cmd": "item_add", "item": { … } } }
```

| Field | Value |
| --- | --- |
| `v` | `1`. Another value gets `bad_version`. |
| `session` | The token of `login`. Left out when there is none. |
| `command` | An object with `cmd` and the fields of the command (section 4). |

Item and agent references are text: an ID, or the exact name without regard to case. Two items with the name give `ambiguous` with their IDs. A revoked agent loses to an active one with the same name.

## 3. Response

```json
{ "ok": true, "code": "ok", "message": "CLI key is added with ID 7.", "data": { "type": "items", "items": [ … ] } }
```

`message` is text for the owner. It has no secret value. `data.type` is one of `none`, `status`, `session`, `items`, `item`, `events`, `agents`, `agent`, `token`, `lifetime`, `requests`, `runs`, `patterns`, `activity`, `export`, `bindings`.

Only two types hold a token: `session` (after `login`) and `token` (after `agent_add` and `agent_rotate`). No type holds a secret value of an item. `item` names the secret fields and the hidden details, without values.

## 4. Commands

S: needs a session. C: asks for the owner check in the window, then answers.

| `cmd` | Fields | S | C | Notes |
| --- | --- | :-: | :-: | --- |
| `status` | | | | Counts of waiting runs, open requests, and reviews only with a valid session. |
| `login` | | | C | `data.session.token`. `vault_locked` when the vault is locked. |
| `logout` | | S | | Ends the session of the request. |
| `lock` | | | | Ends every session. |
| `show` | | | | Brings the window to the front. |
| `item_list` | `query`, `archived` | S | | |
| `item_show` | `item` | S | | Plain fields, secret field names, details (hidden ones without a value), variable, declaration (stored or suggested), connector, review state, times. |
| `item_add` | `item` | S | | `item.kind` and the main `secret` are required. |
| `item_edit` | `item`, `revision`, `changes` | S | | A field that is not in `changes` keeps its value. `revision` defaults to the current one. |
| `item_delete` | `item`, `revision` | S | | |
| `item_archive` | `item` | S | | |
| `item_unarchive` | `item` | S | C | |
| `item_history` | `item`, `limit` | S | | 1 to 1000, default 50. |
| `item_set_variable` | `item`, `name`, `field`, `hosts` | S | C | No `hosts`: the real value. `hosts`: a placeholder (ADR 0011). `field` is a field name or a detail label; the default is the main secret. |
| `item_bind_variables` | `variables` | S | C | Each entry has `item_id` and `name`. At most 200. The main secret of each item, with the real value. The app refuses an invalid name, a name of another item, an item that has a variable, and an item without a secret value before the check. The check (`BindVariables`) lists the rest. `data.results` (type `bindings`) has one row for each entry: `item_id`, `name`, `bound`, and `reason` when it is not bound. When every entry is refused, the answer comes at once, without a check. `apassy import --bind` uses it. |
| `item_clear_variable` | `item` | S | | Also removes every process grant of the item. |
| `item_set_declaration` | `item`, `declaration` | S | C | A field that is not given keeps the stored value or the suggestion. `provider: ""` is no provider. |
| `item_set_connector` | `item`, `base_url` | S | C | An API key item only. |
| `item_clear_connector` | `item` | S | | Also removes the operation grants. |
| `item_confirm_review` | `item` | S | C | |
| `agent_list` | | S | | |
| `agent_show` | `agent` | S | | Process grants with rules, operations, requests. |
| `agent_add` | `name` | S | | `data.token`, one time. |
| `agent_revoke` | `agent` | S | | |
| `agent_rotate` | `agent` | S | C | `data.token`, one time. The window does not show it. |
| `agent_see_all` | `agent`, `on` | S | C when `on` | |
| `token_lifetime` | `days` | S | C when `days` | Without `days`: the lifetime. |
| `grant_set` | `agent`, `items`, `folder`, `mode` | S | C | No `folder`: any folder. `mode`: `ask` or `bouncer`. Each item needs a variable. One item asks for `ChangeGrant`, more for `ChangeGrants`. |
| `grant_remove` | `agent`, `item` | S | | |
| `grant_rule` | `agent`, `item`, `rule` | S | C | Replaces the rule. The agent needs process access first. |
| `operation_allow` | `agent`, `item`, `operation` | S | C | An operation of the connector profile of the item. |
| `operation_remove` | `agent`, `item`, `operation` | S | | |
| `request_list` | `all` | S | | Open requests, or all. |
| `request_grant` | `request`, `folder`, `mode` | S | C | |
| `request_deny` | `request` | S | | |
| `run_list` | | S | | Runs that wait, with the command and the user request. |
| `run_approve` | `run`, `remember` | S | C | The dialog shows the run as it waits. |
| `run_deny` | `run` | S | | |
| `pattern_list` | | S | | |
| `pattern_remove` | `pattern` | S | | |
| `activity` | `limit`, `agent`, `item` | S | | |
| `decision_export` | | S | | JSON Lines of all decisions. |
| `backup` | `path` | S | | An absolute path. The vault locks after it, and every session ends. |
| `change_passphrase` | `current`, `new` | S | | Every session ends. |
| `restore` | `backup` | S | | Opens the restore sheet in the window with the path. |

The folder of a grant is checked before the owner check: it must be an existing absolute directory other than `/`, and the dialog shows its canonical path.

## 5. Error codes

| Code | Meaning |
| --- | --- |
| `bad_request` | The line is not valid JSON of this wire, or it is too long. |
| `bad_version` | `v` is not 1. |
| `session_required` | No session, or the session ended. |
| `busy` | Another owner check is open, or too many connections. |
| `cancelled` | The owner closed the owner check, or a check from the window replaced it. Nothing changed. |
| `owner_check_failed` | Touch ID failed and the owner did not use the passphrase. Nothing changed. |
| `refused` | The owner check passed, and the vault refused the action. The message says why. |
| `timeout` | The app did not answer in 230 s. An open owner check can still finish in the window. |
| `stopped` | The app is stopping. |
| `not_found`, `ambiguous`, `invalid_input`, `category_locked`, `conflict`, `vault_locked`, `already_exists`, `broker_stopped` | As the message says. |

## 6. Command-line exit codes

| Code | Meaning |
| --- | --- |
| 0 | Done. |
| 1 | The app refused the command, or a check of `doctor` failed. |
| 2 | A usage error. |
| 3 | No app answers on the socket. |
