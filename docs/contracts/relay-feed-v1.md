# Relay feed wire contract v1

Date: 2026-10-14.
Status: proposed, for section D of the [stage 5 plan](../design/stage5-plan.md) ("The Mac feed"). The owner chose the relay feed (option b) on 2026-10-14, so that the Agents tab of the iPhone shows real data. The app side (the publisher `src/questions/feed.rs` and the action handler), the iPhone side (`ios/ApassyCore` calls `feed_*`, the Agents tab), and the relay side (`apassy-relay`, team schema 6, `docs/SPEC.md` section 27) implement it. A change to this document changes every side, one pull request on each; a change to a tag, to an AAD, to the action string, or to a check bumps its version. The app implements the client itself and does not depend on the relay crate (FSL license).

This document adds to [relay-questions-v1](relay-questions-v1.md), [relay-sync-v1](relay-sync-v1.md), and [relay-connect-v1](relay-connect-v1.md) (with [ADR 0027](../adr/0027-plans-and-connect.md), on branch `product/sync-plans` when this was written). The encodings (sync section 2, questions section 4), the transport and the Worker (sync section 3), the error envelope (sync section 4), the sign-in (sync section 5), the question key (questions section 5.1), the device keys (questions section 5.2), and the questions team (questions section 12.6) are the same here.

## 1. Purpose and scope

The agents of a vault, their use, and their exceptions are rows of the Mac's vault that do not sync (`LOCAL_TABLES`): they hold history, not credentials. The iPhone holds the synced vault but not these rows. Until now its Agents tab says where the agents are and shows no list.

This contract lets each Mac publish a sealed **feed** of its agents through the relay, and lets the iPhone send one kind of **action** back: remove an exception of an agent, with Face ID when the removal gives authority back.

- The relay keeps the latest feed of each device and routes actions. It never reads a feed or an action: both are sealed with the question key.
- The vault, not the relay, is the trust root: an action counts only when its signature verifies with a key from the `trusted_device` table of the vault.
- The publishing Mac stays the only place where a change takes effect. It checks each action against its rows as they are now and applies it once.

In scope for v1: the agents of one Mac, as the Agents page of the Mac shows them (ADR 0025 §3f, ADR 0026 §2), the weekly counts of Decisions, and the action `remove_exception`.

Reserved for a later version: the open requests, the suggestions, the agent use and the rules on a credential page, and the actions `grant_request`, `disconnect_agent`, and `dismiss_suggestion` of plan section D. Each gets its own fields and its own kinds in a new `v`; nothing in v1 carries them.

## 2. Parts

| Part | Location | Stream |
| --- | --- | --- |
| The publisher: build, fit, seal, `PUT /v1/feed`, the 15-minute beat | `src/questions/feed.rs` | FD |
| The action handler: read, open, check, apply, settle | `src/questions/feed.rs`, `src/vault/exceptions.rs` (reused) | FD |
| `OwnerCheck::RemoteAction` for `OwnerAction::RemoveAgentException` | `src/broker/approvals/owner_auth.rs` | FD |
| "Show agents on the iPhone" in Settings > Devices > Relay, kept in `ui.json` | `src/desktop/ui/settings.rs`, `src/desktop/ui_prefs.rs` | FD |
| The masking of commands | `src/vault/usage.rs` `CommandMask` (mask whole, then cut), `src/vault/learning.rs` `mask_values` (reused) | FD |
| iPhone core calls `feed_list`, `feed_wait`, `feed_action_string`, `feed_action`, `feed_action_status` | `ios/ApassyCore/src/core/feed.rs`, contract [ios-core-v1](ios-core-v1.md) | FD |
| Swift Agents tab, the agent page, Face ID for an action | `ios/` | FD |
| Relay endpoints, team schema 6, limits, audit | `apassy-relay`: `src/server/feed.rs`, `store.rs`, SPEC section 27 | FD |
| The Worker's body limit for `PUT /v1/feed` | `apassy-relay`: `deploy/worker/` | FD |
| Tests against a fake relay | `tests/relay_feed.rs`, `tests/common/fake_relay.rs` | FD |

## 3. Actors and words

| Word | Meaning |
| --- | --- |
| Publisher | A Mac that runs the broker for a vault and publishes the feed of that vault's agents. Each Mac publishes its own feed. |
| Reader | An iPhone that holds the vault and shows the feeds. A Mac does not read other Macs' feeds in v1. |
| Sender | The iPhone that posts an action. |
| Target | The Mac whose feed the action refers to. It is the only device that reads and applies the action. |
| Questions team | The team of questions section 12.6. Its id is `team_id` below. A vault has one; a Mac with two vaults publishes one feed in each vault's team. |
| Feed | The sealed plaintext of section 7, one per publishing device. A new one replaces the old one. |
| `seq` | The number of a feed, chosen by the publisher, higher for each new feed (section 8). |
| `change` | The relay's counter of feed changes in a team. Readers poll with it. It is not `seq`. |
| Action | A sealed request of the sender to the target (section 9). |

## 4. Encodings

The encodings of relay-questions-v1 section 4 apply: b64u without padding, lowercase hex, P-256 keys in X9.63 form, ECDSA P-256 SHA-256 signatures in DER (at most 72 bytes, sent as b64u), Unix seconds, the envelope `{"ok":true,"result":...}`, `deny_unknown_fields` on every relay request body, `key_id`, `nonce`, `ciphertext`, the device uuid, and the relay device id. In addition:

| Value | Form |
| --- | --- |
| `seq` | a JSON number, 1 to 9007199254740991 (2^53 − 1); decimal text without leading zeros in the AAD and in the action string. |
| `change` | a JSON number, 0 or more. |
| `action_id` | 16 random bytes from the sender's CSPRNG, b64u: exactly 22 characters of `A-Za-z0-9-_`. |
| Agent id | the decimal id of the agent row on the publishing Mac, as a string (`"4"`). It means something only on that Mac. Agent ids are never reused in a vault (`AUTOINCREMENT`). |
| Item reference | the item's `uuid` (`item.uuid`) in the vault's own form: 32 lowercase hex characters, no hyphens. This is the only form: a reader and a target refuse any other (a hyphenated or upper-case uuid is a bad form), compare it byte for byte, and never reformat it. An item whose stored uuid has another form has no reference: the feed sends it as `null`. **Never the numeric item id**: that id is per device, and sync matches items by `uuid` (`src/vault/merge.rs`). The plan's "item ids refer to the synced vault" is corrected here. |
| Text in the feed | UTF-8. The publisher removes control characters (as `clean` in `src/vault/usage.rs`) and cuts at a character boundary to the limit of the field. |
| Text in the action string | the exact UTF-8 bytes. No normalization. |

## 5. Keys

- **The feed and the actions are sealed with the question key** (`vault_secret` `question-key-v1`, questions section 5.1), named by `key_id`. Every device that holds the vault has it. The key never goes to the relay.
- **Rotation.** When the question key rotates (a device removed, questions section 5.1), each publisher publishes a new feed under the new key as soon as its vault holds the new key, with the next `seq`, as soon as the 10 s limit of section 12 allows, whether or not its content changed. A reader that has only the old key keeps the feed it opened last and shows "Sync this vault to see the agents of <Mac>". A reader that has only the new key cannot open the old feed: it shows the same text until the new feed arrives. A feed never carries a key.
- **The device keys** are those of `trusted_device` (questions section 5.2): `sign_key` (the relay device key of the iPhone) and `answer_key` (the Secure Enclave key of the iPhone, Face ID). The iPhone has one answer key per team (branch `fix/multi-vault-questions`): an action uses the answer key of the team of the feed.
- The relay's device list is never the source of a key.

## 6. The envelopes

Every feed, action, and settle is sealed with **ChaCha20-Poly1305** (RFC 8439; `ring::aead::CHACHA20_POLY1305` in the app and in `apassy-core`, CryptoKit `ChaChaPoly`), the cipher of questions section 6, under the question key named by `key_id`, with a fresh 12-byte random nonce for each envelope. A nonce is never reused under one key. A publisher seals at most one feed per 10 s, so random nonces stay far below 2^32 envelopes per key.

### 6.1 AAD

The AAD is the ASCII bytes of these fields joined with one zero byte (0x00), with no zero byte at the start or the end:

```
feed:   "apassy-feed-v1" 0x00 "feed"   0x00 <team id> 0x00 <relay device id of the publisher> 0x00 <seq> 0x00 <key_id>
action: "apassy-feed-v1" 0x00 "action" 0x00 <team id> 0x00 <action_id> 0x00 <key_id> 0x00 <relay device id of the sender> 0x00 <relay device id of the target>
settle: "apassy-feed-v1" 0x00 "settle" 0x00 <team id> 0x00 <action_id> 0x00 <key_id> 0x00 <outcome>
```

- Device ids and `seq` are decimal without leading zeros. `<outcome>` is `applied`, `refused`, or `stale`. No field can hold a zero byte.
- The part name (`feed`, `action`, `settle`) separates the kinds: an envelope of one kind never opens as another, and never as a question envelope (other tag).
- The feed binds the publisher's relay device id and `seq`, which the relay stores and returns in clear. A relay that moves a feed to another device, or that serves it with another `seq`, makes it fail to open.
- The action binds the sender's device id (the relay stamps it) and the target's (the sender names it). A relay that moves an action to another Mac, or from another sender, makes it fail to open.
- The settle binds the outcome that the relay stores in clear. A relay that changes it makes the settle fail to open.
- The plan (section D) had `"apassy-feed-v1\0" || team_id || "\0" || device_uuid || "\0" || seq`. This contract adds the part name and `key_id`, and binds the relay device id instead of the device uuid: the relay returns the device id, and the plaintext names the uuid (section 7.4 checks that both name the same device). The tag stays `apassy-feed-v1`.

### 6.2 Opening

A device opens an envelope only with the key whose `key_id` equals the envelope's `key_id`, and with the AAD built from the values that the relay returned with it (for an action: the stamped `from_device_id` and its own device id). A failure to open is one result for every cause; the device never tells the relay why.

### 6.3 Sizes

| Envelope | Plaintext | Ciphertext (plaintext + 16) |
| --- | --- | --- |
| Feed | at most 262128 bytes | at most 262144 bytes (256 KiB) |
| Action | at most 4096 bytes | at most 4112 bytes |
| Settle | at most 1024 bytes | at most 1040 bytes |

The relay refuses a larger ciphertext with `413 payload_too_large`. The publisher fits the feed before it seals (section 7.3).

## 7. The feed

### 7.1 Schema

The plaintext of a feed is one JSON object, UTF-8, with exactly these fields. A reader refuses a feed with an unknown or missing field, or a value outside its form, and shows "Update Apassy to see the agents of <Mac>" (the Mac's name from its `trusted_device` row).

```json
{
  "v": 1,
  "mac": {"device": "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d", "name": "MacBook Pro"},
  "seq": 1790000040,
  "generated_at": 1790000040,
  "truncated": false,
  "week": {"by_you": 3, "automatic": 128},
  "agents": [
    {
      "id": "4",
      "name": "Claude Code",
      "host": "claude",
      "where": "mac",
      "revoked": false,
      "token_expires_at": 1797776000,
      "last_use_at": 1790000010,
      "uses_this_week": 12,
      "projects": ["synthetic-shop"],
      "note": "Deploys only from the main branch.",
      "restricted": false,
      "actions": [{"action": "deploy", "allowed": 2, "not_allowed": 1, "projects": ["synthetic-shop"]}],
      "exceptions": [{"item": "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c", "item_title": "Shop database", "kind": "never", "created_at": 1789990000}],
      "recent": [{"at": 1790000010, "item": "8d2a4c6e1f3b4d5a9c7e0b2d4f6a8c1e", "item_title": "API token", "action": "deploy",
                  "project": "synthetic-shop", "command": "npm run deploy -- --token [apassy:secret]",
                  "outcome": "allowed", "decided_by": "owner", "answered_on": "Test iPhone"}]
    }
  ]
}
```

Top level:

| Field | Type | Rule |
| --- | --- | --- |
| `v` | number | `1`. |
| `mac.device` | uuid | the publisher's `trusted_device.uuid`. |
| `mac.name` | text, 1 to 64 bytes | the publisher's `trusted_device.name`. For display. |
| `seq` | number | equal to the `seq` of the relay record and of the AAD. |
| `generated_at` | number | the publisher's clock when it built the feed. |
| `truncated` | bool | true when the publisher left something out to fit (section 7.3). The reader says "Some older uses are on the Mac only." |
| `week.by_you`, `week.automatic` | number, 0 to 2^32 − 1 | `WeekCounts` of Decisions on this Mac for this vault: owner interactions and decisions that did not wait for the owner in the last 7 days. |
| `agents` | list, at most 64 | the agents of this vault on this Mac, revoked ones included, by `last_use_at` (newest first, `null` last), then by `id`. |

Each agent:

| Field | Type | Rule |
| --- | --- | --- |
| `id` | decimal text, at most 20 characters | `agent.id` on this Mac. |
| `name` | text, 1 to 64 bytes | `agent.name`. |
| `host` | `claude`, `codex`, `t3`, or `other` | `ConnectHost::guess(name)` (`src/desktop/ui/agent_onboarding.rs`). For the icon. |
| `where` | `mac` | the agent reaches the broker through the socket of the publishing Mac. The only value in v1. The reader shows "On <mac.name>". |
| `revoked` | bool | the agent is disconnected. |
| `token_expires_at` | number | `AgentSummary.token_expires_at`. After it, the reader shows "Reconnect on <Mac>". |
| `last_use_at` | number or `null` | the newest `item_use.at` of the agent. |
| `uses_this_week` | number, 0 to 2^32 − 1 | `AgentOverview.uses_this_week`. |
| `projects` | list of text, at most 16, each 1 to 256 bytes | the project labels of its uses, most used first. Labels only, never a project key or a path. |
| `note` | text, 0 to 500 bytes | the owner's sentence for the bouncer (`MAX_AGENT_NOTE_BYTES`). |
| `restricted` | bool | "Only these items" (ADR 0025 §3f): the agent sees only the items listed with `only`. The marker row (`ONLY_MARKER_ITEM`) is never sent as an exception. "Sees" here means the `only` rows of the feed only: grants that the owner made on the Mac (`grant_rule`, `exec_grant`) are not in the feed in v1, so a reader cannot tell from it which other items the agent may use (v2: a `granted` count). |
| `actions` | list, at most 4 | `ActionUse` of the last 7 days, most used first: `action` (`read`, `change`, `deploy`, `delete`), `allowed` and `not_allowed` (numbers), `projects` (as above, at most 16). No duplicate `action`. |
| `exceptions` | list, at most 256 | see below, by `item_title`, then `kind`. |
| `recent` | list, at most 20 | see below, newest first. |

Each exception:

| Field | Type | Rule |
| --- | --- | --- |
| `item` | uuid or `null` | the item's `uuid`; `null` when the item is gone. |
| `item_title` | text, 0 to 128 bytes | the item's title (`MAX_TITLE_BYTES`); empty when the item is gone. |
| `kind` | `never`, `always_ask`, or `only` | `ExceptionKind::as_str`. |
| `created_at` | number | `agent_exception.created_at`. The action signs it (section 9.3). |

Each recent use (an `item_use` row of the agent):

| Field | Type | Rule |
| --- | --- | --- |
| `at` | number | `item_use.at`. |
| `item` | uuid or `null` | as for an exception. |
| `item_title` | text, 0 to 128 bytes | as for an exception. |
| `action` | `read`, `change`, `deploy`, `delete` | `item_use.action_kind`. |
| `project` | text, 0 to 256 bytes | `item_use.project_label`; empty when there is no project. Never `project_key`. |
| `command` | text, 0 to 256 bytes | `item_use.command_summary`, masked again (section 7.2). A command that was cut ends in `...`. |
| `outcome` | `allowed`, `denied`, `refused`, `timed_out` | `UseOutcome::as_str`. |
| `decided_by` | `bouncer`, `pattern`, `answer`, `owner`, `rule` | `UseDecidedBy::as_str`. |
| `answered_on` | text, 0 to 64 bytes | `item_use.answered_on`: the device that answered, or empty. |

A reader shows titles from its own copy of the item with the same `uuid`, and `item_title` only when it has no such item ("not on this iPhone"). A `null` item shows "A deleted credential" and offers no action.

### 7.2 What keeps secrets out

- **No value, ever.** The feed has no field value, no item notes, no secret, no agent token, no destination, no host list of a use, no environment variable value, no `cwd`, and no project key (keys are paths). Items are named by `uuid` and title only.
- **Commands are masked twice, each time before they are cut** (`CommandMask::summary`, `src/vault/usage.rs`).
  - **When the row is written.** The run masks the whole command (`run <argv joined by spaces>`) with the secret values of every item of the request, replaced by `[apassy:secret]` (`mask_values`, the masking of the use log and the decision log), and only then cuts it to 256 bytes, ending in `...`. So a value of one item never shows in the row of another item of the same run, and a value never leaves a part at the cut. `Vault::record_item_use` masks again with the values of the row's item. The Agents page of the Mac shows these rows.
  - **When the feed is built.** The publisher reads the current secret values of every item of the vault once per build (`Vault::vault_command_mask`) and masks every command with all of them, whatever the item of the row, also when that item has no reference (it is gone, or its uuid has another form). So a value set after the row was written, a value of an item that was not in the request, and a value of an item without a reference are masked too. Then it cuts to 256 bytes.
  - **The end of a cut command.** When a command was cut (it is over 256 bytes, or it ends in `...` from an earlier cut), and its end is the start of a known value, at least 8 bytes long, that start is masked too: the command ends in `[apassy:secret]...`. A cut never splits a `[apassy:secret]`.
- **Text from agents.** Agent names, notes, project labels, and command summaries come from agents and the owner. The reader shows them as text, never as a link, with control and format characters replaced by `?` (as questions section 7.3).

### 7.3 Fitting the size

The publisher builds the feed with every field at its limit, then, while the plaintext is over 262128 bytes (or over the size of section 14.2 for an old Worker), it leaves out, in this order, and sets `truncated` to true:

1. `recent` cut to 10 per agent, then to 5, then to 0;
2. the revoked agents, the oldest `last_use_at` first;
3. the other agents, the oldest `last_use_at` first.

It never cuts an exception list: an agent is sent with all its exceptions or not at all, so the reader never shows a partial set of rules. An agent with no exception and no use for 90 days may be left out before step 1.

### 7.4 What the reader checks before it shows a feed

In this order; the first failure keeps the last good feed of that Mac on the screen and shows the text of the step:

1. The envelope opens (section 6.2). Else "Sync this vault to see the agents of <Mac>".
2. The JSON has exactly the fields of section 7.1, within the limits. Else "Update Apassy to see the agents of <Mac>".
3. `v` is 1 and `seq` equals the relay's `seq`.
4. `mac.device` is a live `trusted_device` of kind `mac` whose device number in this team (`relay_devices[team id]`) equals the relay's `device_id`. Else the feed is ignored, with no text. The publisher's `trusted_device` row must carry `relay_devices[team]` equal to the relay's `device_id` on the reader's copy of the vault; a row without that entry publishes nothing there, and its feed is ignored without a text. Unlike the asker check of questions (questions section 13), a missing entry is never accepted: a feed never predates the membership, because the Mac publishes only after its row has its device number in the team.
5. `seq` is above the highest `seq` that this reader accepted from that device (section 8). Else the feed is ignored, with no text.

## 8. Order and freshness

- **The publisher's `seq`.** Each new feed has `seq = max(last seq + 1, now)`, with `now` the publisher's clock. So a Mac that lost its last `seq` (a restart, a vault restored from a backup) still goes up without state. After a start it reads its own feed (`GET /v1/feed?since=0`) and uses `max(that seq + 1, now)`.
- **When it publishes.** While the vault is unlocked, the questions are on for the vault, the feed is on (Settings > Devices > Relay > "Show agents on the iPhone", on by default; a setting of this Mac, kept in its `ui.json`, for every vault), and the vault has at least one live `trusted_device` of kind `iphone`: after each change of what the feed holds (a use, an exception, an agent, a note), at most once per 10 s; and every 15 minutes while nothing changes. A locked Mac publishes nothing; its last feed stays. A problem of the feed (section 14.2) shows as a short line under the setting.
- **When the feed goes.** The Mac deletes its feed (`DELETE /v1/feed`, section 10.5) when the owner turns "Show agents on the iPhone" off, when the questions go off for the vault (or this Mac may no longer ask through the relay), and when the last live iPhone row of the vault is removed. While the setting is off, it publishes nothing and reads no action.
- **The reader** keeps, per team and relay device id, the highest `seq` it accepted, in its app data (not secret; it survives a restart). It ignores a feed with a lower or equal `seq`. So a relay cannot bring back an older feed to a reader that has a mark for that Mac; a reader with no mark (a new or reset iPhone) can be served an older feed (section 15). It shows the feeds of all Macs together, each agent with "On <Mac>", and each Mac's header with "From <Mac>, <generated_at as a relative time>".
- **A reader with an older copy of the devices.** A reader whose copy of a vault's devices is older than a feed of that vault (a vault that is not open) shows the feed but offers no action on it.
- **Stale.** When `generated_at` is more than 24 hours old on the reader's clock, the reader shows that Mac's data dimmed with "The Mac has not reported since <date>", and offers no action on it. A `generated_at` in the future is shown as "now".
- A device whose feed leaves the relay (section 10.4, `present`) leaves the reader's list. A Mac removed from the vault (its `trusted_device` row deleted) leaves at once.

## 9. Actions

### 9.1 Kinds in v1

| `kind` | `exception.kind` | Effect at the target | Gives authority back | Signed by (iPhone) | Face ID |
| --- | --- | --- | --- | --- | --- |
| `remove_exception` | `never` | `remove_agent_exception(agent, item, Never)`: the agent may use the item again (the bouncer decides) | yes | `answer_key` | yes |
| `remove_exception` | `always_ask` | `remove_agent_exception(agent, item, AlwaysAsk)`: uses stop waiting for the owner each time | yes | `answer_key` | yes |
| `remove_exception` | `only` | `remove_agent_exception(agent, item, Only)`: the item leaves the "only these items" list of the agent, which then sees fewer items | no: stricter | `sign_key` | no |

Removing a `never` or `always_ask` row is the remote form of `OwnerAction::RemoveAgentException`, which needs the owner check on the Mac. Removing an `only` row takes authority away (`src/vault/exceptions.rs`); its signature still must verify with `sign_key`, so the relay cannot make one. The marker row of a restriction is never a target: lifting a restriction is not an action in v1. A sender is an iPhone in v1: the target refuses an action whose `by` is a Mac.

### 9.2 Schema

The plaintext of an action is one JSON object with exactly these fields:

```json
{"v":1,"action_id":"sLGys7S1tre4ubq7vL2-vw","by":"6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b","to":"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d","kind":"remove_exception","agent":"4","item":"3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c","exception":{"kind":"never","created_at":1789990000},"feed_seq":1790000040,"time":1790000060,"signature":"<b64u DER>"}
```

| Field | Rule |
| --- | --- |
| `v` | `1` |
| `action_id` | the `action_id` of the relay record |
| `by` | the sender's `trusted_device.uuid` |
| `to` | the target's `trusted_device.uuid`: the `mac.device` of the feed |
| `kind` | `remove_exception` |
| `agent` | the agent `id` of the feed |
| `item` | the item `uuid` of the exception (never `null`) |
| `exception` | `{"kind": …, "created_at": …}` of the exception as the feed showed it |
| `feed_seq` | the `seq` of the feed that showed the exception |
| `time` | the sender's clock when it builds the action, before the Face ID prompt |
| `signature` | section 9.3, by the key of section 9.1 |

### 9.3 The action string

The signed text: eight lines joined with `\n` (0x0A), no trailing newline, no `\r`:

```
apassy-feed-action-v1
<by: sender device uuid>
<to: target device uuid>
<team id>
<action_id>
remove_exception:<agent id>:<item uuid>:<exception kind>:<exception created_at>
<feed_seq>
<time>
```

- No field can hold `:` or a control character (their forms exclude them), so the target line is unambiguous.
- The investigation's sketch had seven lines and `remove_exception:<agent>:<item uuid>:<kind>`. This contract adds the line `<to>` and the exception's `created_at`:
  - **`to`.** Agent ids are per Mac and item uuids are the same on every Mac of the vault. Without the target, an action for agent 4 on one Mac would also verify on another Mac that has an agent 4 with the same exception.
  - **`created_at`.** It names this exception, not one made again later with the same agent, item, and kind. A removal that is replayed or late after the owner added the exception again does not match (section 9.5 step 9).
- The target never parses this text: it rebuilds it from its own uuid, the team id of its membership, the relay's `action_id`, the action's fields after it resolved them against its rows, and verifies the signature over the rebuilt bytes.

### 9.4 Face ID, the window, and replay

- **Face ID.** For `never` and `always_ask`, the iPhone signs with the answer key of the team after Face ID, with a new `LAContext` and `touchIDAuthenticationAllowableReuseDuration = 0`, as an answer (questions section 5.3). The prompt reason is `remove an exception of agent "NAME"`. The Face ID reason shows the agent name after the same replacement of control and format characters as the list, without `"`, cut to 40 characters. For `only`, it signs with `sign_key` and asks nothing.
- **One string.** A sender signs the action string once and sends that exact string with its `feed_seq`; a newer feed of the target in between does not change it, and the target accepts any `feed_seq` up to its last, while the exception row is still as that feed showed it (section 9.5 step 9).
- **The window.** The target accepts `time` within 60 s of its clock, both ways (`PROOF_LIFETIME`, as questions section 12.4). The relay keeps an action open for 300 s (section 10.6); after 60 s it can no longer count.
- **Replay.** `action_id` is 128 random bits, and the relay refuses a second action with the same id (`409 conflict`). The target handles each `action_id` once: it marks the id before the first check, so one id gets at most one settle, also when the relay serves a damaged copy first (section 9.5). It keeps the ids it handled in memory for 10 minutes. A replay after that is outside the window. A replay within the window after a restart finds the exception gone, or made again with another `created_at`, and is `stale`. An action replayed to another Mac fails to open (the AAD binds the target's device id) and fails the signature (`to`). An action replayed into another team fails both (team id).
- **The feed it saw.** `feed_seq` must be a `seq` that the target published (at most its last one). The exception must still exist as the feed showed it. A change after the feed (removed, made again) makes the action `stale`.

### 9.5 What the target checks

While the vault is unlocked and the feed is on, the target long-polls `GET /v1/feed/actions?after=<last seq>&wait=25` and handles at most 20 actions of one answer (section 10.7), each once, in `seq` order. The first failure ends the action with the outcome named, a settle, and, for an action that opened, an Activity line ("An action from <device> did not count: <reason>"):

0. `action_id` was not handled before. Else nothing: no second settle. The target marks the id handled before step 1, so one id gets at most one settle, also when the relay serves a damaged copy of a real action first.
1. It opens with its key named by `key_id` and the AAD with the stamped `from_device_id` and its own device id (section 6.1). Else `refused` ("it could not be read"), with no Activity line of its own: anyone on the path can make such a record. Activity says "Actions through the relay could not be read. They did not count." at most once per 10 minutes.
2. The JSON has exactly the fields of section 9.2, `v` is 1, `action_id` is the relay's, `kind` is `remove_exception`. Else `refused`.
3. `to` is its own `trusted_device.uuid`. Else `refused`.
4. `by` is a live `trusted_device` of kind `iphone`, whose device number in this team (`relay_devices[team id]`), when set, equals the stamped `from_device_id`. Else `refused`.
5. `time` is within the window of section 9.4. Else `refused` ("too old").
6. Once: the target checks it first, as step 0.
7. `agent` is an agent of this vault on this Mac that is not revoked, and `item` is the `uuid` of a live item. Else `stale`.
8. The signature verifies over the rebuilt action string (section 9.3):
   - `never`, `always_ask`: through `OwnerGate::authorize(OwnerAction::RemoveAgentException { agent_id, item_id, kind }, OwnerCheck::RemoteAction { signed, signature })`. The gate loads the live `trusted_device`, rebuilds `to` (the `trusted_device.uuid` of this Mac in the questions team of the vault) and the team id (the questions team of the vault) from the vault and refuses an action whose `to` or team differs (`RemoteRejected`), whatever its caller passed; checks the window, rebuilds the string, verifies with `answer_key` (a NULL `answer_key` or a `mac` row is `RemoteRejected`), and checks the vault session before and after, as `OwnerCheck::Remote` (questions section 12.4). `CheckMethod::Remote` is recorded. A remote check can make a proof for `RemoveAgentException` with `never` or `always_ask` only through `RemoteAction`, and `RemoteAction` makes no other proof.
   - `only`: the signature verifies with `sign_key`. No owner check.
   - A signature by the other key of the device is invalid. Else `refused`.
9. `feed_seq` is at most its last published `seq`, and the row `(agent, item, kind)` exists with `created_at` equal to `exception.created_at`. Else `stale`.
10. It removes the row (`Vault::remove_agent_exception`), writes the Activity line ("Removed on <iPhone name>: “Not for this agent” for <agent> and <item>"), counts one owner interaction for `never` and `always_ask` (ADR 0025 §1, as a remote answer), settles with `applied`, and publishes a new feed when section 12 allows.

- **The device in Activity** is the `trusted_device` that the opened action names in `by`, or "a device of this vault"; never the device that the relay stamped (`from_device_id`).
- **A lock during the check.** When the vault locks (or its session changes) while the target handles an action, the action gets no settle and is not marked handled, and `after` stays before it: the target checks it again after the unlock, while it is in its window.
- **A flood.** When no action of an answer opened (each failed step 1, or was handled before), the target waits before it polls again as after an early empty answer (section 10.10: 5 s, doubling to 60 s, with jitter).
- **An unopenable settle.** A target that cannot open an action settles it `refused` with a settle sealed under its current key. The only legitimate settle that a sender cannot open is `refused`. A reader that cannot open a settle treats it as a refusal whatever the clear outcome; only `refused` may be sealed under a key the sender may not hold, and an unopenable `applied` or `stale` is never shown as such: the sender shows "Not applied, or unknown", never applied or stale.

### 9.6 The settle

The target seals one settle for each action it handled:

```json
{"v":1,"action_id":"sLGys7S1tre4ubq7vL2-vw","outcome":"applied","reason":"","feed_seq":1790000070,"at":1790000061}
```

| Field | Rule |
| --- | --- |
| `outcome` | `applied`, `refused`, or `stale`; equal to the clear `outcome` and the AAD. |
| `reason` | empty for `applied`; else the text of the failed step, at most 200 bytes, for the sender's screen. Never a key, a value, or a signature. |
| `feed_seq` | the `seq` of the first feed that shows the result, or `null` when it publishes none. |
| `at` | the target's clock. |

The sender shows:

| Outcome | Text |
| --- | --- |
| `applied` | "Removed on <Mac>." The row leaves the list at once; the next feed confirms it. |
| `stale` | "The list on <Mac> changed. Look at it again." |
| `refused` | "<Mac> refused it: <reason>." |
| a settle that does not open, any clear outcome | "Not applied, or unknown." (section 9.5) |
| expired, no settle | "<Mac> did not answer. It may be asleep or locked." |

The settle is not signed: it is sealed with the question key, so only a device of the vault can make it, and it changes nothing but the display.

## 10. Relay endpoints

### 10.1 Common rules

- Transport, headers, deadlines, and retries: relay-sync-v1 section 3. A `429` from the Worker holds every call to that relay, as there.
- Auth: `Authorization: Bearer apassy_acc_…`, the access token of a **live device** of the questions team. The relay checks `Need::Member` and then requires `MemberAuth.device`; a member token gets `401 unauthenticated`. The device and its member are read again at each request and at each turn of a long poll.
- The team comes from the token. No endpoint takes a team id.
- **Same-member routing.** A device sees only the feeds of the live devices of its own member, its own included, and may send an action only to such a device, not to itself. Other members' devices never get a feed, its device, or an action, and cannot read one. They can see that feeds and actions change in the team: the team-wide `change` of `GET /v1/feed` and `seq` of `GET /v1/feed/actions` go up with every feed and action of any member, and the team-wide limits (`feed_bytes`, `feed_actions_per_hour`, open actions per team) refuse them too when another member used them up.
- **Member shares.** The relay gives the feed and action budgets of a team member shares, so one member cannot use up a team's `feed_bytes` or actions, and it reserves a poll seat in the team's share of the feed lane (section 10.10) for the Mac's action poll (`GET /v1/feed/actions`), so the feed long polls of other devices do not keep a Mac from its actions.
- Bodies: JSON, `deny_unknown_fields`, `v` must be `1`. At most 64 KiB, except `PUT /v1/feed`: at most 360448 bytes (352 KiB: the b64u of a 256 KiB ciphertext is 349526 characters), with `Content-Length` and without `Transfer-Encoding`.

### 10.2 Errors

| Status | Code | When |
| --- | --- | --- |
| 400 | `invalid_request` | Malformed JSON, an unknown field, `v` not 1; a `seq`, `key_id`, `nonce`, `ciphertext`, `action_id`, `to_device`, or `outcome` out of its form; an empty ciphertext; a settle whose `key_id` is not a 16-hex form; `since`, `after`, or `wait` not a number, `wait` over 25; `PUT /v1/feed` without `Content-Length` or with `Transfer-Encoding`. |
| 401 | `unauthenticated` / `token_expired` | As relay-sync-v1 section 4. |
| 403 | `not_routed` | An action to a device that is not a live device of the caller's member, or to the caller itself. |
| 403 | `feed_limit` | A feed within 10 s of the device's last accepted feed (relay clock); a feed that would pass the team's `feed_bytes`. The message names the limit. A member's feeds and actions stay within three quarters of each team limit (the whole limit in a team of one member); the message then names `member_feed_bytes`, `member_feed_actions_per_hour`, or `member_open_feed_actions`. Not `429`, so the app's other calls go on. |
| 403 | `feed_rate` | The device was given 16 MiB of feed text by `GET /v1/feed` in this minute (relay clock); it reads again at the next minute. Not `429`, so the app's other calls go on. |
| 403 | `too_many_actions` | `feed_actions_per_hour` (60) of the team in the last hour, 20 open actions in the team, or 10 open actions of the sending device. A member's feeds and actions stay within three quarters of each team limit (the whole limit in a team of one member); the message then names `member_feed_bytes`, `member_feed_actions_per_hour`, or `member_open_feed_actions`. |
| 404 | (any) | Any `/v1/feed` route on a relay without team schema 6. Section 14. |
| 404 | `not_found` | An unknown `action_id` in this team (also after the purge, section 12); `GET /v1/feed/actions/{id}` by a device that is not the sender; `POST …/settle` by a device that is not the target; an action to a device that has no feed. |
| 409 | `seq_not_newer` | `PUT /v1/feed` with a `seq` at or below the stored `seq` of the device. |
| 409 | `conflict` | `POST /v1/feed/actions` with an `action_id` that exists in the team. |
| 409 | `action_settled` | A settle of a settled action with another body. |
| 409 | `action_expired` | A settle after `expires_at`. |
| 413 | `payload_too_large` | A body over its limit, or a ciphertext over section 6.3. |
| 503 | `busy` | As relay-sync-v1. `Retry-After: 2`. |

Which code wins on `PUT /v1/feed`, in order: 401 → 400 (shape) → 413 → 409 `seq_not_newer` → 403 `feed_limit` (time, then bytes). The `409` comes before the time limit so that a retry of a feed that landed gets `409`, not `403` (section 10.3).

Which code wins on `POST /v1/feed/actions`: 401 → 400 → 413 → 403 `not_routed` → 404 (no feed) → 409 `conflict` → 403 `too_many_actions`.

The relay checks the token first: a request without a valid device token gets `401` whatever its body (the first draft of this contract had 400 and 413 before 401; the relay deviates, and the app needs no change, as it never sends a body of another form). The Worker's `413` for a body over its limit (section 10.1) still comes before the relay.

### 10.3 `PUT /v1/feed`

```json
{"v":1,"seq":1790000040,"key_id":"630dcd2966c43366","nonce":"MDEyMzQ1Njc4OTo7","ciphertext":"<b64u>"}
```

Answer: `{"device_id":2,"seq":1790000040,"change":17,"updated_at":1790000041}`. The relay replaces the caller's feed (one row per device) in one transaction, sets `change = ++team.feed_change`, and wakes the feed long polls of the member. It does not read the feed.

After a network error the publisher sends the same body again. A `409 seq_not_newer` then means the first one may have landed: the publisher reads `GET /v1/feed?since=0&wait=0`, and follows `more` (section 10.4) until it has seen every feed of the member. The feed landed only when its own entry has this `seq` and the same envelope (the digest of `key_id`, the nonce, and the ciphertext equals the one of the body it sent). Else (another `seq`, or another feed at this `seq`) it builds a new feed with `seq = max(that seq + 1, now)`, also when the content did not change. After three answers in a row that did not land, it waits before the next try, as after a failed put (2 s, doubling to 30 s), and keeps the change for it. A `403 feed_limit` waits until 10 s after the last accepted feed.

### 10.4 `GET /v1/feed?since=N&wait=S`

The feeds of the caller's member with `change > since`, oldest `change` first. `wait` 0 to 25: while there is none, hold the answer up to `wait` seconds. One feed long poll per device; a second is answered at once, as with `wait=0`.

```json
{
  "change": 17,
  "more": false,
  "present": [2, 5],
  "feeds": [
    {"device_id":2,"device_name":"MacBook Pro","seq":1790000040,"change":17,"key_id":"630dcd2966c43366",
     "nonce":"MDEyMzQ1Njc4OTo7","ciphertext":"<b64u>","updated_at":1790000041}
  ]
}
```

- `change` (top level) is the team's current feed counter. A top-level `change` below `since` (a relay restored from a backup) means: the device sets `since` to 0 and reads again.
- `present` lists every device of the member that has a feed now, also those not in `feeds`. A reader drops the feed of a device that is not in `present`.
- The relay stops adding feeds when the `ciphertext` texts of the answer reach 1 MiB (it always adds at least one), and then sets `more: true`; the device asks again at once with `since` = the `change` of the last entry. So an answer stays under the 2 MiB that the app reads (relay-sync-v1 section 3).
- A `403 feed_rate` (section 10.2) means: no feed read of this device for a whole minute, which always passes the relay's next minute whatever the clocks say. The iPhone reads no feed and its long poll waits in that time; the Mac's read-back of section 10.3 waits too, and its feed waits with the change.
- `device_name` is the relay's name of the device, for a log only. The reader takes the name from the plaintext and the `trusted_device` row.

### 10.5 `DELETE /v1/feed`

No body. Removes the caller's feed. Answer `{"device_id":2,"change":18}`. The publisher sends it when the owner turns "Show agents on the iPhone" off, when the questions go off for the vault, and when the last live iPhone row of the vault is removed (section 8). Its open actions expire. A `404` (a relay without the feed) ends the delete; another error that can pass is tried again later.

### 10.6 `POST /v1/feed/actions`

```json
{"v":1,"action_id":"sLGys7S1tre4ubq7vL2-vw","to_device":2,"key_id":"630dcd2966c43366","nonce":"QEFCQ0RFRkdISUpL","ciphertext":"<b64u>"}
```

Answer: `{"action_id":"sLGys7S1tre4ubq7vL2-vw","seq":9,"created_at":1790000060,"expires_at":1790000360}`. The relay stamps the caller's device id and member id, sets `expires_at = created_at + 300`, gives the action the next `team.feed_action_seq`, and wakes the action long poll of the target. A retry after a network error with the same body gets `409 conflict` when the first one landed; the sender then treats the action as posted and reads its state.

The sender posts again after a network error or a `500`/`503` (a new nonce and envelope, the same `action_id` and signature) while `time` is less than 55 s old; after that it asks again (a new action, and Face ID again).

### 10.7 `GET /v1/feed/actions?after=N&wait=S`

The target only: the open actions with `to_device` = the caller and `seq > after`, oldest first, at most 20.

```json
{"seq":9,"actions":[{"action_id":"sLGys7S1tre4ubq7vL2-vw","seq":9,"from_device_id":3,"key_id":"630dcd2966c43366",
  "nonce":"QEFCQ0RFRkdISUpL","ciphertext":"<b64u>","created_at":1790000060,"expires_at":1790000360}]}
```

`wait` 0 to 25: while there is none, hold up to `wait` seconds. One action long poll per device. A top-level `seq` below `after` means: set `after` to 0.

The target handles at most 20 actions of one answer, also when a relay sends more, and moves `after` past an action only once it handled it (section 9.5). When no action of an answer opened, it waits as after an early empty answer (section 10.10) before it polls again.

### 10.8 `POST /v1/feed/actions/{action_id}/settle`

The target only. Body `{"v":1,"outcome":"applied","key_id":"…","nonce":"…","ciphertext":"<b64u>"}`. Answer `{"action_id":"…","state":"settled","outcome":"applied","settled_at":1790000061}`. The same body again answers the same (a retry); another body after a settle is `409 action_settled`; after `expires_at`, `409 action_expired`. It wakes the sender's status long poll.

### 10.9 `GET /v1/feed/actions/{action_id}?wait=S`

The sender only.

```json
{"action_id":"sLGys7S1tre4ubq7vL2-vw","to_device":2,"state":"settled","created_at":1790000060,"expires_at":1790000360,
 "outcome":"applied","settled_at":1790000061,"settle":{"key_id":"630dcd2966c43366","nonce":"UFFSU1RVVldYWVpb","ciphertext":"<b64u>"}}
```

`state` is `open`, `settled`, or `expired`; `outcome`, `settled_at`, and `settle` are present only when settled. `wait` 0 to 25: while the action is open, hold up to `wait` seconds. One status long poll per device.

### 10.10 Long polls and the lane

The three feed long polls (`GET /v1/feed`, `GET /v1/feed/actions`, `GET /v1/feed/actions/{id}`) with a `wait` above 0 run in a feed lane of their own on the relay, apart from the question lane: they never count in a team's share of the question lane or in the Connect bound of relay-connect-v1 section 5. When the feed lane or the team's feed share is full, they are answered at once, as with `wait=0`, so a poll can answer early with nothing new. After an early empty answer the device waits before it polls again (5 s, doubling to 60 s, with jitter). The relay reserves a seat of the team's feed share for the action poll of a Mac, so the feed polls of the iPhones cannot fill it. The iPhone polls the feed only while the Agents tab or an agent page is on the screen; there is no push for feeds or actions in v1.

## 11. Routing

The routing set of a feed and of an action is computed by the relay at each request from the live state: the live devices (not revoked, member not revoked) of the caller's member. There is no `approvers` routing in v1: a feed holds one member's agents and goes to that member's devices only. A revoked device's feed is deleted at the revocation (`change` goes up, so readers see it leave `present`).

## 12. Limits and retention

| Limit | Value | Where |
| --- | --- | --- |
| Feed ciphertext | 262144 bytes (256 KiB) | relay: `413` |
| Feed body | 360448 bytes | Worker and relay: `413` |
| Feeds per device | 1, replaced by each `PUT` | relay |
| Feed rate | 1 accepted feed per device per 10 s (relay clock) | relay: `403 feed_limit` |
| Feed bytes of a team (`feed_bytes`) | 4 MiB by default (1 MiB to 64 MiB); 1 MiB in the `connect` preset; one member at most three quarters of it | relay: `403 feed_limit` |
| Action / settle ciphertext | 4112 / 1040 bytes | relay: `413` |
| Actions | 60 per hour per team (`feed_actions_per_hour`); 20 open per team; 15 open and 45 per hour per member; 10 open per sending device | relay: `403 too_many_actions` |
| Action lifetime | 300 s on the relay (`expires_at`); 60 s window of `time` at the target | relay; app |
| Feed reads | 16 MiB of text per device per minute | relay: `403 feed_rate` |
| Feed long polls | 1 per device for the feeds, 1 for actions, 1 for an action status; `wait` 0 to 25 s | relay |
| Feeds in one answer | until 1 MiB of ciphertext text, at least one | relay |
| Actions in one answer | 20 | relay |
| Feed retention | replaced by each `PUT`; deleted by `DELETE /v1/feed`, by the revocation of the device or its member, and 30 days after `updated_at` | relay |
| Action retention | leaves the target's list when settled or expired; purged 10 minutes after the settle or the expiry, and 24 hours after `created_at` at the latest. A purged action keeps its row in `feed_action` (the relay deviates: the purge does not delete the row) | relay |

- Feeds count in their own budget, `feed_bytes`, not in `question_bytes`, so a large feed never blocks a question. The relay gives the feed and action budgets of a team member shares (section 10.1), and reserves a poll seat for the Mac's action poll (section 10.10). A Connect team's file cap (relay-connect-v1 section 5: about `question_bytes` plus 8 MiB) grows by `feed_bytes`.
- **Audit.** The relay writes no audit row per feed update: a Mac publishes up to every 10 s, and a Connect team never deletes audit rows. It writes `feed_started` at the first feed of a device (the relay deviates: it writes `feed_started` again at the first feed after a delete), `feed_deleted`, `feed_action_posted`, `feed_action_settled` (with the clear outcome), and `limit_reached` as in section 22 of the SPEC. Rows have device ids only, never a ciphertext, a nonce, or an `action_id`.

## 13. Relay team schema 6

### 13.1 Tables

```sql
ALTER TABLE team ADD COLUMN feed_change INTEGER NOT NULL DEFAULT 0;
ALTER TABLE team ADD COLUMN feed_action_seq INTEGER NOT NULL DEFAULT 0;
CREATE TABLE feed (
  device_id INTEGER PRIMARY KEY REFERENCES device(id),
  member_id INTEGER NOT NULL REFERENCES member(id),
  seq INTEGER NOT NULL CHECK (seq >= 1),
  key_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
  change_seq INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE INDEX feed_change ON feed(change_seq);
CREATE TABLE feed_action (
  action_id TEXT PRIMARY KEY,
  seq INTEGER NOT NULL,
  from_device INTEGER NOT NULL REFERENCES device(id),
  to_device INTEGER NOT NULL REFERENCES device(id),
  member_id INTEGER NOT NULL REFERENCES member(id),
  key_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('open','settled','expired')),
  outcome TEXT CHECK (outcome IN ('applied','refused','stale')),
  settled_at INTEGER, settle_key_id TEXT, settle_nonce BLOB, settle_ciphertext BLOB);
CREATE INDEX feed_action_to ON feed_action(to_device, seq);
CREATE INDEX feed_action_created ON feed_action(created_at);
```

- `feed.change_seq` is the `change` of the answer (the column avoids the word `change`).
- The maintenance of questions (every 5 s) also marks actions `expired` at `expires_at`, purges actions (section 12), and deletes feeds 30 days after `updated_at` (with `change` up).
- `feed_bytes` and `feed_actions_per_hour` join the team's limits. A value that differs from its default is stored as the question limits are (SPEC section 17); the `connect` preset's value comes from `team.kind` and is not stored.

### 13.2 Migration from 5

`migrate_v6`, as `migrate_v5` (`src/server/store.rs`): it copies the team file to `teams/<id>.db.pre-v6` (encrypted, mode 0600), then runs the statements of 13.1 and sets `user_version = 6` in one transaction. The change is additive: no table is rebuilt; questions, sync, and devices stay. A team whose copy cannot be made stays at version 5 and does not open; free disk space and start again. `relay.db` does not change version. The previous image (schema 5) refuses a version 6 file.

The Worker goes first (relay OPERATIONS: the Worker always goes before the relay): the new Worker allows the body of section 10.1 on `PUT /v1/feed` and serves every old route as before.

### 13.3 Rollback

- **The Worker.** `npx wrangler rollback`. The old Worker answers a feed body over 128 KiB (131072 bytes) with `413`; the app then fits to the old size, 95 KiB of plaintext (section 14.2).
- **The relay image, back to schema 5.** Stop the relay, put the version 5 copies back (`for f in /data/teams/*.db.pre-v6; do cp -p "$f" "${f%.pre-v6}"; done`), and start the previous image. If an `admin limits` call changed `feed_bytes` or `feed_actions_per_hour` after the deploy, set them back to the default with the new image still running, or restore `relay.db` from the backup taken before the deploy (OPERATIONS section 19.3 has the same rule for question limits).
- **What it loses.** Everything since the migration in each team file: the feeds and the actions, and also the questions, devices, and sync heads made after it (as 19.3). A rollback also undoes every revocation and change of access since the migration (devices, members, agent tokens, grants, invites, roles, policies, the key holder), and drops the audit rows that recorded them; the operator runs `apassy-relay rollback-check` first and fixes forward when it lists any (relay OPERATIONS 21.3).
- **The feeds, and new teams.** The feeds are harmless to lose: the previous image answers `404` on `/v1/feed`, the Macs stop publishing, and the iPhones keep their interim screen (section 14). A team made after the migration has no `.pre-v6` and is version 6 from the start: suspend it, or restore the backup instead.
- Delete the `.pre-v6` files when no rollback to schema 5 is needed any more.

## 14. Versioning and compatibility

### 14.1 Versions

- `v` is `1` in every request body, feed, action, and settle. The relay refuses another `v` with `400`. A reader that cannot read a feed's `v`, or a new field or value, shows "Update Apassy to see the agents of <Mac>". A new field in a feed, an action, or a settle is a new `v`.
- The tags `apassy-feed-v1` (AAD) and `apassy-feed-action-v1` (action string) change with any change of their bytes.
- New optional fields in a relay result are ignored by the app.

### 14.2 Older relays, Workers, and apps

| Case | What happens |
| --- | --- |
| A relay without schema 6 | Every `/v1/feed` route answers `404`. The Mac stops publishing, asks again 5 minutes later, and shows "The relay does not show agents on the iPhone yet — update the relay." in Settings > Devices and once in Activity. The iPhone keeps its interim Agents screen (the agents stay on the Mac, with the Mac's name). |
| A Worker older than this contract | A `PUT /v1/feed` body over 128 KiB (131072 bytes) gets `413` from the Worker. The Mac then fits the feed to 95 KiB of plaintext (97280 bytes; section 7.3, `truncated: true`) until its next start: its ciphertext is 97296 bytes, their b64u 129728 characters, and the body with the other fields stays under 131072 bytes. (At 96 KiB the b64u of the ciphertext alone is 131094 characters, over the limit.) |
| A Mac app older than this contract | It publishes no feed. The iPhone shows its interim screen for that Mac: "Agents of <Mac> show here after you update Apassy on it." |
| An iPhone app older than this contract | It reads no feed. Nothing breaks; the Mac still publishes while the vault has a live iPhone row. |
| An iPhone without an answer key for the team (an old link) | It shows the feed and offers removals of `only` rows. For `never` and `always_ask` it says "Connect this iPhone again on a Mac to use Face ID here." |
| A Connect team (relay-connect-v1) | Works as any team, with the `connect` preset's `feed_bytes` (1 MiB) and the Connect long-poll bound. |
| The local-network companion (companion-v1) | Unchanged. It carries no feed in v1. |

## 15. What this does not protect

- **What the relay sees.** The team, the device ids of the publisher, the sender, and the target, and that they belong to one member; the size of each feed (which grows with the agents and their use), the times of each feed and action (when a Mac is on and unlocked, when the owner acts), the `seq` of each feed (which follows the Mac's clock, section 8), `key_id` (so when the key rotates), and the clear outcome of each action. With one kind in v1, it also knows that an action is a removal of an exception. Cloudflare sees the same.
- **What other members learn.** The devices of another member of the team never get a feed or an action, but they can see that feeds and actions change: the team-wide `change` and action `seq` go up, and the team-wide limits refuse them when this member used them up (section 10.1). They cannot read any of it.
- **What the relay cannot do.** Read a feed or an action (it has no question key). Forge a feed, an action, or a settle. Make an action count (it needs a signature by a key of `trusted_device`, and Face ID for a removal that gives authority back). Roll a feed back for a reader that has a mark for that Mac (the reader keeps the highest `seq`, and the AAD binds it). Move a feed to another Mac, or an action to another Mac or from another sender (the AADs bind the device ids, and the action string binds `to`). Change the outcome inside a settle that opens (the AAD binds it). Replay an action (one-time `action_id`, the 60 s window, the exception's `created_at`). Get more than one settle for one `action_id` (the target marks it before its first check). Wipe the Mac's Activity with actions that do not open (one line per 10 minutes for all of them, at most 20 handled per answer, and a wait when none opened).
- **What the relay can do.** Withhold or delay feeds and actions, keep serving the last feed, or refuse to route. Serve an older feed to a reader with no highest-`seq` mark for that Mac (a new or reset iPhone): the bound is that the feed shows its age, and the Mac checks every action against its rows as they are now, the exception's `created_at` included (section 9.5 step 9) and `time` against its own clock (section 9.4). Make an action end `refused`: it can serve a damaged copy of a real action first, which the Mac settles `refused` ("it could not be read") and after which the real one gets no settle, or serve a settle that the sender cannot open. So the relay can turn an outcome into a refusal, never into `applied`: a settle that does not open shows "Not applied, or unknown" (section 9.5). The reader shows the age of each feed and dims it after 24 hours; an action that gets no settle shows "did not answer". The Mac's own Agents page always works.
- **The names an action shows.** The iPhone signs ids (the agent id, the item uuid, the kind), not the names it shows next to them. A holder of the question key who works with the relay could serve a feed that labels a real exception with false agent and item names, so the owner removes another exception than the one they read. The Mac's Activity line records the true names of what it removed. A digest of the shown names in the action string is planned for v2.
- **The vault is the trust root** (questions section 18). Any device that holds the vault holds the question key: it can read the feeds and seal an action. It still cannot sign an action that gives authority back without the answer key of a live iPhone row, but a holder of the vault passphrase can write `trusted_device` rows.
- **A Mac's agent rows go to the iPhone.** The feed copies local history (agent names, project labels, masked command summaries) to every iPhone of the vault. They are sealed on the wire, and the iPhone keeps only the `seq` high-water mark on disk. Masking catches the values that the vault knows; a secret that the vault does not hold, typed by an agent into a command, is not masked (the same limit as the use log).
- **Display text.** Agent names, notes, and command summaries come from agents. A prompt injection there reaches the iPhone; it is shown as text, never as a link.

## 16. Open questions

1. **Requests and suggestions.** Plan section D also carries the open requests (`grant_request`, Face ID) and the suggestions (`dismiss_suggestion`). They need their own fields and kinds in feed v2, and a request needs the digest rules of a question.
2. **A Mac as a reader.** A second Mac could show the agents of the first. v1 refuses actions from a Mac; a Mac sender would need the local Touch ID before it signs with `sign_key`, as a Mac answer (questions section 5.3).
3. **A push for actions.** The target long-polls; an action to a Mac whose vault is locked expires. A background push is not in v1.

## 17. Test vectors

These values are synthetic. Every suite (the app, `apassy-core` for the iPhone, the relay for the AADs and the sizes) uses them. The key, team, device uuids, relay device ids, and the answer key are those of relay-questions-v1 section 20. They were first computed with a throwaway Python script on `cryptography` (`ChaCha20Poly1305`, `ec.ECDSA(SHA256)` on SECP256R1) and `hashlib`, which first reproduced the settle ciphertext of relay-questions-v1 section 20.4 byte for byte. On 2026-10-14 the item uuids moved to the vault's own 32-hex form (section 4: the same uuids without hyphens), and the values of 17.1 to 17.3 that depend on them (the feed and action plaintexts, their sizes, SHA-256 digests and ciphertexts, the action string, and the signature) were computed again from the Mac implementation (`tests/relay_feed.rs`, `ring`). The AADs and the settle of 17.4 did not change. The new action signature was checked independently with `openssl dgst -sha256 -verify`.

| Name | Value |
| --- | --- |
| Question key (hex) | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| `key_id` | `630dcd2966c43366` |
| Team id | `t_7k2m5q4x3c` |
| Publisher (Mac) uuid, relay device id | `0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d`, `2` |
| Sender (iPhone) uuid, relay device id | `6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b`, `3` |
| Item of the exception, uuid | `3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c` ("Shop database") |
| Item of the recent use, uuid | `8d2a4c6e1f3b4d5a9c7e0b2d4f6a8c1e` ("API token") |
| Feed `seq` | `1790000040` |
| Feed nonce (bytes `30` to `3b`) | `MDEyMzQ1Njc4OTo7` |
| `action_id` (bytes `b0` to `bf`) | `sLGys7S1tre4ubq7vL2-vw` |
| Action nonce (bytes `40` to `4b`) | `QEFCQ0RFRkdISUpL` |
| Settle nonce (bytes `50` to `5b`) | `UFFSU1RVVldYWVpb` |
| Answer key, private (hex) | `bb684f0551ffd30d7040500bc8fa0d83efd5dbde18ea1e253f098b6ddfca5f1b` |
| Answer key, public (b64u) | `BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts` |

### 17.1 The feed

The feed plaintext is exactly these 919 bytes (one line, no newline at the end; SHA-256 `5a47ba132d8e33ffd68237f2c8f5332fbf27c15f39fe14e06b9fc33415b34785`):

```
{"v":1,"mac":{"device":"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d","name":"MacBook Pro"},"seq":1790000040,"generated_at":1790000040,"truncated":false,"week":{"by_you":3,"automatic":128},"agents":[{"id":"4","name":"Claude Code","host":"claude","where":"mac","revoked":false,"token_expires_at":1797776000,"last_use_at":1790000010,"uses_this_week":12,"projects":["synthetic-shop"],"note":"Deploys only from the main branch.","restricted":false,"actions":[{"action":"deploy","allowed":2,"not_allowed":1,"projects":["synthetic-shop"]}],"exceptions":[{"item":"3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c","item_title":"Shop database","kind":"never","created_at":1789990000}],"recent":[{"at":1790000010,"item":"8d2a4c6e1f3b4d5a9c7e0b2d4f6a8c1e","item_title":"API token","action":"deploy","project":"synthetic-shop","command":"npm run deploy -- --token [apassy:secret]","outcome":"allowed","decided_by":"owner","answered_on":"Test iPhone"}]}]}
```

Feed AAD (text, `\0` is one zero byte): `apassy-feed-v1\0feed\0t_7k2m5q4x3c\02\01790000040\0630dcd2966c43366`

Feed AAD (hex, 62 bytes):

```
6170617373792d666565642d7631006665656400745f376b326d357134783363003200313739303030303034300036333064636432393636633433333636
```

Feed ciphertext (hex, 935 bytes; SHA-256 `f79d190efe856940ca7f53b5909c8e2d35d85035d3646551fd15fb70ddbca2a6`; the last 16 bytes are the tag `b0d6de4e7c01d3b980b2c6b4fd344af9`):

```
2dd63c68fed0fbc70573da2e4fe30a66aeb5b976a8a32b0bac67d36775ac2786b3c33d810f960fecdfb645235a84123fc5efd943182bc2ec6862253cd5f918b6ce2b3f1b5baec9990a838d36008edbf9ce1294712bbe2dcf1a7db5c7268e61beb68f20a72bd99de63f88d774bf4121b9a766adade408521da5b3f36aa0b6b57f5e0fdd956a7fc7471bbb5ff39441703e59e76517dcb23d098944e744d4a4797fdf44a9143e5ab65e2474eada739bb1f83ba85ea8dfe4ed55fe9ef01f8007eb352b281f2fdb1db7f9164a2ac9856b9b943786ee6ffef7f962e6fa81deb8a2d999509e18d91b746984c550dd8fccca1fcb1ff803ca97e48d04a78b79695b98bcddc170f808894ef24bd3a890358075f9031cee5ddec1bd9490f4d3162b902c38fbfb69f3ff41fecafa48d111d253daaf23f447d5f9998406241c60a1110213e932690c93933f6e4c91cf52a37380b2a48749999519caed7b735c7395e8e58d8a9e664b16308ec8c502a185a13289e31a5ba84d5ced3a4de5bbcfca9c3bc3b22eb0077f5e1d21af4bfac786ca23eeecaeecdc8e64d59c7997832031134b6d6239dd0ecaf50de6611493b21406f6c780c167cf92edbfe4ee5bf5b87b8d795535ee3249b614a699776b884198a76e346fa239a0ea2e05f5a9b3bf90cb5f99c966486d90836d591637195412f2d114eabe41e6a8d8291012700aac012c1e139e109fc35a7bbd491fb67a9f933dfda4d978f867c6263c4c2d39efeee34636166fb40b147823542fec687577d784b540c818dd16bd10b7b1fb553c70ed0771ad73ffc0079fd8e8a85d2ee5e1bafb2ab2c8aa43dca3380a58325fa7845fe922cb3e7720b691ca4bc360a72785c8c2d0dacee22d7571a5c30702f251bf4115b38c9dbdfdba02646beed6ba2422efe9b9699139b1fb1f6b6533a886dcca81c5230497105c0bf5f1e3a6d09a0598cbef92449133560456bb0b6452e3bd385f849f524a89ea9cd406570f140b8b79797d8e77b9cf1bc9203221717017326b8af9c8b9ba1610b5343065ff48341baa61bc19816baabab6cd5fbf29fc9d7e86de309a9738b1d30ca6401f19cfd66ea1fcc28bee2954d264c1e61ef8c4677ab0ade0bd5043f4c50fb7d4ff7e5b407fbb82fad706ab491b1fd76e9e8e6a20817218377e2f481959ce0ea36c147ee182bc197e97b243eba96d8e1099dd67a695addb320b15f539ad1f938a1d2b78d3d2b54e581453f73b73ea6b0345f7df9305d8f181c9c492e376bd3560d39b303b82c88ddb5c5bbe525d130633465b541678b0d6de4e7c01d3b980b2c6b4fd344af9
```

### 17.2 The action string and its signature

The removal of the `never` exception of agent `4` for "Shop database", by the iPhone, at `time` `1790000060`, from the feed of 17.1. The action string (the bytes between the fences, `\n` between the lines, none at the end; 222 bytes; SHA-256 `4555d68b3fbe31ad493893152aa08eb21342feb0dbf69e91247748a6ae81ad6d`):

```
apassy-feed-action-v1
6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b
0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d
t_7k2m5q4x3c
sLGys7S1tre4ubq7vL2-vw
remove_exception:4:3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c:never:1789990000
1790000040
1790000060
```

ECDSA signatures are randomized: a suite cannot reproduce this signature, and a new signature of the same string differs. This is a **verify vector**: the signature below, by the answer key, must verify with the answer key's public key above over the action string, and the plaintext of 17.3 carries it.

Signature (b64u DER, 71 bytes): `MEUCIQCOrTEXw3oKicPKbs27qpgbvM95jFR7lYdT06KKIVWa-wIgT3NaBhBSf5jHK8K-zhPQ0hBmo181UGMB1WMeAjoHBRk`

### 17.3 The action envelope

The action plaintext (415 bytes, one line; SHA-256 `22af11dac5c7a34b5ff375255a687d57b616f3307301bce022a82a7a9c74aa26`):

```
{"v":1,"action_id":"sLGys7S1tre4ubq7vL2-vw","by":"6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b","to":"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d","kind":"remove_exception","agent":"4","item":"3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c","exception":{"kind":"never","created_at":1789990000},"feed_seq":1790000040,"time":1790000060,"signature":"MEUCIQCOrTEXw3oKicPKbs27qpgbvM95jFR7lYdT06KKIVWa-wIgT3NaBhBSf5jHK8K-zhPQ0hBmo181UGMB1WMeAjoHBRk"}
```

Action AAD (text): `apassy-feed-v1\0action\0t_7k2m5q4x3c\0sLGys7S1tre4ubq7vL2-vw\0630dcd2966c43366\03\02`

Action AAD (hex, 78 bytes):

```
6170617373792d666565642d763100616374696f6e00745f376b326d35713478336300734c4779733753317472653475627137764c322d7677003633306463643239363663343333363600330032
```

Action ciphertext (hex, 431 bytes; SHA-256 `d804b41435c71360d58e728b82f8715e5d586507b8f11d8f844b12789e887da4`):

```
83760aa3487bc22339ac8269d48132a4d0ee593a37b006168d3b816a9e555f5e85d1e847500750db7c180d6b483697bcdb715aafcf15bd4ae9a322086a5f574cff551c3b7e2b861220235deaf24a170fee3da44fc9dfc2429f05c30f367eb216a95dbb391fe5384e66eaf6e93fd854db8fc1d6ceb0b2ab28d979941a463e3768ea501aefb6d699f22d9a1c02c99bfdddfd7c80e2a4cf67d726f759e70e92ee1a4208141f7e524fc951c2e256158fef5c05ebac29bccb949f0d5556311192fd84701066f8b6b1d160cd5a3a0d8cc0a9ac8028785ec8b7f216dd8b58da9aa4a5dbcee3f9aabbbecac7b127969d3df50afe36f1d0d31be580dd9f514a3e33856ce732838b014148ce97e02fc74e40468740e5e304915e362fbcbade163190a3845c06a2b25cb91d5ccdd2534702f1734ac5004cb2ffea57d02891e4598b18e8e8dff089421dc6281a499aa50cc1fe34af67febb3b82bd7f1469eb985b95abab8765c81a6b139417516b56ff72c9b7bd24575eb2b1468d23810569791d4e37bd9703d98cd84eae14fd96d574a4c4985e08d904f2870a7262bc57c9c46488df3340b9c35b116c3068090c9df1df08e407c7
```

### 17.4 The settle

The settle plaintext (114 bytes, one line):

```
{"v":1,"action_id":"sLGys7S1tre4ubq7vL2-vw","outcome":"applied","reason":"","feed_seq":1790000070,"at":1790000061}
```

Settle AAD (hex, 82 bytes; text `apassy-feed-v1\0settle\0t_7k2m5q4x3c\0sLGys7S1tre4ubq7vL2-vw\0630dcd2966c43366\0applied`):

```
6170617373792d666565642d763100736574746c6500745f376b326d35713478336300734c4779733753317472653475627137764c322d76770036333064636432393636633433333636006170706c696564
```

Settle ciphertext (hex, 130 bytes):

```
45c1455083097076570a95408f49b1f62de9b76b09a5c47982c1f3b5c77807a3639e5ecf86f3776b677093db298da725bfe2853c8688b69ad7b4a7832e77d73b1ac2ecd226b7cb5a4afdf3983e7e2acf4d006065b984d08880aaa87d41d13ec7fb54c8e0c1f5a9e420b91c0814b97d13b6e076ff2594ee2ba2c7d39ddfaea96b2a1c
```

### 17.5 What the suites must show

- Each plaintext seals to its ciphertext with its key, nonce, and AAD, and each ciphertext opens to its plaintext.
- The feed does not open with the device id `3` instead of `2`, with `seq` `1790000039`, with another team id or `key_id`, or with the part `action`. The action does not open with the target `5` instead of `2`, or with the sender `4` instead of `3`. The settle does not open with the outcome `refused`.
- The signature of 17.2 verifies with the answer key over the action string, and fails after one changed character of it (for example `:only:` instead of `:never:`, or another `to`), and with the device key of relay-sync-v1 section 15. A new signature of the same string differs and still verifies.
- The target (the publisher of 17.1, with the exception row `(4, Shop database, never, 1789990000)` and its last `seq` `1790000040`) applies the action with its clock at `1790000000` to `1790000120`, and refuses it at `1790000121` (`refused`, too old), with the row made again at `1789990001` (`stale`), on a target whose last published `seq` is `1790000039` (`stale`: the action names a feed it never published; `feed_seq` is signed, so a test changes the target, not the action), from a `trusted_device` row whose `answer_key` is another key (`refused`), from the iPhone's `sign_key` (`refused`), and a second time with the same `action_id` (no second settle).
- The reader shows the feed of 17.1 once, ignores it again with the same `seq`, and ignores a feed of that device with a lower `seq`.
