# ADR 0012 — What an agent sees, where it uses a credential, and access requests

Date: 2026-09-27.
Status: ACCEPTED by the owner on 2026-09-27 ("Start with updated proposal"). In the code.

## Context

On 2026-09-27 the owner asked three questions:

- How do I give one agent a group of credentials for one project or goal?
- How can an agent use a credential that is not tied to a folder?
- How can an agent see all credentials without access to the secrets?

Before this decision:

- An agent saw only the items that it could use.
- Each process grant had one project folder. The app refused the root folder.
- The owner gave process access one item at a time, with one owner check each.

ADR 0011 changed the risk of a folder. A variable in placeholder mode sends its real value only to its hosts, wherever the process runs. For such a variable, the folder no longer limits where the value can go.

## Decision

### 1. What an agent can see

Each agent has a setting (schema version 12, column `agent.see_all`):

| Setting | The agent sees |
| --- | --- |
| Only what it can use (default) | the items of its grants |
| All credentials, without values | also a catalog of each item that is not archived |

A catalog entry has the name, the kind, the plain fields (for example `username`, `host`, `service`, `project`), the visible custom details with their labels, and what the agent can do: `can_use`, `can_request`, `requested`, or `no_variable`. It never has a secret field, a hidden custom detail, the notes (they often hold a pasted secret), or the tags. The catalog has at most 1000 items.

Turning the setting on needs the owner check (`OwnerAction::ShowAllCredentials`). Turning it off takes authority away, so it needs none, and it denies the open requests of the agent. A revoke and a restore turn it off.

### 2. Grants for several items

The owner selects several items in one sheet and confirms once (`OwnerAction::ChangeGrants` names the agent and each item). The vault changes all grants in one transaction: when one item fails (for example, it has no environment variable), no grant changes. One change has at most 64 items. A selected item that already has a grant gets the new place and decision; its rule stays.

### 3. Where a grant works

A process grant works in one project folder, as before, or in any folder (`GrantPlace::AnyFolder`, column `exec_grant.any_folder`):

- In any folder, the broker skips the folder check. The working directory is the project for remembered patterns.
- When the variable of an item in any folder holds the real value, each run with it waits for the owner. The broker checks this at each run, so a later change of the variable counts. The app saves such a grant as "Ask me each time".
- When the variable holds a placeholder, the bouncer can decide, as in a folder.

The other limits stay for each grant: a production credential always waits for the owner (ADR 0010), the hard rule (command prefixes, forbidden words, expiry, hourly limit) applies, and a placeholder goes only to its hosts (ADR 0011).

### 4. Access requests

An agent that sees all credentials can ask for process access to one of them (MCP tool `apassy_request_access`, wire action `request_access`):

- The request names the item and a reason, and optionally a working directory. The broker answers at once. It does not wait for the owner.
- The item must not be archived, must have an environment variable, and the agent must not have a grant for it.
- An agent has one open request for each item. A second request for the same item returns the first one. An agent has at most 20 open requests.
- The reason has at most 500 bytes. Control characters are removed. The app shows it as the text of the agent.
- The Activity view shows each open request. "Give access…" opens a sheet with the place (the folder of the request or any folder) and the decision, then the owner check (`OwnerAction::ChangeGrant`). "Deny" gives nothing, so it needs no check.
- Each grant for the agent and the item answers the open request, also a grant from the Agents view. `list_access` shows the state of the last 20 requests of the agent.
- The history of the item names each request and each denial. The activity log has each request. The Activity item in the sidebar counts waiting runs and open requests.

## What this does not protect

- "All credentials, without values" shows the inventory of the owner to the agent and to the provider of its model: names, usernames, hosts, and visible details.
- The reason of a request is text from the agent. A prompt injection can write a convincing reason. The owner decides with each request.
- In any folder with the real value, each run waits for the owner. That can be many prompts. A variable in placeholder mode avoids this.
- A request does not send a macOS notification yet. It shows in Activity and in the sidebar count.
- A folder is a path on this computer. It has no meaning for a remote agent host (see the cloud stage of ADR 0011).

## Relation to other records

- ADR 0006: the process grant keeps its modes. The folder is now one of two places.
- ADR 0010: the production rule and the owner check (goal item A4) apply to each new grant, each place, and "see all".
- ADR 0011: placeholder mode is what makes "any folder" safe enough for the bouncer to decide.
