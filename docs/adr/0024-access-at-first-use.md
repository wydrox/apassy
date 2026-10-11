# ADR 0024 — Access at first use

Date: 2026-10-09.
Status: ACCEPTED by the owner on 2026-10-09 ("zgadzam się z rekomendacją"). In the code on branch `feat/access-at-first-use`.

## Context

On 2026-10-09 the owner tried to start to use Apassy with Claude Code and stopped at the agent setup. Before this decision, the owner had to plan all access before the first use:

1. Connect the host.
2. Select the credentials for the agent.
3. Set the project folder and the decision mode, and confirm.
4. Start the host with `MCP_TOOL_TIMEOUT=180000 apassy-sandbox -- claude …` from the project folder.
5. Approve each run in the app within 120 seconds.

The setup also had three traps:

- "Bouncer decides" without a declaration asks the owner at each run (`before_model`, ADR 0008). The app did not say so.
- An agent saw only the items of its grants (ADR 0012). A new agent saw nothing, so it could not ask for anything.
- The default bouncer start mode was "Managed outside Apassy", so a new Mac had no bouncer and each run waited for the owner.

A host that Apassy does not start (for example T3 Code, which starts Claude Code itself) cannot follow step 4.

## Decision

The owner decides about access when an agent needs a credential, not before.

### 1. First use

When an agent that sees all credentials (ADR 0012) runs a command with an item that it has no process grant for, the broker does not refuse with `not_granted`. The run waits for the owner, as a run in "ask" mode does.

- The item must be in the catalog: not archived, with a usable process field (`needs_field` still refuses), and reviewed after a restore.
- The waiting run names each item of the first use, the folder of the offer, and the declaration that the grant saves.
- The folder of the offer is the nearest parent of the working directory that has `.git`, up to the home folder. Without one, it is the working directory.
- A folder that is the root, the home folder, or a parent of the home folder gets "Allow once" only, including filesystem aliases such as macOS `/.nofollow` and `/System/Volumes/Data`. The card does not show "Allow in FOLDER". The queue refuses a crafted `ApproveAndGrant` for such a folder (`NothingToGrant`), and the broker checks the folder again before it saves (`grant_failed`). "Allow once" still works.
- The card shows what the process gets for each new item, as `process_binding` delivers it now: the real value or a placeholder with its hosts. An automatic binding delivers the real value, and a grant in the folder keeps delivering it. Paths and names on the card, the folder in the owner-check dialog, and the names in the Touch ID prompt lose control and format characters and are shortened. The proof still names the exact path.
- The bouncer model is not asked. A first use always waits for the owner. A model must never give new access.
- An agent has at most one waiting first-use run. A second one gets `first_use_waiting`. This limits prompts from a prompt injection.
- An agent that does not see all credentials still gets `not_granted`. It cannot learn which items exist.

The approval card has three answers:

| Answer | Effect | Owner check |
| --- | --- | --- |
| Allow in FOLDER | The run starts. The agent gets a process grant for each first-use item in FOLDER, "Bouncer decides". An item without a declaration gets the declaration of the card. | Yes |
| Allow once | The run starts. Nothing is saved. | Yes |
| Deny | The run does not start. | No |

The broker saves the grant and the declaration after it checks the vault again, in the same vault session, before it reads the secrets. This is the same order as "Approve and remember" (ADR 0010). One owner check covers the run, the grant, and the declaration (`OwnerAction::ApproveAndGrant`). The check text names the declaration that it saves, and says that later clean runs in the folder may start without asking. For a production declaration it says that the item still waits at each run. After the check the app says only that the run is approved and that Apassy saves the access when the run starts: the queue took the answer, and the broker saves after its second check.

The iPhone can approve a first use only once. It never makes a grant (ADR 0020: a phone approves a run only). The digest of a run does not change.

### 2. The declaration at first use

The card shows the declaration that Apassy suggests from the item (goal item B4). A value that the suggestion does not find has the most sensitive default (production, high risk, admin, irreversible). The owner can change the environment on the card. A production declaration makes each later run wait for the owner (ADR 0010); the card says so.

An item that has a declaration keeps it. The card shows it and does not change it.

### 3. What an agent sees

- "Connect" in the agent guide has the setting "Let the agent see credential names without values". It is on by default. The connection and this setting need one owner check.
- A catalog entry has the `env_name` that a run with the item will use, also before a grant.
- `can_request` in the catalog now means: use the item in `apassy_run_with_secrets`, and the owner approves the first use. `apassy_request_access` stays for an agent that wants access before a run.

### 4. Host start

The guide shows the normal start of the host. The Apassy sandbox (`apassy-sandbox`) is optional protection. The broker never required it.

### 5. The bouncer

- Apassy is the only program that starts the bouncer. The owner removed the LaunchAgent `com.wydrox.apassy.bouncer` on 2026-10-09; a copy is in `~/.config/apassy/disabled-launchagents/`.
- In "With Apassy", when a server that Apassy did not start stops, Apassy starts its own.
- A missing `bouncer.json` gives "When a run needs it", not "Managed outside Apassy".
- Without a running bouncer, each run waits for the owner, as before.

## What this does not protect

- The catalog shows the names, usernames, hosts, and visible details of the owner's credentials to the agent and to the provider of its model (ADR 0012). The owner can turn it off for each agent.
- A prompt injection can start a first-use run with a convincing user request. The owner decides at each first use. The limit of one waiting first-use run per agent stops a flood of prompts, not one convincing prompt.
- "Allow in FOLDER" gives a grant in "Bouncer decides". Later runs in the folder that the bouncer finds clean start without a prompt. A wrong declaration that the owner accepted on the card makes the bouncer less strict.

## Relation to other records

- ADR 0006: process grants keep their modes and rules. First use adds a way to make a grant.
- ADR 0008: a declaration stays required for a decision of the model. The card makes it in the same step.
- ADR 0010: production runs and first uses always wait for the owner. A grant needs a fresh owner check.
- ADR 0012: "All credentials, without values" is the default for a new connection. Access requests stay.
