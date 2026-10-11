# ADR 0025 — Low-friction access: the bouncer decides, two steps to add, agents add credentials

Date: 2026-10-12.
Status: PROPOSED. The owner agreed to the direction on 2026-10-12 ("tak"). Not in the code. It changes [ADR 0024](0024-access-at-first-use.md) §1 and [ADR 0012](0012-agent-visibility-and-access-requests.md) §3.

## Context

On 2026-10-12, after PR #12 and PR #13 were merged, the owner said that Apassy is hard to use:

- It is not easy to use agents with Apassy.
- To add a credential, the owner fills about a dozen fields from the start.
- Each credential must be given to one agent. This blocks the use of the app.
- "We have the bouncer so that it takes over everything. It can be too sensitive, but we should not require the user to configure each credential."
- "If this is a password manager for agents, why can they not add new credentials?"

ADR 0024 removed the setup before the first use. It did not remove the cost:

- Each first use of each item, by each agent, in each folder, waits for the owner with Touch ID. "The bouncer model is not asked."
- The add form needs a kind, a name and a secret. The variable, the hosts, the provider and the declaration (environment, risk, scope, reversibility) are on other screens. The provider catalog (`packs/providers/`, 19 providers) can find most of them, but Apassy uses it only after the save, as a suggestion.
- The agent interface has no way to store a credential (`src/agent/mcp.rs`, `src/agent/wire.rs`).

The owner's goal: **two steps to add, dozens to customize.**

## Decision

### 1. The measure

Apassy counts the owner interactions: approvals, questions and owner checks. The app shows the count for each week. A change that adds an interaction without a security reason is a regression.

A bouncer that asks too often is acceptable. A required setting before use is not.

### 2. The main path for an agent

1. `apassy_list_access` gives the catalog of the credentials without values. It is on by default for a new connection (ADR 0024 §3).
2. The agent picks an item and uses it with `apassy_run_with_secrets` or `apassy_use_credential`.
3. The bouncer decides with the context (§3). It starts the run or asks the owner.

The agent needs no grant. Connecting the agent is the only setup and needs one owner check. Grants stay as optional settings of the owner: "always allow", "always ask", "never" for one agent and one item.

### 3. The bouncer decides from the first use

This replaces ADR 0024 §1 "A first use always waits for the owner. A model must never give new access."

The bouncer gets this context at each use:

- the agent and the user request that the host sent (ADR 0008),
- the folder, the project (the repository and the branch),
- the command and the hosts that the secret goes to,
- the item: its provider and its declaration, with the source of each value (§4),
- the history: earlier uses of the item in the project, by which agent, with what result, and the owner's earlier answers.

It starts the run without a question when the use fits the context. Examples:

- The project used the item before and the command goes to the hosts of its provider.
- A development key of a known provider goes to that provider's hosts, and the user request names the task.

It asks the owner when:

- the item has no history in the project and its declaration is not development with low risk,
- the secret goes to a host that is not a host of its provider,
- the item does not fit the project, for example the item of another project,
- the command is unusual for the item or the project,
- the bouncer is not sure.

The rules that the model cannot change stay:

- A production declaration waits for the owner at each run (ADR 0010), unless the owner allowed production for the project and the kind of action (§3b). The model and the usage log never make such an allowance.
- A one-time-code setup key is never chosen automatically (the OTP fix in PR #13).
- A placeholder goes only to its hosts (ADR 0011).
- Without a running bouncer, each run waits for the owner.
- An agent has at most one waiting question. This limits prompts from a prompt injection.
- An item marked "Always ask me" waits at each run.

Each answer of the owner is remembered for the item, the project and the kind of action, so the same question does not come again. The question card says what Apassy remembers.

### 3a. Project and kind of action

The owner accepted both on 2026-10-12.

- **Project.** A project is one git repository with all its worktrees: the folders that share the git common directory. A folder without git is its own project. ADR 0024 keeps the root, the home folder and its parents out: they are never a project.
- **Kind of action.** A fixed list: *read*, *change*, *deploy*, *delete or irreversible*. Hard rules classify first (for example `DELETE`, `drop`, `--force`, `rm`, `destroy` are always *delete or irreversible*). The model only fills in what the rules do not cover. When the class is not clear, the more dangerous class counts.

### 3b. Production allowed by the owner

The owner decided on 2026-10-12 that the owner can allow production ("mogę zezwolić").

- A question about a production item has the answer "Allow production for PROJECT: ACTION". ACTION is a kind of action, for example reading data, a deploy, or a change of data. The card names it.
- The allowance needs an owner check. It is valid only for the item, the project and the kind of action. A command of another kind still waits.
- Only an answer of the owner makes an allowance. The bouncer, a remembered pattern and the usage log cannot.
- The item screen lists the allowances. The owner removes one with one click; the removal needs no owner check.

### 3c. Who an answer covers

The owner decided on 2026-10-12 ("tak, zostajemy") that an answer covers all agents in the project. Connecting an agent is already the trust step. A limit to one agent would repeat each question for each new agent. An agent with the setting "Ask me again for this agent" does not use the answers of other agents, for example a remote agent or a test agent.

### 3d. Answers on the iPhone

The owner decided on 2026-10-12 that the iPhone answers the questions of §3, §3b and §5 ("tak"). This changes ADR 0020: the phone can now make a remembered answer, a production allowance and a correction of a declaration. Each such answer is signed with the approval key and Face ID, as a run approval is (ADR 0020 §4). The phone still cannot unlock the vault, connect an agent or change a setting.

### 3e. Waiting and notifications

The owner decided on 2026-10-12:

- A question waits **5 minutes**. When the host of the agent ends the call earlier (its own tool timeout), the agent gets "waiting for the owner, call again", and the question stays open until the 5 minutes end.
- Each question goes as a notification to **every device** connected to the vault: each Mac with the vault, each iPhone, the app. The first valid answer counts. The other devices show who answered and where.
- **Teams.** A question about an item of a team collection goes to the member that the agent acts for (ADR 0019). A production allowance for a team item needs an owner or a manager of the team. Other members get no notification.
- **The relay carries the notifications** ("relay jako kanał powiadomień"), also for a personal vault. The relay keeps no vault data of a personal vault, which still syncs through iCloud Drive (ADR 0023). It routes end-to-end encrypted questions and answers, and sends Apple push notifications (APNs) to the iPhones. The relay sees the routing only. This closes D1 and D2 of ADR 0020.
- Without the relay, notifications work on the Mac and on the local network only.

### 4. Two steps to add

1. **Paste.** One field takes a secret, a `KEY=value` line, a whole `.env` file, a URL with credentials (`postgres://…`) or an `otpauth://` link.
2. **Save.**

Apassy finds the rest on this Mac, without sending the value anywhere:

- The kind, the provider, the name, the variable and the hosts come from the provider catalog: the value prefix (`sk-ant-`, `ghp_`, `sk_live_`, `AKIA`…), the variable name and the host.
- A URL is split into fields. Its password is the secret.
- A `.env` file gives one item for each line. The owner unchecks lines in one list and saves once.
- A value without a signal becomes a Custom item with a name from the variable, or "Credential" with the date.
- The declaration is saved with the item. A value without a signal gets the most sensitive default, as before (ADR 0008).

The save shows the result in one line, for example "Anthropic API key · `ANTHROPIC_API_KEY` · development". All other settings are on the item screen. The owner never needs to open it.

Each value of the declaration has a source: found from a signal, from usage, or set by the owner. The bouncer is more careful with a value that only a weak signal found.

The CLI does the same: `apassy add` reads only the secret from standard input.

### 5. Usage and corrections

Apassy keeps a usage log for each item: the agent, the project, a summary of the command, the hosts, and the decision. The item screen shows it.

From the log, Apassy proposes a correction when the usage does not fit the declaration. Examples:

- "This key goes to `api.stripe.com` with a live value. Mark it as production?"
- "Used only in `~/Dev/x` by Claude Code. Limit it to this project?"

The owner answers with one click or ignores the question. Until the owner answers, the bouncer uses the more careful value.

### 6. Agents add credentials

New MCP tools:

| Tool | What it does | The agent sees the value |
| --- | --- | --- |
| `apassy_capture_credential` | Runs a command or reads a file and saves the output as a new item, for example `gh auth token` or a key that a provider CLI creates. Detection as in §4. | No |
| `apassy_generate_credential` | Apassy makes a password or a token (length and alphabet), saves it and returns the item. The agent uses it with `apassy_run_with_secrets`, for example to create a database user. | No |
| `apassy_save_credential` | Saves a value that the agent already has, for example from an API answer. The tool description says that the value is already in the transcript and that `capture` is better. | It had it before |
| `apassy_ask_owner_for_credential` | Asks the owner to paste a credential. The agent gives a name, the purpose and where to get it. The owner gets the two-step add of §4. The agent gets the item when the owner saves. | No |
| `apassy_update_credential` | A new value for an item that this agent created, by capture or generation. For another item, it is a proposal that the owner approves. | No |
| `apassy_describe_credential` | Changes the name, the notes, the variable and the hosts of an item that this agent created. | — |

The rules for an item that an agent creates:

- An agent only creates. It cannot read a value back, delete an item, or change an item that it did not create.
- The item has "Added by AGENT, in FOLDER, at TIME". Activity shows it, and the owner can archive it with one click.
- A name that exists gets a suffix. A value that exists returns the existing item and creates nothing.
- An agent creates at most a limited number of items each hour. Above the limit, the owner is asked.
- The use of the item goes through the bouncer, as for each other item.

## Implementation order

Each stage is useful alone and has its own PR. There is no release until the owner asks.

1. Two steps to add (§4). It does not change the security model.
2. Usage log, corrections and the interaction count (§1, §5).
3. Agent tools (§6), first `ask_owner`, `capture` and `generate`.
4. The bouncer decides from the first use (§2, §3). This stage changes the security model and gets its own security review.

## What this does not protect

- A wrong decision of the bouncer lets an agent use a credential without asking the owner. A prompt injection can try to cause that. The rules of §3, masked output, placeholders and "Always ask me" limit it. They do not stop it.
- A value that a weak signal classified as development can be production. The bouncer is then less careful until the usage log shows the difference.
- An agent can store a credential of an attacker under a plausible name, for example a token for another account. Other agents can then use it. The catalog and Activity show which agent added the item.
- The catalog shows the names, usernames, hosts and visible details of the credentials to the agent and to the provider of its model (ADR 0012).

## Relation to other records

- ADR 0008: a declaration stays required for a decision of the model. Apassy makes it at the save (§4).
- ADR 0010: the production rule stays, with one exception: an allowance of the owner for a project and a kind of action (§3b).
- ADR 0011: placeholders stay the safe way to send a value only to its hosts.
- ADR 0012: a grant is no longer needed. Grants stay as optional settings.
- ADR 0019: the relay also carries notifications and answers, for teams and for personal vaults (§3e).
- ADR 0020: the phone answers the questions of the bouncer and the corrections, and can allow production (§3d). Access away from the local network and push notifications come through the relay (§3e).
- ADR 0024: first use goes to the bouncer, not always to the owner. The limit of one waiting question stays.
