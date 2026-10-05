# ADR 0016 — Team alpha: a relay, shared collections, and agents anywhere

Date: 2026-09-28.
Status: PROPOSED. A draft for the owner. The open decisions are in the last section, D1 to D9. No code exists yet. The relay is a separate crate under its own license (owner decision of 2026-09-28); this repository stays Apache-2.0.

Update 2026-10-01: [ADR 0018](0018-local-bouncer-shared-vault-relay.md) replaces the relay model sidecar with a local bouncer and relay policy checks. It also records multiple active vaults and the existing VPS as the initial host. The cloud executor below needs revision. The relay alpha (way B, host-held item keys) is in the separate repository `apassy-relay` and runs on the VPS: see [relay server](../operations/relay.md). [ADR 0019](0019-relay-teams-and-accounts.md) (proposed) adds several teams on one relay, device keys, and onboarding by link; it replaces the cut "a hosted multi-tenant relay" in section 8.

## Context

What exists in 0.2.1:

- One owner, one SQLCipher vault on one Mac. The broker listens on a Unix socket, with an agent token, and never returns a secret value ([ADR 0006](0006-process-secrets.md)). `apassy-mcp` is a stdio adapter of that socket.
- A run gets a placeholder and goes through a proxy that puts the real value only into an auth position of a request to the hosts of the variable ([ADR 0011](0011-run-proxy-placeholders.md)). On macOS the process can reach only the proxy. On Linux there is no such rule yet, and the placeholder is still worthless without the proxy.
- The bouncer runs the same decision code for each run: hard rules, the command analysis with 64 packs, the declarations, the user request from the host hook, and the base model on Laya ([ADR 0007](0007-rules-and-local-bouncer.md), [ADR 0009](0009-general-by-default-and-learning.md)). A production credential always waits for the owner.
- Apassy builds and passes its tests on Linux (0.2.1). The desktop app for Linux is not published. Agent isolation is macOS Seatbelt only.

What the owner asked for on 2026-09-28: credential sharing in a team (collections, or sub-vaults); every agent that has Apassy configured can use secrets safely, on the owner's computer, in a cloud session, or anywhere else; the bouncer free for a person, central policies paid for a team.

What the market has: Claude Code cloud environments on Pro and Max plans store API credentials that an Anthropic proxy attaches to requests for listed hosts. There is no policy, no approval, no audit tied to the user request, and the feature is not on Team and Enterprise plans and not in self-hosted environments. Nothing in the market decides per command with a local model and rule packs. That decision layer is what a team edition sells.

## Decision (proposed)

### 1. Parts

| Part | What it is | Where it runs |
| --- | --- | --- |
| Relay | A Linux service in the crate `apassy-relay`. It depends on the `apassy` crate with the `vault` feature: the broker decision code, the run proxy, the packs, the bouncer client, and the vault. | A container on a Linux VM of the team. Self-hosted in the alpha. |
| Team vault | One SQLCipher file on the relay with the items of the team, the members, the agents, the collections, the grants, and the audit. | The relay. |
| Collection | A named set of items with one policy. | The team vault. |
| Member app | The existing macOS app with a second source, "Team", next to the local vault. | The Mac of each member. |
| Remote executor | `apassy-mcp` in remote mode: it talks HTTPS to the relay instead of the Unix socket, and starts the process itself. | Where the agent runs: a cloud session, a CI job, a Linux box. |
| Audit | Each decision, run, denial, grant change, and revocation, with the agent, the member, the collection, the user request, and the network log of the run. Never a value or a placeholder. | The team vault. |

### 2. Two ways an agent uses a team credential

| Way | The agent runs | Decision | Value | Egress |
| --- | --- | --- | --- | --- |
| A. On a member's Mac | Claude Code or Codex in the Seatbelt profile, as today | The local broker, with the policy of the collection from the relay | The local broker fetches the value from the relay for one run, in memory, after the decision. It never enters the member's vault file. | The local run proxy with placeholders, as today |
| B. Without a Mac | A cloud session, a CI job, an agent on Linux | The relay, with the same decision code | Stays on the relay | The relay is the proxy. Base-URL rewrite for tools that have one (`OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, `AWS_ENDPOINT_URL`, `STRIPE_API_BASE`); `CONNECT` with a run certificate where the network allows it; a mediated `Call` for connector operations ([ADR 0004](0004-agent-path-first.md)) |

Way A reuses every part that exists and is the first stage. Way B is what a member's laptop being closed needs, and what a cloud session needs. In way B the placeholder is worthless outside the run, so the relay does not need to control the network of the VM: a program that goes around the proxy fails closed.

### 3. Collections and grants

- A collection has a name, items, and a policy: the packs and local rules that apply, the bouncer mode, the approvers, and "production always waits" (always on; the policy cannot turn it off).
- A grant gives one member, or one agent of a member, the use of a collection in a place: any folder or one project folder, as [ADR 0012](0012-agent-visibility-and-access-requests.md) does for one item. A member with a grant can register agents that use it.
- Sharing is the grant. No value is ever copied to a member. A revocation works at the next request. The audit of the team is in one place.
- The team owner and a member with the manager role add and change items. Every other member sees the catalog of the collections they can use, without values, as an agent does today.

### 4. Identity in the alpha

- The team owner creates the team on the relay with a passphrase. Members join with a one-time invite code from the owner. The member app enrolls once and keeps a member key in the member's local vault. An agent gets a token as today; the token names its member.
- No SSO, no web login, no passkeys in the alpha.
- Approvals for way A stay in the member's app. Approvals for way B go to the approvers of the collection, in their apps, through the relay to the inbox. Slack is stage 2.

### 5. Transport

The wire messages of the broker (`WireRequest`, `WireResponse`, `WIRE_VERSION`) go over HTTPS with the agent token as a bearer, with the same check order as the [broker contract](../contracts/broker-v0.md) section 4. The server is one HTTP/1.1 server on `rustls`, without an async runtime, as the run proxy. The certificate is the operator's, or from Let's Encrypt through the container. Cloud sessions of Claude Code reach an MCP connector outside the network allowlist of the environment, so the relay needs no entry there; a run with base-URL rewrite needs the relay host in the allowlist.

### 6. Bouncer on the relay

- The relay runs `decide::handle` with the packs of the release and the policy of the collection. Unavailable is never an allowance, as today.
- The base model runs as a sidecar container (Python, `tools/basemodel/serve.py`) in the same Compose file. Without the model the relay works in "ask" mode.
- Learning stays in each member app in the alpha. The relay records decisions for the audit only. Central patterns and calibration are a later ADR: they change what runs without a person, so they need their own evidence.

### 7. What the alpha must show

| Item | Evidence |
| --- | --- |
| T1. Two members, one relay, one collection with three credentials: a Stripe test key, a GitHub token, a Postgres staging URL. | A measured run on a real VM, in `docs/operations/relay.md`. |
| T2. Member A's Claude Code runs a `stripe` command on A's Mac with the team key in placeholder mode. A never sees the value. The relay audit has the run with A's user request. | A test against a synthetic service, and the measured run. |
| T3. The owner revokes A's grant. The next request of A's agent is denied. | A test. |
| T4. A Claude Code cloud session, without a Mac, uses the same key: one mediated call and one run with base-URL rewrite. The approver gets the ask in the app. The value never appears in the environment of the VM, in a file, or in the transcript. | The measured session, with the transcript checked for the value. |
| T5. A production credential in the collection always waits for an approver, in way A and in way B. | A test for each way. |
| T6. The model on the relay is down: each request that reaches the model asks, none runs. | A test. |
| T7. One `docker compose up` on one Linux VM with TLS, and a document that a second person followed. | The document and the second person. |
| T8. The relay never returns a secret value on the wire, and no audit row has a value or a placeholder. | Tests with canary values, as `tests/agent_run.rs` does. |

### 8. Not in the alpha

SSO and web approvals, Slack, central learning, rotation, a hosted multi-tenant relay, Windows, a network rule for runs on Linux, HTTP/2 and WebSocket in the proxy, signed requests (AWS SigV4) in way B, and named actions for transfers ([ADR 0011](0011-run-proxy-placeholders.md), stage 3).

## What this does not protect

- In way A the value reaches the member's Mac for one run. The member is trusted to the level of that value; the team trusts the member's machine as much as the member.
- The relay holds the key of the team vault in memory while it runs. An operator with root on the VM can read it. That is the trust model of self-hosting, and the reason the relay is self-hosted in the alpha.
- Way B depends on the network of the host. A cloud environment with its own egress proxy may not allow `CONNECT` to the relay. Base-URL rewrite works only for tools that read a base URL. The spike in stage 1 measures this before anything else is built.
- A run on a Linux host without a network rule can send other data to other hosts, as on macOS in tunnel mode. It cannot get the value.

## Stages

1. Spike, 2 to 3 days: the wire over HTTPS to a relay stub, and a run with base-URL rewrite from a real Claude Code cloud session. The result decides whether way B is in the alpha (D5).
2. Relay core, 2 to 3 weeks: the crate, the team vault, members and invites, collections and grants, the HTTPS wire, the audit, the Compose file, the document.
3. Member app, 1 to 2 weeks: the Team source, enrollment, the collection view, a run through the local broker with a value from the relay, the inbox for relay approvals.
4. Remote executor, 1 to 2 weeks: `apassy-mcp --remote`, placeholders, base-URL rewrite, the mediated call.
5. Two weeks of use by the alpha team. Then a decision on stage 2: Slack, web approvals with passkeys, central learning.

The estimates assume one maintainer with an agent and no other work. They are estimates.

## Open decisions for the owner

| # | Decision | Proposal |
| --- | --- | --- |
| D1 | The alpha team: who, how many members, which hosts, which three credentials. | Two people, Claude Code local and one cloud session, the three credentials of T1. |
| D2 | The relay crate: the repository name, the license text, who creates it. | `wydrox/apassy-relay`, private until the alpha, FSL-1.1-Apache-2.0 at the first public version. |
| D3 | Where the test relay runs: a Linux VM I can reach, a host name, TLS. | One small VM, `relay.apassy.wyderka.cc` in Cloudflare DNS, Let's Encrypt in the container. |
| D4 | The model on the relay: the base model as a sidecar, or no model in the alpha. | The sidecar. It needs `apassy-base-v1.safetensors` and the base weights, or their R2 URL. |
| D5 | Way B in the alpha, and the first provider for base-URL rewrite. | Yes if the spike passes. Stripe test mode first: the `stripe` CLI has `--api-base`, and the SDKs read `STRIPE_API_BASE`. |
| D6 | Approvals for way B: the approver's app only, or Slack now. | The app only. Slack in stage 2. |
| D7 | The key of the team vault: a passphrase typed at each start, or a key file for unattended restarts. | A passphrase at start in the alpha. |
| D8 | Identity: invite codes and device keys, no SSO. | As in section 4. |
| D9 | Names and roles: "collection" or "sub-vault"; owner, manager, member. | "Collection" in the app, "sub-vault" nowhere. Three roles. |

## Relation to other records

- ADR 0006 and ADR 0011 stay valid. Way A is ADR 0011 with a value from the relay. Way B is ADR 0011 stage 7, "the proxy on another computer".
- ADR 0012 stays valid. A collection grant is a grant for several items with one policy.
- ADR 0010 "Models": the relay adds no hosted model. The model is the team's own container.
- The goal in [goal.md](../goal.md) is for one owner. A team goal document comes with the acceptance of this ADR.
