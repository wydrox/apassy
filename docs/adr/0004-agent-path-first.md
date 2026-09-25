# ADR 0004 — Agent path before rules

Date: 2026-09-25.
Status: owner approved on 2026-09-25. This decision changes the task order in `docs/mvp-plan.md`. It does not change the MVP acceptance checks.

## Context

The owner vault works in the desktop app. The alpha test on 2026-09-25 showed this result.
The agent path does not exist. There is no CLI, no MCP server, no agent identity, and no connector.
The plan puts P4c after P3, so rules come before the first agent request.

The main product questions need an agent path to answer them:

- Can an agent use a credential without the secret value?
- Does the owner understand what the agent did?
- Does the isolation boundary hold in a real agent host?

## Decision

Build a thin agent path first. Then add rules (P3) and the bouncer (P5) on that path.

The thin path contains these parts:

1. Agent identity (part of P2b). The owner registers an agent in the desktop app. The app shows a random agent token one time. The owner can revoke the agent.
2. Manual grants (temporary, in place of P3). The owner permits one agent to use one item for one named operation. There is no plain-language rule and no contextual check.
3. One connector (part of P4a). The connector uses the synthetic profile `reporting-api-v0` from candidate A in `docs/contracts/p0-candidates.md`. The broker puts the API token in the request. The agent receives only the permitted output fields.
4. A local broker (part of P4c). The desktop process accepts agent requests on a Unix socket. The socket directory has mode `0700`.
5. An MCP adapter (part of P4c). The `apassy-mcp` program uses stdio. It sends each tool call to the broker socket. It does not open the vault file.
6. An activity record for each decision in the encrypted vault.

## Constraints

- The agent never receives a secret value. The broker reads the secret only after all checks pass.
- The agent request uses a named operation and a registered destination. The request has no URL, header, or SQL field. This follows `docs/contracts/rust-v1.md`.
- A locked vault refuses all agent requests.
- A restore from backup revokes all agents. The owner must register the agents again.
- Agent tokens are in the encrypted vault database. Comparison uses constant time.
- The connector accepted only loopback `http://` destinations at first. [ADR 0005](0005-connector-tls.md) adds `https://` destinations.
- The adapter and the synthetic service use only `std` and `serde_json`.

## Result for the plan

- P2b, P3, P4a, and P4c stay open. This path does not satisfy their acceptance checks.
- Manual grants are temporary. P3 replaces them with confirmed rules on the same path.
- The real-secret gate stays BLOCKED. The broker hides the secret value from the adapter. It does not hide the vault file from an unrestricted process of the same user.
- The isolation test must show that a sandboxed adapter can call the broker and cannot read the vault file.

## Open decisions

- TLS client dependency: closed by [ADR 0005](0005-connector-tls.md).
- Peer identity on the socket. The `std` library has no safe peer-credential call. The directory mode and the token are the controls in this phase.
- Token life and rotation. A token is valid until revoke or restore in this phase.
