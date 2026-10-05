# ADR 0018 — Local bouncer and shared vault relay

Date: 2026-10-01.
Status: Architecture direction accepted by the owner. Not implemented. The relay alpha of ADR 0016 runs on the VPS, but it has none of the decisions below.

## Decision

- Multiple vaults can remain active at the same time. Each vault has separate lock state, agents, grants, and activity.
- Selecting a vault changes the view. It does not lock other vaults.
- A personal vault can stay local. Shared vaults use a relay on the existing VPS.
- The bouncer model, command analysis, and learning stay on each client computer. No model runs on the relay.
- The relay stores shared policies and checks membership, grants, revocation, policy versions, and required approvals before it permits an operation.
- A client can apply stricter local rules. It cannot weaken the policy of a shared vault.
- An unavailable local bouncer does not grant access. Use the approval path or deny the request.
- A shared operation needs the relay. Local personal vaults remain usable when the relay is unavailable.

These decisions replace the single active vault direction in ADR 0013 and the relay model sidecar in ADR 0016, including D4 and T6. The existing application still follows ADR 0013.

## Trust and limits

A local model result is not proof that an untrusted client obeyed the policy. Command analysis and model decisions require a trusted client device. The relay must check server-controlled restrictions, including permitted destination hosts, itself. The protocol must bind approvals and grants to the member, device, vault, credential IDs, exact operation, policy version, and expiry.

The secret transport remains an open implementation decision: a value can reach a trusted local broker for one operation, or stay on the relay behind its proxy. Do not claim that the first option prevents a device administrator from obtaining that value.

Credential use without a client bouncer is outside the first stage. The cloud executor flow in ADR 0016 needs a new design before implementation. No relay model is a fallback.

## Server

The relay runs on the existing VPS (SSH alias `ottervibe`) in its own Docker Compose project with its own storage and limits. No port is public: a Cloudflare Worker reaches it through a Workers VPC binding and a named tunnel. See [relay server](../operations/relay.md).

## Required application checks

- Two unlocked vaults serve their own agents at the same time. A screen change does not interrupt either vault.
- Locking one vault denies its new operations without granting access to another vault.
- A revoked grant and an obsolete policy version cannot authorize a new shared operation.
- A missing bouncer cannot cause automatic permission.
- A forged client allowance cannot bypass relay permissions or required approval.
- A relay outage does not prevent use of a local vault.
