# ADR 0001 — P0 feasibility

Date: 2026-09-16
Status: PARTLY DECIDED. Remaining proposals need evidence or an owner decision.

This record is a feasibility input after approval of `docs/mvp-plan.md`.
It does not complete P0 or claim a complete MVP.

Rust is the confirmed core language.
The owner selected a macOS desktop app on 2026-09-16.
The owner also approved eframe/egui dependencies and evaluation of SQLCipher as one encrypted transactional store.
These decisions do not approve real-secret use or waive isolation and storage tests.

## 1. Decision questions

Decided for the foundation:

- macOS desktop app with eframe/egui
- SQLCipher evaluation for one encrypted transactional store

Still open:

- Production storage and key lifecycle acceptance
- First two real services, required before P4
- Local notification channel
- A complete product isolation profile

The remaining comparison records the options considered. A synthetic fixture does not settle an open security boundary.

## 2. Platform and app form

### Option A — Native macOS owner UI and a sandboxed agent

The owner UI is a native macOS application.
The agent runs under a macOS sandbox that the product defines.
The local notification channel can use native OS delivery.

This option avoids a local web origin as the owner surface.
It still needs a real OS boundary.

Limits:

- The first platform is macOS only.
- The owner selected this option and approved eframe/egui for the desktop foundation.
- `sandbox-exec` on this host is a fixture mechanism. It is not the product isolation profile.

### Option B — Local-web owner UI and an isolated agent runtime

The owner UI is a local web application.
The agent still needs an isolated runtime with a real OS boundary.

A local URL is not owner authentication.
If the owner selects this option, P1 must test origin, CSRF, session, and content-injection defenses.
Browser notifications are not an authenticated owner channel.
The durable inbox remains required.

### Shared non-boundaries

These facts apply to Option A and Option B:

- The same user ID is not isolation.
- A separate process is not isolation.
- A keychain item is not isolation.
- Localhost is not owner authentication.

### Comparison

- Owner UI: Option A is native macOS. Option B is a local web app.
- Owner identity: Option A can use a native owner channel. Option B must not treat a local port as identity.
- Agent isolation: both options still need an OS sandbox. Neither option gets that sandbox from a second process alone.
- Notifications: Option A can use native OS delivery plus the inbox. Option B still needs the inbox. OS delivery then needs extra native work.
- P1 shell: Option A freezes a native toolkit. Option B freezes a web shell and a trusted local server.
- First platform: Option A is macOS. Option B does not prove a second OS.

## 3. Storage, state, and key lifecycle

No encryption design is established.
This record does not verify libraries, formats, algorithms, or versions.
A custom cipher is not a candidate.

The owner approved evaluation of SQLCipher for a single encrypted transactional store.
The probe uses rusqlite 0.40.2 with bundled SQLCipher and vendored OpenSSL.
The synthetic probe passed its encryption, wrong-key, metadata, transaction, corruption, and closed-copy checks. See [ADR 0002](0002-encrypted-state-probe.md).
No production vault is connected to the desktop foundation.

A single store can coordinate credential revisions, requests, approvals, audit, and the outbox in one transaction.
The earlier age-file plus separate SQLite proposal is not the selected evaluation direction.

Required properties, still unverified:

- Startup and recovery begin locked.
- Lock stops new credential use and invalidates pending execution authority.
- Owner reveal needs authenticated, deliberate action.
- Edits are atomic.
- Metadata that can expose secrets stays protected at rest.
- Backup and restore follow a documented procedure.
- Lost recovery material can require credential replacement.
- Restored rules need owner review before new agent sessions.

Operational state must cover grants, approvals, counters, audit records, and the notification outbox.

## 4. First two services

The plan names a reporting API and PostgreSQL as candidates, not fixed choices.
A useful candidate needs named read operations, typed parameters, least-privilege requirements, and bounded outputs.

Synthetic contracts are in `docs/contracts/p0-candidates.md` and `tests/fixtures/p0-services.json`.
Hostnames use the reserved `example.invalid` suffix.
Identities are synthetic. The files contain no live credentials.

Remote verification is still required for provider access, grants, operation semantics, destination control, privacy terms, region, limits, and cost.
This record does not invent those facts.

## 5. Notification channel

MVP needs a durable inbox and one authenticated local delivery path.
Acknowledgment is not approval. Delivery failure does not release a paused request.
Previews must hide private details.

Candidate paths:

- Option A: native macOS notifications plus the inbox
- Option B: the inbox in the local web UI. Browser notifications are not an authenticated owner channel.

The channel is not selected.

## 6. Isolation evidence

P0 requires a real OS boundary test before any claim that a broker hides secrets from an unrestricted agent.

This repository has a synthetic filesystem fixture:

- Command: `python3 tests/isolation/test_fixture_boundary.py`
- Mechanism: macOS `sandbox-exec`
- Scope: temporary synthetic vault and owner-token canaries

On a supported host, the fixture must show three facts:

1. An ordinary child with the same user ID can read the canaries.
2. A sandboxed child can read a permitted synthetic agent task file.
3. That sandboxed child cannot read or replace the canaries.

The fixture does not prove memory isolation or clipboard isolation.
It does not prove automation control or IPC isolation.
It does not prove authenticated owner channels or full broker isolation.

Grok sandbox probes are not Apassy product isolation evidence.

Real-secret gate: BLOCKED.

Unsupported OS or absent `sandbox-exec` is a skip. A skip is not product isolation evidence.
A failure to activate the sandbox is a test failure.

## 7. Model contracts

Jev is the planned risk provider. The rule interpreter provider is not selected.
Access, outputs, model identity, privacy terms, region, limits, and cost are unverified.

Unverified model contracts block live P5 and P6 work.
They do not block synthetic walkthroughs, fixtures, or deterministic tests.

## 8. Recommended next owner decision

The owner selected Option A and approved the desktop and storage-probe dependencies.
The contracts, desktop foundation, and SQLCipher probe can now proceed in separate file scopes.

The next gates are:

1. Review the storage probe before production vault implementation.
2. Select two useful real services and verify their contracts before P4.
3. Confirm the local notification channel before P5b.
4. Test the complete product isolation profile before any real-secret use.

Isolation remains BLOCKED for real secrets until a product profile exists and passes tests beyond this fixture.

## 9. P0 status

P0 is not complete.
The desktop direction and SQLCipher evaluation are accepted for the foundation. Production storage, key handling, and product isolation remain open.
