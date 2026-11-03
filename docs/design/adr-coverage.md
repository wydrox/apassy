# ADR coverage — every open point of ADRs 0001 to 0039

Date: 2026-11-03. Base: `origin/release/0.5.16` at 0edf1f90. Status: MAP, read-only research. No code
changed.

Question of the owner: "Will every point of the existing ADRs be addressed?" Owner decision
(2026-11-03): everything gets built except the TEE enterprise track (ADR 0037 section 11, E1 to E4,
D12, D13). This page lists each point that is not done, so that each one has a home.

Sources read: `docs/adr/0001`–`0039`, `docs/goal.md`, `docs/product/plans.md`,
`docs/design/implementation-plan-*.md`, `docs/design/release-plan-0.5.16.md`,
`docs/design/stage5-plan.md`, `CHANGELOG.md`. Statuses that were unclear were checked in the code
(paths below) and on GitHub.

## Categories

| Category | Meaning |
| --- | --- |
| `0.5.16-core` | In the running 0.5.16 work: main since 4fd3f9f, fixes F1–F6, the cloud slice, the Bouncer section (U1b, U3a, U3b-1, U2c, U2b, U3b-2, U4 of [implementation-plan-bouncer-section](implementation-plan-bouncer-section.md)), ADR 0028 stage 1 |
| `plan:s2-s3` | ADR 0037 rest of stage 2, and stage 3 (Linux node) |
| `plan:s4-teams` | ADR 0037 stage 4, shared vaults (ADR 0018, ADR 0026 §6), ADR 0019 leftovers, ADR 0022 stage 2 and later |
| `plan:s5-env-0011` | ADR 0037 stage 5, ADR 0011 stages 2–7, Linux isolation |
| `plan:s6-sharing` | ADR 0037 stage 6 |
| `plan:s7-connect` | ADR 0037 stage 7, [plans](../product/plans.md), D14, relay-sync notices |
| `plan:0035` | ADR 0035 waves 2–5 |
| `plan:s8` | ADR 0037 stage 8: iPhone embedded tailnet, Linux window |
| `physical` | Only an acceptance check on the owner's devices or accounts |
| `superseded` | Replaced by a later ADR (named in the row) |
| `tee-deferred` | The TEE enterprise track |
| `other` | Fits none of the above; the row says what it needs |

## Summary

| Category | Points |
| --- | --- |
| `0.5.16-core` | 10 |
| `plan:s2-s3` | 14 |
| `plan:s4-teams` | 21 |
| `plan:s5-env-0011` | 10 |
| `plan:s6-sharing` | 4 |
| `plan:s7-connect` | 11 |
| `plan:0035` | 7 |
| `plan:s8` | 2 |
| `physical` | 13 |
| `superseded` | 9 |
| `tee-deferred` | 6 |
| `other` | 24 |
| **Total** | **131** |

### The `other` points

| ID | Point | What it needs |
| --- | --- | --- |
| 0010-1 | Connectors as plugins (P4a, P4b) | A new ADR. goal.md puts it out of scope; the owner's 2026-11-03 rule puts it back in. |
| 0011-7 | ADR 0011 stage 6 for Windows (service account), and stage 4 for Windows | A decision to port to Windows. No ADR or plan covers Windows; the code does not build there. |
| 0012-1 | macOS notification for an access request | A small unit: `OwnerEvent` (`src/desktop/notify.rs:88-96`) has no access-request kind. |
| 0015-1 | `latest.json` `file` to the versioned name; end `/download/Apassy.dmg` | An owner decision that no app before 0.5.0 is in use, then a change of `scripts/build-dmg.sh:340` and the Worker. |
| 0021-1 | Fill a login in a cross-origin frame (D4); agent fills top frame only (ADR 0036) | A design with a host permission for the frame, and a security review. |
| 0022-6 | 64 MiB push through the Cloudflare edge (open question 3) | One test push on the live relay (ops, owner go). |
| 0023-2 | Synced favorites (D3) | A vault schema change and a merge rule. |
| 0023-3 | iPhone app in the App Store (D4) | Owner decision, privacy policy, export classification review, submission. |
| 0026-2 | iPhone Settings follow the Mac grouping of §3 ("when it changes next") | A check against `ios/ApassyCompanion` and the 2026-10-17 UX plan; maybe a small UI unit. |
| 0030-1 | Hardening against synthetic UI input inside the owner window | A unit (reject events by `kCGEventSourceUnixProcessID`, hide AccessKit press actions on approval buttons) and an owner decision. Not in `src/`. |
| 0030-2 | Dark appearance: the egui kit is light only (also ADR 0031) | A theme implementation and a mockup. |
| 0030-3 | CLI code reuse of the owner window (also ADR 0034) | An ADR for a verified owner transport for the CLI. Until then CLI codes stay fresh. |
| 0033-1 | Notification policy for access requests (review item 2): per-Mac budgets, or quotas, a quiet class, an exact-card push link | An owner decision. A quota or quiet class needs a separate transport design. |
| 0035-8 | Shared base model from owner data (decision 5) | A separate ADR on opt-in, anonymization and retention, before any collection. |
| 0035-9 | "Who sees what" in ADR 0037 and `docs/security/trust-model.md` must list the hosted bouncer brain | A doc edit. `trust-model.md` has no bouncer-brain row. |
| 0037-30 | Notification Service Extension: a sealed summary on the phone (§7) | Not in any stage. A plan with the push gateway (fits after 2F). |
| 0037-31 | Proof, not promises (§8): reproducible Linux and relay builds, an SBOM and attestations for every artifact, the notarized-app check, the extension package check | A release-tooling plan. Stage 3 covers attestations for Linux packages only. |
| 0037-32 | Headscale works: documentation task (§3) | A doc page. |
| 0037-33 | Archive `wydrox/apassy-relay` (plan 1E) | Owner action. `gh repo view` shows `isArchived: false`. |
| 0037-34 | D8 / unit 0E steps 2 and 6: tell the owners of hosted teams with team content; delete the team files later | Owner confirmation for the message and for the deletion. No record of the inventory or the notice was found in `docs/`. |
| 0039-2 | Push to the watch | A relay or push-gateway change for a watch APNs topic (fits with 2F). |
| 0039-3 | More than one connected vault per watch | A design change of the watch replica vault. |
| S5-1 | Relay feed later version: requests, suggestions, and the actions `grant_request`, `disconnect_agent`, `dismiss_suggestion` ([stage5-plan](stage5-plan.md) D) | A feed version decision. ADR 0033 says keep `grant_request` unused. |
| CA-1 | Public store submission of the Grok Bot plugin ([cloud plan](implementation-plan-0037-cloud-agents.md) decision 3) | The owner's OK after the release. |

### The `physical` points

| ID | Check | Where it is recorded |
| --- | --- | --- |
| G-1 | N1: two real banners within 5 s (`scripts/n1-check.sh`, after Notifications are on) | goal.md N1, open |
| G-2 | B12: two weeks of daily use, owner asked on 10% or fewer of bouncer runs over 7 days | goal.md B12, open |
| 0027-1 | Desktop Copy: Touch ID, the signed helper, clearing on the owner's Mac | ADR 0027 "Validation boundary" |
| 0030-4 | Owner window: real Touch ID counts, screen lock, sleep, user switch, App Nap, Keychain round trips | ADR 0030 "Limits and validation boundary", amendments B–C |
| 0031-1 | Floating question viewport: native focus, monitor position, fallback | ADR 0031, 2026-11-02 section |
| 0032-1 | Connect: approval on cellular and APNs delivery on a real iPhone | ADR 0032 status |
| 0033-2 | iPhone access requests: fresh Face ID each time, no passcode fallback, prompt cancel, races, push | ADR 0033 status; [plan 0033](implementation-plan-0033.md) F |
| 0034-1 | `apassy code`: Touch ID per code, signed clipboard, a real provider that takes the code | ADR 0034 "Validation boundary" |
| 0036-1 | Agent fills: signed guard, real browser, vault, device | ADR 0036 last line |
| 0038-1 | Touch ID panel: Touch ID, non-activation, accessibility, light/dark, Keychain context reuse | ADR 0038 status |
| 0039-1 | Watch: key ACL flags with wrist detection, mirrored notification tap, LTE without the iPhone, Always On | ADR 0039 status; release plan §7 |
| R-1 | Release plan §7 rows not named above: iPhone lock (#90), PRF and large blob on three devices, imported ES384/EdDSA/RS256 passkeys, Credential Exchange import, Find duplicates merge and restore, two-Mac scope bar, F1 synthetic run | [release plan](release-plan-0.5.16.md) §7 (gate G3) |
| CA-2 | Grok Bot end to end: OAuth connect, run, deny on the iPhone, refresh, lock, packet log | [bouncer-section plan](implementation-plan-bouncer-section.md), "End-to-end acceptance" |

## Points by ADR

ADRs 0001 to 0009 are CLOSED (goal.md R1). Their open questions were decided in ADR 0010. Only the
two goal items below stay open.

### goal.md (ADRs 0001–0010)

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| G-1 | N1 | Native notification within 5 s, on the real Mac | Open; the notifier and tests exist (`tests/notifications.rs`) | `physical` |
| G-2 | B12 | Ask rate ≤ 10% after two weeks of daily use | Open; "starts when the real-secret gate opens" (open since 2026-09-27) | `physical` |

### ADR 0007 — Rules and a local bouncer

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0007-1 | Bouncer | The text says a 3 s timeout; the code uses 10 s | Stale doc; fixed by unit J of [plan 0035](implementation-plan-0035.md) | `plan:0035` |

### ADR 0010 — Closing decisions

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0010-1 | Connectors | "A later ADR will define connectors as plugins" (P4a, P4b) | No ADR; goal.md lists it out of scope | `other` |

Touch ID unlock (A3, paused in the fourth round) is built: `src/desktop/unlock.rs`, ADR 0038.

### ADR 0011 — Placeholders and a proxy for each run

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0011-1 | Stage 2 | Linux: a network namespace with a relay to the proxy | Not started; no Linux network rule | `plan:s5-env-0011` |
| 0011-2 | Stage 3 | Named actions for transfers (`vercel env add`, `gh secret set`) | Not started; the proxy refuses a value in a body | `plan:s5-env-0011` |
| 0011-3 | Stage 4 | Go on macOS: a name-constrained Apassy CA in the user trust store, or loopback base URLs for local runs | Not started; base URLs exist only on the way B relay path | `plan:s5-env-0011` |
| 0011-4 | Stage 5 | HTTP/2 and WebSocket in the proxy (also ADR 0016 §8) | Not started; the proxy offers HTTP/1.1 only | `plan:s5-env-0011` |
| 0011-5 | Stage 6 | Hardening of the broker process on Linux (`PR_SET_DUMPABLE=0`) | Not started. macOS hardened runtime is done (`scripts/build-app.sh:610`, `--options runtime`) | `plan:s5-env-0011` |
| 0011-6 | Stage 7 | The proxy on another computer for agents on other machines | First part is the cloud slice (way B on the Mac node, 0.5.16); the linked-environment part is ADR 0037 stage 5 | `plan:s5-env-0011` |
| 0011-7 | Stages 4, 6 | The Windows parts (Go trust store, service account) | No plan; the codebase does not build for Windows | `other` |

### ADR 0012 — Agent visibility and access requests

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0012-1 | "What this does not protect" | "A request does not send a macOS notification yet" | Still true: `OwnerEvent` has `QuestionWaiting`, `CredentialRequested`, `CorrectionProposed` only (`src/desktop/notify.rs:88-96`) | `other` |

### ADR 0014 — Folder sync

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0014-1 | §7 | A shared collection as another sync scope (own file, own key) | Not built; `SyncScope` has one scope | `plan:s4-teams` |

### ADR 0015 — Automatic updates

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0015-1 | Note 2026-10-12 | Switch `latest.json` to `Apassy-<version>.dmg` and end `/download/Apassy.dmg` when no app before 0.5.0 is in use | Waiting: `scripts/build-dmg.sh:340` writes `"file": "Apassy.dmg"`; `docs/operations/release.md` "Image names" | `other` |

### ADR 0016 — Team alpha relay

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0016-1 | D1–D9, T1–T8, stages | The alpha decisions and checks | Status SUPERSEDED (2026-11-03) by ADR 0019, ADR 0022 and ADR 0037 | `superseded` |

### ADR 0018 — Local bouncer and shared vault relay

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0018-1 | Decision | Several vaults active at once; selecting a vault changes the view, not the lock | Not built: `SharedVault` is "the one open vault in this process" (`src/broker/mod.rs:41-42`) | `plan:s4-teams` |
| 0018-2 | Required application checks | Two unlocked vaults serve their agents; a lock of one denies only it; a revoked grant or old policy authorizes nothing; a forged client allowance cannot bypass the host; an outage keeps the local vault | Not built ("Not implemented" in the status) | `plan:s4-teams` |
| 0018-3 | Server | Shared vaults on a relay on the existing VPS | Replaced by ADR 0037 D8 and stage 4 (team host on the owner's node) | `superseded` |
| 0018-4 | Trust and limits | The secret transport is open (value to the member, or stay on the host) | Decided by ADR 0037 D10: way B by default, a way A switch | `superseded` |

### ADR 0019 — Teams and accounts on the relay

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0019-1 | §9 | One host process for all teams of a machine | Not done (status: "a host serves one team") | `plan:s4-teams` |
| 0019-2 | Stage 5 | The Secure Enclave device key in the app, and teams as shared vaults (with ADR 0018) | Not done; the app keeps the P-256 key in a vault table (ADR 0022 decision 2) | `plan:s4-teams` |
| 0019-3 | Status | Notifications beyond the audit (an invite already used, an added owner device reported to the other owners) | Not done (status line) | `plan:s4-teams` |
| 0019-4 | Open decision 1 | Open sign-up instead of operator team codes, and billing | Open; Connect accounts and Stripe | `plan:s7-connect` |
| 0019-5 | Open decision 2 | More key holders for each team | Open | `plan:s4-teams` |
| 0019-6 | Open decision 3 | Sign in with Apple or Google beside device keys | Open; the Connect account of ADR 0037 D3 is the place | `plan:s7-connect` |
| 0019-7 | Open decision 4 | Metadata that the operator cannot read | Replaced by ADR 0037 §1 and §5: the team runs its own host, Connect is blind | `superseded` |
| 0019-8 | §10 | Operator master key and its rotation on the hosted relay | No rotation command in `crates/apassy-relay`; ADR 0037 stage 7 removes the master key from the hosted service | `superseded` |

### ADR 0020 — Wi-Fi iPhone companion

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0020-1 | D1, D2, D4 | Access away from the LAN, push, give access from the phone | Done another way: relay questions (ADR 0025 §3e), push, ADR 0033 Allow once. The companion itself goes by ADR 0028 stage 3 (row 0028-2) | `superseded` |

### ADR 0021 — Browser extension

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0021-1 | D4; ADR 0036 "Delivery and limits" | Cross-origin frames (owner fills and agent fills are top frame only) | Not built; the 2026-10-17 supersession "does not authorize direct cross-origin frame filling" | `other` |

D1 (peer check), D2 (inline menu), D3 (update), D5 (store) and D6 (codes) are done (2026-10-17,
2026-10-31, ADR 0030, ADR 0034). Non-ASCII hosts match since 2026-10-31 (IDNA).

### ADR 0022 — Relay sync

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0022-1 | Stage 2, §4 | Device public keys in a synced vault table, so the relay cannot add a signer | Not done: the chain check uses the relay's `signers` (`src/sync/relay.rs:698-723`) | `plan:s4-teams` |
| 0022-2 | Stage 3 | Teams with several members as shared vaults, several vaults per team, who may push by role | Not done | `plan:s4-teams` |
| 0022-3 | Open question 1 | Open sign-up and billing instead of operator codes | Open; plans.md §4.1 (relay sync without a code) | `plan:s7-connect` |
| 0022-4 | Open question 2 | Move the device key to the Keychain or the Secure Enclave, and migrate `relay_device` rows | Open (with ADR 0019 stage 5) | `plan:s4-teams` |
| 0022-5 | Open question 5 | A softer path for a Mac more than 10000 pushes behind | Open | `plan:s4-teams` |
| 0022-6 | Open question 3 | The Cloudflare body limit for a 64 MiB push on the live relay | Unverified; the release order checks a push of a few MiB only | `other` |
| 0022-7 | "Still open after round 3" | A saved removal mark (`src/sync/state.rs`), `401 device_removed`, long-poll latency after a removal, slow bodies that hold a thread (SPEC 24.10) | Open; the node serves the same relay-sync-v1 code in stage 4 | `plan:s4-teams` |
| 0022-8 | Decision | Default relay address `https://apassy-relay.wyderka.cc` | Replaced by ADR 0037 (node origin; Connect in stage 7) | `superseded` |

### ADR 0023 — The vault on the iPhone

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0023-1 | D2 | Passkeys: the new algorithms, PRF and large blob | Passkeys shipped earlier (schema 17); ES384, EdDSA, RS256, PRF, large blob are on main, unreleased (CHANGELOG Unreleased, schema 25) | `0.5.16-core` |
| 0023-2 | D3 | Synced favorites | iPhone only; no column in `src/vault` | `other` |
| 0023-3 | D4 | The App Store, after TestFlight | Not started | `other` |
| 0023-4 | D5 | Sign-up without an operator team code | Open (Connect path for questions exists, ADR 0032; not for sync) | `plan:s7-connect` |

### ADR 0025 — Low-friction access

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0025-1 | §3e "Teams" | A team question goes to the member the agent acts for; a production allowance needs an owner or a manager | Not built: no team vaults on the hosted relay (D8) | `plan:s4-teams` |
| 0025-2 | §1, §3 (F1) | "A bouncer that asks too often is acceptable", but the owner reports almost every run asks | F1 of the release plan | `0.5.16-core` |

### ADR 0026 — A simple app

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0026-1 | §6 | Shared vaults: one home, many shares, roles, "From you" and "From others" (also [stage5-plan](stage5-plan.md) B, V3) | Not built; moves to the team host on the node (status) | `plan:s4-teams` |
| 0026-2 | §8 | iPhone Settings follow the Mac regrouping of §3 | Not confirmed in the code; the 2026-10-17 UX plan changed the iPhone tabs | `other` |

§3 "There is no auto-lock setting yet" is out of date: `src/desktop/auto_lock.rs` exists.

### ADR 0027 — Desktop Copy

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0027-1 | Validation boundary | Touch ID, the signed helper and clearing on the physical Mac | Synthetic only | `physical` |

### ADR 0028 — Retire the Wi-Fi companion

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0028-1 | Stage 1 | Remove the "<Mac> is unavailable" card from Requests; one quiet line instead | Not done: `ios/ApassyCompanion/Sources/Views/Decisions/DecisionsView.swift:268` | `0.5.16-core` |
| 0028-2 | Stage 3, D3; ADR 0037 D6, plan 2I | Release N: no new Wi-Fi pairing and a notice; N+1: remove the listener, companion-v1, device rows, `ApassyCompanionKit`, the Local Network prompt | After ADR 0037 stage 2 ships the node | `plan:s2-s3` |
| 0028-3 | Decision | "The relay is the only path" | Changed by ADR 0037 D6: the node's LAN and tailnet routes | `superseded` |

### ADR 0029 — Bouncer evaluation permission

Superseded by ADR 0031 for routing. Nothing is open.

### ADR 0030 — How often to ask for Touch ID

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0030-1 | Owner decision A | Hardening against synthetic input: reject events of another process, no AccessKit press on approval buttons | "No such hardening is implemented"; no match in `src/` | `other` |
| 0030-2 | Limits; ADR 0031 | Dark appearance (the egui kit is light only) | Not built | `other` |
| 0030-3 | Amendment 2026-11-01; ADR 0034 | Window reuse for CLI codes needs a verified owner transport | Deferred; CLI codes stay fresh | `other` |
| 0030-4 | Limits | Physical Touch ID, lock, sleep, user switch, App Nap, Keychain | Fixture tests only | `physical` |

### ADR 0031 — The bouncer decides by default

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0031-2 | Decision vs code (F4) | ADR 0031 and the production default in `src/broker/run.rs` (near lines 443–455) disagree | F4 of the release plan, gate G2 | `0.5.16-core` |
| 0031-1 | 2026-11-02 | Floating viewport device QA | Unit tests cover queue selection only | `physical` |

### ADR 0032 — Connect onboarding

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0032-1 | Status | Cellular approval and APNs delivery on a real iPhone | Pending | `physical` |
| 0032-2 | Plans note; ADR 0037 D14 | The free questions-only path ends at stage 7, with a notice two releases before | Not started | `plan:s7-connect` |
| 0032-3 | Durable creation | Questions-only Connect teams on an Apassy-run server | Replaced by ADR 0037 §5: pairing with the Mac node ("Move approvals to this Mac", row 0037-5) | `superseded` |

### ADR 0033 — iPhone access requests

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0033-1 | Review item 2 | Notification policy (budgets, quotas, quiet class, exact-card link) | Default taken (per-Mac budgets, generic push); owner decision open | `other` |
| 0033-2 | Status; plan F | Physical Face ID, Secure Enclave, notifications | Pending since 0.5.10 | `physical` |

### ADR 0034 — One-time codes in the CLI and agent runs

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0034-1 | Validation boundary | Touch ID, signed clipboard, real provider OTP | Synthetic only | `physical` |

The deferred CLI window reuse is row 0030-3.

### ADR 0035 — Bouncer brain hosting and training

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0035-1 | Wave 2 | C (remote host, credential, consent, owner-checked choice, schema), F (shadow in one request), E2 (image workflow, arm64 and x86_64) | Not merged (status 2026-11-03); wave 1 (A, B, D1) and E1 (`ci.yml:188`) are done | `plan:0035` |
| 0035-2 | Wave 3 | G (head upload), J1 (hosting picker), K1 (latency on `devbox-arm` and `devbox-x86`; owner go) | Not started | `plan:0035` |
| 0035-3 | Wave 4 | D2 (owner namespaces, sign-in), H (hosting on `ottervibe`, owner confirms each deploy), I (training jobs) | Not started; needs Connect accounts (stage 7) | `plan:0035` |
| 0035-4 | Wave 5 | J2 (training picker), K2 and K3 (memory per owner, deletion), L (integration, release) | Not started | `plan:0035` |
| 0035-5 | Open question 1 | Final container limits and the price, after K1 | Open | `plan:0035` |
| 0035-6 | Open question 2; §8 | Confirm that the VPS region is in the EU | Open | `plan:0035` |
| 0035-8 | Decision 5; open question 3 | ADR for opt-in, anonymized base-model data | Not written | `other` |
| 0035-9 | Open question 4 | ADR 0037 "Who sees what" and the trust model list the hosted bouncer brain | Missing in both (`docs/security/trust-model.md`) | `other` |

### ADR 0036 — Agent fills through the extension

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0036-1 | Delivery and limits | Signed guard, browser, vault and device acceptance | Synthetic only | `physical` |

Top-frame only: row 0021-1.

### ADR 0037 — Your own relay

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0037-1 | Stage 2 (cloud slice); §3 Public; §6 | Embedded relay, `EdgeMode::Off`, personal team, master key, public route on Funnel 8443, OAuth self-connect, Bouncer section | Merged into `release/0.5.16` (6d81b585, 2543ef3e, 8a7efd32); U1b–U4 of the bouncer-section plan in progress | `0.5.16-core` |
| 0037-2 | Stage 2, 2B; D4 | TLS front on the tailnet addresses with a pinned certificate (Tailscale Serve as an option), extracted from the companion, rebind, peer ranges | Not started | `plan:s2-s3` |
| 0037-3 | Stage 2, 2C | Pinned trust in the Mac and iPhone relay clients, `pin=`/`alt=` link fields, contract `node-pairing-v1` | Not started; no `docs/contracts/node-pairing-v1.md` | `plan:s2-s3` |
| 0037-4 | Stage 2, 2D | Node lifecycle for the iPhone path: lock stops the listener; the window close keeps the node | Partly: `keep_open_for_node` (`src/desktop/node.rs:248`) for cloud agents | `plan:s2-s3` |
| 0037-5 | Stage 2, 2E; Migration | "Get approvals on your iPhone" on the own node; "Move approvals to this Mac"; delete the hosted membership | Not started | `plan:s2-s3` |
| 0037-6 | Stage 2, 2F; §7; D7 | Push gateway `apassy-push` with per-device push handles; Worker to `deploy/relay-edge`; abuse limits (open check 6) | Not started; `deploy/worker` holds the push route | `plan:s2-s3` |
| 0037-7 | Stage 2, 2G | iPhone accepts node links, "via Tailscale", one quiet Tailscale-off state; check Local Network permission for 100.x (open check 2) | Not started | `plan:s2-s3` |
| 0037-8 | Stage 2, 2H; §4 | Settings → Devices: Tailscale status, Add a device QR with routes and pin, device list with role, route, last contact, Revoke; mockup first | Not started | `plan:s2-s3` |
| 0037-9 | §3 | Tailnet WhoIs check as defense in depth; the LAN route on the same relay API (D6) | Not started | `plan:s2-s3` |
| 0037-10 | Stage 2, 2J; Risks | Security review of the front, `EdgeMode::Off`, pairing, push handles; HTTP parser fuzzing | Not started (the cloud slice has its own review) | `plan:s2-s3` |
| 0037-11 | Stage 2 acceptance | An iPhone on cellular with Tailscale approves a run; no request to the hosted relay; revoke; lock stops the listener | Not started (owner, physical, at the end of stage 2) | `plan:s2-s3` |
| 0037-12 | Stage 3, 3A–3B; §4 | Headless `apassy` (`node` feature) with `serve`, `up`, `pair`, `status`, `doctor`, `team …`; `up` checks `tailscale status` | Not started | `plan:s2-s3` |
| 0037-13 | Stage 3, 3C–3D; §2 | Linux unlock (open check 4), master key in systemd credentials or a 0600 file, systemd user service with linger | Not started | `plan:s2-s3` |
| 0037-14 | Stage 3, 3E–3F; Process changes | `.tar.gz` and `.deb` with checksums and attestations; `apassy-team` as an alias for one release; `linux-cli` becomes the node | Not started | `plan:s2-s3` |
| 0037-15 | Stage 4; D5 | Node-to-node sync with a sync home that the user can change; acceptance: two Macs and a Linux home converge | Not started | `plan:s4-teams` |
| 0037-16 | Stage 4; §9 | Team host on a node, shared across tailnets (manual share first; later `POST /api/v2/device/{id}/device-invites`); acceptance with Konrad's agent | Not started | `plan:s4-teams` |
| 0037-17 | Stage 4; D9 | Embedded tsnet spike (Go runtime in a notarized app, open check 5), then the node; until then a dedicated host and a port grant | Not started | `plan:s4-teams` |
| 0037-18 | Stage 4; §10; D10 | The way A switch: two answers, confirmation, badges, member removal with "Replace now", audit of value deliveries | Not started | `plan:s4-teams` |
| 0037-19 | §9 "Encryption in way B" | The proxy stores no bodies; the audit keeps host, method, status, sizes (check what the relay logs) | Not started | `plan:s4-teams` |
| 0037-20 | Migration | Signed export of a hosted team file to its key holder, import on the node; relay-sync users choose a sync home; later the iPhone syncs from a node (§5) | Not started | `plan:s4-teams` |
| 0037-21 | Stage 5; §6; §3 SSH | `apassy environment link`, thin executor, SSH route, remote MCP on the home node; acceptance on `devbox-arm` | Not started | `plan:s5-env-0011` |
| 0037-22 | §6; stage 8 | A full Linux node that runs agents waits for Linux isolation (Landlock or bubblewrap) | Not started | `plan:s5-env-0011` |
| 0037-23 | Stage 6; D11 | Way C: AWS STS, GitHub Apps, Google Cloud, OAuth refresh, Cloudflare, temporary DB roles; automatic in both modes | Not started | `plan:s6-sharing` |
| 0037-24 | Stage 6; §10 step 2 | Remote SigV4 signing | Not started | `plan:s6-sharing` |
| 0037-25 | Stage 6; §10 step 3 | A key per member through a provider key-management API | Not started | `plan:s6-sharing` |
| 0037-26 | Stage 6 acceptance | A member's agent uses AWS with STS credentials that expire within 15 minutes | Not started | `plan:s6-sharing` |
| 0037-27 | Stage 7; §3 Connect; D2 | Byte relay with end-to-end TLS (outbound tunnel from the node); acceptance: a Mac without Tailscale reaches its iPhone and a cloud agent | Not started | `plan:s7-connect` |
| 0037-28 | Stage 7; D3 | Blind sync store, accounts, Stripe | Not started | `plan:s7-connect` |
| 0037-29 | Stage 7; D8; process changes | Remove way B, team files and the master key from the hosted service; `docs/operations/relay.md` describes Connect | Not started | `plan:s7-connect` |
| 0037-35 | Stage 8 | Embedded tailnet on the iPhone (no Tailscale app; also the work-VPN risk) | Not started; separate ADR | `plan:s8` |
| 0037-36 | Stage 8 | Linux window from the egui UI | Not started; separate ADR | `plan:s8` |
| 0037-37 | §11; D12 | Confidential team host | Enterprise track | `tee-deferred` |
| 0037-38 | E1; §10 step 4 | Confidential relay image, attestation checks, measurement log | Enterprise track | `tee-deferred` |
| 0037-39 | E2; D12 | Hosted way B for static keys | Enterprise track | `tee-deferred` |
| 0037-40 | E3; D13; §10 step 5 | Split TLS prototype and cryptography review | Enterprise track | `tee-deferred` |
| 0037-41 | E4; §11 limits | Item keys sealed in the VM | Enterprise track; its own ADR | `tee-deferred` |
| 0037-30 | §7 | Notification Service Extension with a sealed summary | No stage | `other` |
| 0037-31 | §8 | Reproducible builds, SBOM, attestations, the notarized-app and extension checks | No stage except Linux attestations in 3E | `other` |
| 0037-32 | §3 | Headscale documentation | No page | `other` |
| 0037-33 | Plan 1E | Archive `wydrox/apassy-relay` | `isArchived: false` | `other` |
| 0037-34 | D8; plan 0E steps 2, 6 | Notice to owners of hosted teams with team content; later deletion of team files | No record found | `other` |

Stage 0 is done (`docs/security/trust-model.md`, `docs/security/relay-history-scan-2026-11-02.md`, PR
#66). Stage 1 is done except row 0037-33.

### ADR 0038 — Touch ID panel

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0038-1 | Status | Runtime review on the Mac | Pending; 0.5.15 fixed the unlock dialog | `physical` |

### ADR 0039 — Apple Watch

| ID | Section | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| 0039-4 | Status | Ships with the next release of all six components | Merged (#81, #82), unreleased; TestFlight internal build 29895036 only | `0.5.16-core` |
| 0039-1 | Status | Physical watch acceptance | Pending | `physical` |
| 0039-2 | §7 | Push to the watch (no watch token in v1) | Needs a relay or gateway change | `other` |
| 0039-3 | §4 | One connected vault per watch in v1 | By design in v1 | `other` |

### Plans and release documents

| ID | Source | Point | State and evidence | Category |
| --- | --- | --- | --- | --- |
| R-2 | Release plan §2 (F2, F3, F5, F6) | CPU repaint, stale feed of another Mac, flaky extension tests, the `ssh-keygen` test | F5 and F6 done on `release/0.5.16` (0f0f53d1, a5069831); F2 and F3 open | `0.5.16-core` |
| R-3 | AGENTS.md; release plan §1 | All six components live at 0.5.16 (0.5.15 went out only partly) | Open | `0.5.16-core` |
| R-4 | Release plan G6 | Rotate the Claude Code agent token after the release | Open | `0.5.16-core` |
| R-5 | plans.md §7 | The relay guide (`/guide`) goes live with the next Worker deploy | Waiting for O1 of the release plan | `0.5.16-core` |
| R-1 | Release plan §7 | The physical session (gate G3), rows not named elsewhere | Open | `physical` |
| P-1 | plans.md §4.1; decision 3 | Relay sync without a code: a sync size for Connect teams, "New relay copy" without a team code, the text; measure vault sizes and the VPS disk | To build | `plan:s7-connect` |
| P-2 | plans.md §3 | Stripe: rename to Connect Personal and Connect Team, add Connect Family (EUR 3, 5 + 1 per extra person, 4 per member; a year is 10 months); Stripe Tax; web checkout on the Mac | Prices decided 2026-11-03 (0edf1f90); Stripe changes need the owner's confirmation before stage 7 | `plan:s7-connect` |
| P-3 | plans.md §4; D14 | Notices two releases before free relay sync and the free questions-only path end | Not started | `plan:s7-connect` |
| P-4 | plans.md §3 | "Later, enterprise track: the confidential team host" | Enterprise track | `tee-deferred` |
| S5-1 | stage5-plan D | Feed later version: requests, suggestions, more actions | Not planned | `other` |
| CA-1 | Cloud plan decision 3 | Public Grok Bot plugin submission | After the release and the owner's OK | `other` |
| CA-2 | Bouncer-section plan | Grok Bot end-to-end acceptance | Open | `physical` |
| CA-3 | Cloud plan §5 | A switch for each remote agent: "allow known safe, non-production commands" (today every cloud run asks) | Later, with usage data | `plan:s5-env-0011` |
| CA-4 | Cloud plan risks; ADR 0037 risks | A power assertion while a remote session or a linked environment waits | Later unit | `plan:s5-env-0011` |
| CA-5 | ADR 0037 §3; Risks | Recommend an always-on Linux node for teams (docs and setup) | Not written | `plan:s4-teams` |

## Mentioned as possible, not committed

These are "can come later" remarks, not decisions. They are not counted above.

- ADR 0014: a finer merge than one credential (child tables as records).
- ADR 0023 D1: file providers other than iCloud Drive on the iPhone.
- ADR 0030 decision C: fewer heartbeat wakeups (the strict 250 ms cadence is intentional).
- goal.md "Out of scope": a plain-language rule interpreter, hosted models (now ADR 0035), sharing
  of patterns and rule packs, other operating systems, distribution and the five-day pilot (P7).
- ADR 0010 limit: if macOS removes `sandbox-exec`, isolation needs a new ADR.
