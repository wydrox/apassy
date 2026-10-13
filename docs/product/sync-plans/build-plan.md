# Build plan

Written by the architect on 2026-10-13. The phases, the contracts to write before coding, the streams with disjoint files, the security invariants, and the risks.

## 1. Phases (each shippable)

| Phase | Needs | Delivers |
|---|---|---|
| **P1 Unify (now)** | nothing | M1 hub, M2 one sheet, M3 segmented + L3 relay sheet, I1/I2/I3 one door, hints fixed, first-steps third step (`first_steps.rs:14/39/74`). For a Free vault with no team, M2 shows "Pair on this network" as the only path (honest, works on Wi-Fi today). Operator vaults work as before |
| **P2 Connect for all** | (a) relay codeless team + schema 5 deploy (push, APNs) | M2 works off Wi-Fi for Free; second Mac on Free joins the questions team by link (`join_questions_team` `membership.rs:298`) |
| **P3 Plan + checkout** | (b) accounts, entitlement, Stripe | M4, M5, C, E; Sync through Apassy gated; `Plan::Operator` grandfathered |
| **P4 Shared vaults** | (c) V3 | D |

## 2. Contracts before coding (`docs/contracts/relay-connect-v1.md`, ADR 0027)

**(a) Codeless Connect team.** New edge endpoint `POST /v1/connect` (keep `POST /v1/teams` + `apassy_tcd_` for operators; `Hub::create_team` `relay src/server/hub.rs:417` untouched). Body `{v:1, team, device_name, public_key}`; answer `TeamCreated` (`api.rs:221`) + `kind:"connect"`. Only the Mac calls it (the Mac decides the plan; the iPhone never creates a team), so App Attest is not needed in v1. Record: `team.kind ∈ {operator, connect}` (`relay.db`, DIRECTORY_VERSION 1003) and `connect_key(key_hash, team_id)`. Limits: Worker `CONNECT_LIMITER` 3/h and 20/day per `cf-connecting-ip` (bindings fail open, so also relay-side): one connect team per public key ever; `connect_teams_per_day` relay-wide cap (config, default 200 → `503 busy`); `TeamLimits` preset `connect`: members 1, devices 10/member (exists, `joins.rs:25`), `sync_bytes` 0 (`PUT /v1/sync/snapshot` → `403 plan_required`), `question_bytes` 2 MiB; idle connect teams (one device, 30 days) suspended then deleted (OPERATIONS job). ADR 0019 fit: an ordinary team (one file, member `owner`, device keys, confirmed joins) without §10's code; closes 0019 open decision 1, 0022 OQ1, 0023 D5.

**(b) One vault, one device list.** Today `relay_membership` (`src/vault/schema19.rs:45`) holds purposes per team; a questions-only team plus a later sync team would be two teams (`set_membership_purposes` forbids two sync teams but not sync + questions). Decision: the Connect team is the only team of a vault; upgrading adds purpose `sync` to the existing membership: new `RelaySync::enable_on_membership(team_id)` in `src/sync/relay.rs` reusing `finish_enable_with` (`:2236`) with the existing key, never `create_team_in` (`:2088`). Relay: `POST /v1/teams/entitlement` lifts the team's preset. Other devices keep their rows (`trusted_device.relay_devices` already maps per team) and gain `sync` when they see version > 0; the iPhone core gets `sync_switch_to_relay` on the existing membership. Downgrade: drop `sync` per device; relay deletes the snapshot after 30 days. Grandfathered operator vaults keep their two teams; the hub lists by `trusted_device.uuid`, so the list is already one. Wi-Fi-paired iPhones (`companion_device`) stay separate identities, shown in the same list.

**(c) Entitlement seam** (`src/plan/mod.rs`, feature `vault`). Types: `Plan { Free, Personal, Team, Operator }`; `Entitlement { plan, email, renews_at, status: Active|PastDue|Ended, checked_at }`; trait `PlanProvider { current(), refresh(), offer(from) -> prices, checkout_url(from), portal_url(), sign_out() }`. `FakePlanProvider` driven by `APASSY_PLAN=free|personal|team|operator|ended` (used by `scripts/screenshots.sh`). Real: `apassy_ent_` compact token (ES256, claims sub, email, plan, iat, exp 30 d) from an accounts Worker (Stripe Checkout + webhooks + D1), cached per Mac in the data folder, grace 14 days past `checked_at` (M5 copy). The relay verifies it with the accounts public key on `POST /v1/teams/entitlement` and re-checks `exp` on push. The token holds no device claim and never signs in. `Plan::Operator` = a sync membership whose relay team has `kind=operator` (add `team_kind` to the sign-in answer). iPhone: the Mac writes `vault_secret 'plan-v1'` (plan name, renews_at; no token, no email) → `PlanSummary` in `ios/ApassyVaultKit`.

**(d) QR/link payload.** The iPhone has no URL scheme (nothing in `project.yml`); the QR and the pasted text are the same string. Keep the current body for compatibility and extend the fragment: `https://<relay>/link#apassy_lnk_<team>_<64hex>&r=sync|connect&n=<Mac name>&e=<expires>&p=<b64u of apassy://pair…>`. Parsers (`PendingJoin::parse_link` `src/sync/relay.rs:2438`, `VaultText.joinLink`) take the code before the first `&`; missing `r` = `sync`. `r=sync` → `join_finish` (paid, downloads the copy); `r=connect` → `join_attach` (Free) then the iCloud card; `p` lets the same QR fall back to "Pair on this network" when the relay is unreachable (the Mac opens `PairingController::open` `src/companion/control.rs:184` alongside; windows 300 s vs 600 s, align). The Mac sets `r` from `PlanProvider::current()`. A second Mac pasting `r=connect` runs `join_questions_team`.

## 3. Streams (disjoint files)

**F0 foundation** (one implementer, first): `src/desktop/ui/ui.rs:385` `Sheet::{Devices(..), Upgrade(..), PlanEnded}`, `shell.rs:326` dispatch arms, `settings_view.rs` `Plan` variant, `src/plan/` trait + fake, `src/sync/relay_link.rs` payload build/parse (shared by S1, S3 via `apassy-core`), stub signatures `enable_on_membership`, `create_connect_team`. Contracts (S5) land before F0.

| Stream | Files | Depends | Gates |
|---|---|---|---|
| **S1** Devices hub + Add a device | new `src/desktop/ui/devices.rs`; `settings.rs` (devices_section), `sync/relay.rs`, `sync/questions.rs`, `companion.rs`, `first_steps.rs`, `settings_tests.rs`, `companion_tests.rs`; `src/relay/membership.rs`, `src/sync/relay.rs` (connect team, enable_on_membership) | F0 | `cargo test --features desktop,vault` (incl. `tests/trusted_devices.rs`, `relay_sync.rs`, `relay_questions.rs` unchanged); `scripts/screenshots.sh` M1/M2 next to `docs/design/app-v2-mockup.html` |
| **S2** Sync picker + Plan + Upgrade | `src/desktop/ui/sync.rs`, new `plan.rs`, `sidebar.rs`, `sync_tests.rs` | F0 | `cargo test`; screenshots M3–M5 under `APASSY_PLAN=free` and `personal` |
| **S3** iPhone | `iOS/Views/Vault/{AppWelcomeView,JoinFlowView,ICloudVaultFlowView}.swift`, new `Views/Connect/`, `Vault/ConnectModel.swift`, `Models/{RootModel,PairingModel,QuestionsModel}.swift`, `Views/Main/QuestionsView.swift`, `Views/Settings/DevicesSettingsView.swift`, `Views/Pairing/*` (texts), `ios/ApassyVaultKit` `PlanSummary`, `ios/ApassyCore` join route | F0 (payload) | `swift test` in `ios/ApassyVaultKit` and `ios/ApassyCompanionKit`; Simulator build + screenshots I1–I3 against `docs/design/ios-v1-mockup.html` |
| **S4** relay codeless (code only) | `~/Dev/apassy-relay-sync` branch `feat/connect`: `src/api.rs`, `src/server/{http,hub,directory,sync}.rs`, `src/config.rs`, `deploy/worker/src/index.ts` + `wrangler.jsonc`, `docs/SPEC.md` §26, `OPERATIONS.md` §20, `tests/server_connect.rs` | contract (a) | relay `cargo test`; Worker `vitest`; no deploy |
| **S5** docs | `docs/adr/0027-plans-and-connect.md`, `docs/contracts/relay-connect-v1.md`, amendments to `relay-sync-v1.md` §6 and `relay-questions-v1.md` §12.6, `docs/product/sync-plans/component-map.md` | — | contract vectors in `tests/contracts.rs` |
| **S6** site pricing | site repo (workflow `site.yml`) | prices | later |

Adversarial security judge (2× opus + 1× fable) on: S1 confirm path (words + owner check + `register_linked_device`, approvals-on default, the `p` fallback), S4 (team enumeration, key reuse, IP hashing, idle deletion, fail-open limiters), S2/relay entitlement checks (signature, `exp`, no device claim, token at rest outside the vault, portal links short-lived).

## 4. Security invariants

- A device that can approve is added only after safety words on both sides and an owner check on an existing device (`OwnerAction::ConfirmSyncDevice`, ADR 0022 d6, ADR 0025 §3e); the iPhone's answer key rides in the confirmed `device_name` (`src/questions/device_link.rs`).
- The relay sees routing only: sealed cards and answers, ciphertext snapshots; `to` bit and sizes are the accepted leak (relay-questions-v1 §18).
- An account sign-in or entitlement token never adds a device, never signs in, never opens a vault; sign-in stays device-key challenge only.
- A stolen entitlement token yields at most a raised limit on a team the thief cannot enter.
- Downgrade never removes approvals or the vault (spec §7).

## 5. Risks and open questions

1. **Resolved 2026-10-13 (owner): the iCloud file pick is required for Connect on Free.** Was: spec vs contract conflict: relay questions are sealed with `question-key-v1`, held only by devices that hold the vault (relay-questions-v1 §5.1, §7.3 step 5). A Free iPhone that answers "Not now" to the iCloud card cannot read any question off Wi-Fi. Either make the iCloud file pick required for Connect on Free (recommended; honest copy), or wrap the question key and roster to the iPhone at confirmation (`device_wrapped_key`, heavy, V3-shaped). Owner decision needed.
2. Prices, Stripe account, and who builds the accounts Worker (D1, webhooks, receipt email) — block P3.
3. Schema 5 deploy prerequisites (A4 APNs spike, `.p8`, `PUSH_SECRET`, OPERATIONS §19.2) block P2's peak; without push the iPhone sees questions only in the foreground.
4. App Store review: I3 shows the plan without purchase or link (guideline 3.1.3(b) allows this if no price and no external link); keep PRICE off the iPhone.
5. Test question needs a card flag (contract bump to v2 on three sides); ship P2 without it if needed.
6. Connect teams for Free cost VPS disk/metadata (no snapshots, 2 MiB budget); the fail-open Worker limiters make the relay-side caps mandatory.
7. iOS picker start folder for iCloud Drive > Apassy is unverified; the URL-opening helper on the Mac is unverified.
8. Grandfathering needs `team_kind` in the sign-in answer (relay change) or a local migration flag.

Key files: `/Users/rafalw/Dev/apassy-integration/docs/product/sync-plans/flow-spec.md`, `/Users/rafalw/Dev/apassy-integration/src/relay/membership.rs`, `/Users/rafalw/Dev/apassy-integration/src/desktop/ui/sync/relay.rs`, `/Users/rafalw/Dev/apassy-integration/src/desktop/ui/settings.rs`, `/Users/rafalw/Dev/apassy-integration/ios/ApassyCompanion/Sources/Models/RootModel.swift`, `/Users/rafalw/Dev/apassy-relay-sync/src/server/hub.rs`.
