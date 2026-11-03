# Implementation plan — the open points of category `other` (ADRs 0010 to 0039)

Date: 2026-11-03. Status: PLAN, written on the owner's decision of 2026-11-03 ("build everything in the
ADRs except the TEE track, as fast as possible, with many parallel agents; no approval of intermediate
steps").
Source: [adr-coverage.md](adr-coverage.md), category `other` (24 points). Where an ADR leaves a choice
open, this plan takes the recommended option and marks it **chosen by this plan; the owner can change
it**. Steps that only the owner can do are in [Owner list](#owner-list), with everything prepared.
New ADR drafts: [ADR 0042](../adr/0042-verified-owner-transport-for-cli-codes.md) (CLI codes),
[ADR 0043](../adr/0043-shared-base-model-from-owner-data.md) (shared base model),
[ADR 0044](../adr/0044-connector-plugins.md) (connector plugins). ADRs 0040 and 0041 belong to the
stage 8 plan.
Siblings that run now: [Bouncer section](implementation-plan-bouncer-section.md) (U1b, U2b, U2c, U3a,
U3b-1, U3b-2; release 0.5.17), [stages 2 and 3](implementation-plan-s2-s3.md) (N0–N8, L1–L4, W1–W2;
release R1), [stage 4](implementation-plan-s4-teams.md), [stage 6](implementation-plan-s6-sharing.md),
[stage 5](implementation-plan-s5-env-0011.md), [stage 7](implementation-plan-s7-connect.md),
[stage 8](implementation-plan-s8.md), [plan 0035](implementation-plan-0035.md) (refresh). Format:
[plan 0035](implementation-plan-0035.md).
Base inspected: `origin/release/0.5.16` at `4034c957` (vault schema 26, `src/vault/types.rs:22`);
rebased on `50685a63`, where U1b, U2c, U3a, and U3b-1 of the Bouncer section are merged and U2b,
U3b-2, and U4 are not.

## Outcome and constraints

After this plan, every `other` point of the coverage map has shipped code, a merged document, or a
named owner step:

- The Mac notifies the owner of an access request. The notification policy of ADR 0033 is decided.
- The extension fills a login in a frame of another origin of the same site, after the owner check
  names both origins. Agent fills stay in the top frame.
- Favorites sync through the vault (schema 35) on every Mac and iPhone.
- The iPhone app has everything for the App Store; the owner submits it.
- iPhone Settings follow the Mac grouping.
- A synthetic or accessibility press never uses the Touch ID window. CLI codes can use the window with
  a verified hardware click (ADR 0042). The egui kit has a dark appearance.
- Every release artifact has a build attestation and an SBOM; the Linux binaries and the relay build
  reproducibly; a script checks the notarized app and the store extension against the attested build.
- The old relay repository is archived after its health check runs here.
- Hosted teams with team content are counted, their owners told where a team is not the owner's own,
  and the deletion prepared.
- The watch answers for up to four vaults. The relay feed v3 carries requests and suggestions.
- A shared base model can learn from opt-in, skeletonized, owner-reviewed decisions (ADR 0043).
- Connectors come back as declarative plugins, with GitHub read-only first (ADR 0044), last.

Rules that hold for every unit:

- **One release of all six components at one version** (AGENTS.md). This plan never adds scope to
  0.5.16 or 0.5.17; its code units join the first coordinated release after their dependencies merge.
- **No secret value in any new payload, log, notification, feed field, or record.** Synthetic
  credentials are searched for in every payload that a unit adds.
- **Mac resources:** at most three implementation or validation agents on this Mac across all
  sessions; a judge panel of three counts as three. Subagents never run lint, typechecks, builds,
  `cargo test`, `cargo nextest`, or full suites, also not through `heavy-check`; they return the exact
  commands. The top-level agent validates one revision at a time through CI, or locally only through
  `~/.local/bin/heavy-check`.
- **Docker only on `devbox-arm` / `devbox-x86`** with the architecture named; never on the Mac, never
  on `ottervibe`. Images are built on GitHub.
- **Browser work only in Helium on CDP port 9223**; never port 9222, never Playwright outside the
  existing `extension-tests` suite that CI runs.

## Numbers and names reserved by this plan

| Kind | Value | Note |
| --- | --- | --- |
| Vault schema | **35** | Tables `item_favorite` (synced), `connector_plugin` (local), `contribution_batch` (local). The chain has no gaps: 27 (Bouncer U3a), 28 (s2-s3 N3), 29 (plan 0035), 30 and 33 (s4), 31 (s5), 32 (s6), 34 (s7) land first. If a lower number stays unused at merge time, the top-level agent renumbers `schema35.rs` in one place. Chosen by this plan; the owner can change it. |
| Relay feed | **v3** | After v2 of the Bouncer section (U3a). Readers accept 1, 2, 3. |
| Notifier event | `access_requested` | `native/ApassyNotify/Notify.swift`, `src/native/mod.rs` |
| Window source | `LocalWindowSource::CliConfirm` | ADR 0042 |
| Contracts | `connector-plugin-v1` (new); sections in `browser-v1`, `relay-feed-v1`, `ios-core-v1`, `owner-cli-v1` | |
| Crate | `crates/apassy-input-guard` | The only new crate with `unsafe` (section D6) |
| Mockup | `docs/design/misc-mockup.html` | Unit M0 |
| ADRs | 0042, 0043, 0044 | |

## Facts from the code (2026-11-03)

| Area | Fact | Where |
| --- | --- | --- |
| Mac notifications | `OwnerEvent` has `QuestionWaiting`, `CredentialRequested`, `CorrectionProposed`. The watcher announces new credential requests and corrections (`announce_owner_items`); it never reads `access_request`. | `src/desktop/notify.rs:88-118, 717-760, 765-860` |
| Access requests | `Vault::request_access` (one open per agent and item, 20 open per agent), `access_requests(open_only, limit)`. Decisions already has `Key::Access(id)`. | `src/vault/access.rs:289-394`, `src/desktop/ui/decisions.rs:233, 955-967` |
| Notifier | Fixed templates; events `update_ready`, `approval_waiting`, `suggestion`, `request_blocked`, `sync_stuck`; `waiting_key` only for approval and suggestion. | `native/ApassyNotify/Notify.swift:51-53, 91-105, 315-336`; `src/native/mod.rs:395-420` |
| iPhone push | Fixed "A question is waiting", time-sensitive, one collapse id, no ids. Per-Mac budgets: 5 per agent per hour, 20 per vault per hour, 30 s cooldown. | `docs/adr/0033-iphone-access-requests.md:134-153` |
| Frames | Inline login fields: `handleLoginField` refuses unless `originOf(sender.tab.url) === sender.origin` (`unsupported_frame`, "Open this sign-in page in its own tab"). Toolbar actions, passkeys, codes: frame 0. Agent fills bind frame 0 and the documentId. | `extension/login-worker.js:184-192`, `extension/background.js:43-51, 476, 623`, `docs/contracts/browser-v1.md:191, 251` |
| Favorites | iPhone only, `UserDefaults` key `favorites.<vaultID>` (list of item ids). No favorites in `src/vault`. | `ios/ApassyCompanion/Sources/Vault/VaultSettings.swift:66, 95-116`, `VaultModel.swift:716-731` |
| Merge | Child tables of an item bump its version clock; two diverged clocks make an archived conflict copy. Folders, trusted devices: per-row last writer wins (`merge_lww`). | `src/vault/merge.rs:1-40, 56-122, 1492-1532` |
| iPhone Settings | Pages `general`, `agents`, `devices`, `security`, `advanced`. Sync rows are in Devices. | `ios/ApassyCompanion/Sources/Views/Vault/SettingsView.swift:10-16, 32-88`; `ios/README.md` Settings row |
| Mac Settings | Sections Vault, Security, Devices, Bouncer, Tools, Updates. | `src/desktop/ui/settings.rs:51-64`; ADR 0026 §3 |
| egui input | `Response::clicked()` is true for a pointer click, Space or Enter on a focused widget, and an AccessKit `Click` request (`FAKE_PRIMARY_CLICKED`). | egui 0.36.2 `response.rs:184`, `context.rs:1470-1481` |
| Window sources | `LocalWindowSource::{LocalOwner, DevelopmentClick, AllowOnceClick, BrowserGesture}`; `allow_once_clicked` and `development_clicked` start the local owner check with reuse. | `src/desktop/owner_check.rs:1813-1830`, `src/desktop/browser.rs:1025, 1782` |
| Unsafe | `apassy` and `apassy-app` forbid `unsafe_code`. Only `ios/ApassyCore` has an FFI crate. | `src/lib.rs:3`, `crates/apassy-app/Cargo.toml` `[lints.rust]`, ADR 0023 §2 |
| Colors | 56 `Color32::from_rgb` in `kit.rs` (light constants `WINDOW` … `ACCENT_TEXT`), about 60 more in 12 other UI files. | `src/desktop/ui/kit.rs:25-95`; `ui.rs`, `decisions.rs`, `detail_rows.rs`, `vaults.rs`, `items.rs`, … |
| CLI codes | `OwnerAction::CliCode`, always fresh (ADR 0030 amendment 2026-11-01). | `src/broker/approvals/owner_window.rs:563-593`, `src/desktop/owner_cli.rs:383, 755` |
| Watch | One replica per watch; a second connect gives `already_connected`. One answer key per questions team. | `docs/contracts/ios-core-v1.md` §5.13; ADR 0039 §4 |
| Feed | v1 reserves requests, suggestions, `grant_request`, `disconnect_agent`, `dismiss_suggestion`. ADR 0033: keep `grant_request` unused. v2 is the Bouncer section's. | `docs/contracts/relay-feed-v1.md:24`, `docs/adr/0033-iphone-access-requests.md:142` |
| Updater names | `latest.json` writes `"file": "Apassy.dmg"`; the Worker serves `/download/Apassy.dmg`. Every app since 0.3.0 sends `User-Agent: Apassy/<version>` (checked in tags `v0.3.0`, `v0.4.1`). | `scripts/build-dmg.sh:330-345`, `site/worker/index.ts:6-12, 51-65`, `src/desktop/update/system.rs:224-225` |
| Workflows | `ci.yml`, `relay-image.yml` (image, `linux-cli`, `darwin-cli`; checksums and JSON records, no attestation), `release.yml` (DMG, `latest.json`; no attestation), `site.yml`. The repository is public, so attestations are free. | `.github/workflows/*` |
| Extension zip | Built locally, deterministic (fixed time, sorted list); reads the version with `plutil`. | `scripts/build-extension-zip.sh` |
| Relay image | Base images by tag, not digest; the runtime stage runs `apt-get install ca-certificates` and `useradd`. | `crates/apassy-relay/Dockerfile` |
| Old relay repo | `wydrox/apassy-relay`: private, not archived. Workflows CI, Image, and **Relay health** (cron `17 * * * *`; `curl` of `/healthz` = `ok` and `/v1/me` = 401; no secret; last runs green on 2026-11-03). | `gh api repos/wydrox/apassy-relay/...` (read-only) |
| Hosted teams | `admin teams` shows counts per team (members, items, agents, sync, questions), no names of people or items; `admin delete` works only on a suspended team, no undo. The trust model says the only team vault is the owner's `apassy-alpha`, suspended. | `crates/apassy-relay/docs/OPERATIONS.md:796-896`; `docs/security/trust-model.md:59-67` |
| Trust docs | Neither the trust model nor ADR 0037 "Who sees what" lists the hosted bouncer brain. | `docs/security/trust-model.md:13-27`; `docs/adr/0037-own-relay-open-source.md:368-378` |
| Connectors | `apassy_use_credential` runs a named operation of a compiled profile; only `reporting-api-v0` (synthetic). | `src/agent/mcp.rs:20, 332-345`, `src/broker/profile.rs` |
| iPhone store | `ITSAppUsesNonExemptEncryption = false` (owner, TestFlight); purpose strings for Local Network, Camera, Face ID. No price or purchase text in the iOS sources. The privacy page has no iPhone vault or watch section, and says "The iPhone companion talks to your Mac on your local network only". | `ios/ApassyCompanion/project.yml:103-118, 166, 219`; `site/src/pages/privacy.astro` (updated 2026-10-17) |

## Decisions

### D1. Access-request notifications on the Mac (0012-1) and the notification policy (0033-1)

- New notifier event `access_requested`. Title "Access request", body "Agent “<name>” asks for access
  to a credential. Open Apassy to review." No item, reason, or project (goal item N2). Sound on,
  interruption level as `approval_waiting`.
- One notification per new open request (`access_request` with `state = 'open'`), with the same
  marks as credential requests: the first look at a vault file announces nothing. A duplicate request
  returns the first id, so it sends nothing. A decided, expired, or cancelled request removes its
  notification.
- At most one access-request notification per agent per 30 s (the ADR 0033 cooldown). A request in
  that time waits in Decisions without a banner (N3: a missed notification changes nothing).
- A click opens Decisions with `Key::Access(id)` selected, after the vault-path and session-epoch
  check of the other events.
- **Policy (0033-1): keep the per-Mac budgets and the generic iPhone push.** No quiet class, no
  exact-card push link, no distributed quota. Privacy-safe counts per day (tracing, counts only).
  Chosen by this plan; the owner can change it.

### D2. Fill a login in a frame of another origin (0021-1)

Owner fills only. Agent fills (ADR 0036), passkeys, one-time codes, and post-submit save offers stay in
the top frame. Rules:

1. **Same site only.** Every ancestor origin of the frame and the top origin have the same registrable
   domain as the frame, by the pinned `psl` list of the app (`login.example.com` in
   `shop.example.com`: yes; `accounts.google.com` in `shop.example`: no). Cross-site frames keep the
   "Open this sign-in page in its own tab" recovery. Chosen by this plan; the owner can change it.
2. **The login matches the frame.** The saved website must match the frame origin by `site.rs`, as
   for a top frame. The top origin is not a match source.
3. **Ancestors from the browser.** The frame's content script sends `location.ancestorOrigins`; the
   worker checks that the last entry equals the origin of `sender.tab.url`. An entry `null`, an opaque
   origin (sandboxed frame), a non-HTTPS origin other than `http://localhost`, or a length that does not
   fit refuses the fill.
4. **Site access for the frame.** The extension must hold host permission for the frame origin (the
   owner's "Suggest logins on all sites", or that site). The owner grants it; an agent cannot.
5. **Exact target.** The target binds tab, `frameId`, `documentId`, form token, frame origin, and top
   origin before the owner check; delivery uses `documentIds: [frame document]` and rechecks
   `location.origin` inside the frame. Any navigation of the frame or the top refuses delivery
   (`page_changed`).
6. **The owner check names both origins.** "Fill the login “Example” (rafal) on
   https://login.example.com inside https://shop.example.com in your browser". The proof binds
   `OwnerAction::FillLogin { item_id, login, origin, embedded_in: Some(top origin) }`. The ADR 0030
   window applies as for any fill.
7. **Contract.** `browser-v1` `suggestions` and `fill` accept an optional `embedded: { "frame_url",
   "ancestors": [origins] }`. The app answers `origin` = frame origin and `embedded_in`. The host's
   `hello` reports the capability `frame_fill_v1`; an extension without it sends nothing new, an app
   without it refuses the field.
8. Judge panel 2× opus + 1× fable before merge.

### D3. Synced favorites (0023-2)

- Schema 35 table `item_favorite(item_uuid TEXT PRIMARY KEY, position INTEGER NOT NULL, created_at
  INTEGER NOT NULL, updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL, deleted_at INTEGER)`.
- **Not a child table of the item**: a favorite toggle must not bump the item's version clock, or a
  toggle on the iPhone and an edit on the Mac would make a conflict copy. It merges by
  `merge_lww` with `removal_wins = false` (a later add after a removal wins). Removal sets
  `deleted_at`.
- Order: `position` (add = the highest live position + 1), then `item_uuid`. An archived or missing
  item is hidden. A row whose item tombstone is older than `TOMBSTONE_DAYS` is pruned.
- A copy of schema 34 or older keeps the local rows (the `keep_local` pattern of schema 18).
- The favorite is a vault fact, shared by every device of the vault. Stage 4 must keep
  `item_favorite` out of any shared-collection scope (ADR 0014 §7): favorites are personal.
- iPhone migration: at the first unlock with a schema-35 core, the app sends its `UserDefaults` list
  in order (`favorites_import`), then deletes the key. A core below 35 keeps `UserDefaults`.
- Mac: a star in the credential header and in its "⋯" menu; a **Favorites** sidebar row under All
  Credentials when the vault has at least one favorite (mockup M0, frame F4). Chosen by this plan.

### D4. The iPhone app in the App Store (0023-3)

Everything is prepared in `docs/store/app-store/` (unit M18) from [Appendix A](#appendix-a--app-store-material):
the listing, the App Privacy answers, the export compliance inventory and draft answers, the review
notes, the screenshot list, the privacy policy draft, and the no-IAP rule. Unit M19 makes the
screenshots, the demo video, and a CI check that no iPhone or watch text asks the user to buy. The
submission is the owner's.

### D5. iPhone Settings follow the Mac grouping (0026-2)

| Mac (ADR 0026 §3) | iPhone today | iPhone after M7 |
| --- | --- | --- |
| Vault: the vault, Sync, Backup, Import | General (vault, Move to another app, AutoFill); sync in Devices | **Vault**: the vault (name or picker, Add another vault, Remove from this iPhone), Sync (service, state, last sync, Sync now, Select the iCloud file again, the new passphrase, Use the relay copy), Move to another app |
| Security | Security | **Security** (unchanged) |
| Devices | Devices | **Devices**: questions (relay or node), Mac on Wi-Fi (until W2 of s2-s3), Add Apple Watch, the devices of the vault |
| Bouncer | Agent Access | **Agent Access** (kept; the iPhone has no bouncer) |
| Tools | — | **Tools**: AutoFill |
| Updates | Advanced | **About**: the versions of the app and the core, licenses |

Each row of the list has a tile, the name, and one short status line, as on the Mac. Order as on the
Mac. Names "Agent Access", "Tools", "About": chosen by this plan; the owner can change them.

### D6. Synthetic input never uses the window (0030-1)

- A new crate `crates/apassy-input-guard` (macOS only) installs an `NSEvent` local monitor for
  mouse-down and key-down and keeps the newest record of each: timestamp, `kCGEventSourceUnixProcessID`,
  `kCGEventSourceStateID`. It is the only new code with `unsafe` (the objc2 block and the monitor),
  `#![deny(unsafe_op_in_unsafe_fn)]`, each block with a `SAFETY` note. The precedent is the FFI crate of
  `ios/ApassyCore` (ADR 0023 §2). Chosen by this plan; the owner can change it.
- `is_physical(record)`: process id 0 and state `kCGEventSourceStateHIDSystemState`. The same table of
  cases as the Swift predicate of ADR 0042.
- Every egui button whose click can use the window (Allow Once, Development, every
  `LocalWindowSource::LocalOwner` click, and any later one) reads `owner_press(ui, &response) -> Press`: **Verified** only for a
  pointer click or Space/Enter whose newest guard record is physical and at most 1 s old, and that is
  not an AccessKit request. Everything else is **Unverified** and starts the **fresh check** (Touch ID or
  the passphrase), never a refusal.
- The AccessKit `Click` action stays on the buttons, so VoiceOver, Voice Control, and Switch Control
  still work; they lead to the fresh check. This differs from the sketch in ADR 0030 decision A ("not
  exposing AccessKit press actions"), on purpose. Chosen by this plan; the owner can change it.
- Without the guard (install failed): every press is Unverified.
- Out of scope: browser gestures (`LocalWindowSource::BrowserGesture`) come from the extension, not
  from the app's window; `isTrusted` stays the limit that ADR 0030 names.

### D7. Dark appearance (0030-2)

- The app follows the system appearance. No in-app switch. Chosen by this plan.
- `Palette` with roles (window, sidebar, detail, label, secondary, tertiary, separator, fills, accent,
  status colors, production red), `Palette::LIGHT` with today's exact values, `Palette::DARK` from the
  mockup M0 (frames F1–F3, F7). No color literal outside `palette.rs` and `kit.rs`.
- Text contrast at least 4.5:1 for every text role on its background in both palettes, tested.
- The native panels (ADR 0038) and the notifier already follow the system.

### D8. CLI codes and the window (0030-3)

[ADR 0042](../adr/0042-verified-owner-transport-for-cli-codes.md): inside a valid window, `apassy code`
opens the Apassy panel in a confirm mode; a hardware-verified click on Show Code or Copy Code issues the
proof; anything else becomes the fresh check. One panel at a time; three cancels in 5 minutes give
15 minutes of fresh checks.

### D9. A shared base model from owner data (0035-8)

[ADR 0043](../adr/0043-shared-base-model-from-owner-data.md): off by default; skeleton records built on
the Mac (no free text, no names, hosts, paths, numbers, or variable names); the owner reviews and sends
each batch; anonymous upload with a yearly contributor id; `k = 5` distinct contributors per skeleton;
raw batches at most 180 days; a new base version with a data card starts in shadow mode. Plan 0035 keeps
the base model out of its scope and names ADR 0043; units M23–M26 here build it after plan 0035's C, J1,
and H.

### D10. The trust documents list the hosted bouncer brain (0035-9)

New row in `docs/security/trust-model.md` "Parties" and in ADR 0037 "Who sees what":

| Party | Holds | Sees | Cannot see |
| --- | --- | --- | --- |
| Bouncer brain service of Apassy Connect (paid, opt-in, ADR 0035) | The shared encoder; the owner's head sets while Apassy hosting is on; the examples of a training job for at most 24 h | The state of each bouncer request (user request, command, relative directory, purpose, variable names, owner rule), in memory for one request; the examples of a training job | Values, the vault, the vault path, absolute project paths. It cannot allow a run: the bouncer gate on the Mac decides |

The Connect row keeps "Cannot see: … questions" and gains "except the opt-in bouncer brain service,
which sees the bouncer state".

### D11. Proof for every release artifact (0037-31)

| Artifact | Provenance (GitHub build attestation) | SBOM (SPDX JSON, attested) | Reproducible | User check (`scripts/verify-release.py`) |
| --- | --- | --- | --- | --- |
| macOS DMG and `latest.json` (`release.yml`) | the DMG, `latest.json`, and `macos-binaries.json` (the SHA-256 of each Mach-O of the bundle with its signature removed) | the app bundle and `Cargo.lock` | Not in this plan. The check compares against the attested CI binaries instead | `mac <version>`: download, `codesign --verify --deep --strict`, team `7S3F9767BM`, `spctl` and `stapler validate`, then the signature-stripped digests against `macos-binaries.json` and its attestation |
| iPhone build record (`scripts/ios-testflight.sh` on the Mac, `ios-build-record.yml`) | the record JSON: version, build number, commit, Xcode and SDK, the IPA SHA-256, the SHA-256 of each Mach-O of the archive | `ios/ApassyCore` `Cargo.lock` and the resolved Swift packages | No. The App Store re-signs and encrypts the binary, so no user can compare it; the record is a signed claim, said as such | `ios <version>`: shows the record and checks its attestation and commit |
| Extension zip (`extension-package.yml`, new) | the zip | the zip contents | Yes: the script is deterministic; CI builds it twice and compares | `extension <version>`: download the CRX from the Chrome Web Store update URL, strip the CRX3 header, compare each file with the attested zip, ignoring `_metadata/` and the store's `key` and `update_url` in `manifest.json` |
| Relay image (`relay-image.yml` image job) | the image tarball and its record | the image | Yes (M21): base images by digest, no `apt-get` or `useradd` in the runtime stage, `SOURCE_DATE_EPOCH`, BuildKit `rewrite-timestamp` | `relay <version>`: tarball digest and attestation; the running relay's version |
| Linux CLI (`linux-cli`; the `linux-node` packages after s2-s3 L3) | each binary and package (L3 adds provenance for the node packages; M20 adds the SBOM) | each | Yes (M21): two builds at two paths, same SHA-256 | `linux <version>`: `SHA256SUMS`, attestation, `--version` |
| Darwin CLI (`darwin-cli`) | the binary | the binary | Best effort, reported | with `linux` |

Actions are pinned by commit SHA, as the repository does. Extension zip, SBOMs, and records are also
assets of the GitHub release `v<version>`. `docs/security/verify-a-release.md` explains the checks.

### D12. Headscale (0037-32)

`docs/operations/headscale.md`: what works with a Headscale control server (the node needs only a
tailnet address; the stage 2 route `https://<tailnet IPv4>:8444` with the pinned certificate; the Mac,
the iPhone app of Tailscale with a custom coordination server, and the Linux node; the LocalAPI WhoIs
check), what does not (Tailscale Funnel, so no cloud-agent route; `tailscale cert` and Serve
certificates; sharing a node with another tailnet: use one Headscale for the team instead), a policy
example that lets the owner's devices reach port 8444, and the check steps. Written after s2-s3 N2–N4
merge, so the commands are real. A devbox check (M5b) confirms it.

### D13. Archive the old relay repository (0037-33)

1. `relay-health.yml` in this repository: the same two checks, the same cron (`17 * * * *`), plus
   `workflow_dispatch`, `permissions: {}`, and a `concurrency` group. A scheduled workflow runs from the
   default branch, so it runs from `main`. GitHub sends a failure notice of a scheduled workflow to the
   person who last changed its cron line: the commit must come from the owner's identity, as every
   commit here does.
2. After two green scheduled runs on `main` (`gh run list -w relay-health.yml`), disable the old
   workflow (`gh workflow disable "Relay health" -R wydrox/apassy-relay`), then archive
   (`gh repo archive wydrox/apassy-relay --yes`). Both are reversible (`gh workflow enable`,
   `gh repo unarchive`). Ops checks first: no open pull request or issue that needs a move.
3. `implementation-plan-0037.md` 0C (it said `health.yml` stays private: the workflow uses only public
   addresses and no secret, so it can be public) and 1E get a "done" line.

### D14. Hosted teams with team content (0037-34, ADR 0037 D8)

1. **Inventory, read-only (ops):** `ssh ottervibe 'cd /opt/apassy && docker compose exec -T relay
   apassy-relay admin teams'`. Teams with items, collections, agents, or way B sessions. The full output
   goes only to the owner's private operations notes (the place of 0C), never into this public
   repository. The public record is one line of counts in the trust model ("The hosted relay today").
2. **Notice:** if every such team is the owner's own (`apassy-alpha`), no notice is needed. Else the
   owner sends the draft of [Appendix B](#appendix-b--draft-notice-to-owners-of-hosted-teams).
3. **Deletion (owner-only, no undo):** after the owner says a team is not needed (the case of the
   owner's own team), or no earlier than 60 days after the notice and after stage 4's signed export has
   shipped. Prepared commands: `admin backup` first; `admin suspend` (already); `admin delete <id>`;
   `admin teams` no longer lists it. The data is gone everywhere only when the daily backups that
   hold it age out; the runbook says when.

### D15. More than one vault on a watch (0039-3)

- Up to **4** connected vaults per watch. Chosen by this plan; the owner can change it.
- One replica vault per connected vault, each with its own random passphrase (keychain account
  `replica-<vault_id>`), relay key, questions membership, and answer key (already one per questions
  team).
- `watch_connect_start` no longer refuses because a replica exists. At `attached`, a `vault_id` that the
  watch already has gives `already_connected` ("This watch already answers for <vault>."), and the new
  device leaves the team again. A fifth vault gives `too_many_vaults` at the start.
- `watch_status` answers `{"vaults": [{id, name, state, macs, own}], "connecting": bool}`. The access
  calls take `vault_id`. The watch role opens every replica when the app becomes active and waits on
  all of their teams, as the iPhone's multi-vault questions do. `watch_forget` takes `vault_id`.
- The v1 replica is adopted as the first entry: no new pairing.
- Watch UI: Requests groups rows by vault when there are two or more; the request detail has a Vault
  fact; This Watch lists the vaults with Forget and "Connect another vault". The iPhone's Add Apple
  Watch says "Add another vault to Apple Watch" when the watch has one.

### D16. Relay feed v3 (S5-1)

- **`grant_request` is retired**, not reserved: durable access stays on the Mac (ADR 0033). The
  contract says so.
- v3 adds `agents[].open_requests` (a count, 0 to 20; never the item, the reason, or the folder) and
  `suggestions[]` (at most 20: `id`, the item title, what the correction changes, `created_at`; never a
  value).
- Two actions, both stricter and signed with the device key (no Face ID): `disconnect_agent:<agent id>`
  (the Mac revokes the agent as Agents → Disconnect does; for a remote agent also on the node) and
  `dismiss_suggestion:<correction id>`. A stale target is refused, as for `remove_exception`.
- The iPhone shows the count on the agent page with "Open Requests", a Disconnect… button with a
  confirmation, and a Suggestions list with Dismiss. Accepting a suggestion stays on the Mac.
- Readers accept 1, 2, 3; an old reader shows "Update Apassy to see the agents of <Mac>".
- The watch gets nothing new.

### D17. `latest.json` keeps `Apassy.dmg` (0015-1)

**Keep it.** It costs one extra bucket key per release; removing it leaves every app of 0.3.0 to 0.4.1
without updates for ever. **Condition to remove:** no request for `/latest.json` with a user agent
`Apassy/0.3.*` or `Apassy/0.4.*` for 90 days, read by ops from Cloudflare's request analytics at each
release preparation (read-only, aggregate; no new logging). If the analytics cannot show 90 days, the
decision stays "keep". When the condition holds: one small unit switches `file` to
`Apassy-<version>.dmg` in `build-dmg.sh` and removes the Worker route. Chosen by this plan; the owner
can change it.

### D18. Connectors as plugins (0010-1)

[ADR 0044](../adr/0044-connector-plugins.md): a plugin is a strict JSON manifest, no code; version 1 is
`GET` only; bundled plugins are covered by the app signature, owner-installed ones are pinned by hash in
the vault (`connector_plugin`, schema 35); a plugin can use an item only for a host that the item names;
the first plugin is GitHub read-only. Planned last (wave 7).

### D19. Windows (0011-7)

**No Windows port.** Chosen by this plan; the owner can change it. Apassy is built on macOS facilities
that have no drop-in Windows form: the Keychain and the Secure Enclave for the device keys and Touch ID
(ADR 0003, ADR 0038), the signed Swift helpers in `native/` (notifier, Keychain, browser guard, caller
probe, lifecycle observer), `sandbox-exec` for agent isolation (ADR 0010), audit tokens and code
signatures for the browser host and the owner socket, and a Unix owner socket. A port would need Windows
Hello with a TPM-bound key store, a Windows owner-check panel, AppContainer or a restricted token with a
Windows Filtering Platform rule for isolation (the service account of ADR 0011 stage 6), a named-pipe
owner socket with `GetNamedPipeClientProcessId` and Authenticode checks, a native-messaging host with
the same caller check, the Windows certificate store for the Go part of ADR 0011 stage 4, toast
notifications, Authenticode signing, and an MSIX updater: more work than ADR 0037 stages 2 and 3
together, and a seventh component in every release. Agents on a Windows machine are not left out: in
WSL2 they use a linked environment (ADR 0037 stage 5) of a Mac or Linux node. Revisit when paying
Connect customers ask for a Windows app.

### D20. Notification Service Extension (0037-30) and push to the watch (0039-2)

These belong to the push gateway of [stages 2 and 3](implementation-plan-s2-s3.md) (N0 contract
`push-gateway-v1`, N5 gateway). Interface notes only, in [Interface notes](#interface-notes-for-the-push-gateway-plan).

## Work units

One editor owns each shared file at a time ([One editor per shared file](#one-editor-per-shared-file)).
Paths are current unless marked "new". Integration tests go into the single target (`tests/it.rs`
module list) or the unit's own file. Sizes: S ≤ 1 day, M 2–3 days, L 4–6 days of one implementer.

### M0 — Mockup for the new views (M)

- Owns: `docs/design/misc-mockup.html` (new).
- Frames: F1 Mac credentials list and credential page, light and dark; F2 Decisions with a waiting run
  and an access request, dark; F3 Settings → Bouncer and one sheet, dark; F4 Mac favorites (sidebar row,
  star); F5 the access-request banner; F6 the owner check of a frame fill and the inline chooser in a
  frame; F7 the CLI confirm panel (ADR 0042), light and dark; F8 iPhone Settings list and the Vault
  section (D5); F9 iPhone agent page with the request count, Disconnect…, and Suggestions (D16); F10
  watch Requests with two vaults, the request detail, This Watch; F11 the base-model consent sheet and
  Review and send (ADR 0043); F12 Settings → Tools → Connectors and the install sheet (ADR 0044).
- Rules: demo data only; the text rules of `cloud-agents-mockup.html`; a CSS variable table of the
  light and dark palette that M14 copies. The mockup is the reference for the screenshot check before a
  release; no owner approval gate (owner decision 2026-11-03).
- Owner: implementer (opus, high). Depends on nothing. Judge: 1× opus (completeness against this list).
- Acceptance: every frame present; each text fits the rules; the palette table has every role of D7.

### M1 — Trust documents list the hosted bouncer brain (S)

- Owns: `docs/security/trust-model.md` (the row of D10 and the Connect line), `docs/adr/0037-own-relay-open-source.md`
  ("Who sees what" row), `docs/adr/0035-bouncer-hosting-and-training-choice.md` (open question 4: done).
- Owner: worker (sonnet, high) with D10 as the exact text. Depends on nothing; goes first of all units
  that edit `trust-model.md` (s2-s3 N0/N8, s4, s6, s8 rebase on it).
- Acceptance: both tables have the row; the docs link check passes (`tests/contracts.rs` link check or
  the script the repository uses).

### M2 — Relay health in this repository, then archive (S)

- Owns: `.github/workflows/relay-health.yml` (new), `docs/design/implementation-plan-0037.md` (0C and 1E
  lines).
- Steps after merge (ops): D13 steps 2 and 3.
- Owner: ops (opus, high). Depends on nothing.
- Acceptance: two green scheduled runs on `main`; the old workflow `disabled_manually`;
  `gh repo view wydrox/apassy-relay --json isArchived` is `true`.

### M3 — Hosted teams: inventory, notice, deletion runbook (S)

- Owns: `docs/operations/hosted-teams-d8.md` (new, public: the procedure, the conditions of D14, the
  commands; counts only, never names), the count line in `docs/security/trust-model.md` (after M1).
- Owner: ops (opus, high), read-only on `ottervibe`. Depends on M1 for the trust-model line.
- Acceptance: the counts line exists; the private notes exist (ops reports their path to the top-level
  agent, not the content); the owner list item is filled with the team count and the prepared commands.

### M4 — Decision notes: update names, Windows (S)

- Owns: `docs/adr/0015-automatic-updates.md` (a note: keep, and the condition of D17),
  `docs/operations/release.md` ("Image names": the condition and the per-release analytics check),
  `docs/adr/0011-run-proxy-placeholders.md` (one line: the Windows parts of stages 4 and 6 are not
  planned, D19), `docs/goal.md` ("Out of scope": "Windows: no port", with a link to D19).
- Owner: worker (sonnet, high), in the same task as M1. Depends on nothing.
- Acceptance: each file has its line; links resolve.

### M5 — Headscale page (S) and its devbox check (S)

- M5a owns `docs/operations/headscale.md` (new, D12) and one link each from `docs/operations/node.md`
  (s2-s3 N7) and `docs/operations/team-host.md` (s4). Worker (sonnet, high). Depends on s2-s3 N2, N3,
  N4 merged.
- M5b (ops, opus, high): on `devbox-x86`, a Headscale container, two `tailscale` clients in containers
  with `--login-server`, and `apassy serve` (s2-s3 L1); a client reaches `/healthz` through the pinned
  route; results in the page. Needs the owner's go for the devbox session ([Owner list](#owner-list)).
  `devbox down x86` at the end.
- Acceptance: the page names each "works / does not work" item of D12; M5b's transcript shows the
  `/healthz` answer over the Headscale tailnet.

### M6 — Access-request notification on the Mac (S–M)

- Owns: `src/desktop/notify.rs`, `src/desktop/inbox.rs`, `src/native/mod.rs` (`NotificationEvent`),
  `native/ApassyNotify/Notify.swift`, the `EventKey::Access` arm in `src/desktop/ui/decisions.rs`
  (after U3b-2 and M13), `tests/notifications.rs`, `docs/operations/notifications.md`, the "does not
  send a macOS notification yet" line of ADR 0012, review item 2 of ADR 0033.
- Interface: `EventKey::Access(u64)` with id `access-<id>`; `OwnerEvent::AccessRequested`;
  `NotificationEvent::AccessRequested` (wire `access_requested`, `waiting_key` allowed);
  `ACCESS_NOTICE_COOLDOWN = 30 s` per agent; `OwnerItems.access`, `OwnerMarks.access`.
- Owner: implementer (opus, high). Depends on U3b-2 merged. Judge: 1× opus.
- Acceptance (the implementer writes, CI runs): `a_new_access_request_sends_one_notification_with_the_agent_name_only`,
  `a_duplicate_access_request_sends_none`, `a_decided_access_request_removes_its_notification`,
  `the_first_look_at_a_vault_announces_no_access_request`, `a_second_access_request_of_the_agent_within_30_s_has_no_banner`,
  `inbox::access_key_has_the_id_access_n`, the click routes to `Key::Access`; the Swift template test
  (preview text has no item name). Synthetic-secret scan of the notifier request.

### M7 — iPhone Settings grouping (M)

- Owns: `ios/ApassyCompanion/Sources/Views/Vault/SettingsView.swift`,
  `Views/Settings/GeneralSettingsView.swift` → `VaultSettingsView.swift`, `AdvancedSettingsView.swift`
  → `AboutSettingsView.swift`, `ToolsSettingsView.swift` (new), `SecuritySettingsView.swift`, the sync
  rows of `DevicesSettingsView.swift` (only if s2-s3 N6 has not started; else after N6 merges),
  settings tests in `ios/ApassyCompanion/ModelTests/**`, `UITests/VaultTabsUITests.swift` (navigation),
  the Settings row of `ios/README.md`, ADR 0026 §8 status.
- Owner: implementer (opus, high). Depends on M0 (F8). Judge: 1× opus; screenshots next to F8.
- Acceptance: `SettingsNavigationTests` (six destinations in the order of D5, each status line);
  `VaultTabsUITests` reaches each destination; every row that existed before is reachable (a list test).

### M8 — Input guard: synthetic presses use the fresh check (M)

- Owns: `crates/apassy-input-guard/{Cargo.toml, src/lib.rs}` (new), root `Cargo.toml` (member; an
  optional dependency under `desktop`, macOS only), `Cargo.lock` (serialized by the top-level agent),
  `src/desktop/ui/owner_press.rs` (new), `src/desktop/owner_check.rs` (the click entry points take
  `Press`), the call sites in `src/desktop/ui/decisions.rs` and the other UI files that draw a
  window-using button, `src/broker/approvals/owner_window.rs` (diagnostic reason kinds),
  `src/desktop/ui/owner_tests.rs`, ADR 0030 decision A status line.
- Interface: `apassy_input_guard::{install() -> Result<Guard, GuardError>, Guard::newest(Kind) ->
  Option<EventRecord { kind, timestamp, source_pid, source_state }>, is_physical(&EventRecord) -> bool}`;
  `owner_press(ui, &Response) -> Press { Verified, Unverified(AccessKit | Synthetic | NoRecord | NoGuard) }`;
  `start_local_owner(source, reuse = press.is_verified())`.
- Owner: implementer (opus, high). Depends on U2b and U3b-2 merged; on M13 for `decisions.rs`.
  Judge panel: 2× opus + 1× fable (unsafe crate, owner authority).
- Acceptance: `is_physical` table test (the cases of ADR 0042 §2); `an_accesskit_click_on_allow_once_opens_the_fresh_check`;
  `a_click_without_a_guard_record_opens_the_fresh_check`; `a_stale_record_opens_the_fresh_check`;
  `a_verified_click_inside_the_window_uses_the_window`; `every_window_button_reads_owner_press` (a
  source scan: no `allow_once_clicked(` or `development_clicked(` without a `Press`). No `unsafe` outside
  the new crate (a source scan test). Physical: [Owner list](#owner-list) item 8.

### M9 — CLI code confirmation panel (ADR 0042) (M)

- Owns: `native/ApassyHelper/{AuthPanel.swift, Protocol.swift, HardwareInput.swift (new)}`, the helper
  protocol in `src/native/check.rs` or `src/native/mod.rs` (after M6), `src/desktop/owner_cli.rs`,
  `src/desktop/owner_check.rs` (after M8), `src/broker/approvals/{owner_window.rs, owner_auth.rs}`
  (`LocalWindowSource::CliConfirm`; `CliCode` reuse only with it), `docs/contracts/owner-cli-v1.md`
  (`busy`, `expired`), the CLI lines of ADR 0030 and ADR 0034.
- Owner: implementer (opus, high). Depends on M8. Judge panel: 2× opus + 1× fable.
- Acceptance: the "Required checks" of ADR 0042, each as a named test: `a_cli_code_inside_the_window_opens_the_confirm_panel`,
  `an_unverified_confirm_becomes_the_fresh_check`, `every_time_keeps_the_fresh_check`,
  `a_second_cli_code_while_the_panel_is_open_is_busy`, `three_cancels_give_fifteen_minutes_of_fresh_checks`,
  `the_confirm_proof_is_single_use`, `the_panel_title_comes_from_the_template`; the Swift
  `HardwareInput` table test equals the Rust one.

### M10 — Same-site cross-origin frame fills (L)

- Owns: `extension/{login-worker.js, login-suggestions.js, login-target.js, fill.js}`,
  `extension-tests/tests/**` and `extension-tests/fixtures/frames/` (new: same-site and cross-site frame
  pages on the test server), `src/browser/{site.rs, wire.rs}`, `src/desktop/browser.rs`,
  `src/desktop/owner_store/browser.rs`, `src/broker/approvals/owner_auth.rs` (`FillLogin.embedded_in`,
  after M9), the dialog text in `src/desktop/owner_check.rs` (after M9), `docs/contracts/browser-v1.md`,
  ADR 0021 (D4 row), `docs/operations/browser.md`; the privacy page sentence as a separate draft pull
  request that only the owner merges.
- Interface: D2 rule 7. `Page::embedded(frame, ancestors) -> Result<EmbeddedPage, SiteError>`;
  `SiteError::{CrossSite, OpaqueAncestor, AncestorMismatch}`.
- Owner: implementer (opus, high). The extension and contract part starts at once; the Rust edits of
  `owner_check.rs` and `owner_auth.rs` wait for M9. Judge panel: 2× opus + 1× fable.
- Acceptance: `a_same_site_frame_login_fills_after_the_owner_check_that_names_both_origins`;
  `a_cross_site_frame_is_refused_with_the_own_tab_recovery`; `a_null_or_opaque_ancestor_is_refused`;
  `an_ancestor_list_that_does_not_end_in_the_top_origin_is_refused`; `a_frame_navigation_during_the_check_fills_nothing`;
  `a_login_that_matches_only_the_top_origin_is_not_offered_in_the_frame`; `an_agent_fill_never_targets_a_frame`
  (ADR 0036 regression); `passkeys_and_codes_stay_in_the_top_frame`; an extension without the capability
  sends no `embedded`; an app without it refuses the field. Helium runs of the frame fixtures in CI.

### M11 — Vault schema 35 and favorites in the core (M)

- Owns: `src/vault/schema35.rs` (new), `src/vault/favorites.rs` (new), `src/vault/{mod.rs, types.rs,
  merge.rs}` (`SCHEMA_VERSION`, `SYNCED_TABLES`, `LOCAL_TABLES`, the LWW entry, `keep_local` for older
  copies), `ios/ApassyCore/src/core/favorites.rs` (new) and its routing in `core/mod.rs`,
  `docs/contracts/ios-core-v1.md` (a favorites section), `docs/contracts/vault-v1.md` (schema 35),
  `tests/vault_migration.rs`, `tests/relay_sync.rs`, core tests.
- Schema 35, D3, plus the two local tables of ADR 0044 and ADR 0043:
  `connector_plugin(id TEXT PRIMARY KEY, version TEXT NOT NULL, sha256 TEXT NOT NULL, hosts TEXT NOT NULL, installed_at INTEGER NOT NULL)`,
  `contribution_batch(id INTEGER PRIMARY KEY AUTOINCREMENT, sent_at INTEGER NOT NULL, records INTEGER NOT NULL, batch_sha256 TEXT NOT NULL, delete_token BLOB NOT NULL, last_decision_id INTEGER NOT NULL, deleted_at INTEGER)`.
  One schema step for three plan items. Chosen by this plan; the owner can change it.
- Interface: `Vault::favorites() -> Vec<Favorite { item_id, item_uuid, position }>`,
  `Vault::set_favorite(item_id, on)`, `Vault::import_favorites(&[item_id])`; core calls
  `favorites_list`, `favorite_set {id, on}`, `favorites_import {ids}`.
- Owner: implementer (opus, high). Depends on the schema chain 27–34 merged. Judge panel: 2× opus +
  1× fable (migration, merge).
- Acceptance: `schema_34_to_35_keeps_every_row`, `a_failed_35_migration_keeps_34`,
  `a_favorite_syncs_through_the_relay_and_icloud_snapshots`, `the_later_favorite_toggle_wins` (both
  orders), `a_favorite_toggle_leaves_the_item_clock_alone` (no conflict copy with a parallel edit),
  `a_favorite_of_an_archived_item_is_hidden`, `a_schema_34_copy_keeps_the_local_favorites`,
  `connector_plugin_and_contribution_batch_are_not_in_a_pushed_copy`, the three core calls.

### M12 — Favorites on the Mac and the iPhone migration (M)

- Owns: `src/desktop/ui/items.rs` (star, "⋯" item), `src/desktop/ui/sidebar.rs` (Favorites row; after
  U3b-1 and M13), the desktop model of favorites, `src/desktop/ui/vault_tests.rs`;
  `ios/ApassyCompanion/Sources/Vault/{VaultSettings.swift (after s2-s3 N6), VaultModel.swift, VaultQuery.swift}`,
  `ios/ApassyVaultKit` calls, `ModelTests` (`VaultSettingsTests`, `OlderCoreTests`, `VaultQueryTests`).
- Owner: implementer (opus, high). Depends on M11, M0 (F4). Judge: 1× opus; screenshots next to F4.
- Acceptance: `the_star_toggles_a_favorite_and_the_sidebar_row_appears`, `the_favorites_row_is_hidden_without_favorites`;
  iPhone `migratesUserDefaultsFavoritesOnceInOrder`, `keepsUserDefaultsWithAnOlderCore`,
  `aMigratedVaultShowsTheMacsFavorites`.

### M13 — Palette roles, no visual change (M)

- Owns: `src/desktop/ui/palette.rs` (new), `src/desktop/ui/kit.rs`, and every UI file with a color
  literal (`ui.rs`, `agents.rs`, `decisions.rs`, `decisions_activity.rs`, `agent_onboarding.rs`,
  `vaults.rs`, `sync.rs`, `new_credential.rs`, `items.rs`, `settings_rows.rs`, `detail_rows.rs`,
  `settings_view.rs`) for one short sweep. The top-level agent announces the sweep; other open units
  rebase after it.
- Owner: implementer (opus, high). Depends on U3b-1 and U3b-2 merged. Judge: 1× opus.
- Acceptance: `no_color_literal_outside_the_palette` (source scan); `Palette::LIGHT` equals the old
  constants (a test per role); the light demo screenshots of the top-level run equal the ones before the
  sweep.

### M14 — Dark appearance (L)

- Owns: `src/desktop/ui/palette.rs` (`DARK` from M0), `src/desktop/ui/kit.rs` (dark visuals),
  `src/desktop/mod.rs` (follow the system theme, repaint on change), `src/desktop/ui/demo.rs`,
  `scripts/screenshots.sh` (`--dark`), `docs/operations/desktop-ui.md`, the dark lines of ADR 0030 and
  ADR 0031.
- Owner: implementer (opus, high). Depends on M13, M0. Judge: 1× opus; screenshots of every view in
  dark next to F1–F3 and F7.
- Acceptance: `the_palette_follows_the_system_theme`; `every_text_role_has_contrast_4_5_in_both_palettes`;
  `production_red_is_distinct_in_dark`.

### M15 — Watch: several vaults in the core (M)

- Owns: `ios/ApassyCore/src/core/watch.rs`, the watch fields of `core/config.rs` (after s2-s3 N3), the
  watch-role use of the questions context in `core/questions.rs` (after U2c and s2-s3 N5),
  `docs/contracts/ios-core-v1.md` §5.13, core tests.
- Interface: D15.
- Owner: implementer (opus, high). Depends on U2c, N3, N5 merged (file order). Judge: 1× opus.
- Acceptance: `a_watch_connects_a_second_vault`, `the_same_vault_twice_is_already_connected_and_leaves_the_team`,
  `a_fifth_vault_is_too_many`, `watch_status_lists_every_vault`, `forget_removes_one_vault_only`,
  `the_v1_replica_is_adopted_without_a_new_pairing`, `answers_go_to_the_vault_of_the_request`.

### M16 — Watch and iPhone apps for several vaults (M)

- Owns: `ios/ApassyCompanion/Watch/Sources/**`, `ios/ApassyCompanion/Sources/Views/Settings/AddAppleWatchView.swift`,
  the watch calls of `ios/ApassyVaultKit`, the watch tests, `docs/product/apple-watch-access/flow-spec.md`
  (an addendum), ADR 0039 §4 status line.
- Owner: implementer (opus, high). Depends on M15, M0 (F10). Judge: 1× opus; Simulator screenshots next
  to F10.
- Acceptance: watch model tests for grouping by vault, the vault fact, Forget of one vault; the iPhone
  text "Add another vault to Apple Watch". Physical: [Owner list](#owner-list) item 8.

### M17 — Relay feed v3 (L)

- Owns: `docs/contracts/relay-feed-v1.md` (v3 section, `grant_request` retired),
  `src/questions/{feed.rs, feed_reader.rs}` and the Mac's feed action handling (after U3a and U2c),
  `ios/ApassyCore/src/core/feed.rs`, `ios/ApassyCompanion/Sources/Views/Agents/**`,
  `Sources/Models/AgentsModel.swift`, `tests/relay_feed.rs`, core tests, `ModelTests`.
- Owner: implementer (opus, high). Depends on U3a and U2c merged; M0 (F9). Judge panel: 2× opus +
  1× fable (action authority).
- Acceptance: `a_v3_feed_stays_within_the_limits_and_fit_keeps_days`; `both_readers_accept_1_2_3_and_refuse_4`;
  `a_v3_feed_has_no_item_reason_or_value_in_requests`; `disconnect_agent_from_the_iphone_revokes_the_agent_once`;
  `a_stale_disconnect_is_refused`; `dismiss_suggestion_dismisses_once`; `grant_request_is_refused_by_the_mac`;
  `an_old_reader_shows_the_update_text`.

### M18 — App Store package (M)

- Owns: `docs/store/app-store/{README.md, listing.md, app-privacy.md, export-compliance.md,
  review-notes.md, screenshots.md, privacy-policy-ios-draft.md}` (new).
- Owner: worker (sonnet, high) with [Appendix A](#appendix-a--app-store-material) as the checklist.
  Depends on nothing. Judge: 1× opus (truth against the code: every data flow of Appendix A.2 exists).
- Acceptance: every field of Appendix A has its file and value; the keywords fit 100 characters, the
  subtitle 30; the privacy draft names every flow of A.2.

### M19 — App Store screenshots, demo video, no-purchase check (M)

- Owns: `ios/ApassyCompanion/UITests/AppStoreScreenshotsUITests.swift` (new),
  `scripts/app-store-screenshots.sh` (new: runs the UI test on the named Simulators, extracts the
  attachments from the `.xcresult` into `target/app-store/`), `scripts/check-ios-no-purchase.py` (new)
  and one step in `.github/workflows/ci.yml`, `docs/store/app-store/screenshots.md` (final list).
- Owner: worker (sonnet, high); the top-level agent runs the UI test through `heavy-check`. Depends on
  M18 and on the build to submit (after M7 and M16 if they ship in it).
- Acceptance: `check-ios-no-purchase.py` fails on a fixture with "Upgrade", "€", or a checkout URL and
  passes on the tree; the list of A.5 has a file of the right size for each item; the demo video is at
  most 2 minutes and uses demo data only.

### M20 — Attestations and SBOMs (M)

- Owns: `.github/actions/attest/action.yml` (new composite: SPDX SBOM with a pinned SBOM action, then
  build-provenance and SBOM attestations), `.github/workflows/release.yml` (steps after signing;
  `macos-binaries.json`), `.github/workflows/relay-image.yml` (steps in each job), `.github/workflows/extension-package.yml`
  (new), `.github/workflows/ios-build-record.yml` (new: `workflow_dispatch` with the record JSON, at
  most 64 KiB; checks the commit is on `main` and the version matches), `scripts/build-extension-zip.sh`
  (`plutil` → Python, so it runs on Linux), `scripts/ios-testflight.sh` (writes the record),
  `docs/operations/release.md` (attestations).
- Owner: ops (opus, high). Depends on nothing; file order with s2-s3 L3, s4, and s8 for the two
  workflows. Judge: 1× opus.
- Acceptance: on a provider-check run and on an `image-*` test tag, `gh attestation verify` passes for
  each artifact of D11; each SBOM attestation has predicate type SPDX; the extension job builds the zip
  twice with the same SHA-256.

### M21 — Reproducible Linux binaries and relay image (M)

- Owns: `.github/workflows/reproducible.yml` (new: on `image-*` tags, weekly, and on dispatch; two
  builds at two workspace paths with `--remap-path-prefix`, `SOURCE_DATE_EPOCH` from the commit,
  `CARGO_INCREMENTAL=0`; a compare job that fails and uploads a `diffoscope` report on a difference),
  `crates/apassy-relay/Dockerfile` (base images by digest; the CA bundle copied from the pinned build
  image; numeric user without `useradd`; `SOURCE_DATE_EPOCH`), `.github/workflows/relay-image.yml`
  (BuildKit `rewrite-timestamp`; after M20).
- Owner: ops (opus, high). Depends on M20. Judge: 1× opus.
- Acceptance: two builds give the same SHA-256 for `apassy-team` (and the node binary after L3) and the
  relay binary; two image builds give the same image id; the image's binary equals the reproducible
  build. The darwin CLI result is reported, not required.

### M22 — Release verification script and page (M)

- Owns: `scripts/verify-release.py` (new; Python 3.12, standard library, `gh` for attestations),
  `scripts/tests/test_verify_release.py` and `scripts/tests/fixtures/verify/` (new: a CRX3 sample, a
  manifest with store fields, a `macos-binaries.json`), `docs/security/verify-a-release.md` (new), one
  link in `README.md`, the "Apassy project" row of the trust model (after M3).
- Owner: implementer (opus, high). Depends on M20 (formats). Judge panel: 2× opus + 1× fable (a false
  "verified" is the failure).
- Acceptance: unit tests for the CRX3 parser (wrong magic, wrong version, a header length past the end),
  the manifest normalization (only `key` and `update_url` ignored), the stripped-digest comparison (one
  changed byte fails); the script refuses to say "verified" when an attestation is missing; a top-level
  run against the first release after M20 passes for `mac`, `extension`, `linux`, `relay`.

### M23 — Skeleton records for the base model (M)

- Owns: `src/broker/contrib/{mod.rs, skeleton.rs, vocab.rs}` (new; the vocabulary from `packs/*.json`),
  `tests/fixtures/contrib/adversarial.jsonl` (new: planted tokens of each kind: AWS, GitHub, Stripe,
  JWT, base64, hex, emails, IPv4/IPv6, hosts, paths, names, homoglyphs, long numbers), `tests/contrib_skeleton.rs`
  (new), ADR 0043 status.
- Owner: implementer (opus, high). Depends on ADR 0043. Judge panel: 2× opus + 1× fable (privacy).
- Acceptance: `no_planted_token_survives_the_skeleton` (every corpus row); `a_known_program_keeps_its_pack_flags`;
  `an_unknown_program_is_a_word_placeholder`; `production_code_and_cloud_decisions_make_no_record`;
  `only_owner_decisions_make_records`; `variable_names_become_provider_classes`.

### M24 — Consent, review, and upload (M)

- Owns: `src/broker/contrib/{batch.rs, upload.rs}` (new), `src/desktop/ui/contrib.rs` (new: consent
  sheet, Review and send, Delete my contributions), the switch and the quiet line in
  `src/desktop/ui/settings.rs` (Bouncer section; after plan 0035 J1 and s2-s3 N7), `src/vault/contrib.rs`
  (new; `contribution_batch`), `OwnerAction::ContributeExamples` in `owner_auth.rs` (after M10), a
  build setting `APASSY_CONTRIB_ENDPOINT` (empty = the switch is hidden); the privacy policy section as
  a draft pull request for the owner.
- Owner: implementer (opus, high). Depends on M23, M11, plan 0035 J1. Judge: 1× opus.
- Acceptance: `the_switch_is_hidden_without_an_endpoint`; `turning_on_needs_the_owner_check`;
  `send_uploads_exactly_the_reviewed_rows`; `a_removed_row_is_not_sent`; `delete_sends_every_token`;
  `the_upload_has_no_address_header_and_no_account`; synthetic-secret scan of the upload body.

### M25 — Contribution service (M)

- Owns: `tools/contrib/{app.py, store.py, sweeper.py, build_set.py}` (new; a separate small service, not
  inside the bouncer brain app), `tests/contrib/test_*.py` (new), an edge Worker that forwards no client
  address (`crates/apassy-relay/deploy/contrib-edge/`, new), `docs/operations/contributions.md` (new),
  the contribution-store row of the trust model (after M22), the ops compose plan for `ottervibe`.
- Owner: implementer (opus, high) for the service; ops (opus, high) for the deploy plan. Depends on
  M23 (record format), plan 0035 H (the host layout). Judge panel: 2× opus + 1× fable.
- Acceptance: `a_batch_over_200_records_or_256_kib_is_refused`; `an_unknown_field_is_refused`;
  `a_skeleton_from_four_contributors_is_not_in_the_set_and_from_five_is`; `the_set_has_no_contributor_or_day`;
  `raw_batches_are_gone_after_180_days_and_after_training` (fake clock); `delete_by_token_removes_the_batch`;
  `no_log_line_holds_a_record_or_an_address` (log capture); the Worker test that `CF-Connecting-IP` is not
  forwarded.

### M26 — Base model training and data card (M)

- Owns: `tools/basemodel/base_train.py` (new; uses `tools/finetune/local_train.py` as plan 0035 does),
  the data card in `docs/operations/base-model.md`, the eval numbers.
- Owner: ops (opus, high). Depends on M25 live, enough records (at least 1,000 records past `k`, chosen
  by this plan), and the owner's go for the devbox or GPU session. Judge: architect (fable, xhigh) reads
  the eval against `apassy-base-v1`.
- Acceptance: the new heads are not worse than v1 on the eval set of `apassy-eval` for every head; the
  data card has the counts of ADR 0043 §7; the release ships them in shadow mode.

### M27 — Connector plugin manifests and loader (M)

- Owns: `docs/contracts/connector-plugin-v1.md` (new), `src/broker/plugins/{mod.rs, manifest.rs, load.rs}`
  (new), `src/broker/profile.rs` (`OperationSpec` from data), `connectors/reporting-api-v0.json` (new,
  bundled), `scripts/build-app.sh` (copy `connectors/` into Resources; after s4's edit),
  `tests/connector_plugins.rs` (new). `tests/agent_path.rs` must pass unchanged.
- Owner: implementer (opus, high). Depends on ADR 0044. Judge panel (with M28, M29): 2× opus + 1× fable.
- Acceptance: the refusals of ADR 0044 "Required checks"; `reporting_api_v0_from_the_manifest_behaves_as_the_compiled_profile`.

### M28 — Install, pin, Settings → Tools → Connectors (M)

- Owns: `src/broker/plugins/install.rs` (new), `src/vault/connectors.rs` (new; `connector_plugin`),
  `src/desktop/ui/settings.rs` (Tools → Connectors; after M24), `src/cli/**` (`apassy connectors
  install|list|remove`), `docs/contracts/owner-cli-v1.md`, `OwnerAction::InstallConnector` in
  `owner_auth.rs` (after M24).
- Owner: implementer (opus, high). Depends on M27, M11, M0 (F12).
- Acceptance: `install_needs_the_owner_check_that_names_the_hosts`; `a_changed_file_is_not_loaded`;
  `a_new_host_needs_a_new_check`; `remove_drops_the_pin_and_the_operations`.

### M29 — First plugin: GitHub read only (S–M)

- Owns: `connectors/github.json` (new), `tests/connector_github.rs` (new; a local TLS fake of
  `api.github.com`), `docs/operations/connectors.md` (new), the connectors line of `docs/goal.md` (after
  M4), ADR 0010 "Connectors" status line.
- Owner: implementer (opus, high). Depends on M28.
- Acceptance: `only_the_named_fields_reach_the_agent`; `a_slash_or_dot_dot_in_owner_is_refused`;
  `an_item_with_another_host_is_not_offered`; `a_redirect_is_not_followed`; `a_production_item_asks`;
  `the_token_is_masked_in_every_string`.

### M30 — Integration into each release (S per release)

- Owner: the top-level agent, inside the release unit of the plan that leads the release (U5 of the
  Bouncer section, R of s2-s3, or later). It adds this plan's upgrade notes and acceptance lines, runs one
  validation pass per revision, and screenshots each changed view next to its M0 frame before any
  release claim. Judge panel 2× opus + 1× fable over the combined diff of this plan's units in the
  release.

## One editor per shared file

| File | Order of editors |
| --- | --- |
| `docs/security/trust-model.md` | M1 first; then the sibling plans (s2-s3 N0/N8, s4, s6, s8); then M3 (count line), M22 (project row), M25 (store row) |
| `docs/adr/0037-own-relay-open-source.md` | M1 only in this plan |
| `.github/workflows/release.yml` | One at a time with s4 and s8: M20 adds its steps as a separate block at the end of the `macos` job |
| `.github/workflows/relay-image.yml` | M20 → M21; with s2-s3 L3 and s4: whoever is second adds the step to the other's job |
| `.github/workflows/ci.yml` | M19 adds one step; one editor per wave with the sibling plans |
| `src/desktop/owner_check.rs` | (U2b) → M8 → M9 → M10 |
| `src/broker/approvals/owner_auth.rs` | (U2b) → M9 → M10 → M24 → M28 |
| `src/desktop/ui/decisions.rs` | (U3b-2) → M13 → M6 → M8 |
| `src/desktop/ui/kit.rs`, `sidebar.rs` | (U3b-1) → M13 → M12 (sidebar) → M14 (kit) |
| `src/desktop/ui/settings.rs` | (s2-s3 N7, plan 0035 J1) → M13 → M24 → M28 |
| `src/native/mod.rs` | M6 → M9 |
| `src/vault/{mod.rs, types.rs, merge.rs}` | the schema chain 27–34 → M11 |
| `src/questions/{feed.rs, feed_reader.rs}` | (U3a) → M17 |
| `ios/ApassyCore/src/core/config.rs`, `questions.rs` | (U2c, s2-s3 N3, N5) → M15 |
| `ios/.../DevicesSettingsView.swift` | M7 if s2-s3 N6 has not started; else N6 → M7 |
| `ios/.../VaultSettings.swift` | (s2-s3 N6) → M12 |
| `docs/contracts/ios-core-v1.md` | (s2-s3 N3, N6) → M11 → M15 |
| `Cargo.toml`, `Cargo.lock` | M8; the top-level agent serializes lockfile changes |
| `scripts/build-app.sh` | (s4) → M27 |
| `docs/goal.md` | M4 → M29 |
| `site/src/pages/privacy.astro` | draft pull requests that only the owner merges: M18 → M10 → M24 |

## Execution with subagents

Roles, models, efforts (owner convention; set both explicitly):

| role | agentType | model | effort |
| --- | --- | --- | --- |
| discovery (read-only) | scanner | sonnet | low |
| design, final synthesis (read-only) | architect | fable | xhigh |
| implementation | implementer | opus | high |
| debugging | debugger | opus | xhigh |
| devops, workflows, servers | ops | opus | high |
| verification, judge panels (read-only) | judge | opus | xhigh |
| precisely specified task | worker | sonnet | high |

Every task carries: the three-agent limit across the Mac; no lint, typecheck, build, or test suite by a
subagent (return the commands); the handoff format; the file order above. Ops never makes a hard-to-reverse
or outward-facing change without the owner step of the [Owner list](#owner-list); a reversible repository
setting (M2) is not such a change.

Waves (implementers first, then their judges, so the count never passes three):

| Wave | Units | Verified by | Needs |
| --- | --- | --- | --- |
| 0 | M0 (implementer), M2 (ops), M1 + M4 (one worker) | 1× opus on M0 | nothing |
| 0b | M18 (worker), M3 (ops, read-only), M20 (ops) | 1× opus on M18, M20 | M1 merged (M3's line) |
| 1 | M21 (ops), M22 (implementer), M23 (implementer) | panel on M22 + M23 | M20 merged |
| 2 | M13 (short sweep), then M6, M8, M15 | 1× opus on M13, M6, M15; panel on M8 | Bouncer section U2b, U2c, U3a, U3b-1, U3b-2 merged; s2-s3 N3, N5 for M15 |
| 3 | M9, M10, M17 | panel on M9 + M10; panel on M17 | M8 merged; U3a |
| 4 | M7, M14, M16 | 1× opus each, with screenshots | M0, M13, M15; the N6 order |
| 5 | M11, M12, M19 | panel on M11; 1× opus on M12 | schema 34 merged; M18; the build to submit |
| 6 | M24, M25, M5a (worker) | panel on M24 + M25 | M11, M23, plan 0035 J1 and H; s2-s3 N2–N4 |
| 7 | M5b (ops, owner go), M26 (ops, owner go), M27, M28 | architect on M26; panel on M27 + M28 | data volume; owner go |
| 8 | M29, M30 | panel on M27–M29 combined | M28 |

Handoff format (every agent returns exactly this): `Unit`, `Base revision`, `Files changed` (absolute
paths), `Interface`, `Tests added` (names; "not run" or "cheap check run: <command>"), `Validation
commands for the top-level agent`, `Deviations from the plan`, `Open questions`, `Risks seen`. A judge
returns, per acceptance criterion, PASS, FAIL, or UNVERIFIED with `file:line` evidence, the
counter-example it tried, and a severity.

## Release grouping

| Release | Units | Upgrade notes and checks |
| --- | --- | --- |
| No version (documents, repository, operations) | M0, M1, M2, M3, M4, M5, M18, ADRs 0042–0044, this plan | Merge to `main` as docs |
| From merge on (release tooling) | M20, M21, M22 | The first release after M20 must show an attestation and an SBOM for each artifact of D11 (M30) |
| The first coordinated release after the Bouncer section (with s2-s3 R1 if merged before its preparation; else the next) | M6, M8, M9, M10, M13, M15, M16, M17, and M7 | Feed v3 (an old reader shows "Update Apassy"); the notifier event; frame fills (Chrome Web Store review); the watch and the iPhone together for several vaults |
| The same or the next | M14 | Screenshots of every view in light and dark |
| App Store submission | M19 | The build of the release that holds M7 and M16; the owner submits |
| The release that carries vault schema 35 | M11, M12 | Every Mac and iPhone of a vault update together; a schema-35 vault does not open in an older app |
| Contributions | M24 (switch hidden until ADR 0043 §9 holds), M25 (service) | The switch shows in the first release after the privacy text and the endpoint are live |
| Base model | M26 | `apassy-base-v2` in shadow mode |
| Last | M27, M28, M29 | Connectors; `docs/goal.md` changes |

Every release bumps all six components to one version and passes `python3.12
scripts/check-release-versions.py` (AGENTS.md).

## Interface notes for the push gateway plan

- **0037-30 Notification Service Extension with a sealed summary.** `push-gateway-v1` (s2-s3 N0, N5)
  stays a fixed payload and refuses unknown fields; a later `push-gateway-v2` adds one optional field
  `sealed` (base64url, at most 2048 bytes, an envelope sealed by the node to the vault's question key,
  relay-questions-v1 §5.1) that the gateway copies unread into the APNs payload with
  `mutable-content: 1`, and a Notification Service Extension of the iPhone app opens it with the key from
  the App Group keychain or leaves the fixed text.
- **0039-2 Push to the watch.** The watch registers its own handle (`POST /v1/handles` with `bundle_id =
  com.wydrox.apassy.companion.watchkitapp` and its APNs token) and `PUT /v1/push/handle` with the
  replica's relay key; the gateway accepts the watch bundle id as a second APNs topic from a fixed
  allow-list; the node pushes to a `watch` device only for access requests, never for run questions.

## Owner list

Only the owner can do these. Everything named is prepared by the unit in brackets.

1. **App Store submission** [M18, M19]: enter the listing, the App Privacy answers, the age rating, and
   the export compliance answers in App Store Connect; upload the screenshots; submit the iPhone build
   (with the watch app) for review.
2. **Export compliance (legal)** [M18 `export-compliance.md`]: confirm the classification; choose France
   (file the ANSSI declaration, or leave France out at first); keep or change
   `ITSAppUsesNonExemptEncryption` (a one-line follow-up in `project.yml` if it changes).
3. **Privacy policy texts (legal)** [M18, M10, M24]: approve and merge the draft pull requests of
   `site/src/pages/privacy.astro`: the iPhone and Apple Watch section, the frame-fill sentence, the
   base-model contribution section.
4. **Chrome Web Store** [M10, M20]: submit the extension version with frame fills (the attested zip).
5. **Hosted teams** [M3, Appendix B]: send the notice if a team with content is not the owner's own;
   decide the deletion and run it (`admin delete`, no undo), after the condition of D14.
6. **Contribution service go-live** [M25]: the deploy to `ottervibe` and the switch-on of a new service
   that receives user data (ADR 0043 §9 items 3–4).
7. **Paid runs** [M5b, M26]: a `devbox-x86` session for the Headscale check (about 1 hour), and the
   training session for the base model (devbox or GPU; the cost estimate comes with M26's plan).
8. **Physical checks on the owner's devices**: M8 (a hardware click uses the window; a synthetic click
   and VoiceOver lead to Touch ID); M9 (the CLI confirm panel; Universal Control leads to Touch ID); M6
   (the access-request banner and its click); M10 (a real same-site sign-in frame in Helium); M14 (the
   dark appearance of every view); M16 (two vaults on a physical watch).

Not owner-only: archiving `wydrox/apassy-relay` (reversible, M2), the read-only inventory (M3), the
mockup (M0), and every merge after a green ready run.

## Risks

| Risk | Mitigation |
| --- | --- |
| Schema 35 must land after 27–34 (U3a, N3, plan 0035, s4, s5, s6, s7); a sibling plan slips | Favorites wait; the top-level agent renumbers only if a lower number stays unused; the two local tables are small and fixed here |
| The hardware-input fields differ on real hardware | The predicate fails closed (more Touch ID, never less); the physical check of item 8 confirms the values |
| An `unsafe` crate in a codebase that forbids it | One small crate, `deny(unsafe_op_in_unsafe_fn)`, SAFETY notes, a source scan that no other crate has `unsafe`, a judge panel |
| Frame fills help a clickjacking page | Same site only, ancestors from the browser, both origins in the owner check, the frame must match the login; cross-site keeps the own-tab route |
| App Review rejects a companion that needs a Mac (guideline 4.2) or reads a call to buy (3.1.3(f)) | The demo video and clear review notes; the no-purchase check in CI; if rejected for 4.2, a later unit "New vault on this iPhone" (not in this plan) |
| The export answer `NO` is not right for the App Store build | The owner's legal check of item 2 before submission; the inventory of A.3 |
| Reproducible images depend on Debian packages | No `apt-get` in the runtime stage; base images by digest; the macOS app is checked against attested CI binaries, not rebuilt |
| The Chrome Web Store changes files in the package | The check ignores only `_metadata/`, `key`, `update_url`; any other difference is reported, not hidden |
| Many plans edit the same workflows and docs | The table of one editor per shared file; small separate blocks; M1 first for the trust model |
| Contributions identify a person | Skeletons without free text, `k = 5`, yearly ids, no address, owner review of each batch, the adversarial corpus, a judge panel; the switch stays hidden until the gate |
| A plugin manifest leaks fields or calls a state-changing GET | `GET` only, the owner sees fields and operations at install, the token goes only to the item's hosts, production asks |
| Several watch vaults drain the battery | At most 4; polls only while the app is active; no background work |
| A public health workflow fails without anyone seeing it | The notice goes to the committer of the cron line (the owner's identity); the old workflow stays until two green runs here |
| The deletion of hosted team files cannot be undone | Owner-only, after the condition of D14, with a backup first and the backup retention named |

## Not verified in the code

- The exact values of `kCGEventSourceUnixProcessID` and `kCGEventSourceStateID` for a hardware click on
  this Mac, and whether a process can post an event with the pid field set to 0 (physical check, item 8).
- Whether `location.ancestorOrigins` in Chrome and Helium is masked by a parent's referrer policy for
  the frame fixtures (M10 tests decide; a masked entry refuses).
- `Context::accesskit_node_builder` and the AccessKit request path in egui 0.36.2 beyond
  `response.rs:184` and `context.rs:1470-1481`.
- Cloudflare's analytics retention for the user-agent check of D17.
- The App Store screenshot sizes for the watch at the time of upload (A.5 names the expected ones).
- The Chrome Web Store CRX download URL parameters for the current store (M22 tests with a fixture; the
  live run decides).

## Appendix A — App Store material

Unit M18 writes these into `docs/store/app-store/`. Values are chosen by this plan; the owner can change
them before submission.

### A.1 Listing

| Field | Value |
| --- | --- |
| Name | Apassy |
| Subtitle (≤ 30) | Secrets for coding agents |
| Category | Developer Tools; secondary Utilities |
| Price | Free. No In-App Purchase |
| Age rating | 4+ (no objectionable content; websites open in Safari, not in the app) |
| Support URL | `https://github.com/wydrox/apassy/issues` |
| Marketing URL | `https://apassy.wyderka.cc` |
| Privacy policy URL | `https://apassy.wyderka.cc/privacy` |
| Keywords (≤ 100) | `password manager,passkeys,autofill,secrets,api keys,totp,2fa,agents,developer,vault` (M18 counts) |
| Description | What the app is (the iPhone part of Apassy for the Mac), the vault on the iPhone with Face ID for every secret, AutoFill of passwords, codes, and passkeys, answering agent requests from the Mac with Allow Once or Deny, the Apple Watch for access requests, open source (Apache-2.0), no account, no ads, no analytics |

### A.2 App Privacy answers

- **Tracking:** No.
- **Identifiers → Device ID:** collected when the owner allows notifications: the APNs device token goes
  to the Apassy push service (today the relay's Worker, later the push gateway). Purpose: App
  Functionality. Not linked to the user (no account). Not used for tracking.
- **Other Data:** device names and device public keys, sent to the hosted relay when the owner uses relay
  sync or relay questions. Purpose: App Functionality. Not linked. Not used for tracking.
- **Not declared as collected:** encrypted vault copies, sealed questions, answers, and feeds. They are
  end-to-end encrypted; the developer cannot read them. Declaring more is always allowed; chosen by this
  plan, the owner can change it.
- **Not collected:** contact info, health, financial info, location, contacts, user content, browsing and
  search history, purchases, usage data, diagnostics (no crash or analytics SDK), sensitive info.
- **Review at stage 7:** a Connect account adds Contact Info → Email (linked, App Functionality).

### A.3 Export compliance inventory and draft answers

| Use | Algorithms | Implementation |
| --- | --- | --- |
| Vault at rest | AES-256 (SQLCipher 4 defaults: AES-256-CBC with HMAC-SHA512, PBKDF2-HMAC-SHA512; ADR 0003 forbids weaker settings) | SQLCipher with vendored OpenSSL in the app (iPhone); CommonCrypto (watch) |
| Relay transport | TLS 1.2 and 1.3 | rustls with ring in the app (iPhone core); URLSession (watch) |
| Questions, feed, access requests | ChaCha20-Poly1305 sealing with the question key (relay-questions-v1 §6) | ring in the app; CryptoKit `ChaChaPoly` on the watch where used |
| Device and answer keys | ECDSA P-256 | Secure Enclave (CryptoKit) and ring |
| Passkeys | ES256, ES384, EdDSA, RS256 signatures | the app's core |
| One-time codes | HMAC-SHA1/256/512 | ring |
| Wi-Fi companion | TLS 1.3 with a pinned certificate | Apple frameworks |

Draft answers for the owner's legal check (item 2): the app uses encryption; it implements standard
algorithms in addition to Apple's; it implements no proprietary algorithm; its main function is
information security, so the "authentication only" exemption does not apply; its source is published
under Apache-2.0. The France question and `ITSAppUsesNonExemptEncryption` are the owner's call. This
inventory is a fact sheet, not legal advice.

### A.4 Review notes

- Apassy for iPhone is the phone part of the Apassy Mac app. It is free; it needs no account.
- To try it without a Mac: the demo video (M19) shows the full flow with demo data. With a Mac: install
  Apassy from `apassy.wyderka.cc`, make a vault, then open it on the iPhone through iCloud Drive or
  "Add a device…".
- Face ID guards each reveal, copy, and AutoFill fill. The camera only scans the Mac's code. Local
  Network is only for the Wi-Fi pairing with the Mac (remove this line when s2-s3 W2 removes the
  companion).
- The Apple Watch app answers access requests of a connected Mac with Allow once or Deny.
- The app has no purchase, no price, and no link or instruction to buy.

### A.5 Screenshots

iPhone 6.9-inch (1320 × 2868, portrait), demo data only, status bar set with `xcrun simctl status_bar`:
1 Vault list; 2 credential page (masked password, code tile); 3 AutoFill sheet in Safari; 4 Requests with
a waiting question (Allow Once, Deny); 5 Agent Access; 6 Watchtower; 7 Settings (D5 grouping); 8 Lock with
Face ID over the cover. Apple Watch (the sizes App Store Connect asks for at upload, expected 416 × 496 and
422 × 514): 1 Requests; 2 request detail with Allow once and Deny; 3 This Watch with its vaults.

### A.6 No In-App Purchase

[plans.md](../product/plans.md) §3: "The iPhone shows the plan only. There is no In-App Purchase." App
Review guideline 3.1.3(f) lets a free stand-alone companion of a paid web service skip In-App Purchase
only with no purchase inside the app and no call to action to buy outside it. So no iPhone or watch text
has a price, "Upgrade", "Subscribe", "Buy", a link to a checkout or a pricing page, or an instruction to
buy on the Mac. A plan row shows only the plan name and its state. `scripts/check-ios-no-purchase.py`
(M19) checks this in CI. The [stage 7 plan](implementation-plan-s7-connect.md) §6 applies the same rule
to the Connect plan row; M19's word list is shared with it.

## Appendix B — Draft notice to owners of hosted teams

Sent by the owner only, and only to owners of teams that M3 finds with team content and that are not the
owner's own. Placeholders in angle brackets.

> Subject: Apassy hosted relay: your shared team vault
>
> Hello,
>
> your team "<team>" on the hosted Apassy relay (`apassy-relay.wyderka.cc`) has a shared team vault.
> Since Apassy 0.5.14 the hosted relay no longer serves shared team vaults or the team proxy. Relay sync
> and iPhone questions are not affected.
>
> The team's files are still on the relay, encrypted with keys that only your team's key holder has.
> Nobody at Apassy can read them.
>
> You can:
> 1. Run the team on your own node. When that is available, your key holder can move the team file
>    there. We will write to you when it is.
> 2. Tell us that you do not need the files. We then delete them.
>
> We delete the files no earlier than 60 days after the message that your own node can import them.
> The deletion cannot be undone.
>
> Questions: reply to this message.
>
> <owner name>, Apassy
