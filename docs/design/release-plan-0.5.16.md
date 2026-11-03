# Release plan — 0.5.16

Date: 2026-11-03. Status: IN PROGRESS. The owner widened the scope on 2026-11-03: cloud agents, the
Bouncer section, the iPhone demo mode, the privacy manifests and the store texts are in 0.5.16 (see
§2 "In: added by the owner"); the later stages ship as 0.5.17 and later. The owner asked to accept
nothing in between, so gates G0, G1 and G2 are closed by that decision; G3 to G5 list what only the
owner can do.

## 1. Outcome

All six components are live at 0.5.16 (AGENTS.md): the signed macOS download and `latest.json`, a
processed TestFlight build in the group "Apassy", the public Chrome Web Store listing, the Linux CLI
on `/dl` with its checksum and `--version`, the running relay, and the website with its changelog.
A store review that is still open is PENDING, not published.

0.5.15 went out only partly (see [release](../operations/release.md), 0.5.15). The relay, the Linux
CLI and the extension go from 0.5.14 straight to 0.5.16. The iPhone goes from the internal test build
0.5.15 (29895036) to 0.5.16.

## 2. Scope

### In: merged on main, not released (since the 0.5.15 build 4fd3f9f)

| Change | PR or commit | Schema |
| --- | --- | --- |
| Apple Watch app for access requests (ADR 0039) | #81, #82 | vault 24 |
| Passkeys ES384, EdDSA, RS256, PRF, large blob; full Credential Exchange import; Find duplicates | 8f9e7378, fa0b3f37 | vault 25 |
| Agents and Decisions of every Mac of the vault, scope bar | #88 | — |
| Bouncer decision log, "Why Apassy asked you", `apassy decisions log` | #91 | — |
| Credential page and list audit; one definition of duplicates | #83, 36993af5 | — |
| iPhone asks for Face ID over the app cover before the passphrase field | #90 | — |
| Plans: self-hosted is free, Connect is paid (docs and app texts) | #84 | — |
| Relay: configurable push timeout, guide and onboarding text | 6c65992d, 649792d1 | none (team 6, directory 1003) |

### In: new work (defects known on 2026-11-03)

| Id | Defect | Source |
| --- | --- | --- |
| F1 | The bouncer still asks the owner for almost every run. The bouncer brain is healthy (task match 0.84 to 0.96), so an earlier hard rule (host, hook, declaration or project) probably sends the run to the owner. | Owner report, 2026-11-03 |
| F2 | The installed Mac app uses about 31% CPU, with about 12 SkyLight display queries a second: the window probably repaints all the time. | Measured 2026-11-03 |
| F3 | A Mac that opened another Mac's feed and later fails to open it keeps the old feed and shows no "Sync…" state. | Known limit of #88 |
| F4 | ADR 0031 and `src/broker/run.rs` (the production default near lines 443–455) do not agree. | Known limit of #88 |
| F5 | Extension Node model tests fail now and then on Linux: 214 and 215 on main at fa0b3f37 (fixed by 9e94c4eb), and 203 "a credential outside the allow list is refused" on #89. | CI |
| F6 | Nothing tests the OpenSSH form of an Ed25519 key with `ssh-keygen`. | Note of the passkey work |

### In: added by the owner (2026-11-03)

- **Cloud agents** (#85, #86, #87, #89, #92; vault schemas 26 and 27; Funnel on 8443), with the
  Bouncer section (`implementation-plan-bouncer-section.md`) and the review fixes of panels A, B and
  C.
- **iPhone demo mode** (Try the Demo, See a Sample on the watch), **privacy manifests**, the export
  compliance answer and the App Store texts (`docs/store/app-store/`).

### Out: 0.5.17 or later

- ADR 0035 waves 2 to 5, ADR 0037 stages 3 to 8, ADR 0011 stages 2 to 7, the open parts of ADR 0019
  and ADR 0022, the removal of the Wi-Fi companion (after ADR 0037 stage 2), Connect and Stripe.

## 3. Owner gates

| Gate | The owner decides | Before |
| --- | --- | --- |
| G0 | This plan: the scope, and cloud agents in 0.5.17 | Any agent starts |
| G1 | Test builds from main on the Mac mini, the MacBook and the iPhone and watch (TestFlight internal group), after vault backups. This moves the real vaults from schema 24 to 25, and a schema-25 vault cannot go back. | D1 reads the real decision log |
| G2 | F4, if the fix changes what the broker does (not only the ADR text) | I1 changes the production default |
| G3 | The physical acceptance session (section 7), with the owner's devices | Release prep ends |
| G4 | The exact relay image digest and the backup, before the compose change on `ottervibe` | O1 deploys |
| G5 | TestFlight 0.5.16 to the group "Apassy", and the Chrome Web Store submission | O2 and the top-level agent publish |
| G6 | Rotate the Claude Code agent token, which a session transcript printed on 2026-11-03 (`apassy agent rotate "Claude Code"`, then both wrapper scripts). After the release: rotation restarts the MCP connection of every running Claude Code session. | After wave 5 |

G4 and G5 can be one answer ("release go").

## 4. Agents

Twelve subagents. Model and effort are always set explicitly (owner convention).

| # | Id | Wave | agentType | model | effort | Unit |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | D1 | 1 | debugger | opus | xhigh | F1: root cause of the over-asking bouncer |
| 2 | D2 | 1 | debugger | opus | xhigh | F2 repaint, F3 stale feed |
| 3 | J1 | 1 | judge | opus | xhigh | Release review of 4fd3f9f..main, and F4 |
| 4 | I1 | 2 | implementer | opus | high | F1 fix (and F4 after G2) |
| 5 | I2 | 2 | implementer | opus | high | F2 and F3 fixes, J1 findings outside the broker |
| 6 | W1 | 2 | worker | sonnet | high | F5 and F6 |
| 7 | J2 | 3 | judge | opus | xhigh | Panel on the wave 2 diff |
| 8 | J3 | 3 | judge | fable | xhigh | Panel on the wave 2 diff, independent of J2 |
| 9 | W2 | 4 | worker | sonnet | high | The 0.5.16 version bump, changelog, release notes, store texts |
| 10 | O1 | 4 | ops | opus | high | Relay image, Linux CLI, Worker `/dl` and guide: plan, then deploy after G4 |
| 11 | O2 | 4 | ops | opus | high | TestFlight and Chrome Web Store: plan, then delivery after G5 |
| 12 | J4 | 5 | judge | opus | xhigh | Read back all six live components |

A fix after a review goes back to the same implementer (SendMessage), not to a new agent.

### Limits for every agent (copy into every task)

- At most three implementation or validation agents run at once on this Mac, across all sessions.
  The cloud-agents thread runs its own workers. Before each wave the top-level agent counts the
  running agents of all threads (`t3_thread_list` with subagents) and starts at most three minus
  that count. The others wait.
- Subagents never run lint, typechecks, builds, `cargo test`, `cargo nextest` or full suites, also
  not through `heavy-check`. They return the exact commands. A cheap check runs only when the
  top-level agent names it in the task.
- No push, no merge, no tag, no change on `ottervibe`, App Store Connect, the Chrome Web Store,
  Tailscale or DNS without the gate of section 3. Ops returns a plan first.
- Docker only on `devbox-arm` or `devbox-x86` with the architecture named; never Colima, never the VPS.
- Browser work only in Helium on CDP port 9223; never port 9222, never Playwright.
- Each agent works in its own worktree off main. One editor for each file (section 5). The top-level
  agent owns `CHANGELOG.md`; agents return their changelog lines.

### Handoff format

Every agent returns: `Unit`, `Base revision`, `Files changed` (absolute paths), `Interface`,
`Tests added` (names; "not run" or "cheap check run: <command>"), `Validation commands for the
top-level agent`, `Deviations from the plan`, `Open questions`, `Risks seen`. A judge returns, per
acceptance criterion, PASS, FAIL or UNVERIFIED with `file:line` evidence, the counter-example it
tried, and a severity.

## 5. Waves

### Wave 0 — top-level agent, after G0

1. Merge this plan and the status cleanup (this PR).
2. Start a signed test build of main with `release.yml` (`ci_run_id=provider-check`, on a temporary
   branch). After G1: back up the vaults, install the build on the Mac mini and the MacBook, and
   upload a TestFlight internal test build from the same commit
   (`~/.local/bin/heavy-check scripts/ios-testflight.sh` with the three profiles).

### Wave 1 — find (3 agents)

- **D1 (F1).** Input: `apassy decisions log --asked` and `~/Library/Logs/Apassy/bouncer-decisions.log`
  from the test build, plus synthetic runs with item 92 (`APPLE_WATCH_TEST_SYNTHETIC`). Find the rule
  that sends a run to the owner, with `file:line`. Write a failing synthetic test (not run). Propose
  the fix. Acceptance: the root cause explains each `--asked` reason of the last day by count; the
  test fails on main for that reason. Without G1, D1 works from the code and synthetic vaults only,
  and says so.
- **D2 (F2, F3).** Use `sample` and the egui repaint requests to find what asks for a repaint when the
  window is idle. Find where the feed reader keeps the old value. Acceptance: a named cause for each,
  and a regression test for each (not run).
- **J1 (review).** Read 4fd3f9f..origin/main without docs. Check: the schema 24 and 25 migrations and
  the refusal of newer copies; Macs refuse every run answer from a watch; passkey algorithms, PRF and
  large blob on the iPhone, the Mac sheet and the extension; a duplicate merge loses no value and its
  archive restores; the feed reader keeps the checks of relay-feed-v1 section 7.4; the decision log
  holds no command, user request, purpose or secret; #90; and F4, the production default against
  ADR 0031.

### Wave 2 — fix (3 agents)

- **I1** fixes F1 from D1, and F4 after G2. Owns `src/broker/**`, `src/agent/**` and the bouncer files.
  Acceptance: D1's test passes in the top-level run; no ADR 0031 rule gets weaker without G2.
- **I2** fixes F2 and F3 from D2, and the J1 findings of severity medium or higher outside the broker.
  Owns `src/desktop/**`, `src/questions/**`, `ios/**`, and `extension/` source for J1 findings.
  Acceptance: the idle window uses under 3% CPU in the top-level measurement with `top`; D2's tests pass.
- **W1** (F5, F6). (a) In the extension Node model tests, replace each wait for a fixed number of
  turns with a wait for the event, as 9e94c4eb did, including test 203. (b) Add a regression test
  that converts an Ed25519 key to OpenSSH and checks it with `ssh-keygen -y`, and skips when
  `ssh-keygen` is missing. Owns the extension test files and the new Rust test file. Acceptance: no
  fixed-turn wait is left in those tests (the search command is in the answer); the top-level agent
  runs the extension model tests 20 times in a row without a failure (a cheap check that the
  top-level agent runs).

### Wave 3 — verify (2 agents)

- **J2** and **J3** review the combined wave 2 diff, each without the other's answer. Each FAIL goes
  back to I1, I2 or W1. Then the top-level agent runs one validation pass: it pushes the branch,
  marks the PR ready (full CI, macOS groups included), and merges after the ready run is green.
- After the merge: a second test build for the owner's devices (as in wave 0), and the UI check:
  the top-level agent puts a screenshot of each new or changed view next to its mockup (Decisions
  "Why", scope bar, Find duplicates, credential page, iPhone lock, watch screens in the Simulator).

### Wave 4 — prepare the release (3 agents, beside G3)

- **W2** bumps everything to 0.5.16: `release-versions.json`, the app and core Cargo manifests and
  `Cargo.lock`, `crates/apassy-relay` and the edge Worker package, `MARKETING_VERSION` in
  `ios/ApassyCompanion/project.yml`, the extension manifest, `[Unreleased]` → `[0.5.16]` with the
  date and the upgrade notes (schema 25: update every Mac and iPhone of a vault together; the watch
  needs the iPhone at 0.5.16), the relay changelog, the 0.5.16 section of the release guide, and the
  Chrome Web Store texts. Acceptance: the top-level run of
  `python3.12 scripts/check-release-versions.py` passes.
- **O1** writes the relay plan: the tag `image-release-0.5.16` on the release commit
  (`relay-image.yml` builds the image and both team CLIs), `apassy-relay admin backup`, the compose
  diff on `ottervibe`, the Worker deploy for `/dl` and `guide.html`, the rollback (image
  `image-release-0.5.14` and the backup), and the live checks (`/healthz`; `apassy-team --version`
  from `/dl` prints 0.5.16; `SHA256SUMS` matches). After G4 it deploys and checks.
- **O2** writes the store plan: the highest build number in App Store Connect (above 29895036), the
  three profiles (`APASSY_IOS_WATCH_PROFILE="Apassy Watch App Store"`), the processing check and the
  group "Apassy"; the extension package (`scripts/build-extension-zip.sh`) and the submission in the
  Chrome Web Store dashboard. "URL not reachable" on submit is a known transient error: retry. After
  G5 it delivers. The top-level agent runs the archive and upload through `heavy-check`.

### Wave 5 — publish and read back (1 agent)

Order, after G4 and G5:

1. O1 deploys the relay and checks it.
2. The top-level agent uploads TestFlight from the release PR head after its ready run is green;
   O2 waits for VALID and adds the build to the group. TestFlight goes before the Mac so that an
   iPhone can follow a schema-25 Mac at once.
3. The top-level agent merges the release PR. `release.yml` publishes the DMG and `latest.json`
   (`ci-release-newer.py` allows only a newer version); `site.yml` publishes the website.
4. O2 submits the extension.
5. The top-level agent tags `0.5.16` and `v0.5.16` on the build commit and makes the GitHub release
   from the changelog section. It also tags `v0.5.15` on 4fd3f9f as the record of the published
   macOS build, with no GitHub release, because 0.5.15 was not complete.
6. **J4** reads back all six destinations and reports, per component, the live version, the
   evidence and PASS or PENDING. The release is complete only when all six are PASS. A Chrome Web
   Store review that is still open stays PENDING.
7. G6, then the memory and the release guide get the final state.

## 6. Failure handling

- A FAIL in a review or in the physical session goes back to the implementer of that file. The
  top-level agent runs the next validation pass and makes a new test build; only the failed checks
  run again.
- A defect that takes more than a day: the owner chooses to ship without that fix (it moves to
  0.5.17) or to wait.
- Relay: put back the previous image and the backup. Mac and iPhone: a schema-25 vault does not open
  in an older app, so there is no downgrade; fix forward with 0.5.17. TestFlight: expire the build.
  Chrome Web Store: submit a fixed package.

## 7. Physical acceptance (G3)

The owner does this with the test build of wave 3. The top-level agent records each result in the
release guide.

| Check | Expected |
| --- | --- |
| Watch: pair with Add Apple Watch on the iPhone and the code of the Mac | Safety words match; Touch ID on the Mac confirms |
| Watch on the wrist, unlocked: Allow once and Deny an access request | Allow once gives one use; Deny refuses the agent |
| Watch off the wrist or locked; LTE without the iPhone; Always On; tap on the mirrored notification | Allow once refused; the request arrives over LTE; Always On hides the details; the tap opens the request |
| iPhone lock (#90) | Face ID over the app cover first, then the passphrase field only on failure |
| Mac Touch ID panel (ADR 0038) for vault unlock and an owner check | The Apassy panel, not the macOS dialog |
| PRF and large blob on a WebAuthn PRF test site: iPhone AutoFill, Mac sheet, extension | Same PRF output on each device for the same passkey and salt |
| Imported ES384, EdDSA and RS256 passkeys | Sign-in works |
| Credential Exchange import from Passwords and 1Password on the iPhone | Every item type arrives with the counts of the summary |
| Find duplicates: merge a group, then restore an item from the archive | No value lost; the restore works |
| Two Macs (Mac mini and MacBook): Agents and Decisions with the scope bar | Each Mac shows the other Mac read-only |
| F1: a synthetic run with item 92 | No question, or a question whose "Why" names the reason |
| iPhone access request (ADR 0033): Face ID and the notification | Pending since 0.5.10; record the result |

## 8. Risks

- Schema 25 stops sync with a device on an older app until it updates. Upgrade notes, and
  TestFlight before the Mac (wave 5).
- The cloud-agents thread shares the three-agent limit; waves can wait for it.
- Another session once committed in the shared `~/Dev/apassy` checkout. Every unit uses its own
  worktree.
- A Chrome Web Store review takes days. The release stays PENDING until the listing is public.
