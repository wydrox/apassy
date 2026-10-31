# Independent review of extension suggestions, PR 29

Reviewed [PR 29](https://github.com/wydrox/apassy/pull/29) starting at `972fb6307c876adc156d9b3ab2f58a3c1c43abb9`. Read the PR description, changes against `origin/main`, suggestion audit, visual audit, design mockup and all 86 implementation state screenshots through their six contact sheets. The popup, Google and small-viewport fixes were also inspected in full-size paired captures. This review does not merge or mark the draft ready.

## Confirmed findings and fixes

| Severity | Location in repaired source | Confirmed by | Fix |
| --- | --- | --- | --- |
| P2 | `extension/popup.js:430` | Helium `form.requestSubmit()` generated a trusted submit event and reached the save transport without a trusted choice. Before-fix receipt: `review/before/smoke-results.json`. | Save/create use the submit button's trusted activation. Scripted submit events are always prevented; real Enter still works. The app owner check remains mandatory. |
| P2 | `extension/popup.js:688` | Synthetic checkbox `.click()` reached `chrome.permissions.request`; its resulting change event was trusted. Before-fix receipt: `review/permission-before/smoke-results.json`. | Passkey and suggestion switches accept trusted click events only, canceling synthetic activation. The broad permission button already had its trusted-click gate. |
| P2 | `extension/login-suggestions.js:446` | The document keyboard listener accepted page-generated ArrowDown/Escape and could focus/dismiss the closed-root menu. CDP regression verifies both are refused. | Keyboard and pointer navigation handlers reject untrusted events. Account activation retains its independent trusted-event check. |
| P2 | `extension/popup.css:211` | Supplied popup screenshots and row geometry: the focus border excluded the details action and right padding was uneven. | Focus border and tint cover the full row, with 8px padding around its actions; Fill cannot shrink. |
| P2 | `extension/login-suggestions.js:91` | Supplied Google screenshot and explicit `r.right + 4` placement. New light/dark captures show containment. | Icon sits inside the field with a 6px inset. Narrow/clipped/occupied fields and populated passwords hide it. Text measurement and hit testing avoid site content; input changes refresh visibility. |
| P2 | `extension/popup.js:227` | Three-account CDP regression: after filtering, arrow wrap targeted a hidden account and stalled. | Keyboard navigation includes visible rows only. |
| P2 | `extension-tests/tests/passkey-bridge.spec.mjs:28`; `fixtures/login-journey/{target,worker}.unit.mjs` | Static browser-test review found expectations that all scripts disappear with passkeys off. Node execution found 14 failing login fixture checks caused by missing DOM/storage/permission APIs. | Passkey assertions select passkey registrations and also preserve the login script. Updated the synthetic DOM and worker APIs; all 26 login-journey Node tests pass. |

## Checklist evidence

- **Secrets and owner authority:** metadata is reduced to item/title/username in `login-worker.js`; popup metadata has the existing nonsecret TOTP capability flag. Closed-root content is absent from page `innerText` and `shadowRoot` is null. `ownerAction` and `choose` refuse untrusted activation. App fill/save/create/update paths still request an owner check, and completion requires `OwnerProof`. The 25 app-controller tests cover fresh checks, cancellation, wrong site/account, stale revision, dropped tickets and no secret delivery before approval. Source inspection found no new secret storage, logging, clipboard or remote-request path. Typed save/update values travel through the existing native-memory path, never suggestion metadata or popup fields.
- **Origin/form/frame binding:** `handleLoginField` checks browser sender ID, document lifecycle/ID, frame ID, sender origin and top-tab origin. `targetCall` rechecks the exact document and `self.origin`; targets retain their URL, nodes, form action and signatures. Same-origin blank/srcdoc metadata passes in real Helium frames. Opaque/cross-origin senders fail in unit fixtures; cross-origin form actions fail in Helium. The no-action inherited-origin case does not authorize a cross-origin action. Passkeys and code fills retain their original separate checks.
- **Defaults/migration:** Helium verifies fresh-site default-on suggestions after a broad grant, autofocus on injection/reload/re-enable, exactly one broad registration after replacing a legacy registration, persistent per-host exclusion and global disable. No duplicate login registration remains in the fixture.
- **Detection/empty states:** associated-label username detection passes; search, OTP, hidden, readonly, newsletter and text-displayed-password negatives pass. Username miss and site-empty/missing-Website guidance are distinct.
- **Domain matching/dependencies:** eight site tests and the encrypted owner-store regression pass, including Unicode/punycode, ICANN/private suffixes, sibling refusal, www boundaries, strict ports and HTTPS. All 24 new locked crate versions have bundled notices; all 32 license text files exactly match cached crate sources. No `deny.toml` exists in this repository. [rust-url/IDNA](https://github.com/servo/rust-url) and [PSL](https://github.com/addr-rs/psl) are not archived; GitHub API readback showed pushes on 2026-10-30 and 2026-10-23 respectively. The original-head RustSec CI job passed. These are pinned local tables, without matching-time network access.
- **Visuals:** inspected all 86 original and 86 new state captures through contact sheets, with full-size affected pairs. No additional confirmed contrast/layout defect beyond the repaired shared row/icon behavior. GitHub, Google and Vercel checks verify menu/action separation and icon containment or hiding. The 390×420 and long/many-account fixtures retain bounded lists and metadata truncation.
- **Playwright files:** read all six changed test files and the shared fixtures without importing or running Playwright. Updated stale passkey registration expectations; existing copy/details/Settings selectors correspond to the new UI. GitHub CI currently has no browser execution job, so its status cannot qualify these browser tests.

## Executed checks

All Cargo commands used `CARGO_TARGET_DIR=/Users/rafalw/Dev/.target-review29 CARGO_INCREMENTAL=0`. Initial free space was 14 GiB and remained above 6 GiB. The target directory was removed after the last Cargo command; final free space was 14 GiB.

| Command | Result |
| --- | --- |
| `cargo test --offline --locked --all-features --lib browser:: -- --test-threads=1` | 39 passed, including site and owner-store browser tests |
| `cargo test --offline --locked --all-features --lib desktop::ui::browser_tests:: -- --test-threads=1` | 25 passed |
| `cargo clippy --offline --locked --all-features --all-targets -- -D warnings` | Passed |
| `cargo clippy --offline --locked --all-targets -- -D warnings` | Passed |
| `node --test extension-tests/fixtures/login-journey/*.unit.mjs` | 26 passed |
| `node extension-tests/cdp/suggest-smoke.mjs /Users/rafalw/Dev/apassy/docs/reviews/audit-2026-10-31/impl-extension/review` | 36 passed, Helium CDP 9371 |
| `cargo fmt --all -- --check`; changed JS syntax checks; extension source gate; `git diff --check` | Passed |

The broader passkey Node suites could not load `@simplewebauthn/server` in this worktree. No package installation or Playwright execution was attempted to resolve that dependency. Login fixtures failed first, were repaired, and passed on rerun; the missing passkey dependency is a verification limit rather than a confirmed product failure.

## Evidence and limits

Local artifacts are in `/Users/rafalw/Dev/apassy/docs/reviews/audit-2026-10-31/impl-extension/review/`: 86 state PNGs (43 light/dark pairs), six contact sheets, `capture-manifest.json` with dimensions/SHA-256, `smoke-results.json`, and `cleanup.json`. The final scratch Helium PID was 37759, exited with code 0; its profile was deleted and port 9371 had no remaining listener. Only the harness's own browser was closed. Ports 9222/9223 were not used.

The mock native host received zero fill/save/create/update requests. Trusted popup save and inline approval outcomes use nonsecret transport fixtures; other popup result variants are render fixtures. Public pages were loaded and focused only. Native Touch ID, the running owner app, authenticated sign-in, screen readers, store acceptance, and the unexecuted Playwright suite remain unverified. The owner's profile, vault, keychain and app were untouched.

`gh pr checks 29` showed no failed check on the original head; some jobs were still running. `gh run view 41207668360 --log-failed` reported that logs were unavailable until completion. Pushing the review commits starts a fresh CI run; the handoff must report that head's actual status without treating the original-head passes as current-head acceptance.
