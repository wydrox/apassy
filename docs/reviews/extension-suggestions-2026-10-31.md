# Extension suggestion implementation verification — 2026-10-31

Base: `6759f32022e6435ecb60aaba7fdd5d04e4c83e36`. Scope: browser suggestions, strict site matching and the supplied popup/inline redesign. Versions are unchanged. The owner decision is recorded in ADR 0021.

## Behavior and regression evidence

| Requirement | Check |
| --- | --- |
| Default suggestions on every granted site; existing broad grants need no extra setup | Helium CDP: fresh site after broad grant; one trusted popup permission click; single broad registration |
| Migrate per-host registrations; global switch; per-site exclusions | CDP: replace a legacy registration, assert one broad registration; disable globally; exclude and reload one site, then re-enable its focused field |
| Already-focused fields and label-only username fields | CDP: neutral `f1` with an associated label, autofocus before injection, reload, re-enable |
| Search, OTP, hidden, readonly, newsletter and text-password negatives | CDP: detector results are false for all six controls |
| Empty reasons | CDP: prefix miss says no username match; site-empty state has separate, conditional missing-Website guidance and Show all recovery |
| IDN and suffix matching | Rust site tests cover Unicode/punycode both ways, ports, HTTPS, private/ICANN suffixes, sibling refusal and the www/public-suffix boundary; encrypted owner-store test covers imported Website details and missing Website |
| Frames and refusal messages | CDP: same-origin srcdoc/about:blank actually display metadata; cross-origin sender is refused; cross-origin form action displays an explanation without a native request |
| Trusted choices and keyboard | CDP: untrusted popup and inline clicks send no fill; trusted inline mouse/Enter use a nonsecret transport fixture; arrows and Escape work; automatic success collapse preserves page focus |
| Popup and inline design | Paired light/dark state captures; metadata search; bounded account lists; details/update route; chosen-account approval context; visible input borders |
| Positioning | CDP and screenshots: GitHub, Google and Vercel menus have zero overlap with visible page actions. Long/many-account and 390×420 viewport fixtures are also captured. |

## Commands and results

All Rust commands use `CARGO_TARGET_DIR=/Users/rafalw/Dev/.target-extension CARGO_INCREMENTAL=0`. Free space was checked before builds and stayed above the required 6 GiB floor.

- `cargo test --offline --locked --all-features --lib browser:: -- --test-threads=1`: **39 passed**, including the eight site tests and encrypted owner-store regression.
- `cargo test --offline --locked --all-features --lib desktop::ui::browser_tests:: -- --test-threads=1`: **25 passed**. These are headless app-controller fixtures, not live owner checks.
- `cargo clippy --offline --locked --all-features --all-targets -- -D warnings`: **passed**.
- `cargo fmt --all -- --check`, JavaScript syntax checks and `git diff --check`: **passed**.
- An occupied-port guard was checked with a temporary listener: the runner refuses port 9361 before creating a profile or starting Helium.
- The extension source gate from CI was checked without loading the Playwright test module: **passed**.
- `node extension-tests/cdp/suggest-smoke.mjs /Users/rafalw/Dev/apassy/docs/reviews/audit-2026-10-31/impl-extension`: **25 checks passed** on isolated Helium, CDP port **9361**. The JSON receipt is in that directory.

Existing Playwright tests were updated for the new copy, account details and Settings route by reading them. They were syntax-checked but **not run locally**. No Playwright module was imported. Ports 9222 and 9223 were not used.

## Evidence and limits

Screenshots: `/Users/rafalw/Dev/apassy/docs/reviews/audit-2026-10-31/impl-extension/`. `capture-manifest.json` records PNG dimensions and SHA-256 hashes. `smoke-results.json` records each assertion. Paired popup/inline states and all three live-page pairs were visually inspected; QA contact sheets are alongside them. The original target is `../extension-redesign-mockup.html` in the parent audit directory.

The native host is the repository's mock, installed only inside a scratch browser profile. Metadata is synthetic. Popup approval/result variants are render-state fixtures; inline waiting/success/cancellation use a delayed nonsecret message-transport fixture. The run sends **zero native fill/save/create/update requests** and never fills a password. Public sites are only loaded and focused. This does not prove native Touch ID, the separate owner-check-window branch, screen-reader behavior, authenticated sign-in or production/browser-store acceptance.

The full public-page pass waits for visible, writable SPA fields before focusing them. Early harness attempts encountered a Google selector mismatch and Vercel readiness timing; neither is reported as a product regression. The final pass succeeds on all three pages.

The post-submit save banner remains a follow-up. It needs a reviewed navigation/form/secret capture lifecycle; submitting alone cannot establish sign-in success. When no safe inline space exists, the chooser collapses to the field affordance/toolbar instead of covering page actions. Missing Website guidance remains conditional because a site-empty reply cannot identify which unrelated vault item lacks a Website.

No owner profile, vault, keychain or running app was used. Scratch browser processes/profiles and the dedicated Cargo target were removed after verification. No merge or release action is part of this change.
