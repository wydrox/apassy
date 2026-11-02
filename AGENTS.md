# Apassy releases

- Every release bumps all six components together to one new version: iOS app,
  macOS app, Linux CLI (`apassy-team`), browser extension, relay, and website.
  This applies even when a component has no functional changes. Never publish a
  same-version rebuild as a new release or leave components on different versions.
- Update `release-versions.json`, app/core Cargo manifests and lockfile, iOS
  `MARKETING_VERSION`, extension manifest, and dated changelog together. The website
  derives its version from the changelog. The relay is the crate `crates/apassy-relay`
  of this workspace (ADR 0037); its package version, with the edge Worker package,
  also versions the Linux CLI. Its own rules are in `crates/apassy-relay/AGENTS.md`.
- Run `python3 scripts/check-release-versions.py` with Python 3.12 before publication.
  Local source checks do not prove publication.
- iOS `CURRENT_PROJECT_VERSION` / `APASSY_IOS_BUILD` is an upload build number,
  separate from the shared marketing version. Check App Store Connect for a usable
  higher build number; incrementing it alone is not a new release.
- Verify each delivered artifact and live version: signed macOS download and
  `latest.json`, processed TestFlight build and intended group, public extension
  listing/package, Linux download/checksum/version, running relay version, and live
  website/changelog. Pending store review is not published.
- Do not report a complete release until all six are live at the shared version.
  If blocked, identify each unfinished component, its actual version, and the blocker.

# Pull requests and CI

- Open each pull request as a draft (`gh pr create --draft`) and keep it a draft
  while you still push fixes. Mark it ready (`gh pr ready`) when the work is
  complete; that runs the full suite, macOS test groups included.
- A draft run skips the macOS test groups because the account has five macOS
  runners for all runs. A green draft run is not a green PR: merge only after the
  run of the ready PR succeeds.
