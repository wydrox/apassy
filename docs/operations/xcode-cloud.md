# Manual macOS quality pilot

Status: one manual Cloud pilot passed on
`c6f416653580cf511e548199a469c81282ddc69a` on 2026-11-05. The framework was discovered,
the helper completed all 25 recorded steps, and the framework Build succeeded.
GitHub `macos` remains active. This package publishes no app and replaces no
required GitHub check.

## Measured pilot

Product `ApassyCIPilot`, workflow `Apassy macOS quality pilot`, Build 1 ran on
arm64 after a 15-second queue. The helper took 161.242 seconds; the native report
rounded active Build time to 3 minutes. Expected and actual source SHAs matched.
The host used Xcode 27.2 (27B52), macOS 27.2 (26B123), macOS/watch SDK 27.2 and
the pinned Rust 1.97.0 toolchain. Complete exported logs contained exactly one
matching JSON receipt and the subsequent `BUILD SUCCEEDED` result. Compute-hour
consumption was not exposed in the inspected native reports or logs.

GitHub run [42020717024](https://github.com/wydrox/apassy/actions/runs/42020717024)
ran the same helper successfully on that exact source SHA: 202.807 seconds,
arm64, Xcode 16.4, macOS SDK 15.5 and watch SDK 11.5. Cloud included four extra
bootstrap steps. SDK versions and cache conditions differ, so these raw durations
do not establish a clean speedup. The pilot proves execution of this quality
contract, not equivalence of the other macOS runtime tests or release steps.

Build 1 completed with one traditional-headermap configuration warning. The
project now explicitly sets `ALWAYS_SEARCH_USER_PATHS=NO`; this setting and the
shared Cloud product manifest were recorded after the measured pilot. No second
Cloud run was performed. Cloud execution evidence applies to the SHA above;
GitHub validates subsequent commits separately.

Local evidence is retained outside build directories at
`/Users/rafalw/Dev/apassy-ci-cloud-evidence/2026-11-05/`: `cloud-build-1-quality.json`,
`cloud-build-1-report.md`, exported `cloud-build-1-logs.zip` and
`cloud-build-1-xcresult.zip`, plus `github-head-c6f4166-quality.json`.

## Coverage and identity

The audit baseline is `773f02c2aff5456354776f9ef0bb60e4161800e1`. All existing CI
job identifiers remain. New `portable` uses Ubuntu 24.04, Node 22, Python 3.12 and
Rust 1.97.0/rustfmt. It runs with exactly the existing `reuse-pr` dependency and
reuse condition, including drafts. Whole-workflow success remains necessary for
PR evidence reuse and release consumption. No changes to reuse selection, release,
runner types of existing jobs, Rust test shards, or caches are included.

Moved from `macos`: extension version equality (Python TOML/JSON instead of
`plutil`), Cargo format, P0 Node models, CI-helper/extension-package/notary-retry
Python fixtures, isolated torch-free brain tests and dry-run bench, coordinated
version checks/tests, and whitespace check. The Python helper tests use mocks,
inert Mach-O bytes and temporary repositories; the notary tests fake `xcrun`.
The extension packager already supports Linux. Brain tests run in the same fresh
venv with only pinned FastAPI/httpx; optional torch/MPS tests still lack those
dependencies. No Linux skip is credited as Apple coverage. Local execution of
brain/model tests is outside this package's verification.

`tests/isolation/test_fixture_boundary.py` retains both existing invocations,
including **macOS sandbox-exec** through the shared helper. Helium Playwright and extension Node fixtures
stay in the existing macOS `extension` job. The unrelated Mach-O test file
`test_build_ios_core.py` is not in the migrated discovery patterns.

Both GitHub `macos` and Cloud invoke `scripts/ci-macos-quality.sh`. The shared
contract fetches with `--locked`, then preserves:

1. Swift helper typecheck, Swift 5, warnings as errors.
2. Full Clippy, all features/targets, warnings denied.
3. Desktop-without-vault compile check.
4. Additional app-crate Clippy, all targets, warnings denied.
5. Vault doc/compile-fail tests.
6. Both existing watch targets installed; watch simulator core compile without
   default features.
7. Existing Python fixture boundary tests, including sandbox-exec on macOS.

All Cargo quality commands retain `--offline --locked` after fetch. Rust is
explicitly selected as 1.97.0; Cloud installs the same rustfmt/clippy and watch
targets. Cloud supplements GitHub for these commands; the other macOS Rust runtime test
groups, Helium, signing and release validation are outside the pilot. The boundary
script is executed on both providers, but Cloud sandbox results remain unmeasured.

`APASSY_CI_EXPECTED_SHA` must contain exactly 40 lowercase hex characters matching
`git rev-parse HEAD`. Missing, abbreviated, mismatched, or tracked-dirty source
fails before tooling or fetch. GitHub supplies `github.sha`, which for PRs is
usually the **synthetic merge commit**. Comparing a Cloud PR head against that
merge commit is invalid. For the pilot choose a commit present in remote source
control and independently confirm both providers checked out that exact commit.
A main push that reuses PR evidence has not executed the quality helper at that
main SHA; it is not an identical-SHA timing baseline. Root must obtain an actual
GitHub helper run for the selected SHA, or record the comparison as unavailable.
Do not dispatch GitHub Actions as part of code preparation.

## Exact service configuration (root-owned, manual)

- Product: `ApassyCIPilot`, inert macOS framework; bundle ID
  `pl.wyderka.apassy.cipilot`. It is a CI container, not an app/upload deliverable.
- Project/container: `native/ApassyCIPilot/ApassyCIPilot.xcodeproj` (committed).
- Shared scheme: `ApassyCIPilot`; configuration `Release`; platform macOS.
- Workflow name, exactly: `Apassy macOS quality pilot`.
- Environment: nonsecret `APASSY_CI_EXPECTED_SHA=<selected full SHA>`.
- Start conditions: **none** (no branch changes, PR changes, tags or schedule).
  Start one build manually for the chosen remote branch/commit after checking
  its identity. If onboarding proposes an automatic first run, stop and edit the
  workflow before starting it; do not accept an unintended default workflow.
- Actions: exactly **one Build** for the shared scheme, macOS destination.
  No Analyze, Test, Archive, TestFlight, App Store or other distribution action;
  no post-actions. No certificates or signing credentials for this pilot.
- Project settings disable code signing and skip installation. Archive capability
  exists in the scheme because Apple lists it as a discovery requirement; this
  does not configure an Archive workflow action. The hook rejects anything other
  than `CI_XCODEBUILD_ACTION=build` for this workflow and exact project path.
- Select and record an available explicit Xcode/macOS version; compare with the
  GitHub run's logged Xcode and SDK versions. GitHub `macos-15` does not pin Xcode.
  Do not infer parity from runner labels.

Only `native/ApassyCIPilot/ci_scripts/ci_pre_xcodebuild.sh` is introduced, adjacent
to this project. It uses Apple's `CI_PRIMARY_REPOSITORY_PATH`,
`CI_PROJECT_FILE_PATH`, `CI_WORKFLOW` and `CI_XCODEBUILD_ACTION`; other workflow
names do no work. There are no iOS hook/project changes. The pre-build script
requires the primary checkout to be available and fails if it cannot access it.

The helper uses Python supplied by Xcode/macOS and a fresh temporary, user-writable
`CARGO_HOME`/`RUSTUP_HOME`. It downloads the rustup 1.28.2 bootstrap for the measured
host architecture from the official versioned archive into that location
(120-second download timeout), verifies its pinned SHA-256 before execution,
disables rustup self-updates, and installs pinned tooling without sudo or
modifying shell startup files, and runs quality before Xcode builds the inert
framework. The bootstrap digests were read from the official archive's `.sha256`
files for `aarch64-apple-darwin` and `x86_64-apple-darwin`. Networking and toolchain
availability remain measured pilot risks.
No dependency cache is added. Cold Cloud vs cached GitHub timings must be labeled.

The actual account accepted this unsigned framework in team `7S3F9767BM` without
an app upload, signing or distribution. The Xcode onboarding UI states that
build/test-only products require Xcode 27 or later. The workflow was saved with
only Manual Start - Branch and one Build action; its initial Branch Changes
condition was removed before the first build. The committed Cloud manifest binds
the project to the discovered product; it contains identifiers, not credentials.

## One-run procedure and evidence

1. Review and commit the package, open a draft PR, and choose the remote source
   SHA. Record a GitHub run ID/attempt with
   actual helper execution at the same SHA. Set the Cloud expected-SHA variable.
2. Configure the manual workflow above; review action count/start conditions.
   Check account quota/billing before starting; no availability or free quota is
   assumed. Start **one** manual build. No automatic retries.
3. Budget at most **40 minutes** for tooling, metadata, dependency fetch and
   quality combined; the helper terminates the active process group on timeout
   with status 124. Allow at most **50 minutes of active build time** including
   checkout and the framework Build. Root cancels at that outer bound if needed;
   queue time is recorded separately. Service-level cancellation can truncate
   evidence and must not be called a successful result.
4. In Xcode's Report navigator or App Store Connect's Xcode Cloud build report,
   open/download the build logs. Save the complete pre-xcodebuild log and the
   line prefixed `APASSY_CI_RECEIPT_JSON=`. Strip only that prefix and save the rest
   as `cloud-quality.json`. Do the same for GitHub's shared-helper step. Record
   Cloud workflow/build identifiers, action result, source SHA, elapsed/queue
   time and any reported compute consumption beside the receipts.
5. Compare actual/expected SHAs, metadata (uname/architecture, selected Xcode and
   macOS/watch SDK, rustc/cargo/clippy/rustfmt), ordered quality step names, exit
   statuses and timings. Require every quality step plus the framework action
   to succeed. Investigate any missing receipt, timeout, identity/SDK mismatch,
   warning or failure. Do not rerun or reduce coverage to obtain success.

The receipt is bounded to 24 KiB, written locally to `APASSY_CI_RECEIPT` (default
system temporary directory), and printed as one JSON line on success **and**
ordinary failure. Each attempted command records elapsed seconds and exit status;
execution stops at the first failure and preserves its status. Missing later
steps are not passes. Forced cancellation, missing Python/checkout, or a hook
scope failure can prevent receipt creation: preserve that log and mark incomplete.
The receipt describes the helper only; read the subsequent framework Build result
separately. These are build logs, not a coverage report or performance guarantee.

Apple explicitly says files created by custom scripts are deleted and excluded
from downloadable artifacts. The JSON **log line** is the evidence transport;
no persistence claim is made for the local JSON file or rustup directories. No
upload, xcresult injection or external storage is used.

The root review independently matched the exported log receipt against the JSON,
verified the exact SHA and ordered successful steps, and checked framework Build
success. GitHub macOS stays authoritative and active. This quality pilot does not
establish ARM runtime test equivalence for other jobs. Local fixture checks prove
the script boundaries; the Cloud export is the execution evidence for the measured
SHA. Quota/compute consumption and performance under repeated load remain unknown.

## Primary references

Read for this preparation (2026-11-05):

- [Apple: Writing custom build scripts](https://developer.apple.com/documentation/xcode/writing-custom-build-scripts): hook names/location, workflow scoping, no sudo, log output, and custom files excluded from artifacts.
- [Apple: Environment variable reference](https://developer.apple.com/documentation/xcode/environment-variable-reference): repository/project paths, workflow name and action values.
- [Apple: Setting up your project](https://developer.apple.com/documentation/xcode/setting-up-your-project-to-use-xcode-cloud): stable committed project, shared scheme/archive capability, account and signing requirements.
- [Apple: Configuring your first workflow](https://developer.apple.com/documentation/xcode/configuring-your-first-xcode-cloud-workflow): onboarding, environment/actions, and build reports.
- [Rust: Manual installation](https://rust-lang.github.io/rustup/installation/other): versioned bootstrap archives and checksum files.
