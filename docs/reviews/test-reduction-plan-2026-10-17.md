# Test necessity and reduction plan — 2026-10-17

**Not every current test needs to remain a separate test.** The review supports retiring **11 fully subsumed declarations** and **76 further declarations after assertion-preserving consolidation**. It also identifies **140 cases to strengthen or make faster**. These are source-review conclusions and proposed changes; no test has been removed.

Every inventoried test has an individual disposition and rationale in [the complete ledger](test-necessity-2026-10-17.json). The ledger also contains all 145 proposals, exact retiring/surviving IDs, source locations, assertions to preserve, implementation steps, risks and focused validation. Search by test name or proposal ID.

## Scope and accounting

Reviewed revision `e13c1206654a435d9c53235a4979a38ff179488e` plus the existing uncommitted test-tooling work. All 723 source/configuration file hashes captured for the audit remained unchanged. Test bodies, assertions, relevant setup/helpers and production branches were inspected. There are **2,899 review entries**, consisting of **2,879 framework cases/declarations** and **20 custom-runner groups/scenarios**. This is an inventory count, not a count of runtime invocations.

| Inventory | Entries | Counting boundary |
| --- | ---: | --- |
| Root Rust measured suite | 1,823 | 1,804 passed and 19 ignored in the earlier run |
| Root desktop-only Rust | 2 | Excluded by `not(feature = "vault")` from all-features runs |
| Rust compile-fail doctests | 6 | Public secret/API boundaries |
| iPhone Rust core | 133 | 47 unit and 86 integration declarations |
| iOS Swift | 665 | 383 app model/UI + 282 Companion/Vault kit declarations |
| Python | 104 | 95 CI helper + 9 fixture-boundary methods |
| Node | 71 | 33 walkthrough + 38 relying-party tests |
| Playwright | 75 | 78 registrations after current loops expand |
| Custom native/RP runners | 20 | 10 Swift groups, 1 signed driver, 9 standalone core scenarios |

Parameterized inputs and internal loops remain part of their test’s review. The 383 app model/UI declarations currently expand to 402 framework invocations; the 415 iOS-core/kit declarations expand to 504 before availability guards. The full source inputs are retained in the ledger. Manual notification and real Swift/Rust companion interoperability procedures were reviewed separately and retained; static format/type/build checks are not counted as tests.

| Disposition | Entire inventory | Measured root Rust | Meaning |
| --- | ---: | ---: | --- |
| Keep | 2,662 | 1,653 | Distinct regression purpose justified by source review. |
| Delete | 11 | 6 | Existing survivor already covers the relevant assertions/input path. Validate before retirement. |
| Merge | 76 | 59 | Transfer every specified assertion and input state, then retire the separate declaration. |
| Rework | 140 | 95 | Keep the behavior; repair a weak oracle, synchronization, fixture cost or timing method. |
| Defer | 10 | 10 | Retain an ignored environment-dependent probe; source alone does not establish live acceptance. |

**“Keep” is not a proof of indispensability.** It means the inspected assertions protect a distinct failure mode or caller boundary, and no safe retirement was established. This was not an exhaustive mutation campaign. Ten ignored probes still need their documented live/signed fixture for acceptance; none contributes active-suite savings. Other ignored diagnostic cases have explicit rework plans.

## Implementation order

1. **Repair misleading pass conditions first where a planned survivor depends on them.** Required native process/socket setup must fail explicitly, not skip an `if let` branch; missing native compilation must be visible; shadow acceptance must require rows; network-closure checks must distinguish EOF/reset from timeout. Use P-TB-10/11/15, P-AGENT_BROWSER-11, P-BROKER-16 and P-NATIVE-COMPANION-10. Preserve availability gates as explicit skips with reasons.
2. **Remove the 11 supported assertion subsets.** Each survivor is listed below. Run the focused survivor and a relevant negative control before removing its duplicate. Remove retired exact names from `scripts/parallel-tests.json` in the same change.
3. **Consolidate expensive repeated fixtures.** Start with the HTTPS 120-request pair, the schema-18 matrix and the slow-transfer mutex pair. Then consolidate owner-answer, passkey/OTP and model lifecycles. Keep different policy, authorization, input and transition cases independently identifiable inside the survivor.
4. **Replace deliberate waits with controlled time or request barriers.** Prioritize the root feed’s real-minute wait, owner UI relay responsiveness, model-server monitoring interval, and the iPhone-core feed minute. Preserve actual cancellation/lock-release integration checks.
5. **Apply optional declaration cleanup last.** Table-driven crypto layout, wording, release-artifact and small parser cases mostly reduce maintenance. They preserve scenarios and often do not reduce executed work.
6. **Validate the changed suite and measure before claiming a speedup.** Use the gates below; fix regressions before broadening the next batch. No implementation, commit, push or CI change is part of this plan.

The source review targets **87 existing declaration retirements**, including **65 of the 1,823 measured root cases**. All 65 are active cases. Final test counts can differ if repair work adds cases or converts declarations to separately registered parameterized invocations. **Do not use a test-count quota as the acceptance criterion.**

## Fully subsumed declarations

These require no assertion transfer under the reviewed source, but do require the named survivor to remain runnable. A source change since this audit requires rechecking the mapping.

| Proposal | Retire | Coverage survives in |
| --- | --- | --- |
| P-VAULT-02 | [`cipher_version_is_nonempty_not_ordinary_sqlite`](../../tests/sqlcipher_probe.rs#L494) | [`queried_sqlcipher_defaults_match_sqlcipher4`](../../tests/sqlcipher_probe.rs#L507) |
| P-SYNC-02 | [`the_aads_have_the_contract_bytes`](../../src/questions/envelope.rs#L883) | [`the_contract_test_vectors_reproduce_exactly`](../../tests/relay_questions.rs#L157); [`the_contract_test_vectors_reproduce_exactly`](../../tests/relay_feed.rs#L202) |
| P-SYNC-02 | [`the_aads_have_the_contract_bytes`](../../src/questions/feed.rs#L2123) | [`the_contract_test_vectors_reproduce_exactly`](../../tests/relay_questions.rs#L157); [`the_contract_test_vectors_reproduce_exactly`](../../tests/relay_feed.rs#L202) |
| P-AGENT_BROWSER-01 | [`caller_checks_fail_closed_outside_a_bundle`](../../tests/browser_passkeys.rs#L701) | [`a_test_program_is_not_in_a_bundle_so_every_check_fails`](../../src/browser/caller.rs#L267) |
| P-AGENT_BROWSER-02 | [`the_wire_request_debug_never_shows_a_saved_value`](../../tests/agent_items.rs#L1431) | [`credential_actions_parse_and_a_saved_value_is_redacted`](../../src/agent/wire.rs#L388) |
| P-AGENT_BROWSER-04 | [`direct_broker_call_from_socket_in_denied_dir`](../../tests/isolation/product_profile.rs#L577) | [`permitted_call_returns_only_permitted_fields`](../../tests/agent_path.rs#L194); [`adapter_in_profile_reaches_broker_without_secret`](../../tests/isolation/product_profile.rs#L529) |
| P-IOS-MODELS-01 | [`RunSnapshotTests.openedCurrent`](../../ios/ApassyCompanion/ModelTests/Tests/AppModelsTests/RunSnapshotTests.swift#L102) | [`RunSnapshotTests.current`](../../ios/ApassyCompanion/ModelTests/Tests/AppModelsTests/RunSnapshotTests.swift#L21); [`RunSnapshotTests.openedStale`](../../ios/ApassyCompanion/ModelTests/Tests/AppModelsTests/RunSnapshotTests.swift#L67) |
| P-IOS-MODELS-01 | [`RunSnapshotTests.approvalUsesShownDigest`](../../ios/ApassyCompanion/ModelTests/Tests/AppModelsTests/RunSnapshotTests.swift#L152) | [`RunSnapshotTests.current`](../../ios/ApassyCompanion/ModelTests/Tests/AppModelsTests/RunSnapshotTests.swift#L21); [`RunSnapshotTests.openedStale`](../../ios/ApassyCompanion/ModelTests/Tests/AppModelsTests/RunSnapshotTests.swift#L67) |
| P-IOSCORE-01 | [`givenSignaturesVerify`](../../ios/ApassyCompanionKit/Tests/ApassyCompanionKitTests/ContractVectorTests.swift#L112) | [`givenSignaturesFailWhenChanged`](../../ios/ApassyCompanionKit/Tests/ApassyCompanionKitTests/ContractVectorTests.swift#L132) |
| P-IOSCORE-02 | [`plainUnauthorized`](../../ios/ApassyCompanionKit/Tests/ApassyCompanionKitTests/ErrorMappingTests.swift#L43) | [`contractCodes`](../../ios/ApassyCompanionKit/Tests/ApassyCompanionKitTests/ErrorMappingTests.swift#L20) |
| P-TB-02 | [`approval single-use > a second approve-once on the same request fails`](../../design/walkthrough/model.test.mjs#L399) | [`uncertainty pending approval > approved request reports current completion and keeps require_approval history`](../../design/walkthrough/model.test.mjs#L304) |

Independent challenge rejected an earlier direct-deletion suggestion for `restore_removes_process_grants`: its backup lacks a declaration/custom rule, while the richer survivor adds them. P-AGENT_BROWSER-03 is now a **conditional merge retaining both setups**. P-IOS-MODELS-06 similarly retains saving both before and after `loadFolders`. These distinctions are mandatory, not optional cleanup.

## First consolidation batches

| Proposal | Existing declarations retired | Required preserved coverage | Standalone retired-case time |
| --- | ---: | --- | ---: |
| P-NATIVE-COMPANION-06 | 1 | Exactly 120 successful HTTPS requests; repeated same-nonce 429; unchanged last_seen across next second; other-device 200 and unsigned 404. | 7.452s |
| P-VAULT-01 | 5 | All six schema-18 policy groups, exact narrow row set, absence checks and timestamps now−99, now−70, now−990 from one immutable migrated snapshot. | 1.187s |
| P-DESKTOP_RUNTIME-01 | 1 | Hold one snapshot transfer at a barrier, check both mutexes while blocked, release and assert the merged Gamma row. | 2.098s |
| P-VAULT-05 | 3 | Remembered-answer provenance/count/removal, including ApproveRun allow-once 0→1 before ApproveInProject; preserve distinct answer routes. | 1.446s |
| P-DUI-05 | 3 | Ordinary password-login editing, passkey-before-removal hints, authorized revision-bound removal and post-removal hints. | 0.778s |
| P-SYNC-03 | 1 | v2 signed removal names/settle/feed sequence plus v1 Only compatibility, retaining independent state for version cases. | 2.436s |
| P-AGENT_BROWSER-09 | 1 | Owner and browser socket denial as separate rows, each with an outside connection control, plus real sandbox broker reachability. | 1.259s |
| P-TB-04 | 2 | Each required binary remains an explicit missing and tampered entry with a fresh artifact, no environment append and no chmod on rejection. | Unmeasured |
| P-IOS-MODELS-06 | 1 | Fresh save-without-loadFolders and save-after-loadFolders inputs; preserve all save-result/title/error assertions. | Unmeasured |

The 65 root retirement candidates total **25.17 seconds** in the earlier fresh-process measurements. This is only the standalone work associated with those declarations **before transferred assertions/setup**, not predicted savings. It is about 3.2% of the 777.59 summed test seconds. Repeated native compilation can also be exaggerated by fresh-process profiling because process-local caches reset. Ancillary timings were not measured.

## Larger runtime opportunities

| Proposal | Current evidence | Required replacement |
| --- | --- | --- |
| P-SYNC-04 | Root feed rate test measured 60.521s and explicitly waits at least a minute | Inject monotonic time/wakeup; assert no retry before boundary, no busy loop, questions continue, and publication after the boundary |
| P-DUI-15 | Owner relay UI responsiveness measured 21.790s; persistent fake-relay delays repeat | One-shot entered/release barriers for PUT snapshot, GET head, POST invite and GET devices; assert drawing/progress/vault access while blocked; release on failure with watchdog |
| P-BROKER-07 | Outside-model-server replacement measured 10.141s; production probe cadence is 10s | Inject test probe cadence; retain real process death, replacement, readiness and cleanup checks |
| P-IOSCORE-07 | Separate iPhone core test explicitly waits ≥59s for a 60s feed pause; unmeasured | Controlled clock/wait seam retaining retry, unrelated work, timeout and cancellation semantics |
| P-SYNC-05/06/07, P-DESKTOP_RUNTIME-08, P-IOS-MODELS-09 | Retry, expiry, watcher and ordering tests use sleeps/polls | Gate on observed processing phases; fake elapsed policy time; retain one actual blocked-I/O cancellation path |

The first three measured cases account for **92.45 seconds of current test time**, not 92.45 seconds of proven savings. Production timeout/rate policy must stay unchanged. Virtual time must not erase actual concurrency, socket cancellation, mutex release or process cleanup coverage.

## Coverage that should remain

- Authorization, stale revision/digest, replay/nonce, cross-agent/device/vault, secret redaction and fail-closed behavior remain distinct cases or labeled matrix rows.
- Schema versions and rollback/corruption paths remain distinct. The schema-18 consolidation shares one identical immutable fixture; it does not collapse different schema upgrades.
- Independent crypto verification remains independent. Do not replace a second implementation/verifier with the same helper used by production.
- Rust implementation, Swift FFI, browser content/background/native host, CLI process and real sandbox boundaries retain separate coverage. Shared vectors across languages do not alone justify removal.
- Real signed-app, trust-store, Keychain/device and notification acceptance is not established by preview models or synthetic mocks. Ten deferred ignored probes remain documented; no active speedup is attributed to them.
- Both desktop-without-vault renderer cases remain justified, but `cargo check --features desktop` does not execute them. P-DUI-20 specifies a separate focused feature-matrix execution policy.

## Validation before applying a batch

For each retirement, copy its preserve-list into the change description, establish an unchanged baseline, and make the survivor reject the specified representative fault. For a merge, add missing assertions and input rows before deleting the old declaration. Keep fresh fixtures where state changes matter; do not hide two distinct inputs in one combined input. A matching assertion count alone is insufficient.

After Rust name changes, update the exact parallel allowlist and verify both CI partitions. For scheduling changes, ensure previously reviewed state-free tests stay state-free and new names remain serial until reviewed.

```sh
python3 scripts/ci-test-shard.py --list --check --shard-count 3
python3 scripts/ci-test-shard.py --list --check --shard-count 4
python3.12 -m unittest discover -s scripts/tests -p 'test_ci_*.py'
```

Run changed-area focused checks from each proposal, then the normal macOS three-shard and Linux four-shard CI runs for integrated Rust changes. Run iPhone core/Swift, Node/Playwright and native checks only in the applicable changed areas with their documented fixtures. Do not equate mock/helper tests with signed/provider/device acceptance.

For performance batches, compare three paired warm CI-equivalent runs on the same revision/host/configuration, recording per-shard wall time and test/ignored/skip accounting; use the existing per-test profiler to localize changes. Report distributions and work moved into surviving cases. A lower declaration count or a faster isolated profiler run is not enough to claim lower CI wall time.

## Checks actually completed for this audit

- Exact coverage of all 1,823 measured Rust IDs, plus the two other feature-gated declarations, matched source. Ancillary declarations were enumerated independently from Rust attributes, Swift declarations and Python/JS registration syntax. Every one of 2,899 review entries has a nonempty specific rationale.
- All IDs and proposal IDs are unique; every retiree/survivor reference resolves; no declaration is retired twice and no planned survivor is retired elsewhere. Source paths/lines and all 723 captured source/configuration hashes were checked.
- Independent challenge reviewed the iOS retirement set, restore/SQLCipher candidates and the expensive HTTPS/migration merges; the two missing-input corrections above were incorporated.
- In a temporary copy, the Node walkthrough suite passed **33/33**, then **32/32** after removing the proposed duplicate single-use declaration. An injected wrong replay-denial code failed the retained history/completion test in both versions. This is one illustrative mutation, not an exhaustive equivalence proof.
- No product or test source changed. No full Rust, Swift, Linux, hosted CI, browser, signed/native or device suite was rerun for this planning task. The [earlier timing audit](test-suite-audit-2026-10-17.md) contains the separate baseline execution evidence.

## Proposal index

The complete per-proposal assertion map, implementation steps and validation controls are in [the ledger](test-necessity-2026-10-17.json). Count reductions below are declarations; reworks preserve behavior and can add missing scenarios.

| ID | Action | Retirement count | Proposal |
| --- | --- | ---: | --- |
| P-DUI-01 | rework | 0 | Prove stalled setup process-group cleanup |
| P-DUI-02 | merge | 1 | Fold hostless detail rendering into the existing decision card cases |
| P-DUI-03 | merge | 1 | One host-color contract table |
| P-DUI-04 | rework | 0 | Exercise actual Disconnect confirmation instead of manually denying its waiter |
| P-DUI-05 | merge | 3 | One ordinary-login to passkey-removal lifecycle preserves three rendering states |
| P-DUI-06 | merge | 1 | Check initial OTP masking in the ShowCode consent lifecycle |
| P-DUI-07 | rework | 0 | Make UI OTP refresh cross a deterministic period boundary |
| P-DUI-08 | merge | 1 | One custom-label OTP pre/post-consent isolation test |
| P-DUI-09 | merge | 1 | Check removed-device UI before turning that device off |
| P-DUI-10 | merge | 1 | Exercise failed masked team-code submission before successful relay setup |
| P-DUI-11 | merge | 1 | Unify duplicate six-section Settings contract tables |
| P-DUI-12 | rework | 0 | Reuse baseline for six viewport/sidebar combinations without deleting cases |
| P-DUI-13 | rework | 0 | Make Command-F shortcut assert actual search focus |
| P-DUI-14 | merge | 1 | One segmented-picker keyboard contract with focus isolation |
| P-DUI-15 | rework | 0 | Replace repeated three-second relay sleeps with request barriers |
| P-DUI-16 | merge | 1 | Preserve full declaration invariants in development-key answer lifecycle |
| P-DUI-17 | rework | 0 | Strengthen credential responsive checks beyond title presence |
| P-DUI-18 | merge | 1 | Move exact owner-denial reason into stronger alert synchronization case |
| P-DUI-19 | merge | 1 | Move notification preconditions into approval-history lifecycle |
| P-DUI-20 | rework | 0 | Cover desktop-only UI branch outside all-features inventory |
| P-DESKTOP_RUNTIME-01 | merge | 1 | Check both mutexes during one explicitly blocked relay snapshot |
| P-DESKTOP_RUNTIME-02 | merge | 1 | Consolidate successful hook merge with the stronger decoy-hook fixture |
| P-DESKTOP_RUNTIME-03 | merge | 1 | Exercise Bitwarden custom fields and TOTP in one export fixture |
| P-DESKTOP_RUNTIME-04 | merge | 1 | Combine updater defaults with malformed/partial-file loader matrix |
| P-DESKTOP_RUNTIME-05 | merge | 1 | Move missing-build-commit compatibility into staging success and remove repeated equal-version check |
| P-DESKTOP_RUNTIME-06 | rework | 0 | Make no-loaded-preferences write avoidance observable |
| P-DESKTOP_RUNTIME-07 | rework | 0 | Remove broker/vault/bouncer setup from pure path formatting/classification check |
| P-DESKTOP_RUNTIME-08 | rework | 0 | Replace notification watcher blind negative waits with acknowledged processing passes |
| P-DESKTOP_RUNTIME-09 | defer | 0 | Retain ignored real macOS updater signature probes pending explicit signed-app fixture |
| P-DESKTOP_RUNTIME-10 | rework | 0 | Bind fish action-list assertions to their parent command predicate |
| P-BROKER-01 | merge | 1 | Assert age-map cleanup in existing approval terminal-outcome tests |
| P-BROKER-02 | merge | 1 | Unify Custom OTP exclusion rows under one unlocked vault fixture |
| P-BROKER-03 | merge | 1 | Audit rule notes while loading the same builtin JSON files |
| P-BROKER-04 | merge | 1 | Separate and consolidate legacy-instruction integration assertions by current policy |
| P-BROKER-05 | merge | 1 | Consolidate injected purpose and user-request channels with existing hard-flag gate coverage |
| P-BROKER-06 | merge | 1 | Fold baseline safe command examples into existing safe-classification audit |
| P-BROKER-07 | rework | 0 | Make supervisor probe/tick cadence short in tests while preserving process evidence |
| P-BROKER-08 | rework | 0 | Replace blind child-process sleeps with explicit readiness and bounded death checks |
| P-BROKER-09 | rework | 0 | Prove timeout kills both process-group members |
| P-BROKER-10 | rework | 0 | Check training eligibility matrix without recreating five encrypted vaults |
| P-BROKER-11 | rework | 0 | Make foreign-agent and foreign-epoch prompt exclusions observable |
| P-BROKER-12 | rework | 0 | Replace random-prefix inequality with deterministic prefix-selection assertion |
| P-BROKER-13 | rework | 0 | Expose ignored evaluation/report utilities as explicit diagnostics with execution status |
| P-BROKER-14 | rework | 0 | Pin actual calibration/test split membership |
| P-BROKER-15 | rework | 0 | Protect individual declaration-suggestion cases as well as aggregate accuracy |
| P-BROKER-16 | rework | 0 | Reject vacuous zero-shadow-row manual acceptance |
| P-BROKER-17 | rework | 0 | Settle reason-focused owner questions actively instead of timing each out |
| P-BROKER-18 | rework | 0 | Check generated host timeout configuration rather than source text presence |
| P-VAULT-01 | merge | 5 | Run the shared schema-18 derivation fixture once and assert the whole agent matrix |
| P-VAULT-02 | delete | 1 | Remove the SQLCipher version-only probe already required by full-defaults probe |
| P-VAULT-03 | merge | 2 | One encrypted SQLCipher seed with independent right/wrong/absent-key reads |
| P-VAULT-04 | merge | 1 | Fold repeated backup-flag checks into independent registration/assertion crypto case |
| P-VAULT-05 | merge | 3 | Keep owner-answer count, provenance and revocation in one staged lifecycle |
| P-VAULT-06 | merge | 1 | Combine owner creation state and exact owner-facing errors |
| P-VAULT-07 | merge | 1 | Add category-mismatch rejection to existing atomic update lifecycle |
| P-VAULT-08 | merge | 1 | Keep production OTP label contract in the full label matrix |
| P-VAULT-09 | merge | 1 | Place OTP category wording beside invalid setting failures |
| P-VAULT-10 | rework | 0 | Assert actual data-directory path rules in isolated environment |
| P-VAULT-11 | rework | 0 | Exercise mask preparation ordering rather than already-sorted values |
| P-VAULT-12 | rework | 0 | Coordinate the native-authentication epoch race without fixed one-second sleep |
| P-VAULT-13 | rework | 0 | Read back every owner form category before calling it a round trip |
| P-SYNC-01 | merge | 1 | Transfer the typed empty-list timeout assertion into the richer directory-worker lifecycle case |
| P-SYNC-02 | delete | 2 | Remove two exact-AAD declarations already fully covered by existing contract-vector cases |
| P-SYNC-03 | merge | 1 | Consolidate repeated successful v2 removal path while keeping old-phone compatibility |
| P-SYNC-04 | rework | 0 | Control feed scheduler time and observable worker progress instead of wall-minute/negative sleeps |
| P-SYNC-05 | rework | 0 | Inject relay retry time for rate limiting, pending join and removed-device probe |
| P-SYNC-06 | rework | 0 | Synchronize transport and child-process phases with barriers while retaining cancellation latency checks |
| P-SYNC-07 | rework | 0 | Control question queue expiry and concurrent-answer delivery |
| P-SYNC-08 | rework | 0 | Use deterministic curve boundary vectors instead of statistical point coverage |
| P-SYNC-09 | rework | 0 | Exercise both normalized-title actions, not just compute both digests |
| P-SYNC-10 | rework | 0 | Make row merge chronology explicit while preserving tombstone and tie-break semantics |
| P-NATIVE-COMPANION-01 | merge | 1 | Put the nonempty body SHA256 vector beside primitive known values |
| P-NATIVE-COMPANION-02 | merge | 1 | Keep pair-string layout and HMAC proof vectors in one case |
| P-NATIVE-COMPANION-03 | merge | 1 | Fold digest shape and repeatability checks into fixed contract vectors |
| P-NATIVE-COMPANION-04 | merge | 1 | Keep empty optional-offer marker with digest field-boundary cases |
| P-NATIVE-COMPANION-05 | merge | 1 | Assert erased pairing secret in cancellation transition case |
| P-NATIVE-COMPANION-06 | merge | 1 | Share the expensive HTTPS 120-request device-budget saturation |
| P-NATIVE-COMPANION-07 | merge | 1 | Check vault certificate identity in the signed HTTPS status smoke |
| P-NATIVE-COMPANION-08 | merge | 1 | Consolidate agent-request session consistency and exact endpoints |
| P-NATIVE-COMPANION-09 | merge | 1 | Keep small native event literals and accessors with preview contract |
| P-NATIVE-COMPANION-10 | rework | 0 | Require actual network closure instead of accepting any read error |
| P-NATIVE-COMPANION-11 | rework | 0 | Make total-request deadline test reject multi-second deadline drift |
| P-NATIVE-COMPANION-12 | rework | 0 | Give discovery-to-link compatibility a non-vacuous fixture |
| P-NATIVE-COMPANION-13 | rework | 0 | Remove legitimate six-digit-code collision flakiness from attacker case |
| P-NATIVE-COMPANION-14 | defer | 0 | Retain ignored live Tailscale acceptance as an opt-in environment gate |
| P-NATIVE-COMPANION-15 | rework | 0 | Make hostile digest framing fixtures expose a demonstrated faulty encoding |
| P-AGENT_BROWSER-01 | delete | 1 | Remove exact duplicate missing-bundle caller check |
| P-AGENT_BROWSER-02 | delete | 1 | Remove redundant constructed SaveCredential Debug test |
| P-AGENT_BROWSER-03 | merge | 1 | Preserve undeclared/default-rule and declared/custom-rule restore shapes together |
| P-AGENT_BROWSER-04 | delete | 1 | Retire misleading unsandboxed broker reachability duplicate |
| P-AGENT_BROWSER-05 | merge | 1 | Move readable-canary controls next to the actual denial cases |
| P-AGENT_BROWSER-06 | merge | 1 | Keep store/extension ID consistency in manifest identity contract |
| P-AGENT_BROWSER-07 | merge | 1 | Use one persisted provider-delivery matrix for signing and CLI exceptions |
| P-AGENT_BROWSER-08 | merge | 2 | Combine basic normal-repository identity controls |
| P-AGENT_BROWSER-09 | merge | 1 | Table-test owner and browser socket denial against the same broker control |
| P-AGENT_BROWSER-10 | merge | 1 | Combine ordinary file-work and child-process sandbox positive controls |
| P-AGENT_BROWSER-11 | rework | 0 | Build validated native guards once per run and expose missing-compiler applicability |
| P-AGENT_BROWSER-12 | rework | 0 | Separate missing-account Keychain probe from provisioned-item isolation proof |
| P-AGENT_BROWSER-13 | rework | 0 | Report real Codex invocation separately from usage-limit injected run |
| P-AGENT_BROWSER-14 | rework | 0 | Replace bad-frame cancellation delay with socket-ready acknowledgement |
| P-AGENT_BROWSER-15 | rework | 0 | Make Python and Node proxy applicability independently visible |
| P-AGENT_BROWSER-16 | rework | 0 | Replace random alphabet-completeness claim with deterministic sampler checks |
| P-IOS-MODELS-01 | delete | 2 | Remove two fully subsumed RunSnapshot declarations |
| P-IOS-MODELS-02 | merge | 1 | Consolidate identical model-only stale-snapshot sequences |
| P-IOS-MODELS-03 | merge | 1 | Share one successful unlock fixture and identity-publication assertion |
| P-IOS-MODELS-04 | merge | 1 | Check second generation within random success case |
| P-IOS-MODELS-05 | merge | 1 | Unify biometric-fallback prompt and cancellation cleanup |
| P-IOS-MODELS-06 | merge | 1 | Consolidate new-item save declarations while retaining both folder initialization states |
| P-IOS-MODELS-07 | merge | 1 | Exercise loading and locked reach states in one pure case |
| P-IOS-MODELS-08 | rework | 0 | Replace broad/message-only oracles with actual side-effect evidence |
| P-IOS-MODELS-09 | rework | 0 | Make polling, debounce and lifecycle timing deterministic without deleting races |
| P-IOS-MODELS-10 | rework | 0 | Prove credential-exchange cancellation and no-data-access claims |
| P-IOSCORE-01 | delete | 1 | Remove positive-only fixed-signature duplicate |
| P-IOSCORE-02 | delete | 1 | Remove duplicate generic unauthorized mapping |
| P-IOSCORE-03 | merge | 2 | Consolidate immutable pairing-record assertions |
| P-IOSCORE-04 | merge | 1 | Move uncertain-approval copy into existing error-message contract |
| P-IOSCORE-05 | merge | 1 | Combine DER fixture shape with existing fixed-signature loop |
| P-IOSCORE-06 | merge | 1 | Share real TLS mismatch fixture for sequential wrong-pin controls |
| P-IOSCORE-07 | rework | 0 | Drive rate-limit clock deterministically while preserving cancellation |
| P-IOSCORE-08 | rework | 0 | Use a fixed leading-zero pairing-code vector |
| P-IOSCORE-09 | rework | 0 | Make export and Swift Debug redaction checks nonvacuous |
| P-IOSCORE-10 | rework | 0 | Require precise owner-role errors with valid unlocked targets |
| P-IOSCORE-11 | rework | 0 | Prove concurrency overlap and bound question-unlock races |
| P-IOSCORE-12 | rework | 0 | Replace scheduler delays with request/listener readiness signals |
| P-IOSCORE-13 | rework | 0 | Verify bookmark removal rather than only provider preservation |
| P-IOSCORE-14 | rework | 0 | Test keychain policy promised by service test title |
| P-IOSCORE-15 | rework | 0 | Report or inject the privileged filesystem failure gate |
| P-IOSCORE-16 | rework | 0 | Separate signature correctness from ECDSA nonce strategy |
| P-IOSCORE-17 | rework | 0 | Pin missing-vault feed error rather than accepting several codes |
| P-IOSCORE-18 | rework | 0 | Replace SHA width-only oracle with independent abc digest |
| P-TB-01 | merge | 1 | One refusal matrix with all refusal-specific assertions |
| P-TB-02 | delete | 1 | Remove fully subsumed second-approval-only walkthrough test |
| P-TB-03 | merge | 1 | Combine basic and historical approval transition checks |
| P-TB-04 | merge | 2 | Table-drive artifact absence and tamper across named release binaries |
| P-TB-05 | rework | 0 | Make fenced-heading test discriminate parser behavior |
| P-TB-06 | merge | 1 | Fold default shard-count assertion into partition test |
| P-TB-07 | rework | 0 | Complete title and username form-validation coverage |
| P-TB-08 | rework | 0 | Assert messages promised by busy/no-match test |
| P-TB-09 | rework | 0 | Separate badge scheduling semantics from long wall-clock wait |
| P-TB-10 | rework | 0 | Fail native integration scenarios when required setup cannot start |
| P-TB-11 | rework | 0 | Reject missing or malformed signed-probe cases |
| P-TB-12 | rework | 0 | Bound RP CLI startup and assert shutdown |
| P-TB-13 | merge | 1 | Transfer approved-use counter assertion into approval-history flow |
| P-TB-14 | rework | 0 | Exercise deterministic equal-duration ordering explicitly |
| P-TB-15 | rework | 0 | Bound required async gates without weakening race order |
