# Review: single-probe entry patch for W8 (2026-11-04)

Scope: source-only. I read only
`docs/reviews/bouncer-context-single-probe-entry-proposal.patch`, the current
experiment workflow (SHA-256 `68b169a5…6f491`, matches the stated baseline), the
`ci.yml` bridge, and job `needs`/`outputs`/`if`. Nothing was run: no CI, no
dispatch, no tests, no actionlint. Head `1b9cbd98`. The new method is
**NOT_RUN**. B is **UNSUPPORTED**. Quality and held-out are not measured. C/D/E
stay blocked.

Checks done here: `git apply --check` passes. The patch applied to a temporary
copy gives a file byte-identical to `/tmp/bouncer-context-single-probe-proposed.yml`.

## Verdict: ACCEPT, with two small conditions (C1, C2) in the same commit X

The W8 order is accepted: push the final X, wait for green CI with the compiled
and tokenizer preflight, then send **one**
`gh workflow run ci.yml --ref feat/bouncer-secret-context -f context_experiment=full`.
No `mode=probe` dispatch. No rerun. A result other than ELIGIBLE ends the path.
I accept that training starts automatically after ELIGIBLE, with no manual
pause. Training still needs a successful probe job: ELIGIBLE, L1, and the
freeze and cost bench must all pass first.

## Verified properties

1. **A PR event cannot start full training.** `train.if` needs the actual
   `github.event_name == 'workflow_dispatch'`. `evaluate` needs `train`, so it
   is skipped when `train` is skipped.
2. **A result other than ELIGIBLE skips train and evaluate.**
   - If the budget is UNSUPPORTED, `groups=''` and `train.if` is false.
   - If the verify step is missing or skipped, the output is `''`.
   - If verify, the freeze check or the cost bench fails, the probe job fails
     and `train` (default `success()`) is skipped.
   - `freeze_sha256` is written after `groups`. If something fails between the
     two writes, the step fails.
   - The `train` job still checks the downloaded artifact again: the expected
     SHA must be 64 characters, the budget is recomputed, and an empty
     `GROUPS_SELECTED` gives exit 1.
3. **No false probe PASS from the preflight.**
   - On a PR the job is named `preflight`.
   - All four workload steps are gated on `workflow_dispatch`, so no
     `budget.json`, training report or freeze is made.
   - The summary step runs only after the replay and tokenizer steps pass. It
     says there is no runtime result.
   - `scope` is `synthetic_preflight_only` and `gate_B` is always
     `UNSUPPORTED`.
   - The artifact name still contains `probe`. That is acceptable, because
     `scope` tells the two cases apart.
4. **One probe, on X.** A `full` dispatch runs exactly one `probe` job, and
   `train` needs it. The PR run on the merge SHA now only runs the preflight.
   On the dispatch, `github.sha` is the branch tip X. The probe job runs the
   compiled replay, G1 and tokenizer checks again on X before the workload, so
   compiled parity covers the same SHA.
5. **Bridge unchanged and still works.** There is no diff in `ci.yml`. The
   bridge `if` is still dispatch-only. In a reusable call, `github.event_name`
   and `GITHUB_EVENT_NAME` are the caller's `workflow_dispatch`, and
   `inputs.mode` is the string `full`.
   The concurrency groups `ci-<sha>`, `bouncer-context-probe-refs/heads/…` and
   PR `…-104` do not overlap.
6. **Unchanged:** root `permissions: contents: read`, the runners, every
   timeout (40/23/40/300/120/110), the secrets (none), the held-out removal and
   isolation, and the evaluate path. The shared verify block, which the
   `test_context_workflow_budget` extractor reads, is unchanged.

## Conditions (small; parent fixes them, no new review)

**C1. Signal regression: a run that is not ELIGIBLE now looks green.**
Before the patch, a `full` dispatch with UNSUPPORTED(budget) ended with a red
`train` job and an explicit summary. Now the run ends with `success`, `train`
and `evaluate` are skipped, and the summary only says "Training completed; gate
B unmeasured". Minimal fix: add a separate step after `verify`. This leaves the
duplicated verify block unchanged:

```yaml
    - name: Record probe eligibility (not gate B)
      if: ${{ github.event_name == 'workflow_dispatch' }}
      env:
        GROUPS_SELECTED: ${{ steps.verify.outputs.groups }}
      run: |
        if [[ -n "$GROUPS_SELECTED" ]]; then
          echo "Probe ELIGIBLE by budget: groups=$GROUPS_SELECTED. Train still requires the cost bench to pass. Gate B unmeasured."
        else
          echo 'Probe UNSUPPORTED(budget): train and evaluate skipped. B UNSUPPORTED; path ends, no retry.'
        fi >> "$GITHUB_STEP_SUMMARY"
```

Report the outcome from `budget.json` and the job states. Never report it from
the run conclusion.

**C2. Documentation drift (same commit X).** In
`docs/evaluation/bouncer-context-ci-probe.md`:
- Lines 17–18 still say that the PR trigger "runs the bounded probe".
- Lines 29–30 and 39–45 list a probe dispatch and then a full dispatch ("at
  most one probe and one full run"). That would spend a second probe on X.

Replace them with the preflight-only PR boundary and the single
`context_experiment=full` command. Say that `mode=probe` is kept only for
compatibility and is not used.

## Operational notes (not patch defects)

- Put this review file, and every other change, into X before CI.
  `docs/reviews/bouncer-context-*.md` is in the PR paths, so a later push moves
  the head. Do not push between green CI and the dispatch.
- `gh workflow run` does not return a run ID. Identify the run from the run
  list, then confirm that its `headSha` is X before you read any result.
- The same dispatch also runs the regular `ci.yml` jobs on X. They do not gate
  `train`, which is unchanged from before. If one of them fails, report it next
  to the outcome; do not rerun.

PR https://github.com/wydrox/apassy/pull/104, head 1b9cbd9886a710ce4ba10f17229fb317c62fb460, checks new method not run, single-probe orchestration under review; B unsupported.
