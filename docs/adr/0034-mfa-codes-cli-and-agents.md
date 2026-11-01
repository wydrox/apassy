# ADR 0034 — One-time codes in the owner CLI and agent runs

Date: 2026-11-01. Status: owner-approved decisions, implementation proposed for review.
Amends [ADR 0030](0030-owner-check-window.md) and the OTP boundary of
[ADR 0025](0025-low-friction-access.md). Existing production, host, exception,
Always ask, missing-context and unavailable-bouncer rules remain in force.

## Owner command

`apassy code ITEM` resolves an ID or exact name and prints the current TOTP code
and seconds left. `--json` returns the ordinary owner CLI envelope with
`data.type = "code"`, `code`, `seconds_left`, and `copied: false`. `--copy` uses
the app's existing concealed clipboard and its code-expiry/session cleanup;
it returns only seconds left and `copied: true`, omitting `code` even in JSON.
No code appears in app status text. A missing OTP detail gives `no_code`;
multiple OTP details are ambiguous and refused, as is an invalid setting.
Legacy OTP labels and explicit TOTP URIs use the shared vault discovery rule.

An authenticated owner CLI session is required. CLI code is a distinct covered
action in the ADR 0030 source allowlist. A new single-use proof binds the exact
item, seed field, show-versus-copy action and vault epoch. Inside a healthy
configured window it completes without another prompt; outside it the ordinary
fresh local check runs. Delivery rechecks the window/session fence. UI Show Code
and Copy Code retain their always-fresh checks. No agent API accepts this action
or an owner-window token.

## Agent selection and timing

`apassy_list_access` adds `has_code` and, for an unambiguous setting,
`code_env_name: "APASSY_ITEM_<ID>_OTP"` to each visible catalog item. No value or
seed is returned. `apassy_run_with_secrets` accepts optional `codes: [ID, ...]`.
`items` continues to select ordinary secrets and may be `[]` for a code-only run.
An item may appear in both lists. Code-bearing wire requests (including tracked
envelopes) use protocol version 1; ordinary requests retain version 0. Older brokers
refuse version 1 before execution instead of ignoring code selection. There are at most 16 distinct items; duplicate
selectors or colliding environment names are refused. Scoped `access_request_id`
consent does not authorize codes; code runs use the explicit owner question.

For example, request a publishing token in `items: [17]`, its code in `codes:
[17]`, and run `["/bin/sh", "-c", "npm publish --otp=$APASSY_ITEM_17_OTP"]`.
The tool still takes an argument list and adds no implicit shell.

Seeds are parsed after the unchanged-authorization recheck and kept in erasing
buffers. Codes are generated in the spawn callback, after proxy setup, immediately
before session-fenced process creation. If at most five whole seconds remain,
Apassy supplies the **next period's code**. It does not sleep. A service with no
future-window tolerance may reject that code until the boundary; retry only after
checking the operation receipt and external outcome, with a new run approval as
needed. Owner CLI/UI always return the current period's code. Clock-injected tests
cover the boundary and custom periods/digit counts.

## Owner veto and remembered scope

Every requested code is a hard veto before pattern/model execution routing. The
question names each affected item as “includes one-time code” and lists its code
variable. An allowing model, a learned pattern, usage history, an evaluation scope
or an old password-only answer cannot waive it. Allow once covers only that run.
An explicit Allow in project answer (or its production counterpart) saves
`includes_codes` for each affected item, project, action and destination scope.
The normal hard rules still apply, including Always ask even after that answer.

Schema 23 adds `owner_answer.includes_codes` with default false. All pre-existing
answers remain password-only. A code-covering answer replaces its destination
scope with the destinations shown in that question. A subsequent password-only
answer replaces and clears code coverage; merging password-only destination
history must never expand a code allowance. The item UI labels answers that include
codes. Answers remain local authority, excluded from sync and cleared on restore.
All clients sharing a vault need a schema-23-capable build before sync resumes.

## Exposure and masking

Agents receive only the generated code in the child environment. Stored OTP
setup keys, including legacy explicit process bindings, cannot be delivered.
There is no agent clipboard path. Generated values are absent from model input,
approval/relay cards, activity/use/decision logs, receipts and operation status:
generation happens after those inputs are constructed, and receipts whitelist
outcome metadata only. Original stdout/stderr are masked before leaving the broker.
Code and seed buffers erase on drop; the OS process environment has the same
same-user access and child-process limitations as other injected secrets.

Masking uses exact literal matches, including inside a longer number. A six-digit
code does not mask all six-digit output: unrelated counts, ports and numbers remain.
A coincidental occurrence of those exact digits in an identifier or larger number
is redacted too. This deliberate loss of numeric output avoids leaking a code
through surrounding digits. Transformed, encoded or fragmented values are outside
the masker's guarantee; owner approval authorizes code use by the process, not an
exfiltration-proof sandbox.

## Validation boundary

Regression fixtures cover CLI response/copy, exact owner proof/window expiry,
missing/ambiguous details, typed selection, injection, near-boundary timing,
model/pattern vetoes, code-aware project answers, output masking and metadata-only
status. They use synthetic vaults and an in-memory clipboard. CI owns compilation
and test execution. They do not establish physical Touch ID, signed app clipboard,
real provider OTP acceptance, relay delivery or production acceptance.
