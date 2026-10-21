# ADR 0029: Explicit permission for bouncer evaluation

Date: 2026-10-21.
Status: Accepted by the maintainer in the implementation request.
Tracking: https://github.com/wydrox/apassy/issues/27.

## Problem

A running model can receive no requests. A default environment or risk stops a run
before inference. For a credential outside development with low risk, the first-use
gate requires an earlier use allowed by the model itself. An owner approval once,
a project answer, and a pattern do not establish that history.

Readiness also treated a successful health endpoint as sufficient after a failed
inference warm-up. The automatic-use counter omitted remembered project answers.

## Decision

The Mac question offers a separate, authenticated action: allow this run once and
let the bouncer evaluate later requests. The owner reviews the environment and risk
of every credential. Both fields become owner-confirmed, with other declaration
fields and their sources preserved. Classification and permission are committed
atomically, after the broker rechecks the original credential and access state.

A local evaluation scope binds one connected agent, credential revision, project,
action, and explicit destination hosts. Generic action scopes require a certain
classification and a resolved system native executable. Other supported commands
bind exact argv, working directory, PATH, executable path and directly invoked
project script bytes. A changed bound script needs a new owner decision. Unknown
native tools, project native binaries and unsupported interpreter forms have no
durable evaluation offer.

Installed tool identity and semantics are trusted; external binaries are not
attested. Inline interpreter code binds its argv, not files that the code later
loads. Imports, hooks, plugins, sourced files and other dependencies are outside
the binding. It is checked again before secret access, not atomically with process
execution. This is permission for model evaluation, not a script sandbox.

The scope permits model evaluation, never execution by itself. The model still
checks the current user request and command. Production allowances, always-ask
settings, secret-output and foreign-host checks remain authoritative. Development
with confirmed low risk keeps its existing eligibility. Prior model decisions no
longer bootstrap non-development eligibility or survive scope removal.

Allow once neither confirms classification nor creates a scope. Existing project
answers keep their explicit automatic-execution semantics. The UI distinguishes
those immediate answers from permission to evaluate and from the legacy pattern
learning count.

Schema 20 adds an empty local scope table. No history or old approval is migrated
into a permission. Scope identity is checked again before secrets are read.
Credential/access edits, agent revocation, stricter policy and sync conflicts
invalidate scopes. Scope rows do not sync and are removed from exported sync copies
and restored backups. Removal is stricter and needs no new owner authentication.

The new offer stays outside the existing relay question/card and signed answer
contracts. The Mac can configure it; existing iPhone answers retain their meaning.
Older mobile clients must not receive unknown answer kinds.

Readiness requires a valid inference response, including any active model pin.
Managed starts wait for it; external mode never launches a process. Inference has
an absolute per-attempt deadline and at most one retry for a timeout. The retry
repeats evaluation only, never credential-bearing command execution. Invalid answers,
HTTP errors, and model-version mismatches still require the owner.

Both automatic-use summaries derive their totals from successful requests that did
not ask the owner, broken down into model, pattern, and remembered-answer decisions.
Manual questions retain the concrete reason that stopped automatic evaluation.

## Verification

Synthetic tests cover classification and scope creation, exact owner proofs, once
semantics, subsequent model evaluation, revocation during inference, changed scopes
and scripts, migration/restore/sync isolation, unchanged relay contracts, delayed
inference, failed warm-up recovery, and matching automation counters. This work does
not change permissions in the owner's live vault or publish a release.
