# ADR 0031 — The bouncer decides by default

Date: 2026-10-31.
Status: Accepted. The owner decided "Decide by default" in the implementation request.
Supersedes the routing permission requirement of [ADR 0029](0029-bouncer-evaluation-permission.md).
ADR 0029 remains a historical record. Its readiness, timeout and authorization protections remain.

## Problem

The model can be ready while nearly every credential request asks the owner before
inference. Default production, default environment/risk sources and missing local
evaluation scopes require repeated manual setup. This contradicts the low-friction
direction of [ADR 0025](0025-low-friction-access.md): over-asking is acceptable;
configuration before each credential can be evaluated is not.

## Decision

After the existing hard checks, each process request goes to the model, including
first use, staging, default-source environment/risk and unconfirmed production.
No evaluation scope, earlier use or per-credential setup is required.

The following still ask or refuse before inference, with their existing reasons:

- Access restrictions, including Never, Only these items, archived/restored items,
  missing process bindings and duplicate variables.
- Command-analysis flags, foreign database hosts, Always ask, and production found
  by a signal, confirmed by usage or set by the owner without a fitting allowance.
- A model that is off, unavailable or has not passed inference readiness.
- Root, HOME or a parent of HOME instead of a project.
- An existing owner execution answer that does not cover this run.
- A foreign-project declaration without a fitting owner execution answer, and a
  missing user request or declaration.

Fitting explicit execution answers and owner-taught patterns retain their existing
semantics. Evaluation scopes never waive the foreign-project check.

The current model input has no structured declaration-source fields. The broker
therefore treats default classifications more strictly: every such model decision
requires `task_match >= 0.80`, even for known safe commands or certain reads.
Calibration cannot lower this check. The original sensitive declaration is kept:
high-risk or irreversible credentials still need the existing read-only certainty
check for commands that are not known safe. Other thresholds and model weights do
not change. The question and decision log state the actual failed check and the
stricter treatment. Shadow decisions use the same treatment.

A model allow permits only the current run. It creates no grant, remembered answer,
evaluation scope, classification confirmation or pattern approval. Each later run
is evaluated afresh unless an explicit owner execution answer or pattern covers it.
The credential revision, declaration and sources, access, project, canonical
folders and supported command/script binding are checked again before secret use.
Existing limits of the binding (no transitive dependency pinning or atomic
filesystem isolation) remain.

Schema stays at 20. Existing evaluation-scope data and authenticated compatibility
APIs remain. Routing neither reads nor requires these scopes. The broker stops
making offers, and Decisions hides the obsolete "Allow once and enable bouncer"
setup. This preserves stored data and other callers without asking the owner for
pointless configuration. Ordinary Allow once retains its meaning on every device.
Connector operations keep their existing fixed-profile behavior.

## Evidence and visibility

Settings > Bouncer shows inference readiness and today's UTC counts from the local
decision log: allowed by the model, asked the owner, and failed. Failed means model
or readiness failure, or an unanswered/invalidated question; it can overlap asked.
Owner denials, patterns and remembered answers are not model successes.
The view refreshes with the existing supervisor repaint timer.

The evaluation harness uses the broker's non-executing `evaluate_run` entry point.
It shares routing and the authorization recheck, then returns before credential-environment preparation,
proxy startup and process creation. This mode has no agent wire action. Scratch
project names match fixture declarations; `cwd_project` can deliberately differ.
A marker executable must never run. Missing intended inference, unsafe allowances,
empty input and harness errors fail the process. Historical published sets and
labels stay unchanged. The new frozen smoke set is bounded routing evidence,
not a broad or independent model-acceptance claim.

The existing desktop toolkit forces light appearance. A dark tour can document
that limit; it cannot establish dark-mode design acceptance without a separate
theme implementation.
