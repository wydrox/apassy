# 0045: Secret context for the bouncer candidate

Date: 2026-11-04. Status: **Proposed**. Parent must verify the ADR number on current main.

The current fact heads see the user request, command and purpose, without structured
provenance/history. We propose measuring a single `owner_accepts_use` head on the
frozen pinned encoder using bounded, closed-vocabulary metadata. The canonical
[contract and policy matrix](../contracts/secret-decision-context-v1.md) define the
candidate. No secret value, fragment, hash or encoding enters model context.

A/B adds only the contract, evidence/facts builders, local client and synthetic
measurement harness. The verdict is unused. No schema, server route, live call,
routing or policy change follows from this ADR. Remote evaluation is unsupported.

Only after supervised B PASS may C propose replacing MissingDeclaration's blanket
ask with context scoring. Production signal guards must still run first: missing
declaration never exempts a production write/admin credential. Local production
read-only still needs safety checks; remote production read-only still asks.
Database foreign-host veto, other-host and project scope checks, hook validation,
AlwaysAsk, one-time-code rules and unfit answers retain their exact distinctions.
Remembered answers/patterns retain existing scope and precedence. The matrix also
preserves access refusal, connector, browser-fill and cloud-agent paths.

The parent revised the initial byte-only contract with a measured 43-token header
and 99 segment costs; the evidence and regenerated pins are recorded with the
contract. The full B environment still must confirm that measurement. Refusal is
not successful coverage, and budget coverage is not model-quality evidence.
Owner/legacy provenance cannot be distinguished without a later schema change,
and history is device-local and may be incomplete. Synthetic labels express the
author's rubric, not owner preferences. Full B gates include held-out risky false
allows, counterfactuals, injection, coverage and cost; dry runs are UNSUPPORTED.
