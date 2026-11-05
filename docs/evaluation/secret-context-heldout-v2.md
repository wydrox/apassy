# Independent secret context held-out H2

This is an initial, unsealed synthetic authoring handoff under
`secret-context-rubric-v1`. The author used only the supplied H2 brief, public
human and machine contracts, inline R1 clarification, and applicable repository
instructions. No earlier dataset, template, trainer, preflight implementation,
candidate output, score, checkpoint, review, owner data, or credential value was
consulted. The required `H1:h2-` family namespace is a reader convention and does
not indicate use of H1 content. All resources and requests are synthetic.

The generator uses Python standard library code, fixed iteration, and sorted,
compact ASCII JSON with exactly one final newline. It reads only the public
machine contract and its own source; comparison mode additionally reads its own
JSONL and manifest. It does not import repository Python modules or invoke any
service, executable, tokenizer, model, or preflight. Its output contains aggregate
counts and closed failure messages only. The manifest binds exact JSONL bytes
and generator source bytes with SHA-256; the document's hash is reported by the
author separately.

## Population

| Class | Allow | Must ask | Deterministic ask | Total | Fact pairs | Injections |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| cold_start_no_declaration | 72 | 72 | 24 | 168 | 48 | 24 |
| known_with_owner_history | 72 | 72 | 24 | 168 | 48 | 24 |
| changed_or_rotated | 72 | 72 | 24 | 168 | 48 | 24 |
| repeat | 72 | 72 | 24 | 168 | 48 | 24 |
| multi_secret | 72 | 72 | 24 | 168 | 48 | 24 |
| Total | 360 | 360 | 120 | 840 | 240 | 120 |

Each class has 60 original allows and 60 original model-scored asks, plus 12
injection variants on each label. The injections are part of the displayed
population. Every multi-secret row has two items. There are 312 allow rows with
explicit HTTPS destinations under `.example.test`, with independent known host
coverage on every item. No row contains a credential value.

The 240 counterfactuals preserve the complete request, action, class and family;
only facts, label and rationale change. A single risky item is sufficient.
The 60 independent task-mismatch asks expose a visible mismatch rather than an
unobservable author flag. Injections preserve facts, command, action and label;
they append untrusted claims to request or purpose, use `injection_of`, and have
no `pair_of`. No example text is duplicated in this document.

Cold-start facts retain absent provenance and unknown environment, scope and
sensitivity on every row. Positive history classes carry their specified
history; recent changes alone are not a veto. Other-scope denials and unknown
denial history are distinct from explicit same-scope denials. Positive reads
are intended to be clean established reads visibly serving their requests.
Changing actions use explicit HTTP methods and operation-specific endpoints.

Model-scored asks cover same-scope denial, conflict, unknown environment with
non-read action, production non-read action with read-only scope, insufficient
delete approval, agent-created credentials without known hosts, and commands
that do not serve the request. Same-scope positive allow and deny buckets carry
`conflict=yes`. Deterministic cases use public matrix IDs: 36 MissingTask,
36 ForeignHost.other, 24 ForeignProject and 24 Production.write_admin. The
cold-start deterministic subset uses only missing-task and uncovered-host cases,
preserving its necessary provenance condition. Production admin exclusions also
include read operations; read action cannot waive that guard.

## Reproduction

From the checkout root, materialize the two generated owned files with:

```text
python3.12 -I -B tests/evals/secret_context_heldout_v2.py --write
```

In the parent's authorized CI environment, byte comparison is available with:

```text
python3.12 -I -B tests/evals/secret_context_heldout_v2.py --check
```

Comparison regenerates bytes in memory, compares both files exactly, and exits
nonzero on mismatch without modifying either file. Neither mode reads any
other dataset. All four owned files must travel together for review; generation
does not modify the documentation or generator.

## Validation and limitations

Only initial source writing and bounded fixture materialization are authorized
locally. Tests, byte comparison, lint, import validation, budget/tokenizer checks,
compiled replay, preflight, blind judgement, CI, model inference, and sealing are
NOT_RUN in this authoring task. Counts above describe the authored population,
not measured fit or acceptance. The per-class fit target and the minimum 300
fitting risky rows require the parent's compiled CI validation; no tokenizer or
candidate was used to optimize text. Natural requests were not truncated.

The dataset samples a public synthetic policy, not measured owner preferences.
Its deterministic subset is intentionally limited to exclusions expressible by
the row's visible request and fact fields; it does not simulate hidden hook,
brain location, answer, or code-type state. Two-item multi-secret coverage does
not establish three-item budget acceptance. Repeated resource and operation
structures provide controlled counterfactuals and do not establish natural
traffic representativeness.

Parent-controlled preflight feedback may contain check names, counts and at
most 50 H2 IDs, with no G1 text or candidate information. At most two pre-seal
repair rounds are allowed, followed by independent blind judgement and a parent
seal. This handoff is not a seal. No H2 bytes may change after that seal.
