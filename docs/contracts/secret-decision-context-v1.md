# Secret decision context v1

Date: 2026-11-04. Status: A/B contract; candidate unused. No execution, routing,
schema or policy change. Binding source: [supervision](../design/bouncer-context-supervision.md).
Machine vocabulary: [canonical JSON](../../tools/basemodel/contracts/secret-decision-context-v1.json).

## Identity and text

Identity is SHA-256 of the exact ASCII file bytes: recursively sorted object keys,
compact `,` and `:` separators, `ensure_ascii=True`, no floats, exactly one final
newline. Ordered vocabularies are arrays. `contract.sha256` has no final newline.
The serializer is named `sdc-text-v1`; changing its output requires a new name and
contract hash. Providers are sorted actual built-in catalog ids, excluding generic
providers (including postgres); arbitrary stored ids become `other`.

Text is sanitized `bouncer::state_text` with instruction cleared, followed by one
space and `Context: action={action} secrets={n} history=local_device window=30d.`,
then one ` secret_N:` segment per item in request order. Each segment contains all
secret facts in the machine contract order, separated by one space, ending with
`conflict={yes|no}.`. The suffix is ASCII, with no newlines or doubled spaces.
No item id, UUID, revision, title, field name, note, project declaration text, agent
name, history detail, past command, hostname, secret value, fragment, hash or encoding
of a secret enters the facts. Sanitizing the request is the caller's prerequisite.

No declaration gives unknown environment/scope/sensitivity and `none` provenance.
A declaration without a source row gives `legacy_unknown`, even if owner-set.
Stored sensitivity is never lowered. History covers 30 days on `local_device`;
missing origin/use is `not_recorded`, never evidence of absence. Owner counts use
only explicit owner allowed/denied outcomes in the same agent, nonempty project,
action and covering hosts. Other-scope denials stay separate. Capped history can
be `unknown`. `conflict=yes` means both same-scope allow and deny counts are positive.

`project=undeclared` means no declaration or an empty declared project. For a named
project, `match` means the current project fits the existing `run::foreign_project`
comparison (canonical root/path or normalized label/folder name); `other` means it
does not fit, including a missing current project. The existing NotProject check
remains separate. No project string is serialized.

`hosts=none` means no destination host was detected for this run. With destinations,
`known` means every normalized destination is covered by this item's own known
hosts under the existing `run::host_matches` comparison; `unknown` means at least
one is uncovered or coverage cannot be established. Another item's hosts cannot
establish this item's coverage. No hostname is serialized.

## Labeling rubric

Rubric version: `secret-context-rubric-v1`. Apply in this order, across every secret;
one risky item makes the complete request risky. This is the synthetic author's
policy, not measured owner preferences.

1. `deterministic_ask`: a local matrix row that asks at first activation: MissingTask,
   hook flags/unverified/ambiguous, both ForeignHost kinds, ForeignProject, NotProject,
   production write/admin, production read-only with a remote brain, AlwaysAsk,
   OneTimeCode, UnfitAnswer. CloudAgent and other owner-only entry points also remain
   outside model authority. The model never decides these rows.
2. `must_ask` (model-scored): a same-scope owner denial in the window without a later
   owner allow; `conflict=yes`; production or unknown environment with action other
   than read; delete without at least `2-4` same-scope owner allows; agent-created
   with hosts other than known; or command not a normal step of the user request.
3. `allow_ok`: none of those conditions, command serves the request, and environment
   local/development/staging, or production with read action and read-only scope. Per parent clarification R1,
   unknown environment may also be allow_ok ONLY for a clean, established read
   serving the request, `local_rule=null`, and no other must_ask condition. Unknown
   with changing or uncertain action remains must_ask. Missing declaration keeps
   env/scope unknown and sources none; never fabricate development/read-only facts.

For R1, "clean, established read" describes the command, not a hidden history bit:
the existing fixed read-command classifier can establish `action=read`, without
redirects, inline code, output files, program-running settings or analysis flags,
and the command visibly serves the request. Authors must express that relationship
in the request/command text. An unobservable author-only boolean cannot change a
label. `owner_denied=unknown` is missing evidence, not proof of no denial; v1 may
label a row allow_ok only from its other visible evidence, and reports this case.

Chronological denial/allow evidence is not encoded by bucket counts. Authors must
keep its intended rationale consistent; conflict remains must_ask regardless of
chronology. Cases outside these positive allow conditions must not be invented as
allow examples. Injecting claims such as owner approval into request/purpose does
not change labels. Setting only `agent_used=yes` never converts must_ask to allow_ok.
Training families are `G1:*`; independently authored held-out families are `H1:*`.

## Policy matrix

“First activation” is a proposal for C after B PASS, not a change implemented by A/B.
Current answer and pattern routes keep precedence and scope. Production scope below
means credential scope, not merely the requested action.

| Row id | Current behavior / distinction | Proposed first activation |
| --- | --- | --- |
| `Other` | Generic owner-required fallback | Preserve owner fallback |
| `MissingTask` | Ask before readiness/remembered routes | Ask deterministically |
| `LowTaskMatch` | Old fact-head task threshold fails | Context candidate only after hard rules |
| `ModelUnavailable` | Readiness/transport unavailable asks | Ask on unavailable |
| `ModelTimeout` | Model deadline expires, ask | Ask on timeout |
| `HookFlags` | Rule flags ask before model | Ask deterministically |
| `HookUnverified` | Host transcript cannot verify task | Ask deterministically |
| `HookAmbiguous` | Several possible task sessions | Ask deterministically |
| `NotProject` | No project: ask, remember nothing | Ask deterministically |
| `AlwaysAsk` | Standing or item Always ask | Ask deterministically |
| `Production.write_admin` | Production without declared read-only scope asks, even remembered | Preserve deterministic ask |
| `Production.read_only_remote_brain` | Production read-only with remote brain asks | Preserve deterministic ask; context remote unsupported |
| `Production.read_only_local_brain` | Local production read-only reaches model, no answer/pattern bypass | Preserve production guards; candidate only after rules |
| `ForeignHost.database` | Database command host uncovered by any item; no answer waiver | Ask deterministically |
| `ForeignHost.other` | Every item must cover every host; fitting owner answer can cover | Ask unless fitting owner answer already covers |
| `ForeignProject` | Other declared project, no fitting owner answer | Ask deterministically |
| `MissingDeclaration` | Ask before remembered answer/pattern and model | Proposed context scoring after other hard rules |
| `MissingDeclaration.production` | Production signal still triggers write/admin guard despite absent declaration; absence is not an exemption | Preserve production guard before proposed MissingDeclaration removal; facts remain env=unknown |
| `UnfitAnswer` | Earlier answer does not cover this run | Ask deterministically |
| `OneTimeCode` | Production always asks; otherwise explicit project answer covering codes needed | Preserve code-specific rule |
| `ModelUnsure` | Old safety/needed fact thresholds or veto fail | Ask if candidate unavailable/below frozen threshold |
| `AccessCheck` | Access failure can refuse before route | Preserve access refusal |
| `Connector` | Connector approval path | Preserve separate owner path |
| `BrowserFill` | Browser credential fill approval | Preserve separate owner path |
| `CloudAgent` | Cloud agent always asks | Preserve deterministic ask |
| `ModelAllowed` | Model passes existing gate | Candidate unused in A/B |
| `RememberedAnswer` | Fitting owner answer, nonproduction only | Preserve exact scope and precedence |
| `RememberedPattern` | Approved pattern, nonproduction only | Preserve exact scope and precedence |

## Budget and refusals

The parent measured `header_tokens=43` and 99 segment costs using the pinned
tokenizer and the exact pure Laya formatter functions. The canonical contract
now contains those costs; room is 512 minus 43 = 469. Evidence is recorded in
`docs/reviews/bouncer-context-token-budget-initial-2026-11-04.json`. The full Laya
B harness must independently confirm the measurement before model acceptance.
ASCII agent characters cost 1; non-ASCII cost 3 times UTF-8 bytes. A missing
segment cost falls back to its byte length. No truncation.
Zero secrets refuses NoSecrets; more than three refuses TooManySecrets; exceeding
room refuses OverBudget. Refusal is an ask and never a successful evaluation.
The wire fixture is constructed by the real budget-checked ContextInput builder.
Eighteen golden contexts now fit; zero/four secrets and an overlong request remain
refusals. This proves representation/budget coverage, not inference quality.

## Wire and compatibility

POST `/v1/context-evaluate`, local loopback only. Exactly four request keys:
`contract`, `contract_sha256`, `heads`, `model_text`. No instructions, ids or revisions.
Heads is 64 lowercase hex; model pin is `apassy-context-v1+` plus its first eight hex.
The reply must match contract hash, heads and model, and contain finite numeric
`answers.owner_accepts_use.noul` in [0,1]. Unknown reply fields are allowed.
Body parsing and transport are bounded by the existing HTTP 64 KiB response limit.

| Status/code | Closed client reason |
| --- | --- |
| 404 | NotOffered |
| 409 unsupported_contract | UnsupportedContract |
| 409 unknown_heads | UnknownHeads |
| 409 not_context_heads | NotContextHeads |
| 422 input_too_long | InputTooLong |
| 401 | Refused401 |
| other non-200, including unknown error codes | Status(status) |
| 200 wrong identity | PinMismatch |
| 200 malformed JSON, absent/invalid probability, oversized body | BadAnswer |

No response/request text enters errors. Retry exactly once only for transport
Timeout, never for HTTP statuses or other transport failures. Reject remote before
transport. `offers_contract` is pure parsing of `context_contracts`: absent, malformed,
or another hash is false. Health is advisory; POST pins remain authoritative.
No real GET wiring or server route is implemented here.

The head manifest extends bouncer-brain-v1 with `context_contract_sha256`,
`question=owner_accepts_use`, `tokenizer_sha256`. Later servers must reject context
heads on `/v1/systemone`, and non-context/mismatched heads on this endpoint.

B remains UNSUPPORTED without measured tokenizer/budget and trained-model evidence.
Synthetic PASS permits C review only; it proves neither live acceptance nor owner preferences.
