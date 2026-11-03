# ADR 0043 — A shared base model from owner data: opt-in, local anonymization, retention

Date: 2026-11-03.
Status: PROPOSED (draft). Written on the owner's decision of 2026-11-03 ("build everything in the
ADRs except the TEE track; no approval of intermediate steps"). Choices are **chosen by this ADR;
the owner can change them**. No data is collected before the gate of section 9 passes.
Answers: [ADR 0035](0035-bouncer-hosting-and-training-choice.md) owner decision 5 and open question 3
("only with a separate opt-in and anonymization, defined in a separate ADR before any collection").
Plan: [implementation-plan-misc.md](../design/implementation-plan-misc.md), units M23 to M26. The
hosting and training service itself is [implementation-plan-0035.md](../design/implementation-plan-0035.md);
that plan keeps the base model out of its scope and names this ADR.

## Context

- The bouncer brain is a shared encoder (ModernBERT-large) with decision heads (`apassy-base-v1`).
  Each owner can fine-tune the heads on their own decisions (ADR 0035). The stock heads come from
  synthetic and public data only.
- Real decisions of many owners would make the stock heads better for every new owner. A new owner
  then gets fewer questions before the 300 decisions of the training gate.
- The bouncer state holds sensitive text: the user request, the command, the relative directory, the
  purpose, environment variable names, and the owner rule (ADR 0007). A command can hold a host, a
  path, a customer name, an email address, or a value that an agent pasted by mistake.
- No Apassy server reads content today, except the opt-in hosted bouncer brain (ADR 0035 §4).

## Decision

### 1. Off by default, a separate opt-in

- Settings → Bouncer gets **Help train the shared bouncer brain**, off by default, on every plan and
  for self-hosters. It is not part of the Connect hosting consent and not a condition of any plan.
- Turning it on shows a consent sheet (section 8) and needs the owner check. Turning it off needs
  none and stops every later batch.

### 2. What leaves the Mac: skeleton records

The Mac builds each record locally from one decision. Only these fields leave:

| Field | Content |
| --- | --- |
| `skeleton` | The command as tokens. A program name stays only when it is in the vocabulary of the bundled rule packs (`packs/*.json`); its subcommands and flags stay only when that pack names them. Every other token becomes a typed placeholder: `<PATH>`, `<HOST>`, `<URL>`, `<EMAIL>`, `<IP>`, `<NUM>`, `<HEX>`, `<B64>`, `<STR>`, `<WORD>`. |
| `action` | `read`, `change`, `deploy`, or `delete` (the action class of the bouncer gate) |
| `env` | For each environment variable of the run, the provider class of its item (the provider tiles of the app, for example `stripe`, `github`, `postgres`, or `other`), never the variable name |
| `placeholder` | Whether the run used placeholder mode (ADR 0011) |
| `label` | The owner's answer: `allow` or `deny`. Only decisions with `decided_by = owner`. |
| `versions` | The app version and the base model version |

Never sent: the user request, the purpose, the agent name, item names and ids, environment variable
names, the directory, hosts, URLs, file names, numbers, quoted strings, any token of high entropy,
the owner rule text, and anything of an item marked production. A decision of a production item, of
a run with a code (ADR 0034), or of a cloud agent is never a record.

Consequence: contributions train the risk heads (`writes`, `destroy`, and the others). The
`task_match` head needs the user request and stays trained on synthetic data.

### 3. The owner sees each batch

- The app builds the candidate records from the local decision log (`decision_log`, the source of
  the `apassy-decision-v1` export of `src/broker/finetune.rs`) only when the owner opens **Review and
  send**, and keeps them in memory. The vault keeps only a row per sent batch (a local table, not
  synced: `contribution_batch`, vault schema 35) with its delete token and the newest decision it
  covered. Nothing leaves without an owner action.
- **Review and send** shows the batch exactly as it will be sent, one row per record, at most 200
  rows. The owner can remove rows. **Send** needs the owner check (`OwnerAction::ContributeExamples
  { count, batch_hash }`).
- The app offers a batch at most once a week, as a quiet line in Settings → Bouncer, never as a
  notification.

### 4. Anonymous upload

- `POST /v1/contributions` to the contribution endpoint of the Apassy project in the European Union.
  No Connect account, no device key, no relay team.
- The edge does not forward the client address to the service, and the service writes no request
  log. Rate limits at the edge count per address in memory only.
- Each batch carries a random `delete_token` (kept on the Mac) and a `contributor` id: 128 random
  bits made by this Mac for one calendar year. The service uses `contributor` only to count distinct
  contributors (section 5). A new year gives a new id, so batches of two years cannot be linked.

### 5. A skeleton must be common

A record enters a training set only when the same `skeleton` came from at least **5 distinct
contributors** (`k = 5`). Rare commands, which identify a person or a company most easily, never
train the shared model.

### 6. Retention and deletion

- Raw batches stay at most 180 days, or until the next training run, whichever is first. Then they
  are deleted.
- A training set keeps only aggregated rows: `(skeleton, action, env, placeholder, allow count, deny
  count)` that passed section 5. It has no `contributor` and no time finer than the month.
- `DELETE /v1/contributions/<delete_token>` deletes a batch before training. **Delete my
  contributions** in the app sends every token of this Mac.
- A model that a training run produced cannot unlearn a record. The consent sheet says so.

### 7. The model

- A new base version (`apassy-base-v2`, …) ships in a normal release under Apache-2.0, with a data
  card: the number of batches, contributors, records, distinct skeletons, `k`, and the dates. The
  records and the training sets are never published.
- On each Mac the new base heads start in shadow mode, as every new head set does (ADR 0035 §3). The
  owner promotes them.

### 8. The consent sheet

It says, in this order: what leaves (section 2, with an example record), what never leaves, that each
batch is shown before it is sent, the `k = 5` rule, the retention of section 6, that a trained model
cannot unlearn, the location (EU), and how to turn it off and delete. It links the privacy policy.

### 9. The gate before any collection

1. The skeletonizer passes the adversarial corpus test of the plan (unit M23): no planted secret,
   host, path, email, name, or number survives.
2. A judge panel (2× opus + 1× fable) finds no open high finding in the skeletonizer, the upload, and
   the service.
3. The privacy policy has the section of this ADR (owner-only: legal text).
4. The contribution endpoint is live (owner-only: a new service that receives user data).

Until all four hold, the switch of section 1 is hidden.

## Who sees what

| Party | Sees |
| --- | --- |
| Contribution store (Apassy project, opt-in) | Skeleton records, contributor ids of one year, batch times. No address, no account, no value. |

The trust model ([trust-model.md](../security/trust-model.md)) gets this row with unit M25.

## Rejected options

- Collect the full bouncer state with consent: rejected; free text cannot be anonymized reliably.
- Differential privacy on the heads (DP-SGD) instead of `k`: kept for later. It needs many more
  records than early Apassy has, and the skeleton rule already removes the free text.
- Federated training of the heads on each Mac: kept for later. The heads are small, but a secure
  aggregation service is a larger project than this one.
- Contributions linked to a Connect account: rejected; they would link a person to commands.

## Relation to other records

- ADR 0035: the hosted bouncer brain and Apassy training stay separate services. This store is not
  the bouncer brain service and never receives a bouncer request.
- ADR 0007, ADR 0009 §2: owner data leaves the Mac only through section 3, never by default.
- ADR 0010: the training gate (300 decisions, 30 denials) for an owner's own heads is unchanged.
