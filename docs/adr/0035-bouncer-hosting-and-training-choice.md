# ADR 0035 — The owner chooses who hosts and who trains the bouncer brain

Date: 2026-11-02.
Status: PROPOSED. Direction from the owner on 2026-11-02: "The user has the choice:
trains it themselves or delegates; hosts it themselves or delegates." The open
decisions are in the last section.
Amends [ADR 0018](0018-local-bouncer-shared-vault-relay.md) ("The bouncer model,
command analysis, and learning stay on each client computer") and
[ADR 0009](0009-general-by-default-and-learning.md) section 2 ("They never leave the
computer"). Command analysis, policy, hard limits and the decision order of
[ADR 0031](0031-bouncer-decides-by-default.md) stay in the bouncer gate on the Mac.

Words ([bouncer.md](../operations/bouncer.md), Words): the **bouncer brain** is the
decision model. It gives a probability for each question. The **bouncer gate** is the
fixed part in Apassy. It makes the decision from those answers and its own checks.
This ADR is only about the bouncer brain. The bouncer gate always runs on the Mac.
Apassy does not host it, and its learning (remembered patterns and the `task_match`
calibration) stays on the Mac.

## Problem

The bouncer brain needs about 1.8 GB of memory on an Apple GPU, and up to 2.9 GB
during requests (after the fp16 change of PR #60; before it, 3.4 GB and more). The
local fine-tune needs AC power, encoder passes over every example, and up to one
hour. Some computers cannot do this well: Macs with 8 GB, Macs that are on battery
most of the time, and computers without a supported GPU. On these computers the
bouncer is off or slow, and the owner gets more questions. This is the opposite of
[ADR 0025](0025-low-friction-access.md).

Other owners do not want any data to leave the computer. They must keep the
current local path, without loss.

## Facts that make a choice cheap

- The learning step trains only the decision heads: 26.2M parameters, about 100 MB
  in fp32. The encoder (ModernBERT-large, 421.3M parameters, fp16 in the base
  checkpoint) is the same for every owner and does not change.
- `tools/basemodel/serve.py` already computes two head sets on one encoder pass
  (the stock heads for `leak`). The same method serves many owners from one encoder,
  and runs a shadow candidate at almost no extra cost.
- One server process thus holds one encoder (about 0.85 GB) and a cache of head
  sets, about 50 to 100 MB for each active owner.

## Decision

### 1. Two independent choices

| Choice | Own (default) | Delegated to Apassy |
| --- | --- | --- |
| Hosting of the bouncer brain (inference) | This Mac, or a server of the owner | The Apassy bouncer service |
| Training of the bouncer brain (fine-tune of the heads) | This Mac, or a server of the owner | An Apassy training job |

All four combinations are valid. The default is own hosting and own training on
this Mac, as today. The owner can change each choice at any time in the Learning
view. A change needs a fresh owner check (ADR 0030).

| Hosting | Training | What leaves the Mac |
| --- | --- | --- |
| Own | Own | Nothing (today), or only to the owner's server |
| Apassy | Own | Bouncer requests, and the trained head file |
| Own | Apassy | The training examples, for one job |
| Apassy | Apassy | Bouncer requests, and the training examples for each job |

### 2. One protocol, two operators

The owner's server and the Apassy service use the same protocol. Only the address
and the credential are different. Apassy publishes the server as a container image
(arm64 and x86_64 on the CPU, and x86_64 with CUDA). The image contains
`tools/basemodel/serve.py` and the trainer `tools/finetune/local_train.py`.

- `POST /v1/systemone` gets a `heads` field: the SHA-256 of the active head set, and
  an optional `shadow_heads`. The server answers with both, from one encoder pass.
  An unknown hash gives HTTP 409. The bouncer gate treats 409 as "unavailable" until the
  head set is on the server.
- `PUT /v1/heads/<sha256>` stores a head set and its manifest. The server checks the
  hash, the base revision and the base weights against the manifest, as
  `serve.py` does today.
- `DELETE /v1/heads/<sha256>` and `DELETE /v1/owner` remove one head set or every
  head set and job of the owner.
- `POST /v1/train` starts a job with the examples of `src/broker/finetune.rs` (the
  `apassy-decision-v1` export, converted). `GET /v1/train/<id>` gives the state, and
  at the end `result.json`, the head file and its manifest.

A non-loopback address must use `https://`. The credential is in the vault. For
the Apassy service, the device signs in with a device key, as in
[ADR 0019](0019-relay-teams-and-accounts.md) section 5.

### 3. What does not change in any combination

- The bouncer gate makes every decision on the Mac, as it does today with the local
  bouncer brain. The server only gives the probability for each model question (`task_match`,
  `writes`, `destroy` and the others). `decide` in `src/broker/bouncer.rs` turns
  them into "run" or "ask the owner", in step 8 of the decision order
  (`docs/operations/bouncer.md` section 3.0). Steps 1 to 7, the thresholds,
  command analysis, "production always asks"
  ([ADR 0010](0010-closing-open-decisions.md)) and Always ask stay local. The
  credential stays in the vault on the Mac, and Apassy gives it to the process.
  The server never receives it.
- An unavailable, slow or wrong answer is never an allowance. A missing answer, a
  wrong model version or a wrong head hash means "unavailable", and the owner is
  asked.
- The training gate of ADR 0010 stays the same: 300 owner decisions and 30 owner denials.
- A new head set always starts in shadow mode. Only the owner promotes it. This is
  also true for a head set from an Apassy job.
- No payload contains a secret value, the vault path, or an absolute project path.
  Requests contain the same state as the local bouncer (ADR 0007).
- The owner can always get the active head file. A head set that Apassy trained can
  run on the owner's Mac or server. The owner pays for convenience, not for access
  to their own model.

### 4. Data at the Apassy service

- Inference: the service keeps requests only in memory, for the duration of one
  request. It does not log the state or the answers. It records counts, latency and
  errors, without request data.
- Training: the examples go to one job. The job runs on a temporary worker. The
  service deletes the examples when the job ends, and at the latest 24 hours after
  the upload if the job fails.
- Head sets: the service keeps a head set only while the owner uses Apassy hosting.
  With own hosting, it deletes the head file after the download. `DELETE /v1/owner`
  deletes every head set and job. The app shows the result of the deletion.
- Location: the European Union.
- Apassy does not use owner data to train the base model. A shared base model from
  many owners is outside this ADR (open decision 5).

### 5. Trust

A delegated host changes the trust model. A server that is under the control of
an attacker can give low-risk answers. Then the bouncer gate can run development requests
without a question, inside the limits of section 3. It cannot cause a production
run, a hard check failure, secret output or a foreign host. The app tells the owner
about this risk before the owner selects a remote host.

[ADR 0018](0018-local-bouncer-shared-vault-relay.md) still applies: a model answer
is not proof that a client obeyed a shared policy. The relay does not use the
bouncer service, and the bouncer service does not run on the relay.

### 6. Plans and price

Own hosting and own training are in every plan, also Free. Apassy hosting and
Apassy training are part of the paid plans (open decision 1). The low price is
possible because one encoder serves many owners, a head set is small, and a
training job trains only the heads.

## Stages

| Stage | Content | Measurement |
| --- | --- | --- |
| 1 | Protocol with `heads`, HTTPS address with a credential, consent screen, container image | CPU latency of one bouncer request (5 or 6 questions, up to 512 tokens) on arm64 and x86_64. Today each attempt has a deadline of 10 s, with one retry after a transport timeout ([bouncer.md](../operations/bouncer.md) section 1). |
| 2 | Own training with a remote host: upload of the head set, shadow mode on the server | The shadow answers on the server are the same as the local shadow answers for the same head set. |
| 3 | Apassy hosting: many owners on one encoder, device keys, deletion | Memory for each active owner; latency at 10 parallel owners; a deletion test |
| 4 | Apassy training: jobs, temporary examples, result download | Job time and cost; the examples are absent after the job; the head set is the same as one trained locally from the same examples, within the tolerance of `train.py` |

## Required checks

- With every combination, an unavailable server or a wrong head hash asks the owner.
- A server answer cannot cause a production run, a hard check failure, secret output
  or a foreign host.
- The requests and the training examples contain no secret value. Test with
  synthetic credentials whose values are searched for in every payload.
- A head set from an Apassy job starts in shadow mode and needs the owner to promote
  it.
- A change of a choice needs a fresh owner check.
- After `DELETE /v1/owner`, the service has no head set, job or example of the owner.
- The local path (own hosting and own training on this Mac) works with no account
  and no network.

## Open decisions

1. Which paid plans include Apassy hosting and Apassy training, and the price.
2. Where the Apassy service runs. The Contabo VPS (`ottervibe`) is production and
   can host an approved service, but its free memory and CPU must be measured first.
   The other choice is a separate server in the EU. Training jobs need a temporary
   worker.
3. The latency budget for a remote host: does the deadline of 10 s for each attempt,
   with one retry after a transport timeout, stay?
4. The license of the Laya weights (`convaiinnovations/laya`) for a hosted service.
   The `laya` package is Apache-2.0. The model card was not checked.
5. A shared base model from the decisions of many owners: separate opt-in,
   anonymization, or not at all.
6. The account of the Apassy service for a Free or Personal owner without a relay
   team: a device key with a subscription, or a relay team.
