# ADR 0035 — The owner chooses who hosts and who trains the bouncer brain

Date: 2026-11-02.
Status: ACCEPTED by the owner on 2026-11-02, with the implementation plan
[implementation-plan-0035.md](../design/implementation-plan-0035.md) ("start with the plan").
Progress (2026-11-03): wave 1 (units A, B and D1, PR #67) shipped in 0.5.14. The later waves are not merged.
Direction from the owner on 2026-11-02: "The user has the choice:
trains it themselves or delegates; hosts it themselves or delegates." The owner
answered the open decisions on the same day (last section).
Fits the draft [ADR 0037](0037-own-relay-open-source.md): all of Apassy is open
source, and Apassy Connect is the paid, optional hosted part (its D2 and D3).
Plans (2026-11-03): "Personal and Team" below are the Connect plans; Connect Family is added. See [plans](../product/plans.md).
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
| Hosting of the bouncer brain (inference) | This Mac, or a server of the owner (for example on the owner's tailnet) | The bouncer brain service of Apassy Connect |
| Training of the bouncer brain (fine-tune of the heads) | This Mac, or a server of the owner | A training job of Apassy Connect |

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
`tools/basemodel/serve.py` and the trainer `tools/finetune/local_train.py`. The
weights are Apache-2.0: the Laya checkpoint `convaiinnovations/laya` (model card
at the pinned revision `55cf4c4`, checked on 2026-11-02, tag `commercial-use`) and
its encoder ModernBERT-large. An image that contains the weights also contains
their license and notice files.

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

A non-loopback address must use `https://`. On a tailnet, a Tailscale Serve
certificate gives a public certificate for the `*.ts.net` name. Tailscale gives only
reachability, never authorization: the owner's server still needs its credential (a
bearer token). The credential is in the vault, on this Mac only; it does not sync.
For Apassy Connect, the device signs in to the owner's Connect account
([ADR 0037](0037-own-relay-open-source.md) D3). The sign-in uses a device key, as in
[ADR 0019](0019-relay-teams-and-accounts.md) section 5, with its own domain tag.

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
- Training: the examples go to one job. The job runs in its own limited
  container, one job at a time (section 8). The service deletes the examples when the job ends, and at the latest 24 hours after
  the upload if the job fails.
- Head sets: the service keeps a head set only while the owner uses Apassy hosting.
  With own hosting, it deletes the head file after the download. `DELETE /v1/owner`
  deletes every head set and job. The app shows the result of the deletion.
- Location: the European Union (section 8).
- What the service reads: the bouncer brain service is the one part of Apassy
  Connect that reads content: the state of each bouncer request (ADR 0007: the user
  request, the command, the relative directory, the purpose, the environment
  variable names and the owner rule), and the examples of a training job. Every other
  Connect function is blind ([ADR 0037](0037-own-relay-open-source.md)). The owner
  turns it on separately. The consent screen shows exactly what leaves the Mac, and
  ADR 0037 lists it in "Who sees what". A variant in a confidential VM (TEE) belongs
  to the enterprise track of ADR 0037.
- The base model: Apassy uses owner data for the shared base model only with a
  separate opt-in and anonymization (owner decision 5). A separate ADR defines the
  anonymization, the retention and the consent before anything is collected. Until
  then, no owner data goes into the base model.

### 5. Trust

A delegated host changes the trust model. A server that is under the control of
an attacker can give low-risk answers. Then the bouncer gate can run development requests
without a question, inside the limits of section 3. It cannot cause a production
run, a hard check failure, secret output or a foreign host. The app tells the owner
about this risk before the owner selects a remote host.

[ADR 0018](0018-local-bouncer-shared-vault-relay.md) still applies: a model answer
is not proof that a client obeyed a shared policy. The bouncer brain service is a
separate process. It does not run inside the Connect byte relay, and the relay does
not call it.

### 6. Plans and price

Own hosting and own training are free and open source, in every plan (ADR 0037
D3). Apassy hosting and Apassy training are part of the paid Apassy Connect, for
Personal and Team (owner decision 1). The price follows the measured cost for each
owner. It can be low because one encoder serves many owners, a head set is small,
and a training job trains only the heads.

### 7. Deadlines

A remote bouncer brain (the owner's server or Apassy Connect) has a deadline of 20 s
for each attempt, with the existing single retry after a transport timeout, so at
most 40 s (owner decision 3). The bouncer brain on this Mac keeps 10 s for each
attempt. After the deadline, the bouncer gate asks the owner. (ADR 0007 still says
3 s; the code has used 10 s since before this ADR.)

### 8. Where Apassy Connect runs the bouncer brain

The first host is the Contabo VPS `ottervibe`, in its own Docker Compose project with
hard limits (owner decision 2). The first limits are 2 vCPU and 3 GB of memory for
inference, and 2 vCPU and 4 GB for one training job at a low CPU priority. The
limits protect the production services on the same VPS (mail, relay, pretix and
MDmesh). A read-only check on 2026-11-02 showed 6 vCPU (AMD EPYC), 12 GB of memory
with 6.9 GB available, no swap in use, and a load of 0.7 to 1.8. The VPS region must
be confirmed as EU.

The latency with these limits is measured on `devbox-x86` with the same container
limits, never with a test on the production VPS. If the 95th percentile is above
the deadline of section 7, the service moves to a separate server.

## Stages

| Stage | Content | Measurement |
| --- | --- | --- |
| 1 | Protocol with `heads`, HTTPS address with a credential, consent screen, container image | CPU latency of one bouncer request (5 or 6 questions, up to 512 tokens) on arm64 and x86_64, also with the container limits of section 8. The 95th percentile must stay under the 20 s deadline of section 7; the target is 10 s. |
| 2 | Own training with a remote host: upload of the head set, shadow mode on the server | The shadow answers on the server are the same as the local shadow answers for the same head set. |
| 3 | Apassy Connect hosting: many owners on one encoder, Connect account sign-in, deletion | Memory for each active owner; latency at 10 parallel owners; a deletion test |
| 4 | Apassy Connect training: jobs, temporary examples, result download | Job time and cost; the examples are absent after the job; the head set is the same as one trained locally from the same examples, within the tolerance of `train.py` |

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

## Owner decisions (2026-11-02)

1. Plans: Apassy hosting and Apassy training of the bouncer brain are part of the
   paid Apassy Connect, for Personal and Team. Self-hosting is free and open source,
   for example on the owner's server over Tailscale (section 6).
2. Location: the Contabo VPS `ottervibe`, with hard CPU and memory limits (section 8).
3. Deadline: 20 s for each attempt to a remote bouncer brain; 10 s on this Mac
   (section 7).
4. License: the Laya weights and ModernBERT-large are Apache-2.0, also for a hosted
   service (section 2).
5. Shared base model: only with a separate opt-in and anonymization, defined in a
   separate ADR before any collection (section 4).
6. Account: the Apassy Connect account of ADR 0037 D3, for Personal and Team. No
   relay team is needed (section 2).
7. Content at Connect: the bouncer brain service is the one Connect service that
   reads content. It is an opt-in with a consent screen (section 4).

## Open questions

- The final container limits and the price, after the measurement of stage 1.
- The region of the VPS (it must be in the EU).
- The ADR for the opt-in, anonymized base-model data (decision 5).
- ADR 0037 must list the bouncer brain service in "Who sees what" when it is accepted.
