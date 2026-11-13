# ADR 0046 — Decision reasons and "Next time"

Status: Accepted for implementation.
Date: 2026-11-13

The owner asked that each decision of the bouncer say why it went as it did, and offer
a way to change what happens the next time. The owner also asked for less text: so a
decision says one line at rest, and the facts come on demand.

## Context

- A run is refused by a check, asked by a hard rule or a route, or allowed by the
  model, a remembered pattern, or a remembered answer (ADR 0025, ADR 0031). Each
  outcome has a reason kind (`ReasonKind`) and, for a flagged run, its rule flags.
- The reason kind and the refusal code were in the decision log file only. The vault's
  decision log kept the note, which is an agent-facing sentence or a model note.
- The answers that change future decisions exist already: the project answer, the
  agent exceptions, "Always ask me", and the removal of an answer or a pattern. All of
  them except the removals were reachable only from a waiting question.

## Decision

### 1. Rules

1. One sentence per decision, from a closed table (`broker::reasons`). The same
   sentence is the title of the question and the "Why" of its History entry, except
   for a browser fill, whose question has its own title, and an injection flag, whose
   History line names the stored phrase ("Your prompt mentions “bouncer”."). A short
   form (at most 30 characters) is the reason on the History row.
2. The broker records the reason as closed words. The app never parses prose.
3. A button of "Next time" does only what the owner can already do elsewhere, plus one
   new entry point: saving the project answer that the question itself offered.
4. Loosening needs the owner check. Tightening does not.
5. No hard rule changes. Where nothing can change, "Next time" says so in one sentence
   and has no button.
6. No schema change, no feed or card field, no new use value.

### 2. Closed words in `policy`

`decision_log.policy` already carries the model version as text. It now also carries,
before `; model`, these words of `[A-Za-z0-9_:]` (1 to 48 bytes; any other word is
neither stored nor read):

| Part | Value |
|---|---|
| `why` | the reason kind, as `ReasonKind` prints it: `ForeignProject` |
| `code` | the wire code of a refusal by a check: `not_granted` |
| `offered` | the remembered answer that the question offered: `in_project:change`, `production:read` |
| `codes` | one-time codes of a run with one credential: `with_value` or `only` |
| `inject` | where the injection flag found its phrase: `prompt:1000` (`prompt`, `task`, `purpose`, `command`, and the number of the entry in the append-only phrase lists) |
| `noremember` | the first condition that kept a question from offering a remembered answer, when no other sentence says why: `uncertain`, `brain`, `dbhost`, … |

Example: `apassy-bouncer-v9; task_match 0.75; why ForeignProject; offered
in_project:change; model apassy-base-v1+1a2b3c4d`. A decision from before has no words;
its kind then comes from `decided_by` and its flags. The words never hold request text;
the phrase itself shows only in the owner's window, read from the lists.

### 3. The why text

The why text of a flagged run is the sentence of each flag, in a fixed order. How long
such a run keeps asking ("A command like this asks every time.") is for the owner's
window only: the desktop draws it on the question card, in the floating question
window, and in "Next time". It is not part of the stored why, the refusal text that an
agent receives, the relay card, or the log file. In the refusal text that an agent
receives, the sentence of the injection flag is "A safety rule flagged the request
text."; the owner's window keeps the full sentence. The question does not repeat what its
title says: the why text drops the title sentence, and a production question, a folder
outside a project, or a run without a task, whose why text says that it asks, gets no
every-time line.

### 4. The actions of "Next time"

| Action | Button | Owner check |
|---|---|---|
| Save the project answer the question offered | **Allow…** | yes: its own action (§5) |
| Remove the remembered answer | **Remove** | no |
| Forget the remembered command (the active patterns of the agent, the project key of the use, the folder in it, the credentials, and the command; read again at the click, so a pattern blocked since stays) | **Forget** | no |
| Always ask for the agent | **Always Ask** | no |
| Never for the agent | **Never** | no |
| Remove the exception | **Remove…** | yes |
| Turn "Always ask me" off | **Turn Off…** | yes |
| Open the credential, or Settings › Bouncer | **Open Credential**, **Open Settings** | where it saves |

Actions exist only for a decision with one credential. A decision that a check refused,
or that the owner denied, never shows a button that loosens: an exception then shows its
sentence with **Open Credential**.

### 5. Saving the answer later

The saved answer is the one the card offered: "Allow ACTION in PROJECT" for one
credential, for every agent in the project (ADR 0025 §3c). It is offered only when all
of these hold:

1. The decision was a run that asked, and the owner allowed it or did not answer.
2. Its question offered a project answer. A production allowance is not saved here.
3. It used one credential, had no rule flag, and its one-time codes are recorded as
   they were used.
4. Its agent is still connected, and the vault was not restored after it.
5. A use of the decision names the credential, a project, and the same action.
6. The credential exists now, is not archived, needs no review, has "Always ask me"
   off, and has a declaration that is not production.
7. Every host of the use is a known host of the credential now, as the run counts
   them (a code-only run without the host rules of the placeholder). History never
   adds a host.
8. No answer exists for the credential, the project, and the action. One that fits is
   reported as saved already; one that does not fit is never changed from History.

When one of these does not hold, the row says why: "Environment not set" or "Always
ask me" with their button, that the production credential asks every time, or to tick
"Remember for this project" on the next question. No **Allow…** shows while the agent
has an "Always ask" exception for the credential: that exception asks in any case.

The save needs its own owner action, `OwnerAction::RememberAnswer`, which names the
decision, the credential, the project, the action, and the codes. The "How often to
ask" window never covers it, and no phone can give it. The app checks every condition
again under the proof, and only the broker module writes the answer. Every hard rule
still runs before the answer at each use.

### 6. What stays asked

Every flagged run; production with write or admin scope; "Always ask me" until the
owner turns it off; a run outside a project; a run without a task; a remote agent; a
database host that the credential does not know. No row of History changes these.

## Not decided

Whether a remembered answer of the owner applies to a run whose only rule flag is
`injection_phrase` is not decided here. It would change the order of a hard rule (ADR
0031) and needs its own record.

## Relation to other records

- ADR 0025 §3b, §3c, §3f: the project answer and the exceptions; both can now also come
  from a past decision.
- ADR 0031: the question card's title and why text use the sentences of §1 and §3.
