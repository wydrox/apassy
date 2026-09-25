# ADR 0006 — Secrets for agent processes

Date: 2026-09-25.
Status: owner selected this mode on 2026-09-25. It changes the priority in the original concept. It does not remove mediated use from ADR 0004.

## Context

The original concept (commit `709fe03`) put mediated use first. It listed secret delivery through the process environment as a later compatibility mode with weaker guarantees.
The owner stated a different priority on 2026-09-25: agents must get access to secrets, with limits from the bouncer.
A coding agent, for example Claude Code in a project, runs commands that need secrets in the environment. A connector for each service does not fit that work.

The owner compared three options:

1. The broker starts a process with the secrets in its environment. The model does not see the values.
2. The agent receives the secret value after a bouncer decision.
3. Mediated use only.

The owner selected option 1.

## Decision

- An agent asks the broker to run one command in one working directory with named vault items. The request also states a purpose.
- The broker starts the process. The agent does not start it. The secret goes only into the environment of that process. The socket never returns a secret value.
- The owner binds each item to one environment variable name and one secret field. The agent cannot select the variable name.
- The owner gives an agent process access to an item for one project directory. The working directory must be inside that directory.
- The grant has one of two modes: "ask" (the owner approves each run in the desktop app) or "allow" (the run starts without a prompt).
- The broker replaces each secret value in the output with `[apassy:NAME]`.
- Each decision and each result goes to the activity log without secret values.
- The command is an argument list. The broker does not use a shell. The agent can ask for a shell, and the owner sees that in the approval.
- The process gets a clean environment: `HOME`, `USER`, `LOGNAME`, `SHELL`, `TMPDIR`, `LANG`, the `PATH` from the adapter, and the bound secrets. Names such as `PATH`, `DYLD_*`, `LD_*`, and `NODE_OPTIONS` cannot be bound.
- A run waits a maximum of 120 seconds for the owner. A process runs a maximum of 300 seconds. Then the broker stops its process group.
- A lock of the vault denies every waiting run. After an approval, the broker checks the vault, the agent, and the grants again before it reads a secret.

## What this mode does not protect

- The process can read, print in encoded form, write to a file, or send the secret to a network host. Masking finds only the exact value.
- A command in "allow" mode runs without a human check. Use "allow" only for commands that you trust.
- The owner approval is the main control until the risk evaluator (P5) exists.
- The real-secret gate stays BLOCKED until the owner accepts these risks in a separate decision.

## Relation to other records

- ADR 0004 and ADR 0005 stay valid. Mediated use stays available for services with a connector profile.
- `docs/concept.md` section 6 says that the MVP has no raw delivery as a silent fallback. This mode is not silent. It needs an owner grant, and in "ask" mode an approval for each run.
