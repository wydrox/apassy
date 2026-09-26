# Isolation profile for the agent host

Date: 2026-09-26. Decisions: [ADR 0001 §6](../adr/0001-p0-feasibility.md), [ADR 0004](../adr/0004-agent-path-first.md), [ADR 0010](../adr/0010-closing-open-decisions.md).
Scope: goal items I1 to I4 in [goal.md](../goal.md). Use only synthetic values.

## 1. What the profile does

Apassy supplies a macOS Seatbelt profile for the agent host. The file is
`sandbox/apassy-agent-host.sb`. The host (Claude Code, Codex) and every command
that the host starts run inside the profile.

The profile denies read and write to:

- the Apassy data directory (`~/Library/Application Support/Apassy`). This
  directory holds the vault, the broker socket, and the Laya model at
  `.../Apassy/laya`.
- the vault file. The owner can place it outside the data directory.
- the backup file. The owner can place it outside the data directory.
- the SQLite companion files of the vault and the backup (`-wal`, `-shm`,
  `-journal`, `.lock`).

The profile permits a connection to the broker socket. The socket lives inside
the denied data directory. A later rule in the profile re-opens only the socket
node. So `apassy-mcp` still reaches the broker.

The profile starts from `(allow default)`. So normal development stays usable:
git, cargo, npm, the network, and the host's own configuration and credentials.

The profile uses `(param ...)` for each path. A test uses temporary directories.

### Parameters

Pass each parameter with `sandbox-exec -D KEY=VALUE`. Use absolute, resolved
paths.

| Parameter | Meaning |
| --- | --- |
| `APASSY_DATA_DIR` | the Apassy data directory (subtree deny) |
| `APASSY_VAULT_FILE` | the vault database |
| `APASSY_BACKUP_FILE` | the backup database |
| `APASSY_SOCKET` | the broker socket (re-allowed) |

### Directory-rename defense

A subtree deny blocks a rename of the denied directory itself. It does not
block a rename of a directory above it. Without more rules, a process can
rename a parent directory and then read the protected file at its new path. A
measurement showed this bypass (section 5). So the profile also denies a rename
or a delete of each parent directory of the data directory, the vault file, and
the backup file.

## 2. The launcher

`apassy-sandbox` resolves the paths, finds the profile, and replaces itself
with `/usr/bin/sandbox-exec`. It uses only `std` and no `unsafe`.

```
apassy-sandbox [OPTIONS] -- <host> [host args...]
```

| Option | Default |
| --- | --- |
| `--data-dir DIR` | `$HOME/Library/Application Support/Apassy` |
| `--vault-file FILE` | `<data-dir>/vault.db` |
| `--backup-file FILE` | `<vault-file>.backup` |
| `--socket FILE` | `$APASSY_BROKER_SOCKET`, else `<data-dir>/broker.sock` |
| `--profile FILE` | `$APASSY_SANDBOX_PROFILE`, else a file near the program |
| `--print` | print the resolved command; do not run it |

The launcher resolves symlinks in each path, because Seatbelt matches the
resolved path. On macOS `/var` and `/tmp` are symlinks.

The owner keeps rotated backups in the data directory, or gives one backup
path with `--backup-file`. The data directory is a subtree deny, so any file
in it is protected.

## 3. How to start each host in the profile

The host runs its agent commands as child processes. Both hosts also have their
own Seatbelt sandbox for these commands. A second Seatbelt sandbox inside the
first one cannot start (section 5). So the owner turns off the host's own
sandbox and lets the Apassy profile confine the host and its commands.

This does not weaken the Apassy boundary. The Apassy profile protects the vault,
the backup, and the Laya model. It denies these paths to the host process, to
the host's file tools, to every command, and to the MCP servers, because they
are all child processes of the host.

### Claude Code

Turn off the Claude Code Bash sandbox. Put this in the project or user
settings, or pass it on the command line:

```
{ "sandbox": { "enabled": false } }
```

Start Claude Code in the profile:

```
apassy-sandbox -- claude --settings /path/to/nosandbox.json
```

This changes only the inner sandbox. Keep your normal permission mode and
approval prompts. Do not add `--dangerously-skip-permissions` for daily use.

Claude Code runs `apassy-mcp` as an MCP server. An MCP server can run outside the
Claude Code Bash sandbox, but it is still a child of the host, so it runs inside
the Apassy profile. It reaches the broker socket. Set the MCP server in the
project `.mcp.json`, as in [agent-path.md](agent-path.md) section 4.

### Codex

Turn off the Codex sandbox for the run, so Codex does not start its own
Seatbelt:

```
apassy-sandbox -- codex -c sandbox_mode=danger-full-access
```

This changes only the inner sandbox. Codex keeps the `approval_policy` from your
configuration. Do not add `approval_policy=never` for daily use.

The one-off test runs in section 5 use `--dangerously-skip-permissions` and
`approval_policy=never`. Those runs use synthetic paths only. They turn off the
host prompts so that the run is non-interactive, and so that the test shows the
boundary holds even when the host approves every command.

### Tradeoffs

- The chosen approach runs the whole host under the Apassy profile and turns off
  the host's own sandbox. This gives one boundary for the host, its file tools,
  its commands, and its MCP servers. It is the only approach that also protects
  the paths from the host process itself.
- An alternative uses only the host's own sandbox with deny-read and deny-write
  rules for the protected paths. This does not protect the paths from the host
  process, because the Claude Code file tools (Read, Edit, Write) and the MCP
  servers do not run in the Bash sandbox. So this alternative is not enough on
  its own.
- The owner can add the host's own deny rules as a second layer, but must not
  rely on them alone.

## 4. Limits

- Seatbelt does not protect memory, the clipboard, or processes outside the
  profile.
- Apple marks `sandbox-exec` as deprecated. It still ships in macOS 27. If a
  later macOS release removes it, isolation needs a new ADR.
- The profile protects files. It does not stop a command that reads a secret
  from the broker in "allow" mode and then sends it to a network host. The
  bouncer and the owner approval control that path (ADR 0006).
- A Keychain deny check is pending. See section 6.
- The profile does not fully hide the environment of other processes of the
  same user. See "Process information (F11)" in section 5.
- `ps` and `top` are setuid programs. They cannot start inside any
  `sandbox-exec` profile on this macOS, also with `(allow default)` only. A host
  feature that runs `ps` fails in the profile. The measured Claude Code run did
  not need `ps`.

## 5. Measured results

Host: macOS 27.0 (build 26A428), arm64. `sandbox-exec` present at
`/usr/bin/sandbox-exec`. Claude Code 2.1.280. Codex 0.156.1.

### Nested Seatbelt

A second Seatbelt profile that narrows access cannot start inside the first one.

| Command | Result |
| --- | --- |
| `sandbox-exec (allow default)` inside `sandbox-exec (allow default)` | exit 0 (a no-op nests) |
| an inner profile with a `deny` inside an outer profile | `sandbox_apply: Operation not permitted`, exit 71 |
| `codex sandbox -P :workspace` inside `sandbox-exec (allow default)` | `sandbox_apply: Operation not permitted`, exit 71 |

This is why each host runs with its own sandbox off, under the Apassy profile.

### The profile boundary

The `apassy-sandbox` launcher ran each command with a synthetic data directory,
a vault canary, a fake Laya file, a backup canary, and a live broker socket.

| Command in the profile | Result |
| --- | --- |
| read the vault file | denied (`Operation not permitted`) |
| read the vault `-wal` file | denied |
| read the Laya model file | denied |
| read the backup file | denied |
| list the data directory | denied |
| overwrite the vault file | denied |
| delete the vault file | denied |
| replace the vault file by a rename | denied |
| rename the data directory, then read the vault | denied |
| rename the backup parent directory, then read the backup | denied |
| connect to the broker socket | allowed |
| read a project file | allowed |
| write a file in a temporary directory | allowed |

The vault bytes never changed. A same-user process without the profile read all
canaries first, as a control.

### The broker through `apassy-mcp`

The `apassy-mcp` adapter ran inside the profile. It called the broker on the
socket in the denied data directory.

| Adapter call | Result |
| --- | --- |
| `initialize` | server name `apassy` |
| `apassy_list_access` | one grant for `get_sales_summary`. No secret. |
| `apassy_use_credential` (`get_sales_summary`) | 318 orders, permitted fields only. No secret. |

The evidence for these checks is `cargo test --locked --features desktop,vault
--test isolation_profile`. It has 10 tests. All pass. If `sandbox-exec` is
absent, or the host is not macOS, the test fails. There is no skip (goal I4).

### Process information (F11)

The key-memory review (goal V2) found that `ps eww` and `ps -E` show the
environment of another process of the same user. The broker starts agent
commands with secrets in their environment. So an agent could try to read a
secret from the environment of a broker child.

Measured on this macOS:

| Check | Result |
| --- | --- |
| `ps eww -p PID` outside the profile, target is a third-party program with a canary variable | shows the canary |
| same, target is an Apple platform program (for example `/bin/sleep`) | does not show the environment |
| `ps eww -p PID` and `ps -E -p PID` inside the profile | fail. `ps` cannot start (setuid program). No canary. |
| a child process of the sandboxed process, with its own environment | runs and works |
| `(deny process-info* (target others))` | did not stop a direct read of the process arguments of an outside process |
| `(deny process-info*)` | broke ordinary programs (Python stopped with a trap) |

Result:

- The test `ps_in_profile_cannot_show_environment_of_outside_process` shows the
  `ps` path is closed in the profile. It uses a control: outside the profile,
  `ps` shows the canary.
- The test `own_child_processes_work_in_profile` shows that children of the
  sandboxed process still work.
- No tested Seatbelt rule both hides the environment of an outside process from
  a direct system call and keeps ordinary programs working. So the profile has
  no `process-info` rule. A program in the profile that calls the system
  interface for process arguments directly can still read the environment of a
  same-user third-party process. This is an open limit.
- Mitigation belongs to the broker (ADR 0006 process mode): keep secret runs
  short, and do not treat the environment of a running broker child as hidden
  from other processes of the same user. The owner decides if more work is
  needed before the real-secret gate opens.
- Host tooling: `ps` and `top` cannot start in any `sandbox-exec` profile, so a
  host feature that runs them fails. No SBPL allowance for this was verified.
  The measured Claude Code run did not break.

### Real Claude Code session (goal I3)

A headless Claude Code 2.1.280 session ran inside the profile. The Bash sandbox
was off. The run used `--dangerously-skip-permissions`, so the host approved
every command. Synthetic paths only.

| Command the agent ran | Result |
| --- | --- |
| `cat <data-dir>/vault.db` | `cat: ...: Operation not permitted` |
| `ls <data-dir>` | `ls: ...: Operation not permitted` |
| `echo ok > "$TMPDIR/apassy-iso-check.txt" && cat ...` | `ok` |

The agent reported each result. The vault bytes did not change. This shows the
I2 boundary holds for a real Claude Code session, even when the host skips all
its own permission checks.

### Real Codex session (goal I3)

A Codex 0.156.1 session started inside the profile with
`sandbox_mode=danger-full-access` and `approval_policy=never`. The session
header showed `sandbox: danger-full-access`. Codex started with no nested
Seatbelt error. This shows the launcher, the profile, and the Codex overrides
work together.

The agent turn did not finish. The account hit its usage limit: "You've hit your
usage limit." The owner must run the Codex check again after the limit resets,
with credits available:

```
cd <a git repository>
apassy-sandbox \
  --data-dir /tmp/apassy-i3/d \
  --vault-file /tmp/apassy-i3/d/vault.db \
  --backup-file /tmp/apassy-i3/backups/apassy.backup \
  --socket /tmp/apassy-i3/d/broker.sock \
  -- codex exec --skip-git-repo-check \
       -c sandbox_mode=danger-full-access -c approval_policy=never \
       "Run: cat /tmp/apassy-i3/d/vault.db ; ls /tmp/apassy-i3/d ; sh -c 'echo ok > \"$TMPDIR/x\" && cat \"$TMPDIR/x\"'. Report each result."
```

The expected result is the same as the Claude Code run: the first two commands
give `Operation not permitted`, and the temporary write gives `ok`.

## 6. Keychain (pending)

Goal I2 also needs proof that a process in the profile cannot read the Touch ID
Keychain item. A parallel task builds the Swift Keychain helper (goal A1, A3).
The Keychain item does not exist yet.

When the helper lands, add a check to `tests/isolation/product_profile.rs`. The
check reads the Keychain item outside the profile as a control, and shows a deny
inside the profile. The test `keychain_check_is_pending` marks this gap now. It
also checks that `/usr/bin/security` exists for the future check. This is not a
skip of the isolation test.

Note: a Seatbelt file deny does not cover the Keychain, because the Keychain is
a system service, not a file the agent opens. The deny for the Keychain uses the
biometric access control of the item and the code signing of `Apassy.app`
(ADR 0010). The isolation test measures only that a command in the profile
cannot reach the item.

## 7. Real-secret gate

The real-secret gate stays BLOCKED until every gate item in
[goal.md](../goal.md) is done. This document is the evidence for goal items I1,
I2, and I4, and the partial evidence for I3.
