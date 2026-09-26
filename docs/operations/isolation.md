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

### The Apassy app bundle

The app bundle holds the desktop app and the native helpers. The keychain
helper and `apassy-helper` can show a Touch ID prompt and post a notification
with the text of their caller. With a provisioning profile, the keychain helper
can also return the Touch ID unlock key. So a process in the profile must not
start them.

For each app bundle, the profile:

- denies the start of each program in the bundle (`process-exec*`),
- denies each read and each write in the bundle (`file-read*`, `file-write*`).
  So a process cannot copy, clone, or hard-link a helper, with its signature and
  its provisioning profile, to a path that the profile does not deny. It cannot
  change the bundle.
- denies a rename or a delete of each parent directory of the bundle. So the
  bundle cannot move out of the denied path.
- re-allows the start and the read of `Contents/MacOS/apassy-mcp` and
  `Contents/MacOS/apassy-hook`, and the metadata of `Apassy.app`,
  `Contents`, and `Contents/MacOS`. The agent host starts these two programs.

The bundle from `scripts/build-app.sh` contains `apassy-mcp`. It does not
contain `apassy-hook` now. The host can start `apassy-hook` from
`target/release/apassy-hook` or from a copy outside the bundle, as in
[host-hooks.md](host-hooks.md). The rule for `Contents/MacOS/apassy-hook` is
ready for a later bundle that contains it.

The helpers also check their caller (see section 6). This is a second layer.

### Parameters

Pass each parameter with `sandbox-exec -D KEY=VALUE`. Use absolute, resolved
paths.

| Parameter | Meaning |
| --- | --- |
| `APASSY_DATA_DIR` | the Apassy data directory (subtree deny) |
| `APASSY_VAULT_FILE` | the vault database |
| `APASSY_BACKUP_FILE` | the backup database |
| `APASSY_SOCKET` | the broker socket (re-allowed) |
| `APASSY_APP` | the installed app bundle. Optional. Default: `/Applications/Apassy.app` |
| `APASSY_APP_BUILD` | a second app bundle, for example `<repository>/target/Apassy.app`. Optional. |

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
| `--app DIR` | `/Applications/Apassy.app` |
| `--app-build DIR` | `<target>/Apassy.app` when the launcher is `<target>/<profile>/apassy-sandbox` and the directory is named `target`, else none |
| `--profile FILE` | `$APASSY_SANDBOX_PROFILE`, else a file near the program |
| `--print` | print the resolved command; do not run it |

The launcher resolves symlinks in each path, because Seatbelt matches the
resolved path. On macOS `/var` and `/tmp` are symlinks.

`scripts/build-app.sh` writes the app to `<repository>/target/Apassy.app`. A
launcher from `target/debug` or `target/release` protects this bundle without
an option. With another target directory, or with a launcher in another place,
give the build with `--app-build`. Keep the installed app in
`/Applications/Apassy.app`, or give its path with `--app`.

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
project `.mcp.json`, as in [agent-path.md](agent-path.md) section 4. The command
can be `Apassy.app/Contents/MacOS/apassy-mcp` or `target/release/apassy-mcp`.
The profile allows both. It denies the other programs in `Apassy.app`.

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
- The profile denies a start of the Apassy helpers only for the bundle paths it
  knows: `APASSY_APP` and `APASSY_APP_BUILD`. A copy of the app in another
  place is not denied. Give each place of the app to the launcher. The caller
  check of the helper (section 6) still refuses a caller that is not the
  signed Apassy app.
- A process in the profile cannot delete or move the protected bundles. So
  `cargo clean` or `rm -rf target` in the profile fails at `target/Apassy.app`.
  Run them outside the profile. `scripts/build-app.sh` also fails in the
  profile. Build the signed app outside the profile.
- A program that launchd or LaunchServices starts runs outside the profile.
  From the profile, `open` of a helper and `launchctl submit` of a job failed
  (section 5). A helper that launchd starts refuses the request (section 6). A
  start of other programs through LaunchServices, for example a terminal app,
  is not measured.
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
--test isolation_profile`. It has 16 tests. All pass. If `sandbox-exec` is
absent, or the host is not macOS, the test fails. There is no skip (goal I4).

### The Apassy app bundle

The tests use a synthetic `Apassy.app` with the layout of
`scripts/build-app.sh`. Its helpers are the real Swift helper without a
signature. `apassy-mcp` and `apassy-hook` are the programs of the build.

| Command in the profile | Result |
| --- | --- |
| start the keychain helper, `apassy-helper`, or the main program: direct, from a shell pipe, and with `APASSY_HELPER_DEV_ANY_CALLER=1` | denied (`Operation not permitted`). No answer. |
| the same programs outside the profile (control) | start and answer `caller_not_allowed` |
| `keychain_read` to the keychain helper | denied. The helper does not start. |
| `cat`, `cp`, `cp -c` (clone), `ln` (hard link) of a helper | denied |
| `cp -R` of the keychain helper bundle or of the app | denied. No file is copied. |
| `ls Contents` | denied |
| overwrite a helper, add a file in `Contents/MacOS` | denied. The helper bytes do not change. |
| rename the app, rename the parent directory of the app | denied |
| start `Contents/MacOS/apassy-mcp` of the bundle | allowed. `initialize`, `apassy_list_access`, and `apassy_use_credential` work. No secret. |
| start `Contents/MacOS/apassy-hook` of the bundle with a prompt | allowed. The broker accepts the prompt. With a wrong token, the hook reports "the broker refused". |
| a copy of the keychain helper bundle that the owner made outside the bundle: `ping`, `keychain_exists`, `keychain_read`, `authenticate` | the copy starts. Each request gets `caller_not_allowed`. |
| `sandbox-exec` with only `APASSY_APP_BUILD` (no `APASSY_APP`) | the profile loads. The keychain helper is denied. `apassy-mcp --version` works. |

The test `launcher_passes_the_installed_and_the_build_app` checks the launcher
defaults with `--print`: `APASSY_APP=/Applications/Apassy.app` and
`APASSY_APP_BUILD=<target>/Apassy.app`.

The same checks with the signed bundle ran in `scripts/build-app.sh` (section
"Check the agent profile with the signed bundle"):

```
ok: the agent profile denies the start of Contents/Helpers/ApassyKeychain.app/Contents/MacOS/ApassyKeychain
ok: the agent profile denies the start of Contents/MacOS/apassy-helper
ok: the agent profile denies the start of Contents/MacOS/apassy
ok: apassy-mcp --version in the agent profile
ok: the agent profile denies a copy of the keychain helper
ok: keychain helper copy in the agent profile refuses the caller, line 1
ok: keychain helper copy in the agent profile refuses the caller, line 2
```

Mutation checks: with the two `apassy-protect-app` lines removed from the
profile, four tests failed: `apassy_programs_cannot_start_in_profile`,
`apassy_programs_cannot_be_read_copied_linked_or_changed_in_profile`,
`profile_protects_the_build_app_without_the_installed_app_parameter`, and
`keychain_item_is_not_readable_in_profile`. With the caller check removed from
the helper, three isolation tests and two `native_helper` tests failed. The
agent restored both files after the check.

### launchd and LaunchServices

Measured with the signed bundle `target/Apassy.app`, synthetic data only.

| Command | Result |
| --- | --- |
| in the profile: `open -W -n --stdin req --stdout out <keychain helper app>` | `The file ... does not exist.`, exit 1. No answer. |
| in the profile: the same with `-a <keychain helper app>` | exit 0, no answer. The output file does not exist. |
| in the profile: the same with `-b com.wydrox.apassy.keychain` | `LSCopyApplicationURLsForBundleIdentifier() failed`, exit 1 |
| in the profile: `launchctl submit` of a job that copies the vault canary | exit 1. The job does not run. |
| outside the profile (control): the same `launchctl submit` with a harmless job | the job runs |
| outside any sandbox (control): `open -W -n --stdin req --stdout out <keychain helper app>` | the helper starts with launchd as the parent and answers `caller_not_allowed`: "launchd started the helper. Only Apassy.app can start it." |

From a sandbox with `(allow default)` only, `open --stdin --stdout` of a helper
copy also gave no answer. The agent did not find out if LaunchServices starts
the program without its standard input and output in this case. The caller
check refuses such a start in each case.

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

## 6. Keychain and the helper caller check

Goal I2 also needs proof that a process in the profile cannot read the Touch ID
Keychain item. The item is in the data protection keychain, with the access
group `<TEAM_ID>.com.wydrox.apassy` and `.biometryCurrentSet` access control.
Only the keychain helper in `Apassy.app` has this access group, and only with a
provisioning profile ([native-app.md](native-app.md)).

A Seatbelt file deny does not cover the Keychain, because the Keychain is a
system service, not a file that the agent opens. So the protection has these
parts:

1. `/usr/bin/security` in the profile finds no item with the Apassy service and
   account. The same query outside the profile (control) also finds none: the
   tool does not search the data protection keychain, and the item needs the
   Apassy access group.
2. The profile denies the start of the keychain helper and of `apassy-helper`
   (section 1). The deny does not depend on the signature or on a provisioning
   profile. So it also holds for a provisioned build with an access group. A
   process in the profile cannot ask the helper for a Touch ID prompt with its
   own reason text, or for the unlock key. It also cannot run `authenticate`,
   or `notify` with its own text.
3. The profile denies a read of the bundle. So a process cannot copy the helper
   bundle, with its provisioning profile, to a path that the profile does not
   deny.
4. The helper checks its caller. It answers only when its parent process is the
   signed Apassy app that contains it. Any other parent gets
   `caller_not_allowed`, also a start by launchd (LaunchServices, launchctl) and
   a copy of the helper in another place. The rule and the APIs are in
   [native-app.md](native-app.md), section "Caller check".

The test `keychain_item_is_not_readable_in_profile` checks parts 1 and 2. The
other tests in section 5 check parts 2 to 4. `scripts/build-app.sh` checks parts
2 to 4 with the signed bundle.

What stays open: the real `.biometryCurrentSet` item needs a provisioning
profile, and this Mac has none. The deny of the helper start does not depend on
it. The owner can run the checks again with a provisioned build (native-app.md,
owner step 3.8).

## 7. Real-secret gate

The real-secret gate stays BLOCKED until every gate item in
[goal.md](../goal.md) is done. This document is the evidence for goal items I1,
I2 (with the Keychain part in section 6), and I4, and the partial evidence for
I3.
