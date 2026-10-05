# Isolation profile for the agent host

Date: 2026-09-26. Decisions: [ADR 0001 §6](../adr/0001-p0-feasibility.md), [ADR 0004](../adr/0004-agent-path-first.md), [ADR 0010](../adr/0010-closing-open-decisions.md).
Scope: goal items I1 to I4 in [goal.md](../goal.md). Use only synthetic values.

## 1. What the profile does

Apassy supplies a macOS Seatbelt profile for the agent host. The file is
`sandbox/apassy-agent-host.sb`. The host (Claude Code, Codex) and every command
that the host starts run inside the profile.

The profile denies read and write to:

- the Apassy data directory (`~/Library/Application Support/Apassy`). This
  directory holds the vaults, the vault list `vaults.json`, the broker socket,
  the owner socket of the command line
  ([ADR 0017](../adr/0017-owner-command-line.md)), and the Laya model at
  `.../Apassy/laya`.
- the vault file. The owner can place it outside the data directory.
- each other vault file in the vault list that is outside the data directory
  ([several vaults](multiple-vaults.md), ADR 0013).
- the backup file. The owner can place it outside the data directory.
- the SQLite companion files of the vault and the backup (`-wal`, `-shm`,
  `-journal`, `.lock`).
- the Apassy folder in iCloud Drive
  (`~/Library/Mobile Documents/com~apple~CloudDocs/Apassy`). It holds a closed,
  encrypted copy of each vault that syncs there ([sync](sync.md), [ADR
  0014](../adr/0014-icloud-sync.md)). A process with a copy can guess
  passphrases offline, and a changed copy can reach the other Macs. The rest of
  iCloud Drive stays usable.
- the synced file of each vault that syncs through another folder (Dropbox,
  Google Drive, a share): the file, its push temporary file
  `<file>.push.nosync`, and its SQLite companions. Only these files, not the
  folder: an agent's projects can live in the same Dropbox folder.

The profile also denies a connection to every Unix socket in the data directory.
A `connect()` to a Unix socket is not a file read or write, so the file rule does
not stop it: a measurement on 2026-10-01 connected to a second socket in the
denied directory. The rule `(deny network-outbound (remote unix-socket (subpath
DATA_DIR)))` closes it. So an agent cannot reach the owner socket of the command
line.

The profile permits a connection to the broker socket. The socket lives inside
the denied data directory. A later rule in the profile re-opens only the socket
node. So `apassy-mcp` still reaches the broker.

`apassy-sandbox` removes `APASSY_SESSION`, the command-line session of the owner,
from the environment of the host.

The profile also denies each measured route to start a program OUTSIDE the
sandbox as the same user, because such a program is not confined and can read
the vault: LaunchServices (`open`/`lsopen`), Apple Events, the Shortcuts and
Automator services, and a write to an autostart location (LaunchAgents,
LaunchDaemons, login items, application scripts, and shell startup files).
Section 7 has the routes and the measurements.

The profile starts from `(allow default)`. So normal development stays usable:
git, cargo, npm, the network, and the host's own configuration and credentials.
A browser login flow that runs `open <url>` is the one exception; the owner runs
it outside the profile (section 7).

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
| `APASSY_VAULT_FILE_2` to `APASSY_VAULT_FILE_16` | more vault files from the vault list, outside the data directory. Optional. Each one gets the same rules as `APASSY_VAULT_FILE`. |
| `APASSY_BACKUP_FILE` | the backup database |
| `APASSY_SOCKET` | the broker socket (re-allowed) |
| `APASSY_HOME` | the owner home directory. The profile denies a write to the autostart locations under it (section 7). |
| `APASSY_APP` | the installed app bundle. Optional. Default: `/Applications/Apassy.app` |
| `APASSY_APP_BUILD` | a second app bundle, for example `<repository>/target/Apassy.app`. Optional. |
| `APASSY_CLOUD_DIR` | the Apassy folder in iCloud Drive (subtree deny). Optional. The launcher passes it by default. |
| `APASSY_SYNC_FILE_1` to `APASSY_SYNC_FILE_16` | the synced vault files from the vault list outside the data directory and the iCloud Apassy folder: the file, `<file>.push.nosync`, and the SQLite companions. Optional. |

### Directory-rename defense

A subtree deny blocks a rename of the denied directory itself. It does not
block a rename of a directory above it. Without more rules, a process can
rename a parent directory and then read the protected file at its new path. A
measurement showed this bypass (section 5). So the profile also denies a rename
or a delete of each parent directory of the data directory, the vault file, each
listed vault file outside the data directory, the backup file, the Apassy
folder in iCloud Drive, and each synced file in another folder. For a synced
file in Dropbox this stops only a rename or a delete of the Dropbox folder and
its parents; the files and folders inside stay usable.

## 2. The launcher

`apassy-sandbox` resolves the paths, finds the profile, and replaces itself
with `/usr/bin/sandbox-exec`. It uses only `std` and no `unsafe`.

```
apassy-sandbox [OPTIONS] -- <host> [host args...]
```

| Option | Default |
| --- | --- |
| `--data-dir DIR` | `$HOME/Library/Application Support/Apassy` |
| `--vault-file FILE` | `<data-dir>/vault.db`. Each vault of `<data-dir>/vaults.json` is denied too (below). |
| `--backup-file FILE` | `<vault-file>.backup` |
| `--socket FILE` | `$APASSY_BROKER_SOCKET`, else `<data-dir>/broker.sock` |
| `--home DIR` | `$HOME`. The profile denies a write to the autostart locations under it (section 7). |
| `--app DIR` | `/Applications/Apassy.app` |
| `--app-build DIR` | `<target>/Apassy.app` when the launcher is `<target>/<profile>/apassy-sandbox` and the directory is named `target`, else none |
| `--cloud-dir DIR` | `$HOME/Library/Mobile Documents/com~apple~CloudDocs/Apassy`. The folder may not exist yet; the profile denies it anyway. |
| `--profile FILE` | `$APASSY_SANDBOX_PROFILE`, else a file near the program |
| `--print` | print the resolved command; do not run it |

The launcher resolves symlinks in each path, because Seatbelt matches the
resolved path. On macOS `/var` and `/tmp` are symlinks.

### The vault list

The launcher reads `<data-dir>/vaults.json` (ADR 0013) and denies each listed
vault file:

- A vault inside the data directory is in the subtree deny, with its SQLite
  companions and its `.lock` file.
- A vault outside the data directory gets its own parameter,
  `APASSY_VAULT_FILE_2` to `APASSY_VAULT_FILE_16`, in the order of the list.
  `--print` shows them.
- The synced file of a vault that syncs through a folder other than the iCloud
  Apassy folder gets its own parameter, `APASSY_SYNC_FILE_1` to
  `APASSY_SYNC_FILE_16` (ADR 0014). A synced file in the data directory or in
  the iCloud Apassy folder needs none: their subtree denies cover it.

The launcher fails closed. It stops with an error, and the host does not
start, in these cases:

- The list cannot be read, is not valid, or has a format from a newer Apassy.
  The launcher cannot name each vault file of a damaged list, so it cannot prove
  that the profile denies each vault. A fallback that denies only the data
  directory would leave a vault in another folder open without a warning. Open
  Apassy once: it moves the damaged list aside and makes a new one.
- More than 15 listed vaults are outside the data directory. Move vaults into
  the data directory, or remove vaults from the list in Settings > Vaults.
- A synced vault has no valid synced file in the list, or more than 16 synced
  files are outside the data directory and the iCloud Apassy folder. Turn the
  sync of a vault off and on again, or sync some vaults through iCloud Drive.

Without a list, the launcher denies the data directory and `--vault-file`, as
before.

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
- A program that starts outside the profile is not confined and can read the
  vault. The profile denies each measured route to start one: LaunchServices
  (`open`/`lsopen`), Apple Events, the Shortcuts and Automator services, and a
  write to an autostart location. Section 7, "Launching outside the sandbox",
  has the routes, the results before and after, and the limits. The profile
  cannot close every route: a program that the owner runs later, for example
  from a project git hook or a Makefile that a process in the profile wrote,
  runs outside the profile at that later time.
- `open` of an `https://` URL also fails, because the deny of `lsopen` is total.
  So a browser login flow (for example `gh auth login --web` or `claude`
  `/login`) does not work in the profile. The owner runs the login outside the
  profile, or copies the URL and opens it by hand. Section 7 has the
  measurement.
- The iPhone companion listener (ADR 0020) is a TCP listener in the Apassy app
  process, off by default. The profile still denies the app bundle and the
  vault, and it does not change. A process in the profile may connect to the
  listener as any network client can, but the listener closes each connection
  from the Mac itself (a loopback address or an address of the Mac), and it
  answers nothing useful without the key of a paired iPhone. So an agent in the
  profile cannot use the companion. The listener is a network surface that is
  open while the setting is on and the vault is unlocked. See
  [companion](companion.md), section 8.
- The profile does not fully hide the environment of other processes of the
  same user. See "Process information (F11)" in section 5.
- The launcher reads the vault list when it starts. A host that started earlier
  does not get a vault that the owner adds later outside the data directory.
  Start the host again after such a change. A vault in the data directory needs
  no restart.
- "Remove from list" keeps the file. A removed vault outside the data
  directory, or a vault that a damaged list lost, is not denied to hosts that
  start later.
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
| read, list, or write in the Apassy folder in iCloud Drive | denied |
| rename the iCloud Drive folder, then read the vault copy | denied |
| read a file in another iCloud Drive folder | allowed |
| read or write a synced file in a Dropbox folder, its push temporary file, or its journal | denied |
| rename the Dropbox folder of a synced file | denied |
| read another file in that Dropbox folder, or work on a project next to it | allowed |
| connect to the broker socket | allowed |
| connect to the owner socket (`nc -U`) | denied (2026-10-01) |
| `APASSY_SESSION` in the host environment | removed by the launcher (2026-10-01) |
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
--test isolation_profile`. It has 27 tests. All pass. If `sandbox-exec` is
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

Measured with the signed bundle `target/Apassy.app`, synthetic data only. These
measurements are about the Apassy helper only. The general routes to start a
program outside the sandbox, and the deny rules that close them, are in section
8, "Launching outside the sandbox".

| Command | Result |
| --- | --- |
| in the profile: `open -W -n --stdin req --stdout out <keychain helper app>` | `The file ... does not exist.`, exit 1. No answer. |
| in the profile: the same with `-a <keychain helper app>` | exit 0, no answer. The output file does not exist. |
| in the profile: the same with `-b com.wydrox.apassy.keychain` | `LSCopyApplicationURLsForBundleIdentifier() failed`, exit 1 |
| in the profile: `launchctl submit` of a job that copies the vault canary | exit 1. The job does not run. |
| outside the profile (control): the same `launchctl submit` with a harmless job | the job runs |
| outside any sandbox (control): `open -W -n --stdin req --stdout out <keychain helper app>` | the helper starts with launchd as the parent and answers `caller_not_allowed`: "launchd started the helper. Only Apassy.app can start it." |

These `open` rows measured the helper before the profile denied `lsopen`. The
`-a` row got exit 0 from `open`, so LaunchServices accepted the request; the
helper did not answer only because of its caller check. Section 7 shows that
`open` of a general application did start it outside the sandbox and read the
vault canary. The profile now denies `lsopen`, so `open` fails before the start
(section 7).

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
- Since 2026-09-27 a variable can use placeholder mode (ADR 0011). Then the
  environment of the run has a placeholder, the address of the run proxy, and
  its password, but no value. A proxied run starts in a second Seatbelt profile
  that denies each outgoing connection except the one to the proxy port. That
  rule works: a direct connection fails with `Operation not permitted`.
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

The first agent turn did not finish, because the account hit its usage limit.
The check ran again on 2026-09-26 at 17:55 with the same Codex version, with
this command:

```
cd <a git repository>
apassy-sandbox \
  --data-dir /tmp/apassy-i3/d \
  --vault-file /tmp/apassy-i3/d/vault.db \
  --backup-file /tmp/apassy-i3/backups/apassy.backup \
  --socket /tmp/apassy-i3/d/broker.sock \
  -- codex exec --skip-git-repo-check \
       -c sandbox_mode=danger-full-access -c approval_policy=never \
       "Run: cat /tmp/apassy-i3/d/vault.db ; ls /tmp/apassy-i3/d ; sh -c 'echo ok > \"$TMPDIR/x\" && cat \"$TMPDIR/x\"'. Report each result verbatim."
```

The session header showed `sandbox: danger-full-access` and `approval: never`.
The vault file and the data directory were synthetic canaries.

| Command that Codex ran | Result |
| --- | --- |
| `cat /tmp/apassy-i3/d/vault.db` | `Operation not permitted`, exit 1 |
| `ls /tmp/apassy-i3/d` | `Operation not permitted`, exit 1 |
| `sh -c 'echo ok > "$TMPDIR/x" && cat "$TMPDIR/x"'` | `ok`, exit 0 |

The canary file was unchanged after the run. The result is the same as the
Claude Code run. Goal item I3 is done for both hosts.

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

## 7. Launching outside the sandbox

Seatbelt confines a process and its child processes. It does not confine a
program that a system service starts on request. Such a program runs outside
the profile, as the same user, so it can read the vault. This section measures
each route to start a program outside the sandbox, and the deny rules that
close the routes.

Host: macOS 27.0 (build 26A428), arm64. GUI login session (`launchctl
managername` is `Aqua`). Synthetic canary paths only: a plaintext vault canary,
a synthetic data directory, and a synthetic home directory.

Method for each route: a payload tries to read the vault canary and writes the
result to a file the test can read. If the payload runs outside the sandbox, it
reads the canary ("escape"). A control runs the same route with the profile
off.

### Result table

| Route | Works in the profile before? | Escapes before? | Closed by | Test |
| --- | --- | --- | --- | --- |
| `open <app>` / `open <.command>` (LaunchServices, `lsopen`) | yes | yes: an application bundle started outside the sandbox and read the canary | `(deny lsopen)` | `profile_denies_lsopen_of_an_application` |
| `open https://…` (browser) | yes: launches the browser | the browser starts outside the sandbox | `(deny lsopen)` | (manual; see "Browser and normal work") |
| URL scheme, e.g. `x-apple.systempreferences:`, `terminal:` | through `open`/`lsopen` | same as `open` | `(deny lsopen)` | covered by the `lsopen` test |
| `osascript -e 'do shell script …'` | yes | no: the shell is a child of `osascript`, so it stays in the sandbox | not needed | — |
| Apple Events, e.g. `tell application "Terminal" to do script …`, `tell application "System Events" …` | yes: the send reaches a running application | yes: the other application runs outside the sandbox | `(deny appleevent-send)` | manual (needs a GUI target) |
| `shortcuts run <name>` with a "Run Shell Script" action | the Shortcuts service is reachable | the runner is outside the sandbox | `(deny mach-lookup [Ss]hortcut / WorkflowKit)` | manual (needs an authored shortcut) |
| `automator <workflow>` | starts; a real run needs the Automator app | through `lsopen` or a runner | `(deny lsopen)` and the mach-lookup deny | manual (needs an authored workflow) |
| write `~/Library/LaunchAgents/<x>.plist` (persistence) | yes | yes: launchd ran the plist outside the sandbox and read the canary | `(deny file-write* …/Library/LaunchAgents)` | `profile_denies_writes_to_autostart_locations` |
| write `~/.zshrc` and other shell startup files (persistence) | yes | runs outside the sandbox at the next terminal | `(deny file-write* ~/.zshrc …)` | `profile_denies_writes_to_autostart_locations` |
| `launchctl submit …` | no (exit 1) | no | already blocked by launchd | manual |
| `launchctl bootstrap gui/$UID <plist>` | no (`Input/output error`) | no | already blocked by launchd | manual |
| `at` / `at -f` | no (`at` is setuid; it cannot start; `atrun` is off) | no | already blocked | manual |
| `crontab <file>` | no (`crontab` is setuid; it cannot start) | no | already blocked | manual |

### The measured escapes, before the fix

`open` of an application: a synthetic headless application bundle read the vault
canary.

```
# in the profile, before (deny lsopen)
open /tmp/…/Canary.app        # exit 0; the app started and wrote:
                              #   SYNTHETIC-VAULT-CANARY-NOT-A-SECRET
                              #   ESCAPED-READ-OK
```

Apple Events reach a running application:

```
# in the profile, before (deny appleevent-send)
osascript -e 'tell application "Finder" to get name of startup disk'
# error -1712 (AppleEvent timed out): the send reached Finder, which was busy.
# The send crossed the sandbox boundary to an application outside it.
```

A LaunchAgent runs outside the sandbox:

```
# in the profile, before the autostart deny
#   the plist wrote OK into ~/Library/LaunchAgents
# the owner loads it (or launchd loads it at the next login):
launchctl bootstrap gui/$UID ~/Library/LaunchAgents/<x>.plist
#   the job ran outside the sandbox and read the canary:
#   SYNTHETIC-VAULT-CANARY-NOT-A-SECRET / ESCAPED-READ-OK
```

### The results, after the fix

```
# open of an application
open /tmp/…/Canary.app
#   _LSOpenURLsWithCompletionHandler() failed with error -54.  (no start)

# open of an https URL (browser)
open https://example.com
#   _LSOpenURLsWithCompletionHandler() failed with error -54.  (no browser)

# Apple Events
osascript -e 'tell application "Finder" to get name of startup disk'
#   error -600 (Application isn't running): the sandbox blocked the send,
#   although Finder was running.

# Shortcuts
shortcuts list
#   Error: Couldn't communicate with a helper application.

# write a LaunchAgent plist or a shell startup file
sh -c 'echo x > ~/Library/LaunchAgents/<x>.plist'   # Operation not permitted
sh -c 'echo x >> ~/.zshrc'                          # Operation not permitted
cat ~/.zshrc                                        # still works (read only)
```

### Why a total `lsopen` deny

`lsopen` does not take a useful filter here. A test denied `lsopen` and then
re-allowed it for the target path (`literal`, `subpath`, `regex`) and for the
URL (`regex`). None re-opened the route: `open` still failed with error -54. So
the profile cannot allow `open https://…` and deny `open <app>` at the same
time. The deny is total.

### Browser and normal work

The total `lsopen` deny stops `open https://…`, so a browser login flow does not
work in the profile:

- `gh auth login --web`, `claude` `/login`, and any tool that runs `open <url>`
  to reach the browser fail in the profile.

The workaround: the owner runs the login outside the profile (the token is then
in place before the agent host starts), or copies the URL from the agent and
opens it by hand. This matches the guidance to build the signed app outside the
profile.

Normal development is not affected. Measured in the profile, after the fix:

| Command in the profile | Result |
| --- | --- |
| `git --version`, `cargo --version` | run |
| `curl https://example.com` | HTTP 200 (network works) |
| `osascript -e 'do shell script "echo ok"'` | `ok` (stays in the sandbox) |
| read (source) a shell startup file | works |
| write an ordinary file in the home directory | works |
| `apassy-mcp` to the broker | works (section 5) |

`git`, `npm`, and `cargo` do not use `lsopen`, Apple Events, or an autostart
location for their normal work. A start of a normal program uses `process-exec`,
which the profile allows.

### The autostart locations

The profile denies a write to these paths under `APASSY_HOME`. The deny is on
writes only, so a shell still reads (sources) its startup files:

- `Library/LaunchAgents`, `Library/LaunchDaemons`,
- `Library/Application Scripts`,
- `Library/Application Support/com.apple.backgroundtaskmanagementagent` (login
  items),
- `Library/Preferences/com.apple.loginitems.plist`,
- the shell startup files `.zshenv`, `.zprofile`, `.zshrc`, `.zlogin`,
  `.zlogout`, `.bashrc`, `.bash_profile`, `.bash_login`, `.profile`.

### Manual routes

Three routes need a GUI login session, an authored shortcut or workflow, or a
running target application, so there is no automated test. They were measured by
hand once, on the host above.

- Apple Events: `osascript -e 'tell application "Finder" to get name of startup
  disk'`. Before: error -1712 (the send reached Finder). After: error -600 (the
  sandbox blocked the send). A running application is needed as the target, and
  a headless test host has no such target, so there is no automated test.
- Shortcuts: `shortcuts list`. Before: the list of the owner shortcuts. After:
  `Error: Couldn't communicate with a helper application.` A full read of the
  canary needs a pre-authored "Run Shell Script" shortcut in the owner library,
  which needs the GUI to create, so there is no automated test.
- `open` of the browser: `open https://example.com`. After: error -54; no
  browser starts. This would open a visible browser window in a control, so
  there is no automated test; the `lsopen` test uses a headless application
  bundle instead.

### Routes already blocked

`launchctl submit`, `launchctl bootstrap gui/$UID`, `at`, and `crontab` do not
work in the profile even without a new rule. `launchctl submit` and `bootstrap`
fail because launchd refuses a job from a sandboxed process (exit 1, and
`Input/output error`). `at` and `crontab` are setuid programs, so they cannot
start in any `sandbox-exec` profile, like `ps` and `top`. `atrun` is also off by
default on this macOS. The controls outside the profile ran each of these, so
the block is the profile, not a broken tool.

### Limits

- The profile cannot close a route that runs a program the owner starts later.
  A process in the profile can write a project file, for example a git hook in
  the working tree (`.git/hooks/*`) or a `Makefile` target. The owner runs it
  later, outside the profile. Seatbelt cannot stop this, because the write to
  the project file is normal work and the run is a separate, later action of the
  owner. The bouncer and the owner approval (ADR 0006) are the control for what
  a running command does.
- Recommendation (owner decision, [ADR 0010](../adr/0010-closing-open-decisions.md)):
  in a project that agents edit, start your own terminal in the profile too, with
  `apassy-sandbox -- zsh`. Commands that you run there, and the git hooks that
  they start, then have the same limits. You lose no access to secrets, because
  secrets come from the Apassy app.
- The Shortcuts deny uses a name match on the service. A future macOS can rename
  the service. The `lsopen` and `appleevent-send` denies do not depend on a
  service name.

## 8. Real-secret gate

The real-secret gate is OPEN since 2026-09-27 (ADR 0006). Every gate item in
[goal.md](../goal.md) is done. This document is the evidence for goal items I1,
I2 (with the Keychain part in section 6), and I4, and the partial evidence for
I3.
