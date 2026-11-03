# Isolation on Linux (bubblewrap)

Date: 2026-11-03. Status: built (unit X1), not yet measured on a real machine: the
`linux-isolation` CI job is the first measurement.
Decisions: [ADR 0011](../adr/0011-run-proxy-placeholders.md) stage 2 (a proxied run
has no route except the proxy), [ADR 0037](../adr/0037-own-relay-open-source.md)
stage 8 ("Linux isolation"), decision D7 of the
[s5 plan](../design/implementation-plan-s5-env-0011.md).
Related: [isolation.md](isolation.md) (the Seatbelt profiles of macOS),
[ADR 0041](../adr/0041-linux-window.md) (the Linux window, which waits for agents to be
kept off the session bus).
Code: `src/isolation/linux/` (Linux only, `std`, `serde`, and `serde_json`, no
`unsafe`). Tests: `src/isolation/linux/*` unit tests and
`tests/isolation/linux_sandbox.rs`. Use only synthetic values.

Unit X1 makes the sandbox. Unit X2 runs local proxied runs in it (section 6a); LE3
will run the commands of a linked environment in it, and X3 will start an agent host
in it (`apassy-sandbox` on Linux).

## 1. What the sandbox is

A sandbox is one `bwrap` (bubblewrap 0.8 or later) command line. bubblewrap runs
without privileges. It makes new namespaces and a new mount plan, then starts the
Apassy init program as PID 1, and the init program starts the command.

Namespaces (`namespace_args` in `bwrap.rs`):

| Option | Why |
| --- | --- |
| `--unshare-user` | A user namespace: the mounts below need no root. The user ID stays the same. |
| `--unshare-ipc`, `--unshare-uts`, `--unshare-cgroup-try` | Own System V IPC and POSIX message queues, own host name, own cgroup view. |
| `--unshare-pid` | Own PID namespace: the processes of the user outside are not there, so the F11 read of another process's environment (isolation.md §5) has no target. |
| `--unshare-net` (with `NetPlan::Bridged`) | Own network namespace with only `lo`. |
| `--disable-userns` | The command cannot make a user namespace of its own, so it cannot remount its view. Needs bubblewrap 0.8. |
| `--die-with-parent` | When the caller (the broker, the executor) ends, the sandbox ends. |
| `--new-session` | A new session: the command cannot push keys into the caller's terminal (TIOCSTI). |
| `--as-pid-1` | The Apassy init program is PID 1. When it exits, the kernel stops every other process of the sandbox. |

There is no seccomp filter and no Landlock rule (D7 explains why).

## 2. The mount plan

In this order (`arguments` in `bwrap.rs`). A later mount covers an earlier one.

| Step | Mounts | Effect |
| --- | --- | --- |
| 1 | `--ro-bind / /`, `--dev /dev`, `--proc /proc` | The system is read-only. `/dev` has only `null`, `zero`, `full`, `random`, `urandom`, `tty`, a private `shm`, and `pts`. `/proc` shows the sandbox's own processes. |
| 2 | An empty tmpfs over `/tmp`, `/var/tmp`, `/home`, `/root`, `/run` (each that exists, after symlinks) | The files of other users are gone. The user's runtime folder (`/run/user/<uid>`: the session bus, the keyring control socket, the SSH and GPG agent sockets, `systemd --user`) is gone. The system sockets of `/run` (Docker, the system bus, snapd, libvirt) are gone. `/tmp` is private. |
| 3 | From the hidden `/run`: the NixOS links `/run/current-system` and `/run/booted-system`; with the host network only, the DNS file that `/etc/resolv.conf` points to | Programs still start on NixOS, and DNS works with the host network. |
| 4 | The home folder: an empty private tmpfs (`HomePolicy::Hidden`) or the real home read-only (`HomePolicy::ReadOnly`) | A run sees no file of the home except what step 5 names. |
| 5 | The allowed paths at the same path: read-only (`read_only`) or writable (`rw`), ancestors first | The project folder of a run is writable. |
| 6 | A mask over each denied path that steps 1 to 5 left visible: an empty tmpfs (later read-only) over a folder, `/dev/null` over a file or a socket | A deny always wins over a bind. An allowed path inside a denied one is refused when the sandbox is built. |
| 7 | The sockets of `bind_socket`, read-only | A socket in a denied folder (the broker socket for X3). |
| 8 | The init program at `/tmp/.apassy-sandbox/init` and each bridge socket at `/tmp/.apassy-sandbox/bridge-<n>.sock`, read-only | The init program can live in a hidden folder (the executor in `~/.local/share/apassy/bin`). |
| 9 | `--remount-ro` of each folder mask, `--chdir <cwd>` | The masks cannot be written. |

The builder refuses, before bubblewrap starts:

- a relative path; an allowed path, a socket, the init program, or the working
  directory that does not exist;
- an allowed path or a home that holds a hidden folder of step 2 (`/`, `/var`, `/home`,
  `/tmp`, …): a bind of it would show what step 2 hides;
- an allowed path in `/proc`, `/dev`, or `/tmp/.apassy-sandbox`; a host `/proc` would
  show the environment of every process of the user;
- an allowed path inside a denied path;
- a bridge whose outside end is not a socket, or whose port is 0 or used twice;
- a working directory that would not exist in the sandbox;
- an environment name that is empty or has `=` or a zero byte, and a value with a zero
  byte.

### The plan of a proxied run

`Sandbox::for_run(&HostPaths::from_env()?, project)` is the default of a run (X2, LE3):

| Path | In the sandbox |
| --- | --- |
| `/usr`, `/etc`, `/bin`, `/lib`, `/opt`, … (the system) | read-only |
| the project folder | read and write; the working directory |
| `/tmp` | private, empty, writable; `TMPDIR=/tmp` |
| `$HOME` | private, empty, writable; writes do not reach the host |
| other homes (`/home/*`, `/root`), `/var/tmp`, `/dev/shm` of the host | not there |
| `/run`, with `$XDG_RUNTIME_DIR` (session bus, keyring, agent sockets) | not there |
| the Apassy data folder (`$XDG_DATA_HOME/apassy`): vaults, `vaults.json`, the broker and owner sockets, the bouncer brain | not there |
| `$XDG_CONFIG_HOME/apassy`: the configuration and the link file `link.json` of a linked environment (D4) | not there |
| each vault of the vault list outside the data folder, with `-wal`, `-shm`, `-journal`, `.lock`, `.backup`; each synced vault file with `.push.nosync` | not there (masked). A vault list that cannot be read stops the build: the sandbox cannot hide a vault file that it does not know. |
| `~/.ssh`, `~/.gnupg`, `~/.password-store`, `~/.pki`, the GNOME keyring and KWallet folders | not there (hidden home; masked when a bind shows them) |
| browser and mail profiles: Firefox, LibreWolf, Waterfox, Thunderbird, Chrome, Chromium, Brave, Edge, Vivaldi, Opera, Helium, and their Snap and Flatpak folders | as above |
| `/var/snap/lxd/common/lxd/unix.socket`, `/var/lib/lxd/unix.socket`, `/var/lib/incus/unix.socket` | masked in every sandbox (root for the `lxd` and `incus-admin` groups) |
| network | only `lo`; the bridges that the caller adds |

The hidden home is the main rule; the deny list is the second layer. It matters when
a bind shows a part of the home (a run in the home folder itself), with the read-only
home of X3, and for files outside the home.

### Environment

The command gets only the variables that the caller gives (`env`, `envs`). The
builder drops `DBUS_SESSION_BUS_ADDRESS`, `DBUS_SYSTEM_BUS_ADDRESS`,
`XDG_RUNTIME_DIR`, `SSH_AUTH_SOCK`, `SSH_AGENT_PID`, `GPG_AGENT_INFO`,
`GNOME_KEYRING_CONTROL`, `GNOME_KEYRING_PID`, `DISPLAY`, `WAYLAND_DISPLAY`,
`XAUTHORITY`, `KRB5CCNAME`, and `APASSY_SESSION`, and sets `TMPDIR=/tmp`.

The variables reach bubblewrap as its environment, never as `--setenv` arguments.
Every user can read the arguments of a process (`/proc/<pid>/cmdline`); only its user
can read its environment. The arguments hold paths and ports only. The `Debug` output
of `Builder` and `Sandbox` shows the variable names, not the values.

## 3. The network

With `NetPlan::Bridged(bridges)` the sandbox has its own network namespace with only
`lo`. Each bridge is the only way out:

```text
 sandbox (own network namespace)                       host
 command ─TCP─▶ 127.0.0.1:<inside>
                 init (PID 1) ─Unix─▶ bridge socket ─▶ HostRelay ─TCP─▶ run proxy
```

- `HostRelay::start(target)` makes a new folder with mode 0700 in the temporary
  folder of the host, listens on `bridge.sock` in it, and forwards each connection to
  `target` (the run proxy on `127.0.0.1:<port>`, or the router of a linked
  environment). Dropping it stops it and removes the socket and the folder.
- `relay.bridge(port)` is the `Bridge { inside: port, outside: socket }` of a sandbox.
  X2 uses the port of the proxy as the inside port, so `HTTPS_PROXY` does not change.
- The init program (`bridge_main`, called by `apassy-sandbox __netns-bridge …`) listens
  on each `127.0.0.1:<inside>` before the command starts, and forwards each connection
  to its socket. At most 256 connections at once go through one bridge or one relay.
- Abstract Unix sockets belong to the network namespace, so the host's (an old-style
  session bus, an X server) are out of reach. Path sockets of the host are out of reach
  through the mount plan, not through the namespace.
- No bridge: no network at all. `NetPlan::Host` keeps the host network and has no
  network rule (X3, as `sandbox/apassy-agent-host.sb` keeps the network on macOS).

DNS does not work in a network namespace. Programs that use `HTTPS_PROXY` do not need
it: they send `CONNECT host:443` to the proxy, and the proxy resolves the host.

## 4. Lifetime

- The init program is PID 1 of the sandbox (`--as-pid-1`). It exits with the exit
  code of the command (128 + the signal number when a signal stopped it; 125 for a
  setup error, 126 when the command cannot start, 127 when it is not found). Then the
  kernel stops every other process of the PID namespace: a `setsid` or double-forked
  grandchild does not outlive the run.
- A caller that kills `bwrap` stops the sandbox: `--die-with-parent` sends SIGKILL from
  `bwrap` to PID 1, and then the PID namespace ends.
- `--die-with-parent` uses `PR_SET_PDEATHSIG`, which fires when the *thread* that
  started `bwrap` exits. A caller must start and wait for the sandbox from one thread
  that lives as long as the run. `spawn_collect` in `src/broker/exec.rs` does.

## 5. The probe and the report without a rule

`probe()` runs once per process:

1. It takes the first of `/usr/bin/bwrap`, `/bin/bwrap`, `/usr/local/bin/bwrap`,
   `/run/current-system/sw/bin/bwrap` that root owns, in a folder that root owns, that
   no other user can change, and that is not setuid. There is no `PATH` search and no
   environment override: an agent can set the environment of the program that starts a
   run, and its own `bwrap` would report a sandbox that is not there.
2. It reads `bwrap --version` (0.8.0 or later).
3. It starts one empty sandbox with the namespace options of section 1 and runs
   `true`.

| Result | `network.rule` | `reason` |
| --- | --- | --- |
| `Ready` | `netns` | — |
| `Missing` (no trusted bwrap, or not bubblewrap) | `none` | `bwrap_missing` |
| `TooOld` | `none` | `bwrap_too_old` |
| `UsernsBlocked` (the empty sandbox failed; `detail` is bubblewrap's first line) | `none` | `userns_blocked` |

`Availability::report()` is the JSON of the run answer (broker-v0 `network.rule`,
added by X2), for example:

```json
{"rule":"none","reason":"userns_blocked","detail":"bwrap: setting up uid map: Permission denied","fix":"Let bubblewrap make user namespaces. …"}
```

A run without the rule still holds only placeholders. The agent-host launcher (X3)
refuses to start without the rule, as `apassy-sandbox` fails closed on macOS.

### Fixes

- **No bubblewrap:** `sudo apt-get install bubblewrap` (Debian, Ubuntu),
  `sudo dnf install bubblewrap` (Fedora), `sudo pacman -S bubblewrap` (Arch).
  A Homebrew `bwrap` in the user's home is not used: root does not own it.
- **Ubuntu 23.10 and later** restrict unprivileged user namespaces with AppArmor
  (`kernel.apparmor_restrict_unprivileged_userns=1`). The narrow fix is an AppArmor
  profile that lets only bubblewrap make them, in `/etc/apparmor.d/bwrap`:

  ```text
  abi <abi/4.0>,
  include <tunables/global>

  profile bwrap /usr/bin/bwrap flags=(unconfined) {
    userns,
    include if exists <local/bwrap>
  }
  ```

  then `sudo apparmor_parser -r /etc/apparmor.d/bwrap`. The wide fix, for all programs,
  is `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` (and a file in
  `/etc/sysctl.d/` to keep it). The sandbox itself then forbids user namespaces inside
  (`--disable-userns`).
- **A container** (Docker, Podman, a CI container) usually forbids user namespaces
  through its seccomp or AppArmor profile. Run the commands outside the container, or
  allow user namespaces in the container runtime, or accept `network.rule = "none"`.
- **Older kernels** with `kernel.unprivileged_userns_clone=0` (old Debian):
  `sudo sysctl -w kernel.unprivileged_userns_clone=1`.

## 6. Interface (for X2, X3, LE3)

```rust
use apassy::isolation::linux::{probe, HostPaths, HostRelay, NetPlan, Sandbox, HomePolicy};

let relay = HostRelay::start(proxy_addr)?;                    // host end of the bridge
let sandbox = Sandbox::for_run(&HostPaths::from_env()?, &project)?
    .net(NetPlan::Bridged(vec![relay.bridge(proxy_addr.port())]))
    .init_program(path_of_a_program_that_calls_bridge_main)   // apassy-sandbox on Linux
    .envs(run_env)                                            // placeholders, proxy variables
    .build()?;                                                // checks the plan
let mut command = sandbox.command(program, args);             // bwrap … -- program args
// The caller sets stdin, stdout, stderr, and process_group, and waits.
let rule = probe().report();                                  // network.rule of the answer
```

- `Sandbox::builder()` with `bwrap`, `init_program`, `net`, `home`, `deny`,
  `read_only`, `rw`, `bind_socket`, `cwd`, `env`, `envs`, then `build()`.
- `Sandbox::{command, args, program, rule}`. `rule()` is `netns` for a bridged
  sandbox and `none` for the host network.
- `HostPaths::{from_env, under_home, config_dir, link_file, denied}`.
- `bridge_main(args) -> i32` and `is_bridge_call(arg)`: a program whose first argument
  is `__netns-bridge` calls `std::process::exit(bridge_main(rest))` at once.
  `apassy-sandbox` does on Linux; LE3 adds it to `apassy-team`.
- `probe()`, `probe_with(path)`, `find_bwrap()`, `Availability::{report, is_ready,
  program}`, `RuleReport` (serializes to the JSON above).

## 6a. Local proxied runs (unit X2)

`network_for` (`src/broker/proxy/network.rs`) gives a proxied run of the broker the rule
of this computer when the run asks for it (local runs always do):

| Found | `network.rule` | What the run gets |
| --- | --- | --- |
| `probe()` is `Ready` and `apassy-sandbox` is next to the broker program | `netns` | `Sandbox::for_run(&HostPaths::from_env()?, cwd)` with one bridge: `127.0.0.1:<proxy port>` in the namespace, through a `HostRelay`, to the run proxy. `HTTPS_PROXY` does not change. |
| bubblewrap missing, too old, or user namespaces blocked | `none` with `reason`, `detail`, `fix` (`Availability::report`) | the old run with the user's network; only placeholders |
| `apassy-sandbox` is not next to the broker program (`target/<profile>/` for a Cargo test binary in `deps/`) | `none`, `reason` = `sandbox_program_missing` | as above |

The init program is found only next to the running program; there is no environment
override, because it is PID 1 of every run.

What `spawn_collect` (`src/broker/exec.rs`) adds to the plan of section 2:

- The folder of the trust files of the run (`apassy-run-…` in the host temporary
  folder, hidden by the private `/tmp`), read-only.
- Each folder of the run's `PATH`, and the program when its path is absolute, that the
  plan would hide (under the home, `/tmp`, `/var/tmp`, `/run`, `/root`), read-only, so
  that `~/.local/bin`, `~/.cargo/bin`, and the NixOS wrappers still start. Skipped: the
  home itself and any folder that holds a hidden one, a path in a denied path, a path in
  the working directory (already writable), and a path that does not exist. A tool whose
  files live elsewhere in the hidden home (for example a rustup proxy and
  `~/.rustup`) still does not start; put it in a folder outside the home or run it
  without placeholders.
- The base environment (`HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `PATH`; `TMPDIR` is
  `/tmp`) goes through the sandbox plan. The secrets, the placeholders, and the proxy
  variables are set on the `bwrap` command after it, as before, so their values never
  pass through the plan or its `Debug`.
- One thread starts `bwrap` and waits for it (`--die-with-parent`). A timeout or the end
  of the run stops the process group of `bwrap`; then PID 1 and every process of the
  sandbox stop.

A run whose sandbox cannot be built (its working directory is `/`, `/tmp`, or `/home`
itself; the vault list cannot be read; a path is inside a denied one) does not start
(`start_failed`, with the cause), instead of running without the rule.

Differences from a run without the rule: a process stopped by a signal reports
`exit_code` 128 + the signal (the init program's code) instead of none; the run sees an
empty home and a private `/tmp`; DNS does not work except through the proxy.

## 7. Tests

Unit tests (every Linux test job; no bubblewrap needed): the argument order and the
namespace options, the mount order (denies after binds, sockets after denies,
remounts last), the refusals of section 2, the environment never in the arguments,
the session variables dropped, the deny list and the vault list (a damaged list fails
closed), the bridge parser and exit codes, a bridged connection through the bridge and
the host relay, the private relay folder, and the probe with fake `bwrap` scripts
(`probe_reports_userns_blocked`, an old, a missing, a foreign, a hanging, and a
user-owned `bwrap`).

Integration tests, `tests/isolation/linux_sandbox.rs` (`isolation_linux::`), each with a
control outside the sandbox:

| Test | Checks |
| --- | --- |
| `run_profile_hides_the_vault_ssh_and_files_outside_the_project` | No canary of the vault, its `-wal`, the bouncer brain, a listed vault outside the data folder, the link file, the configuration, `~/.ssh`, GPG, the keyring, Firefox, Chrome, Chromium, another project, a note in the home, or the host `/tmp`. The project is readable and writable; a write in the private home does not reach the host. |
| `a_read_only_home_still_hides_keys_keyrings_browsers_and_apassy_files` | The same secrets with the real home read-only; other home files readable; the masks are empty and cannot be written; the home cannot be written. |
| `sandbox_hides_the_apassy_data_dir_and_the_runtime_dir` | The runtime folder and its bus socket, `/run/user`, the system bus, the Docker socket, the bus variable, and the other homes are not there; the bus gets no connection. |
| `netns_reaches_the_proxy_through_the_bridge` | `curl -x` reaches a stand-in proxy through the bridge and the host relay. |
| `netns_reaches_only_the_bridged_port` | Another listener on the host's 127.0.0.1, `1.1.1.1:443`, and a direct `curl` fail; the listener gets nothing; the proxy works in the same run. |
| `netns_has_no_udp` | A datagram to the host's 127.0.0.1 never arrives; `1.1.1.1:53` has no route. |
| `netns_abstract_socket_of_the_host_is_unreachable` | `ECONNREFUSED` for an abstract socket that the host listens on. |
| `netns_cannot_see_outside_processes` | An outside process is not in `/proc`; at most a few processes are. |
| `netns_run_ends_with_its_descendants` | A `setsid` grandchild stops when the command ends. |
| `stopping_the_sandbox_stops_every_process_in_it` | A kill of `bwrap` stops a `setsid` grandchild. |
| `a_sandboxed_process_cannot_make_a_user_namespace` | `unshare -U` and `unshare -Ur … mount` fail. |
| `the_exit_code_of_the_program_is_the_exit_code_of_the_sandbox` | Exit code 7, and 127 for a missing command. |
| `the_probe_reports_the_network_rule_of_this_computer` | The probe and the JSON report, printed for the log. |

Without bubblewrap the integration tests print why and pass. With
`APASSY_REQUIRE_BWRAP=1` they fail instead. They also need `bash`, `curl`, `python3`,
`setsid`, `timeout`, and `unshare` (all on GitHub's ubuntu-24.04 runners).

CI: the job `linux-isolation` (ubuntu-24.04) installs bubblewrap, records the runner
defaults (the AppArmor knob, the AppArmor profiles, and whether an empty sandbox
starts), sets `kernel.apparmor_restrict_unprivileged_userns=0`, and runs:

```
APASSY_REQUIRE_BWRAP=1 cargo nextest run --profile ci --offline --locked --all-features \
  --lib --test it -E 'test(/^isolation(::|_linux::)/) | test(/^broker::proxy::network::/) | test(/^run_proxy::linux_/) | test(=agent_run::a_placeholder_variable_gets_a_placeholder_and_the_run_proxy)'
```

The X2 tests in that filter: `broker::proxy::network::tests::on_linux::*` (the plan
with a ready, blocked, and missing bubblewrap and a missing init; the folders of
`PATH` that are shown), `run_proxy::linux_direct_connection_fails_in_a_proxied_run`,
`run_proxy::linux_proxied_run_reports_netns`,
`run_proxy::linux_proxied_run_reports_its_rule_and_holds_only_placeholders`, and the
broker-level `agent_run::a_placeholder_variable_gets_a_placeholder_and_the_run_proxy`.
In the other Linux test jobs (no bubblewrap) the same tests check `none` with the
reason, or skip.

## 8. Measurements

None yet on a real machine. The first `linux-isolation` run records, in its step
"Record user namespaces with the runner defaults", whether GitHub's ubuntu-24.04 runner
lets bubblewrap make user namespaces before the change (an open question of the s5
plan, "Not verified in the code"). Copy the result here with the run link. The devbox
(`devbox-arm`, `devbox-x86`) and a container remote are measured with the physical
acceptance of the s5 plan.

## 9. What this does not protect

- **The host network (`NetPlan::Host`)** has no network rule, and the abstract Unix
  sockets of the host stay reachable there: an old-style session bus
  (`unix:abstract=…`) or an X server. Ubuntu 24.04 and Fedora use a path socket for the
  session bus, which the mount plan hides. X3 must check this on each supported desktop.
- **Supplementary groups stay.** A user namespace keeps the user's groups for file
  access. A root-equivalent socket outside `/run` and outside the masked list (for
  example a Docker socket in another place, `--group docker`) stays reachable. Add it
  with `deny`.
- **Paths that appear later.** A denied path that does not exist when the sandbox
  starts gets no mask. The read-only system and the hidden folders keep the sandbox
  from making one, but a process outside can make one later in a visible place (a
  vault created outside the data folder after the start).
- **Visible system files.** `/` is read-only, not hidden: world-readable files of
  other users outside `/home`, `/root`, and the temporary folders (for example in
  `/srv`, `/opt`, `/mnt`, `/media`) stay readable.
- **A masked file reads as empty** (`/dev/null`); a masked folder is an empty
  read-only folder. The sandbox sees that the path exists.
- **Orphaned processes** become children of the init program, which waits only for
  its command. Their zombies stay until the run ends (the standard library cannot
  wait for any child without `unsafe`). The run ends them all.
- **No seccomp**, so the kernel's whole system call surface is open to the command,
  inside its namespaces. A kernel bug in user namespaces is an escape.
- **The program that starts the sandbox is not inside it.** In a linked environment
  the agent runs outside and can change the executor or its environment. The remote
  holds only placeholders, so this costs no value (ADR 0037 §6).
- **`/sys` is read-only, not hidden.** It shows hardware and the host's network
  interfaces, not files of the user.
- **Interactive programs** lose their controlling terminal (`--new-session`): job
  control and the terminal's Ctrl-C do not reach them. Runs have no terminal; X3 must
  check an interactive agent host.

## 10. For the judge panel (X1 + X3)

The security-sensitive parts are marked `SECURITY (judge panel)` in the code:

- `bwrap.rs`: the namespace options and the whole mount plan (`arguments`, `home`,
  `allowed`, `denied`, `visible`): the order, the hidden roots, the refusals, and the
  masks.
- `probe.rs`: `trusted` and the fixed bubblewrap paths (no `PATH`, no override).
- `mod.rs`: `sandbox_env` (no values in arguments, dropped session variables) and the
  `Debug` output without values; `HostPaths::denied` with the vault list that fails
  closed.
- `bridge.rs`: the bridge connects only to the bound sockets; the init program as
  PID 1 and its exit; `HostRelay`'s private folder.

Questions for the panel: whether `/run` must be hidden for the host network of X3
(DNS through `/etc/resolv.conf` is given back); whether the list of hidden roots
needs `/mnt`, `/media`, or `/srv`; whether a masked file should fail to open rather
than read as empty; whether `--as-pid-1` without a reaper for orphans is acceptable.
