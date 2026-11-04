# PR #104: review of the two CI reliability fixes (2026-11-04)

Scope: the working diff on `feat/bouncer-secret-context` at HEAD
`c222c0c3ea1c8384a2887b4edc6fd62bc24d6fe9`. This review read source only. It did not
build, run tests, query CI, use the network, or use secrets. The bouncer method, its gates
and the held-out files are out of scope, and the review did not read them.

Verdict: **ACCEPT**. No blocking findings. Runtime proof is still missing: the three new
tests have not been compiled or run (NOT_RUN until CI).

## 1. `extension-tests/tests/passkey-bridge.spec.mjs`

- Only the two first navigations use `goto` from `support/helium.mjs`: `openRp` (line 20)
  and `/otp-iframe` (line 46). The helper retries only `net::ERR_ABORTED`, at most 3 times,
  250 ms apart. It rethrows every other error.
- Line 114, the navigation in the cancellation test, still uses `page.goto`. This is
  correct: a retry would add a second navigation to the event sequence that the test checks.
- No WebAuthn step or assertion is retried. The fixture already warms Helium up with
  `warmUpHelium` (`fixtures/passkey-bridge/browser.mjs:194`), so the helper is the existing
  pattern, not a new one. Both CI errors happened at `page.goto ... waiting until "load"`,
  before any assertion, so the retry targets the observed failure.

## 2. `vendor/tiny_http/src/lib.rs`: lifecycle of the accept thread

These points are correct in source:

- **Bounded shutdown.** Inside the loop, the accept thread waits only in `accept`
  (nonblocking), in `park_timeout(10ms)`, and on short mutex holds (the reaper lock,
  `TaskPool::spawn`, `MessagesQueue::push`). `push` does not block on capacity
  (`VecDeque::with_capacity` only), and `ClientConnection::new` does no I/O. A steady
  stream of connections cannot keep the loop running, because the loop checks `close`
  after each successful `accept`. The `>= 1024` and `try_clone` paths use `continue` and
  return to the `close` check.
- **Wake race.** Drop sets `close` and then calls `unpark`. If the thread is not yet in
  `park_timeout`, the unpark token makes the next park return at once. `unpark`
  synchronizes with `park`, and the 10 ms timeout also limits a missed wake. `Relaxed` is
  enough.
- **Wake without a connection.** Shutdown does not depend on a connect-to-self, so the
  wildcard IPv4/IPv6 cases and an unlinked or unnamed Unix socket all finish. The patch
  removes the old `as_pathname().unwrap()` panic in Drop for unnamed Unix addresses.
- **Error, panic and reentrancy.** After an accept error, the thread pushes the error and
  breaks, as before, and `join` returns at once. After a panic, unwinding drops the
  `Listener` before `join` returns, and the code ignores `Err`. The `assert_ne!` blocks a
  self-join. This can only happen through a reentrant drop on the accept thread, which
  this crate does not do.
- **Blocking I/O for clients.** `set_nonblocking(false)` runs before `try_clone` and
  before the guard is made, so both handles share blocking mode on macOS, where accepted
  sockets inherit nonblocking mode.
- **Send and Sync.** `JoinHandle<()>` is `Send + Sync`, so `MustBeShareDummy for Server`
  still compiles.
- **Relay path.** `http::serve` owns `Serving.server` as a local, so the `Server` drops
  when `serve` returns. `RunningRelay::stop` joins the threads of the node, public,
  tailnet and tailnet-local listeners, so every listener closes before `stop` returns.
  This is the property that `tailnet_scope.rs:197` asserts.
- **Unchanged parts.** TLS stays compiled out. The transport limits (1024 tracked
  connections, deadlines, the reaper) did not change.

### Non-blocking findings (small doc fixes; the parent can make them)

- **N1. Idle wake-ups, a material tradeoff in addition to latency.**
  `src/lib.rs:394` parks for 10 ms on every idle loop, so each `Server` wakes about
  100 times per second. The Mac app embeds the relay
  (`crates/apassy-app/src/main.rs:88`, `EmbeddedRelay`) with the node, tailnet and
  tailnet-local listeners. That is about 300 idle wake-ups per second on the owner's Mac,
  in addition to the reaper's 20 per second per `Server` and the 200 ms `recv_timeout`.
  APASSY-PATCH.md describes only the admission latency.
  Minimal fix: in APASSY-PATCH.md, add one sentence about the idle wake-ups per listener.
  If the energy impact becomes a problem, a possible follow-up is `poll(2)` on the
  listener with a self-pipe wake. That gives no admission latency and still bounds
  shutdown.
- **N2. The patch note says too much about responses after drop.** APASSY-PATCH.md
  says "preserving responses already handed to `recv()`". That is true only for servers
  without deadlines. With `http_with_deadlines`, the only constructor that the relay uses,
  the reaper shares the `close` flag and calls `Shutdown::Both` on every tracked socket
  after close (`src/deadline.rs:70-73`). This behaviour did not change.
  Minimal fix: limit the sentence to servers without deadlines and mention the reaper.
- **N3. The Unix test checks only that drop finishes.** In `tests/shutdown.rs`, the
  Unix test also passes against the old code, because the old Drop did not join. It
  proves that the new join cannot hang, but not that the Unix listener is released.
  The TCP test does tell the old code from the new: there, the old code closed the
  listener only after Drop returned. No change is needed; describe the Unix test
  accurately.

## 3. `tests/shutdown.rs` and the CI step

- `drop_server` runs the drop on a separate thread, waits at most 3 s with
  `recv_timeout`, and then checks `join`. A broken implementation therefore fails instead
  of hanging, and no sleep or retry hides a failure.
- Test 1 (loopback and wildcard): the listener must refuse a connection after Drop
  returns. Each case binds port 0, and nextest runs each test in its own process, so the
  risk that another process takes the freed port in that short window is low.
- Test 2: a server without deadlines answers a request after `Server` drop. This tests
  that the client workers are not joined.
- Test 3: the test uses its own temporary directory with a short path
  (pid plus nanoseconds), cleaned up by RAII. It does not use `~/.t3/userdata` or any
  user data.
- The format strings use explicit arguments, which is correct for Rust 2018.
- CI (`ci.yml:316-318`, relay slice 1 only): `-p tiny_http` selects a path dependency
  that is not a workspace member. It has no dev-dependencies, so `--locked --offline`
  needs no new lock entries. The workflow does not set `-D warnings` for this step.
  Whether nextest accepts this package selection has not been checked: the CI run is the
  proof.

## Required after push

1. `relay (1)`: `tailnet_scope::the_tailnet_listener_stops_with_the_node` passes, the new
   step "Verify vendored HTTP listener shutdown" passes (3 tests), and the existing
   relay and core tests pass in both slices.
2. Extension E2E: the two passkey-bridge tests pass on Ubuntu and on the Intel fallback,
   and the cancellation test still passes.
3. Before a release claim: on the Mac app with the embedded node, check idle wake-ups
   (N1) and the connection latency of the tailnet route.

Status: source-only review. Quality gate B is not supported by this review. C, D and E
are blocked. No release or merge is approved.
