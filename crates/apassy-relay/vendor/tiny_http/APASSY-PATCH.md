# Apassy local patch

Base: crates.io `tiny_http` 0.12.0, crate SHA-256
`389915df6413a2e74fb181895f933386023c71110878cd0825588928e64cdc82`.
Copied `src/`, Cargo manifest, README and upstream licenses. Optional TLS features
remain unused; the relay terminates TLS at Cloudflare.

Changes relative to that base (plus rustfmt):

- `request.rs`, `common.rs`: strict request framing and header constructors.
- `client.rs`: header bounds; install body deadline; guarded connections handle one
  request only, avoiding pipelined requests sharing a cancellation boundary.
- `connection.rs`, `util/refined_tcp_stream.rs`, new `deadline.rs`: absolute read
  budgets, idle read/write limits, single transport-expiry reaper.
- `lib.rs`: opt-in `Server::http_with_deadlines`; legacy constructors used by test
  mocks preserve their previous behavior.
- `request.rs`: `abort_input` / `abort` shut down the actual socket; guarded responses
  declare `Connection: close`. `response.rs` permits that header value.
- `util/equal_reader.rs`: bounded destructor buffer. `util/mod.rs` and the dummy
  Send/Sync assertion suppress/remove preexisting unused-code warnings.
- Independent review: reject obs-fold before trimming and restrict optional
  whitespace to SP/HTAB; cap aggregate headers at 64 KiB; reject guarded upgrades;
  disable guarded small-body prefetch before relay admission; cap live transports
  at 1024 before spawning parser work. New `util/chunked.rs` replaces the inbound
  decoder with bounded metadata, checked sizes, strict CRLF and incomplete body
  errors. EqualReader also rejects premature EOF. `test.rs` retains the original
  prefetch behavior for synthetic requests.

The relay regression tests exercise this path dependency directly. This is a
bounded local mitigation of the published reports, not an upstream release or a
complete HTTP parser audit. See `docs/HTTP-SECURITY.md` for source links, incompatible
fork decision, remaining exposure and rollout effects.

## Lints (2026-11-02)

Since ADR 0037 the relay is a crate of the `wydrox/apassy` workspace, and Cargo makes this path
dependency a workspace member (`workspace.exclude` does not apply to path dependencies). Two
changes to `Cargo.toml` follow:

- `[lints.clippy] all = "allow"`: Clippy lints members with the workspace's `-D warnings`. This copy
  keeps the upstream style; the patch itself is reviewed as relay code.
- The TLS features (`ssl`, `ssl-openssl`, `ssl-rustls`) are empty, and their optional dependencies
  (openssl, rustls 0.20 with ring 0.16, rustls-pemfile, zeroize) and the dev-dependencies are
  removed. A member locks every optional and dev dependency, and these old versions carry
  advisories. The relay never enabled them. Enabling a TLS feature now fails to compile.

## WebSocket upgrade for the tunnel (2026-11-10, connect-tunnel-v1, unit C4)

The Connect tunnel (`crates/apassy-relay/src/server/tunnel.rs`) upgrades
`GET /v1/tunnel/node` and `GET /v1/tunnel/dial/{node}` on the deadline transport.

- `client.rs`: the guarded transport still refuses an upgrade with `Content-Length` or
  `Transfer-Encoding`, or of another method; a body-less `GET` upgrade now reaches the
  handler. Its reader is the raw stream, and the connection still serves one request.
- `request.rs`: new `Request::upgrade_split` returns the read half (the same buffered
  reader that read the head, so bytes that came with the head are kept), the write
  half, and a shutdown function. It first releases the request's deadlines.
- `deadline.rs`, `connection.rs`: `Deadline::release(idle)` ends the header/body/handle
  deadlines of an upgraded transport, sets read and write timeouts to `idle`, and makes
  the reaper forget it (it no longer counts against the 1024 live transports; the
  tunnel caps its own WebSockets).

Open question settled: upstream `Request::upgrade` (and `upgrade_split`) keep bytes in
the read buffer, because the head and the upgraded stream share one
`BufReader<RefinedTcpStream>` through `SequentialReader`. The regression test is
`upgrade_keeps_bytes_sent_with_the_head` in `crates/apassy-relay/tests/server_tunnel.rs`.

## One upgrade rule (2026-11-10, tunnel review)

- `common.rs`: new `asks_upgrade(headers)`: an `Upgrade` header, or the token `upgrade`
  (any case, comma-separated, SP/HTAB trimmed) in any `Connection` header. Exported as
  `tiny_http::asks_upgrade`; the relay's guard (`http::wants_upgrade`) calls it.
- `client.rs`: the guarded transport's refusal of an upgrade that is not a body-less
  `GET`, and the end of connection reuse after an upgrade, use it (upstream read a
  substring of the first `Connection` header for the latter).
- `request.rs`: the raw upgrade reader is chosen by it, and only for a request without
  `Content-Length` or `Transfer-Encoding`; upstream chose it on a substring of the first
  `Connection` header and then ignored the body framing.

## Sequential requests where the relay allows them (2026-11-11, unit RM item 5)

The iPhone reaches its Mac through a Connect dial, and a dial for each request is slow and
counts against Connect's dial rate. A device stream of the tunnel may now carry sequential
requests; every other connection still serves one request.

- `lib.rs`: new `KeepAlive { idle, allow }` and `Server::http_with_deadlines_and_keep_alive`
  (`http_with_deadlines` is that with `None`). `allow` gets the client's address and the
  listener's address; the relay passes `apassy::net::front_peers::is_tunnel` for its
  tailnet listener only (no header is read). A connection that may be kept is handed the
  next request only after the answer of the one before it was written (the notification
  that the TLS path of upstream uses).
- `request.rs`: `respond_impl` keeps the connection only when `allow` says so for this
  connection, the request is HTTP/1.1 and asks neither to close nor to upgrade, its body
  was read to its end (new `UntilEnd` reader: no body is drained after a kept answer), the
  answer has no `Connection` header, and no byte waits on the socket (a non-blocking peek,
  `Connection::input_waiting`). Then the answer has no `Connection: close`; else it has
  it, as before. `into_writer`, `upgrade`, and `upgrade_split` never keep.
- `client.rs`: `await_next` waits for the reader of the request before (the answer is
  written), goes on only when that answer kept the connection and nothing came before it
  (bytes in the read buffer close the connection: pipelining), and waits at most `idle` for
  the first byte of the next head. An idle or pipelined connection closes without a byte
  from the server (no `408`). From the first byte on the request has fresh header, body,
  and handle deadlines.
- `deadline.rs`: the handle deadline moved into `Deadline` (`handle_until`), so the reaper
  closes a kept connection by the deadline of its current request, or 5 s after its idle
  wait; `idle_wait`, `next_request`, `answered_for_next`/`take_again`, `allows`.
- `util/sequential.rs`: `SequentialReader::inner` (the reader once its turn came).
- `keep_alive_tests.rs`: two and more sequential requests on an allowed connection, a
  pipelined request closes and is never served, a connection that is not allowed (and a
  server without keep-alive) serves one request with `Connection: close`, an unread body
  and HTTP/1.0 close, the idle close writes nothing, and a stalled next head ends at its
  own header deadline.
