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

The relay regression tests exercise this path dependency directly. This is a
bounded local mitigation of the published reports, not an upstream release or a
complete HTTP parser audit. See `docs/HTTP-SECURITY.md` for source links, incompatible
fork decision, remaining exposure and rollout effects.
