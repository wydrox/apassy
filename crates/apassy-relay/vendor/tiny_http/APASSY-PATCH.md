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

Since ADR 0036 the relay is a crate of the `wydrox/apassy` workspace, and Cargo makes this path
dependency a workspace member (`workspace.exclude` does not apply to path dependencies). Two
changes to `Cargo.toml` follow:

- `[lints.clippy] all = "allow"`: Clippy lints members with the workspace's `-D warnings`. This copy
  keeps the upstream style; the patch itself is reviewed as relay code.
- The TLS features (`ssl`, `ssl-openssl`, `ssl-rustls`) are empty, and their optional dependencies
  (openssl, rustls 0.20 with ring 0.16, rustls-pemfile, zeroize) and the dev-dependencies are
  removed. A member locks every optional and dev dependency, and these old versions carry
  advisories. The relay never enabled them. Enabling a TLS feature now fails to compile.
