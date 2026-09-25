# ADR 0005 — TLS for connector destinations

Date: 2026-09-25.
Status: owner approved option A on 2026-09-25. This decision closes the TLS question in [ADR 0004](0004-agent-path-first.md). It does not select a real service.

## Context

The broker sends the stored token to the destination of an item. Before this decision, the broker accepted only loopback `http://` destinations, because the crate had no TLS client.
A real service needs `https://`. A custom cipher or TLS implementation is not permitted (ADR 0001).

## Options

| Option | Result |
| --- | --- |
| A. `rustls` with `ring` and `rustls-platform-verifier` | Selected. macOS checks the certificate chain with the system trust store. No async runtime. |
| B. `rustls` with `aws-lc-rs` | Not selected. It compiles a large C library and needs CMake. |
| C. `rustls` with `webpki-roots` | Not selected. The root list is in the binary. It ignores the macOS trust settings. |
| D. `reqwest` | Not selected. It adds an async runtime, redirects, and proxy logic. A redirect can send the token to a different host. |

## Decision

- `rustls = "=0.23.44"` with `default-features = false` and the features `ring`, `std`, and `tls12`.
- `rustls-platform-verifier = "=0.7.0"`.
- The `vault` feature enables both dependencies. The MCP adapter does not use them.
- On macOS arm64, these dependencies add 14 crates to the build: `core-foundation`, `core-foundation-sys`, `getrandom` 0.2, `log`, `ring`, `rustls`, `rustls-pki-types`, `rustls-platform-verifier`, `rustls-webpki`, `security-framework`, `security-framework-sys`, `subtle`, `untrusted`, and `zeroize`. There is no `aws-lc` crate in `Cargo.lock`.

## Connector rules after this decision

- A destination is `https://HOST` or `https://HOST:PORT`. The host is a DNS name or an IP address.
- A destination can also be `http://` on a loopback address. This supports local tests and the synthetic service.
- A destination has no path, query, fragment, or user information.
- The broker uses the destination host for SNI and for the certificate name check.
- The broker does not follow redirects. A `3xx` status gives `destination_error`.
- A TLS failure gives `tls_failed`. The broker does not send the token when the handshake fails.
- The HTTP client reads `Content-Length` and `chunked` bodies. The limit is 64 KiB.
- Tests can add a test root certificate. The desktop app uses only the system trust store.

## Limits

- The owner selects the destination. The broker does not check the destination against a list of known providers.
- There is no certificate pinning.
- DNS answers are not verified beyond the TLS certificate check.
- The real-secret gate stays BLOCKED. TLS protects the network path. It does not isolate the vault from a same-user process.
