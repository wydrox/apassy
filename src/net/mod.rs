//! The network pieces of the node over the tailnet (ADR 0037 §2, §3, D4; plan
//! `docs/design/implementation-plan-s2-s3.md`, unit N2).
//!
//! - [`tailnet`]: the tailnet addresses of this machine and the two Tailscale ranges.
//! - [`pin`]: the certificate pin, `b64u(SHA-256(DER))`, the format of the companion
//!   and of `PinnedTLS.swift`.
//! - [`sealed_key`]: AES-256-GCM under a key derived from the node master key.
//! - [`certificate`]: the node certificate, its DER in a file and its key sealed.
//! - [`limits`]: connection slots and per-key rates, shared with the companion.
//! - [`tls_front`]: the TLS front. It binds only tailnet addresses, refuses other
//!   peers before the handshake, and pumps bytes to a loopback target. It never parses
//!   HTTP.
//!
//! The Wi-Fi companion (`crate::companion`) uses the TLS configuration, the limits,
//! the pin, and the Tailscale parsing from here until its removal (unit W2).
//!
//! Nothing here binds `0.0.0.0` or `::`.

pub mod limits;
pub mod pin;
pub mod tailnet;

pub use pin::Pin;
