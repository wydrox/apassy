//! The team relay of Apassy (ADR 0013 of the core, way B).
//!
//! The relay holds the team vault, decides each run with the core command
//! analysis, and proxies the requests of a run to the hosts of its items. It puts
//! the real value only into an auth position, and it puts the placeholder back
//! in the response. The design is in `docs/SPEC.md`.
//!
//! Shared modules (frozen after the skeleton; a track does not edit them):
//! `api`, `config`, `error`, `ids`, `secret`, `session`.
//! Track modules: `server` (track server), `proxy` (track proxy), `cli` (track client).
#![forbid(unsafe_code)]

pub mod api;
pub mod config;
pub mod error;
pub mod ids;
pub mod secret;
pub mod session;

pub mod cli;
pub mod proxy;
pub mod server;

/// Seconds since the Unix epoch. Every time in the relay is in this unit.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
