//! Agent side of the thin agent path (ADR 0004).
//!
//! This module uses only `std`, `serde`, and `serde_json`. It does not open the
//! vault. The MCP adapter and tests use it to talk to the local broker.

pub mod client;
pub mod mcp;
pub mod wire;
