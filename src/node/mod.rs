//! The Mac's own node (ADR 0037, cloud slice): an embedded relay in the app process
//! that hosted cloud agents reach through Tailscale Funnel
//! (docs/design/implementation-plan-0037-cloud-agents.md).
//!
//! The root crate cannot depend on the relay crate (the relay depends on this one), so
//! the app talks to its node through the object-safe traits of `backend`. The relay
//! crate implements them (`apassy_relay::embedded::EmbeddedRelay`); the app crate passes
//! that implementation in. Tests use a fake backend.

pub mod backend;
