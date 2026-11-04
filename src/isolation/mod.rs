//! Process isolation outside Seatbelt.
//!
//! macOS runs agents and proxied runs in Seatbelt profiles (`sandbox/`,
//! `src/broker/proxy`, [isolation.md](../../docs/operations/isolation.md)). Linux has
//! no Seatbelt, so [`linux`] builds a bubblewrap sandbox: ADR 0011 stage 2 (a proxied
//! run has no route except the run proxy) and ADR 0037 stage 8 ("Linux isolation").
//! The design and the measurements are in
//! [isolation-linux.md](../../docs/operations/isolation-linux.md).
//!
//! On other systems this module is empty.

#[cfg(target_os = "linux")]
pub mod linux;

/// The path rules of a proxied run in the Linux sandbox. Pure, so they are tested
/// on every system.
#[cfg(any(target_os = "linux", test))]
pub(crate) mod run_paths;
