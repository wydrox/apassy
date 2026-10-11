//! The vault core of the Apassy iPhone app (ADR 0023, contract
//! `docs/contracts/ios-core-v1.md`).
//!
//! A C interface over the same vault and relay sync code as the Mac app: the app and
//! its AutoFill extension call [`ffi`] with JSON requests and get JSON answers. All
//! the logic is in safe Rust ([`core`]); `ffi` is the only module with `unsafe`.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod core;
mod ffi;

pub use core::Core;
