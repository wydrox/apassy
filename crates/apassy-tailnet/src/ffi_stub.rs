//! The stand-in for `ffi.rs` without the feature `tailnet`: the same safe signatures,
//! no archive, no `unsafe`. `TailnetNode::new` checks `LINKED` first and returns
//! `Error::NotBuilt`, so nothing below runs; each function still answers "closed".

use std::ffi::{CStr, c_int};
use std::os::fd::{BorrowedFd, OwnedFd};

pub const LINKED: bool = false;

pub type Handle = c_int;

pub const EBADF: c_int = libc::EBADF;
pub const ENOENT: c_int = libc::ENOENT;
pub const ERANGE: c_int = libc::ERANGE;

#[derive(Clone, Copy, Debug)]
pub enum Setting {
    Dir,
    Hostname,
    AuthKey,
    ControlUrl,
}

pub fn new() -> Handle {
    -1
}

pub fn start(_sd: Handle) -> c_int {
    EBADF
}

pub fn up(_sd: Handle) -> c_int {
    EBADF
}

pub fn close(_sd: Handle) -> c_int {
    EBADF
}

pub fn set(_sd: Handle, setting: Setting, _value: &CStr) -> c_int {
    let _ = setting;
    EBADF
}

pub fn set_ephemeral(_sd: Handle, _ephemeral: bool) -> c_int {
    EBADF
}

pub fn set_log_fd(_sd: Handle, _fd: Option<OwnedFd>) -> c_int {
    EBADF
}

pub fn errmsg(_sd: Handle) -> (c_int, String) {
    (EBADF, String::new())
}

pub fn getips(_sd: Handle) -> (c_int, String) {
    (EBADF, String::new())
}

pub fn listen(_sd: Handle, _addr: &CStr) -> Result<OwnedFd, c_int> {
    Err(EBADF)
}

pub fn accept(_listener: BorrowedFd<'_>) -> Result<OwnedFd, c_int> {
    Err(EBADF)
}

pub fn remote_addr(_listener: BorrowedFd<'_>, _conn: BorrowedFd<'_>) -> (c_int, String) {
    (EBADF, String::new())
}

pub fn dial(_sd: Handle, _addr: &CStr) -> Result<OwnedFd, c_int> {
    Err(EBADF)
}

pub fn status_json(_sd: Handle) -> Result<String, c_int> {
    Err(EBADF)
}

pub fn whois_json(_sd: Handle, _addr: &CStr) -> Result<String, c_int> {
    Err(EBADF)
}

pub fn loopback(_sd: Handle) -> Result<(String, String), c_int> {
    Err(EBADF)
}
