//! The C API of the vendored libtailscale (`go/tailscale.h`, commit `ac7ed43a`) and
//! the Apassy export of `go/apassy.go`. This is the only module of the workspace with
//! `unsafe` (lib.rs allows it here and nowhere else). Every function here is safe to
//! call: it passes valid, NUL-terminated strings and buffers of the stated sizes, and
//! it turns each file descriptor that libtailscale hands out into an `OwnedFd` exactly
//! once.
//!
//! The rules of libtailscale that the safe layer relies on:
//! - A handle (`tailscale`) is an integer key into a Go map. A stale or closed handle
//!   gives `EBADF`, never undefined behavior.
//! - Strings passed in are copied by Go (`C.GoString`) before the call returns.
//! - `tailscale_listen` and `tailscale_dial` return one end of a socket pair that only
//!   the caller closes; Go keeps the other end and closes it itself. Closing the
//!   listener end tells Go to close the tailnet listener.
//! - `tailscale_accept` returns a descriptor that `recvmsg` installed in this process.
//!   Go closed its own copy after `sendmsg`; the caller owns the new one.
//! - `tailscale_status_json` and `ApassyTailnetWhoisJSON` return a string from
//!   `malloc` (`C.CString`) that the caller frees with `free`.
//! - `tailscale_set_logfd` gives the descriptor to Go (`os.NewFile`): Go closes it when
//!   the server is garbage-collected. The caller passes a descriptor it owns and stops
//!   owning it on success.
//! - A nil buffer or a zero length makes Go panic, which ends the process. Nothing
//!   here passes one, except the spike probe `spike::go_panic`.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::ptr;

use zeroize::Zeroize;

/// The libtailscale archive is linked.
pub const LINKED: bool = true;

/// A libtailscale server handle (`tailscale` in `tailscale.h`).
pub type Handle = c_int;

pub const EBADF: c_int = libc::EBADF;
pub const ENOENT: c_int = libc::ENOENT;
pub const ERANGE: c_int = libc::ERANGE;

/// Error messages of libtailscale are short; a longer one is cut and still ends in NUL.
const ERRMSG_LEN: usize = 1024;
/// "<ipv4>,<ipv6>" fits easily.
const IPS_LEN: usize = 256;
/// The loopback address is "127.0.0.1:<port>".
const LOOPBACK_ADDR_LEN: usize = 64;
/// `tailscale_loopback` writes 32 credential bytes and a NUL into each buffer.
const CRED_LEN: usize = 33;
/// libtailscale's own record size for a remote address (`listenAddrLen`).
const REMOTE_ADDR_LEN: usize = 64;

// The archive itself is linked by build.rs (`rustc-link-lib=static=tailscale`).
unsafe extern "C" {
    fn tailscale_new() -> c_int;
    fn tailscale_start(sd: c_int) -> c_int;
    fn tailscale_up(sd: c_int) -> c_int;
    fn tailscale_close(sd: c_int) -> c_int;
    fn tailscale_set_dir(sd: c_int, dir: *const c_char) -> c_int;
    fn tailscale_set_hostname(sd: c_int, hostname: *const c_char) -> c_int;
    fn tailscale_set_authkey(sd: c_int, authkey: *const c_char) -> c_int;
    fn tailscale_set_control_url(sd: c_int, control_url: *const c_char) -> c_int;
    fn tailscale_set_ephemeral(sd: c_int, ephemeral: c_int) -> c_int;
    fn tailscale_set_logfd(sd: c_int, fd: c_int) -> c_int;
    fn tailscale_getips(sd: c_int, buf: *mut c_char, buflen: usize) -> c_int;
    fn tailscale_dial(
        sd: c_int,
        network: *const c_char,
        addr: *const c_char,
        conn_out: *mut c_int,
    ) -> c_int;
    fn tailscale_listen(
        sd: c_int,
        network: *const c_char,
        addr: *const c_char,
        listener_out: *mut c_int,
    ) -> c_int;
    fn tailscale_getremoteaddr(l: c_int, conn: c_int, buf: *mut c_char, buflen: usize) -> c_int;
    fn tailscale_accept(listener: c_int, conn_out: *mut c_int) -> c_int;
    fn tailscale_loopback(
        sd: c_int,
        addr_out: *mut c_char,
        addrlen: usize,
        proxy_cred_out: *mut c_char,
        local_api_cred_out: *mut c_char,
    ) -> c_int;
    fn tailscale_status_json(sd: c_int, json_out: *mut *mut c_char) -> c_int;
    fn tailscale_errmsg(sd: c_int, buf: *mut c_char, buflen: usize) -> c_int;
    // go/apassy.go. cgo declares the parameter as `char*`; Go only reads it.
    fn ApassyTailnetWhoisJSON(sd: c_int, addr: *const c_char, json_out: *mut *mut c_char) -> c_int;
}

/// The string settings of a server; each must be set before the server starts.
#[derive(Clone, Copy, Debug)]
pub enum Setting {
    Dir,
    Hostname,
    AuthKey,
    ControlUrl,
}

const TCP: &CStr = c"tcp";

/// Text up to the first NUL of a buffer that C filled.
fn text(buf: &[u8]) -> String {
    let end = buf.iter().position(|&byte| byte == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

pub fn new() -> Handle {
    // SAFETY: no arguments; returns a new handle.
    unsafe { tailscale_new() }
}

pub fn start(sd: Handle) -> c_int {
    // SAFETY: an integer handle; a stale one gives EBADF.
    unsafe { tailscale_start(sd) }
}

/// Blocks until the node runs or fails. `close` from another thread ends it once the
/// server was started (`start`); before that libtailscale cannot cancel it.
pub fn up(sd: Handle) -> c_int {
    // SAFETY: an integer handle; a stale one gives EBADF.
    unsafe { tailscale_up(sd) }
}

pub fn close(sd: Handle) -> c_int {
    // SAFETY: an integer handle; a stale one gives EBADF. libtailscale removes the
    // handle from its map first, so a second close is EBADF too.
    unsafe { tailscale_close(sd) }
}

pub fn set(sd: Handle, setting: Setting, value: &CStr) -> c_int {
    let value = value.as_ptr();
    // SAFETY: `value` is NUL-terminated and lives for the call; Go copies it.
    unsafe {
        match setting {
            Setting::Dir => tailscale_set_dir(sd, value),
            Setting::Hostname => tailscale_set_hostname(sd, value),
            Setting::AuthKey => tailscale_set_authkey(sd, value),
            Setting::ControlUrl => tailscale_set_control_url(sd, value),
        }
    }
}

pub fn set_ephemeral(sd: Handle, ephemeral: bool) -> c_int {
    // SAFETY: integers only.
    unsafe { tailscale_set_ephemeral(sd, c_int::from(ephemeral)) }
}

/// `None` discards the logs. `Some(fd)` gives the descriptor to Go; on failure it is
/// closed here.
pub fn set_log_fd(sd: Handle, fd: Option<OwnedFd>) -> c_int {
    let Some(fd) = fd else {
        // SAFETY: integers only; -1 means discard.
        return unsafe { tailscale_set_logfd(sd, -1) };
    };
    let raw = fd.into_raw_fd();
    // SAFETY: `raw` is an open descriptor that this process owns; on success Go owns it.
    let rc = unsafe { tailscale_set_logfd(sd, raw) };
    if rc != 0 {
        // SAFETY: Go did not take `raw` (the only failure is EBADF before os.NewFile),
        // so it is still ours, open, and owned by nothing else.
        drop(unsafe { OwnedFd::from_raw_fd(raw) });
    }
    rc
}

/// The last error message of the server (`tailscale_errmsg`).
pub fn errmsg(sd: Handle) -> (c_int, String) {
    let mut buf = [0u8; ERRMSG_LEN];
    // SAFETY: a writable buffer of `buf.len()` bytes; Go writes at most that many and
    // always a NUL. ERANGE means the message was cut.
    let rc = unsafe { tailscale_errmsg(sd, buf.as_mut_ptr().cast(), buf.len()) };
    (rc, text(&buf))
}

/// The tailnet addresses, comma-separated (`tailscale_getips`).
pub fn getips(sd: Handle) -> (c_int, String) {
    let mut buf = [0u8; IPS_LEN];
    // SAFETY: as in `errmsg`.
    let rc = unsafe { tailscale_getips(sd, buf.as_mut_ptr().cast(), buf.len()) };
    (rc, text(&buf))
}

/// `tailscale_listen(sd, "tcp", addr)`: the listener end of the socket pair.
pub fn listen(sd: Handle, addr: &CStr) -> Result<OwnedFd, c_int> {
    let mut out: c_int = -1;
    // SAFETY: NUL-terminated strings that live for the call; `out` is writable.
    let rc = unsafe { tailscale_listen(sd, TCP.as_ptr(), addr.as_ptr(), &mut out) };
    if rc != 0 {
        return Err(rc);
    }
    // SAFETY: on success `out` is the C end of a new socket pair. Go never closes it
    // (it closes its own end, `sp`), so this process owns it from here.
    Ok(unsafe { OwnedFd::from_raw_fd(out) })
}

/// `tailscale_accept`: blocks until a tailnet connection arrives.
pub fn accept(listener: BorrowedFd<'_>) -> Result<OwnedFd, c_int> {
    let mut out: c_int = -1;
    // SAFETY: `listener` is open for the call; `out` is writable.
    let rc = unsafe { tailscale_accept(listener.as_raw_fd(), &mut out) };
    if rc != 0 {
        return Err(rc);
    }
    // SAFETY: on success `out` is the descriptor that recvmsg installed for this
    // process; Go closed its own copy after sendmsg and keeps only the number as a
    // map key. This process owns it from here.
    Ok(unsafe { OwnedFd::from_raw_fd(out) })
}

/// The remote IP of an accepted connection (`tailscale_getremoteaddr`), as
/// libtailscale wrote it: "100.64.0.1" or "[fd7a:115c:a1e0::1]".
pub fn remote_addr(listener: BorrowedFd<'_>, conn: BorrowedFd<'_>) -> (c_int, String) {
    let mut buf = [0u8; REMOTE_ADDR_LEN];
    // SAFETY: open descriptors; a writable buffer of `buf.len()` bytes that Go
    // NUL-terminates.
    let rc = unsafe {
        tailscale_getremoteaddr(
            listener.as_raw_fd(),
            conn.as_raw_fd(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    (rc, text(&buf))
}

/// `tailscale_dial(sd, "tcp", addr)`: the caller's end of the socket pair.
pub fn dial(sd: Handle, addr: &CStr) -> Result<OwnedFd, c_int> {
    let mut out: c_int = -1;
    // SAFETY: as in `listen`.
    let rc = unsafe { tailscale_dial(sd, TCP.as_ptr(), addr.as_ptr(), &mut out) };
    if rc != 0 {
        return Err(rc);
    }
    // SAFETY: on success `out` is the C end of a new socket pair (`newConn`). Go
    // closes only its own end, so this process owns it from here.
    Ok(unsafe { OwnedFd::from_raw_fd(out) })
}

/// Takes a `malloc`'d C string from Go and frees it.
fn take_c_string(ptr: *mut c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: Go's C.CString returns a NUL-terminated string from malloc; it is valid
    // until it is freed below, and nothing else frees it.
    let text = unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: the pointer came from malloc (C.CString) and is freed exactly once.
    unsafe { libc::free(ptr.cast::<c_void>()) };
    text
}

/// The JSON of `ipnstate.Status` over the in-memory LocalAPI (`tailscale_status_json`).
pub fn status_json(sd: Handle) -> Result<String, c_int> {
    let mut out: *mut c_char = ptr::null_mut();
    // SAFETY: `out` is a writable pointer slot; Go sets it to NULL or a malloc'd string.
    let rc = unsafe { tailscale_status_json(sd, &mut out) };
    let json = take_c_string(out);
    if rc != 0 { Err(rc) } else { Ok(json) }
}

/// The JSON of `apitype.WhoIsResponse` for `addr` (`ApassyTailnetWhoisJSON`).
pub fn whois_json(sd: Handle, addr: &CStr) -> Result<String, c_int> {
    let mut out: *mut c_char = ptr::null_mut();
    // SAFETY: `addr` is NUL-terminated and lives for the call; `out` as in `status_json`.
    let rc = unsafe { ApassyTailnetWhoisJSON(sd, addr.as_ptr(), &mut out) };
    let json = take_c_string(out);
    if rc != 0 { Err(rc) } else { Ok(json) }
}

/// `tailscale_loopback`: the address of the loopback LocalAPI and SOCKS5 server, and
/// the LocalAPI credential. The SOCKS5 credential is erased here; nothing uses it.
pub fn loopback(sd: Handle) -> Result<(String, String), c_int> {
    let mut addr = [0u8; LOOPBACK_ADDR_LEN];
    let mut proxy = [0u8; CRED_LEN];
    let mut local = [0u8; CRED_LEN];
    // SAFETY: a writable address buffer of its stated length, and two writable
    // 33-byte buffers, as tailscale.h requires.
    let rc = unsafe {
        tailscale_loopback(
            sd,
            addr.as_mut_ptr().cast(),
            addr.len(),
            proxy.as_mut_ptr().cast(),
            local.as_mut_ptr().cast(),
        )
    };
    let result = if rc == 0 {
        Ok((text(&addr), text(&local)))
    } else {
        Err(rc)
    };
    proxy.zeroize();
    local.zeroize();
    result
}

/// Probes for the spike binary only (feature `spike`): what the Go runtime did to the
/// signal handlers, and how a crash in Rust or in Go ends the process.
#[cfg(feature = "spike")]
pub mod spike {
    use std::ffi::c_int;
    use std::ptr;

    /// How a signal is handled now.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Disposition {
        Default,
        Ignore,
        Handler,
    }

    /// The disposition and the raw `sa_flags` of `signal`, or `None` when
    /// `sigaction` refuses the number.
    pub fn disposition(signal: c_int) -> Option<(Disposition, c_int)> {
        // SAFETY: an all-zero sigaction is a valid value to be overwritten.
        let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: a NULL new action only reads the current one into `old`.
        let rc = unsafe { libc::sigaction(signal, ptr::null(), &mut old) };
        if rc != 0 {
            return None;
        }
        let disposition = if old.sa_sigaction == libc::SIG_DFL {
            Disposition::Default
        } else if old.sa_sigaction == libc::SIG_IGN {
            Disposition::Ignore
        } else {
            Disposition::Handler
        };
        Some((disposition, old.sa_flags))
    }

    /// A write to an unmapped, non-null, aligned address: a real SIGSEGV
    /// (SEGV_MAPERR) in Rust code, not a raised signal. The first 64 KiB are never
    /// mapped on Linux (`vm.mmap_min_addr`), and macOS maps no page below 4 GiB
    /// (`__PAGEZERO`).
    pub fn fault_in_rust() -> ! {
        let address = ptr::without_provenance_mut::<u8>(16);
        // SAFETY: none. This is the deliberate fault of `crash rust-segv`.
        unsafe { address.write_volatile(1) };
        std::process::abort()
    }

    /// A Go panic through the C API: `tailscale_errmsg` with a NULL buffer panics
    /// in Go ("errmsg passed nil buf"). The safe layer never does this.
    pub fn go_panic(sd: c_int) {
        // SAFETY: none. Go checks the NULL before any write and panics.
        unsafe { super::tailscale_errmsg(sd, ptr::null_mut(), 0) };
    }
}
