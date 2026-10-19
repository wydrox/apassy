//! The C interface (contract section 2). The only `unsafe` code of the crate: it reads
//! the C strings of the caller, hands out the core as an opaque pointer, and frees
//! the answers.

use std::ffi::{CStr, CString, c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

use crate::core::{Core, HistoryKeyError, HistoryKeyProvider, error_answer};

type HistoryCallback = unsafe extern "C" fn(*mut c_void, *const c_char, bool, *mut u8) -> i32;

struct NativeHistoryProvider {
    callback: HistoryCallback,
    context: *mut c_void,
}

// SAFETY: the constructor contract requires a thread-safe callback and context that
// outlive this core. Rust calls never retain the output pointer or the vault-ID string.
unsafe impl Send for NativeHistoryProvider {}
unsafe impl Sync for NativeHistoryProvider {}

impl HistoryKeyProvider for NativeHistoryProvider {
    fn key(
        &self,
        vault_id: &str,
        may_create: bool,
    ) -> Result<Zeroizing<[u8; 32]>, HistoryKeyError> {
        let vault_id = CString::new(vault_id).map_err(|_| HistoryKeyError::Unavailable)?;
        let mut key = Zeroizing::new([0u8; 32]);
        // SAFETY: all buffers live through this synchronous call, and the native
        // provider contract limits its write to these 32 bytes.
        match unsafe {
            (self.callback)(
                self.context,
                vault_id.as_ptr(),
                may_create,
                key.as_mut_ptr(),
            )
        } {
            0 => Ok(key),
            1 => Err(HistoryKeyError::Missing),
            _ => Err(HistoryKeyError::Unavailable),
        }
    }
}

/// Start a core with a device-local history key provider, never a key in JSON.
///
/// # Safety
/// `config` is NUL-terminated; callback and context stay valid until core_free returns.
/// The callback is thread-safe and writes exactly 32 bytes only on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn apassy_core_new_with_history_key_provider(
    config: *const c_char,
    provider: Option<HistoryCallback>,
    context: *mut c_void,
) -> *mut Core {
    let Some(callback) = provider else {
        return std::ptr::null_mut();
    };
    if config.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller supplied a live NUL-terminated config.
    let Ok(config) = unsafe { CStr::from_ptr(config) }.to_str() else {
        return std::ptr::null_mut();
    };
    let provider = Arc::new(NativeHistoryProvider { callback, context });
    match catch_unwind(AssertUnwindSafe(|| {
        Core::new_with_history_key_provider(config, provider)
    })) {
        Ok(Ok(core)) => Box::into_raw(Box::new(core)),
        _ => std::ptr::null_mut(),
    }
}

/// Start a core from a JSON config. NULL when the config is not valid.
///
/// # Safety
///
/// `config` is a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn apassy_core_new(config: *const c_char) -> *mut Core {
    if config.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller passes a valid NUL-terminated string.
    let config = unsafe { CStr::from_ptr(config) };
    let Ok(config) = config.to_str() else {
        return std::ptr::null_mut();
    };
    match catch_unwind(|| Core::new(config)) {
        Ok(Ok(core)) => Box::into_raw(Box::new(core)),
        _ => std::ptr::null_mut(),
    }
}

/// One call. The answer is never NULL; free it with [`apassy_core_free_string`].
///
/// # Safety
///
/// `core` comes from [`apassy_core_new`] and is not freed; `request` is a valid
/// NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn apassy_core_call(
    core: *const Core,
    request: *const c_char,
) -> *mut c_char {
    let answer = if core.is_null() || request.is_null() {
        error_answer("internal", "The core is not started.")
    } else {
        // SAFETY: the caller passes a live core and a valid NUL-terminated string.
        let (core, request) = unsafe { (&*core, CStr::from_ptr(request)) };
        match request.to_str() {
            Ok(request) => {
                catch_unwind(AssertUnwindSafe(|| core.call(request))).unwrap_or_else(|_| {
                    error_answer(
                        "internal",
                        "The vault core failed. This is a bug in Apassy.",
                    )
                })
            }
            Err(_) => error_answer("invalid_input", "The request is not UTF-8."),
        }
    };
    into_c(answer)
}

/// Erase an answer and free it.
///
/// # Safety
///
/// `answer` comes from [`apassy_core_call`] and is freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn apassy_core_free_string(answer: *mut c_char) {
    if answer.is_null() {
        return;
    }
    // SAFETY: the pointer came from `CString::into_raw` in `into_c`.
    let answer = unsafe { CString::from_raw(answer) };
    let mut bytes = answer.into_bytes();
    bytes.zeroize();
}

/// Lock the vault, drop the relay session, and free the core.
///
/// # Safety
///
/// `core` comes from [`apassy_core_new`] and is freed once, after every call ended.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn apassy_core_free(core: *mut Core) {
    if core.is_null() {
        return;
    }
    // SAFETY: the pointer came from `Box::into_raw` in `apassy_core_new`.
    let core = unsafe { Box::from_raw(core) };
    let _ = catch_unwind(AssertUnwindSafe(move || {
        core.shutdown();
        drop(core);
    }));
}

/// The answer as a C string. JSON from `serde_json` has no NUL byte; one in a value
/// would be escaped as `\u0000`.
fn into_c(mut answer: String) -> *mut c_char {
    let mut bytes = std::mem::take(&mut answer).into_bytes();
    // Normal answers reserve this byte before any secret is serialized. For
    // another caller's String, copy once and erase the old allocation before
    // its release. Exact capacity also avoids CString's boxed-slice shrink.
    if bytes.capacity() != bytes.len() + 1 {
        let mut exact = Vec::with_capacity(bytes.len() + 1);
        exact.extend_from_slice(&bytes);
        bytes.zeroize();
        bytes = exact;
    }
    bytes.push(0);
    match CString::from_vec_with_nul(bytes) {
        Ok(text) => text.into_raw(),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            CString::new(error_answer("internal", "The answer has a NUL byte."))
                .unwrap_or_default()
                .into_raw()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_answer_moves_to_c_without_a_copy() {
        let mut answer = String::with_capacity(3);
        answer.push_str("{}");
        let pointer = answer.as_ptr();
        let c = into_c(answer);
        assert_eq!(c.cast::<u8>().cast_const(), pointer);
        // SAFETY: into_c returned this owned, terminated string.
        assert_eq!(unsafe { CStr::from_ptr(c) }.to_bytes(), b"{}");
        unsafe { apassy_core_free_string(c) };
    }

    #[test]
    fn unexpected_nul_returns_a_safe_error() {
        let c = into_c("synthetic\0value".to_owned());
        let text = unsafe { CStr::from_ptr(c) }.to_str().unwrap();
        assert!(text.contains("internal"));
        assert!(!text.contains("synthetic"));
        unsafe { apassy_core_free_string(c) };
    }
}
