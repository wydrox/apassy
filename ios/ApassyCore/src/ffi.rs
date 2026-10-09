//! The C interface (contract section 2). The only `unsafe` code of the crate: it reads
//! the C strings of the caller, hands out the core as an opaque pointer, and frees
//! the answers.

use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};

use zeroize::Zeroize;

use crate::core::{Core, error_answer};

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
    let bytes = std::mem::take(&mut answer).into_bytes();
    match CString::new(bytes) {
        Ok(text) => text.into_raw(),
        Err(error) => {
            let mut bytes = error.into_vec();
            bytes.zeroize();
            CString::new(error_answer("internal", "The answer has a NUL byte."))
                .unwrap_or_default()
                .into_raw()
        }
    }
}
