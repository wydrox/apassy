//! The C interface (contract section 2). The only `unsafe` code of the crate: it reads
//! the C strings of the caller, hands out the core as an opaque pointer, frees the
//! answers, and calls the external HTTP transport of the host (section 2.1).

use std::ffi::{CStr, CString, c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

use apassy::sync::{ExternalAnswer, ExternalRequest, HttpError, HttpTransport};

use crate::core::{Core, HistoryKeyError, HistoryKeyProvider, error_answer};

type HistoryCallback = unsafe extern "C" fn(*mut c_void, *const c_char, bool, *mut u8) -> i32;
type HttpSend = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_char;
type HttpCancel = unsafe extern "C" fn(*mut c_void, u64);

unsafe extern "C" {
    /// The C allocator of the host: it allocates each answer of the transport with
    /// `malloc` or `strdup`.
    fn free(pointer: *mut c_void);
}

/// The external HTTP transport of the host (contract section 2.1): URLSession on the
/// Apple Watch.
struct NativeTransport {
    send: HttpSend,
    cancel: HttpCancel,
    context: *mut c_void,
}

// SAFETY: the contract of `apassy_core_set_http_transport` requires thread-safe callbacks
// and a context that lives as long as the process.
unsafe impl Send for NativeTransport {}
unsafe impl Sync for NativeTransport {}

impl HttpTransport for NativeTransport {
    fn send(&self, request: &ExternalRequest<'_>) -> Result<ExternalAnswer, HttpError> {
        let json = crate::transport::request_json(request).ok_or(HttpError::Protocol)?;
        // SAFETY: `json` is NUL-terminated and lives through this synchronous call; the
        // host does not keep the pointer.
        let answer = unsafe { (self.send)(self.context, json.as_ptr().cast()) };
        drop(json);
        if answer.is_null() {
            return Err(HttpError::Broken);
        }
        // SAFETY: a non-NULL answer is a NUL-terminated string of the host's `malloc`,
        // and the core owns it from here.
        let length = unsafe { CStr::from_ptr(answer) }.to_bytes().len();
        let result = if length > crate::transport::MAX_ANSWER_TEXT {
            Err(HttpError::Protocol)
        } else {
            // SAFETY: `length` bytes before the NUL byte, as just measured.
            let text = unsafe { std::slice::from_raw_parts(answer.cast::<u8>(), length) };
            crate::transport::parse_answer(text, request.pin.is_some())
        };
        // SAFETY: the answer can hold a token: erase its bytes, then free it with the C
        // allocator that made it. Nothing borrows it any more.
        unsafe {
            std::ptr::write_bytes(answer, 0, length);
            free(answer.cast());
        }
        result
    }

    fn cancel(&self, id: u64) {
        // SAFETY: the host's cancel callback is thread-safe and takes only the ID.
        unsafe { (self.cancel)(self.context, id) }
    }
}

/// Install the external HTTP transport of this process (contract section 2.1), before
/// the first `apassy_core_new`. A second call, or a NULL callback, changes nothing.
///
/// # Safety
///
/// `send` and `cancel` are thread-safe and stay valid, with `context`, for the life of
/// the process. `send` returns NULL or a NUL-terminated string from `malloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn apassy_core_set_http_transport(
    send: Option<HttpSend>,
    cancel: Option<HttpCancel>,
    context: *mut c_void,
) {
    let (Some(send), Some(cancel)) = (send, cancel) else {
        return;
    };
    let _ = catch_unwind(AssertUnwindSafe(|| {
        apassy::sync::set_http_transport(Box::new(NativeTransport {
            send,
            cancel,
            context,
        }))
    }));
}

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

    unsafe extern "C" {
        fn strdup(text: *const c_char) -> *mut c_char;
    }

    /// A host transport for the test: it keeps the last request and answers with the
    /// JSON in its context.
    struct Host {
        answer: Option<CString>,
        seen: std::sync::Mutex<Vec<String>>,
        cancelled: std::sync::Mutex<Vec<u64>>,
    }

    unsafe extern "C" fn host_send(context: *mut c_void, request: *const c_char) -> *mut c_char {
        // SAFETY: the test passes a live `Host`, and the core a NUL-terminated request.
        let host = unsafe { &*context.cast::<Host>() };
        let request = unsafe { CStr::from_ptr(request) }
            .to_str()
            .unwrap()
            .to_owned();
        host.seen.lock().unwrap().push(request);
        match &host.answer {
            // SAFETY: a NUL-terminated string; `strdup` allocates with `malloc`.
            Some(answer) => unsafe { strdup(answer.as_ptr()) },
            None => std::ptr::null_mut(),
        }
    }

    unsafe extern "C" fn host_cancel(context: *mut c_void, id: u64) {
        // SAFETY: the test passes a live `Host`.
        let host = unsafe { &*context.cast::<Host>() };
        host.cancelled.lock().unwrap().push(id);
    }

    fn native(host: &Host) -> NativeTransport {
        NativeTransport {
            send: host_send,
            cancel: host_cancel,
            context: std::ptr::from_ref(host).cast_mut().cast(),
        }
    }

    fn request(body: Option<&[u8]>) -> ExternalRequest<'_> {
        ExternalRequest {
            id: 3,
            method: "GET",
            url: "https://relay.example.test/v1/questions?since=0".to_owned(),
            headers: vec![(
                "Authorization",
                Zeroizing::new("Bearer apassy_acc_synthetic".to_owned()),
            )],
            body,
            timeout: std::time::Duration::from_secs(30),
            pin: None,
        }
    }

    /// The native transport sends the request JSON, reads and frees the host's answer,
    /// maps a NULL answer to `Broken`, and passes a cancel on.
    #[test]
    fn the_host_transport_gets_json_and_its_answer_is_freed() {
        let host = Host {
            answer: Some(
                CString::new(r#"{"status":200,"headers":[["ETag","\"1\""]],"body_b64u":"e30"}"#)
                    .unwrap(),
            ),
            seen: std::sync::Mutex::new(Vec::new()),
            cancelled: std::sync::Mutex::new(Vec::new()),
        };
        let transport = native(&host);
        let answer = transport.send(&request(Some(&b"{}"[..]))).unwrap();
        assert_eq!(answer.status, 200);
        assert_eq!(answer.body.as_slice(), b"{}");
        assert_eq!(answer.headers, [("ETag".to_owned(), "\"1\"".to_owned())]);
        let seen: serde_json::Value = serde_json::from_str(&host.seen.lock().unwrap()[0]).unwrap();
        assert_eq!(seen["id"], 3);
        assert_eq!(
            seen["url"],
            "https://relay.example.test/v1/questions?since=0"
        );
        assert_eq!(
            seen["headers"],
            serde_json::json!([["Authorization", "Bearer apassy_acc_synthetic"]])
        );
        assert_eq!(seen["body_b64u"], "e30");
        assert_eq!(seen["timeout_ms"], 30000);
        transport.cancel(9);
        assert_eq!(*host.cancelled.lock().unwrap(), vec![9]);
        let silent = Host {
            answer: None,
            seen: std::sync::Mutex::new(Vec::new()),
            cancelled: std::sync::Mutex::new(Vec::new()),
        };
        assert_eq!(
            native(&silent).send(&request(None)).err(),
            Some(HttpError::Broken)
        );
        let failing = Host {
            answer: Some(CString::new(r#"{"error":"connect"}"#).unwrap()),
            seen: std::sync::Mutex::new(Vec::new()),
            cancelled: std::sync::Mutex::new(Vec::new()),
        };
        assert_eq!(
            native(&failing).send(&request(None)).err(),
            Some(HttpError::Connect)
        );
    }
}
