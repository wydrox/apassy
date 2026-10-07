//! The core: one per process. Placeholder until the calls are written.

use serde_json::json;

/// The vault core of one process (the app or the AutoFill extension).
pub struct Core {}

impl Core {
    pub fn new(_config: &str) -> Result<Self, String> {
        Ok(Self {})
    }

    pub fn call(&self, _request: &str) -> String {
        error_answer("internal", "This call is not built yet.")
    }

    pub fn shutdown(&self) {}
}

/// An error answer (contract section 4).
pub fn error_answer(code: &str, message: &str) -> String {
    json!({"ok": false, "error": {"code": code, "message": message}}).to_string()
}
