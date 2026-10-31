//! One opt-in JSON result per finite CLI invocation. Human progress is stderr.
use super::CliError;
use serde::Serialize;
use serde_json::Value;
use std::cell::RefCell;
use std::fmt::Arguments;

#[derive(Default)]
struct State {
    enabled: bool,
    result: Option<Value>,
}
thread_local! { static STATE: RefCell<State> = RefCell::default(); }

pub fn begin(enabled: bool) {
    STATE.with(|state| {
        *state.borrow_mut() = State {
            enabled,
            result: None,
        }
    });
}
pub fn enabled() -> bool {
    STATE.with(|state| state.borrow().enabled)
}
pub fn line(args: Arguments<'_>) {
    if enabled() {
        eprintln!("{args}");
    } else {
        std::println!("{args}");
    }
}
pub fn text(args: Arguments<'_>) {
    if enabled() {
        eprint!("{args}");
    } else {
        std::print!("{args}");
    }
}
pub fn result(value: &impl Serialize) -> Result<(), CliError> {
    if enabled() {
        let value = serde_json::to_value(value)
            .map_err(|_| CliError::relay("Cannot encode the answer."))?;
        STATE.with(|state| state.borrow_mut().result = Some(value));
    }
    Ok(())
}
pub fn secret(field: &str, secret: &str) -> Result<(), CliError> {
    if enabled() {
        result(&serde_json::json!({field:secret}))
    } else {
        std::println!("{secret}");
        Ok(())
    }
}
pub fn finish() -> Value {
    STATE.with(|state| {
        state
            .borrow_mut()
            .result
            .take()
            .unwrap_or_else(|| serde_json::json!({}))
    })
}
