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
pub fn secret(_field: &str, secret: &str) -> Result<(), CliError> {
    if enabled() {
        Err(CliError::usage(
            "One-time secrets cannot be printed in --json mode.",
        ))
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

/// Last serialization boundary: even reflected metadata/errors cannot echo a
/// recognized Apassy credential. Secret-issuing commands are rejected earlier.
pub fn redact(value: &mut Value) {
    match value {
        Value::String(text) => *text = crate::server::audit::mask_tokens(text),
        Value::Array(values) => values.iter_mut().for_each(redact),
        Value::Object(values) => values.values_mut().for_each(redact),
        _ => {}
    }
}
