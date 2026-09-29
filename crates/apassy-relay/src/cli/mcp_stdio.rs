//! `apassy-team mcp`: newline-delimited JSON-RPC on stdin and stdout, each message forwarded to POST /mcp.
//!
//! Each line is posted as is with the agent token. A JSON body from the relay is written
//! back as one line. A 202 writes nothing. A failure becomes a JSON-RPC error with the
//! request id (for a request only). Logs go to stderr and hold no token and no body.

use std::io::{BufRead, Write};

use serde_json::{Value, json};

use crate::api::paths;
use crate::cli::CliError;
use crate::cli::client::{CALL_TIMEOUT, Client, Method};
use crate::cli::settings::Settings;

/// The longest input line, in bytes.
pub const MAX_LINE: usize = 1024 * 1024;

const ACCEPT: &str = "application/json, text/event-stream";

pub fn run(settings: &Settings) -> Result<i32, CliError> {
    let client = Client::new(
        settings.relay()?,
        Some(settings.agent()?),
        settings.edge_secret.as_ref(),
    );
    eprintln!(
        "apassy-team mcp: forwarding to {}{}",
        client.base(),
        paths::MCP
    );
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    serve(&client, stdin.lock(), stdout.lock())
}

/// The loop, over any reader and writer.
pub fn serve(
    client: &Client,
    mut input: impl BufRead,
    mut output: impl Write,
) -> Result<i32, CliError> {
    loop {
        let line = match read_line(&mut input, MAX_LINE) {
            Ok(Line::Eof) => return Ok(0),
            Ok(line) => line,
            Err(e) => {
                return Err(CliError::usage(format!("Cannot read stdin: {}.", e.kind())));
            }
        };
        let reply = match line {
            Line::Eof => return Ok(0),
            Line::TooLong => {
                eprintln!("apassy-team mcp: a line is longer than 1 MiB and was refused");
                Some(rpc_error(
                    &Value::Null,
                    -32600,
                    "The message is longer than 1 MiB.",
                ))
            }
            Line::Text(text) if text.trim().is_empty() => None,
            Line::Text(text) => handle(client, &text),
        };
        if let Some(reply) = reply {
            let written = writeln!(output, "{reply}").and_then(|_| output.flush());
            if written.is_err() {
                // The reader of stdout is gone.
                return Ok(0);
            }
        }
    }
}

enum Line {
    Text(String),
    TooLong,
    Eof,
}

/// Reads one line of at most `max` bytes. A longer line is skipped to its end.
fn read_line(input: &mut impl BufRead, max: usize) -> std::io::Result<Line> {
    let mut buf: Vec<u8> = Vec::new();
    let mut too_long = false;
    let mut seen_any = false;
    loop {
        let chunk = input.fill_buf()?;
        if chunk.is_empty() {
            return Ok(if !seen_any {
                Line::Eof
            } else if too_long {
                Line::TooLong
            } else {
                Line::Text(String::from_utf8_lossy(&buf).into_owned())
            });
        }
        seen_any = true;
        let (piece, found) = match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => (&chunk[..i], true),
            None => (chunk, false),
        };
        if !too_long {
            if buf.len() + piece.len() > max {
                too_long = true;
                buf.clear();
            } else {
                buf.extend_from_slice(piece);
            }
        }
        let used = piece.len() + usize::from(found);
        input.consume(used);
        if found {
            return Ok(if too_long {
                Line::TooLong
            } else {
                Line::Text(String::from_utf8_lossy(&buf).into_owned())
            });
        }
    }
}

/// Forwards one message. `None` means: write nothing.
pub fn handle(client: &Client, text: &str) -> Option<String> {
    let parsed: Option<Value> = serde_json::from_str(text).ok();
    // A request has a method and an id. A notification has no id.
    let id = parsed
        .as_ref()
        .and_then(|v| v.as_object())
        .filter(|o| o.contains_key("method"))
        .and_then(|o| o.get("id"))
        .cloned();

    let fail = |code: &str, message: &str| -> Option<String> {
        eprintln!("apassy-team mcp: relay call failed: {code}");
        id.as_ref()
            .map(|id| rpc_error(id, -32000, &format!("relay: {code}: {message}")))
    };

    let reply = match client.raw(
        Method::Post,
        paths::MCP,
        Some(text),
        Some(ACCEPT),
        CALL_TIMEOUT,
    ) {
        Ok(reply) => reply,
        Err(message) => return fail("unreachable", &message),
    };
    if reply.status == 202 || reply.body.trim().is_empty() && reply.status < 300 {
        return None;
    }
    match serde_json::from_str::<Value>(&reply.body) {
        Ok(value) if value.get("jsonrpc").is_some() => Some(value.to_string()),
        Ok(value) if value.get("ok") == Some(&Value::Bool(false)) => {
            let code = value["error"]["code"].as_str().unwrap_or("relay_error");
            let message = value["error"]["message"]
                .as_str()
                .unwrap_or("The relay refused the call.");
            fail(code, message)
        }
        _ => fail(
            &format!("http_{}", reply.status),
            "The relay sent an answer that is not JSON-RPC. Is this the relay URL?",
        ),
    }
}

fn rpc_error(id: &Value, code: i32, message: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn lines(input: &[u8], max: usize) -> Vec<String> {
        let mut cursor = Cursor::new(input.to_vec());
        let mut out = Vec::new();
        loop {
            match read_line(&mut cursor, max).unwrap() {
                Line::Eof => return out,
                Line::TooLong => out.push("<long>".into()),
                Line::Text(t) => out.push(t),
            }
        }
    }

    #[test]
    fn lines_split_and_long_lines_are_skipped() {
        assert_eq!(lines(b"a\nbb\n\nlast", 10), vec!["a", "bb", "", "last"]);
        assert_eq!(lines(b"0123456789AB\nok\n", 10), vec!["<long>", "ok"]);
        assert_eq!(lines(b"0123456789\n", 10), vec!["0123456789"]);
        assert_eq!(lines(b"", 10), Vec::<String>::new());
    }

    #[test]
    fn rpc_error_carries_the_id() {
        let text = rpc_error(&json!(7), -32000, "relay: x: y");
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            (v["id"].clone(), v["error"]["code"].clone()),
            (json!(7), json!(-32000))
        );
    }
}
