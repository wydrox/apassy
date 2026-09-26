//! Export the deterministic command analysis for the base-model generator (goal B8).
//!
//! `tools/basemodel/gen_data.py` writes one JSON object per line to stdin:
//! `{"id": "...", "line": "shell line", "purpose": "...", "secrets": ["NAME", ...]}`.
//! This program writes one JSON object per line to stdout:
//! `{"id": "...", "argv": [...], "command": "argv joined", "flags": [...], "known_safe": bool}`.
//!
//! `command` is the text that the broker puts in the bouncer state
//! (`request.command.join(" ")` in `src/broker/run.rs`). The generator uses it, so the
//! training state is the same string that the broker sends.
//!
//! Run: `cargo run --locked --features vault --example basemodel_labels < in.jsonl > out.jsonl`

#![forbid(unsafe_code)]

use std::io::{BufRead, BufWriter, Write};

use serde_json::{Value, json};

use apassy::broker::shell_risk::{analyze, command_line_to_argv};

fn main() {
    let stdin = std::io::stdin();
    let mut out = BufWriter::new(std::io::stdout().lock());
    for (number, line) in stdin.lock().lines().enumerate() {
        let line = line.expect("read stdin");
        if line.trim().is_empty() {
            continue;
        }
        let input: Value = serde_json::from_str(&line)
            .unwrap_or_else(|error| panic!("line {}: bad JSON: {error}", number + 1));
        let text = |key: &str| input[key].as_str().unwrap_or_default().to_owned();
        let secrets: Vec<String> = input["secrets"]
            .as_array()
            .map(|names| {
                names
                    .iter()
                    .filter_map(|name| name.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let argv = command_line_to_argv(&text("line"));
        let analysis = analyze(&argv, &text("purpose"), &secrets);
        let row = json!({
            "id": input["id"],
            "command": argv.join(" "),
            "argv": argv,
            "flags": analysis.flags,
            "known_safe": analysis.known_safe,
        });
        writeln!(out, "{row}").expect("write stdout");
    }
    out.flush().expect("flush stdout");
}
