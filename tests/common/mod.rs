//! Test helpers shared by integration tests.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

/// A fake Jev-compatible bouncer. It answers every question with one probability,
/// except the names in `high`, which get 0.99. It keeps each request body.
pub struct FakeBouncer {
    pub url: String,
    pub bodies: Arc<Mutex<Vec<String>>>,
}

pub fn fake_bouncer(high: &'static [&'static str]) -> FakeBouncer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake bouncer");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&bodies);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; length];
            if reader.read_exact(&mut body).is_err() {
                continue;
            }
            let request: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            seen.lock()
                .expect("bodies")
                .push(String::from_utf8_lossy(&body).into_owned());
            let mut answers = serde_json::Map::new();
            if let Some(questions) = request["questions"].as_object() {
                for name in questions.keys() {
                    let p = if high.contains(&name.as_str()) {
                        0.99
                    } else {
                        0.01
                    };
                    answers.insert(name.clone(), serde_json::json!({"type": "noul", "noul": p}));
                }
            }
            let out = serde_json::json!({"answers": answers, "usage": {"input_tokens": 1, "output_tokens": 0}}).to_string();
            let mut stream = stream;
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{out}",
                out.len()
            );
        }
    });
    FakeBouncer { url, bodies }
}
