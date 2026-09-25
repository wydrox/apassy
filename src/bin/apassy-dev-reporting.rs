//! Synthetic reporting API for local tests and demos (candidate A, P0).
//!
//! This is not a real service. It listens on 127.0.0.1 only. It accepts one
//! synthetic bearer token from `APASSY_DEV_REPORTING_TOKEN`. It never prints
//! the token. The response has one extra field that the broker must drop.
//!
//! Usage: `APASSY_DEV_REPORTING_TOKEN=FAKE-... apassy-dev-reporting [PORT]`
//! With port 0 or no port, the system selects a free port.
//! The first stdout line is `listening on 127.0.0.1:PORT`.

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

const TOKEN_ENV: &str = "APASSY_DEV_REPORTING_TOKEN";
/// A project ID that makes the service echo the presented token in a permitted field.
/// The broker must block that output. Tests use it.
const ECHO_CANARY_PROJECT: &str = "echo-token-canary";

fn main() {
    let Some(token) = std::env::var(TOKEN_ENV)
        .ok()
        .filter(|token| !token.trim().is_empty())
    else {
        eprintln!("apassy-dev-reporting: set {TOKEN_ENV} to a synthetic token.");
        std::process::exit(2);
    };
    let port: u16 = match std::env::args().nth(1) {
        Some(arg) => match arg.parse() {
            Ok(port) => port,
            Err(_) => {
                eprintln!("apassy-dev-reporting: the port must be a number.");
                std::process::exit(2);
            }
        },
        None => 0,
    };
    let listener = match TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("apassy-dev-reporting: cannot listen: {err}");
            std::process::exit(1);
        }
    };
    let Ok(addr) = listener.local_addr() else {
        std::process::exit(1);
    };
    println!("listening on {addr}");
    let _ = std::io::stdout().flush();
    eprintln!("apassy-dev-reporting: SYNTHETIC service. Do not use real credentials.");
    for stream in listener.incoming().flatten() {
        let _ = serve(stream, &token);
    }
}

fn serve(stream: TcpStream, token: &str) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut authorization = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("authorization")
        {
            authorization = Some(value.trim().to_owned());
        }
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let expected = format!("Bearer {token}");
    let (status, body) = if method != "GET" {
        (405, r#"{"error":"method not allowed"}"#.to_owned())
    } else if authorization.as_deref() != Some(expected.as_str()) {
        (401, r#"{"error":"unauthorized"}"#.to_owned())
    } else {
        route(target, token)
    };
    eprintln!(
        "apassy-dev-reporting: {method} {} -> {status}",
        redact_query(target)
    );
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Error",
    };
    write!(
        writer,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    writer.flush()
}

fn route(target: &str, token: &str) -> (u16, String) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match segments.as_slice() {
        ["v1", "projects", project, "sales-summary"] => {
            let start = query_value(query, "period_start");
            let end = query_value(query, "period_end");
            let currency = if *project == ECHO_CANARY_PROJECT {
                token.to_owned()
            } else {
                "EUR".to_owned()
            };
            let body = serde_json::json!({
                "project_id": project,
                "period_start": start,
                "period_end": end,
                "currency": currency,
                "total_amount": "12840.50",
                "order_count": 318,
                "internal_debug_note": "synthetic field that the broker must drop",
            });
            (200, body.to_string())
        }
        ["v1", "report-jobs", job_id] => {
            if job_id.starts_with("missing") {
                return (404, r#"{"error":"not found"}"#.to_owned());
            }
            let body = serde_json::json!({
                "job_id": job_id,
                "state": "completed",
                "completed_at": "2026-09-25T10:00:00Z",
                "raw_log": "synthetic log that the broker must drop",
            });
            (200, body.to_string())
        }
        _ => (404, r#"{"error":"not found"}"#.to_owned()),
    }
}

fn query_value<'a>(query: &'a str, name: &str) -> &'a str {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map_or("", |(_, value)| value)
}

fn redact_query(target: &str) -> &str {
    target.split_once('?').map_or(target, |(path, _)| path)
}
