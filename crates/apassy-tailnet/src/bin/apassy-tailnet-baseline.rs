//! The size baseline of the spike (docs/design/spike-tsnet.md, "Sizes"): Rust std,
//! serde_json, and a TCP echo on loopback, without the Go archive. Build it without
//! features; the difference to `apassy-tailnet-spike` is the cost of the archive.

use std::io::{Read, Write};
use std::net::TcpListener;

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    println!(
        "{}",
        serde_json::json!({ "event": "baseline", "addr": addr.to_string() })
    );
    if std::env::args().any(|arg| arg == "--serve-one") {
        let (mut stream, _) = listener.accept()?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf)?;
        stream.write_all(&buf)?;
    }
    Ok(())
}
