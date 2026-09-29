//! The relay server with a mock HTTPS upstream, for `scripts/e2e.sh` only.
//!
//! It runs the same server code as `apassy-relay serve`, with the same configuration
//! from the environment. The one difference: the proxy trusts the test certificate
//! authority of the mock and sends the upstream hosts to the mock on 127.0.0.1. The
//! release binary has no switch for that on purpose, so a deployed relay cannot be
//! told to trust another root.
//!
//! Variables on top of the relay's own:
//! - `E2E_UPSTREAM_HOSTS`: comma-separated hosts of the mock (default
//!   `api.stripe.com,api.github.com`).
//! - `E2E_UPSTREAM_LOG`: a file. Each request the mock gets adds one line:
//!   `<host> <method> <target> authorization=<Authorization header>`. The values are
//!   synthetic; the log shows what the upstream saw.
#![forbid(unsafe_code)]

#[path = "../tests/common/upstream.rs"]
mod upstream;

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use apassy_relay::config::RelayConfig;
use apassy_relay::server::Relay;

fn main() -> ExitCode {
    let hosts = std::env::var("E2E_UPSTREAM_HOSTS")
        .unwrap_or_else(|_| "api.stripe.com,api.github.com".to_string());
    let hosts: Vec<&str> = hosts.split(',').filter(|h| !h.is_empty()).collect();
    let mock = upstream::start(&hosts);

    let mut config = match RelayConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("e2e_relay: {}", error.message);
            return ExitCode::from(1);
        }
    };
    config.upstream = mock.options();
    let running = match Relay::start(config) {
        Ok(running) => running,
        Err(error) => {
            eprintln!("e2e_relay: {}", error.message);
            return ExitCode::from(1);
        }
    };
    eprintln!(
        "e2e_relay: listening on {}, mock upstream for {} on {}",
        running.addr,
        hosts.join(", "),
        mock.addr
    );

    if let Ok(path) = std::env::var("E2E_UPSTREAM_LOG") {
        std::thread::spawn(move || {
            let mut written = 0;
            loop {
                let seen = mock.requests();
                if seen.len() > written {
                    let Ok(mut file) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)
                    else {
                        return;
                    };
                    for request in &seen[written..] {
                        let _ = writeln!(
                            file,
                            "{} {} {} authorization={}",
                            request.header("host").unwrap_or("-"),
                            request.method,
                            request.target,
                            request.header("authorization").unwrap_or("-")
                        );
                    }
                    written = seen.len();
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
    }
    running.wait();
    ExitCode::SUCCESS
}
