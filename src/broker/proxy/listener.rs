//! The listener of a local run (ADR 0011): 127.0.0.1 with a password for the run.
//!
//! It serves only the run, and it stops when the run ends. A same-user process
//! that reads the environment of the run (F11) can send requests through it while
//! the run lasts. It gets what the swap rules allow, each request is logged, and it
//! never gets a value.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use zeroize::Zeroizing;

use super::ca::Alpn;
use super::engine::{Auth, CoreOptions, ProxyCore, UpstreamPolicy};
use super::network::{RunNetwork, network_for};
use super::{ProxyEvent, ProxyOptions, ProxySecret};
use crate::broker::access_once::Admission;

fn random_hex(bytes: usize) -> io::Result<String> {
    let mut raw = vec![0u8; bytes];
    getrandom::fill(&mut raw).map_err(|_| io::Error::other("no random source"))?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

/// A running proxy. [`RunProxy::finish`] stops it and returns the request log.
pub struct RunProxy {
    core: Arc<ProxyCore>,
    network: RunNetwork,
    addr: SocketAddr,
    accept: Option<JoinHandle<()>>,
}

impl RunProxy {
    pub fn start(secrets: Vec<ProxySecret>, options: ProxyOptions) -> io::Result<Self> {
        Self::start_with_access(secrets, options, None, false)
    }

    pub(crate) fn start_with_access(
        secrets: Vec<ProxySecret>,
        options: ProxyOptions,
        access: Option<Admission>,
        omit_event_details: bool,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr = listener.local_addr()?;
        let core = ProxyCore::with_access(
            secrets,
            CoreOptions {
                tls: options.tls,
                other_hosts: options.other_hosts,
                upstream: UpstreamPolicy::Any,
                sink: None,
                alpn: Alpn::Http11,
            },
            access,
            omit_event_details,
        )?;
        let token = Zeroizing::new(random_hex(16)?);
        let proxy_url = Zeroizing::new(format!(
            "http://apassy:{}@127.0.0.1:{}",
            token.as_str(),
            addr.port()
        ));
        let network = network_for(core.ca_pem(), &proxy_url, addr.port(), options.enforce)?;
        let accept_core = Arc::clone(&core);
        let accept = thread::Builder::new()
            .name("apassy-run-proxy".to_owned())
            .spawn(move || accept_loop(&listener, &accept_core, &token))?;
        Ok(Self {
            core,
            network,
            addr,
            accept: Some(accept),
        })
    }

    pub fn network(&self) -> &RunNetwork {
        &self.network
    }

    /// Stop the proxy, close each connection, and return the request log.
    pub fn finish(mut self) -> Vec<ProxyEvent> {
        self.stop();
        self.core.events()
    }

    fn stop(&mut self) {
        let Some(accept) = self.accept.take() else {
            return;
        };
        // The engine refuses every connection from now on, also one that the
        // accept loop takes before it sees the stop.
        self.core.close_all();
        // Wake the accept loop.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_secs(1));
        let _ = accept.join();
        // A connection that started while the loop stopped.
        self.core.close_all();
    }
}

impl Drop for RunProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(listener: &TcpListener, core: &Arc<ProxyCore>, password: &Zeroizing<String>) {
    for stream in listener.incoming() {
        if core.is_closed() {
            break;
        }
        let Ok(stream) = stream else {
            continue;
        };
        let core = Arc::clone(core);
        let auth = Auth::Password(password.clone());
        let _ = thread::Builder::new()
            .name("apassy-run-proxy-conn".to_owned())
            .spawn(move || core.serve_connection(stream, Vec::new(), auth));
    }
}
