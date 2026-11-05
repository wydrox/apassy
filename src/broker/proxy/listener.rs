//! The listener of a local run (ADR 0011): 127.0.0.1 with a password for the run.
//!
//! It serves only the run, and it stops when the run ends. A same-user process
//! that reads the environment of the run (F11) can send requests through it while
//! the run lasts. It gets what the swap rules allow, each request is logged, and it
//! never gets a value.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use zeroize::Zeroizing;

use super::ca::Alpn;
use super::engine::{Auth, CoreOptions, ProxyCore, UpstreamPolicy};
use super::network::{RunNetwork, network_for};
use super::{ProxyEvent, ProxyOptions, ProxySecret};
use crate::broker::access_once::Admission;

/// At most this many connections at once, as the bridge of the Linux sandbox. A
/// connection above it is closed at once (judge finding L4).
const MAX_CONNECTIONS: usize = 256;

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
    /// The open connections, for the limit. The accept loop counts them; the tests
    /// fill it.
    #[cfg_attr(not(test), allow(dead_code))]
    active: Arc<AtomicUsize>,
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
        let active = Arc::new(AtomicUsize::new(0));
        let accept_active = Arc::clone(&active);
        let accept = thread::Builder::new()
            .name("apassy-run-proxy".to_owned())
            .spawn(move || accept_loop(&listener, &accept_core, &token, &accept_active))?;
        Ok(Self {
            core,
            network,
            addr,
            accept: Some(accept),
            active,
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

fn accept_loop(
    listener: &TcpListener,
    core: &Arc<ProxyCore>,
    password: &Zeroizing<String>,
    active: &Arc<AtomicUsize>,
) {
    for stream in listener.incoming() {
        if core.is_closed() {
            break;
        }
        let Ok(stream) = stream else {
            // For example no free file descriptor. Do not spin.
            thread::sleep(Duration::from_millis(50));
            continue;
        };
        // A full listener closes the new connection (the drop).
        let Some(slot) = Slot::take(active) else {
            continue;
        };
        let core = Arc::clone(core);
        let auth = Auth::Password(password.clone());
        let _ = thread::Builder::new()
            .name("apassy-run-proxy-conn".to_owned())
            .spawn(move || {
                let _slot = slot;
                core.serve_connection(stream, Vec::new(), auth);
            });
    }
}

/// One counted connection. Dropping it frees the place.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(active: &Arc<AtomicUsize>) -> Option<Slot> {
        let previous = active.fetch_add(1, Ordering::AcqRel);
        if previous >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Slot(Arc::clone(active)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::time::Instant;

    use super::*;
    use crate::broker::http::TlsClient;
    use crate::broker::proxy::OtherHosts;

    fn proxy() -> RunProxy {
        RunProxy::start(
            Vec::new(),
            ProxyOptions {
                tls: TlsClient::platform().expect("TLS"),
                other_hosts: OtherHosts::Refuse,
                enforce: false,
            },
        )
        .expect("proxy")
    }

    fn connect_client(addr: SocketAddr, read_timeout: Duration) -> TcpStream {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .expect("socket");
        // On macOS a peer reset can make a later timeout setter return EINVAL.
        socket.set_read_timeout(Some(read_timeout)).expect("timeout");
        socket.connect(&addr.into()).expect("connect");
        socket.into()
    }

    /// True when the proxy closes `stream` without an answer; false on an answer
    /// or when its preconfigured read timeout expires.
    fn closed_without_answer(stream: &mut TcpStream) -> bool {
        let mut buf = [0u8; 64];
        match stream.read(&mut buf) {
            Ok(read) => read == 0,
            Err(err) => !matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
        }
    }

    /// Judge finding L4: a full listener closes new connections.
    #[test]
    fn a_full_listener_closes_new_connections() {
        let proxy = proxy();
        let slots: Vec<Slot> = (0..MAX_CONNECTIONS)
            .map(|_| Slot::take(&proxy.active).expect("a free place"))
            .collect();
        assert!(Slot::take(&proxy.active).is_none());
        let mut stream = connect_client(proxy.addr, Duration::from_secs(15));
        let _ = stream.write_all(b"CONNECT a.example:443 HTTP/1.1\r\n\r\n");
        assert!(
            closed_without_answer(&mut stream),
            "the connection is closed"
        );
        drop(slots);
        assert_eq!(proxy.active.load(Ordering::SeqCst), 0);
        // With a free place, the proxy answers (here: the password is missing).
        let mut stream = connect_client(proxy.addr, Duration::from_secs(10));
        stream
            .write_all(b"CONNECT a.example:443 HTTP/1.1\r\n\r\n")
            .expect("write");
        let mut answer = [0u8; 12];
        stream.read_exact(&mut answer).expect("answer");
        assert_eq!(&answer, b"HTTP/1.1 407");
    }

    /// Judge finding L4: a client that sends no whole request head in 10 s is
    /// closed, also when it sends a byte now and then.
    #[test]
    fn a_slow_first_request_head_is_closed_after_the_deadline() {
        let proxy = proxy();
        let mut stream = connect_client(proxy.addr, Duration::from_secs(15));
        let started = Instant::now();
        let mut closed = false;
        for byte in b"CONNECT a.example:443 HTTP/1.1\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaa" {
            if stream.write_all(&[*byte]).is_err() {
                closed = true;
                break;
            }
            thread::sleep(Duration::from_millis(500));
            if started.elapsed() > Duration::from_secs(14) {
                break;
            }
        }
        if !closed {
            closed = closed_without_answer(&mut stream);
        }
        assert!(closed, "the slow client is closed");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_secs(9) && elapsed < Duration::from_secs(25),
            "{elapsed:?}"
        );
    }
}
