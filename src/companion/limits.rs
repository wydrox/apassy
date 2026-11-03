//! The limits of the companion listener (contract companion-v1, sections 3 and 6): the
//! connections, the rate of requests, and the nonces of signed requests.
//!
//! The connection slots and the rate limiter are shared with the TLS front of the node
//! (`crate::net::limits`, unit N2). The numbers of the contract stay here. The nonce
//! cache is the companion's own.
//!
//! Every function that depends on time takes the time as an argument, so the tests do
//! not need to sleep. The maps have a size limit, so a peer cannot grow them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

pub use crate::net::limits::RateLimiter;

use super::wire::NONCE_BYTES;

/// At most this many connections at the same time.
pub const MAX_CONNECTIONS: usize = 16;
/// At most this many connections from one IP address.
pub const MAX_CONNECTIONS_PER_IP: usize = 4;
/// Answers to requests without a valid signature, per IP address and minute.
pub const UNSIGNED_PER_MINUTE: usize = 30;
/// Requests of one paired device per minute.
pub const DEVICE_PER_MINUTE: usize = 120;
/// How long a nonce is kept.
pub const NONCE_KEEP: Duration = Duration::from_secs(300);

/// A device has at most this many nonces in the cache. At 120 requests per minute it
/// never reaches this.
const MAX_NONCES_PER_DEVICE: usize = 4096;

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The open connections of the companion: [`MAX_CONNECTIONS`] in total and
/// [`MAX_CONNECTIONS_PER_IP`] from one address.
pub type Connections = crate::net::limits::Connections;

/// The connection slots with the limits of the contract.
pub fn companion_connections() -> Arc<Connections> {
    Connections::new(MAX_CONNECTIONS, MAX_CONNECTIONS_PER_IP)
}

/// The nonces of signed requests, per device. A nonce is kept for 5 minutes, longer
/// than the 60 s in which the time of a request is valid on both sides.
#[derive(Debug, Default)]
pub struct NonceCache {
    devices: Mutex<HashMap<String, HashMap<[u8; NONCE_BYTES], Instant>>>,
}

impl NonceCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn fresh(at: Instant, now: Instant) -> bool {
        now.saturating_duration_since(at) < NONCE_KEEP
    }

    /// True when this device used this nonce in the last 5 minutes. It records nothing:
    /// a request that fails its signature must not use up a nonce.
    pub fn seen_at(&self, device_id: &str, nonce: &[u8; NONCE_BYTES], now: Instant) -> bool {
        locked(&self.devices)
            .get(device_id)
            .and_then(|nonces| nonces.get(nonce))
            .is_some_and(|at| Self::fresh(*at, now))
    }

    /// Record a nonce after its request verified. False when the nonce is in the cache
    /// already, so of two requests with the same nonce at the same time only one passes.
    /// False also when the device has [`MAX_NONCES_PER_DEVICE`] live nonces.
    pub fn insert_at(&self, device_id: &str, nonce: [u8; NONCE_BYTES], now: Instant) -> bool {
        let mut devices = locked(&self.devices);
        devices.retain(|_, nonces| {
            nonces.retain(|_, at| Self::fresh(*at, now));
            !nonces.is_empty()
        });
        let nonces = devices.entry(device_id.to_owned()).or_default();
        if nonces.contains_key(&nonce) || nonces.len() >= MAX_NONCES_PER_DEVICE {
            return false;
        }
        nonces.insert(nonce, now);
        true
    }

    pub fn seen(&self, device_id: &str, nonce: &[u8; NONCE_BYTES]) -> bool {
        self.seen_at(device_id, nonce, Instant::now())
    }

    pub fn insert(&self, device_id: &str, nonce: [u8; NONCE_BYTES]) -> bool {
        self.insert_at(device_id, nonce, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};

    use super::*;

    #[test]
    fn the_budgets_of_the_contract_are_30_unsigned_and_120_per_device() {
        assert_eq!(UNSIGNED_PER_MINUTE, 30);
        assert_eq!(DEVICE_PER_MINUTE, 120);
        let budgets = crate::companion::Budgets::default();
        assert_eq!(budgets.unsigned_per_minute, 30);
        assert_eq!(budgets.device_per_minute, 120);
        assert_eq!(
            RateLimiter::<u8>::new(budgets.device_per_minute).limit(),
            120
        );
    }

    #[test]
    fn a_nonce_is_new_once_and_for_five_minutes() {
        let cache = NonceCache::new();
        let start = Instant::now();
        let nonce = [7u8; NONCE_BYTES];
        assert!(!cache.seen_at("dev", &nonce, start));
        assert!(
            !cache.seen_at("dev", &nonce, start),
            "looking does not record"
        );
        assert!(cache.insert_at("dev", nonce, start));
        assert!(cache.seen_at("dev", &nonce, start + Duration::from_secs(299)));
        assert!(!cache.insert_at("dev", nonce, start + Duration::from_secs(1)));
        assert!(
            !cache.seen_at("other", &nonce, start),
            "nonces are per device"
        );
        assert!(!cache.seen_at("dev", &nonce, start + NONCE_KEEP));
        assert!(cache.insert_at("dev", nonce, start + NONCE_KEEP));
    }

    #[test]
    fn a_device_cannot_fill_the_nonce_cache() {
        let cache = NonceCache::new();
        let start = Instant::now();
        for n in 0..MAX_NONCES_PER_DEVICE {
            let mut nonce = [0u8; NONCE_BYTES];
            nonce[..8].copy_from_slice(&(n as u64).to_le_bytes());
            assert!(cache.insert_at("dev", nonce, start));
        }
        assert!(!cache.insert_at("dev", [0xff; NONCE_BYTES], start));
        assert!(cache.insert_at("dev", [0xff; NONCE_BYTES], start + NONCE_KEEP));
    }

    fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let client = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        (client, server)
    }

    #[test]
    fn connections_are_limited_in_total_and_per_address() {
        let connections = companion_connections();
        let one: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let mut kept = Vec::new();
        let mut pairs = Vec::new();
        for _ in 0..MAX_CONNECTIONS_PER_IP {
            let (client, server) = socket_pair();
            kept.push(connections.admit(one, server).expect("slot"));
            pairs.push(client);
        }
        let (client, server) = socket_pair();
        assert!(
            connections.admit(one, server).is_none(),
            "the fifth is refused"
        );
        pairs.push(client);
        // Other addresses fill the rest of the total.
        for host in 2..=(1 + (MAX_CONNECTIONS - MAX_CONNECTIONS_PER_IP) as u8) {
            let (client, server) = socket_pair();
            let ip: IpAddr = Ipv4Addr::new(10, 0, 0, host).into();
            kept.push(connections.admit(ip, server).expect("slot"));
            pairs.push(client);
        }
        assert_eq!(connections.open(), MAX_CONNECTIONS);
        let (client, server) = socket_pair();
        let other: IpAddr = Ipv4Addr::new(10, 0, 1, 1).into();
        assert!(
            connections.admit(other, server).is_none(),
            "the total is full"
        );
        pairs.push(client);
        // A dropped slot frees its place.
        kept.pop();
        let (client, server) = socket_pair();
        assert!(connections.admit(other, server).is_some());
        pairs.push(client);
    }

    #[test]
    fn shutdown_ends_the_sockets_and_wait_idle_sees_the_slots_go() {
        use std::io::Read;
        let connections = companion_connections();
        let (mut client, server) = socket_pair();
        let slot = connections
            .admit(
                Ipv4Addr::LOCALHOST.into(),
                server.try_clone().expect("clone"),
            )
            .expect("slot");
        connections.shutdown_all();
        let mut byte = [0u8; 1];
        assert_eq!(client.read(&mut byte).expect("eof"), 0);
        assert!(!connections.wait_idle(Duration::from_millis(30)));
        drop(slot);
        assert!(connections.wait_idle(Duration::from_millis(30)));
    }
}
