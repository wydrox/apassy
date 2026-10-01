//! The limits of the companion listener (contract companion-v1, sections 3 and 6): the
//! connections, the rate of requests, and the nonces of signed requests.
//!
//! Every function that depends on time takes the time as an argument, so the tests do
//! not need to sleep. The maps have a size limit, so a peer cannot grow them.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::{IpAddr, Shutdown, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

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

const RATE_WINDOW: Duration = Duration::from_secs(60);
/// A limiter keeps at most this many keys.
const MAX_KEYS: usize = 4096;
/// A device has at most this many nonces in the cache. At 120 requests per minute it
/// never reaches this.
const MAX_NONCES_PER_DEVICE: usize = 4096;

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A sliding window of one minute: each key gets at most `limit` admissions in it.
#[derive(Debug)]
pub struct RateLimiter<K> {
    limit: usize,
    hits: Mutex<HashMap<K, VecDeque<Instant>>>,
}

impl<K: Hash + Eq> RateLimiter<K> {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            hits: Mutex::new(HashMap::new()),
        }
    }

    fn prune(queue: &mut VecDeque<Instant>, now: Instant) {
        while queue
            .front()
            .is_some_and(|first| now.saturating_duration_since(*first) >= RATE_WINDOW)
        {
            queue.pop_front();
        }
    }

    /// Count one request of `key` at `now`. False when the key has used its limit: the
    /// request is not counted then, so a peer that keeps asking does not extend its own
    /// wait. False also for a new key when the map is full of live keys.
    pub fn admit_at(&self, key: K, now: Instant) -> bool {
        let mut hits = locked(&self.hits);
        if !hits.contains_key(&key) && hits.len() >= MAX_KEYS {
            hits.retain(|_, queue| {
                Self::prune(queue, now);
                !queue.is_empty()
            });
            if hits.len() >= MAX_KEYS {
                return false;
            }
        }
        let queue = hits.entry(key).or_default();
        Self::prune(queue, now);
        if queue.len() >= self.limit {
            return false;
        }
        queue.push_back(now);
        true
    }

    pub fn admit(&self, key: K) -> bool {
        self.admit_at(key, Instant::now())
    }

    /// True when `admit_at` would count one more request of `key` at `now`. It counts
    /// nothing. A key with no live hits has its full limit, also when the map is full.
    pub fn would_admit_at(&self, key: &K, now: Instant) -> bool {
        let mut hits = locked(&self.hits);
        let Some(queue) = hits.get_mut(key) else {
            return true;
        };
        Self::prune(queue, now);
        queue.len() < self.limit
    }

    pub fn would_admit(&self, key: &K) -> bool {
        self.would_admit_at(key, Instant::now())
    }
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

#[derive(Debug, Default)]
struct ConnectionState {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
    /// A copy of each open socket, so that a stop can end the connections at once.
    sockets: HashMap<u64, TcpStream>,
    next_id: u64,
}

/// The open connections. [`Connections::admit`] gives a slot or refuses.
#[derive(Debug, Default)]
pub struct Connections {
    state: Mutex<ConnectionState>,
}

/// A slot. It frees itself on drop.
#[derive(Debug)]
pub struct ConnectionSlot {
    connections: Arc<Connections>,
    id: u64,
    ip: IpAddr,
}

impl Connections {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Take a slot for a connection from `ip`, or `None` when the listener has
    /// [`MAX_CONNECTIONS`] connections or `ip` has [`MAX_CONNECTIONS_PER_IP`]. `socket`
    /// is a clone of the connection, kept until the slot drops.
    pub fn admit(self: &Arc<Self>, ip: IpAddr, socket: TcpStream) -> Option<ConnectionSlot> {
        let mut state = locked(&self.state);
        let from_ip = state.per_ip.get(&ip).copied().unwrap_or(0);
        if state.total >= MAX_CONNECTIONS || from_ip >= MAX_CONNECTIONS_PER_IP {
            return None;
        }
        state.total += 1;
        state.per_ip.insert(ip, from_ip + 1);
        let id = state.next_id;
        state.next_id += 1;
        state.sockets.insert(id, socket);
        Some(ConnectionSlot {
            connections: Arc::clone(self),
            id,
            ip,
        })
    }

    /// End every open connection now.
    pub fn shutdown_all(&self) {
        for socket in locked(&self.state).sockets.values() {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }

    /// Wait until no connection is open, at most `timeout`. True when none is open.
    pub fn wait_idle(&self, timeout: Duration) -> bool {
        let end = Instant::now() + timeout;
        loop {
            if locked(&self.state).total == 0 {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The number of open connections.
    pub fn open(&self) -> usize {
        locked(&self.state).total
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        let mut state = locked(&self.connections.state);
        state.total = state.total.saturating_sub(1);
        state.sockets.remove(&self.id);
        if let Some(count) = state.per_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.per_ip.remove(&self.ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, TcpListener};

    use super::*;

    #[test]
    fn a_key_gets_its_limit_per_minute_and_then_a_refusal() {
        let limiter = RateLimiter::new(3);
        let start = Instant::now();
        for _ in 0..3 {
            assert!(limiter.admit_at("a", start));
        }
        assert!(!limiter.admit_at("a", start));
        assert!(
            limiter.admit_at("b", start),
            "another key has its own count"
        );
        // A refusal does not count, so the window does not move.
        assert!(!limiter.admit_at("a", start + Duration::from_secs(59)));
        assert!(limiter.admit_at("a", start + Duration::from_secs(60)));
    }

    #[test]
    fn would_admit_looks_and_counts_nothing() {
        let limiter = RateLimiter::new(2);
        let start = Instant::now();
        for _ in 0..10 {
            assert!(limiter.would_admit_at(&"a", start), "looking is free");
        }
        assert!(limiter.admit_at("a", start));
        assert!(limiter.would_admit_at(&"a", start));
        assert!(limiter.admit_at("a", start));
        assert!(!limiter.would_admit_at(&"a", start), "the limit is used");
        assert!(!limiter.would_admit_at(&"a", start + Duration::from_secs(59)));
        assert!(limiter.would_admit_at(&"a", start + RATE_WINDOW));
        assert!(
            limiter.would_admit_at(&"b", start),
            "an unknown key is fine"
        );
        assert!(
            limiter.admit_at("b", start),
            "looking at b did not count for it"
        );
    }

    #[test]
    fn a_full_limiter_refuses_a_new_key_until_old_keys_expire() {
        let limiter = RateLimiter::new(1);
        let start = Instant::now();
        for key in 0..MAX_KEYS {
            assert!(limiter.admit_at(key, start));
        }
        assert!(!limiter.admit_at(MAX_KEYS, start), "the map is full");
        assert!(!limiter.admit_at(0, start), "a known key keeps its limit");
        assert!(limiter.admit_at(MAX_KEYS, start + RATE_WINDOW));
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
        let connections = Connections::new();
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
        let connections = Connections::new();
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
