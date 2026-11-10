//! The tailnet peer behind each connection that a TLS front pumps to its target (N8-1).
//!
//! The front connects to the relay's tailnet listener from the loopback, so the relay
//! sees every peer as `127.0.0.1`. The front and the relay run in one process (the Mac
//! app, `apassy serve`), so the front writes down here, for each pumped connection, the
//! loopback address pair of its connection to the target and the peer that it serves.
//! The relay's tailnet listener looks up the remote address of a request here and counts
//! failed authentications per peer.
//!
//! This is process memory only: no header, no first line, nothing that a local process
//! that connects to the listener itself could forge. A connection that the table does
//! not know (a local process that bypasses the front) is keyed by its own address, the
//! loopback. With the Serve fallback (`FrontRoute::ServeTcp`) every peer is Tailscale's
//! daemon on the loopback, so the peers share one key there.
//!
//! A stream of the Connect tunnel has no peer address (Connect tells the node nothing
//! about the caller): the front writes it down as a tunnel stream ([`register_tunnel`]),
//! so the relay knows, without a header, that the request came through Connect
//! ([`is_tunnel`]).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

type Key = (SocketAddr, SocketAddr);

/// Whose bytes a pumped connection carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// A tailnet peer.
    Peer(IpAddr),
    /// A stream of the Connect tunnel.
    Tunnel,
}

fn table() -> MutexGuard<'static, HashMap<Key, Origin>> {
    static TABLE: OnceLock<Mutex<HashMap<Key, Origin>>> = OnceLock::new();
    TABLE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

fn key(source: SocketAddr, target: SocketAddr) -> Key {
    (
        SocketAddr::new(source.ip().to_canonical(), source.port()),
        SocketAddr::new(target.ip().to_canonical(), target.port()),
    )
}

/// The entry of one pumped connection. Drop removes it.
#[derive(Debug)]
pub struct PeerEntry {
    key: Key,
}

impl Drop for PeerEntry {
    fn drop(&mut self) {
        table().remove(&self.key);
    }
}

/// Write down that the connection from `source` to `target` (both on the loopback, as
/// the target connection's `local_addr` and `peer_addr`) carries the bytes of `peer`.
/// The entry lives until the returned value drops.
pub fn register(source: SocketAddr, target: SocketAddr, peer: IpAddr) -> PeerEntry {
    let key = key(source, target);
    table().insert(key, Origin::Peer(peer.to_canonical()));
    PeerEntry { key }
}

/// Write down that the connection from `source` to `target` carries a stream of the
/// Connect tunnel. The entry lives until the returned value drops.
pub fn register_tunnel(source: SocketAddr, target: SocketAddr) -> PeerEntry {
    let key = key(source, target);
    table().insert(key, Origin::Tunnel);
    PeerEntry { key }
}

/// The peer of the connection from `source` to the listener at `target`, while a front
/// pumps it. `None`: no front of this process made that connection, or it carries a
/// tunnel stream.
pub fn peer_of(source: SocketAddr, target: SocketAddr) -> Option<IpAddr> {
    match table().get(&key(source, target)) {
        Some(Origin::Peer(peer)) => Some(*peer),
        _ => None,
    }
}

/// True while the connection from `source` to the listener at `target` carries a stream
/// of the Connect tunnel that the front of this process pumps.
pub fn is_tunnel(source: SocketAddr, target: SocketAddr) -> bool {
    table().get(&key(source, target)) == Some(&Origin::Tunnel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_names_its_peer_until_it_drops() {
        let source: SocketAddr = "127.0.0.1:50001".parse().unwrap();
        let target: SocketAddr = "127.0.0.1:50002".parse().unwrap();
        let peer: IpAddr = "100.64.0.9".parse().unwrap();
        assert_eq!(peer_of(source, target), None);
        let entry = register(source, target, peer);
        assert_eq!(peer_of(source, target), Some(peer));
        // Another listener with the same source port is another connection.
        let other: SocketAddr = "127.0.0.1:50003".parse().unwrap();
        assert_eq!(peer_of(source, other), None);
        drop(entry);
        assert_eq!(peer_of(source, target), None);
    }

    #[test]
    fn a_tunnel_stream_has_no_peer() {
        let source: SocketAddr = "127.0.0.1:50021".parse().unwrap();
        let target: SocketAddr = "127.0.0.1:50022".parse().unwrap();
        assert!(!is_tunnel(source, target));
        let entry = register_tunnel(source, target);
        assert!(is_tunnel(source, target));
        assert_eq!(peer_of(source, target), None);
        drop(entry);
        assert!(!is_tunnel(source, target));
        let _peer = register(source, target, "100.64.0.9".parse().unwrap());
        assert!(!is_tunnel(source, target));
    }

    #[test]
    fn a_mapped_loopback_address_is_the_same_key() {
        let source: SocketAddr = "[::ffff:127.0.0.1]:50011".parse().unwrap();
        let target: SocketAddr = "127.0.0.1:50012".parse().unwrap();
        let peer: IpAddr = "::ffff:100.64.0.10".parse().unwrap();
        let _entry = register(source, target, peer);
        assert_eq!(
            peer_of("127.0.0.1:50011".parse().unwrap(), target),
            Some("100.64.0.10".parse().unwrap())
        );
    }
}
