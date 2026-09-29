//! Track proxy: the HTTPS/1.1 client to upstream hosts.
//!
//! rustls with ring and the platform verifier (plus extra roots in tests), the
//! handshake before the first byte, a request head written from parts, and a
//! response head parsed with `httparse`, with Content-Length, chunked, or
//! read-to-close framing.
