//! Track proxy: byte-stream helpers.
//!
//! A copy, with attribution, of the `Scanner` and `Replacer` of
//! `src/broker/proxy/http1.rs` of wydrox/apassy at rev 77f6628 (Apache-2.0): find a
//! placeholder in a request body, and replace each value with its placeholder in a
//! response stream, across chunk boundaries, with no change in length.
