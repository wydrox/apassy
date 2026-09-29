//! Track proxy: the swap of placeholders in a request head.
//!
//! A copy, with attribution, of `src/broker/proxy/swap.rs` of wydrox/apassy at rev
//! 77f6628 (Apache-2.0), adapted to the relay request type: the Authorization header
//! (exact, `<scheme> <placeholder>`, Basic parts), the nine key headers, and the
//! seven key query parameters. Any other placeholder refuses the request.
