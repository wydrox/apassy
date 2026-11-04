//! The node words of a pin (contract node-pairing-v1 section 4a): the iPhone core shows
//! the words of the same function as the Mac, so the two screens agree. The vector is the
//! contract's: the certificate `tests/fixtures/node-pairing-v1/node-cert.der`.

use apassy::net::pin::{self, Pin};

/// The node words of the fixture certificate (node-pairing-v1 section 4a and section 12).
const NODE_CERT_WORDS: &str = "noodle monkey dinner sled guitar garden";

const NODE_CERT: &[u8] = include_bytes!("../../../tests/fixtures/node-pairing-v1/node-cert.der");

#[test]
fn pin_words_of_the_node_pairing_fixture_are_the_contract_vector() {
    let pin = Pin::of_certificate(NODE_CERT);
    assert_eq!(pin.text(), "u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE");
    assert_eq!(pin.words(), NODE_CERT_WORDS);
    // The core reads the stored pin text (the membership keeps text) and gets the same words.
    let stored = pin::parse(&pin.text()).expect("a canonical pin");
    assert_eq!(stored.words(), NODE_CERT_WORDS);
}
