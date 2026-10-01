import Foundation
import Testing

@testable import ApassyCompanionKit

@Suite("Encoding")
struct EncodingTests {
    @Test("b64u round trips at every length from 0 to 70 bytes")
    func b64uRoundTrip() {
        for length in 0...70 {
            let data = RandomBytes.make(length)
            let text = B64U.encode(data)
            #expect(!text.contains("="))
            #expect(!text.contains("+") && !text.contains("/"))
            #expect(B64U.decode(text) == data)
        }
    }

    @Test("b64u matches known encodings")
    func b64uKnown() {
        #expect(B64U.encode(Data()) == "")
        #expect(B64U.encode(Data([0xFB, 0xFF])) == "-_8")
        #expect(B64U.encode(Data("f".utf8)) == "Zg")
        #expect(B64U.encode(Data("fo".utf8)) == "Zm8")
        #expect(B64U.encode(Data("foo".utf8)) == "Zm9v")
        #expect(B64U.encode(Data(0...15)) == Vectors.nonce)
        #expect(B64U.decode("-_8") == Data([0xFB, 0xFF]))
    }

    @Test("b64u decoding is strict", arguments: [
        "Zg==",  // padding
        "Zm9v ",  // white space
        "Zm9v\n",
        "Zm+v",  // standard alphabet
        "Zm/v",
        "Z",  // a length that no data has
        "ZmZmZ",
        "AB",  // spare bits are not zero, so the text is not the canonical one
        "Zh",
        "Zm9é",  // not ASCII
    ])
    func b64uStrict(text: String) {
        #expect(B64U.decode(text) == nil)
    }

    @Test("b64u vectors decode to the right sizes")
    func vectorSizes() {
        #expect(Vectors.requestPublicKey.count == 65)
        #expect(Vectors.requestPublicKey.first == 0x04)
        #expect(Vectors.approvalPublicKey.count == 65)
        #expect(Vectors.secretBytes.count == 32)
        #expect(Vectors.bytes(Vectors.nonce).count == 16)
    }

    @Test("hex encodes lowercase and decodes only lowercase pairs")
    func hex() {
        #expect(Hex.encode(Data([0x00, 0xAB, 0xFF])) == "00abff")
        #expect(Hex.decode("00abff") == Data([0x00, 0xAB, 0xFF]))
        #expect(Hex.decode("00ABFF") == nil)
        #expect(Hex.decode("abc") == nil)
        #expect(Hex.decode("zz") == nil)
        #expect(Hex.decode("") == Data())
    }

    @Test("SHA-256 helpers")
    func sha() {
        #expect(Hashing.sha256Hex(Data()) == Vectors.emptyHash)
        #expect(Hashing.sha256(Data("abc".utf8)).count == 32)
    }

    @Test("constant-time comparison")
    func constantTime() {
        #expect(Hashing.constantTimeEqual(Data([1, 2, 3]), Data([1, 2, 3])))
        #expect(!Hashing.constantTimeEqual(Data([1, 2, 3]), Data([1, 2, 4])))
        #expect(!Hashing.constantTimeEqual(Data([1, 2, 3]), Data([1, 2])))
        #expect(Hashing.constantTimeEqual(Data(), Data()))
    }

    @Test("a device ID has 32 lowercase hex characters")
    func deviceID() {
        for _ in 0..<20 { #expect(DeviceID.isValid(DeviceID.random())) }
        #expect(DeviceID.random() != DeviceID.random())
        #expect(DeviceID.isValid(Vectors.deviceID))
        #expect(!DeviceID.isValid(Vectors.deviceID.uppercased()))
        #expect(!DeviceID.isValid("abc"))
        #expect(!DeviceID.isValid(String(repeating: "g", count: 32)))
    }
}
