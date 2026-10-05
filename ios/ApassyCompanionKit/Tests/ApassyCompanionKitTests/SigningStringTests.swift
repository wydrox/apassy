import Foundation
import Testing

@testable import ApassyCompanionKit

@Suite("Signing strings")
struct SigningStringTests {
    static let controls = ["\n", "\r", "\t", "\u{0}", "\u{1B}", "\u{7F}", "\u{85}", "a\nb"]

    @Test("a control character in any field is refused", arguments: controls)
    func controlCharacterRefused(control: String) {
        let bad = "x" + control + "y"
        let key = Vectors.requestPublicKey
        #expect(throws: SigningError.controlCharacter(field: "device_id")) {
            try SigningStrings.pair(deviceID: bad, deviceName: "n", requestKey: key, approvalKey: key)
        }
        #expect(throws: SigningError.controlCharacter(field: "device_name")) {
            try SigningStrings.pair(deviceID: "d", deviceName: bad, requestKey: key, approvalKey: key)
        }
        #expect(throws: SigningError.controlCharacter(field: "method")) {
            try SigningStrings.request(method: bad, path: "/", deviceID: "d", time: 1, nonce: "n", body: Data())
        }
        #expect(throws: SigningError.controlCharacter(field: "path")) {
            try SigningStrings.request(method: "GET", path: bad, deviceID: "d", time: 1, nonce: "n", body: Data())
        }
        #expect(throws: SigningError.controlCharacter(field: "device_id")) {
            try SigningStrings.request(method: "GET", path: "/", deviceID: bad, time: 1, nonce: "n", body: Data())
        }
        #expect(throws: SigningError.controlCharacter(field: "nonce")) {
            try SigningStrings.request(method: "GET", path: "/", deviceID: "d", time: 1, nonce: bad, body: Data())
        }
        #expect(throws: SigningError.controlCharacter(field: "run_id")) {
            try SigningStrings.approve(deviceID: "d", action: .approve, runID: bad, digest: "x", time: 1)
        }
        #expect(throws: SigningError.controlCharacter(field: "digest")) {
            try SigningStrings.approve(deviceID: "d", action: .approve, runID: "1", digest: bad, time: 1)
        }
        #expect(throws: SigningError.controlCharacter(field: "device_id")) {
            try SigningStrings.approve(deviceID: bad, action: .approve, runID: "1", digest: "x", time: 1)
        }
    }

    @Test("printable non-ASCII text is allowed")
    func nonASCIIAllowed() throws {
        let key = Vectors.requestPublicKey
        let string = try SigningStrings.pair(deviceID: "d", deviceName: "Telefon Zażółć 📱", requestKey: key, approvalKey: key)
        #expect(string.contains("Telefon Zażółć 📱"))
    }

    @Test("a string has no trailing line feed and one line per field")
    func shape() throws {
        let request = try SigningStrings.request(
            method: "POST", path: "/v1/x", deviceID: "d", time: 5, nonce: "n", body: Data("{}".utf8))
        #expect(!request.hasSuffix("\n"))
        #expect(request.split(separator: "\n", omittingEmptySubsequences: false).count == 7)
        #expect(Vectors.pairString.split(separator: "\n").count == 5)
        let code = SigningStrings.code(secret: Vectors.secretBytes, requestKey: Vectors.requestPublicKey, approvalKey: Vectors.approvalPublicKey)
        #expect(code.split(separator: "\n").count == 4)
        #expect(code.hasPrefix("apassy-companion-code-v1\n\(Vectors.secret)\n\(Vectors.requestPublic)\n\(Vectors.approvalPublic)"))
    }

    @Test("the request body hash is over the exact bytes")
    func bodyHashIsOverBytes() throws {
        let a = try SigningStrings.request(method: "POST", path: "/p", deviceID: "d", time: 1, nonce: "n", body: Data(#"{"a":1}"#.utf8))
        let b = try SigningStrings.request(method: "POST", path: "/p", deviceID: "d", time: 1, nonce: "n", body: Data(#"{"a": 1}"#.utf8))
        #expect(a != b)
        #expect(a.hasSuffix(Hashing.sha256Hex(Data(#"{"a":1}"#.utf8))))
    }
}
