import Foundation
import Testing

@testable import ApassyCompanionKit

@Suite("Error mapping")
struct ErrorMappingTests {
    static func body(_ code: String, _ message: String) -> Data {
        Data(#"{"error":{"code":"\#(code)","message":"\#(message)"}}"#.utf8)
    }

    @Test("an error body gives its status, code, and message")
    func serverError() {
        let error = CompanionError.from(
            status: 404, body: Self.body("not_waiting", "The run no longer waits. Nothing was approved."))
        #expect(error == .server(status: 404, code: "not_waiting", message: "The run no longer waits. Nothing was approved."))
        #expect(error.errorDescription == "The run no longer waits. Nothing was approved.")
    }

    @Test("each code of the contract keeps its status and message", arguments: [
        (400, "bad_request"), (401, "unauthorized"), (403, "owner_check_failed"), (403, "stale"),
        (404, "not_waiting"), (404, "not_found"), (409, "changed"), (409, "nothing_to_remember"),
        (409, "already_paired"), (413, "too_large"), (423, "vault_locked"), (429, "too_many_requests"),
        (500, "internal"),
    ])
    func contractCodes(status: Int, code: String) {
        let error = CompanionError.from(status: status, body: Self.body(code, "Message for \(code)."))
        #expect(error == .server(status: status, code: code, message: "Message for \(code)."))
    }

    @Test("401 unpaired means the UI deletes the pairing")
    func unpaired() {
        #expect(CompanionError.from(status: 401, body: Self.body("unpaired", "No.")) == .unpaired)
    }

    @Test("401 clock_skew keeps the message that names the difference")
    func clockSkew() {
        let error = CompanionError.from(status: 401, body: Self.body("clock_skew", "The clocks differ by 93 s."))
        #expect(error == .clockSkew(message: "The clocks differ by 93 s."))
        #expect(error.errorDescription?.contains("93 s") == true)
    }

    @Test("a plain 401 is not unpaired")
    func plainUnauthorized() {
        #expect(CompanionError.from(status: 401, body: Self.body("unauthorized", "No.")) == .server(status: 401, code: "unauthorized", message: "No."))
    }

    @Test("a body that is not an error body still gives an error with the status", arguments: [
        "", "<html>Bad gateway</html>", "{}", #"{"error":"x"}"#, #"{"error":{"code":"x"}}"#,
    ])
    func unreadableBody(text: String) {
        let error = CompanionError.from(status: 502, body: Data(text.utf8))
        #expect(error == .server(status: 502, code: "unknown", message: "The Mac answered with an unexpected error (HTTP 502)."))
    }

    @Test("failures of all hosts sort into one error")
    func hostFailures() {
        #expect(CompanionError.from(failures: [.pinMismatch, .pinMismatch]) == .pinMismatchOnAllHosts)
        #expect(CompanionError.from(failures: [.pinMismatch]) == .pinMismatchOnAllHosts)
        #expect(CompanionError.from(failures: [.connection, .pinMismatch]) == .notReachable)
        #expect(CompanionError.from(failures: [.connection, .tls]) == .notReachable)
        #expect(CompanionError.from(failures: [.localNetworkDenied, .localNetworkDenied]) == .localNetworkDenied)
        #expect(CompanionError.from(failures: [.connection, .localNetworkDenied]) == .localNetworkDenied)
        #expect(CompanionError.from(failures: []) == .notReachable)
    }

    @Test("the owner messages")
    func messages() {
        #expect(
            CompanionError.localNetworkDenied.errorDescription
                == "Allow local network access for Apassy in Settings > Privacy & Security > Local Network.")
        #expect(CompanionError.pinMismatchOnAllHosts.errorDescription?.contains("Forget this Mac") == true)
        #expect(CompanionError.linkRejected.errorDescription?.contains("Select Cancel on your Mac") == true)
        #expect(CompanionError.notReachable.errorDescription?.contains("same Wi-Fi") == true)
        #expect(CompanionError.unpaired.errorDescription?.contains("Pair it again") == true)
    }
}
