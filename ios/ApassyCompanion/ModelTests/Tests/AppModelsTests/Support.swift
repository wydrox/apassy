import ApassyCompanionKit
import Foundation
import Synchronization

@testable import AppModels

/// A Mac that answers the calls of `SessionModel`, or fails them the way a real Mac or network can.
actor ScriptedConnection: MacConnection {
    enum Failure {
        case none
        case unreachable
        case unpaired
        case localNetworkDenied
        case pinMismatch
        case server(status: Int, code: String, message: String)
        /// Only an approval fails, with the error of the key. Everything else works.
        case approvalKey(CompanionKeyError)
    }

    private(set) var failure = Failure.none
    private(set) var calls: [String] = []
    private(set) var inboxCalls = 0
    var inboxAnswer = PreviewData.inbox
    var lastGoodHost: String? { "Mac-mini.local" }

    func fail(with failure: Failure) {
        self.failure = failure
    }

    func setInbox(_ inbox: Inbox) {
        inboxAnswer = inbox
    }

    private func check() throws {
        switch failure {
        case .none: return
        case .unreachable: throw CompanionError.notReachable
        case .unpaired: throw CompanionError.unpaired
        case .localNetworkDenied: throw CompanionError.localNetworkDenied
        case .pinMismatch: throw CompanionError.pinMismatchOnAllHosts
        case .server(let status, let code, let message):
            throw CompanionError.server(status: status, code: code, message: message)
        case .approvalKey: return
        }
    }

    func status() async throws -> StatusInfo {
        try check()
        return PreviewData.status
    }

    func inbox() async throws -> Inbox {
        inboxCalls += 1
        try check()
        return inboxAnswer
    }

    func approve(run: PendingRun, remember: Bool) async throws -> ApproveOutcome {
        if case .approvalKey(let error) = failure { throw error }
        try check()
        calls.append("approve \(run.id) remember=\(remember) digest=\(run.digest.prefix(4))")
        return remember ? .approvedAndRemembered : .approved
    }

    func deny(run: PendingRun) async throws {
        try check()
        calls.append("deny \(run.id)")
    }

    func denyAccessRequest(id: String) async throws {
        try check()
        calls.append("denyAccess \(id)")
    }

    func unpair() async throws {
        try check()
        calls.append("unpair")
    }
}

/// A transport that plays the pairing side of a Mac: it accepts the pair request, then answers each
/// status poll from a list, and then `waiting`.
final class ScriptedPairingMac: CompanionTransport {
    enum Poll {
        case waiting
        case paired
        case denied
        case expired
        case dropped
    }

    private let polls: Mutex<[Poll]>
    private let sent = Mutex<[String]>([])
    /// Runs while the pair request is answered, before the answer. A test uses it to act at that moment.
    private let onPair: (@Sendable () async -> Void)?

    init(polls: [Poll], onPair: (@Sendable () async -> Void)? = nil) {
        self.polls = Mutex(polls)
        self.onPair = onPair
    }

    /// The method and path of each request so far.
    var requests: [String] { sent.withLock { $0 } }

    func send(_ request: TransportRequest) async throws(TransportFailure) -> TransportResponse {
        sent.withLock { $0.append("\(request.method) \(request.path)") }
        if request.method == "POST" && request.path == "/v1/pair" {
            await onPair?()
            let end = Int(Date().timeIntervalSince1970) + 300
            return TransportResponse(status: 200, body: Data("{\"expires_at\":\(end)}".utf8))
        }
        if request.method == "GET" && request.path.hasPrefix("/v1/pair/") {
            let next = polls.withLock { $0.isEmpty ? Poll.waiting : $0.removeFirst() }
            switch next {
            case .waiting: return Self.state("waiting")
            case .paired: return Self.state("paired", macName: "Mac mini")
            case .denied: return Self.state("denied")
            case .expired: return Self.state("expired")
            case .dropped: throw .connection
            }
        }
        return TransportResponse(status: 404, body: Data(#"{"error":{"code":"not_found","message":"No."}}"#.utf8))
    }

    private static func state(_ state: String, macName: String? = nil) -> TransportResponse {
        let name = macName.map { ",\"mac_name\":\"\($0)\"" } ?? ""
        return TransportResponse(status: 200, body: Data("{\"state\":\"\(state)\"\(name)}".utf8))
    }
}

/// A pairing link for a Mac with a synthetic pin and secret.
func pairingLinkText(expiresIn seconds: Int) -> String {
    let pin = B64U.encode(Data(repeating: 0x11, count: 32))
    let secret = B64U.encode(Data(repeating: 0x22, count: 32))
    let end = Int(Date().timeIntervalSince1970) + seconds
    return "apassy://pair?v=1&h=Mac-mini.local&p=48620&c=\(pin)&s=\(secret)&n=Mac%20mini&e=\(end)"
}

/// Wait until a condition holds, for at most `seconds`. It returns whether the condition held.
@MainActor
func waitUntil(seconds: Double = 5, _ condition: () -> Bool) async -> Bool {
    let end = Date().addingTimeInterval(seconds)
    while Date() < end {
        if condition() { return true }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return condition()
}

/// Keys whose approval fails the way a Face ID prompt can.
struct FailingApprovalKeys: CompanionKeys {
    let inner = SoftwareKeys()
    let error: CompanionKeyError
    var requestPublicKey: Data { inner.requestPublicKey }
    var approvalPublicKey: Data { inner.approvalPublicKey }
    var isSecureEnclave: Bool { false }
    func signRequest(_ message: Data) throws -> Data { try inner.signRequest(message) }
    func signApproval(_ message: Data, reason: String) async throws -> Data { throw error }
}

/// Holds a model for a closure that is made before the model.
@MainActor
final class ModelBox {
    var model: PairingModel?
}
