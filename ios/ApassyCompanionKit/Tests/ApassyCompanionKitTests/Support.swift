// Fakes that the client tests share.

import Foundation
import Synchronization
import Testing

@testable import ApassyCompanionKit

/// A transport with a script: a function from the request and its index to an answer or a failure.
final class ScriptedTransport: CompanionTransport {
    typealias Handler = @Sendable (TransportRequest, Int) -> Result<TransportResponse, TransportFailure>

    private let recorded = Mutex<[TransportRequest]>([])
    private let handler: Handler

    init(_ handler: @escaping Handler) {
        self.handler = handler
    }

    var requests: [TransportRequest] { recorded.withLock { $0 } }

    func send(_ request: TransportRequest) async throws(TransportFailure) -> TransportResponse {
        let index = recorded.withLock { requests -> Int in
            requests.append(request)
            return requests.count - 1
        }
        switch handler(request, index) {
        case .success(let response): return response
        case .failure(let failure): throw failure
        }
    }
}

/// The keys of the vectors, with a record of each approval.
final class RecordingKeys: CompanionKeys {
    private let inner: SoftwareKeys
    private let reasonsLog = Mutex<[String]>([])
    private let messagesLog = Mutex<[String]>([])

    init() throws {
        inner = try Vectors.makeKeys()
    }

    var requestPublicKey: Data { inner.requestPublicKey }
    var approvalPublicKey: Data { inner.approvalPublicKey }
    var isSecureEnclave: Bool { false }
    var approvalReasons: [String] { reasonsLog.withLock { $0 } }
    var approvalMessages: [String] { messagesLog.withLock { $0 } }

    func signRequest(_ message: Data) throws -> Data {
        try inner.signRequest(message)
    }

    func signApproval(_ message: Data, reason: String) async throws -> Data {
        reasonsLog.withLock { $0.append(reason) }
        messagesLog.withLock { $0.append(String(decoding: message, as: UTF8.self)) }
        return try await inner.signApproval(message, reason: reason)
    }
}

/// Keys whose approval always fails.
struct RefusingKeys: CompanionKeys {
    let inner = SoftwareKeys()
    var requestPublicKey: Data { inner.requestPublicKey }
    var approvalPublicKey: Data { inner.approvalPublicKey }
    var isSecureEnclave: Bool { false }
    func signRequest(_ message: Data) throws -> Data { try inner.signRequest(message) }
    func signApproval(_ message: Data, reason: String) async throws -> Data { throw CompanionKeyError.cancelled }
}

/// Keys whose Face ID takes time: the clock of the test moves while the owner looks at the prompt.
struct SlowKeys: CompanionKeys {
    let inner = SoftwareKeys()
    let clock: TestClock
    let seconds: Double
    var requestPublicKey: Data { inner.requestPublicKey }
    var approvalPublicKey: Data { inner.approvalPublicKey }
    var isSecureEnclave: Bool { false }
    func signRequest(_ message: Data) throws -> Data { try inner.signRequest(message) }
    func signApproval(_ message: Data, reason: String) async throws -> Data {
        clock.advance(seconds)
        return try await inner.signApproval(message, reason: reason)
    }
}

/// A clock that a test moves.
final class TestClock: Sendable {
    private let seconds: Mutex<Double>

    init(_ start: Int64 = Vectors.time) {
        seconds = Mutex(Double(start))
    }

    func advance(_ by: Double) {
        seconds.withLock { $0 += by }
    }

    var source: TimeSource {
        { [self] in Date(timeIntervalSince1970: seconds.withLock { $0 }) }
    }
}

enum Support {
    /// The bytes of a base64url field of a JSON object.
    static func field(_ text: String?) throws -> Data {
        let value = try #require(text)
        return try #require(B64U.decode(value))
    }

    static func json(_ data: Data) throws -> [String: Any] {
        try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    /// The nonces `00 01 ... 0F` for the first call, then the first byte counts up.
    static func nonces() -> NonceSource {
        let counter = Mutex<UInt8>(0)
        return {
            let step = counter.withLock { value -> UInt8 in
                defer { value &+= 1 }
                return value
            }
            var bytes = Data(0...15)
            bytes[0] = step
            return bytes
        }
    }

    static func ok(_ json: String) -> Result<TransportResponse, TransportFailure> {
        .success(TransportResponse(status: 200, body: Data(json.utf8)))
    }

    static func error(_ status: Int, _ code: String, _ message: String = "Message.") -> Result<TransportResponse, TransportFailure> {
        .success(TransportResponse(status: status, body: ErrorMappingTests.body(code, message)))
    }

    static let endpoint = CompanionEndpoint(
        hosts: ["Mac-mini.local", "192.168.1.20"], port: 48620, pin: Data(repeating: 7, count: 32))

    static func client(
        transport: any CompanionTransport,
        keys: (any CompanionKeys)? = nil,
        endpoint: CompanionEndpoint = Support.endpoint,
        lastGoodHost: String? = nil,
        clock: TestClock = TestClock()
    ) throws -> CompanionClient {
        CompanionClient(
            deviceID: Vectors.deviceID, endpoint: endpoint, keys: try keys ?? Vectors.makeKeys(),
            lastGoodHost: lastGoodHost, transport: transport, now: clock.source, nonce: nonces())
    }

    /// The run of the contract examples.
    static func run(remember: Bool = true) -> PendingRun {
        PendingRun(
            id: "123456789012345", agent: "claude-code", command: ["npm", "run", "migrate"], cwd: "/Users/me/Dev/shop",
            envNames: ["DATABASE_URL"], purpose: "Apply the new migration.",
            risk: "production credential: always asks the owner", userRequest: "Deploy the new schema to staging.",
            requestSource: "from the host hook", agentRequest: "",
            remember: remember ? RememberOffer(pattern: "npm run migrate", approvals: 1, needed: 3) : nil,
            digest: Vectors.approvalDigest, waitingSeconds: 12)
    }

    /// Check a captured signed request: its four headers, and its signature over the request string
    /// that is rebuilt from the method, the path, the headers, and the body that were sent.
    static func verifySigned(_ request: TransportRequest, publicKey: Data, sourceLocation: SourceLocation = #_sourceLocation) {
        let headers = request.headers
        #expect(headers["X-Apassy-Device"].map(DeviceID.isValid) == true, sourceLocation: sourceLocation)
        let time = headers["X-Apassy-Time"] ?? ""
        #expect(!time.isEmpty && time.count <= 12 && time.allSatisfy(\.isASCII) && Int64(time) != nil, sourceLocation: sourceLocation)
        let nonce = headers["X-Apassy-Nonce"] ?? ""
        #expect(nonce.count == 22 && B64U.decode(nonce)?.count == 16, sourceLocation: sourceLocation)
        let signature = B64U.decode(headers["X-Apassy-Signature"] ?? "")
        #expect(signature != nil, sourceLocation: sourceLocation)

        let string = try? SigningStrings.request(
            method: request.method, path: request.path, deviceID: headers["X-Apassy-Device"] ?? "",
            time: Int64(time) ?? 0, nonce: nonce, body: request.body)
        #expect(string != nil, sourceLocation: sourceLocation)
        #expect(
            Vectors.verifies(signature: signature ?? Data(), of: string ?? "", publicKey: publicKey),
            sourceLocation: sourceLocation)
    }
}
