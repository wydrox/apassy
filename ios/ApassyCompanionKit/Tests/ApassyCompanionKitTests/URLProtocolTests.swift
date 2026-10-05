// The client through a real URL session, with a URL protocol that captures each request. The
// protocol replaces the network only; the request that it sees is the one that goes on the wire.

import Foundation
import Synchronization
import Testing

@testable import ApassyCompanionKit

struct CapturedRequest: Sendable {
    var method: String
    var url: URL
    var headers: [String: String]
    var body: Data
}

final class CaptureURLProtocol: URLProtocol, @unchecked Sendable {
    typealias Responder = @Sendable (CapturedRequest) -> Result<(Int, Data), URLError>

    static let captured = Mutex<[CapturedRequest]>([])
    static let responder = Mutex<Responder>({ _ in .success((200, Data("{}".utf8))) })

    static func reset(_ responder: @escaping Responder) {
        captured.withLock { $0.removeAll() }
        self.responder.withLock { $0 = responder }
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        var body = request.httpBody ?? Data()
        if let stream = request.httpBodyStream {
            stream.open()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let count = stream.read(&buffer, maxLength: buffer.count)
                if count <= 0 { break }
                body.append(buffer, count: count)
            }
            stream.close()
        }
        let seen = CapturedRequest(
            method: request.httpMethod ?? "", url: request.url!, headers: request.allHTTPHeaderFields ?? [:], body: body)
        Self.captured.withLock { $0.append(seen) }
        switch Self.responder.withLock({ $0 })(seen) {
        case .success(let (status, data)):
            let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: nil)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        case .failure(let error):
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

@Suite("Client through a URL session", .serialized)
struct URLProtocolTests {
    static let endpoint = CompanionEndpoint(hosts: ["mac.local", "10.0.0.2"], port: 48620, pin: Data(repeating: 7, count: 32))

    static func client(clock: TestClock = TestClock()) throws -> CompanionClient {
        CompanionClient(
            deviceID: Vectors.deviceID, endpoint: endpoint, keys: try Vectors.makeKeys(),
            transport: PinnedURLSessionTransport(pin: endpoint.pin, protocolClasses: [CaptureURLProtocol.self]),
            now: clock.source, nonce: Support.nonces())
    }

    /// Check a captured request as the Mac does: rebuild the request string from what arrived.
    static func verify(_ request: CapturedRequest, publicKey: Data) throws {
        let components = try #require(URLComponents(url: request.url, resolvingAgainstBaseURL: false))
        let device = try #require(request.headers["X-Apassy-Device"])
        let timeText = try #require(request.headers["X-Apassy-Time"])
        let nonce = try #require(request.headers["X-Apassy-Nonce"])
        let signatureText = try #require(request.headers["X-Apassy-Signature"])
        #expect(DeviceID.isValid(device))
        #expect(nonce.count == 22)
        let time = try #require(Int64(timeText))
        let string = try SigningStrings.request(
            method: request.method, path: components.percentEncodedPath, deviceID: device, time: time,
            nonce: nonce, body: request.body)
        let signature = try #require(B64U.decode(signatureText))
        #expect(Vectors.verifies(signature: signature, of: string, publicKey: publicKey))
    }

    @Test("a GET is sent over https to the host and port, with four headers and a verifying signature")
    func get() async throws {
        CaptureURLProtocol.reset { _ in .success((200, Data(WireModelTests.inboxJSON.utf8))) }
        let inbox = try await Self.client().inbox()
        #expect(inbox.runs.count == 1)

        let request = try #require(CaptureURLProtocol.captured.withLock { $0.first })
        #expect(request.method == "GET")
        #expect(request.url.scheme == "https")
        #expect(request.url.host == "mac.local")
        #expect(request.url.port == 48620)
        #expect(request.url.path == "/v1/inbox")
        #expect(request.body.isEmpty)
        #expect(request.headers["Cookie"] == nil)
        try Self.verify(request, publicKey: Vectors.requestPublicKey)
        #expect(request.headers["X-Apassy-Time"] == "1790000000")
        #expect(request.headers["X-Apassy-Nonce"]?.count == 22)
    }

    @Test("a POST body reaches the wire as the bytes that were signed")
    func post() async throws {
        CaptureURLProtocol.reset { _ in .success((200, Data(#"{"outcome":"approved"}"#.utf8))) }
        let outcome = try await Self.client().approve(run: Support.run(), remember: false)
        #expect(outcome == .approved)
        let request = try #require(CaptureURLProtocol.captured.withLock { $0.first })
        #expect(request.method == "POST")
        #expect(request.url.path == "/v1/runs/123456789012345/approve")
        #expect(request.headers["Content-Type"] == "application/json")
        #expect(!request.body.isEmpty)
        try Self.verify(request, publicKey: Vectors.requestPublicKey)
    }

    @Test("a DELETE without a body signs the hash of the empty body")
    func delete() async throws {
        CaptureURLProtocol.reset { _ in .success((200, Data(#"{"outcome":"unpaired"}"#.utf8))) }
        try await Self.client().unpair()
        let request = try #require(CaptureURLProtocol.captured.withLock { $0.first })
        #expect(request.method == "DELETE")
        #expect(request.body.isEmpty)
        try Self.verify(request, publicKey: Vectors.requestPublicKey)
    }

    @Test("a connection error moves to the next host, and an error status does not")
    func fallback() async throws {
        CaptureURLProtocol.reset { request in
            request.url.host == "mac.local" ? .failure(URLError(.cannotConnectToHost)) : .success((200, Data(WireModelTests.inboxJSON.utf8)))
        }
        let client = try Self.client()
        _ = try await client.inbox()
        #expect(CaptureURLProtocol.captured.withLock { $0.map { $0.url.host } } == ["mac.local", "10.0.0.2"])
        #expect(await client.lastGoodHost == "10.0.0.2")
        for request in CaptureURLProtocol.captured.withLock({ $0 }) {
            try Self.verify(request, publicKey: Vectors.requestPublicKey)
        }
    }

    @Test("URL errors reach the client as owner errors")
    func errors() async throws {
        CaptureURLProtocol.reset { _ in .failure(URLError(.secureConnectionFailed)) }
        await #expect(throws: CompanionError.notReachable) { try await Self.client().inbox() }
        #expect(CaptureURLProtocol.captured.withLock { $0.count } == 2)

        CaptureURLProtocol.reset { _ in .failure(URLError(.timedOut)) }
        await #expect(throws: CompanionError.notReachable) { try await Self.client().inbox() }

        CaptureURLProtocol.reset { _ in .success((401, ErrorMappingTests.body("unpaired", "No."))) }
        await #expect(throws: CompanionError.unpaired) { try await Self.client().inbox() }
        #expect(CaptureURLProtocol.captured.withLock { $0.count } == 1)
    }

    @Test("a refused challenge that URL loading reports as a cancel is not a cancellation of the task")
    func refusedChallengeIsNotCancellation() async throws {
        CaptureURLProtocol.reset { _ in .failure(URLError(.cancelled)) }
        // The client goes on to the next host and ends with a connection error. It does not throw a
        // CancellationError, which the screens ignore.
        await #expect(throws: CompanionError.notReachable) { try await Self.client().inbox() }
        #expect(CaptureURLProtocol.captured.withLock { $0.count } == 2)
    }

    @Test("cancelling the task ends the request as a cancellation")
    func taskCancellation() async throws {
        CaptureURLProtocol.reset { _ in
            Thread.sleep(forTimeInterval: 1)
            return .success((200, Data(WireModelTests.inboxJSON.utf8)))
        }
        let client = try Self.client()
        let task = Task { try await client.inbox() }
        try await Task.sleep(for: .milliseconds(200))
        task.cancel()
        let started = ContinuousClock.now
        do {
            _ = try await task.value
            Issue.record("A cancelled request answered.")
        } catch {
            #expect(error is CancellationError)
        }
        #expect(ContinuousClock.now - started < .milliseconds(900))
        // Only the first host was tried.
        #expect(CaptureURLProtocol.captured.withLock { $0.count } == 1)
    }
}
