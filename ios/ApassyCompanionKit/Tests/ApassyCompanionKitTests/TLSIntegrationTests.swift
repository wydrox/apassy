// The pin check against a real TLS 1.3 server on the loopback interface. The server has a
// throwaway self-signed certificate (see TLSFixture). This shows what a stub cannot: that the
// delegate accepts the pinned certificate, cancels any other one, and that the session refuses
// TLS 1.2.

import Foundation
import Network
import Security
import Synchronization
import Testing

@testable import ApassyCompanionKit

/// A minimal HTTPS server: it answers every request with 200 and a JSON body, then closes.
final class TLSTestServer: @unchecked Sendable {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "apassy.tls-test-server")
    private let received = Mutex<[String]>([])
    let port: UInt16

    var requests: [String] { received.withLock { $0 } }

    static func identity() throws -> sec_identity_t {
        var items: CFArray?
        let options: [String: Any] = [
            kSecImportExportPassphrase as String: TLSFixture.password,
            kSecImportToMemoryOnly as String: true,
        ]
        let status = SecPKCS12Import(try #require(Data(base64Encoded: TLSFixture.pkcs12Base64)) as CFData, options as CFDictionary, &items)
        try #require(status == errSecSuccess)
        let first = try #require((items as? [[String: Any]])?.first)
        let identity = first[kSecImportItemIdentity as String] as! SecIdentity
        return try #require(sec_identity_create(identity))
    }

    /// The DER bytes of the certificate of the fixture.
    static func certificateDER() throws -> Data {
        var items: CFArray?
        let options: [String: Any] = [
            kSecImportExportPassphrase as String: TLSFixture.password,
            kSecImportToMemoryOnly as String: true,
        ]
        SecPKCS12Import(try #require(Data(base64Encoded: TLSFixture.pkcs12Base64)) as CFData, options as CFDictionary, &items)
        let first = try #require((items as? [[String: Any]])?.first)
        let identity = first[kSecImportItemIdentity as String] as! SecIdentity
        var certificate: SecCertificate?
        SecIdentityCopyCertificate(identity, &certificate)
        return SecCertificateCopyData(try #require(certificate)) as Data
    }

    /// Start a server. `maxTLS12` makes it refuse TLS 1.3.
    static func start(maxTLS12: Bool = false, body: String = #"{"outcome":"denied"}"#) async throws -> TLSTestServer {
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_local_identity(tls.securityProtocolOptions, try identity())
        if maxTLS12 {
            sec_protocol_options_set_max_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
        } else {
            sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv13)
        }
        let parameters = NWParameters(tls: tls)
        parameters.requiredInterfaceType = .loopback
        let listener = try NWListener(using: parameters, on: .any)
        let queue = DispatchQueue(label: "apassy.tls-test-server")
        let ready: UInt16 = try await withCheckedThrowingContinuation { continuation in
            let once = Mutex(false)
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if once.withLock({ let was = $0; $0 = true; return !was }) {
                        continuation.resume(returning: listener.port!.rawValue)
                    }
                case .failed(let error):
                    if once.withLock({ let was = $0; $0 = true; return !was }) {
                        continuation.resume(throwing: error)
                    }
                default: break
                }
            }
            listener.newConnectionHandler = { _ in }
            listener.start(queue: queue)
        }
        return TLSTestServer(listener: listener, port: ready, body: body)
    }

    private init(listener: NWListener, port: UInt16, body: String) {
        self.listener = listener
        self.port = port
        listener.newConnectionHandler = { [self] connection in
            connection.start(queue: DispatchQueue(label: "apassy.tls-test-connection"))
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, _, _ in
                if let data { self.received.withLock { $0.append(String(decoding: data, as: UTF8.self)) } }
                let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n"
                connection.send(content: Data((head + body).utf8), completion: .contentProcessed { _ in connection.cancel() })
            }
        }
    }

    func stop() {
        listener.cancel()
    }
}

@Suite("Pinned TLS against a real server", .serialized)
struct TLSIntegrationTests {
    static func request(path: String = "/v1/inbox") -> TransportRequest {
        TransportRequest(host: "127.0.0.1", port: 0, method: "GET", path: path, headers: ["X-Test": "1"], body: Data())
    }

    static func send(pin: Data, to server: TLSTestServer) async -> Result<TransportResponse, TransportFailure> {
        var request = Self.request()
        request.port = server.port
        do {
            return .success(try await PinnedURLSessionTransport(pin: pin).send(request))
        } catch {
            return .failure(error)
        }
    }

    @Test("the fixture certificate has the pin that openssl computed")
    func fixturePin() throws {
        let der = try TLSTestServer.certificateDER()
        #expect(PinnedTLS.pinText(ofCertificate: der) == TLSFixture.pin)
    }

    @Test("the pinned certificate is accepted")
    func matchingPin() async throws {
        let server = try await TLSTestServer.start()
        defer { server.stop() }
        let pin = try #require(B64U.decode(TLSFixture.pin))
        let result = await Self.send(pin: pin, to: server)
        let response = try result.get()
        #expect(response.status == 200)
        #expect(String(decoding: response.body, as: UTF8.self) == #"{"outcome":"denied"}"#)
        let seen = server.requests.joined()
        #expect(seen.hasPrefix("GET /v1/inbox HTTP/1.1\r\n"))
        #expect(seen.contains("X-Test: 1"))
        #expect(!seen.lowercased().contains("cookie:"))
    }

    @Test("another pin cancels the challenge and reports a pin mismatch, each time")
    func wrongPin() async throws {
        let server = try await TLSTestServer.start()
        defer { server.stop() }
        var wrong = try #require(B64U.decode(TLSFixture.pin))
        wrong[0] ^= 1
        let transport = PinnedURLSessionTransport(pin: wrong)
        var request = Self.request()
        request.port = server.port
        for _ in 0..<2 {
            do {
                _ = try await transport.send(request)
                Issue.record("A wrong pin was accepted.")
            } catch {
                #expect(error == .pinMismatch)
            }
        }
        // The server never saw an HTTP request: the handshake is where the phone stopped.
        #expect(server.requests.isEmpty)
    }

    @Test("a pin mismatch does not fall back to the system trust")
    func noSystemFallback() async throws {
        // The certificate is self-signed and not in the system trust store. A client that fell back
        // would fail for that reason; this client fails for the pin, so the two differ.
        let server = try await TLSTestServer.start()
        defer { server.stop() }
        let result = await Self.send(pin: Data(repeating: 0, count: 32), to: server)
        #expect(throws: TransportFailure.pinMismatch) { try result.get() }
    }

    @Test("the client with the right pin talks to the server, and with a wrong pin says the pin does not match")
    func clientEndToEnd() async throws {
        let server = try await TLSTestServer.start()
        defer { server.stop() }
        let pin = try #require(B64U.decode(TLSFixture.pin))

        let good = CompanionClient(
            deviceID: Vectors.deviceID, endpoint: CompanionEndpoint(hosts: ["127.0.0.1"], port: server.port, pin: pin),
            keys: try Vectors.makeKeys())
        try await good.deny(run: Support.run())
        #expect(await good.lastGoodHost == "127.0.0.1")
        let seen = try #require(server.requests.first)
        #expect(seen.hasPrefix("POST /v1/runs/123456789012345/deny HTTP/1.1\r\n"))
        // The Mac refuses Transfer-Encoding and HTTP/1.0, and needs a Content-Length for a body.
        #expect(seen.contains("Content-Length: 2\r\n"))
        #expect(!seen.lowercased().contains("transfer-encoding"))
        for header in ["X-Apassy-Device", "X-Apassy-Time", "X-Apassy-Nonce", "X-Apassy-Signature"] {
            #expect(seen.contains("\(header): "), "\(header) is missing")
        }

        let bad = CompanionClient(
            deviceID: Vectors.deviceID,
            endpoint: CompanionEndpoint(hosts: ["127.0.0.1"], port: server.port, pin: Data(repeating: 3, count: 32)),
            keys: try Vectors.makeKeys())
        await #expect(throws: CompanionError.pinMismatchOnAllHosts) { try await bad.deny(run: Support.run()) }
        #expect(server.requests.count == 1)
    }

    @Test("a pin mismatch is a pin mismatch for a host with capitals, each time", arguments: ["LOCALHOST", "LocalHost", "localhost"])
    func wrongPinCapitals(host: String) async throws {
        // CFNetwork lowercases the host of a challenge. The mismatch must not depend on the spelling
        // that the client passed, or the client reads it as a cancellation and stops.
        let server = try await TLSTestServer.start()
        defer { server.stop() }
        var wrong = try #require(B64U.decode(TLSFixture.pin))
        wrong[0] ^= 1
        let transport = PinnedURLSessionTransport(pin: wrong)
        var request = Self.request()
        request.host = host
        request.port = server.port
        for _ in 0..<2 {
            do {
                _ = try await transport.send(request)
                Issue.record("A wrong pin was accepted.")
            } catch {
                #expect(error == .pinMismatch)
            }
        }
        #expect(server.requests.isEmpty)
    }

    static func status(of transport: PinnedURLSessionTransport, _ request: TransportRequest) async -> Result<Int, TransportFailure> {
        do {
            return .success(try await transport.send(request).status)
        } catch {
            return .failure(error)
        }
    }

    @Test("the right pin works for a host with capitals")
    func rightPinCapitals() async throws {
        let server = try await TLSTestServer.start()
        defer { server.stop() }
        let pin = try #require(B64U.decode(TLSFixture.pin))
        var request = Self.request()
        request.host = "LOCALHOST"
        request.port = server.port
        #expect(try await PinnedURLSessionTransport(pin: pin).send(request).status == 200)
    }

    @Test("requests at the same time to one host each report their own pin mismatch")
    func concurrentMismatches() async throws {
        // A mark kept per host would be taken by the first request to fail, and the others would
        // read their cancel as a cancellation.
        let server = try await TLSTestServer.start()
        defer { server.stop() }
        var wrong = try #require(B64U.decode(TLSFixture.pin))
        wrong[0] ^= 1
        let transport = PinnedURLSessionTransport(pin: wrong)
        var built = Self.request()
        built.host = "LocalHost"
        built.port = server.port
        let request = built
        let results = await withTaskGroup(of: Result<Int, TransportFailure>.self) { group in
            for _ in 0..<12 {
                group.addTask { await Self.status(of: transport, request) }
            }
            var all: [Result<Int, TransportFailure>] = []
            for await result in group { all.append(result) }
            return all
        }
        #expect(results.count == 12)
        for result in results {
            switch result {
            case .success: Issue.record("A wrong pin was accepted.")
            case .failure(let failure): #expect(failure == .pinMismatch)
            }
        }
        #expect(server.requests.isEmpty)
    }

    /// Sends each host to its own transport, so a test can give one host a wrong pin and the next a
    /// right one, over the same server.
    final class PerHostTransport: CompanionTransport {
        private let transports: [String: PinnedURLSessionTransport]
        private let tried = Mutex<[String]>([])

        init(_ transports: [String: PinnedURLSessionTransport]) {
            self.transports = transports
        }

        var hostsTried: [String] { tried.withLock { $0 } }

        func send(_ request: TransportRequest) async throws(TransportFailure) -> TransportResponse {
            tried.withLock { $0.append(request.host) }
            guard let transport = transports[request.host] else { throw .connection }
            return try await transport.send(request)
        }
    }

    @Test("the client goes on to the next host after a pin mismatch on a host with capitals")
    func nextHostAfterMismatch() async throws {
        let server = try await TLSTestServer.start()
        defer { server.stop() }
        let pin = try #require(B64U.decode(TLSFixture.pin))
        var wrong = pin
        wrong[0] ^= 1
        let hosts = ["LOCALHOST", "127.0.0.1"]
        let transport = PerHostTransport([
            "LOCALHOST": PinnedURLSessionTransport(pin: wrong),
            "127.0.0.1": PinnedURLSessionTransport(pin: pin),
        ])
        let client = CompanionClient(
            deviceID: Vectors.deviceID, endpoint: CompanionEndpoint(hosts: hosts, port: server.port, pin: pin),
            keys: try Vectors.makeKeys(), transport: transport)
        try await client.deny(run: Support.run())
        #expect(transport.hostsTried == hosts)
        #expect(await client.lastGoodHost == "127.0.0.1")
        #expect(server.requests.count == 1)
    }

    @Test("when every host has a wrong pin, capitals or not, the client reports it and tries them all")
    func mismatchOnAllHosts() async throws {
        let server = try await TLSTestServer.start()
        defer { server.stop() }
        let pin = try #require(B64U.decode(TLSFixture.pin))
        var wrong = pin
        wrong[0] ^= 1
        let hosts = ["LOCALHOST", "LocalHost", "127.0.0.1"]
        let real = PinnedURLSessionTransport(pin: wrong)
        let transport = PerHostTransport(Dictionary(uniqueKeysWithValues: hosts.map { ($0, real) }))
        let client = CompanionClient(
            deviceID: Vectors.deviceID, endpoint: CompanionEndpoint(hosts: hosts, port: server.port, pin: wrong),
            keys: try Vectors.makeKeys(), transport: transport)
        await #expect(throws: CompanionError.pinMismatchOnAllHosts) { try await client.deny(run: Support.run()) }
        #expect(transport.hostsTried == hosts)
        #expect(server.requests.isEmpty)
    }

    @Test("the client with the default transport reports a mismatch on a host with capitals")
    func defaultTransportCapitals() async throws {
        let server = try await TLSTestServer.start()
        defer { server.stop() }
        let client = CompanionClient(
            deviceID: Vectors.deviceID,
            endpoint: CompanionEndpoint(hosts: ["LOCALHOST", "LocalHost"], port: server.port, pin: Data(repeating: 3, count: 32)),
            keys: try Vectors.makeKeys())
        await #expect(throws: CompanionError.pinMismatchOnAllHosts) { try await client.deny(run: Support.run()) }
        #expect(server.requests.isEmpty)
    }

    @Test("a server that offers only TLS 1.2 is refused")
    func tls12Refused() async throws {
        let server = try await TLSTestServer.start(maxTLS12: true)
        defer { server.stop() }
        let pin = try #require(B64U.decode(TLSFixture.pin))
        let result = await Self.send(pin: pin, to: server)
        let failure = try #require({ () -> TransportFailure? in
            if case .failure(let failure) = result { return failure }
            return nil
        }())
        #expect(failure == .tls)
        #expect(server.requests.isEmpty)
    }

    @Test("a closed port is a connection error")
    func closedPort() async throws {
        let server = try await TLSTestServer.start()
        let port = server.port
        server.stop()
        try await Task.sleep(for: .milliseconds(200))
        var request = Self.request()
        request.port = port
        let pin = try #require(B64U.decode(TLSFixture.pin))
        do {
            _ = try await PinnedURLSessionTransport(pin: pin).send(request)
            Issue.record("A closed port answered.")
        } catch {
            #expect(error == .connection)
        }
    }
}
