import ApassyVaultKit
import Foundation
import Network
import Security
import Synchronization
import Testing

@testable import ApassyVaultCore

// The pinned requests of the watch's transport (contract ios-core-v1 section 2.1, node-pairing-v1
// section 4; plan S2–S3 unit N6) against a real TLS 1.3 server on the loopback interface. The
// server has the throwaway self-signed certificate of the companion tests (a copy of
// `TLSFixture`): it is in no system trust store, so a request that fell back to the system trust
// would fail for another reason than the pin. Synthetic values only.

/// A throwaway self-signed ECDSA P-256 certificate and key, as PKCS#12 with the password "test",
/// copied from `ApassyCompanionKitTests/Vectors.swift`. It secures nothing: the common name is
/// `apassy-test.invalid`.
enum CoreTLSFixture {
    static let pkcs12Base64 =
        "MIIDZwIBAzCCAy0GCSqGSIb3DQEHAaCCAx4EggMaMIIDFjCCAe8GCSqGSIb3DQEHBqCCAeAwggHcAgEAMIIB1QYJ" +
        "KoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIb1+0jdjoWw4CAggAgIIBqD2Bk/qoT8Io+BY4Oua2hXxtET0IkJ95" +
        "bd6bqCp7H0GHULq37ZlNTlVhiiRIH4L8ApEWBdERkfY8rQFJy8lRRNwWyIO9dHljZ3jqxBuCCx8dyalqFCgUPuwM" +
        "4873bZrL0ORaX3/lR8SK4kftFJYk7bviyZkEq5TerXS/mWwMpkinus7QyDLrV0Iy6u/xjwvFLUkME15HHFALuOKT" +
        "exJsLvDyoTSPH4eqZa0Vq4/s7i3SVpOlqT0t5FQNSrSc0Lhnb6267rjF7WGjcpJkzfBsWh0oAas2mQVlBub8a5QR" +
        "1UY/NEw8JLtYAtRC/edlA0eZ/RQpo/QIODUwivMy6txG5LpzCky/U6LpmNyAPUpz7twpXui2TPstxvtuxiO9yvKL" +
        "hGTxmNeJigH8WglamFGz0fep/eYpci0QeM4AQI6+p6vyU0Xg7p+sEdFq/jrQB/YrOTWI4BoxrqEyH7qRwQos64b6" +
        "v4eLbChNBa7LiPADgkxL4btR4VsqlOxV8ksts1PXaZc0axwixwup8u9JlcZZQdzhgbo5yKQ+LJxAFHD8sZYfQcmB" +
        "kNq7yFIwggEfBgkqhkiG9w0BBwGgggEQBIIBDDCCAQgwggEEBgsqhkiG9w0BDAoBAqCBtDCBsTAcBgoqhkiG9w0B" +
        "DAEDMA4ECBQ74KYg/QWlAgIIAASBkLwzg5mbMAIExj191mE1lBUJ17nO55iioKZ07/kfzBH6twaAgDLOSdrDGd+6" +
        "GhNcWgKXLt2Jg9cf5rFmSSbWqTNLZaPilXAy1a5ReFQjSr+mj/Hm8OoJdW65RFmb6iOh49w6J4/jftCHn2/wKDb3" +
        "iljC+P8Wv4p1o0rx2nFRv2Zf3twOqkbybgWOJpd9xlclhTE+MBcGCSqGSIb3DQEJFDEKHggAdABlAHMAdDAjBgkq" +
        "hkiG9w0BCRUxFgQUWfpH+v/hrUnP2ap8VleDGfhtAzwwMTAhMAkGBSsOAwIaBQAEFF9XWxKxZTxtZI0cXBZ2tDLL" +
        "YEvTBAhnu2gRnhheJwICCAA="
    static let password = "test"
    /// The pin of its certificate, computed with openssl when the fixture was made.
    static let pin = "75r2QEN0o4P_I3ifA2mcoAJhP8Px4o3d7i4cSDeXO-4"
    /// The pin of the DER bytes `30 00`: `PIN_OF_3000` of `src/net/pin.rs` and `pinOf3000` of the
    /// companion vectors.
    static let pinOf3000 = "5PYNCqbX89O2pklLHIYbmfZJxvnsUauvIBsg8pcyfJU"

    static func identity() throws -> SecIdentity {
        var items: CFArray?
        let options: [String: Any] = [
            kSecImportExportPassphrase as String: password,
            kSecImportToMemoryOnly as String: true,
        ]
        let status = SecPKCS12Import(try #require(Data(base64Encoded: pkcs12Base64)) as CFData, options as CFDictionary, &items)
        try #require(status == errSecSuccess)
        let first = try #require((items as? [[String: Any]])?.first)
        return first[kSecImportItemIdentity as String] as! SecIdentity
    }

    static func certificateDER() throws -> Data {
        var certificate: SecCertificate?
        SecIdentityCopyCertificate(try identity(), &certificate)
        return SecCertificateCopyData(try #require(certificate)) as Data
    }
}

/// A minimal HTTPS server with TLS 1.3 only: it answers every request with 200 and a JSON body, then
/// closes. It records what it received.
final class CoreTLSServer: @unchecked Sendable {
    private let listener: NWListener
    private let received = Mutex<[String]>([])
    let port: UInt16

    var requests: [String] { received.withLock { $0 } }

    static func start() async throws -> CoreTLSServer {
        let tls = NWProtocolTLS.Options()
        let identity = try #require(sec_identity_create(try CoreTLSFixture.identity()))
        sec_protocol_options_set_local_identity(tls.securityProtocolOptions, identity)
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv13)
        let parameters = NWParameters(tls: tls)
        parameters.requiredInterfaceType = .loopback
        let listener = try NWListener(using: parameters, on: .any)
        let port: UInt16 = try await withCheckedThrowingContinuation { continuation in
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
            listener.start(queue: DispatchQueue(label: "apassy.core-tls-test-server"))
        }
        return CoreTLSServer(listener: listener, port: port)
    }

    private init(listener: NWListener, port: UInt16) {
        self.listener = listener
        self.port = port
        let body = #"{"ok":true}"#
        listener.newConnectionHandler = { [self] connection in
            connection.start(queue: DispatchQueue(label: "apassy.core-tls-test-connection"))
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, _, _ in
                if let data { self.received.withLock { $0.append(String(decoding: data, as: UTF8.self)) } }
                let head =
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n"
                connection.send(content: Data((head + body).utf8), completion: .contentProcessed { _ in connection.cancel() })
            }
        }
    }

    func stop() { listener.cancel() }
}

@Suite("The pinned requests of the watch transport", .serialized)
struct CoreTransportPinTests {
    /// The request JSON of the core (contract ios-core-v1 section 2.1).
    static func request(id: UInt64, url: String, pin: String?) -> String {
        var object: [String: Any] = [
            "id": id, "method": "GET", "url": url,
            "headers": [["Authorization", "Bearer apassy_acc_synthetic"], ["User-Agent", "apassy-sync/1"]],
            "timeout_ms": 10_000,
        ]
        if let pin { object["pin"] = pin }
        let data = try! JSONSerialization.data(withJSONObject: object)
        return String(decoding: data, as: UTF8.self)
    }

    static func answer(_ text: String) throws -> [String: Any] {
        try #require(try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
    }

    @Test("the pin of a certificate is the format of the core and of PinnedTLS")
    func pinFormat() throws {
        #expect(CorePin.text(ofCertificate: Data([0x30, 0x00])) == CoreTLSFixture.pinOf3000)
        #expect(CorePin.text(ofCertificate: try CoreTLSFixture.certificateDER()) == CoreTLSFixture.pin)
        #expect(CorePin.isValid(CoreTLSFixture.pin))
        #expect(!CorePin.isValid(String(CoreTLSFixture.pin.dropLast())))
        #expect(!CorePin.isValid(CoreTLSFixture.pin + "A"))
        #expect(!CorePin.isValid(CoreTLSFixture.pin.replacingOccurrences(of: "_", with: "/")))
        #expect(!CorePin.isValid(""))
    }

    @Test("a request with the pin of the server reaches it")
    func matchingPin() async throws {
        let server = try await CoreTLSServer.start()
        defer { server.stop() }
        let transport = URLSessionCoreTransport()
        let text = transport.perform(
            Self.request(id: 1, url: "https://127.0.0.1:\(server.port)/v1/questions", pin: CoreTLSFixture.pin))
        let answer = try Self.answer(text)
        #expect(answer["status"] as? Int == 200, "\(text)")
        #expect(server.requests.joined().hasPrefix("GET /v1/questions HTTP/1.1\r\n"))
        #expect(transport.problem(since: 0) == nil, "a JSON answer leaves no problem")
    }

    @Test("another pin is a pin mismatch before any request byte, each time")
    func wrongPin() async throws {
        let server = try await CoreTLSServer.start()
        defer { server.stop() }
        let transport = URLSessionCoreTransport()
        var other = Array(CoreTLSFixture.pin)
        other[0] = other[0] == "A" ? "B" : "A"
        for id in UInt64(2)...3 {
            let text = transport.perform(
                Self.request(id: id, url: "https://127.0.0.1:\(server.port)/v1/questions", pin: String(other)))
            #expect(try Self.answer(text)["error"] as? String == "pin_mismatch", "\(text)")
        }
        #expect(server.requests.isEmpty, "the server never saw an HTTP request")
    }

    @Test("a request without a pin keeps the system trust: the node's certificate is refused, not as a pin")
    func systemTrustRefusesTheNode() async throws {
        let server = try await CoreTLSServer.start()
        defer { server.stop() }
        let transport = URLSessionCoreTransport()
        let text = transport.perform(
            Self.request(id: 4, url: "https://127.0.0.1:\(server.port)/v1/questions", pin: nil))
        let error = try Self.answer(text)["error"] as? String
        #expect(error == "connect", "\(text)")
        #expect(server.requests.isEmpty)
        let line = try #require(transport.problem(since: 0))
        #expect(line.hasPrefix("connect, URLError -12"), "\(line)")
        #expect(!line.contains("127.0.0.1") && !line.contains("Bearer"), "codes only: \(line)")
    }

    @Test("a pin with http, or a pin of another form, is never sent")
    func badPinnedRequests() throws {
        let transport = URLSessionCoreTransport()
        for (id, url, pin) in [
            (UInt64(5), "http://127.0.0.1:9/v1/questions", CoreTLSFixture.pin),
            (6, "https://127.0.0.1:9/v1/questions", "short"),
            (7, "https://127.0.0.1:9/v1/questions", CoreTLSFixture.pin + "="),
        ] {
            let text = transport.perform(Self.request(id: id, url: url, pin: pin))
            #expect(try Self.answer(text)["error"] as? String == "connect", "\(url) \(pin)")
            #expect(transport.problem(since: 0) == "connect, the pin of the request is not valid")
        }
    }

    @Test("a call of the core that made no request says so")
    func noRequest() {
        let transport = URLSessionCoreTransport()
        let mark = transport.sendCount()
        #expect(transport.problem(since: mark) == "no request was made")
        _ = transport.perform("not json")
        #expect(transport.problem(since: mark) == "connect, the request of the core is not valid")
        #expect(transport.problem(since: transport.sendCount()) == "no request was made")
    }

    @Test("a refused connection is connect with its error code, and no system proxy is turned off")
    func refusedConnection() throws {
        let configuration = URLSessionCoreTransport.configuration(minimumTLS: .TLSv12)
        #expect(configuration.connectionProxyDictionary == nil, "nil keeps the proxies of the system")
        #expect(configuration.waitsForConnectivity)
        let transport = URLSessionCoreTransport()
        let object: [String: Any] = [
            "id": 8, "method": "GET", "url": "http://127.0.0.1:9/v1/questions", "headers": [[String]](),
            "timeout_ms": 2_000,
        ]
        let text = transport.perform(String(decoding: try JSONSerialization.data(withJSONObject: object), as: UTF8.self))
        #expect(try Self.answer(text)["error"] as? String == "connect", "\(text)")
        let line = try #require(transport.problem(since: 0))
        #expect(line.hasPrefix("connect, "), "\(line)")
        #expect(line.hasSuffix(" ms"), "\(line)")
    }
}
