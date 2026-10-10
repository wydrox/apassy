import Foundation
import Testing

@testable import ApassyCompanionKit

@Suite("Pinned TLS")
struct PinnedTLSTests {
    static let der = Data([0x30, 0x00])

    @Test("the contract vector matches")
    func vector() {
        #expect(PinnedTLS.matches(pinText: Vectors.pinOf3000, certificate: Self.der))
        #expect(PinnedTLS.matches(pin: Vectors.bytes(Vectors.pinOf3000), certificate: Self.der))
    }

    @Test("another certificate does not match")
    func otherCertificate() {
        #expect(!PinnedTLS.matches(pinText: Vectors.pinOf3000, certificate: Data([0x30, 0x01, 0x00])))
        #expect(!PinnedTLS.matches(pinText: Vectors.pinOf3000, certificate: Data()))
    }

    @Test("a pin with one changed character, a wrong size, or other text does not match")
    func changedPin() {
        for index in 0..<Vectors.pinOf3000.count {
            #expect(!PinnedTLS.matches(pinText: Vectors.changed(Vectors.pinOf3000, at: index), certificate: Self.der))
        }
        #expect(!PinnedTLS.matches(pinText: String(Vectors.pinOf3000.dropLast()), certificate: Self.der))
        #expect(!PinnedTLS.matches(pinText: Vectors.pinOf3000 + "A", certificate: Self.der))
        #expect(!PinnedTLS.matches(pinText: "", certificate: Self.der))
        #expect(!PinnedTLS.matches(pin: Data(count: 32), certificate: Self.der))
        #expect(!PinnedTLS.matches(pin: Data(), certificate: Self.der))
        // The standard alphabet is another text: the pin is base64url.
        #expect(!PinnedTLS.matches(pinText: Vectors.pinOf3000 + "=", certificate: Self.der))
    }

    @Test("the session is ephemeral, has no cache, no cookies, TLS 1.3 at least, and a short timeout")
    func configuration() {
        let configuration = PinnedTLS.makeConfiguration()
        #expect(configuration.urlCache == nil)
        #expect(configuration.httpCookieStorage == nil)
        #expect(configuration.httpShouldSetCookies == false)
        #expect(configuration.urlCredentialStorage == nil)
        #expect(configuration.requestCachePolicy == .reloadIgnoringLocalAndRemoteCacheData)
        #expect(configuration.tlsMinimumSupportedProtocolVersion == .TLSv13)
        #expect(configuration.timeoutIntervalForRequest == 5)
        #expect(configuration.waitsForConnectivity == false)
        // Each transport request limits this permission to a numeric Tailscale IPv4 host.
        #expect(configuration.allowsCellularAccess == true)
        // An ephemeral configuration has no disk cache and no persistent storage.
        #expect(configuration.identifier == nil)
    }

    @Test("URL errors sort into transport failures")
    func classification() {
        func failure(_ code: Int) -> TransportFailure {
            TransportErrorClassifier.classify(NSError(domain: NSURLErrorDomain, code: code))
        }
        #expect(failure(NSURLErrorCannotConnectToHost) == .connection)
        #expect(failure(NSURLErrorTimedOut) == .connection)
        #expect(failure(NSURLErrorCannotFindHost) == .connection)
        #expect(failure(NSURLErrorNetworkConnectionLost) == .connection)
        #expect(failure(NSURLErrorNotConnectedToInternet) == .connection)
        #expect(failure(NSURLErrorSecureConnectionFailed) == .tls)
        #expect(failure(NSURLErrorServerCertificateUntrusted) == .tls)
        #expect(failure(NSURLErrorServerCertificateHasUnknownRoot) == .tls)
        #expect(failure(NSURLErrorCancelled) == .cancelled)
        #expect(TransportErrorClassifier.classify(NSError(domain: "other", code: 1)) == .connection)
    }

    @Test("the local network denial is found in the error or in an underlying error")
    func localNetworkDenied() {
        let path = "unsatisfied (Local network prohibited), interface: en0"
        let direct = NSError(
            domain: NSURLErrorDomain, code: NSURLErrorNotConnectedToInternet,
            userInfo: ["_NSURLErrorNWPathKey": path])
        #expect(TransportErrorClassifier.classify(direct) == .localNetworkDenied)

        let underlying = NSError(domain: "kCFErrorDomainCFNetwork", code: -1009, userInfo: ["reason": path])
        let wrapped = NSError(
            domain: NSURLErrorDomain, code: NSURLErrorCannotConnectToHost,
            userInfo: [NSUnderlyingErrorKey: underlying])
        #expect(TransportErrorClassifier.classify(wrapped) == .localNetworkDenied)

        let policy = NSError(domain: "NWErrorDomain", code: -65570)
        #expect(TransportErrorClassifier.classify(policy) == .localNetworkDenied)

        // Wi-Fi off gives the same URL error code without the local network mark.
        let offline = NSError(
            domain: NSURLErrorDomain, code: NSURLErrorNotConnectedToInternet,
            userInfo: ["_NSURLErrorNWPathKey": "unsatisfied (No network route)"])
        #expect(TransportErrorClassifier.classify(offline) == .connection)
    }
}
