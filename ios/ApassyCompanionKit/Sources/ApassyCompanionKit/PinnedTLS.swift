// Pinned TLS (contract section 3, "Pin").
//
// The phone trusts one certificate: the one whose SHA-256 is the pin from the pairing link. It
// ignores the host name and the system trust store, and it never falls back to the system trust.

import Foundation
import Security
import Synchronization

/// The pin check and the session configuration.
public enum PinnedTLS {
    /// The pin of a certificate: `b64u(SHA-256(certificate DER))`.
    public static func pinText(ofCertificate der: Data) -> String {
        B64U.encode(Hashing.sha256(der))
    }

    /// Whether the certificate has this pin. The comparison takes the same time for any input of
    /// the same length.
    public static func matches(pinText: String, certificate der: Data) -> Bool {
        Hashing.constantTimeEqual(Data(pinText.utf8), Data(self.pinText(ofCertificate: der).utf8))
    }

    /// Whether the certificate has this pin, given as its 32 bytes.
    public static func matches(pin: Data, certificate der: Data) -> Bool {
        matches(pinText: B64U.encode(pin), certificate: der)
    }

    /// The session configuration: nothing on disk, no cache, no cookies, no proxy, no cellular,
    /// a short timeout, and TLS 1.3 at least.
    public static func makeConfiguration() -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.urlCredentialStorage = nil
        configuration.timeoutIntervalForRequest = 5
        configuration.timeoutIntervalForResource = 15
        configuration.tlsMinimumSupportedProtocolVersion = .TLSv13
        configuration.waitsForConnectivity = false
        // The Mac is on the local network. A proxy or the mobile network would only leak the request.
        configuration.connectionProxyDictionary = [:]
        configuration.allowsCellularAccess = false
        return configuration
    }
}

/// Answers each server trust challenge by the pin, and refuses everything else.
///
/// A failed pin is recorded under the identifier of the task that met it, not under a host name:
/// the name in the challenge is not always the string the client passed (CFNetwork lowercases
/// it), and one host can have two requests at the same time.
final class PinnedTLSDelegate: NSObject, URLSessionTaskDelegate, Sendable {
    private let pin: Data
    private let mismatchedTasks = Mutex<Set<Int>>([])

    init(pin: Data) {
        self.pin = pin
    }

    /// The challenge of a task. For a server trust challenge, this method takes the place of the
    /// session level one, and it says which task met the challenge.
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        let space = challenge.protectionSpace
        // Only server trust. Never the default handling.
        guard space.authenticationMethod == NSURLAuthenticationMethodServerTrust, let trust = space.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first,
            PinnedTLS.matches(pin: pin, certificate: SecCertificateCopyData(leaf) as Data)
        else {
            mismatchedTasks.withLock { _ = $0.insert(task.taskIdentifier) }
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    /// A redirect could send the signed request to another host. The Mac never redirects.
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }

    /// Whether the challenge of this task failed the pin. It clears the mark.
    func takePinMismatch(taskIdentifier: Int) -> Bool {
        mismatchedTasks.withLock { $0.remove(taskIdentifier) != nil }
    }
}
