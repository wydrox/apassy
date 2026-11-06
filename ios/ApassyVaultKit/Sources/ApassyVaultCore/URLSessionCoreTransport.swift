import ApassyCoreFFI
import ApassyVaultKit
import CryptoKit
import Foundation
import Security
import Synchronization

/// The relay HTTP of the core on the Apple Watch (ADR 0039 section 5): watchOS gives this app no
/// BSD sockets, so the core hands each request to URLSession (`apassy_core_set_http_transport`).
///
/// The session is ephemeral: no cookie, no cache, no credential storage. Redirects are not
/// followed. Each `send` blocks the calling thread of the core until the answer, the deadline of
/// the request, or `cancel`. The request holds the bearer; no copy of it stays after `send`.
///
/// A request to a pinned origin (a node on the tailnet, contract node-pairing-v1 section 4)
/// carries the pin: it goes through a second session with TLS 1.3 only, and its task accepts
/// only the leaf certificate with that pin, never the system trust store. Another certificate
/// answers `pin_mismatch` before any request byte. Only the watch installs the transport; the
/// type builds everywhere so that the macOS tests reach it.
///
/// Both sessions keep the network settings of the system, proxies included: with the iPhone near,
/// the watch reaches the internet through it. A request waits for a network path up to its
/// deadline instead of failing at once. Each failure is kept as a line of codes for the screen
/// (`problem(since:)`).
final class URLSessionCoreTransport: Sendable {
    static let shared = URLSessionCoreTransport()
    private static let installed = Mutex(false)

    /// The largest answer body: the limit of the core (2 MiB).
    private static let maxBody = 2 * 1024 * 1024

    private let session: URLSession
    /// The session of the pinned requests: TLS 1.3 at least, as the core's own pinned client.
    private let pinnedSession: URLSession
    private let state = Mutex(State())
    /// The requests so far, and the line of the last one, nil after a JSON answer.
    private let record = Mutex<(sends: UInt64, problem: String?)>((0, nil))

    private struct Running {
        let task: URLSessionTask
        let exchange: Exchange
    }

    private struct State {
        var running: [UInt64: Running] = [:]
        /// Requests that `cancel` named before their `send` started.
        var cancelled: Set<UInt64> = []
    }

    init() {
        session = URLSession(configuration: Self.configuration(minimumTLS: .TLSv12))
        pinnedSession = URLSession(configuration: Self.configuration(minimumTLS: .TLSv13))
    }

    static func configuration(minimumTLS: tls_protocol_version_t) -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.urlCredentialStorage = nil
        // Wait for a path instead of failing at once: `perform` ends the wait at the deadline of
        // the request, and the bytes sent decide `connect` or `broken`.
        configuration.waitsForConnectivity = true
        configuration.allowsCellularAccess = true
        // No `connectionProxyDictionary`: an empty one turns off the proxies of the system, and with
        // them the path of the watch through the paired iPhone. A pinned request needs no such
        // guard: it accepts only the pinned leaf.
        configuration.tlsMinimumSupportedProtocolVersion = minimumTLS
        // Each request has its own deadline (`timeout_ms`); this only bounds a stuck one.
        configuration.timeoutIntervalForResource = 120
        return configuration
    }

    #if os(watchOS)
    /// Install the transport once, before the first `apassy_core_new`.
    static func install() {
        let first = installed.withLock { (done: inout Bool) -> Bool in
            defer { done = true }
            return !done
        }
        guard first else { return }
        apassy_core_set_http_transport(sendCallback, cancelCallback, Unmanaged.passUnretained(shared).toOpaque())
    }

    private static let sendCallback: apassy_http_send = { context, request in
        guard let context else { return strdup(Answer.failure("broken")) }
        let transport = Unmanaged<URLSessionCoreTransport>.fromOpaque(context).takeUnretainedValue()
        return strdup(transport.perform(String(cString: request)))
    }

    private static let cancelCallback: apassy_http_cancel = { context, id in
        guard let context else { return }
        Unmanaged<URLSessionCoreTransport>.fromOpaque(context).takeUnretainedValue().cancel(id)
    }
    #endif

    // MARK: - One request

    private struct Request: Decodable {
        var id: UInt64
        var method: String
        var url: String
        var headers: [[String]]
        var body_b64u: String?
        var timeout_ms: UInt64
        /// The pin of a pinned origin (node-pairing-v1 section 4); absent for system trust.
        var pin: String?
    }

    /// The headers that URLSession writes itself.
    private static let reserved: Set<String> = ["host", "content-length", "connection", "transfer-encoding"]

    /// One request of the core: its JSON in, the answer JSON out (contract ios-core-v1 section 2.1).
    func perform(_ json: String) -> String {
        record.withLock { $0.sends += 1 }
        // A request that cannot be read was not sent: nothing reached the relay.
        guard let request = try? JSONDecoder().decode(Request.self, from: Data(json.utf8)),
            let url = URL(string: request.url), url.scheme == "https" || url.scheme == "http"
        else { return unsent("the request of the core is not valid") }
        // A pinned request is https with a pin of the contract's form, or it is not sent.
        if let pin = request.pin, url.scheme != "https" || !CorePin.isValid(pin) {
            return unsent("the pin of the request is not valid")
        }
        let seconds = Double(min(max(request.timeout_ms, 1), 600_000)) / 1000
        var urlRequest = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: seconds)
        urlRequest.httpMethod = request.method
        urlRequest.httpShouldHandleCookies = false
        for pair in request.headers {
            guard pair.count == 2 else { return unsent("a header of the request is not valid") }
            guard !Self.reserved.contains(pair[0].lowercased()) else { continue }
            urlRequest.addValue(pair[1], forHTTPHeaderField: pair[0])
        }
        if let body = request.body_b64u {
            guard let data = Base64URL.decode(body) else { return unsent("the body of the request is not valid") }
            urlRequest.httpBody = data
        }
        let exchange = Exchange(limit: Self.maxBody, pin: request.pin)
        let task = (request.pin == nil ? session : pinnedSession).dataTask(with: urlRequest)
        task.delegate = exchange
        let started = state.withLock { (state: inout State) -> Bool in
            if state.cancelled.remove(request.id) != nil { return false }
            state.running[request.id] = Running(task: task, exchange: exchange)
            return true
        }
        guard started else { return Answer.failure("broken") }
        defer { state.withLock { (state: inout State) in state.running[request.id] = nil } }
        let began = ContinuousClock.now
        task.resume()
        if exchange.done.wait(timeout: .now() + .milliseconds(Int(seconds * 1000) + 1000)) == .timedOut {
            // Past the deadline of the request. The metrics decide: `connect` when no byte left this
            // watch (it waited for a path), else `broken`, as it may have reached the relay.
            exchange.passDeadline()
            task.cancel()
            exchange.done.wait()
        }
        note(exchange.problem(after: began.duration(to: .now)))
        return exchange.answer()
    }

    /// A request that is not sent: `connect`, with its line.
    private func unsent(_ problem: String) -> String {
        note("connect, \(problem)")
        return Answer.failure("connect")
    }

    /// The number of requests so far: the mark of the start of a call of the core.
    func sendCount() -> UInt64 { record.withLock { $0.sends } }

    /// The line of the last request when one was made since `mark`; else a line that says none
    /// was (the core failed before the network).
    func problem(since mark: UInt64) -> String? {
        record.withLock { record in record.sends == mark ? "no request was made" : record.problem }
    }

    private func note(_ problem: String?) {
        record.withLock { $0.problem = problem }
    }

    private func cancel(_ id: UInt64) {
        let running = state.withLock { (state: inout State) -> Running? in
            if let running = state.running[id] { return running }
            state.cancelled.insert(id)
            // Keep only recent marks: the ids of the core grow.
            if state.cancelled.count > 64, let oldest = state.cancelled.min() { state.cancelled.remove(oldest) }
            return nil
        }
        // A cancelled request answers `broken`, as the core expects.
        running?.exchange.end()
        running?.task.cancel()
    }
}

/// The answer JSON of `send`.
private enum Answer {
    static func failure(_ kind: String) -> String { #"{"error":"\#(kind)"}"# }

    static func success(status: Int, headers: [[String]], body: Data) -> String {
        let object: [String: Any] = ["status": status, "headers": headers, "body_b64u": Base64URL.encode(body)]
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.withoutEscapingSlashes])
        else { return failure("protocol") }
        return String(decoding: data, as: UTF8.self)
    }
}

/// The pin of a node certificate (contract node-pairing-v1 section 4): `b64u(SHA-256(DER))` of the
/// leaf, 43 characters. The format of `PinnedTLS.pinText` and of the core.
enum CorePin {
    static func isValid(_ text: String) -> Bool {
        text.utf8.count == 43 && Base64URL.decode(text)?.count == 32
            && text.utf8.allSatisfy { byte in
                (0x30...0x39).contains(byte) || (0x41...0x5A).contains(byte) || (0x61...0x7A).contains(byte)
                    || byte == 0x2D || byte == 0x5F
            }
    }

    static func text(ofCertificate der: Data) -> String {
        Base64URL.encode(Data(SHA256.hash(data: der)))
    }

    /// Whether the leaf of `trust` has the pin `pin`. The texts are compared in the same time for
    /// any input of the same length; a later certificate of the chain never counts.
    static func leafMatches(_ trust: SecTrust, pin: String) -> Bool {
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first else {
            return false
        }
        let seen = Array(text(ofCertificate: SecCertificateCopyData(leaf) as Data).utf8)
        let wanted = Array(pin.utf8)
        guard seen.count == wanted.count else { return false }
        var difference: UInt8 = 0
        for index in seen.indices { difference |= seen[index] ^ wanted[index] }
        return difference == 0
    }
}

/// The delegate of one task: it keeps the answer, caps the body, refuses redirects, and counts the
/// bytes sent, so that a failure before the first byte is `connect` (the request did not reach the
/// relay) and any later one is `broken` (it may have landed). With a pin it answers the server
/// trust challenge by the pin alone: another leaf is `pin_mismatch`.
private final class Exchange: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    let done = DispatchSemaphore(value: 0)
    private let limit: Int
    private let pin: String?
    private let lock = NSLock()
    private var response: HTTPURLResponse?
    private var body = Data()
    private var failure: String?
    private var sentBytes: Int64?
    private var error: NSError?
    private var waited = false
    private var deadlinePassed = false

    init(limit: Int, pin: String?) {
        self.limit = limit
        self.pin = pin
    }

    /// The server trust of this task. Without a pin: the system's handling, as before. With a pin:
    /// only the pinned leaf, and never the default handling or another kind of challenge.
    func urlSession(
        _ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard let pin else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        let space = challenge.protectionSpace
        guard space.authenticationMethod == NSURLAuthenticationMethodServerTrust, let trust = space.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        guard CorePin.leafMatches(trust, pin: pin) else {
            lock.withLock { failure = "pin_mismatch" }
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    /// The request was cancelled: it answers `broken`.
    func end() {
        lock.withLock {
            if failure == nil { failure = "broken" }
        }
    }

    /// The request passed its deadline: its completion is `connect` only when no byte was sent.
    func passDeadline() {
        lock.withLock { deadlinePassed = true }
    }

    /// One line for the screen when the request failed or the answer is not JSON, else nil. Codes
    /// and counts only: no header, body, or URL.
    func problem(after elapsed: Duration) -> String? {
        lock.withLock {
            var parts: [String] = []
            if let failure {
                parts.append(failure)
                if let error {
                    parts.append("\(error.domain == NSURLErrorDomain ? "URLError" : error.domain) \(error.code)")
                    if let domain = error.userInfo["_kCFStreamErrorDomainKey"],
                        let code = error.userInfo["_kCFStreamErrorCodeKey"]
                    {
                        parts.append("stream \(domain)/\(code)")
                    }
                    if let underlying = error.userInfo[NSUnderlyingErrorKey] as? NSError {
                        parts.append("under \(underlying.domain) \(underlying.code)")
                    }
                    if let reason = error.userInfo[NSURLErrorNetworkUnavailableReasonKey] as? Int {
                        parts.append("unavailable \(reason)")
                    }
                }
                if deadlinePassed { parts.append("deadline") }
            } else if let response {
                let type = response.value(forHTTPHeaderField: "Content-Type") ?? "no type"
                guard !type.contains("json") else { return nil }
                parts.append("HTTP \(response.statusCode) \(type)")
            } else {
                return nil
            }
            if waited { parts.append("waited for a network") }
            if let sentBytes { parts.append("\(sentBytes) B sent") }
            let (seconds, attoseconds) = elapsed.components
            parts.append("\(seconds * 1000 + attoseconds / 1_000_000_000_000_000) ms")
            return parts.joined(separator: ", ")
        }
    }

    func urlSession(_ session: URLSession, taskIsWaitingForConnectivity task: URLSessionTask) {
        lock.withLock { waited = true }
    }

    func answer() -> String {
        lock.withLock {
            if let failure { return Answer.failure(failure) }
            guard let response else { return Answer.failure("protocol") }
            let headers = response.allHeaderFields.compactMap { name, value -> [String]? in
                guard let name = name as? String else { return nil }
                return [name, value as? String ?? "\(value)"]
            }
            return Answer.success(status: response.statusCode, headers: headers, body: body)
        }
    }

    func urlSession(
        _ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
        completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void
    ) {
        let allowed = lock.withLock { () -> Bool in
            guard let http = response as? HTTPURLResponse, http.expectedContentLength <= Int64(limit) else {
                failure = "protocol"
                return false
            }
            self.response = http
            return true
        }
        completionHandler(allowed ? .allow : .cancel)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        let tooLarge = lock.withLock { () -> Bool in
            body.append(data)
            guard body.count > limit else { return false }
            failure = "protocol"
            body = Data()
            return true
        }
        if tooLarge { dataTask.cancel() }
    }

    func urlSession(
        _ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        // The core reads a redirect as the answer; it never follows one.
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
        let sent = metrics.transactionMetrics.reduce(Int64(0)) {
            $0 + $1.countOfRequestHeaderBytesSent + $1.countOfRequestBodyBytesSent
        }
        lock.withLock { sentBytes = sent }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        lock.withLock {
            if let error {
                self.error = error as NSError
                if failure == nil {
                    failure =
                        deadlinePassed
                        ? (sentBytes == 0 ? "connect" : "broken") : Self.classify(error, sentBytes: sentBytes)
                }
            }
            if error == nil, response == nil, failure == nil { failure = "protocol" }
        }
        done.signal()
    }

    /// `connect` only when no byte of the request left this watch: the metrics say none was sent,
    /// or, without metrics, the error comes before any connection. Any byte sent is `broken`.
    private static func classify(_ error: any Error, sentBytes: Int64?) -> String {
        if let sentBytes { return sentBytes == 0 ? "connect" : "broken" }
        let ns = error as NSError
        guard ns.domain == NSURLErrorDomain else { return "broken" }
        switch ns.code {
        case NSURLErrorCannotFindHost, NSURLErrorCannotConnectToHost, NSURLErrorDNSLookupFailed,
            NSURLErrorNotConnectedToInternet, NSURLErrorInternationalRoamingOff, NSURLErrorCallIsActive,
            NSURLErrorDataNotAllowed, NSURLErrorAppTransportSecurityRequiresSecureConnection,
            NSURLErrorSecureConnectionFailed, NSURLErrorServerCertificateHasBadDate,
            NSURLErrorServerCertificateUntrusted, NSURLErrorServerCertificateHasUnknownRoot,
            NSURLErrorServerCertificateNotYetValid, NSURLErrorClientCertificateRejected,
            NSURLErrorClientCertificateRequired, NSURLErrorBadURL, NSURLErrorUnsupportedURL:
            return "connect"
        default:
            return "broken"
        }
    }
}
