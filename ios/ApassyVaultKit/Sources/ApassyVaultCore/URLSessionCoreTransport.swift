#if os(watchOS)
import ApassyCoreFFI
import ApassyVaultKit
import Foundation
import Synchronization

/// The relay HTTP of the core on the Apple Watch (ADR 0039 section 5): watchOS gives this app no
/// BSD sockets, so the core hands each request to URLSession (`apassy_core_set_http_transport`).
///
/// The session is ephemeral: no cookie, no cache, no credential storage. Redirects are not
/// followed. Each `send` blocks the calling thread of the core until the answer, the deadline of
/// the request, or `cancel`. The request holds the bearer; no copy of it stays after `send`.
final class URLSessionCoreTransport: Sendable {
    static let shared = URLSessionCoreTransport()
    private static let installed = Mutex(false)

    /// The largest answer body: the limit of the core (2 MiB).
    private static let maxBody = 2 * 1024 * 1024

    private let session: URLSession
    private let state = Mutex(State())

    private struct Running {
        let task: URLSessionTask
        let exchange: Exchange
    }

    private struct State {
        var running: [UInt64: Running] = [:]
        /// Requests that `cancel` named before their `send` started.
        var cancelled: Set<UInt64> = []
    }

    private init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.urlCredentialStorage = nil
        configuration.waitsForConnectivity = false
        configuration.allowsCellularAccess = true
        configuration.tlsMinimumSupportedProtocolVersion = .TLSv12
        // Each request has its own deadline (`timeout_ms`); this only bounds a stuck one.
        configuration.timeoutIntervalForResource = 120
        session = URLSession(configuration: configuration)
    }

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

    // MARK: - One request

    private struct Request: Decodable {
        var id: UInt64
        var method: String
        var url: String
        var headers: [[String]]
        var body_b64u: String?
        var timeout_ms: UInt64
    }

    /// The headers that URLSession writes itself.
    private static let reserved: Set<String> = ["host", "content-length", "connection", "transfer-encoding"]

    private func perform(_ json: String) -> String {
        // A request that cannot be read was not sent: nothing reached the relay.
        guard let request = try? JSONDecoder().decode(Request.self, from: Data(json.utf8)),
            let url = URL(string: request.url), url.scheme == "https" || url.scheme == "http"
        else { return Answer.failure("connect") }
        let seconds = Double(min(max(request.timeout_ms, 1), 600_000)) / 1000
        var urlRequest = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: seconds)
        urlRequest.httpMethod = request.method
        urlRequest.httpShouldHandleCookies = false
        for pair in request.headers {
            guard pair.count == 2 else { return Answer.failure("connect") }
            guard !Self.reserved.contains(pair[0].lowercased()) else { continue }
            urlRequest.addValue(pair[1], forHTTPHeaderField: pair[0])
        }
        if let body = request.body_b64u {
            guard let data = Base64URL.decode(body) else { return Answer.failure("connect") }
            urlRequest.httpBody = data
        }
        let exchange = Exchange(limit: Self.maxBody)
        let task = session.dataTask(with: urlRequest)
        task.delegate = exchange
        let started = state.withLock { (state: inout State) -> Bool in
            if state.cancelled.remove(request.id) != nil { return false }
            state.running[request.id] = Running(task: task, exchange: exchange)
            return true
        }
        guard started else { return Answer.failure("broken") }
        defer { state.withLock { (state: inout State) in state.running[request.id] = nil } }
        task.resume()
        if exchange.done.wait(timeout: .now() + .milliseconds(Int(seconds * 1000) + 1000)) == .timedOut {
            // Past the deadline of the request: it may have reached the relay.
            exchange.end()
            task.cancel()
            exchange.done.wait()
        }
        return exchange.answer()
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

/// The delegate of one task: it keeps the answer, caps the body, refuses redirects, and counts the
/// bytes sent, so that a failure before the first byte is `connect` (the request did not reach the
/// relay) and any later one is `broken` (it may have landed).
private final class Exchange: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    let done = DispatchSemaphore(value: 0)
    private let limit: Int
    private let lock = NSLock()
    private var response: HTTPURLResponse?
    private var body = Data()
    private var failure: String?
    private var sentBytes: Int64?

    init(limit: Int) { self.limit = limit }

    /// The request was cancelled or passed its deadline: it answers `broken`.
    func end() {
        lock.withLock {
            if failure == nil { failure = "broken" }
        }
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
            if let error, failure == nil { failure = Self.classify(error, sentBytes: sentBytes) }
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
#endif
