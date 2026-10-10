// The transport under the client: one request to one host.

import Foundation
import Synchronization

/// One request to one host. The client builds it, with its headers and its exact body bytes.
public struct TransportRequest: Sendable, Equatable {
    public var host: String
    public var port: UInt16
    public var method: String
    /// The request target as sent, for example `/v1/inbox`.
    public var path: String
    public var headers: [String: String]
    public var body: Data

    public init(host: String, port: UInt16, method: String, path: String, headers: [String: String], body: Data) {
        self.host = host
        self.port = port
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body
    }
}

/// The answer of a host, whatever the status.
public struct TransportResponse: Sendable, Equatable {
    public var status: Int
    public var body: Data

    public init(status: Int, body: Data) {
        self.status = status
        self.body = body
    }
}

/// Why a host gave no answer. The client goes on with the next host after each of these.
public enum TransportFailure: Error, Sendable, Equatable {
    /// No connection: refused, unreachable, not resolved, or too slow.
    case connection
    /// The TLS handshake failed.
    case tls
    /// The certificate does not have the pin.
    case pinMismatch
    /// iOS refused local network access.
    case localNetworkDenied
    /// The task was cancelled.
    case cancelled
}

/// Sends a request to a host.
public protocol CompanionTransport: Sendable {
    func send(_ request: TransportRequest) async throws(TransportFailure) -> TransportResponse
}

/// HTTPS through a URL session with the pin check, and nothing else.
public final class PinnedURLSessionTransport: CompanionTransport {
    private let session: URLSession
    private let delegate: PinnedTLSDelegate

    /// - Parameters:
    ///   - pin: SHA-256 of the Mac certificate DER, 32 bytes.
    ///   - protocolClasses: URL protocol classes for the session. Tests use it; the app does not.
    public init(pin: Data, protocolClasses: [AnyClass]? = nil) {
        let configuration = PinnedTLS.makeConfiguration()
        if let protocolClasses {
            configuration.protocolClasses = protocolClasses
        }
        let delegate = PinnedTLSDelegate(pin: pin)
        self.delegate = delegate
        self.session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    }

    deinit {
        session.invalidateAndCancel()
    }

    public func send(_ request: TransportRequest) async throws(TransportFailure) -> TransportResponse {
        var components = URLComponents()
        components.scheme = "https"
        components.host = request.host
        components.port = Int(request.port)
        components.percentEncodedPath = request.path
        guard let url = components.url else { throw .connection }

        var urlRequest = URLRequest(
            url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 5)
        urlRequest.allowsCellularAccess = Self.isTailscaleIPv4(request.host)
        urlRequest.httpMethod = request.method
        urlRequest.httpShouldHandleCookies = false
        for (name, value) in request.headers {
            urlRequest.setValue(value, forHTTPHeaderField: name)
        }
        if !request.body.isEmpty {
            urlRequest.httpBody = request.body
        }

        let result = await load(urlRequest)
        switch result {
        case .success(let (data, response)):
            guard let http = response as? HTTPURLResponse else { throw .connection }
            return TransportResponse(status: http.statusCode, body: data)
        case .failure(let failure):
            throw failure
        }
    }

    /// Only canonical dotted-decimal IPv4 in 100.64.0.0/10 can use cellular.
    /// Names, abbreviated addresses, and octal forms retain the local-network restriction.
    private static func isTailscaleIPv4(_ host: String) -> Bool {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        var octets: [UInt8] = []
        for part in parts {
            guard !part.isEmpty, part.utf8.count <= 3,
                part.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
                part.count == 1 || part.first != "0",
                let octet = UInt8(part)
            else { return false }
            octets.append(octet)
        }
        return octets[0] == 100 && (64...127).contains(octets[1])
    }

    /// Run one data task and tell why it failed. The task is made here, not by the async URL
    /// session call, so the identifier of the task is known and the pin check can say which
    /// request it stopped.
    private func load(_ request: URLRequest) async -> Result<(Data, URLResponse), TransportFailure> {
        let handle = TaskHandle()
        let outcome: Result<(Data, URLResponse), Error> = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let task = session.dataTask(with: request) { data, response, error in
                    if let error {
                        continuation.resume(returning: .failure(error))
                    } else if let data, let response {
                        continuation.resume(returning: .success((data, response)))
                    } else {
                        continuation.resume(returning: .failure(TransportFailure.connection))
                    }
                }
                if handle.set(task) { task.resume() } else { task.cancel() }
            }
        } onCancel: {
            handle.cancel()
        }
        switch outcome {
        case .success(let value):
            return .success(value)
        case .failure(let error):
            return .failure(classify(error, taskIdentifier: handle.identifier))
        }
    }

    private func classify(_ error: Error, taskIdentifier: Int?) -> TransportFailure {
        if let taskIdentifier, delegate.takePinMismatch(taskIdentifier: taskIdentifier) { return .pinMismatch }
        if let failure = error as? TransportFailure { return failure }
        if error is CancellationError { return .cancelled }
        let failure = TransportErrorClassifier.classify(error)
        // The delegate answers a challenge that it refuses with `cancelAuthenticationChallenge`,
        // which URL loading reports as NSURLErrorCancelled. When this task was not cancelled, the
        // cancel is a refused TLS challenge, not the owner leaving: the client must go on to the
        // next host, so it is a TLS failure and not a cancellation.
        if failure == .cancelled && !Task.isCancelled { return .tls }
        return failure
    }
}

/// The URL session task of one request, for the cancellation handler and for the pin mark.
private final class TaskHandle: Sendable {
    private struct State {
        var task: URLSessionTask?
        var cancelled = false
    }

    private let state = Mutex(State())

    /// Keep the task. False when the request was cancelled before the task existed.
    func set(_ task: URLSessionTask) -> Bool {
        state.withLock {
            $0.task = task
            return !$0.cancelled
        }
    }

    func cancel() {
        let task = state.withLock {
            $0.cancelled = true
            return $0.task
        }
        task?.cancel()
    }

    var identifier: Int? {
        state.withLock { $0.task?.taskIdentifier }
    }
}

/// Sorts an error from URL loading into a `TransportFailure`.
enum TransportErrorClassifier {
    static func classify(_ error: Error) -> TransportFailure {
        let ns = error as NSError
        if isLocalNetworkDenied(ns) { return .localNetworkDenied }
        guard ns.domain == NSURLErrorDomain else { return .connection }
        switch ns.code {
        case NSURLErrorCancelled:
            return .cancelled
        case NSURLErrorSecureConnectionFailed, NSURLErrorServerCertificateHasBadDate,
            NSURLErrorServerCertificateUntrusted, NSURLErrorServerCertificateHasUnknownRoot,
            NSURLErrorServerCertificateNotYetValid, NSURLErrorClientCertificateRejected,
            NSURLErrorClientCertificateRequired, NSURLErrorAppTransportSecurityRequiresSecureConnection:
            return .tls
        default:
            return .connection
        }
    }

    /// Whether iOS refused local network access. This is a best effort: iOS has no API for it, so
    /// it reads the marks that the system leaves in the error and its underlying errors.
    ///
    /// The marks are the text "local network prohibited" that the network path adds, and the
    /// DNS policy denial code (kDNSServiceErr_PolicyDenied, -65570).
    static func isLocalNetworkDenied(_ error: NSError, depth: Int = 0) -> Bool {
        if depth > 4 { return false }
        if error.code == -65570 { return true }
        let text = String(describing: error.userInfo).lowercased()
        if text.contains("local network prohibited") || text.contains("local network denied") { return true }
        if let underlying = error.userInfo[NSUnderlyingErrorKey] as? NSError {
            return isLocalNetworkDenied(underlying, depth: depth + 1)
        }
        return false
    }
}
