// The client side of the bridge socket. One call opens one connection, checks that
// the listener is the signed bridge inside the same Apassy.app (audit token and code
// signature, PeerCode.swift), writes one frame, and waits for one frame.
//
// Cancellation (the owner closes the sheet, or macOS ends the request) closes the
// connection. The bridge then sends "cancel" to the app, which closes its owner check
// and signs nothing. The wait ends after 180 seconds at the latest.

import Foundation

/// One blocking call on a background queue. `cancel()` may come from any thread.
final class BridgeCall: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    private var wakeWriter: Int32 = -1

    func cancel() {
        lock.lock()
        cancelled = true
        if wakeWriter >= 0 {
            _ = writeAll(wakeWriter, Data([1]))
        }
        lock.unlock()
    }

    private func isCancelled() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }

    /// `socketPath` replaces the app group socket in the signed probe test only.
    func run(_ body: Data, socketPath: String? = nil) throws -> Data {
        var wake: [Int32] = [-1, -1]
        guard pipe(&wake) == 0 else {
            throw ProviderFailure.failed("AutoFill cannot wait for Apassy.")
        }
        lock.lock()
        wakeWriter = wake[1]
        lock.unlock()
        defer {
            lock.lock()
            wakeWriter = -1
            lock.unlock()
            close(wake[0])
            close(wake[1])
        }
        if isCancelled() {
            throw ProviderFailure.cancelled
        }

        let fd = try connectToBridge(socketPath)
        defer { close(fd) }
        do {
            try checkBridge(fd)
        } catch {
            throw ProviderFailure.bridgeRefused
        }
        guard let frame = try? encodeFrame(body, max: BridgeConstants.maxRequestBytes), writeAll(fd, frame) else {
            throw ProviderFailure.notRunning
        }

        var reader = FrameReader(max: BridgeConstants.maxResponseBytes)
        let deadline = Date().addingTimeInterval(BridgeConstants.requestTimeout + 5)
        while true {
            let left = deadline.timeIntervalSinceNow
            guard left > 0 else { throw ProviderFailure.timeout }
            var fds = [pollfd(fd: fd, events: Int16(POLLIN), revents: 0), pollfd(fd: wake[0], events: Int16(POLLIN), revents: 0)]
            let status = poll(&fds, 2, Int32(min(left, 60) * 1000))
            if status < 0, errno == EINTR { continue }
            guard status >= 0 else { throw ProviderFailure.failed("AutoFill lost the connection to Apassy.") }
            if fds[1].revents != 0 || isCancelled() {
                throw ProviderFailure.cancelled
            }
            guard fds[0].revents != 0 else { continue }
            guard let bytes = readSome(fd, count: 256 * 1024), !bytes.isEmpty else {
                throw ProviderFailure.failed("Apassy closed the connection without an answer.")
            }
            do {
                if let answer = try reader.append(bytes) {
                    return answer
                }
            } catch {
                throw ProviderFailure.failed("Apassy sent an answer that AutoFill cannot read.")
            }
        }
    }

    private func connectToBridge(_ override: String?) throws -> Int32 {
        guard let path = override ?? FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: BridgeConstants.appGroup)
            .flatMap(bridgeSocketPath(container:))
        else {
            throw ProviderFailure.failed("The app group of Apassy is not available to AutoFill.")
        }
        guard let fd = connectSocket(path) else {
            // No socket, or nobody listens: Apassy is not running.
            throw ProviderFailure.notRunning
        }
        prepareSocket(fd, sendTimeoutSeconds: 5)
        return fd
    }

    /// The listener must be com.wydrox.apassy.credential-bridge of this team, at
    /// Contents/MacOS/apassy-credential-bridge of the Apassy.app that contains this extension.
    private func checkBridge(_ fd: Int32) throws {
        let team = try ownTeam()
        guard let app = containingApp(of: Bundle.main.bundlePath, suffix: BridgeConstants.extensionPathInApp) else {
            throw CodeCheckError("The extension is not inside Apassy.app.")
        }
        _ = try checkSocketPeer(
            fd, identifier: BridgeConstants.bridgeIdentifier, team: team, expectedPath: app + BridgeConstants.bridgePathInApp)
    }
}

/// A connected socket to `path`, or nil.
func connectSocket(_ path: String) -> Int32? {
    guard var address = unixAddress(path) else { return nil }
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return nil }
    let status = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
    }
    guard status == 0 else {
        close(fd)
        return nil
    }
    return fd
}

enum BridgeClient {
    /// Send one call and wait for its answer. Task cancellation closes the connection.
    static func send(_ body: Data) async throws -> Data {
        let call = BridgeCall()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
                DispatchQueue.global(qos: .userInitiated).async {
                    do {
                        continuation.resume(returning: try call.run(body))
                    } catch {
                        continuation.resume(throwing: error)
                    }
                }
            }
        } onCancel: {
            call.cancel()
        }
    }
}
