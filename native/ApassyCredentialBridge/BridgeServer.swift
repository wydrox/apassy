// The socket server of the bridge: one thread, one poll loop.
//
// Inputs: stdin (the lines of the app), the listening socket, and the connections of
// the extension. Each connection carries one request:
//
//   accept -> peer check -> read one frame (10 s) -> forward to the app -> wait (180 s)
//          -> write the answer of the app -> close
//
// A peer that fails the check is closed without an answer. When the peer closes or
// hangs up while the app works on its request, the bridge sends "cancel" to the app
// and drops a later answer. The answer goes only to the connection of its request id.
// At end of stdin (the app quit or closed the pipe) the bridge closes all
// connections, removes its socket, and exits.

import Foundation

/// How the bridge checks a peer.
enum PeerCheck {
    /// The AutoFill extension inside the same Apassy.app, signed by `team`. A nil team
    /// or path refuses every peer.
    case codeSignature(team: String?, extensionPath: String?)
    #if APASSY_BRIDGE_DEV
    /// Development builds only: accept any peer of the same user.
    case developmentOverride
    #endif
}

struct BridgeSettings {
    let socketDirectory: String
    let socketPath: String
    let peerCheck: PeerCheck
    /// The parent at the start. Nil only with the development override.
    let parent: pid_t?
    let timeout: Double
}

struct BridgeFailure: Error {
    let code: String
    let message: String

    init(_ code: String, _ message: String) {
        self.code = code
        self.message = message
    }
}

let frameReadSeconds: Double = 10
let maxConnections = 8
let sendTimeoutSeconds = 5

final class Connection {
    let fd: Int32
    let peer: Provenance
    var reader = FrameReader(max: BridgeConstants.maxRequestBytes)
    var rid: String?
    var op: BridgeOp?
    var deadline: Date

    init(fd: Int32, peer: Provenance, deadline: Date) {
        self.fd = fd
        self.peer = peer
        self.deadline = deadline
    }
}

func log(_ message: String) {
    FileHandle.standardError.write(Data("apassy-credential-bridge: \(message)\n".utf8))
}

final class BridgeServer {
    private let settings: BridgeSettings
    private let listener: Int32
    private let socketIdentity: (dev: dev_t, ino: ino_t)
    private var connections: [Int32: Connection] = [:]
    private var input = Data()
    private var discarding = false
    private var stopping = false
    private var exitStatus: Int32 = 0

    init(settings: BridgeSettings) throws {
        self.settings = settings
        try prepareDirectory(settings.socketDirectory)
        try removeStaleSocket(settings.socketPath)
        (listener, socketIdentity) = try listenOn(settings.socketPath)
    }

    /// Run until the app closes stdin or sends "shutdown". Returns the exit status.
    func run() -> Int32 {
        guard let ready = readyLine(socket: settings.socketPath), emit(ready) else {
            cleanup()
            return 1
        }
        while !stopping {
            var fds = [pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)]
            if connections.count < maxConnections {
                fds.append(pollfd(fd: listener, events: Int16(POLLIN), revents: 0))
            }
            for fd in connections.keys.sorted() {
                fds.append(pollfd(fd: fd, events: Int16(POLLIN), revents: 0))
            }
            let status = poll(&fds, nfds_t(fds.count), pollTimeout())
            if status < 0 {
                if errno == EINTR { continue }
                log("poll failed (\(errno))")
                exitStatus = 1
                break
            }
            for entry in fds where entry.revents != 0 {
                if entry.fd == STDIN_FILENO {
                    readApp()
                } else if entry.fd == listener {
                    acceptPeer()
                } else if let connection = connections[entry.fd] {
                    readPeer(connection)
                }
                if stopping { break }
            }
            expireDeadlines()
            if !stopping, let parent = settings.parent, getppid() != parent {
                log("the app is gone")
                stopping = true
            }
        }
        for connection in Array(connections.values) {
            finish(connection, cancel: .bridgeClosing, frame: errorFrame(code: "not_running", message: "Apassy closed the connection."))
        }
        cleanup()
        return exitStatus
    }

    // MARK: - The app

    private func emit(_ line: Data) -> Bool {
        guard writeAll(STDOUT_FILENO, line) else {
            log("cannot write to the app")
            stopping = true
            return false
        }
        return true
    }

    private func readApp() {
        guard let bytes = readSome(STDIN_FILENO, count: 64 * 1024), !bytes.isEmpty else {
            stopping = true
            return
        }
        input.append(bytes)
        while let newline = input.firstIndex(of: 0x0A) {
            let line = Data(input[input.startIndex..<newline])
            input = Data(input[input.index(after: newline)...])
            if discarding {
                // The tail of a line that was too long. Its request times out.
                discarding = false
                log("dropped a line of the app that is too long")
            } else if !line.isEmpty {
                handleApp(line)
            }
            if stopping { return }
        }
        if input.count > BridgeConstants.maxResponseBytes + 4096 {
            discarding = true
            input = Data()
        }
    }

    private func handleApp(_ line: Data) {
        let message: AppMessage
        do {
            message = try parseAppLine(line)
        } catch {
            let reason = (error as? RequestError)?.message ?? "unreadable line"
            log("refused a line of the app: \(reason)")
            // Answer the waiting connection, if the line names one, so it does not wait.
            if let object = try? JSONSerialization.jsonObject(with: line) as? JSONObject,
               let rid = object["rid"] as? String, let connection = connection(for: rid)
            {
                finish(connection, cancel: nil, frame: errorFrame(code: "internal", message: "Apassy sent an answer that AutoFill cannot use."))
            }
            return
        }
        switch message {
        case .shutdown:
            stopping = true
        case .response(let rid, let result):
            guard let connection = connection(for: rid) else {
                // The request was cancelled or timed out: drop the late answer.
                log("dropped an answer for a finished request \(rid)")
                return
            }
            let frame = resultFrame(result)
                ?? errorFrame(code: "internal", message: "The answer of Apassy is too large for AutoFill.")
            log("answered \(connection.op?.rawValue ?? "?") \(rid) for pid \(connection.peer.pid)")
            finish(connection, cancel: nil, frame: frame)
        }
    }

    private func connection(for rid: String) -> Connection? {
        connections.values.first { $0.rid == rid }
    }

    // MARK: - The extension

    private func acceptPeer() {
        let fd = accept(listener, nil, nil)
        guard fd >= 0 else { return }
        prepareSocket(fd, sendTimeoutSeconds: sendTimeoutSeconds)
        let peer: Provenance
        do {
            peer = try checkPeer(fd)
        } catch {
            // No answer: another program learns nothing from the bridge.
            log("refused a peer: \((error as? CodeCheckError)?.message ?? "check failed")")
            close(fd)
            return
        }
        connections[fd] = Connection(fd: fd, peer: peer, deadline: Date().addingTimeInterval(frameReadSeconds))
    }

    private func checkPeer(_ fd: Int32) throws -> Provenance {
        switch settings.peerCheck {
        case .codeSignature(let team, let extensionPath):
            guard let team, let extensionPath else {
                throw CodeCheckError("This bridge has no team signature or no extension path, so it refuses every peer.")
            }
            let code = try checkSocketPeer(
                fd, identifier: BridgeConstants.extensionIdentifier, team: team, expectedPath: extensionPath)
            return Provenance(
                check: "code_signature", signingIdentifier: code.identifier, team: code.team, pid: code.pid, path: code.path)
        #if APASSY_BRIDGE_DEV
        case .developmentOverride:
            guard let token = peerAuditToken(fd), tokenEffectiveUser(token) == geteuid() else {
                throw CodeCheckError("The peer runs as another user.")
            }
            return Provenance(
                check: "development_override", signingIdentifier: "", team: "", pid: tokenPid(token), path: "")
        #endif
        }
    }

    private func readPeer(_ connection: Connection) {
        let bytes = readSome(connection.fd, count: BridgeConstants.maxRequestBytes + 4)
        if connection.rid != nil {
            // Waiting for the app: end of input, a hang-up, or any byte cancels.
            log("the peer closed \(connection.op?.rawValue ?? "?") \(connection.rid ?? "")")
            finish(connection, cancel: .peerClosed, frame: nil)
            return
        }
        guard let bytes, !bytes.isEmpty else {
            finish(connection, cancel: nil, frame: nil)
            return
        }
        let body: Data?
        do {
            body = try connection.reader.append(bytes)
        } catch {
            finish(connection, cancel: nil, frame: errorFrame(code: "invalid_input", message: "The request of AutoFill is too large or broken."))
            return
        }
        guard let body else { return }
        forward(connection, body)
    }

    private func forward(_ connection: Connection, _ body: Data) {
        let request: CheckedRequest
        do {
            request = try checkRequest(body)
        } catch {
            let message = (error as? RequestError)?.message ?? "The request of AutoFill is not valid."
            finish(connection, cancel: nil, frame: errorFrame(code: "invalid_input", message: message))
            return
        }
        let rid = UUID().uuidString
        guard let line = requestLine(rid: rid, request: request, peer: connection.peer) else {
            finish(connection, cancel: nil, frame: errorFrame(code: "internal", message: "The bridge cannot encode the request."))
            return
        }
        connection.rid = rid
        connection.op = request.op
        connection.deadline = Date().addingTimeInterval(settings.timeout)
        log("forwarded \(request.op.rawValue) \(rid) from pid \(connection.peer.pid)")
        _ = emit(line)
    }

    /// Close a connection. With `cancel`, tell the app first; with `frame`, answer first.
    private func finish(_ connection: Connection, cancel: CancelReason?, frame: Data?) {
        if let cancel, let rid = connection.rid, let line = cancelLine(rid: rid, reason: cancel) {
            _ = emit(line)
        }
        if let frame {
            _ = writeAll(connection.fd, frame)
        }
        connections[connection.fd] = nil
        close(connection.fd)
    }

    // MARK: - Time

    private func pollTimeout() -> Int32 {
        guard let next = connections.values.map(\.deadline).min() else {
            return -1
        }
        let milliseconds = next.timeIntervalSinceNow * 1000
        return Int32(max(0, min(milliseconds.rounded(.up), 60_000)))
    }

    private func expireDeadlines() {
        let now = Date()
        for connection in Array(connections.values) where connection.deadline <= now {
            if connection.rid != nil {
                log("timed out \(connection.op?.rawValue ?? "?") \(connection.rid ?? "")")
                finish(connection, cancel: .timeout, frame: errorFrame(code: "timeout", message: "Apassy did not answer in time."))
            } else {
                finish(connection, cancel: nil, frame: nil)
            }
        }
    }

    // MARK: - The socket file

    private func cleanup() {
        close(listener)
        var info = stat()
        if lstat(settings.socketPath, &info) == 0, info.st_dev == socketIdentity.dev, info.st_ino == socketIdentity.ino {
            unlink(settings.socketPath)
        }
    }
}

/// The socket directory: mode 0700, owned by this user, not a symlink.
func prepareDirectory(_ directory: String) throws {
    let container = (directory as NSString).deletingLastPathComponent
    for path in [container, directory] {
        if mkdir(path, 0o700) != 0, errno != EEXIST {
            throw BridgeFailure("socket_unavailable", "The bridge cannot make its folder in the app group (\(errno)).")
        }
        var info = stat()
        guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR, info.st_uid == geteuid() else {
            throw BridgeFailure("socket_unavailable", "The folder of the bridge is not a folder of this user.")
        }
    }
    guard chmod(directory, 0o700) == 0 else {
        throw BridgeFailure("socket_unavailable", "The bridge cannot protect its folder (\(errno)).")
    }
}

/// Remove a socket that no bridge serves. A live one means another bridge runs.
func removeStaleSocket(_ path: String) throws {
    var info = stat()
    guard lstat(path, &info) == 0 else {
        return
    }
    guard info.st_mode & S_IFMT == S_IFSOCK, info.st_uid == geteuid() else {
        throw BridgeFailure("socket_unavailable", "A file that is not a socket of this user is in the way of the bridge.")
    }
    if let fd = connectUnix(path) {
        close(fd)
        throw BridgeFailure("busy", "Another Apassy bridge runs already.")
    }
    guard unlink(path) == 0 else {
        throw BridgeFailure("socket_unavailable", "The bridge cannot remove an old socket (\(errno)).")
    }
}

/// A connected socket to `path`, or nil.
func connectUnix(_ path: String) -> Int32? {
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

/// Bind and listen. The socket file gets mode 0600.
func listenOn(_ path: String) throws -> (Int32, (dev: dev_t, ino: ino_t)) {
    guard var address = unixAddress(path) else {
        throw BridgeFailure("socket_unavailable", "The socket path is too long.")
    }
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else {
        throw BridgeFailure("socket_unavailable", "The bridge cannot make a socket (\(errno)).")
    }
    _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
    let previous = umask(0o177)
    let bound = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
    }
    umask(previous)
    var info = stat()
    guard bound == 0, chmod(path, 0o600) == 0, listen(fd, 16) == 0, lstat(path, &info) == 0,
          info.st_mode & S_IFMT == S_IFSOCK, info.st_mode & 0o777 == 0o600, info.st_uid == geteuid()
    else {
        let code = errno
        close(fd)
        throw BridgeFailure("socket_unavailable", "The bridge cannot listen on its socket (\(code)).")
    }
    return (fd, (info.st_dev, info.st_ino))
}
