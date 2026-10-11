// The socket protocol between the AutoFill extension (ApassyAutoFill.appex) and the
// credential bridge (apassy-credential-bridge). Both programs compile this file.
// See docs/operations/mac-passkeys.md.
//
// One connection carries one request. The extension writes one frame. The bridge
// writes one frame back and closes. A frame is a 4-byte big-endian length, then that
// many bytes of JSON. When the extension closes the connection before the answer,
// the bridge cancels the request in the app.

import Foundation

enum BridgeConstants {
    static let protocolVersion = 1
    /// The team of every program here. The app group carries it as its prefix.
    static let teamIdentifier = "7S3F9767BM"
    static let appGroup = "7S3F9767BM.com.wydrox.apassy"
    static let appIdentifier = "com.wydrox.apassy"
    static let extensionIdentifier = "com.wydrox.apassy.autofill"
    static let bridgeIdentifier = "com.wydrox.apassy.credential-bridge"
    /// Paths relative to Apassy.app.
    static let extensionPathInApp = "/Contents/PlugIns/ApassyAutoFill.appex"
    static let bridgePathInApp = "/Contents/MacOS/apassy-credential-bridge"
    /// The socket: <group container>/bridge/cp.sock. Short, because `sun_path` holds
    /// 104 bytes with the closing NUL.
    static let socketDirectoryName = "bridge"
    static let socketName = "cp.sock"
    static let maxSocketPathBytes = 103
    /// A request of the extension.
    static let maxRequestBytes = 64 * 1024
    /// An answer to the extension.
    static let maxResponseBytes = 1024 * 1024
    /// The longest wait for one answer, in seconds. The owner check runs in this time.
    static let requestTimeout: Double = 180
}

enum FrameError: Error, Equatable {
    case tooLarge
    case empty
    case trailingBytes
}

/// A frame: the length of `body` as 4 bytes big-endian, then `body`.
func encodeFrame(_ body: Data, max: Int) throws -> Data {
    guard !body.isEmpty else { throw FrameError.empty }
    guard body.count <= max, body.count <= Int(UInt32.max) else { throw FrameError.tooLarge }
    let length = UInt32(body.count)
    var frame = Data([UInt8(length >> 24 & 0xFF), UInt8(length >> 16 & 0xFF), UInt8(length >> 8 & 0xFF), UInt8(length & 0xFF)])
    frame.append(body)
    return frame
}

/// Collects the bytes of one frame. A declared length above `max` fails before the
/// body arrives. Bytes after the frame fail too: a connection carries one frame.
struct FrameReader {
    let max: Int
    private var buffer = Data()
    private var expected: Int?
    private(set) var body: Data?

    init(max: Int) {
        self.max = max
    }

    /// Add received bytes. Returns the body once the frame is complete.
    mutating func append(_ bytes: Data) throws -> Data? {
        guard body == nil else {
            if bytes.isEmpty { return body }
            throw FrameError.trailingBytes
        }
        buffer.append(bytes)
        if expected == nil, buffer.count >= 4 {
            let head = [UInt8](buffer.prefix(4))
            let length = Int(head[0]) << 24 | Int(head[1]) << 16 | Int(head[2]) << 8 | Int(head[3])
            guard length > 0 else { throw FrameError.empty }
            guard length <= max else { throw FrameError.tooLarge }
            expected = length
            buffer = Data(buffer.dropFirst(4))
        }
        guard let expected else { return nil }
        if buffer.count > expected { throw FrameError.trailingBytes }
        if buffer.count < expected { return nil }
        body = buffer
        buffer = Data()
        return body
    }
}

/// The socket path in a group container, or nil when it does not fit `sun_path`.
func bridgeSocketPath(container: URL) -> String? {
    let path = container
        .appendingPathComponent(BridgeConstants.socketDirectoryName, isDirectory: true)
        .appendingPathComponent(BridgeConstants.socketName, isDirectory: false).path
    return path.utf8.count <= BridgeConstants.maxSocketPathBytes ? path : nil
}

/// A Unix socket address for `path`, or nil when the path is too long.
func unixAddress(_ path: String) -> sockaddr_un? {
    var address = sockaddr_un()
    let bytes = Array(path.utf8)
    let capacity = MemoryLayout.size(ofValue: address.sun_path)
    guard !bytes.isEmpty, bytes.count < capacity else { return nil }
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    withUnsafeMutableBytes(of: &address.sun_path) { raw in
        raw.copyBytes(from: bytes)
        raw[bytes.count] = 0
    }
    return address
}

/// Socket options of both ends: no SIGPIPE, close on exec, a send timeout.
func prepareSocket(_ fd: Int32, sendTimeoutSeconds: Int) {
    var one: Int32 = 1
    _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
    var timeout = timeval(tv_sec: sendTimeoutSeconds, tv_usec: 0)
    _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
}

/// Write all of `data`. False on any error, including a send timeout.
func writeAll(_ fd: Int32, _ data: Data) -> Bool {
    data.withUnsafeBytes { raw -> Bool in
        guard let base = raw.baseAddress else { return true }
        var offset = 0
        while offset < raw.count {
            let written = write(fd, base + offset, raw.count - offset)
            if written > 0 {
                offset += written
            } else if written < 0, errno == EINTR {
                continue
            } else {
                return false
            }
        }
        return true
    }
}

/// Read up to `count` bytes. Nil on an error, empty data at end of input.
func readSome(_ fd: Int32, count: Int) -> Data? {
    var bytes = [UInt8](repeating: 0, count: count)
    while true {
        let got = bytes.withUnsafeMutableBytes { read(fd, $0.baseAddress, count) }
        if got >= 0 {
            return Data(bytes.prefix(got))
        }
        if errno != EINTR {
            return nil
        }
    }
}
