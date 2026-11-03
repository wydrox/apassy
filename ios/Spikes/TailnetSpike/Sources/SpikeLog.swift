import Foundation

/// The node's log, in memory only: libtailscale writes to a pipe, and a thread keeps the last
/// lines. Nothing of it goes to disk (ADR 0040 section 2).
///
/// stderr is separate. With "stderr to a file" on (a spike setting, for the crash tests), fd 2
/// goes straight to Library/Caches/spike-stderr.txt, so a Go or Rust panic message survives the
/// end of the process. tsnet's own log.Printf lines (the sign-in URL among them) also go there.
final class SpikeLog {
    static let shared = SpikeLog()

    static var cachesDir: URL { FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0] }
    static var stderrFile: URL { cachesDir.appendingPathComponent("spike-stderr.txt") }
    static var previousStderrFile: URL { cachesDir.appendingPathComponent("spike-stderr-previous.txt") }

    private let lock = NSLock()
    private var lines: [String] = []
    private var partial: [UInt8] = []
    private var readFD: Int32 = -1
    private var writeFD: Int32 = -1
    private var handler: ((String) -> Void)?

    /// Called on the reader thread for each line.
    func setHandler(_ handler: @escaping (String) -> Void) {
        lock.lock()
        self.handler = handler
        lock.unlock()
    }

    func setUp() {
        lock.lock()
        defer { lock.unlock() }
        guard readFD < 0 else { return }
        var fds: [Int32] = [-1, -1]
        guard pipe(&fds) == 0 else { return }
        readFD = fds[0]
        writeFD = fds[1]
        let reader = Thread { [weak self] in self?.readLoop() }
        reader.name = "tailnet-spike-log"
        reader.start()
    }

    /// A new descriptor of the pipe for one node. libtailscale wraps it in a Go file and never
    /// gives it back, so each node gets its own copy.
    func descriptorForGo() -> Int32 {
        lock.lock()
        defer { lock.unlock() }
        return writeFD >= 0 ? dup(writeFD) : -1
    }

    func snapshot() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return lines
    }

    private func readLoop() {
        var buf = [UInt8](repeating: 0, count: 16_384)
        while true {
            let n = read(readFD, &buf, buf.count)
            if n < 0 && errno == EINTR { continue }
            if n <= 0 { return }
            var complete: [String] = []
            lock.lock()
            partial.append(contentsOf: buf[0..<n])
            while let i = partial.firstIndex(of: 0x0A) {
                complete.append(String(decoding: partial[0..<i], as: UTF8.self))
                partial.removeSubrange(0...i)
            }
            if partial.count > 64 * 1024 {
                complete.append(String(decoding: partial, as: UTF8.self))
                partial.removeAll()
            }
            lines.append(contentsOf: complete)
            if lines.count > 3000 { lines.removeFirst(lines.count - 3000) }
            let handler = self.handler
            lock.unlock()
            if let handler {
                for line in complete { handler(line) }
            }
        }
    }

    /// Points fd 2 at a fresh file; the last run's file becomes the "previous" one.
    static func redirectStderrToFile() {
        let fm = FileManager.default
        if fm.fileExists(atPath: stderrFile.path) {
            try? fm.removeItem(at: previousStderrFile)
            try? fm.moveItem(at: stderrFile, to: previousStderrFile)
        }
        let fd = open(stderrFile.path, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0o600)
        if fd >= 0 {
            dup2(fd, STDERR_FILENO)
            Darwin.close(fd)
        }
    }

    /// The last bytes of a file, as text.
    static func tail(of url: URL, bytes: Int = 16_384) -> String {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return "" }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        let start = size > UInt64(bytes) ? size - UInt64(bytes) : 0
        try? handle.seek(toOffset: start)
        let data: Data = (try? handle.readToEnd()) ?? Data()
        return String(decoding: data, as: UTF8.self)
    }
}
