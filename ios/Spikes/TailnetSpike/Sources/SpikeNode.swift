import Foundation

/// The settings of one node start. The auth key is used once and never saved.
struct NodeConfig {
    var dir: String
    var hostname: String
    var controlURL: String
    var authKey: String
}

struct SpikeError: Error, CustomStringConvertible {
    let description: String
}

/// One libtailscale server (a tsnet node) in this process. Every call into Go can block, so the
/// model calls these methods off the main thread.
final class SpikeNode {
    let handle: Int32
    private let lock = NSLock()
    private var loopbackCache: (addr: String, cred: String)?

    /// Makes the server and sets its options. It does not start it.
    init(config: NodeConfig, logFD: Int32) throws {
        handle = tailscale_new()
        do {
            // libtailscale wraps logFD in a Go file and owns it from now on (-1 drops the log).
            try check(tailscale_set_logfd(handle, logFD), "set_logfd")
            try check(tailscale_set_dir(handle, config.dir), "set_dir")
            try check(tailscale_set_hostname(handle, config.hostname), "set_hostname")
            if !config.controlURL.isEmpty {
                try check(tailscale_set_control_url(handle, config.controlURL), "set_control_url")
            }
            if !config.authKey.isEmpty {
                try check(tailscale_set_authkey(handle, config.authKey), "set_authkey")
            }
            try check(tailscale_set_ephemeral(handle, 0), "set_ephemeral")
        } catch {
            _ = tailscale_close(handle)
            throw error
        }
    }

    private func check(_ rc: Int32, _ what: String) throws {
        if rc != 0 { throw SpikeError(description: "\(what): \(rc) \(errorMessage())") }
    }

    /// tailscale_start: connects to the control server without waiting.
    func start() -> Int32 { tailscale_start(handle) }

    /// tailscale_up: blocks until the node runs, or until tailscale_close.
    func up() -> Int32 { tailscale_up(handle) }

    /// tailscale_close: stops the node. It also ends a blocked up().
    func close() -> Int32 { tailscale_close(handle) }

    func errorMessage() -> String {
        var buf = [CChar](repeating: 0, count: 4096)
        _ = tailscale_errmsg(handle, &buf, buf.count)
        return buf.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
    }

    func ips() -> String {
        var buf = [CChar](repeating: 0, count: 256)
        guard tailscale_getips(handle, &buf, buf.count) == 0 else { return "" }
        return buf.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
    }

    /// The backend status (ipnstate.Status) through tsnet's in-memory LocalAPI.
    func statusJSON() throws -> Data {
        var out: UnsafeMutablePointer<CChar>? = nil
        let rc = tailscale_status_json(handle, &out)
        guard rc == 0, let out else {
            throw SpikeError(description: "status_json \(rc): \(errorMessage())")
        }
        defer { free(out) }
        return Data(bytes: out, count: strlen(out))
    }

    /// A TCP stream to address ("100.x.y.z:port" or "name:port") through the tailnet. The
    /// descriptor is one end of a socket pair; the caller owns it. libtailscale's dial has no
    /// deadline: it returns when the netstack gives up.
    func dial(_ address: String) throws -> Int32 {
        var conn: tailscale_conn = -1
        let rc = tailscale_dial(handle, "tcp", address, &conn)
        guard rc == 0 else { throw SpikeError(description: "dial \(address): \(errorMessage())") }
        return conn
    }

    /// The loopback server (SOCKS5 and LocalAPI over TCP on 127.0.0.1), started once per node.
    func loopback() throws -> (addr: String, cred: String) {
        lock.lock()
        defer { lock.unlock() }
        if let cached = loopbackCache { return cached }
        var addr = [CChar](repeating: 0, count: 128)
        var proxy = [CChar](repeating: 0, count: 33)
        var local = [CChar](repeating: 0, count: 33)
        let rc = tailscale_loopback(handle, &addr, addr.count, &proxy, &local)
        guard rc == 0 else { throw SpikeError(description: "loopback \(rc): \(errorMessage())") }
        let value = (
            addr: addr.withUnsafeBufferPointer { String(cString: $0.baseAddress!) },
            cred: local.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        )
        loopbackCache = value
        return value
    }
}

/// The spike's Go hooks (Native/go/apassy_spike.go).
enum GoHooks {
    static func getenv(_ name: String) -> String? {
        guard let p = ApassySpikeGetenv(name) else { return nil }
        defer { free(p) }
        return String(cString: p)
    }

    static func info() -> [String: Any] {
        guard let p = ApassySpikeGoInfo() else { return [:] }
        defer { free(p) }
        let text = String(cString: p)
        return (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any] ?? [:]
    }
}

/// The monotonic clock of the measurements, in seconds.
func now() -> TimeInterval { ProcessInfo.processInfo.systemUptime }

/// Runs blocking work on a global queue and resumes with its result.
func background<T>(_ work: @escaping () -> T) async -> T {
    await withCheckedContinuation { (continuation: CheckedContinuation<T, Never>) in
        DispatchQueue.global(qos: .userInitiated).async {
            continuation.resume(returning: work())
        }
    }
}

/// Runs work on the main actor, in order.
func onMain(_ work: @escaping @MainActor () -> Void) {
    DispatchQueue.main.async {
        MainActor.assumeIsolated { work() }
    }
}
