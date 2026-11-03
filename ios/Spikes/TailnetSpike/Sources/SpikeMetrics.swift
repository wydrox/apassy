import CFNetwork
import Darwin
import Foundation
import Network

struct FileRow: Identifiable {
    var id: String { name }
    let name: String
    let size: Int64
    let protection: String
}

/// Measurements of this process and of the phone's network. None of them are isolated to an
/// actor: they run on any thread.
enum SpikeMetrics {
    struct Memory {
        var footprint: UInt64 = 0
        var peak: UInt64 = 0
        var resident: UInt64 = 0
    }

    /// phys_footprint is what iOS counts against the app's memory limit (Xcode's memory gauge).
    static func memory() -> Memory {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        guard kr == KERN_SUCCESS else { return Memory() }
        return Memory(
            footprint: info.phys_footprint,
            peak: UInt64(max(0, info.ledger_phys_footprint_peak)),
            resident: info.resident_size
        )
    }

    /// User and system CPU time of the process, in seconds.
    static func cpuSeconds() -> Double {
        var usage = rusage()
        guard getrusage(RUSAGE_SELF, &usage) == 0 else { return 0 }
        let user = Double(usage.ru_utime.tv_sec) + Double(usage.ru_utime.tv_usec) / 1_000_000
        let system = Double(usage.ru_stime.tv_sec) + Double(usage.ru_stime.tv_usec) / 1_000_000
        return user + system
    }

    static func threadCount() -> Int {
        var list: thread_act_array_t?
        var count: mach_msg_type_number_t = 0
        guard task_threads(mach_task_self_, &list, &count) == KERN_SUCCESS, let list else { return -1 }
        for i in 0..<Int(count) {
            mach_port_deallocate(mach_task_self_, list[i])
        }
        let size = vm_size_t(MemoryLayout<thread_act_t>.stride * Int(count))
        vm_deallocate(mach_task_self_, vm_address_t(UInt(bitPattern: list)), size)
        return Int(count)
    }

    /// The physical network under the path: Wi-Fi, Cellular, Wired, or what NWPath names.
    static func network(_ path: NWPath) -> (primary: String, detail: String) {
        guard path.status == .satisfied else { return ("Offline", "no network") }
        let names = path.availableInterfaces.map { "\($0.name) (\(label($0.type)))" }
        let physical = path.availableInterfaces.first { [.wifi, .cellular, .wiredEthernet].contains($0.type) }
        let primary = physical.map { label($0.type) } ?? label(path.availableInterfaces.first?.type ?? .other)
        var detail = names.joined(separator: ", ")
        if path.isExpensive { detail += "; expensive" }
        if path.isConstrained { detail += "; low data mode" }
        return (primary, detail)
    }

    private static func label(_ type: NWInterface.InterfaceType) -> String {
        switch type {
        case .wifi: return "Wi-Fi"
        case .cellular: return "Cellular"
        case .wiredEthernet: return "Wired"
        case .loopback: return "Loopback"
        case .other: return "Other"
        @unknown default: return "Other"
        }
    }

    /// Tunnel interfaces that look like a VPN: those in the scoped proxy settings, and tunnel
    /// interfaces with an IPv4 address. iOS keeps a few utun interfaces of its own (IPv6 link
    /// local only), so read this next to the "Another VPN is on" switch.
    static func tunnels() -> String {
        var scopedNames: [String] = []
        if let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any],
           let scoped = settings["__SCOPED__"] as? [String: Any] {
            scopedNames = scoped.keys.filter(isTunnelName).sorted()
        }
        let withIPv4 = tunnelIPv4Addresses()
        var parts: [String] = []
        if !scopedNames.isEmpty { parts.append("scoped: " + scopedNames.joined(separator: ", ")) }
        if !withIPv4.isEmpty { parts.append("IPv4: " + withIPv4.joined(separator: ", ")) }
        return parts.joined(separator: "; ")
    }

    private static func isTunnelName(_ name: String) -> Bool {
        ["utun", "ipsec", "ppp", "tun", "tap"].contains { name.hasPrefix($0) }
    }

    private static func tunnelIPv4Addresses() -> [String] {
        var result: [String] = []
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0 else { return [] }
        defer { freeifaddrs(first) }
        var cursor = first
        while let entry = cursor {
            let name = String(cString: entry.pointee.ifa_name)
            if let addr = entry.pointee.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET), isTunnelName(name) {
                var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(addr, socklen_t(addr.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                    let text = host.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
                    result.append("\(name) \(text)")
                }
            }
            cursor = entry.pointee.ifa_next
        }
        return result
    }

    /// Seconds from the start of this process until now (dyld, the Go runtime's start, Swift).
    static func secondsSinceProcessStart() -> Double? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        guard sysctl(&mib, u_int(mib.count), &info, &size, nil, 0) == 0 else { return nil }
        let start = info.kp_proc.p_un.__p_starttime
        let started = Double(start.tv_sec) + Double(start.tv_usec) / 1_000_000
        return Date().timeIntervalSince1970 - started
    }

    static func fileSize(_ url: URL?) -> Int64 {
        guard let url, let values = try? url.resourceValues(forKeys: [.fileSizeKey]) else { return 0 }
        return Int64(values.fileSize ?? 0)
    }

    static func directorySize(_ url: URL) -> Int64 {
        let keys: [URLResourceKey] = [.fileSizeKey, .isRegularFileKey]
        guard let walker = FileManager.default.enumerator(at: url, includingPropertiesForKeys: keys) else { return 0 }
        var total: Int64 = 0
        for case let file as URL in walker {
            if let values = try? file.resourceValues(forKeys: Set(keys)), values.isRegularFile == true {
                total += Int64(values.fileSize ?? 0)
            }
        }
        return total
    }

    /// The node's state directory as ADR 0040 section 2 has it: excluded from backups, with the
    /// protection completeUntilFirstUserAuthentication.
    static func prepareStateDir(_ dir: URL) throws {
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true,
            attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var url = dir
        try url.setResourceValues(values)
    }

    static func listing(_ dir: URL) -> [FileRow] {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: dir.path) else { return [] }
        return names.sorted().map { name in
            let attributes = (try? fm.attributesOfItem(atPath: dir.appendingPathComponent(name).path)) ?? [:]
            let size = (attributes[.size] as? NSNumber)?.int64Value ?? 0
            let protection = protectionName(attributes[.protectionKey])
            return FileRow(name: name, size: size, protection: protection)
        }
    }

    static func dirInfo(_ dir: URL) -> String {
        guard FileManager.default.fileExists(atPath: dir.path) else { return "no state directory" }
        let excluded = (try? dir.resourceValues(forKeys: [.isExcludedFromBackupKey]))?.isExcludedFromBackup ?? false
        let attributes = (try? FileManager.default.attributesOfItem(atPath: dir.path)) ?? [:]
        let protection = protectionName(attributes[.protectionKey])
        return "excluded from backup: \(excluded ? "yes" : "NO"); protection: \(protection)"
    }

    private static func protectionName(_ value: Any?) -> String {
        if let type = value as? FileProtectionType { return type.rawValue }
        if let text = value as? String { return text }
        return "none"
    }

    static func percentile(_ values: [Double], _ q: Double) -> Double? {
        guard !values.isEmpty else { return nil }
        let sorted = values.sorted()
        let rank = max(1, Int((q * Double(sorted.count)).rounded(.up)))
        return sorted[min(rank, sorted.count) - 1]
    }

    static func mb(_ bytes: UInt64) -> Double { Double(bytes) / 1_048_576 }
    static func mb(_ bytes: Int64) -> Double { Double(bytes) / 1_048_576 }
}
