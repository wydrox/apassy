import Foundation
import Network
import SwiftUI
import UIKit

/// What the app does with the node when it leaves the screen.
enum Lifecycle: String, CaseIterable, Identifiable {
    case stopNow = "stop-now"
    case stopAfter30 = "stop-30"
    case keep = "keep"

    var id: String { rawValue }

    var label: String {
        switch self {
        case .stopNow: return "Stop at once"
        case .stopAfter30: return "Stop after 30 s (plan)"
        case .keep: return "Keep it (iOS suspends it)"
        }
    }
}

enum CrashKind: String, CaseIterable, Identifiable {
    case goPanic, goGoroutinePanic, goNil, rustPanic, rustSegv, rustAbort

    var id: String { rawValue }

    var label: String {
        switch self {
        case .goPanic: return "Go: panic on the calling thread"
        case .goGoroutinePanic: return "Go: panic in a goroutine"
        case .goNil: return "Go: nil dereference (SIGSEGV in Go)"
        case .rustPanic: return "Rust: panic at the C boundary"
        case .rustSegv: return "Rust: SIGSEGV"
        case .rustAbort: return "Rust: abort()"
        }
    }
}

/// One try: from the moment that starts it (the app becoming active, or a button) to the first
/// byte of the Mac's answer.
final class Cycle {
    let kind: String
    let t0: TimeInterval
    let secondsHidden: Double?
    var upMs: Double?
    var dialMs: Double?
    var handshakeMs: Double?
    var answerMs: Double?
    var error = ""

    init(kind: String, t0: TimeInterval, secondsHidden: Double? = nil) {
        self.kind = kind
        self.t0 = t0
        self.secondsHidden = secondsHidden
    }
}

struct Sample: Codable, Identifiable {
    var id = UUID()
    var at: Date
    var kind: String
    var network: String
    var vpnOn: Bool
    var tunnels: String
    var secondsHidden: Double?
    var upMs: Double?
    var dialMs: Double?
    var handshakeMs: Double?
    var answerMs: Double?
    var path: String
    var ok: Bool
    var error: String
}

struct StatKey: Hashable, Comparable {
    let network: String
    let vpn: String
    let kind: String

    static func < (a: StatKey, b: StatKey) -> Bool {
        (a.network, a.vpn, a.kind) < (b.network, b.vpn, b.kind)
    }
}

struct StatRow: Identifiable {
    var id: StatKey { key }
    let key: StatKey
    let count: Int
    let failures: Int
    let upP50: Double?
    let upP90: Double?
    let answerP50: Double?
    let answerP90: Double?
}

struct ProbeResult {
    var at = Date()
    var address = ""
    var dialMs: Double?
    var report: [String: Any] = [:]
    var error = ""

    var ok: Bool { error.isEmpty && (report["ok"] as? Bool ?? false) }
    func text(_ key: String) -> String { report[key] as? String ?? "" }
    func number(_ key: String) -> Double? { (report[key] as? NSNumber)?.doubleValue }
}

/// The result of the blocking part of a probe, made off the main thread.
struct ProbeOutcome {
    var dialAt: TimeInterval = 0
    var rc: Int32 = -1
    var json = ""
    var error = ""
}

struct Resources {
    var footprintMB = 0.0
    var peakMB = 0.0
    var residentMB = 0.0
    var threads = 0
    var cpuSeconds = 0.0
    var go: [String: Any] = [:]
}

/// Set up before the model, in the app's init: stderr, the log pipe, the no-logs mode of Go, and
/// the Go traceback level. Each setting applies at the next launch.
enum SpikeBoot {
    nonisolated(unsafe) static var noLogsInfo = ""

    static func early() {
        let defaults = UserDefaults.standard
        if defaults.object(forKey: "stderrToFile") as? Bool ?? true {
            SpikeLog.redirectStderrToFile()
        }
        SpikeLog.shared.setUp()
        if defaults.object(forKey: "noLogs") as? Bool ?? true {
            // Plan T3 sets the variable before the start. Ask Go whether a setenv in Swift reaches
            // it: a c-archive's Go runtime starts when the library loads, before main.
            setenv("TS_NO_LOGS_NO_SUPPORT", "1", 1)
            let seen = GoHooks.getenv("TS_NO_LOGS_NO_SUPPORT")
            let applied = ApassySpikeNoLogs() == 1
            noLogsInfo = "Swift setenv seen by Go: \(seen.map { "yes (\($0))" } ?? "NO"). "
                + "After the Go call: \(applied ? "no-logs on, logtail disabled" : "NOT on")."
        } else {
            noLogsInfo = "No-logs is OFF (positive control): the node may upload logs to log.tailscale.com."
        }
        let crash = defaults.object(forKey: "goTracebackCrash") as? Bool ?? false
        ApassySpikeSetTraceback(crash ? "crash" : "single")
    }
}

@MainActor
final class SpikeModel: ObservableObject {
    private let defaults = UserDefaults.standard
    let stateDir: URL

    // Settings, saved. The auth key is not saved.
    @Published var hostname: String { didSet { defaults.set(hostname, forKey: "hostname") } }
    @Published var controlURL: String { didSet { defaults.set(controlURL, forKey: "controlURL") } }
    @Published var authKey = ""
    @Published var targetHost: String { didSet { defaults.set(targetHost, forKey: "targetHost") } }
    @Published var targetPort: String { didSet { defaults.set(targetPort, forKey: "targetPort") } }
    @Published var useTLS: Bool { didSet { defaults.set(useTLS, forKey: "useTLS") } }
    @Published var pin: String { didSet { defaults.set(pin, forKey: "pin") } }
    @Published var path: String { didSet { defaults.set(path, forKey: "path") } }
    @Published var lifecycle: Lifecycle { didSet { defaults.set(lifecycle.rawValue, forKey: "lifecycle") } }
    @Published var autoStart: Bool { didSet { defaults.set(autoStart, forKey: "autoStart") } }
    @Published var autoProbe: Bool { didSet { defaults.set(autoProbe, forKey: "autoProbe") } }
    @Published var vpnOn: Bool { didSet { defaults.set(vpnOn, forKey: "vpnOn") } }
    @Published var goTracebackCrash: Bool {
        didSet {
            defaults.set(goTracebackCrash, forKey: "goTracebackCrash")
            ApassySpikeSetTraceback(goTracebackCrash ? "crash" : "single")
        }
    }
    @Published var noLogsNextLaunch: Bool { didSet { defaults.set(noLogsNextLaunch, forKey: "noLogs") } }
    @Published var stderrToFileNextLaunch: Bool { didSet { defaults.set(stderrToFileNextLaunch, forKey: "stderrToFile") } }

    // The node.
    @Published private(set) var node: SpikeNode? = nil
    @Published private(set) var upDone = false
    @Published var state = "stopped"
    @Published var backendState = ""
    @Published var authURL: URL? = nil
    @Published var authURLNotes: [String] = []
    @Published var selfIPs = ""
    @Published var tailnetName = ""
    @Published var peerPath = ""
    @Published var peers: [String] = []
    @Published var hasState = false

    // Probes and samples.
    @Published var lastProbe: ProbeResult? = nil
    @Published var probing = false
    @Published var samples: [Sample] = []
    @Published var seriesRunning = false
    @Published var seriesStatus = ""

    // The phone and the process.
    @Published var network = "unknown"
    @Published var networkDetail = ""
    @Published var tunnels = ""
    @Published var resources = Resources()
    @Published var cpuWindow = ""
    @Published var executableMB = 0.0
    @Published var bundleMB = 0.0
    @Published var buildInfo: [String: Any] = [:]

    // Logs and privacy.
    @Published var noLogsInfo = SpikeBoot.noLogsInfo
    @Published var localAPIResult = ""
    @Published var stateFiles: [FileRow] = []
    @Published var stateDirInfo = ""
    @Published var stderrTail = ""
    @Published var previousStderrTail = ""
    @Published var lastCrashTest = ""
    @Published var events: [String] = []

    private var nodeStartedAt: TimeInterval = 0
    private var statusTask: Task<Void, Never>?
    private var metricsTask: Task<Void, Never>?
    private var stopTask: Task<Void, Never>?
    private var backgroundTask: UIBackgroundTaskIdentifier = .invalid
    private var backgroundAt: TimeInterval?
    private var firstActivation = true
    private var localAPIAskedForLogin = false
    private var cpuWindowStart: (t: TimeInterval, cpu: Double)?
    private var cpuWindowPeak: UInt64 = 0
    private var goInfoTick = 0
    private let pathMonitor = NWPathMonitor()
    private let webSignIn = WebSignIn()
    private let clock = DateFormatter()

    init() {
        let d = UserDefaults.standard
        hostname = d.string(forKey: "hostname") ?? "apassy-spike-iphone"
        controlURL = d.string(forKey: "controlURL") ?? ""
        targetHost = d.string(forKey: "targetHost") ?? ""
        targetPort = d.string(forKey: "targetPort") ?? "48700"
        useTLS = d.object(forKey: "useTLS") as? Bool ?? true
        pin = d.string(forKey: "pin") ?? ""
        path = d.string(forKey: "path") ?? "/"
        lifecycle = Lifecycle(rawValue: d.string(forKey: "lifecycle") ?? "") ?? .stopAfter30
        autoStart = d.object(forKey: "autoStart") as? Bool ?? true
        autoProbe = d.object(forKey: "autoProbe") as? Bool ?? true
        vpnOn = d.object(forKey: "vpnOn") as? Bool ?? false
        goTracebackCrash = d.object(forKey: "goTracebackCrash") as? Bool ?? false
        noLogsNextLaunch = d.object(forKey: "noLogs") as? Bool ?? true
        stderrToFileNextLaunch = d.object(forKey: "stderrToFile") as? Bool ?? true
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        stateDir = support.appendingPathComponent("TailnetSpike", isDirectory: true)
        if let data = d.data(forKey: "samples"), let saved = try? JSONDecoder().decode([Sample].self, from: data) {
            samples = saved
        }
        lastCrashTest = d.string(forKey: "lastCrashTest") ?? ""
        clock.dateFormat = "HH:mm:ss.SSS"

        if let url = Bundle.main.url(forResource: "build-info", withExtension: "json"),
           let data = try? Data(contentsOf: url),
           let info = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
            buildInfo = info
        }
        executableMB = SpikeMetrics.mb(SpikeMetrics.fileSize(Bundle.main.executableURL))
        bundleMB = SpikeMetrics.mb(SpikeMetrics.directorySize(Bundle.main.bundleURL))

        SpikeLog.shared.setHandler { [weak self] line in
            guard line.contains("/a/") else { return }
            onMain { self?.logLine(line) }
        }
        pathMonitor.pathUpdateHandler = { [weak self] path in
            let network = SpikeMetrics.network(path)
            onMain {
                self?.network = network.primary
                self?.networkDetail = network.detail
                self?.event("network: \(network.detail)")
            }
        }
        pathMonitor.start(queue: DispatchQueue(label: "tailnet-spike-path"))
        event("launch; \(SpikeBoot.noLogsInfo)")
        refreshFiles()
        refreshStderr()
    }

    var hasTarget: Bool {
        !targetHost.trimmingCharacters(in: .whitespaces).isEmpty && !targetPort.trimmingCharacters(in: .whitespaces).isEmpty
    }

    // MARK: - Events

    func event(_ text: String) {
        events.insert("\(clock.string(from: Date())) \(text)", at: 0)
        if events.count > 400 { events.removeLast(events.count - 400) }
    }

    private func logLine(_ line: String) {
        guard node != nil, backendState != "Running",
              let range = line.range(of: #"https://[^\s"]+/a/[A-Za-z0-9]+"#, options: .regularExpression),
              let url = URL(string: String(line[range])) else { return }
        noteAuthURL(url, source: "node log")
    }

    private func noteAuthURL(_ url: URL, source: String) {
        if authURL == nil { authURL = url }
        guard !authURLNotes.contains(where: { $0.hasPrefix(source) }) else { return }
        let note = String(format: "%@ after %.0f ms", source, (now() - nodeStartedAt) * 1000)
        authURLNotes.append(note)
        event("sign-in URL via \(note)")
    }

    // MARK: - The node

    func startNode(cycle: Cycle?, timeout: Double? = nil) async {
        guard node == nil else { return }
        do {
            try SpikeMetrics.prepareStateDir(stateDir)
        } catch {
            state = "failed: state directory: \(error.localizedDescription)"
            return
        }
        let config = NodeConfig(
            dir: stateDir.path,
            hostname: hostname.trimmingCharacters(in: .whitespaces),
            controlURL: controlURL.trimmingCharacters(in: .whitespaces),
            authKey: authKey.trimmingCharacters(in: .whitespacesAndNewlines))
        authKey = ""
        state = "starting"
        backendState = ""
        authURL = nil
        authURLNotes = []
        localAPIAskedForLogin = false
        upDone = false
        nodeStartedAt = cycle?.t0 ?? now()
        let logFD = SpikeLog.shared.descriptorForGo()
        let made: Result<SpikeNode, Error> = await background { Result { try SpikeNode(config: config, logFD: logFD) } }
        let n: SpikeNode
        switch made {
        case .success(let value):
            n = value
        case .failure(let error):
            state = "failed: \(error)"
            event("node: \(error)")
            cycle?.error = "\(error)"
            return
        }
        node = n
        event("node: start (\(cycle?.kind ?? "button"))")
        startPolling()
        let rc = await background { n.start() }
        guard node === n else { return }
        if rc != 0 {
            let message = n.errorMessage()
            state = "failed: start: \(message)"
            cycle?.error = "start: \(message)"
            await stopNode(reason: "start failed")
            return
        }
        // tailscale_up blocks until the node runs, or until tailscale_close.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let rc = n.up()
            let at = now()
            let message = rc == 0 ? "" : n.errorMessage()
            onMain { self?.upFinished(n, rc: rc, at: at, message: message, cycle: cycle) }
        }
        await waitFor(timeout: timeout) { self.upDone || self.node !== n }
        if !upDone, node === n, let cycle, cycle.error.isEmpty {
            cycle.error = "not up after \(Int(timeout ?? 0)) s (\(backendState))"
        }
    }

    private func upFinished(_ n: SpikeNode, rc: Int32, at: TimeInterval, message: String, cycle: Cycle?) {
        guard node === n else { return }
        if rc == 0 {
            let ms = (at - nodeStartedAt) * 1000
            cycle?.upMs = ms
            upDone = true
            state = "running"
            authURL = nil
            webSignIn.cancel()
            event(String(format: "node: up after %.0f ms", ms))
            Task { await self.pollStatus() }
        } else {
            state = "failed: up: \(message)"
            cycle?.error = "up: \(message)"
            event("node: up failed: \(message)")
        }
    }

    func stopNode(reason: String) async {
        guard let n = node else { return }
        node = nil
        upDone = false
        stopPolling()
        let t = now()
        let rc = await background { n.close() }
        event(String(format: "node: stopped (%@) in %.0f ms, rc %d", reason, (now() - t) * 1000, rc))
        state = "stopped"
        backendState = ""
        selfIPs = ""
        peerPath = ""
        authURL = nil
        refreshFiles()
    }

    func waitFor(timeout: Double?, _ done: () -> Bool) async {
        let start = now()
        while !done() {
            if let timeout, now() - start > timeout { return }
            try? await Task.sleep(nanoseconds: 20_000_000)
        }
    }

    /// "Disconnect from Tailscale" of plan T4: log out through the LocalAPI, stop, delete the state.
    func logoutAndDelete() async {
        if let n = node, upDone {
            let result = await localAPI(n, method: "POST", path: "/localapi/v0/logout")
            event("logout: \(result.summary)")
        }
        await stopNode(reason: "log out")
        do {
            if FileManager.default.fileExists(atPath: stateDir.path) {
                try FileManager.default.removeItem(at: stateDir)
            }
            event("node state deleted")
        } catch {
            event("node state not deleted: \(error.localizedDescription)")
        }
        refreshFiles()
    }

    // MARK: - Status

    private func startPolling() {
        statusTask?.cancel()
        statusTask = Task {
            while !Task.isCancelled {
                await self.pollStatus()
                let fast = !self.upDone
                try? await Task.sleep(nanoseconds: fast ? 250_000_000 : 2_000_000_000)
            }
        }
    }

    private func stopPolling() {
        statusTask?.cancel()
        statusTask = nil
    }

    func pollStatus() async {
        guard let n = node else { return }
        let result: Result<Data, Error> = await background { Result { try n.statusJSON() } }
        guard node === n else { return }
        switch result {
        case .failure(let error):
            backendState = "status error: \(error)"
        case .success(let data):
            applyStatus(data)
        }
    }

    private func applyStatus(_ data: Data) {
        guard let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return }
        let backend = json["BackendState"] as? String ?? ""
        if backend != backendState { event("status: \(backend)") }
        backendState = backend
        if backend == "Running" {
            authURL = nil
        } else if let text = json["AuthURL"] as? String, !text.isEmpty, let url = URL(string: text) {
            noteAuthURL(url, source: "status JSON")
        }
        if backend == "NeedsLogin" && !localAPIAskedForLogin {
            // ADR 0040 D4: does the LocalAPI over loopback (TailscaleKit's way) give the URL too?
            localAPIAskedForLogin = true
            Task { await self.checkLocalAPI() }
        }
        if let ips = json["TailscaleIPs"] as? [String] { selfIPs = ips.joined(separator: ", ") }
        if let tailnet = json["CurrentTailnet"] as? [String: Any] { tailnetName = tailnet["Name"] as? String ?? "" }
        let target = targetHost.trimmingCharacters(in: .whitespaces).lowercased()
        var rows: [String] = []
        var pathToTarget = ""
        if let peerMap = json["Peer"] as? [String: Any] {
            for case let peer as [String: Any] in peerMap.values {
                let name = peer["HostName"] as? String ?? "?"
                let dns = (peer["DNSName"] as? String ?? "").lowercased()
                let ips = peer["TailscaleIPs"] as? [String] ?? []
                let online = peer["Online"] as? Bool ?? false
                let direct = peer["CurAddr"] as? String ?? ""
                let relay = peer["Relay"] as? String ?? ""
                let via = !direct.isEmpty ? "direct \(direct)" : (relay.isEmpty ? "no path yet" : "DERP \(relay)")
                rows.append("\(name) \(ips.first ?? "") \(online ? "online" : "offline"), \(via)")
                if !target.isEmpty && (ips.contains(target) || dns.hasPrefix(target) || name.lowercased() == target) {
                    pathToTarget = via
                }
            }
        }
        peers = rows.sorted()
        peerPath = pathToTarget
    }

    // MARK: - Probes

    func probeNow() async {
        let cycle = Cycle(kind: "probe (node up)", t0: now())
        await probe(cycle: cycle)
        record(cycle)
    }

    func probe(cycle: Cycle) async {
        guard let n = node, upDone else {
            lastProbe = ProbeResult(error: "the node is not running")
            if cycle.error.isEmpty { cycle.error = "the node is not running" }
            return
        }
        let host = targetHost.trimmingCharacters(in: .whitespaces)
        let port = targetPort.trimmingCharacters(in: .whitespaces)
        guard !host.isEmpty, !port.isEmpty else {
            lastProbe = ProbeResult(error: "no target")
            cycle.error = "no target"
            return
        }
        let address = host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
        let tls = useTLS
        let pinText = tls ? pin.trimmingCharacters(in: .whitespacesAndNewlines) : ""
        let requestPath = path.isEmpty ? "/" : path
        probing = true
        let dialStart = now()
        let outcome: ProbeOutcome = await background {
            var result = ProbeOutcome()
            do {
                let fd = try n.dial(address)
                result.dialAt = now()
                var out = [CChar](repeating: 0, count: 16_384)
                // The Rust probe owns fd from here and closes it.
                result.rc = spike_rs_probe(fd, tls, host, pinText, requestPath, 10_000, &out, out.count)
                result.json = out.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
            } catch {
                result.dialAt = now()
                result.error = "\(error)"
            }
            return result
        }
        probing = false
        var result = ProbeResult(address: address, dialMs: (outcome.dialAt - dialStart) * 1000)
        if !outcome.error.isEmpty {
            result.error = outcome.error
        } else if let report = (try? JSONSerialization.jsonObject(with: Data(outcome.json.utf8))) as? [String: Any] {
            result.report = report
            if outcome.rc != 0 {
                let text = report["error"] as? String ?? ""
                result.error = text.isEmpty ? "probe failed (\(outcome.rc))" : text
            }
        } else {
            result.error = "the probe gave no report"
        }
        lastProbe = result
        let dialOffset = (outcome.dialAt - cycle.t0) * 1000
        cycle.dialMs = dialOffset
        if let ms = result.number("handshake_ms") { cycle.handshakeMs = dialOffset + ms }
        if let ms = result.number("first_byte_ms") { cycle.answerMs = dialOffset + ms }
        if !result.error.isEmpty && cycle.error.isEmpty { cycle.error = result.error }
        event(result.ok
            ? String(format: "probe: answer %.0f ms after the start (%@)", cycle.answerMs ?? 0, cycle.kind)
            : "probe: \(result.error)")
        await pollStatus()
    }

    private func record(_ cycle: Cycle) {
        let sample = Sample(
            at: Date(), kind: cycle.kind, network: network, vpnOn: vpnOn, tunnels: tunnels,
            secondsHidden: cycle.secondsHidden, upMs: cycle.upMs, dialMs: cycle.dialMs,
            handshakeMs: cycle.handshakeMs, answerMs: cycle.answerMs, path: peerPath,
            ok: cycle.error.isEmpty && cycle.answerMs != nil, error: cycle.error)
        samples.insert(sample, at: 0)
        if samples.count > 500 { samples.removeLast(samples.count - 500) }
        saveSamples()
    }

    private func saveSamples() {
        if let data = try? JSONEncoder().encode(samples) { defaults.set(data, forKey: "samples") }
    }

    func clearSamples() {
        samples = []
        saveSamples()
    }

    /// 10 starts of the node from its saved state, each with a probe, in this process.
    func runSeries(count: Int) {
        if seriesRunning {
            seriesRunning = false
            return
        }
        guard hasState else {
            seriesStatus = "sign in first"
            return
        }
        seriesRunning = true
        Task {
            for i in 1...count {
                guard self.seriesRunning else { break }
                self.seriesStatus = "try \(i) of \(count)"
                await self.stopNode(reason: "series")
                try? await Task.sleep(nanoseconds: 700_000_000)
                let cycle = Cycle(kind: "cold (series)", t0: now())
                await self.startNode(cycle: cycle, timeout: 30)
                if self.upDone && self.hasTarget {
                    await self.probe(cycle: cycle)
                } else if cycle.error.isEmpty {
                    cycle.error = "not up"
                }
                self.record(cycle)
            }
            self.seriesRunning = false
            self.seriesStatus = ""
        }
    }

    // MARK: - Foreground and background

    func scenePhaseChanged(_ phase: ScenePhase) {
        switch phase {
        case .active: becameActive()
        case .background: wentToBackground()
        case .inactive: event("scene: inactive")
        @unknown default: break
        }
    }

    private func becameActive() {
        let t0 = now()
        let hidden = backgroundAt.map { t0 - $0 }
        backgroundAt = nil
        event(hidden.map { String(format: "scene: active after %.1f s hidden", $0) } ?? "scene: active")
        cancelScheduledStop()
        startMetrics()
        refreshStderr()
        refreshFiles()
        let wasRunning = node != nil
        let kind = firstActivation ? "launch" : (wasRunning ? "kept" : "cold")
        firstActivation = false
        guard autoStart, !seriesRunning else { return }
        guard hasState || wasRunning else {
            event("no start on activation: no saved node state yet (sign in first)")
            return
        }
        let cycle = Cycle(kind: kind, t0: t0, secondsHidden: hidden)
        Task {
            if self.node == nil {
                await self.startNode(cycle: cycle, timeout: 60)
            } else if !self.upDone {
                await self.waitFor(timeout: 60) { self.upDone || self.node == nil }
            }
            guard self.autoProbe && self.hasTarget else { return }
            if self.upDone {
                await self.probe(cycle: cycle)
            } else if cycle.error.isEmpty {
                cycle.error = "not up after 60 s (\(self.backendState))"
            }
            self.record(cycle)
            // TailscaleKit reports that iOS takes the loopback listener of a suspended app.
            if kind == "kept", (hidden ?? 0) > 10 { await self.checkLocalAPI() }
        }
    }

    private func wentToBackground() {
        backgroundAt = now()
        event("scene: background")
        stopMetrics()
        guard node != nil else { return }
        switch lifecycle {
        case .keep: event("node: kept while hidden")
        case .stopNow: scheduleStop(after: 0)
        case .stopAfter30: scheduleStop(after: 30)
        }
    }

    private func scheduleStop(after seconds: Double) {
        cancelScheduledStop()
        backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "tailnet-spike-stop") { [weak self] in
            MainActor.assumeIsolated {
                self?.event("background time ended before the stop")
                self?.endBackgroundTask()
            }
        }
        stopTask = Task {
            if seconds > 0 { try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000)) }
            if Task.isCancelled { return }
            await self.stopNode(reason: seconds > 0 ? "hidden for \(Int(seconds)) s" : "hidden")
            self.endBackgroundTask()
        }
    }

    private func cancelScheduledStop() {
        stopTask?.cancel()
        stopTask = nil
        endBackgroundTask()
    }

    private func endBackgroundTask() {
        guard backgroundTask != .invalid else { return }
        UIApplication.shared.endBackgroundTask(backgroundTask)
        backgroundTask = .invalid
    }

    // MARK: - Sign-in

    func signIn(inApp: Bool) {
        guard let url = authURL else { return }
        if inApp {
            event("sign-in: in-app sheet (ASWebAuthenticationSession)")
            webSignIn.start(url) { [weak self] text in
                onMain { self?.event("sign-in sheet: \(text)") }
            }
        } else {
            event("sign-in: Safari")
            UIApplication.shared.open(url)
        }
    }

    // MARK: - LocalAPI over loopback

    struct LocalAPIResult {
        var code = 0
        var ms = 0.0
        var json: [String: Any] = [:]
        var error = ""

        var summary: String {
            error.isEmpty ? String(format: "HTTP %ld in %.0f ms", code, ms) : error
        }
    }

    private func localAPI(_ n: SpikeNode, method: String, path: String) async -> LocalAPIResult {
        var result = LocalAPIResult()
        let loop: Result<(addr: String, cred: String), Error> = await background { Result { try n.loopback() } }
        let endpoint: (addr: String, cred: String)
        switch loop {
        case .success(let value): endpoint = value
        case .failure(let error):
            result.error = "loopback: \(error)"
            return result
        }
        guard let url = URL(string: "http://\(endpoint.addr)\(path)") else {
            result.error = "bad loopback address \(endpoint.addr)"
            return result
        }
        var request = URLRequest(url: url, timeoutInterval: 5)
        request.httpMethod = method
        request.setValue("localapi", forHTTPHeaderField: "Sec-Tailscale")
        request.setValue("Basic " + Data("tsnet:\(endpoint.cred)".utf8).base64EncodedString(), forHTTPHeaderField: "Authorization")
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        let t = now()
        do {
            let (data, response) = try await session.data(for: request)
            result.ms = (now() - t) * 1000
            result.code = (response as? HTTPURLResponse)?.statusCode ?? 0
            result.json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
        } catch {
            result.error = "LocalAPI over loopback failed after \(Int((now() - t) * 1000)) ms: \(error.localizedDescription)"
        }
        return result
    }

    func checkLocalAPI() async {
        guard let n = node else {
            localAPIResult = "the node is not running"
            return
        }
        let result = await localAPI(n, method: "GET", path: "/localapi/v0/status")
        guard result.error.isEmpty else {
            localAPIResult = result.error
            event(result.error)
            return
        }
        let backend = result.json["BackendState"] as? String ?? "?"
        let authText = result.json["AuthURL"] as? String ?? ""
        localAPIResult = "\(result.summary), BackendState \(backend), AuthURL \(authText.isEmpty ? "empty" : "present")"
        event("LocalAPI: \(localAPIResult)")
        if !authText.isEmpty, backend != "Running", let url = URL(string: authText) {
            noteAuthURL(url, source: "LocalAPI over loopback")
        }
    }

    // MARK: - Resources

    private func startMetrics() {
        metricsTask?.cancel()
        metricsTask = Task {
            while !Task.isCancelled {
                self.tick()
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }

    private func stopMetrics() {
        metricsTask?.cancel()
        metricsTask = nil
    }

    private func tick() {
        let memory = SpikeMetrics.memory()
        var r = resources
        r.footprintMB = SpikeMetrics.mb(memory.footprint)
        r.peakMB = SpikeMetrics.mb(memory.peak)
        r.residentMB = SpikeMetrics.mb(memory.resident)
        r.threads = SpikeMetrics.threadCount()
        r.cpuSeconds = SpikeMetrics.cpuSeconds()
        goInfoTick += 1
        if goInfoTick % 5 == 1 { r.go = GoHooks.info() }
        resources = r
        tunnels = SpikeMetrics.tunnels()
        if let start = cpuWindowStart {
            cpuWindowPeak = max(cpuWindowPeak, memory.footprint)
            let elapsed = now() - start.t
            if elapsed >= 300 {
                let cpu = r.cpuSeconds - start.cpu
                cpuWindow = String(
                    format: "5 min in the foreground: CPU %.1f s (%.1f%% of one core), footprint peak %.0f MB, node %@, %@",
                    cpu, cpu / elapsed * 100, SpikeMetrics.mb(cpuWindowPeak), state, network)
                defaults.set(cpuWindow, forKey: "cpuWindow")
                cpuWindowStart = nil
                UIApplication.shared.isIdleTimerDisabled = false
                event(cpuWindow)
            } else {
                cpuWindow = String(format: "measuring: %.0f s of 300; keep the app on the screen", elapsed)
            }
        }
    }

    func startCPUWindow() {
        cpuWindowStart = (now(), SpikeMetrics.cpuSeconds())
        cpuWindowPeak = SpikeMetrics.memory().footprint
        UIApplication.shared.isIdleTimerDisabled = true
        cpuWindow = "measuring: keep the app on the screen for 5 minutes"
    }

    var savedCPUWindow: String { defaults.string(forKey: "cpuWindow") ?? "" }

    // MARK: - Files and stderr

    func refreshFiles() {
        hasState = FileManager.default.fileExists(atPath: stateDir.appendingPathComponent("tailscaled.state").path)
        stateFiles = SpikeMetrics.listing(stateDir)
        stateDirInfo = SpikeMetrics.dirInfo(stateDir)
    }

    func refreshStderr() {
        stderrTail = SpikeLog.tail(of: SpikeLog.stderrFile)
        previousStderrTail = SpikeLog.tail(of: SpikeLog.previousStderrFile)
    }

    // MARK: - Crash tests

    func crash(_ kind: CrashKind) {
        let note = "\(kind.label) at \(Date().formatted(date: .abbreviated, time: .standard)); node \(state); "
            + "Go traceback \(goTracebackCrash ? "crash" : "single")"
        defaults.set(note, forKey: "lastCrashTest")
        fputs("apassy spike: crash test: \(note)\n", stderr)
        switch kind {
        case .goPanic: ApassySpikeGoCrash(0)
        case .goGoroutinePanic: ApassySpikeGoCrash(1)
        case .goNil: ApassySpikeGoCrash(2)
        case .rustPanic: spike_rs_crash(0)
        case .rustSegv: spike_rs_crash(1)
        case .rustAbort: spike_rs_crash(2)
        }
        event("crash test returned: \(kind.label)")
    }

    func clearCrashNote() {
        defaults.removeObject(forKey: "lastCrashTest")
        lastCrashTest = ""
    }

    // MARK: - Results

    func groupedStats() -> [StatRow] {
        let groups = Dictionary(grouping: samples) {
            StatKey(network: $0.network, vpn: $0.vpnOn ? "VPN on" : "VPN off", kind: $0.kind)
        }
        return groups.keys.sorted().map { key in
            let items = groups[key] ?? []
            let ok = items.filter { $0.ok }
            let up = ok.compactMap { $0.upMs }
            let answer = ok.compactMap { $0.answerMs }
            return StatRow(
                key: key, count: items.count, failures: items.count - ok.count,
                upP50: SpikeMetrics.percentile(up, 0.5), upP90: SpikeMetrics.percentile(up, 0.9),
                answerP50: SpikeMetrics.percentile(answer, 0.5), answerP90: SpikeMetrics.percentile(answer, 0.9))
        }
    }

    /// The results as Markdown, for the results table of docs/design/spike-tsnet-ios.md. It holds
    /// no auth key, no sign-in URL, and no address other than the target's.
    func resultsText() -> String {
        func f(_ v: Double?) -> String { v.map { String(format: "%.0f", $0) } ?? "–" }
        var lines: [String] = []
        lines.append("## Tailnet spike results, \(Date().formatted(date: .abbreviated, time: .standard))")
        lines.append("")
        let pins = buildInfo["pins"] as? [String: Any] ?? [:]
        lines.append("- Build: \(buildInfo["go"] as? String ?? "?"); libtailscale \(pins["LIBTAILSCALE_COMMIT"] as? String ?? "?"); "
            + "tailscale.com \(pins["TAILSCALE_MODULE_VERSION"] as? String ?? "?"); licenses \(buildInfo["licenses"] as? String ?? "?")")
        lines.append(String(format: "- On the phone: executable %.1f MB, app bundle %.1f MB", executableMB, bundleMB))
        lines.append("- Logs: \(noLogsInfo)")
        lines.append("- Sign-in URL seen via: \(authURLNotes.isEmpty ? "–" : authURLNotes.joined(separator: "; "))")
        lines.append("- LocalAPI over loopback: \(localAPIResult.isEmpty ? "–" : localAPIResult)")
        lines.append("- State directory: \(stateDirInfo); files: "
            + stateFiles.map { "\($0.name) (\($0.size) B, \($0.protection))" }.joined(separator: ", "))
        lines.append(String(format: "- Now: footprint %.0f MB (peak %.0f MB), resident %.0f MB, %ld threads, CPU %.1f s since launch",
                            resources.footprintMB, resources.peakMB, resources.residentMB, resources.threads, resources.cpuSeconds))
        lines.append("- CPU window: \(cpuWindow.isEmpty ? (savedCPUWindow.isEmpty ? "–" : savedCPUWindow) : cpuWindow)")
        lines.append("- Last crash test: \(lastCrashTest.isEmpty ? "–" : lastCrashTest)")
        lines.append("")
        lines.append("| Network | VPN | Kind | n | failed | up p50 ms | up p90 ms | answer p50 ms | answer p90 ms |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for row in groupedStats() {
            lines.append("| \(row.key.network) | \(row.key.vpn) | \(row.key.kind) | \(row.count) | \(row.failures) | "
                + "\(f(row.upP50)) | \(f(row.upP90)) | \(f(row.answerP50)) | \(f(row.answerP90)) |")
        }
        lines.append("")
        lines.append("| Time | Kind | Network | VPN | Hidden s | Up ms | Dial ms | TLS ms | Answer ms | Path | Result |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for s in samples.prefix(200) {
            let hidden = s.secondsHidden.map { String(format: "%.0f", $0) } ?? "–"
            lines.append("| \(s.at.formatted(date: .omitted, time: .standard)) | \(s.kind) | \(s.network) | \(s.vpnOn ? "on" : "off") | "
                + "\(hidden) | \(f(s.upMs)) | \(f(s.dialMs)) | \(f(s.handshakeMs)) | \(f(s.answerMs)) | \(s.path) | "
                + "\(s.ok ? "ok" : s.error.replacingOccurrences(of: "|", with: "/")) |")
        }
        return lines.joined(separator: "\n")
    }

    func copyResults() {
        UIPasteboard.general.string = resultsText()
        event("results copied")
    }
}
