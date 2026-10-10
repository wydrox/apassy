// The signed probe: the real code-signing checks of the bridge and of the extension,
// without a vault, a key, or a registered extension. scripts/build-credential-provider.sh
// --test --sign <identity> builds a fake Apassy.app in target/ with:
//
//   Contents/MacOS/apassy                     this probe, signed as com.wydrox.apassy
//   Contents/MacOS/apassy-credential-bridge   a bridge with only the container override
//   Contents/PlugIns/ApassyAutoFill.appex     this probe, signed as com.wydrox.apassy.autofill
//
// Modes:
//   parent <container> <bridge> <case>...     start the bridge as its child, play the app
//   client <socket>                           the client of the extension (BridgeClient.swift)
//   raw <socket>                              connect and send without checking the server
//   sandboxed <socket> <denied>               the client in the App Sandbox: one JSON line of
//                                             evidence, then the client (exit status as client)
//   group                                     print the app group container (sandboxed)
//   remove <path>...                          remove what one sandbox run made, by exact shape
//                                             (team-signed, so macOS container protection lets it)
//
// A case is <expect>:<mode>:<program>, with expect "answered", "refused" (the bridge
// closes without an answer and the app sees nothing), or "server_refused" (the client
// refuses the server). Exit status 0 when every case holds.
//
// The sandbox cases sign this probe as the extension with only the App Sandbox and the
// app group of ApassyAutoFill.entitlements, so macOS applies application.sb, as it does
// to the real extension. Its own signing identifier (unique per run) keeps it out of
// the data container of the real extension, so the bridge runs with
// APASSY_BRIDGE_DEV_ANY_PEER=1 and APASSY_BRIDGE_DEV_TIMEOUT (passed on by the parent)
// and only the client check of the bridge decides. The parent reads
// APASSY_PROBE_SANDBOX_ID (the identifier the sandbox must report) and
// APASSY_PROBE_DENIED (an existing file outside the sandbox). It starts the client
// without APP_SANDBOX_CONTAINER_ID, so only macOS can set it. Both expectations need
// that exact identifier and EPERM on the denied file; "answered" also needs a readable
// bridge and a passed check; "refused" needs EPERM on the bridge file, the code check
// failing with 100001 (errSecErrnoBase + EPERM), and the client ending with 3
// (bridgeRefused).
//
// Every wait has a deadline, also the wait for a child to end. A child past its
// deadline gets SIGTERM, then SIGKILL; so does every child when the probe gets SIGTERM
// or SIGHUP. Only the probe's own children get a signal, while Foundation still sees
// them running (not yet reaped, so their process IDs are still theirs).

import Foundation

let request = Data(#"{"allowed":[],"op":"passkey_list","rp_id":"example.com"}"#.utf8)

func runClient(socket: String, checkServer: Bool) -> Int32 {
    if checkServer {
        do {
            let answer = try BridgeCall().run(request, socketPath: socket)
            return (try? decodeAnswer(answer, as: PasskeyListAnswer.self)) != nil ? 0 : 4
        } catch let failure as ProviderFailure {
            switch failure {
            case .bridgeRefused: return 3
            case .notRunning: return 5
            case .failed: return 2
            default: return 4
            }
        } catch {
            return 4
        }
    }
    guard let fd = connectSocket(socket) else { return 5 }
    defer { close(fd) }
    prepareSocket(fd, sendTimeoutSeconds: 2)
    guard let frame = try? encodeFrame(request, max: BridgeConstants.maxRequestBytes) else { return 4 }
    _ = writeAll(fd, frame)
    var entry = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
    guard poll(&entry, 1, 3000) > 0, let bytes = readSome(fd, count: 4096), !bytes.isEmpty else {
        return 2
    }
    return 0
}

/// The check chain of BridgeCall.checkBridge on its own connection, which closes before
/// a frame (the bridge forwards nothing), then the client itself.
func runSandboxedClient(socket: String, denied: String) -> Int32 {
    var evidence: [String: String] = [
        "sandbox": ProcessInfo.processInfo.environment["APP_SANDBOX_CONTAINER_ID"] ?? "",
        "denied": "ok",
        "read": "no app",
        "check": "no app",
    ]
    let probe = open(denied, O_RDONLY)
    if probe >= 0 {
        close(probe)
    } else {
        evidence["denied"] = "errno \(errno)"
    }
    if let app = containingApp(of: Bundle.main.bundlePath, suffix: BridgeConstants.extensionPathInApp) {
        let bridge = app + BridgeConstants.bridgePathInApp
        let file = open(bridge, O_RDONLY)
        if file >= 0 {
            evidence["read"] = "ok"
            close(file)
        } else {
            evidence["read"] = "errno \(errno)"
        }
        if let fd = connectSocket(socket) {
            do {
                _ = try checkSocketPeer(fd, identifier: BridgeConstants.bridgeIdentifier, team: try ownTeam(), expectedPath: bridge)
                evidence["check"] = "ok"
            } catch let failure as CodeCheckError {
                evidence["check"] = failure.message
            } catch {
                evidence["check"] = "\(error)"
            }
            close(fd)
        } else {
            evidence["check"] = "no connection"
        }
    }
    if var line = try? JSONSerialization.data(withJSONObject: evidence, options: [.sortedKeys]) {
        line.append(0x0A)
        FileHandle.standardOutput.write(line)
    }
    return runClient(socket: socket, checkServer: true)
}

/// What one sandbox run of the script may remove, by exact shape: its socket folder
/// <group container>/ap-<pid>-<random>, and the data container and Application Scripts
/// folder of its own identifier com.wydrox.apassy.probe-sandbox-<pid>-<random>. Never
/// the group container or any other folder of it, never a path with ".", "..", a
/// double or a trailing slash, never a symbolic link or a file.
func removable(_ path: String) -> Bool {
    guard path.hasPrefix("/"), !path.hasSuffix("/"), !path.contains("//"),
          !path.split(separator: "/").contains(where: { $0 == "." || $0 == ".." })
    else { return false }
    let home = NSHomeDirectory()
    let run = "[0-9]+-[0-9]+"
    let probe = NSRegularExpression.escapedPattern(for: BridgeConstants.appIdentifier) + "\\.probe-sandbox-" + run
    let shapes = [
        ("\(home)/Library/Group Containers/\(BridgeConstants.appGroup)", "ap-" + run),
        ("\(home)/Library/Containers", probe),
        ("\(home)/Library/Application Scripts", probe),
    ]
    let parent = (path as NSString).deletingLastPathComponent
    let name = (path as NSString).lastPathComponent
    return shapes.contains { folder, pattern in
        parent == folder && name.range(of: "\\A\(pattern)\\z", options: .regularExpression) != nil
    }
}

/// Remove what one sandbox run of the script made (see `removable`).
func runRemove(_ paths: [String]) -> Int32 {
    var status: Int32 = 0
    for path in paths {
        guard removable(path) else {
            FileHandle.standardError.write(Data("probe: will not remove \(path)\n".utf8))
            status = 1
            continue
        }
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: path) else {
            continue
        }
        guard attributes[.type] as? FileAttributeType == .typeDirectory else {
            FileHandle.standardError.write(Data("probe: will not remove \(path): not a folder\n".utf8))
            status = 1
            continue
        }
        do { try FileManager.default.removeItem(atPath: path) } catch {
            FileHandle.standardError.write(Data("probe: cannot remove \(path): \(error)\n".utf8))
            status = 1
        }
    }
    return status
}

/// The children of this probe, so that a deadline or a signal can end them.
final class Children: @unchecked Sendable {
    private let lock = NSLock()
    private var running: [Process] = []

    func add(_ process: Process) {
        lock.lock()
        running.append(process)
        lock.unlock()
    }

    func remove(_ process: Process) {
        lock.lock()
        running.removeAll { $0 === process }
        lock.unlock()
    }

    /// SIGTERM to every child, up to 2 seconds, then SIGKILL to those still running.
    func stopAll() {
        lock.lock()
        let all = running
        lock.unlock()
        for process in all where process.isRunning {
            process.terminate()
        }
        let grace = Date().addingTimeInterval(2)
        while all.contains(where: \.isRunning), grace.timeIntervalSinceNow > 0 {
            usleep(50_000)
        }
        for process in all where process.isRunning {
            kill(process.processIdentifier, SIGKILL)
        }
    }
}

let children = Children()

/// Wait while `process` runs, at most until `deadline`. True when it no longer runs.
func waitWhileRunning(_ process: Process, until deadline: Date) -> Bool {
    while process.isRunning, deadline.timeIntervalSinceNow > 0 {
        usleep(50_000)
    }
    return !process.isRunning
}

/// Wait at most `seconds` for `process`, then SIGTERM, 2 seconds, SIGKILL, and 3 more
/// seconds. Never waits longer (no waitUntilExit). True when it ended by itself.
func waitBounded(_ process: Process, seconds: Double) -> Bool {
    let ended = waitWhileRunning(process, until: Date().addingTimeInterval(seconds))
    if !ended {
        process.terminate()
        if !waitWhileRunning(process, until: Date().addingTimeInterval(2)) {
            kill(process.processIdentifier, SIGKILL)
            if !waitWhileRunning(process, until: Date().addingTimeInterval(3)) {
                print("FAIL: \(process.executableURL?.path ?? "a child") (pid \(process.processIdentifier)) does not end")
                return false
            }
        }
    }
    children.remove(process)
    return ended
}

/// The exit status of an ended child; nil while it runs (Foundation raises then).
func exitStatus(_ process: Process) -> Int32? {
    process.isRunning ? nil : process.terminationStatus
}

final class LineReader {
    let fd: Int32
    var buffer = Data()

    init(_ fd: Int32) {
        self.fd = fd
    }

    func line(timeout: Double) -> [String: Any]? {
        let deadline = Date().addingTimeInterval(timeout)
        while true {
            if let newline = buffer.firstIndex(of: 0x0A) {
                let line = buffer[buffer.startIndex..<newline]
                buffer = Data(buffer[buffer.index(after: newline)...])
                return (try? JSONSerialization.jsonObject(with: line)) as? [String: Any]
            }
            let left = deadline.timeIntervalSinceNow
            guard left > 0 else { return nil }
            var entry = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&entry, 1, Int32(left * 1000)) > 0, let bytes = readSome(fd, count: 65536), !bytes.isEmpty else {
                return nil
            }
            buffer.append(bytes)
        }
    }
}

/// The settings of the sandbox cases, from the environment of the parent (see above).
struct SandboxExpectation {
    let identifier: String
    let denied: String

    static func load() -> SandboxExpectation? {
        let environment = ProcessInfo.processInfo.environment
        guard let identifier = environment["APASSY_PROBE_SANDBOX_ID"], !identifier.isEmpty,
              let denied = environment["APASSY_PROBE_DENIED"], !denied.isEmpty
        else { return nil }
        return SandboxExpectation(identifier: identifier, denied: denied)
    }
}

func runParent(container: String, bridgePath: String, cases: [String]) -> Int32 {
    var failed = 0
    func report(_ ok: Bool, _ name: String) {
        print("\(ok ? "ok" : "FAIL"): \(name)")
        if !ok { failed += 1 }
    }
    let sandbox = SandboxExpectation.load()
    if let sandbox {
        // The denied file exists and is readable outside the sandbox, so EPERM inside it
        // comes from the sandbox.
        let file = open(sandbox.denied, O_RDONLY)
        report(file >= 0, "the parent reads \(sandbox.denied) outside the sandbox")
        if file >= 0 { close(file) }
    }
    // A sandboxed client launches cold (its container, the first code checks): it gets
    // 20 seconds to reach the app. The bridge gives up on an unanswered request after
    // APASSY_BRIDGE_DEV_TIMEOUT (10 seconds in the sandbox cases), so 15 seconds after
    // the answer is enough for the client to end.
    let startSeconds: Double = sandbox == nil ? 5 : 20
    let bridge = Process()
    let toBridge = Pipe()
    let fromBridge = Pipe()
    bridge.executableURL = URL(fileURLWithPath: bridgePath)
    var environment = ["APASSY_BRIDGE_DEV_CONTAINER": container]
    for name in ["APASSY_BRIDGE_DEV_ANY_PEER", "APASSY_BRIDGE_DEV_TIMEOUT"] {
        if let value = ProcessInfo.processInfo.environment[name] {
            environment[name] = value
        }
    }
    bridge.environment = environment
    bridge.standardInput = toBridge
    bridge.standardOutput = fromBridge
    do { try bridge.run() } catch {
        print("FAIL: the bridge does not start")
        return 1
    }
    children.add(bridge)
    let lines = LineReader(fromBridge.fileHandleForReading.fileDescriptor)
    let ready = lines.line(timeout: startSeconds)
    guard ready?["type"] as? String == "ready", let socket = ready?["socket"] as? String else {
        print("bridge said: \(ready.map { "\($0["type"] ?? "")/\($0["code"] ?? "")" } ?? "nothing")")
        report(false, "the bridge accepts its signed parent")
        _ = try? toBridge.fileHandleForWriting.close()
        _ = waitBounded(bridge, seconds: 10)
        return 1
    }
    report(true, "the bridge accepts its signed parent")

    for item in cases {
        let parts = item.split(separator: ":", maxSplits: 2).map(String.init)
        guard parts.count == 3 else { continue }
        let (expect, mode, program) = (parts[0], parts[1], parts[2])
        let client = Process()
        client.executableURL = URL(fileURLWithPath: program)
        client.arguments = [mode, socket]
        let output = Pipe()
        if mode == "sandboxed" {
            guard let sandbox else {
                report(false, "\(item): APASSY_PROBE_SANDBOX_ID and APASSY_PROBE_DENIED are set")
                continue
            }
            client.arguments = [mode, socket, sandbox.denied]
            // Only macOS may set this name, when it starts the client in the sandbox.
            var clean = ProcessInfo.processInfo.environment
            clean["APP_SANDBOX_CONTAINER_ID"] = nil
            client.environment = clean
            client.standardOutput = output
        }
        do { try client.run() } catch {
            report(false, "\(item): the client starts")
            continue
        }
        children.add(client)
        if mode == "sandboxed", let sandbox {
            let answered = expect == "answered"
            let ended: Bool
            if answered {
                let forwarded = lines.line(timeout: startSeconds)
                let peer = forwarded?["peer"] as? [String: Any]
                report(peer?["check"] as? String == "development_override"
                       && peer?["pid"] as? Int == Int(client.processIdentifier),
                       "\(item): the app gets the request of the sandboxed client")
                if let rid = forwarded?["rid"] as? String,
                   var line = try? JSONSerialization.data(withJSONObject: ["type": "response", "rid": rid, "result": ["ok": true, "result": ["passkeys": []]]])
                {
                    line.append(0x0A)
                    _ = writeAll(toBridge.fileHandleForWriting.fileDescriptor, line)
                }
                ended = waitBounded(client, seconds: 15)
            } else {
                // Wait for the client first: a cold start must not hide a late request.
                ended = waitBounded(client, seconds: startSeconds)
                report(lines.line(timeout: 1.5) == nil, "\(item): the app sees nothing")
            }
            report(ended, "\(item): the client ends in time")
            let status = exitStatus(client)
            // The first line of the client, read with a deadline (it may never come).
            let evidence = (LineReader(output.fileHandleForReading.fileDescriptor).line(timeout: 2) ?? [:])
                .compactMapValues { $0 as? String }
            print("    sandbox=\(evidence["sandbox"] ?? "?") denied=\(evidence["denied"] ?? "?") read=\(evidence["read"] ?? "?") check=\(evidence["check"] ?? "?")")
            report(evidence["sandbox"] == sandbox.identifier, "\(item): macOS runs the client in the App Sandbox as \(sandbox.identifier)")
            report(evidence["denied"] == "errno \(EPERM)", "\(item): the sandbox denies the client a file outside it")
            if answered {
                report(evidence["read"] == "ok", "\(item): the sandbox lets the client read the bridge")
                report(evidence["check"] == "ok", "\(item): the client check accepts the bridge")
                report(status == 0, "\(item): the client gets the answer (got \(status.map(String.init) ?? "running"))")
            } else {
                report(evidence["read"] == "errno \(EPERM)", "\(item): the sandbox denies the bridge file to the client")
                report(evidence["check"]?.hasSuffix("(\(errSecErrnoBase + EPERM)).") == true,
                       "\(item): the code check fails on the sandbox denial")
                report(status == 3, "\(item): the client ends with 3 (got \(status.map(String.init) ?? "running"))")
            }
            continue
        }
        let forwarded = lines.line(timeout: expect == "answered" ? 5 : 1.5)
        if expect == "answered" {
            let peer = forwarded?["peer"] as? [String: Any]
            report(peer?["check"] as? String == "code_signature"
                   && peer?["signing_identifier"] as? String == BridgeConstants.extensionIdentifier
                   && peer?["pid"] as? Int == Int(client.processIdentifier)
                   && (peer?["path"] as? String)?.hasSuffix(BridgeConstants.extensionPathInApp) == true,
                   "\(item): the app gets the request with the checked provenance")
            if let rid = forwarded?["rid"] as? String,
               var line = try? JSONSerialization.data(withJSONObject: ["type": "response", "rid": rid, "result": ["ok": true, "result": ["passkeys": []]]])
            {
                line.append(0x0A)
                _ = writeAll(toBridge.fileHandleForWriting.fileDescriptor, line)
            }
            report(waitBounded(client, seconds: 15), "\(item): the client ends in time")
            report(exitStatus(client) == 0, "\(item): the client gets the answer")
        } else {
            report(forwarded == nil, "\(item): the app sees nothing")
            report(waitBounded(client, seconds: 15), "\(item): the client ends in time")
            let want: Int32 = expect == "server_refused" ? 3 : 2
            let status = exitStatus(client)
            report(status == want, "\(item): the client ends with \(want) (got \(status.map(String.init) ?? "running"))")
        }
    }
    _ = try? toBridge.fileHandleForWriting.close()
    let ended = waitBounded(bridge, seconds: 10)
    report(ended && exitStatus(bridge) == 0, "the bridge exits at the end of stdin")
    return failed == 0 ? 0 : 1
}

signal(SIGPIPE, SIG_IGN)
// SIGTERM or SIGHUP (the script at a deadline, or the script ending): end the children
// first. The dispatch source sees the signal; the handler only keeps it from ending the
// probe. Not SIG_IGN: an ignored signal may stay ignored in the children across exec
// (Foundation resets it on macOS 27, but need not), a handler never does.
let stopSignals = [SIGTERM, SIGHUP].map { number in
    signal(number) { _ in }
    let source = DispatchSource.makeSignalSource(signal: number, queue: .global())
    source.setEventHandler { [children] in
        children.stopAll()
        exit(128 + number)
    }
    source.resume()
    return source
}
let arguments = CommandLine.arguments
if arguments.count == 2, arguments[1] == "group" {
    guard let group = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: BridgeConstants.appGroup) else {
        exit(6)
    }
    print(group.path)
    exit(0)
}
switch arguments.count > 2 ? arguments[1] : "" {
case "client": exit(runClient(socket: arguments[2], checkServer: true))
case "raw": exit(runClient(socket: arguments[2], checkServer: false))
case "sandboxed" where arguments.count == 4: exit(runSandboxedClient(socket: arguments[2], denied: arguments[3]))
case "remove": exit(runRemove(Array(arguments.dropFirst(2))))
case "parent" where arguments.count > 3:
    exit(runParent(container: arguments[2], bridgePath: arguments[3], cases: Array(arguments.dropFirst(4))))
default:
    FileHandle.standardError.write(Data("usage: probe parent <container> <bridge> <case>... | client <socket> | raw <socket> | sandboxed <socket> <denied> | group | remove <path>...\n".utf8))
    exit(2)
}
