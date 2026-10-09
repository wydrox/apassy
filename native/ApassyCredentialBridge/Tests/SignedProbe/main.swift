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
//
// A case is <expect>:<mode>:<program>, with expect "answered", "refused" (the bridge
// closes without an answer and the app sees nothing), or "server_refused" (the client
// refuses the server). Exit status 0 when every case holds.

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

func runParent(container: String, bridgePath: String, cases: [String]) -> Int32 {
    var failed = 0
    func report(_ ok: Bool, _ name: String) {
        print("\(ok ? "ok" : "FAIL"): \(name)")
        if !ok { failed += 1 }
    }
    let bridge = Process()
    let toBridge = Pipe()
    let fromBridge = Pipe()
    bridge.executableURL = URL(fileURLWithPath: bridgePath)
    bridge.environment = ["APASSY_BRIDGE_DEV_CONTAINER": container]
    bridge.standardInput = toBridge
    bridge.standardOutput = fromBridge
    do { try bridge.run() } catch {
        print("FAIL: the bridge does not start")
        return 1
    }
    let lines = LineReader(fromBridge.fileHandleForReading.fileDescriptor)
    let ready = lines.line(timeout: 5)
    guard ready?["type"] as? String == "ready", let socket = ready?["socket"] as? String else {
        print("bridge said: \(ready.map { "\($0["type"] ?? "")/\($0["code"] ?? "")" } ?? "nothing")")
        report(false, "the bridge accepts its signed parent")
        _ = try? toBridge.fileHandleForWriting.close()
        bridge.waitUntilExit()
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
        do { try client.run() } catch {
            report(false, "\(item): the client starts")
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
            client.waitUntilExit()
            report(client.terminationStatus == 0, "\(item): the client gets the answer")
        } else {
            report(forwarded == nil, "\(item): the app sees nothing")
            client.waitUntilExit()
            let want: Int32 = expect == "server_refused" ? 3 : 2
            report(client.terminationStatus == want, "\(item): the client ends with \(want) (got \(client.terminationStatus))")
        }
    }
    _ = try? toBridge.fileHandleForWriting.close()
    bridge.waitUntilExit()
    report(bridge.terminationStatus == 0, "the bridge exits at the end of stdin")
    return failed == 0 ? 0 : 1
}

signal(SIGPIPE, SIG_IGN)
let arguments = CommandLine.arguments
switch arguments.count > 2 ? arguments[1] : "" {
case "client": exit(runClient(socket: arguments[2], checkServer: true))
case "raw": exit(runClient(socket: arguments[2], checkServer: false))
case "parent" where arguments.count > 3:
    exit(runParent(container: arguments[2], bridgePath: arguments[3], cases: Array(arguments.dropFirst(4))))
default:
    FileHandle.standardError.write(Data("usage: probe parent <container> <bridge> <case>... | client <socket> | raw <socket>\n".utf8))
    exit(2)
}
