// Synthetic tests of the credential bridge and of the wire checks of the extension.
// No vault, no key, no real extension. scripts/build-credential-provider.sh --test
// builds this runner with BridgeWire.swift, the shared files, and
// native/ApassyAutoFill/ProviderWire.swift, then runs:
//
//   bridge-tests <development bridge built with -D APASSY_BRIDGE_DEV>
//
// The integration part starts the development bridge as a child with its own
// container folder, connects to its socket like the extension, and plays the app on
// its stdin and stdout.

import Foundation

nonisolated(unsafe) var failures = 0
nonisolated(unsafe) var passes = 0

func expect(_ condition: Bool, _ name: String, file: StaticString = #fileID, line: UInt = #line) {
    if condition {
        passes += 1
    } else {
        failures += 1
        print("FAIL \(name) (\(file):\(line))")
    }
}

func expectThrows(_ name: String, _ body: () throws -> Void) {
    do {
        try body()
        expect(false, name)
    } catch {
        expect(true, name)
    }
}

func json(_ object: Any) -> Data {
    (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
}

let hash32 = Data(repeating: 7, count: 32).base64EncodedString()
let credential = Data([1, 2, 3, 4, 5]).base64EncodedString()

// MARK: - Frames

func frameTests() {
    let body = Data("{\"op\":\"credential_identities\"}".utf8)
    var reader = FrameReader(max: 1024)
    let frame = (try? encodeFrame(body, max: 1024)) ?? Data()
    expect(frame.count == body.count + 4, "a frame has a 4-byte length")
    // Byte by byte: the body arrives once, at the last byte.
    var got: Data?
    for byte in frame {
        got = try? reader.append(Data([byte]))
    }
    expect(got == body, "a frame read byte by byte gives its body")
    expectThrows("bytes after the frame fail") { _ = try reader.append(Data([0])) }

    var large = FrameReader(max: 16)
    expectThrows("a declared length above the limit fails before the body") {
        _ = try large.append(Data([0, 0, 0, 17]))
    }
    var empty = FrameReader(max: 16)
    expectThrows("an empty frame fails") { _ = try empty.append(Data([0, 0, 0, 0])) }
    expectThrows("encoding above the limit fails") { _ = try encodeFrame(Data(count: 17), max: 16) }
    var tail = FrameReader(max: 16)
    expectThrows("a frame with extra bytes in the same read fails") {
        _ = try tail.append(Data([0, 0, 0, 1, 65, 66]))
    }
}

// MARK: - Requests

func requestTests() {
    func check(_ object: [String: Any]) throws -> CheckedRequest {
        try checkRequest(json(object))
    }
    let assert: [String: Any] = [
        "op": "passkey_assert", "id": 12, "rp_id": "example.com", "credential_id": credential, "client_data_hash": hash32,
    ]
    let good = try? check(assert)
    expect(good?.op == .passkeyAssert && good?.op.needsOwnerCheck == true, "a valid assertion passes and needs the owner check")
    expect(good.map { Set($0.payload.keys) } == ["op", "id", "rp_id", "credential_id", "client_data_hash"], "the payload holds only checked fields")

    var verified = assert
    verified["verified"] = true
    expectThrows("a claimed \"verified\" field is refused") { _ = try check(verified) }
    var peer = assert
    peer["peer"] = ["check": "code_signature"]
    expectThrows("a claimed provenance is refused") { _ = try check(peer) }
    expectThrows("an unknown call is refused") { _ = try check(["op": "reveal", "id": 1, "field": "password"]) }
    expectThrows("an app-only call is refused") { _ = try check(["op": "passkey_import", "accounts": []]) }
    expectThrows("a missing call is refused") { _ = try check(["id": 1]) }

    var shortHash = assert
    shortHash["client_data_hash"] = Data(count: 31).base64EncodedString()
    expectThrows("a client data hash of 31 bytes is refused") { _ = try check(shortHash) }
    var urlSafe = assert
    urlSafe["credential_id"] = "-_8="
    expectThrows("base64url is refused") { _ = try check(urlSafe) }
    var spareBits = assert
    spareBits["credential_id"] = "AB=="
    expectThrows("base64 with non-zero spare bits is refused") { _ = try check(spareBits) }
    var unpadded = assert
    unpadded["credential_id"] = "AQIDBAU"
    expectThrows("base64 without padding is refused") { _ = try check(unpadded) }
    var longId = assert
    longId["credential_id"] = Data(count: 1024).base64EncodedString()
    expectThrows("a credential ID above 1023 bytes is refused") { _ = try check(longId) }

    for bad in [true, 1.5, -1, "12", 9_007_199_254_740_992] as [Any] {
        var wrong = assert
        wrong["id"] = bad
        expectThrows("the id \(bad) is refused") { _ = try check(wrong) }
    }
    for bad in ["", ".example.com", "example.com.", "exa mple.com", "ex..com", "exämple.com", String(repeating: "a", count: 254)] {
        var wrong = assert
        wrong["rp_id"] = bad
        expectThrows("the website \(bad.prefix(20)) is refused") { _ = try check(wrong) }
    }

    let register: [String: Any] = [
        "op": "passkey_register", "rp_id": "example.com", "user_name": "ann@example.com", "user_display_name": "Ann",
        "user_handle": Data([9, 9]).base64EncodedString(), "client_data_hash": hash32, "algorithms": [-7, -257],
        "excluded": [credential], "title": "Example",
    ]
    expect((try? check(register))?.op == .passkeyRegister, "a valid registration passes")
    var attachHalf = register
    attachHalf["attach_id"] = 4
    expectThrows("attach_id without attach_revision is refused") { _ = try check(attachHalf) }
    var attach = register
    attach["attach_id"] = 4
    attach["attach_revision"] = 2
    expect((try? check(attach))?.payload["attach_revision"] as? UInt64 == 2, "attach_id with attach_revision passes")
    var bidi = register
    bidi["user_name"] = "ann\u{202E}moc.elpmaxe"
    expectThrows("a user name with a bidi override is refused") { _ = try check(bidi) }
    var control = register
    control["title"] = "Ex\nample"
    expectThrows("a title with a control character is refused") { _ = try check(control) }
    var algorithms = register
    algorithms["algorithms"] = Array(repeating: -7, count: 33)
    expectThrows("more than 32 algorithms are refused") { _ = try check(algorithms) }
    var floatAlgorithm = register
    floatAlgorithm["algorithms"] = [-7.5]
    expectThrows("a fractional algorithm is refused") { _ = try check(floatAlgorithm) }
    var handle = register
    handle["user_handle"] = Data(count: 65).base64EncodedString()
    expectThrows("a user handle above 64 bytes is refused") { _ = try check(handle) }
    var many = register
    many["excluded"] = Array(repeating: credential, count: 257)
    expectThrows("more than 256 excluded credentials are refused") { _ = try check(many) }

    expect((try? check(["op": "autofill_list", "domains": ["example.com", "https://a.example.com/x"]])) != nil, "a domain list passes")
    expectThrows("more than 16 domains are refused") { _ = try check(["op": "autofill_list", "domains": Array(repeating: "a.com", count: 17)]) }
    expect((try? check(["op": "credential_identities"]))?.op.needsOwnerCheck == false, "the identity list needs no owner check")
    expectThrows("the identity list takes no field") { _ = try check(["op": "credential_identities", "rp_id": "a.com"]) }
    expect((try? check(["op": "autofill_code", "id": 3]))?.op.needsOwnerCheck == true, "a one-time code needs the owner check")

    let huge = ["op": "autofill_list", "domains": [String(repeating: "a", count: 70_000)]] as [String: Any]
    expectThrows("a request above 64 KiB is refused") { _ = try check(huge) }
    expectThrows("a JSON array is refused") { _ = try checkRequest(Data("[1]".utf8)) }
}

// MARK: - Lines of the app

func appLineTests() {
    let rid = UUID().uuidString
    let ok = json(["type": "response", "rid": rid, "result": ["ok": true, "result": ["passkeys": []]]])
    if case .response(let got, _)? = try? parseAppLine(ok) {
        expect(got == rid, "a response names its request")
    } else {
        expect(false, "a valid response parses")
    }
    let failed = json(["type": "response", "rid": rid, "result": ["ok": false, "error": ["code": "locked", "message": "The vault is locked."]]])
    expect((try? parseAppLine(failed)) != nil, "an error response parses")
    expectThrows("a response without a UUID is refused") {
        _ = try parseAppLine(json(["type": "response", "rid": "1", "result": ["ok": true, "result": [:]]]))
    }
    expectThrows("an ok result without an object is refused") {
        _ = try parseAppLine(json(["type": "response", "rid": rid, "result": ["ok": true, "result": "x"]]))
    }
    expectThrows("\"ok\" as a number is refused") {
        _ = try parseAppLine(json(["type": "response", "rid": rid, "result": ["ok": 1, "result": [:]]]))
    }
    expectThrows("an error code with capitals is refused") {
        _ = try parseAppLine(json(["type": "response", "rid": rid, "result": ["ok": false, "error": ["code": "Locked", "message": "x"]]]))
    }
    expectThrows("extra result fields are refused") {
        _ = try parseAppLine(json(["type": "response", "rid": rid, "result": ["ok": true, "result": [:], "verified": true]]))
    }
    expectThrows("an unknown type is refused") { _ = try parseAppLine(json(["type": "unlock"])) }
    if case .shutdown? = try? parseAppLine(json(["type": "shutdown"])) {
        expect(true, "shutdown parses")
    } else {
        expect(false, "shutdown parses")
    }
    let big = resultFrame(["ok": true, "result": ["x": String(repeating: "a", count: BridgeConstants.maxResponseBytes)]])
    expect(big == nil, "a result above 1 MiB gets no frame")
}

func pathTests() {
    let short = bridgeSocketPath(container: URL(fileURLWithPath: "/Users/ann/Library/Group Containers/7S3F9767BM.com.wydrox.apassy"))
    expect(short?.hasSuffix("/bridge/cp.sock") == true, "the socket path is in the bridge folder")
    let long = bridgeSocketPath(container: URL(fileURLWithPath: "/Users/" + String(repeating: "n", count: 40) + "/Library/Group Containers/7S3F9767BM.com.wydrox.apassy"))
    expect(long == nil, "a socket path above 103 bytes is refused")
    expect(requirementText(identifier: BridgeConstants.extensionIdentifier, team: "7S3F9767BM")
        == "anchor apple generic and identifier \"com.wydrox.apassy.autofill\" and certificate leaf[subject.OU] = \"7S3F9767BM\"",
        "the peer requirement names the extension and the team")
}

// MARK: - The bridge as a child

final class Bridge {
    let process = Process()
    let toBridge = Pipe()
    let fromBridge = Pipe()
    let container: String
    var buffer = Data()

    var socket: String { container + "/bridge/cp.sock" }

    init?(binary: String, container: String, anyPeer: Bool = true, timeout: Double? = nil) {
        self.container = container
        process.executableURL = URL(fileURLWithPath: binary)
        var environment = ["APASSY_BRIDGE_DEV_ANY_PARENT": "1", "APASSY_BRIDGE_DEV_CONTAINER": container]
        if anyPeer { environment["APASSY_BRIDGE_DEV_ANY_PEER"] = "1" }
        if let timeout { environment["APASSY_BRIDGE_DEV_TIMEOUT"] = String(timeout) }
        process.environment = environment
        process.standardInput = toBridge
        process.standardOutput = fromBridge
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return nil }
    }

    /// The next line on stdout, or nil after `timeout` seconds.
    func line(timeout: Double = 3) -> [String: Any]? {
        let deadline = Date().addingTimeInterval(timeout)
        let fd = fromBridge.fileHandleForReading.fileDescriptor
        while true {
            if let newline = buffer.firstIndex(of: 0x0A) {
                let line = buffer[buffer.startIndex..<newline]
                buffer = Data(buffer[buffer.index(after: newline)...])
                return (try? JSONSerialization.jsonObject(with: line)) as? [String: Any]
            }
            let left = deadline.timeIntervalSinceNow
            guard left > 0 else { return nil }
            var entry = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&entry, 1, Int32(left * 1000)) > 0, let bytes = readSome(fd, count: 1 << 20), !bytes.isEmpty else {
                return nil
            }
            buffer.append(bytes)
        }
    }

    func send(_ object: [String: Any]) {
        var data = json(object)
        data.append(0x0A)
        sendRaw(data)
    }

    func sendRaw(_ data: Data) {
        // writeAll, not FileHandle.write: a closed pipe must fail a test, not stop the runner.
        expect(writeAll(toBridge.fileHandleForWriting.fileDescriptor, data), "the bridge reads stdin")
    }

    func closeInput() {
        try? toBridge.fileHandleForWriting.close()
    }

    func waitExit(timeout: Double = 3) -> Int32? {
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning, Date() < deadline {
            usleep(20_000)
        }
        return process.isRunning ? nil : process.terminationStatus
    }

    func stop() {
        if process.isRunning {
            process.terminate()
            process.waitUntilExit()
        }
    }
}

/// Connect like the extension and send one frame.
func sendRequest(_ path: String, _ body: Data) -> Int32? {
    guard let fd = connectUnix(path) else { return nil }
    prepareSocket(fd, sendTimeoutSeconds: 2)
    guard let frame = try? encodeFrame(body, max: BridgeConstants.maxRequestBytes), writeAll(fd, frame) else {
        close(fd)
        return nil
    }
    return fd
}

/// The answer frame, or nil at end of input or after `timeout` seconds.
func readAnswer(_ fd: Int32, timeout: Double = 3) -> [String: Any]? {
    var reader = FrameReader(max: BridgeConstants.maxResponseBytes)
    let deadline = Date().addingTimeInterval(timeout)
    while deadline.timeIntervalSinceNow > 0 {
        var entry = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard poll(&entry, 1, Int32(deadline.timeIntervalSinceNow * 1000)) > 0,
              let bytes = readSome(fd, count: 1 << 20), !bytes.isEmpty
        else {
            return nil
        }
        if let body = try? reader.append(bytes) {
            return (try? JSONSerialization.jsonObject(with: body)) as? [String: Any]
        }
    }
    return nil
}

func errorCode(_ answer: [String: Any]?) -> String? {
    (answer?["error"] as? [String: Any])?["code"] as? String
}

func mode(_ path: String) -> mode_t? {
    var info = stat()
    return lstat(path, &info) == 0 ? info.st_mode & 0o777 : nil
}

func integrationTests(binary: String) {
    // A short root: the socket path must fit sun_path.
    let root = "/tmp/apb-" + UUID().uuidString.prefix(8)
    try? FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: root) }

    // Start, folder and socket modes, a full round trip.
    let containerA = root + "/a"
    guard let bridge = Bridge(binary: binary, container: containerA) else {
        expect(false, "the development bridge starts")
        return
    }
    defer { bridge.stop() }
    let ready = bridge.line()
    expect(ready?["type"] as? String == "ready" && ready?["socket"] as? String == bridge.socket, "the bridge reports its socket")
    expect(mode(containerA + "/bridge") == 0o700, "the socket folder has mode 0700")
    expect(mode(bridge.socket) == 0o600, "the socket has mode 0600")

    let list = json(["op": "passkey_list", "rp_id": "example.com", "allowed": [credential]])
    let client = sendRequest(bridge.socket, list)
    let forwarded = bridge.line()
    let rid = forwarded?["rid"] as? String ?? ""
    let peer = forwarded?["peer"] as? [String: Any]
    let payload = forwarded?["payload"] as? [String: Any]
    expect(forwarded?["type"] as? String == "request" && UUID(uuidString: rid) != nil, "the app gets a request with a bridge id")
    expect(forwarded?["owner_check"] as? Bool == false, "a list needs no owner check")
    expect(peer?["check"] as? String == "development_override" && peer?["pid"] as? Int == Int(getpid()),
           "the provenance comes from the bridge and names the peer pid from the audit token")
    expect(payload.map { Set($0.keys) } == ["op", "rp_id", "allowed"], "the app gets only the checked fields")
    let entry: [String: Any] = [
        "id": 1, "title": "Example", "rp_id": "example.com", "user_name": "ann", "user_display_name": "Ann",
        "credential_id": credential, "user_handle": credential,
    ]
    bridge.send(["type": "response", "rid": rid, "result": ["ok": true, "result": ["passkeys": [entry]]]])
    let answer = client.flatMap { readAnswer($0) }
    expect(((answer?["result"] as? [String: Any])?["passkeys"] as? [Any])?.count == 1, "the extension gets the answer of the app")
    if let client { close(client) }

    // A claimed "verified" field: an error for the extension, nothing for the app.
    let claimed = json(["op": "passkey_assert", "id": 1, "rp_id": "example.com", "credential_id": credential,
                        "client_data_hash": hash32, "verified": true])
    let refused = sendRequest(bridge.socket, claimed)
    expect(errorCode(refused.flatMap { readAnswer($0) }) == "invalid_input", "a claimed \"verified\" field gets invalid_input")
    expect(bridge.line(timeout: 0.5) == nil, "the app sees nothing of a refused request")
    if let refused { close(refused) }

    // The extension closes while the app works: the app gets "cancel"; a late answer is dropped.
    let assertion = json(["op": "passkey_assert", "id": 1, "rp_id": "example.com", "credential_id": credential, "client_data_hash": hash32])
    let leaving = sendRequest(bridge.socket, assertion)
    let pending = bridge.line()
    expect(pending?["owner_check"] as? Bool == true, "an assertion needs the owner check")
    if let leaving { close(leaving) }
    let cancel = bridge.line()
    expect(cancel?["type"] as? String == "cancel" && cancel?["rid"] as? String == pending?["rid"] as? String
           && cancel?["reason"] as? String == "peer_closed", "closing the connection cancels the request in the app")
    bridge.send(["type": "response", "rid": pending?["rid"] as? String ?? "", "result": ["ok": true, "result": ["signature": "AA=="]]])

    // A broken answer for a waiting request: the extension gets "internal".
    let next = sendRequest(bridge.socket, assertion)
    let nextRequest = bridge.line()
    expect(nextRequest?["rid"] as? String != pending?["rid"] as? String, "each request gets a new id")
    bridge.send(["type": "response", "rid": nextRequest?["rid"] as? String ?? "", "result": ["ok": true, "result": [:], "verified": true]])
    expect(errorCode(next.flatMap { readAnswer($0) }) == "internal", "a broken answer of the app becomes internal")
    if let next { close(next) }

    // An answer that does not fit a frame of 1 MiB.
    let large = sendRequest(bridge.socket, list)
    let largeRequest = bridge.line()
    bridge.send(["type": "response", "rid": largeRequest?["rid"] as? String ?? "",
                 "result": ["ok": true, "result": ["x": String(repeating: "a", count: BridgeConstants.maxResponseBytes - 10)]]])
    expect(errorCode(large.flatMap { readAnswer($0) }) == "internal", "an answer above 1 MiB becomes internal")
    if let large { close(large) }

    // A line of the app above the limit is dropped; the bridge keeps working.
    bridge.sendRaw(Data(repeating: 0x61, count: BridgeConstants.maxResponseBytes + 10_000) + Data([0x0A]))
    let after = sendRequest(bridge.socket, list)
    let afterRequest = bridge.line()
    bridge.send(["type": "response", "rid": afterRequest?["rid"] as? String ?? "", "result": ["ok": false, "error": ["code": "locked", "message": "The vault is locked."]]])
    expect(errorCode(after.flatMap { readAnswer($0) }) == "locked", "the bridge works after a line that is too long")
    if let after { close(after) }

    // A declared frame above 64 KiB.
    if let fd = connectUnix(bridge.socket) {
        _ = writeAll(fd, Data([0, 1, 0, 1]))
        expect(errorCode(readAnswer(fd)) == "invalid_input", "a frame above 64 KiB gets invalid_input")
        close(fd)
    }

    // A second bridge on the same folder stops with "busy".
    if let second = Bridge(binary: binary, container: containerA) {
        let line = second.line()
        expect(line?["type"] as? String == "error" && line?["code"] as? String == "busy", "a second bridge reports busy")
        expect(second.waitExit() == 3, "a second bridge exits with status 3")
    }

    // End of stdin: the bridge exits and removes its socket.
    bridge.closeInput()
    expect(bridge.waitExit() == 0, "the bridge exits at the end of stdin")
    expect(mode(bridge.socket) == nil, "the bridge removes its socket")

    // The peer check: this unsigned test process is refused without an answer.
    let containerB = root + "/b"
    if let strict = Bridge(binary: binary, container: containerB, anyPeer: false) {
        _ = strict.line()
        let stranger = sendRequest(strict.socket, list)
        expect(stranger.map { readAnswer($0) } ?? nil == nil, "an unsigned peer gets no answer")
        expect(strict.line(timeout: 0.5) == nil, "the app sees nothing of an unsigned peer")
        if let stranger { close(stranger) }
        strict.stop()
    }

    // A timeout: the extension gets "timeout", the app gets "cancel".
    let containerC = root + "/c"
    if let slow = Bridge(binary: binary, container: containerC, timeout: 1) {
        _ = slow.line()
        let waiting = sendRequest(slow.socket, assertion)
        let request = slow.line()
        expect(errorCode(waiting.flatMap { readAnswer($0, timeout: 4) }) == "timeout", "the extension gets timeout")
        let cancelled = slow.line()
        expect(cancelled?["reason"] as? String == "timeout" && cancelled?["rid"] as? String == request?["rid"] as? String,
               "the app gets cancel after the timeout")
        if let waiting { close(waiting) }
        slow.stop()
    }

    // A stale socket file is replaced; a regular file in its place stops the bridge.
    let containerD = root + "/d"
    try? FileManager.default.createDirectory(atPath: containerD + "/bridge", withIntermediateDirectories: true)
    if let stale = try? listenOn(containerD + "/bridge/cp.sock") {
        close(stale.0)
    }
    if let replaced = Bridge(binary: binary, container: containerD) {
        expect(replaced.line()?["type"] as? String == "ready", "a stale socket is replaced")
        replaced.stop()
    }
    let containerE = root + "/e"
    try? FileManager.default.createDirectory(atPath: containerE + "/bridge", withIntermediateDirectories: true)
    FileManager.default.createFile(atPath: containerE + "/bridge/cp.sock", contents: Data("x".utf8))
    if let blocked = Bridge(binary: binary, container: containerE) {
        let line = blocked.line()
        expect(line?["type"] as? String == "error" && line?["code"] as? String == "socket_unavailable", "a file in the way stops the bridge")
        expect(blocked.waitExit() == 1, "the bridge exits with status 1")
    }
}

// MARK: - Run

signal(SIGPIPE, SIG_IGN)
frameTests()
requestTests()
appLineTests()
pathTests()
appexWireTests()
if CommandLine.arguments.count > 1 {
    integrationTests(binary: CommandLine.arguments[1])
} else {
    print("SKIP integration: no development bridge given")
}
print("bridge-tests: \(passes) passed, \(failures) failed")
exit(failures == 0 ? 0 : 1)
