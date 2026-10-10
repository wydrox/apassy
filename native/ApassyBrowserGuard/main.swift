// apassy-browser-guard: the caller check of browser passkey and one-time code
// requests (docs/contracts/browser-v1.md, section 9).
//
// The crate forbids unsafe Rust, so the audit token and code signing checks run
// here. The guard is Apassy.app/Contents/MacOS/apassy-browser-guard. It answers
// one check and exits: "ok" on standard output and status 0, or status 1 with no
// output. It reads no request and has no development override. The test build
// adds self-test modes (APASSY_BROWSER_GUARD_SELFTEST) that never answer "ok".
//
// The browser gives the native messaging host the origin of the extension as an
// argument. Any local process can start the host with that argument, so the
// argument proves nothing. The guard proves the chain from the operating system:
//
//   browser-parent  The signed apassy-browser-host starts the guard before it
//                   passes a passkey or code request to the app.
//                   1. The parent of the guard is apassy-browser-host of the
//                      same Apassy.app, signed by the team of the guard.
//                   2. The parent of that host is a known browser, signed by
//                      its own Developer ID team (`knownBrowsers`), started
//                      without a switch of `unsafeSwitches`.
//
//   socket-peer     The Apassy app starts the guard with the accepted
//                   connection of browser.sock as standard input.
//                   1. The parent of the guard is the Apassy app that contains
//                      the guard, signed by the team of the guard.
//                   2. The peer of the socket (LOCAL_PEERTOKEN) is
//                      apassy-browser-host of the same Apassy.app.
//                   3. The parent of that host is a known browser, started
//                      without a switch of `unsafeSwitches`.
//
// Each process is named by its audit token, not by a process ID from a request.
// A token holds the pid version, so a reused pid has another token. After the
// checks the guard reads each token again and compares: a process that exited,
// changed its image, or got a new parent fails the check.
//
// A signed browser is not enough. Started with `--load-extension` or
// `--disable-extensions-except`, Helium runs an unpacked extension from any
// folder. An unpacked copy with the public key of the store extension has the
// same ID, so the browser gives the host the expected origin. A
// `--remote-debugging-*` switch lets another process drive the browser. So the
// guard reads the arguments of the browser from the kernel
// (`KERN_PROCARGS2`, not the text of `ps`), refuses these switches in each
// form, and refuses arguments it cannot read or parse.
//
// The team of the guard comes from its own signature. An unsigned or ad hoc
// guard has no team and refuses every check.

import Darwin
import Foundation
import Security

/// The Apassy app and its browser host.
let appIdentifier = "com.wydrox.apassy"
let hostIdentifier = "com.wydrox.apassy.browser-host"
let appExecutableInApp = "/Contents/MacOS/apassy"
let hostExecutableInApp = "/Contents/MacOS/apassy-browser-host"
let guardExecutableInApp = "/Contents/MacOS/apassy-browser-guard"

/// A browser that may start the host: the signing identifier of its main
/// program and the team of its Developer ID certificate.
struct KnownBrowser {
    let identifier: String
    let team: String
}

/// Each entry comes from the signature of the official build, not from a list
/// on the web. Add a browser only after `codesign -d -r- <app>` on its official
/// download shows a Developer ID designated requirement with this identifier
/// and team.
///
/// - Helium: /Applications/Helium.app, checked 2026-10-09. "Developer ID
///   Application: imput LLC (S4Q33XPHB4)", designated requirement
///   `identifier "net.imput.helium" and anchor apple generic and certificate
///   1[field.1.2.840.113635.100.6.2.6] and certificate
///   leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] =
///   S4Q33XPHB4`.
/// - Google Chrome (stable only): official disk image
///   https://dl.google.com/chrome/mac/universal/stable/googlechrome.dmg,
///   SHA-256 88257ad17f1bda730f2a0600e1c7b9155bff2ae5ff9500386f5d4734bb411d55,
///   version 155.0.8059.40, checked 2026-10-09. "Developer ID Application:
///   Google LLC (EQHXZ8M8AV)", notarized. The designated requirement of Google
///   also admits `com.google.Chrome.beta`, `.dev`, and `.canary`; this list
///   names only `com.google.Chrome`, with the same certificate chain as Helium.
let knownBrowsers = [
    KnownBrowser(identifier: "net.imput.helium", team: "S4Q33XPHB4"),
    KnownBrowser(identifier: "com.google.Chrome", team: "EQHXZ8M8AV"),
]

struct Refused: Error {
    let reason: String
}

/// A process that passed a check.
struct Checked {
    let pid: pid_t
    let token: audit_token_t
}

// MARK: - Checks

/// The parent of the guard is apassy-browser-host of this app, and its parent
/// is a known browser.
func checkBrowserParent(app: String, team: String) throws {
    let parent = getppid()
    guard parent > 1, let token = auditToken(of: parent), pid(of: token) == parent else {
        throw Refused(reason: "no parent")
    }
    let host = try checkHost(token, app: app, team: team)
    let browser = try checkBrowserOf(host)
    try confirm(host: host, browser: browser)
    guard getppid() == parent else {
        throw Refused(reason: "the parent changed")
    }
}

/// The parent of the guard is the Apassy app, the peer of standard input is
/// apassy-browser-host of this app, and its parent is a known browser.
func checkSocketPeer(app: String, team: String) throws {
    let parent = getppid()
    guard parent > 1, let appToken = auditToken(of: parent), pid(of: appToken) == parent else {
        throw Refused(reason: "no parent")
    }
    let appCode = try guest(appToken)
    try check(appCode, requirement: ownTeamRequirement(appIdentifier, team: team))
    guard let appExecutable = mainExecutable(appCode), appExecutable == realPath(app + appExecutableInApp) else {
        throw Refused(reason: "the parent is not this Apassy app")
    }
    let peer = try peerToken(STDIN_FILENO)
    let host = try checkHost(peer, app: app, team: team)
    let browser = try checkBrowserOf(host)
    try confirm(host: host, browser: browser)
    guard getppid() == parent, let again = auditToken(of: parent), same(again, appToken) else {
        throw Refused(reason: "the parent changed")
    }
}

/// The process of `token` is apassy-browser-host of this app.
func checkHost(_ token: audit_token_t, app: String, team: String) throws -> Checked {
    let code = try guest(token)
    try check(code, requirement: ownTeamRequirement(hostIdentifier, team: team))
    guard let executable = mainExecutable(code), executable == realPath(app + hostExecutableInApp) else {
        throw Refused(reason: "the host is not in this Apassy app")
    }
    return Checked(pid: pid(of: token), token: token)
}

/// The parent of `host` is a known browser.
func checkBrowserOf(_ host: Checked) throws -> Checked {
    guard let browser = parentPid(of: host.pid), browser > 1 else {
        throw Refused(reason: "the host has no browser parent")
    }
    return try checkBrowser(browser)
}

/// The process `browser` is a known signed browser, started without an unsafe
/// switch.
func checkBrowser(_ browser: pid_t) throws -> Checked {
    guard let token = auditToken(of: browser), pid(of: token) == browser else {
        throw Refused(reason: "no browser process")
    }
    let code = try guest(token)
    var allowed = false
    for known in knownBrowsers {
        if (try? check(code, requirement: developerIDRequirement(known))) != nil {
            allowed = true
            break
        }
    }
    guard allowed else {
        throw Refused(reason: "the browser is not a known signed browser")
    }
    try checkArguments(of: browser, token: token)
    return Checked(pid: browser, token: token)
}

/// The arguments of the process `pid` have no unsafe switch. The token is read
/// again after the arguments, so the arguments belong to the checked process.
func checkArguments(of pid: pid_t, token: audit_token_t) throws {
    let arguments = try processArguments(of: pid)
    if let name = unsafeSwitch(in: arguments) {
        throw Refused(reason: "the browser runs with --\(name)")
    }
    guard let again = auditToken(of: pid), same(again, token) else {
        throw Refused(reason: "the browser changed during the check")
    }
}

/// After the signature checks: the host is the same process, its parent is
/// still the browser, and the browser is the same process.
func confirm(host: Checked, browser: Checked) throws {
    guard let hostAgain = auditToken(of: host.pid), same(hostAgain, host.token),
          parentPid(of: host.pid) == browser.pid,
          let browserAgain = auditToken(of: browser.pid), same(browserAgain, browser.token)
    else {
        throw Refused(reason: "a process changed during the check")
    }
}

// MARK: - Browser arguments

/// Switches that run extension code from a folder, or let another process
/// drive the browser. A switch counts with any value, after `=` or as the next
/// argument, with any number of leading dashes, without regard to case.
let unsafeSwitches = ["load-extension", "disable-extensions-except"]
/// Every switch that starts with one of these, like `--remote-debugging-port`
/// and `--remote-debugging-pipe`.
let unsafeSwitchPrefixes = ["remote-debugging"]

/// The largest `kern.argmax` that the guard reads. macOS has 1 MiB.
let maxArgumentBuffer = 4 << 20
/// A browser started by the owner has a few arguments. More is refused.
let maxArgumentCount = 256
/// The bytes of the executable path and all arguments, with their terminators.
let maxArgumentBytes = 64 << 10

/// The arguments of the process `pid` from the kernel (`KERN_PROCARGS2`), with
/// `argv[0]`. A process that is gone, of another user, or with arguments that do
/// not parse, is refused.
func processArguments(of pid: pid_t) throws -> [String] {
    var argmax: Int32 = 0
    var size = MemoryLayout<Int32>.size
    var argmaxName: [Int32] = [CTL_KERN, KERN_ARGMAX]
    guard sysctl(&argmaxName, u_int(argmaxName.count), &argmax, &size, nil, 0) == 0,
          size == MemoryLayout<Int32>.size, argmax > 0, Int(argmax) <= maxArgumentBuffer
    else {
        throw Refused(reason: "no argument limit")
    }
    var buffer = [UInt8](repeating: 0, count: Int(argmax))
    var length = buffer.count
    var name: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
    let status = buffer.withUnsafeMutableBytes { bytes in
        sysctl(&name, u_int(name.count), bytes.baseAddress, &length, nil, 0)
    }
    guard status == 0, length > 0, length <= buffer.count else {
        throw Refused(reason: "no arguments of the browser")
    }
    return try parseProcessArguments(Array(buffer[..<length]))
}

/// The arguments in a `KERN_PROCARGS2` buffer: `argc` (32 bits, the byte order
/// of the Mac), the executable path, padding zeros, then `argc` strings that each
/// end with a zero. The environment after them is not read.
///
/// Padding and an empty `argv[0]` look the same, so a parse may shift by one
/// string. The caller checks every string it gets, `argv[0]` too, so a shift
/// checks more, never less.
func parseProcessArguments(_ bytes: [UInt8]) throws -> [String] {
    let start = MemoryLayout<Int32>.size
    guard bytes.count > start else {
        throw Refused(reason: "malformed arguments")
    }
    let argc = bytes.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
    guard argc >= 1, argc <= maxArgumentCount else {
        throw Refused(reason: "malformed arguments")
    }
    // Nothing after this limit is read, so a longer argument area is refused.
    let limit = min(bytes.count, start + maxArgumentBytes)
    guard bytes[start] != 0, let pathEnd = bytes[start..<limit].firstIndex(of: 0) else {
        throw Refused(reason: "malformed or long arguments")
    }
    var index = pathEnd
    while index < limit, bytes[index] == 0 {
        index += 1
    }
    var arguments: [String] = []
    for _ in 0..<argc {
        guard index < limit, let end = bytes[index..<limit].firstIndex(of: 0),
              let argument = String(bytes: bytes[index..<end], encoding: .utf8)
        else {
            throw Refused(reason: "malformed or long arguments")
        }
        arguments.append(argument)
        index = end + 1
    }
    return arguments
}

/// The name of the first unsafe switch in `arguments`, or nil.
///
/// Chromium reads `-name` and `--name`, with the value after `=`; a value in the
/// next argument does not count for Chromium, but the name alone is refused here.
/// The guard also strips more dashes, ignores case, and checks the arguments
/// after `--`, so it refuses more than Chromium reads.
func unsafeSwitch(in arguments: [String]) -> String? {
    for argument in arguments where argument.hasPrefix("-") {
        let name = argument.drop { $0 == "-" }.prefix { $0 != "=" }.lowercased()
        if unsafeSwitches.contains(name) || unsafeSwitchPrefixes.contains(where: { name.hasPrefix($0) }) {
            return name
        }
    }
    return nil
}

// MARK: - Requirements

/// Code of this team with this identifier, like native/ApassyHelper/Caller.swift.
func ownTeamRequirement(_ identifier: String, team: String) -> String {
    "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"\(team)\""
}

/// A Developer ID application of the browser vendor.
func developerIDRequirement(_ browser: KnownBrowser) -> String {
    "anchor apple generic and identifier \"\(browser.identifier)\""
        + " and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
        + " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
        + " and certificate leaf[subject.OU] = \"\(browser.team)\""
}

func check(_ code: SecCode, requirement text: String) throws {
    var requirement: SecRequirement?
    guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement else {
        throw Refused(reason: "no requirement")
    }
    guard SecCodeCheckValidityWithErrors(code, [], requirement, nil) == errSecSuccess else {
        throw Refused(reason: "the code does not satisfy the requirement")
    }
}

// MARK: - Own signature

/// The team and the containing app of this guard.
func ownApp() throws -> (team: String, app: String) {
    var own: SecCode?
    var ownStatic: SecStaticCode?
    guard SecCodeCopySelf([], &own) == errSecSuccess, let own,
          SecCodeCheckValidity(own, [], nil) == errSecSuccess,
          SecCodeCopyStaticCode(own, [], &ownStatic) == errSecSuccess, let ownStatic
    else {
        throw Refused(reason: "no valid own signature")
    }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(ownStatic, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let fields = info as? [String: Any],
          let team = fields[kSecCodeInfoTeamIdentifier as String] as? String, !team.isEmpty,
          let executable = fields[kSecCodeInfoMainExecutable as String] as? URL,
          let resolved = realPath(executable.path), resolved.hasSuffix(guardExecutableInApp)
    else {
        throw Refused(reason: "the guard has no team or is not in Apassy.app")
    }
    let app = String(resolved.dropLast(guardExecutableInApp.count))
    guard app.hasSuffix(".app") else {
        throw Refused(reason: "the guard is not in Apassy.app")
    }
    return (team, app)
}

// MARK: - Processes

/// The running code of the process with this audit token.
func guest(_ token: audit_token_t) throws -> SecCode {
    var token = token
    let data = withUnsafeBytes(of: &token) { Data($0) }
    var code: SecCode?
    guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: data] as CFDictionary, [], &code) == errSecSuccess,
          let code
    else {
        throw Refused(reason: "no code for the process")
    }
    return code
}

/// The path of the main executable of `code`, with symlinks resolved.
func mainExecutable(_ code: SecCode) -> String? {
    var staticCode: SecStaticCode?
    var info: CFDictionary?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
          SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let fields = info as? [String: Any],
          let executable = fields[kSecCodeInfoMainExecutable as String] as? URL
    else {
        return nil
    }
    return realPath(executable.path)
}

/// The audit token of the process `pid`, or nil.
func auditToken(of pid: pid_t) -> audit_token_t? {
    var name = mach_port_name_t(MACH_PORT_NULL)
    guard task_name_for_pid(mach_task_self_, pid, &name) == KERN_SUCCESS else {
        return nil
    }
    defer { mach_port_deallocate(mach_task_self_, name) }
    var token = audit_token_t()
    var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
    let status = withUnsafeMutablePointer(to: &token) { pointer in
        pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
            task_info(name, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
        }
    }
    return status == KERN_SUCCESS ? token : nil
}

/// The audit token of the peer of the Unix socket `fd`.
func peerToken(_ fd: Int32) throws -> audit_token_t {
    var status = stat()
    guard fstat(fd, &status) == 0, (status.st_mode & S_IFMT) == S_IFSOCK else {
        throw Refused(reason: "standard input is not a socket")
    }
    var token = audit_token_t()
    var length = socklen_t(MemoryLayout<audit_token_t>.size)
    guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length) == 0,
          length == socklen_t(MemoryLayout<audit_token_t>.size)
    else {
        throw Refused(reason: "no peer token")
    }
    return token
}

/// The process ID in an audit token (`audit_token_to_pid`: the sixth value).
func pid(of token: audit_token_t) -> pid_t {
    pid_t(bitPattern: token.val.5)
}

/// The parent of the process `pid`, from the kernel.
func parentPid(of pid: pid_t) -> pid_t? {
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.stride
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
    guard sysctl(&mib, u_int(mib.count), &info, &size, nil, 0) == 0,
          size == MemoryLayout<kinfo_proc>.stride, info.kp_proc.p_pid == pid
    else {
        return nil
    }
    return info.kp_eproc.e_ppid
}

func same(_ one: audit_token_t, _ other: audit_token_t) -> Bool {
    var one = one
    var other = other
    return withUnsafeBytes(of: &one) { first in
        withUnsafeBytes(of: &other) { second in first.elementsEqual(second) }
    }
}

/// The path with all symlinks resolved, or nil when it does not exist.
func realPath(_ path: String) -> String? {
    guard let resolved = realpath(path, nil) else {
        return nil
    }
    defer { free(resolved) }
    return String(cString: resolved)
}

// MARK: - Main

#if APASSY_BROWSER_GUARD_SELFTEST
// Only the test build (`-D APASSY_BROWSER_GUARD_SELFTEST`, tests/browser_passkeys.rs)
// has these modes. They check one part of the guard and answer `allowed` or
// `refused`, never `ok`, and they run before and without the checks of the
// guard. scripts/build-app.sh does not define the flag.
func runSelfTest(_ arguments: [String]) -> Int32? {
    guard arguments.count == 3, arguments[1].hasPrefix("selftest-") else {
        return nil
    }
    do {
        switch arguments[1] {
        case "selftest-parse":
            // A synthetic KERN_PROCARGS2 buffer from standard input.
            let input = FileHandle.standardInput.readData(ofLength: maxArgumentBuffer + 1)
            guard input.count <= maxArgumentBuffer else {
                throw Refused(reason: "too long")
            }
            if let name = unsafeSwitch(in: try parseProcessArguments([UInt8](input))) {
                throw Refused(reason: "--\(name)")
            }
        case "selftest-process":
            // The arguments of a real process, read like those of the browser.
            guard let target = pid_t(arguments[2]), target > 0,
                  let token = auditToken(of: target), pid(of: token) == target
            else {
                throw Refused(reason: "no process")
            }
            try checkArguments(of: target, token: token)
        case "selftest-known":
            // The allow-list and the requirement made from each entry.
            for known in knownBrowsers {
                FileHandle.standardOutput.write(Data("known \(known.identifier) \(known.team)\n".utf8))
                FileHandle.standardOutput.write(Data("requirement \(developerIDRequirement(known))\n".utf8))
            }
        case "selftest-app":
            // The signature on disk of an app (no launch) against the allow-list.
            var staticCode: SecStaticCode?
            guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: arguments[2]) as CFURL, [], &staticCode) == errSecSuccess,
                  let staticCode
            else {
                throw Refused(reason: "no code")
            }
            var matched = false
            for known in knownBrowsers {
                var requirement: SecRequirement?
                guard SecRequirementCreateWithString(developerIDRequirement(known) as CFString, [], &requirement) == errSecSuccess,
                      let requirement
                else {
                    throw Refused(reason: "no requirement")
                }
                let strict = SecCSFlags(rawValue: kSecCSStrictValidate)
                if SecStaticCodeCheckValidityWithErrors(staticCode, strict, requirement, nil) == errSecSuccess {
                    matched = true
                }
            }
            guard matched else {
                throw Refused(reason: "the code is not a known signed browser")
            }
        case "selftest-browser":
            // The browser check of a real process: signature and arguments.
            guard let target = pid_t(arguments[2]), target > 1 else {
                throw Refused(reason: "no process")
            }
            _ = try checkBrowser(target)
        default:
            throw Refused(reason: "unknown self-test")
        }
    } catch let refused as Refused {
        FileHandle.standardOutput.write(Data("refused: \(refused.reason)\n".utf8))
        return 1
    } catch {
        FileHandle.standardOutput.write(Data("refused\n".utf8))
        return 1
    }
    FileHandle.standardOutput.write(Data("allowed\n".utf8))
    return 0
}
#endif

func runGuard() -> Int32 {
    let arguments = CommandLine.arguments
    #if APASSY_BROWSER_GUARD_SELFTEST
    if let status = runSelfTest(arguments) {
        return status
    }
    #endif
    guard arguments.count == 2 else {
        FileHandle.standardError.write(Data("apassy-browser-guard: usage: apassy-browser-guard browser-parent|socket-peer\n".utf8))
        return 2
    }
    do {
        let own = try ownApp()
        switch arguments[1] {
        case "browser-parent":
            try checkBrowserParent(app: own.app, team: own.team)
        case "socket-peer":
            try checkSocketPeer(app: own.app, team: own.team)
        default:
            throw Refused(reason: "unknown check")
        }
    } catch let refused as Refused {
        FileHandle.standardError.write(Data("apassy-browser-guard: refused: \(refused.reason)\n".utf8))
        return 1
    } catch {
        FileHandle.standardError.write(Data("apassy-browser-guard: refused\n".utf8))
        return 1
    }
    FileHandle.standardOutput.write(Data("ok\n".utf8))
    return 0
}

exit(runGuard())
