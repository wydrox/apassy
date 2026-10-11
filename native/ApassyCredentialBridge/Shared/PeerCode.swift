// Code-signing checks of another process, from its audit token. The bridge checks its
// parent (the Apassy app) and each socket peer (the AutoFill extension). The
// extension checks the bridge at the other end of its socket. Both programs compile
// this file. The rule follows native/ApassyHelper/Caller.swift:
//
//   anchor apple generic and identifier "<id>" and certificate leaf[subject.OU] = "<team>"
//
// plus the path of the running code inside the same Apassy.app. The team comes from
// the signature of the checking program itself, and must be the team of the app
// group. An unsigned or ad hoc program has no team, so it refuses every peer.
//
// The audit token names one process image, so a later exec or a reused pid does not
// pass. A socket keeps the token of the process that connected (LOCAL_PEERTOKEN).
// Nothing here trusts a user ID alone or a pid that a request claims.

import Foundation
import Security

struct CodeCheckError: Error, Equatable {
    let message: String

    init(_ message: String) {
        self.message = message
    }
}

/// A process that passed a check.
struct CheckedCode: Equatable {
    let pid: pid_t
    let identifier: String
    let team: String
    let path: String
}

/// The audit token of the process at the other end of a Unix socket.
func peerAuditToken(_ fd: Int32) -> audit_token_t? {
    var token = audit_token_t()
    var length = socklen_t(MemoryLayout<audit_token_t>.size)
    let status = getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length)
    guard status == 0, length == socklen_t(MemoryLayout<audit_token_t>.size) else {
        return nil
    }
    return token
}

/// The pid of the peer as the kernel reports it, to compare with the token.
func peerPid(_ fd: Int32) -> pid_t? {
    var pid: pid_t = 0
    var length = socklen_t(MemoryLayout<pid_t>.size)
    guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &length) == 0 else {
        return nil
    }
    return pid
}

/// Fields of an audit token (bsm/libbsm.h): val[1] is the effective user, val[5] the pid.
func tokenEffectiveUser(_ token: audit_token_t) -> uid_t {
    token.val.1
}

func tokenPid(_ token: audit_token_t) -> pid_t {
    pid_t(bitPattern: token.val.5)
}

/// The audit token of the process `pid` (the parent check).
func processAuditToken(_ pid: pid_t) -> audit_token_t? {
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

func sameAuditToken(_ one: audit_token_t, _ other: audit_token_t) -> Bool {
    var one = one
    var other = other
    return withUnsafeBytes(of: &one) { first in
        withUnsafeBytes(of: &other) { second in first.elementsEqual(second) }
    }
}

/// The team identifier and the main executable of the running program.
func ownSigning() throws -> (team: String?, executable: String) {
    var own: SecCode?
    var ownStatic: SecStaticCode?
    guard SecCodeCopySelf([], &own) == errSecSuccess, let own,
          SecCodeCheckValidity(own, [], nil) == errSecSuccess,
          SecCodeCopyStaticCode(own, [], &ownStatic) == errSecSuccess, let ownStatic
    else {
        throw CodeCheckError("This program cannot check its own signature.")
    }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(ownStatic, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let fields = info as? [String: Any],
          let executable = fields[kSecCodeInfoMainExecutable as String] as? URL
    else {
        throw CodeCheckError("This program cannot read its own signature.")
    }
    return (fields[kSecCodeInfoTeamIdentifier as String] as? String, executable.path)
}

/// The team of this program, which must be the team of the app group.
func ownTeam() throws -> String {
    guard let team = try ownSigning().team else {
        throw CodeCheckError("This program has no team signature, so it cannot check another program.")
    }
    guard team == BridgeConstants.teamIdentifier else {
        throw CodeCheckError("This program is signed by another team than the Apassy app group.")
    }
    return team
}

/// Apassy.app for a program at `path` that should end with `suffix`, or nil.
func containingApp(of path: String, suffix: String) -> String? {
    guard let resolved = resolvedPath(path), resolved.hasSuffix(suffix) else {
        return nil
    }
    let app = String(resolved.dropLast(suffix.count))
    return app.hasSuffix(".app") ? app : nil
}

/// The running code of the process with this audit token.
func runningCode(_ token: audit_token_t) throws -> SecCode {
    var token = token
    let data = withUnsafeBytes(of: &token) { Data($0) }
    var code: SecCode?
    let status = SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: data] as CFDictionary, [], &code)
    guard status == errSecSuccess, let code else {
        throw CodeCheckError("The code of the other process is not available (\(status)).")
    }
    return code
}

/// The requirement text for one signing identifier of one team.
func requirementText(identifier: String, team: String) -> String {
    "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"\(team)\""
}

/// Check the running code (dynamic and on disk) against the requirement.
func requireSignature(_ code: SecCode, identifier: String, team: String) throws {
    var requirement: SecRequirement?
    let text = requirementText(identifier: identifier, team: team)
    guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement else {
        throw CodeCheckError("The requirement cannot be built.")
    }
    let status = SecCodeCheckValidityWithErrors(code, [], requirement, nil)
    guard status == errSecSuccess else {
        throw CodeCheckError("The other process is not \(identifier) of the Apassy team (\(status)).")
    }
}

/// The path of the bundle or the file of `code`, with symlinks resolved.
func codePath(_ code: SecCode) -> String? {
    var staticCode: SecStaticCode?
    var url: CFURL?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
          SecCodeCopyPath(staticCode, [], &url) == errSecSuccess, let url
    else {
        return nil
    }
    return resolvedPath((url as URL).path)
}

/// Check the process behind `token`: signature, team, and its exact path.
func checkCode(token: audit_token_t, identifier: String, team: String, expectedPath: String) throws -> CheckedCode {
    let code = try runningCode(token)
    try requireSignature(code, identifier: identifier, team: team)
    guard let path = codePath(code), let expected = resolvedPath(expectedPath), path == expected else {
        throw CodeCheckError("The other process is not the copy of \(identifier) inside this Apassy app.")
    }
    return CheckedCode(pid: tokenPid(token), identifier: identifier, team: team, path: path)
}

/// Check the peer of a connected Unix socket. The pid of the token must be the pid the
/// kernel reports, and the peer must run as the same user.
func checkSocketPeer(_ fd: Int32, identifier: String, team: String, expectedPath: String) throws -> CheckedCode {
    guard let token = peerAuditToken(fd) else {
        throw CodeCheckError("The audit token of the peer is not available.")
    }
    guard let pid = peerPid(fd), pid == tokenPid(token), pid > 1 else {
        throw CodeCheckError("The peer process does not match its audit token.")
    }
    guard tokenEffectiveUser(token) == geteuid() else {
        throw CodeCheckError("The peer runs as another user.")
    }
    return try checkCode(token: token, identifier: identifier, team: team, expectedPath: expectedPath)
}

/// The path with all symlinks resolved, or nil when it does not exist.
func resolvedPath(_ path: String) -> String? {
    guard let resolved = realpath(path, nil) else {
        return nil
    }
    defer { free(resolved) }
    return String(cString: resolved)
}
