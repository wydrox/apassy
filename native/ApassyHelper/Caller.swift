// Caller check: the helper answers only the signed Apassy app that contains it.
//
// The agent profile (sandbox/apassy-agent-host.sb) denies the start of the
// helpers. This check is a second layer. It stops a helper that another
// process started: for example LaunchServices (`open`), launchctl, a
// terminal, or a copy of the bundle. Without it, such a process could show
// a Touch ID prompt with its own reason text, ask for the unlock key, or
// post a notification with its own text.
//
// Before each request, the helper checks its parent process:
//
// 1. The parent is not launchd. LaunchServices, launchctl, and login items
//    start a program with launchd (pid 1) as the parent.
// 2. The helper gets the audit token of the parent: `task_name_for_pid` and
//    `task_info(TASK_AUDIT_TOKEN)`. An audit token names one process image. A
//    later exec in the parent gives a different token.
// 3. `SecCodeCopyGuestWithAttributes` with `kSecGuestAttributeAudit` gives the
//    code of the parent. `SecCodeCheckValidityWithErrors` checks the running
//    code against the requirement
//      anchor apple generic and identifier "com.wydrox.apassy"
//      and certificate leaf[subject.OU] = "<team of this helper>"
//    The team comes from the signature of the helper itself
//    (`kSecCodeInfoTeamIdentifier`). An unsigned or ad hoc helper has no team,
//    so it refuses every request.
// 4. The parent is the app bundle that contains this helper
//    (`SecCodeCopyPath`). So a program signed as `com.wydrox.apassy` in another
//    place does not pass.
//
// The notifier (native/ApassyNotify) compiles this file too, so it has the
// same check. The Apassy app starts it as its child, like the keychain
// helper. Measured: macOS does not need a LaunchServices start of the
// notifier (docs/operations/native-app.md, "Notification research").
// 5. After the check, the parent is still the same process with the same
//    audit token.
//
// A failure gives the error `caller_not_allowed`. The helper then does
// nothing else for the request.
//
// Development override: a helper built with `-D APASSY_HELPER_DEV` skips the
// check when the environment has APASSY_HELPER_DEV_ANY_CALLER=1. Tests build
// the helper this way. scripts/build-app.sh does not set the flag, so a
// release helper does not contain the override.

import Foundation
import Security

/// Signing identifier and bundle ID of the only allowed parent.
let apassyAppIdentifier = "com.wydrox.apassy"

/// The helper paths inside Apassy.app, relative to the app bundle. The
/// notifier (native/ApassyNotify) uses this file too.
let helperPathsInApp = [
    "/Contents/MacOS/apassy-helper",
    "/Contents/Helpers/ApassyKeychain.app/Contents/MacOS/ApassyKeychain",
    "/Contents/Helpers/ApassyNotify.app/Contents/MacOS/ApassyNotify",
]

#if APASSY_HELPER_DEV
/// Development builds only: set to "1" to skip the caller check.
let devAnyCallerVariable = "APASSY_HELPER_DEV_ANY_CALLER"
#endif

func callerNotAllowed(_ message: String) -> HelperError {
    HelperError(.callerNotAllowed, message)
}

/// Throws `caller_not_allowed` unless the parent process is the signed Apassy
/// app that contains this helper.
func requireApassyParent() throws {
    #if APASSY_HELPER_DEV
    if ProcessInfo.processInfo.environment[devAnyCallerVariable] == "1" {
        return
    }
    #endif
    let parent = getppid()
    guard parent > 1 else {
        throw callerNotAllowed("launchd started the helper. Only Apassy.app can start it.")
    }
    let own = try ownSigning()
    guard let team = own.team else {
        throw callerNotAllowed("The helper has no team signature, so it cannot check its caller.")
    }
    guard let app = containingApp(of: own.executable) else {
        throw callerNotAllowed("The helper is not inside Apassy.app.")
    }
    guard let token = auditToken(of: parent) else {
        throw callerNotAllowed("The helper cannot identify its parent process.")
    }
    let code = try parentCode(token)
    try checkRequirement(code, team: team)
    guard let parentPath = codePath(code), let parentApp = realPath(parentPath), parentApp == app else {
        throw callerNotAllowed("The parent process is not the Apassy app that contains this helper.")
    }
    guard getppid() == parent, let again = auditToken(of: parent), sameToken(again, token) else {
        throw callerNotAllowed("The parent process changed during the check.")
    }
}

/// The team identifier and the main executable path of this helper.
func ownSigning() throws -> (team: String?, executable: String) {
    var own: SecCode?
    var ownStatic: SecStaticCode?
    guard SecCodeCopySelf([], &own) == errSecSuccess, let own,
          SecCodeCheckValidity(own, [], nil) == errSecSuccess,
          SecCodeCopyStaticCode(own, [], &ownStatic) == errSecSuccess, let ownStatic
    else {
        throw callerNotAllowed("The helper cannot check its own signature.")
    }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(ownStatic, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let fields = info as? [String: Any],
          let executable = fields[kSecCodeInfoMainExecutable as String] as? URL
    else {
        throw callerNotAllowed("The helper cannot read its own signature.")
    }
    return (fields[kSecCodeInfoTeamIdentifier as String] as? String, executable.path)
}

/// The Apassy.app bundle that contains the helper at `executable`, or nil.
func containingApp(of executable: String) -> String? {
    guard let resolved = realPath(executable) else {
        return nil
    }
    for suffix in helperPathsInApp where resolved.hasSuffix(suffix) {
        let app = String(resolved.dropLast(suffix.count))
        if app.hasSuffix(".app") {
            return app
        }
    }
    return nil
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

func sameToken(_ one: audit_token_t, _ other: audit_token_t) -> Bool {
    var one = one
    var other = other
    return withUnsafeBytes(of: &one) { first in
        withUnsafeBytes(of: &other) { second in first.elementsEqual(second) }
    }
}

/// The running code of the process with this audit token.
func parentCode(_ token: audit_token_t) throws -> SecCode {
    var token = token
    let data = withUnsafeBytes(of: &token) { Data($0) }
    var code: SecCode?
    let status = SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: data] as CFDictionary, [], &code)
    guard status == errSecSuccess, let code else {
        throw callerNotAllowed("The helper cannot get the code of its parent process (\(status)).")
    }
    return code
}

/// Check the running parent against the Apassy requirement for `team`.
func checkRequirement(_ code: SecCode, team: String) throws {
    let text = "anchor apple generic and identifier \"\(apassyAppIdentifier)\" and certificate leaf[subject.OU] = \"\(team)\""
    var requirement: SecRequirement?
    guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement else {
        throw callerNotAllowed("The helper cannot build the caller requirement.")
    }
    let status = SecCodeCheckValidityWithErrors(code, [], requirement, nil)
    guard status == errSecSuccess else {
        throw callerNotAllowed("The parent process is not the signed Apassy app (\(status)).")
    }
}

/// The path of the bundle or the file of `code`.
func codePath(_ code: SecCode) -> String? {
    var staticCode: SecStaticCode?
    var url: CFURL?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
          SecCodeCopyPath(staticCode, [], &url) == errSecSuccess, let url
    else {
        return nil
    }
    return (url as URL).path
}

/// The path with all symlinks resolved, or nil when it does not exist.
func realPath(_ path: String) -> String? {
    guard let resolved = realpath(path, nil) else {
        return nil
    }
    defer { free(resolved) }
    return String(cString: resolved)
}
