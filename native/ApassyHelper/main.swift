// Apassy native helper: Touch ID and the data protection keychain for the
// Rust app. The Rust crate forbids unsafe code, so these Apple APIs live here.
// Notifications run in a separate program, native/ApassyNotify, because
// macOS accepts a notification client only as the main program of its own
// bundle.
//
// Protocol: JSON lines on stdin and stdout. Each request line gets exactly
// one response line. The helper exits at end of input. See
// docs/operations/native-app.md.
//
// Before each request, the helper checks that its parent process is the
// signed Apassy app that contains it (Caller.swift). Any other parent gets
// `caller_not_allowed`, also for `ping` and for a malformed request.

import Foundation

func handle(_ request: Request) throws -> Fields {
    switch request.cmd {
    case "ping":
        return [
            "ok": true,
            "protocol": protocolVersion,
            "helper_version": helperVersion,
            "bundle_id": Bundle.main.bundleIdentifier ?? NSNull(),
            "keychain_access_group": keychainAccessGroup() ?? NSNull(),
            "biometry": biometryStatus(),
        ]
    case "authenticate":
        return try handleAuthenticate(request)
    case "keychain_store":
        return try handleKeychainStore(request)
    case "keychain_read":
        return try handleKeychainRead(request)
    case "keychain_delete":
        return try handleKeychainDelete(request)
    case "keychain_exists":
        return try handleKeychainExists(request)
    case "notify", "notify_status", "notify_authorize":
        throw HelperError(.notificationsUnavailable, "Notifications run in Contents/Helpers/ApassyNotify.app, not in this helper.")
    default:
        throw HelperError(.invalidRequest, "Unknown command.")
    }
}

if CommandLine.arguments.count > 1 {
    FileHandle.standardError.write(Data("apassy-helper takes no arguments. It reads JSON lines on stdin.\n".utf8))
    exit(2)
}

while let line = readLine(strippingNewline: true) {
    if line.trimmingCharacters(in: .whitespaces).isEmpty {
        continue
    }
    let response: Fields
    do {
        try requireApassyParent()
        response = try handle(try Request.parse(line))
    } catch let error as HelperError {
        response = errorResponse(error)
    } catch {
        response = errorResponse(HelperError(.internalError, "Unexpected helper error."))
    }
    writeResponse(response)
}
exit(0)
