// Apassy notifier: native notifications for the Rust app (goal items N1 to
// N3). It is the main program of `Apassy.app/Contents/Helpers/ApassyNotify.app`
// (bundle ID `com.wydrox.apassy.notify`, display name "Apassy").
//
// Protocol: the JSON lines of the native helper (native/ApassyHelper/
// Protocol.swift). Each request line gets exactly one response line. The
// notifier exits at end of input. See docs/operations/native-app.md.
//
// Guard: the Apassy app starts the notifier as its child, as it starts the
// keychain helper. Before each request, the notifier checks that its parent
// process is the signed Apassy app that contains it (Caller.swift). Any other
// parent gets `caller_not_allowed`, also for `ping` and for a malformed
// request. A notification has only the fixed text of Notify.swift.
//
// When LaunchServices starts the notifier (launchd is the parent), for
// example after a click on a notification, it serves no request. It opens the
// Apassy app that contains it and exits.

import Foundation

func handle(_ request: Request) throws -> Fields {
    switch request.cmd {
    case "ping":
        return [
            "ok": true,
            "protocol": protocolVersion,
            "helper_version": helperVersion,
            "bundle_id": Bundle.main.bundleIdentifier ?? NSNull(),
        ]
    case "notify":
        return try handleNotify(request)
    case "notify_status":
        return try handleNotifyStatus(request)
    case "notify_authorize":
        return try handleNotifyAuthorize(request)
    case "preview":
        return try handlePreview(request)
    default:
        throw HelperError(.invalidRequest, "Unknown command.")
    }
}

// LaunchServices can pass its own arguments, so this check comes first.
if getppid() == 1 {
    openContainingApp()
}

if CommandLine.arguments.count > 1 {
    FileHandle.standardError.write(Data("ApassyNotify takes no arguments. It reads JSON lines on stdin.\n".utf8))
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
        response = errorResponse(HelperError(.internalError, "Unexpected notifier error."))
    }
    writeResponse(response)
}
exit(0)
