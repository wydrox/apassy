// apassy-credential-bridge: the authenticated path between the AutoFill extension
// (Contents/PlugIns/ApassyAutoFill.appex) and the Apassy app. The Rust crate forbids
// unsafe code, so the socket peer check (LOCAL_PEERTOKEN and the Security framework)
// lives here. See docs/operations/mac-passkeys.md.
//
// Only the signed Apassy app that contains this program may start it, as its child.
// The bridge listens on <group container 7S3F9767BM.com.wydrox.apassy>/bridge/cp.sock
// (folder 0700, socket 0600), accepts only the signed extension of the same bundle,
// and forwards each checked request to the app as one JSON line on stdout. The app
// answers on stdin. The bridge holds no key, no vault, and no secret; it never logs a
// request or an answer.
//
// Development override: a bridge built with `-D APASSY_BRIDGE_DEV` reads
// APASSY_BRIDGE_DEV_ANY_PARENT=1, APASSY_BRIDGE_DEV_ANY_PEER=1,
// APASSY_BRIDGE_DEV_CONTAINER=<folder>, and APASSY_BRIDGE_DEV_TIMEOUT=<seconds>. In a
// release build these names are not even in the binary.
// The tests build it this way. scripts/build-credential-provider.sh refuses a release
// bridge that contains these names.

import Foundation

/// Development overrides. A release bridge has none: every value is off.
struct DevelopmentOverrides {
    var anyParent = false
    var anyPeer = false
    var container: String?
    var timeout: Double?

    static func load() -> DevelopmentOverrides {
        var overrides = DevelopmentOverrides()
        #if APASSY_BRIDGE_DEV
        let environment = ProcessInfo.processInfo.environment
        overrides.anyParent = environment["APASSY_BRIDGE_DEV_ANY_PARENT"] == "1"
        overrides.anyPeer = environment["APASSY_BRIDGE_DEV_ANY_PEER"] == "1"
        overrides.container = environment["APASSY_BRIDGE_DEV_CONTAINER"]
        overrides.timeout = environment["APASSY_BRIDGE_DEV_TIMEOUT"].flatMap(Double.init).flatMap { $0 > 0 ? $0 : nil }
        #endif
        return overrides
    }
}

/// Check the parent (the Apassy app that contains this bridge) and find the paths.
func loadSettings(_ overrides: DevelopmentOverrides) throws -> BridgeSettings {
    var parent: pid_t?
    var team: String?
    var extensionPath: String?
    if overrides.anyParent {
        team = try? ownTeam()
    } else {
        let checked = try checkParent()
        parent = checked.parent
        team = checked.team
        let path = checked.app + BridgeConstants.extensionPathInApp
        guard resolvedPath(path) != nil else {
            throw BridgeFailure("no_extension", "This Apassy app has no AutoFill extension.")
        }
        extensionPath = path
    }

    let container: URL
    if let override = overrides.container {
        container = URL(fileURLWithPath: override, isDirectory: true)
    } else if let group = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: BridgeConstants.appGroup) {
        container = group
    } else {
        throw BridgeFailure("socket_unavailable", "The app group container of Apassy is not available.")
    }
    guard let socketPath = bridgeSocketPath(container: container) else {
        throw BridgeFailure("socket_unavailable", "The socket path in the app group is too long.")
    }

    var peerCheck = PeerCheck.codeSignature(team: team, extensionPath: extensionPath)
    #if APASSY_BRIDGE_DEV
    if overrides.anyPeer {
        peerCheck = .developmentOverride
    }
    #endif
    return BridgeSettings(
        socketDirectory: (socketPath as NSString).deletingLastPathComponent, socketPath: socketPath,
        peerCheck: peerCheck, parent: parent, timeout: overrides.timeout ?? BridgeConstants.requestTimeout)
}

/// The rule of native/ApassyHelper/Caller.swift: the parent is not launchd, it is the
/// signed Apassy app of this team, it is the bundle that contains this bridge, and it
/// is the same process (audit token) after the check.
func checkParent() throws -> (parent: pid_t, team: String, app: String) {
    let parent = getppid()
    guard parent > 1 else {
        throw BridgeFailure("caller_not_allowed", "launchd started the bridge. Only Apassy.app can start it.")
    }
    let team: String
    let app: String
    do {
        team = try ownTeam()
        guard let found = containingApp(of: try ownSigning().executable, suffix: BridgeConstants.bridgePathInApp) else {
            throw CodeCheckError("The bridge is not inside Apassy.app.")
        }
        app = found
        guard let token = processAuditToken(parent) else {
            throw CodeCheckError("The bridge cannot identify its parent process.")
        }
        _ = try checkCode(token: token, identifier: BridgeConstants.appIdentifier, team: team, expectedPath: app)
        guard getppid() == parent, let again = processAuditToken(parent), sameAuditToken(again, token) else {
            throw CodeCheckError("The parent process changed during the check.")
        }
    } catch let error as CodeCheckError {
        throw BridgeFailure("caller_not_allowed", error.message)
    }
    return (parent, team, app)
}

/// A fatal error: one line for the app, one line for the log, then exit.
func fail(_ failure: BridgeFailure, status: Int32) -> Never {
    log("\(failure.code): \(failure.message)")
    if let line = jsonLine(["type": "error", "v": BridgeConstants.protocolVersion, "code": failure.code, "message": failure.message]) {
        _ = writeAll(STDOUT_FILENO, line)
    }
    exit(status)
}

signal(SIGPIPE, SIG_IGN)
if CommandLine.arguments.count > 1 {
    FileHandle.standardError.write(Data("apassy-credential-bridge takes no arguments. Apassy.app starts it.\n".utf8))
    exit(2)
}
do {
    let server = try BridgeServer(settings: try loadSettings(DevelopmentOverrides.load()))
    exit(server.run())
} catch let failure as BridgeFailure {
    fail(failure, status: failure.code == "busy" ? 3 : 1)
} catch {
    fail(BridgeFailure("internal", "The bridge could not start."), status: 1)
}
