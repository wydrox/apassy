// Revocation-only notifications plus a trusted OS session snapshot. An unlock
// never restores a verification. Synchronous probes fence reuse after suspension.
import AppKit
import CoreGraphics
import CoreFoundation
import Foundation
import IOKit
import os.log

private let lifecycleLog = OSLog(subsystem: "com.wydrox.apassy", category: "owner-window")

func ownerSessionActive() -> Bool {
    guard let session = CGSessionCopyCurrentDictionary() as? [String: Any],
          let onConsole = session[kCGSessionOnConsoleKey as String] as? Bool,
          let loggedIn = session[kCGSessionLoginDoneKey as String] as? Bool
    else { return false }
    // CGSession omits its lock key on an unlocked session on current macOS.
    // Read the kernel registry root's explicit console-lock state instead;
    // absence or a wrong type is unknown, never inferred to mean unlocked.
    let root = IORegistryGetRootEntry(kIOMainPortDefault)
    guard root != 0 else { return false }
    defer { IOObjectRelease(root) }
    guard let locked = IORegistryEntryCreateCFProperty(root, "IOConsoleLocked" as CFString,
        kCFAllocatorDefault, 0)?.takeRetainedValue() as? Bool else { return false }
    let sessionLocked = session["CGSSessionScreenIsLocked"] as? Bool ?? false
    return onConsole && loggedIn && !locked && !sessionLocked
}
func runOwnerLifecycle() throws -> Never {
    var sequence: UInt64 = 0
    var lockCounter: UInt64 = 0
    var nextIdleSample = Date.distantPast
    func emit(revoke: Bool = false, event: String = "heartbeat", probe: UInt64? = nil) {
        do { try requireApassyParent() } catch { exit(1) }
        sequence += 1
        if revoke { lockCounter += 1 }
        let active = ownerSessionActive()
        var fields: Fields = ["sequence": sequence, "lock_counter": lockCounter, "active": active, "screen_locked": !active, "revoke": revoke, "event": event]
        if let probe { fields["probe"] = probe }
        // Reuse the identity-window heartbeat without polling system idle at 4 Hz.
        // Lifecycle events sample immediately and wake the Rust UI for cleanup.
        let now = Date()
        if revoke || now >= nextIdleSample {
            fields["idle_seconds"] = CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: CGEventType(rawValue: UInt32.max)!)
            nextIdleSample = now.addingTimeInterval(30)
        }
        if revoke { os_log("revocation: %{public}@", log: lifecycleLog, type: .info, event) }
        writeResponse(fields)
    }
    let workspace = NSWorkspace.shared.notificationCenter
    var observers: [NSObjectProtocol] = []
    for (name, event) in [(NSWorkspace.willSleepNotification, "system_sleep"),
                          (NSWorkspace.sessionDidResignActiveNotification, "session_resigned")] {
        observers.append(workspace.addObserver(forName: name, object: nil, queue: nil) { _ in emit(revoke: true, event: event) })
    }
    // Display sleep is not a lock. Continue sampling IOConsoleLocked at 4 Hz,
    // including while the display is off, so delayed password policies revoke.
    observers.append(workspace.addObserver(forName: NSWorkspace.screensDidSleepNotification, object: nil, queue: nil) { _ in emit(event: "display_sleep") })
    let distributed = DistributedNotificationCenter.default()
    observers.append(distributed.addObserver(forName: NSNotification.Name("com.apple.screenIsLocked"), object: nil, queue: nil) { _ in emit(revoke: true, event: "screen_locked") })
    // Read requests off-main; answer on the notification run loop after queued
    // notifications have drained. A suspended helper cannot answer stale state.
    DispatchQueue.global().async {
        while let line = readLine(strippingNewline: true) {
            guard let data = line.data(using: .utf8),
                  let request = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let probe = request["probe"] as? UInt64 else { exit(1) }
            DispatchQueue.main.async {
                // Drain already-pending notification sources, with synchronous
                // observer callbacks, before sampling. No scheduling-time lease.
                while CFRunLoopRunInMode(.defaultMode, 0, true) == .handledSource {}
                emit(event: "snapshot", probe: probe)
            }
        }
        exit(0)
    }
    // Distributed events can only revoke. Authority always comes from fresh local
    // authentication and CGSession state, never from an unlock notification.
    // Heartbeats are telemetry; App Nap and coalescing cannot revoke authority.
    let timer = DispatchSource.makeTimerSource(queue: .main)
    timer.schedule(deadline: .now(), repeating: .milliseconds(250), leeway: .milliseconds(100))
    timer.setEventHandler { emit() }
    timer.resume()
    withExtendedLifetime((observers, timer)) { RunLoop.main.run() }
    exit(0)
}
