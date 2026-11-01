// Revocation-only notifications plus a trusted OS session snapshot. An unlock
// never restores a verification. Heartbeats let Rust fail closed on observer loss.
import AppKit
import CoreGraphics
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
    return onConsole && loggedIn && !locked
}
func runOwnerLifecycle() throws -> Never {
    var sequence: UInt64 = 0
    var nextIdleSample = Date.distantPast
    func emit(revoke: Bool = false, event: String = "heartbeat") {
        do { try requireApassyParent() } catch { exit(1) }
        sequence += 1
        var fields: Fields = ["sequence": sequence, "active": ownerSessionActive(), "revoke": revoke, "event": event]
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
        observers.append(workspace.addObserver(forName: name, object: nil, queue: .main) { _ in emit(revoke: true, event: event) })
    }
    // Display sleep is not a lock. Continue sampling IOConsoleLocked at 4 Hz,
    // including while the display is off, so delayed password policies revoke.
    observers.append(workspace.addObserver(forName: NSWorkspace.screensDidSleepNotification, object: nil, queue: .main) { _ in emit(event: "display_sleep") })
    let distributed = DistributedNotificationCenter.default()
    observers.append(distributed.addObserver(forName: NSNotification.Name("com.apple.screenIsLocked"), object: nil, queue: .main) { _ in emit(revoke: true, event: "screen_locked") })
    // Distributed events can only revoke. Authority always comes from fresh local
    // authentication and CGSession state, never from an unlock notification.
    // Prevent App Nap/coalescing without preventing idle system sleep. This costs
    // four wakeups per second while the app owns the observer, even when idle.
    let activity = ProcessInfo.processInfo.beginActivity(options: .userInitiatedAllowingIdleSystemSleep,
        reason: "Observe owner verification revocation")
    defer { ProcessInfo.processInfo.endActivity(activity) }
    let timer = DispatchSource.makeTimerSource(flags: .strict, queue: .main)
    timer.schedule(deadline: .now(), repeating: .milliseconds(250), leeway: .nanoseconds(0))
    timer.setEventHandler { emit() }
    timer.resume()
    withExtendedLifetime((observers, timer, activity)) { RunLoop.main.run() }
    exit(0)
}
