// Revocation-only notifications plus a trusted OS session snapshot. An unlock
// never restores a verification. Heartbeats let Rust fail closed on observer loss.
import AppKit
import CoreGraphics
import Foundation
import IOKit

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
    func emit(revoke: Bool = false) {
        do { try requireApassyParent() } catch { exit(1) }
        sequence += 1
        writeResponse(["sequence": sequence, "active": ownerSessionActive(), "revoke": revoke,
                       "idle_seconds": CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: CGEventType(rawValue: UInt32.max)!)])
    }
    let workspace = NSWorkspace.shared.notificationCenter
    var observers: [NSObjectProtocol] = []
    for name in [NSWorkspace.willSleepNotification, NSWorkspace.screensDidSleepNotification,
                 NSWorkspace.sessionDidResignActiveNotification] {
        observers.append(workspace.addObserver(forName: name, object: nil, queue: .main) { _ in emit(revoke: true) })
    }
    let distributed = DistributedNotificationCenter.default()
    observers.append(distributed.addObserver(forName: NSNotification.Name("com.apple.screenIsLocked"), object: nil, queue: .main) { _ in emit(revoke: true) })
    // Distributed events can only revoke. Authority always comes from fresh local
    // authentication and CGSession state, never from an unlock notification.
    let timer = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { _ in emit() }
    emit()
    withExtendedLifetime((observers, timer)) { RunLoop.main.run() }
    exit(0)
}
