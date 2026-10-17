// Local notification navigation only. No URL scheme, command, approval, vault path,
// or request content crosses this channel. A random capability is meaningful only
// to the running app that issued it; the app revalidates the destination on use.
import AppKit
import Darwin
import Foundation
import UserNotifications

func validRouteToken(_ token: String) -> Bool {
    token.utf8.count == 64 && token.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}

/// No symlink, shared directory, or different owner is accepted. The directory
/// contains only 64-byte opaque capabilities, and is never an executable channel.
func activationDirectory() throws -> (url: URL, descriptor: Int32) {
    let directory = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/ApassyNotify-Activations", isDirectory: true)
    if mkdir(directory.path, 0o700) != 0 && errno != EEXIST {
        throw HelperError(.failed, "The local notification destination is unavailable.")
    }
    let descriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard descriptor >= 0 else {
        throw HelperError(.failed, "The local notification destination is unavailable.")
    }
    var info = stat()
    guard fstat(descriptor, &info) == 0,
          info.st_mode & S_IFMT == S_IFDIR, info.st_uid == geteuid(),
          info.st_mode & 0o077 == 0 else {
        close(descriptor)
        throw HelperError(.failed, "The local notification destination is not private.")
    }
    return (directory, descriptor)
}

func storeActivation(_ token: String) throws {
    guard validRouteToken(token) else { return }
    let directory = try activationDirectory()
    defer { close(directory.descriptor) }
    let files = try FileManager.default.contentsOfDirectory(atPath: directory.url.path)
    // A bounded spool avoids unlimited growth while the containing app is closed.
    guard files.count < 128 else {
        throw HelperError(.failed, "The local notification destination is full.")
    }
    let name = UUID().uuidString
    let descriptor = openat(directory.descriptor, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
    guard descriptor >= 0 else { throw HelperError(.failed, "The notification destination could not be saved.") }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    do {
        try handle.write(contentsOf: Data(token.utf8))
        try handle.close()
    } catch {
        unlinkat(directory.descriptor, name, 0)
        throw HelperError(.failed, "The notification destination could not be saved.")
    }
}

func handleNotifyActivations(_ request: Request) throws -> Fields {
    try requireNotifierBundle()
    guard Set(request.fields.keys) == ["cmd"] else {
        throw HelperError(.invalidRequest, "Notification activation polling takes no fields.")
    }
    let directory = try activationDirectory()
    defer { close(directory.descriptor) }
    let names = try FileManager.default.contentsOfDirectory(atPath: directory.url.path).sorted().prefix(128)
    var routes: [(token: String, seconds: Int, nanoseconds: Int)] = []
    for name in names {
        // Only our fixed UUID filenames can be opened or removed.
        guard UUID(uuidString: name) != nil, !name.contains("/") else { continue }
        let descriptor = openat(directory.descriptor, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard descriptor >= 0 else { continue }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(),
              info.st_mode & 0o077 == 0, info.st_nlink == 1, info.st_size == 64 else {
            continue
        }
        let data = try handle.read(upToCount: 65) ?? Data()
        // Remove the consumed hint before returning it, so successive polls do not
        // repeat navigation. It grants no authority even if it is replayed.
        guard unlinkat(directory.descriptor, name, 0) == 0 else { continue }
        if let token = String(data: data, encoding: .utf8), validRouteToken(token) {
            routes.append((token, info.st_mtimespec.tv_sec, info.st_mtimespec.tv_nsec))
        }
    }
    // Only the latest owner navigation intent wins if the app was not polling.
    let latest = routes.max { lhs, rhs in
        lhs.seconds == rhs.seconds ? lhs.nanoseconds < rhs.nanoseconds : lhs.seconds < rhs.seconds
    }
    return ["ok": true, "routes": latest.map { [$0.token] } ?? []]
}

func handleNotifyRemove(_ request: Request) throws -> Fields {
    guard Set(request.fields.keys) == ["cmd", "ids"],
          let ids = request.fields["ids"] as? [String], ids.count <= 512 else {
        throw HelperError(.invalidRequest, "Notification removal needs at most 512 identifiers.")
    }
    for id in ids {
        _ = try Request(cmd: "notify_remove", fields: ["id": id]).identifier("id")
    }
    let center = try checkedInNotificationCenter()
    center.removePendingNotificationRequests(withIdentifiers: ids)
    center.removeDeliveredNotifications(withIdentifiers: ids)
    return ["ok": true]
}

final class ActivationDelegate: NSObject, UNUserNotificationCenterDelegate {
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        // Dismissal and any unknown future actions do not navigate or approve.
        guard response.actionIdentifier == UNNotificationDefaultActionIdentifier else {
            completionHandler()
            exit(0)
        }
        // Old alerts without a capability still request an unselected list.
        let token = response.notification.request.content.userInfo["route"] as? String
        try? storeActivation(token.flatMap { validRouteToken($0) ? $0 : nil } ?? String(repeating: "0", count: 64))
        completionHandler()
        openContainingApp()
    }
}

/// LaunchServices is the only response entry point. It serves no stdin command.
/// Keep a strong delegate and an AppKit run loop so macOS can deliver the response
/// before opening the containing app. A plain helper launch opens the list safely.
func runNotificationActivation() -> Never {
    do { try requireNotifierBundle() } catch { exit(0) }
    let delegate = ActivationDelegate()
    let app = NSApplication.shared
    _ = app.setActivationPolicy(.prohibited)
    app.finishLaunching()
    let center = UNUserNotificationCenter.current()
    center.delegate = delegate
    _ = Timer.scheduledTimer(withTimeInterval: 3, repeats: false) { _ in openContainingApp() }
    withExtendedLifetime(delegate) { app.run() }
    exit(0)
}

/// Only alerts representing waiting decisions/suggestions participate. Activity,
/// blocked-request risks and sync alerts remain. The caller must have successfully
/// refreshed all waiting sources; a locked vault or read error is not settlement.
func handleNotifyReconcile(_ request: Request) throws -> Fields {
    guard Set(request.fields.keys) == ["cmd", "waiting_keys"],
          let keys = request.fields["waiting_keys"] as? [String], keys.count <= 512,
          keys.allSatisfy(validRouteToken) else {
        throw HelperError(.invalidRequest, "Invalid waiting notification keys.")
    }
    let keep = Set(keys)
    let center = try checkedInNotificationCenter()
    let done = DispatchSemaphore(value: 0)
    let box = ResultBox<[String]>()
    center.getDeliveredNotifications { notifications in
        box.set(notifications.compactMap { notification in
            guard let key = notification.request.content.userInfo["waiting_key"] as? String,
                  validRouteToken(key), !keep.contains(key) else { return nil }
            return notification.request.identifier
        })
        done.signal()
    }
    guard done.wait(timeout: .now() + .seconds(5)) == .success, let ids = box.get() else {
        throw HelperError(.failed, "Waiting notifications could not be refreshed.")
    }
    center.removePendingNotificationRequests(withIdentifiers: ids)
    center.removeDeliveredNotifications(withIdentifiers: ids)
    return ["ok": true]
}
