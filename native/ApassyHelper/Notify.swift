// Native notifications with UNUserNotificationCenter.
//
// Preview rule (ADR 0010, goal N2): the caller sends the agent name and the
// event type only. A title or a body must never contain a command, a user
// request, or a value. The helper cannot check the meaning of the text. It
// only limits the length and refuses control characters.
//
// UNUserNotificationCenter needs an app bundle. The helper finds the bundle
// because it is in `Apassy.app/Contents/MacOS/`. Outside a bundle, the
// notification commands return `notifications_unavailable`.

import Foundation
import UserNotifications

let firstUseAuthorizationWait: DispatchTimeInterval = .seconds(20)
let explicitAuthorizationWait: DispatchTimeInterval = .seconds(120)

func notificationCenter() throws -> UNUserNotificationCenter {
    let bundle = Bundle.main
    guard bundle.bundleURL.pathExtension == "app", bundle.bundleIdentifier != nil else {
        throw HelperError(.notificationsUnavailable, "The helper is not inside an app bundle, so it cannot send notifications.")
    }
    return UNUserNotificationCenter.current()
}

func currentSettings(_ center: UNUserNotificationCenter) -> UNNotificationSettings? {
    let done = DispatchSemaphore(value: 0)
    let box = ResultBox<UNNotificationSettings>()
    center.getNotificationSettings { settings in
        box.set(settings)
        done.signal()
    }
    if done.wait(timeout: .now() + .seconds(5)) == .timedOut {
        return nil
    }
    return box.get()
}

func authorizationName(_ status: UNAuthorizationStatus) -> String {
    switch status {
    case .notDetermined: return "not_determined"
    case .denied: return "denied"
    case .authorized: return "authorized"
    case .provisional: return "provisional"
    @unknown default: return "unknown"
    }
}

func settingName(_ setting: UNNotificationSetting) -> String {
    switch setting {
    case .notSupported: return "not_supported"
    case .disabled: return "disabled"
    case .enabled: return "enabled"
    @unknown default: return "unknown"
    }
}

func alertStyleName(_ style: UNAlertStyle) -> String {
    switch style {
    case .none: return "none"
    case .banner: return "banner"
    case .alert: return "alert"
    @unknown default: return "unknown"
    }
}

func statusFields(_ settings: UNNotificationSettings) -> Fields {
    [
        "authorization": authorizationName(settings.authorizationStatus),
        "alert": settingName(settings.alertSetting),
        "alert_style": alertStyleName(settings.alertStyle),
        "notification_center": settingName(settings.notificationCenterSetting),
        "lock_screen": settingName(settings.lockScreenSetting),
        "sound": settingName(settings.soundSetting),
    ]
}

func isAllowed(_ status: UNAuthorizationStatus) -> Bool {
    status == .authorized || status == .provisional
}

/// Ask for permission. Waits at most `wait` for the owner's choice.
func requestAuthorization(_ center: UNUserNotificationCenter, wait: DispatchTimeInterval) -> (Bool, String?) {
    let done = DispatchSemaphore(value: 0)
    let box = ResultBox<(Bool, Error?)>()
    center.requestAuthorization(options: [.alert, .sound]) { granted, error in
        box.set((granted, error))
        done.signal()
    }
    if done.wait(timeout: .now() + wait) == .timedOut {
        return (false, "The owner did not answer the notification permission prompt in time.")
    }
    guard let (granted, error) = box.get() else {
        return (false, "The permission request returned no result.")
    }
    return (granted, error.map { ($0 as NSError).localizedDescription })
}

/// `notify_status`: authorization and delivery settings. Never prompts.
func handleNotifyStatus(_ request: Request) throws -> Fields {
    let center = try notificationCenter()
    guard let settings = currentSettings(center) else {
        throw HelperError(.failed, "The notification settings did not arrive in time.")
    }
    var fields = statusFields(settings)
    fields["ok"] = true
    return fields
}

/// `notify_authorize`: show the permission prompt when the owner has not
/// decided yet. Waits for the owner's choice.
func handleNotifyAuthorize(_ request: Request) throws -> Fields {
    let center = try notificationCenter()
    let (granted, detail) = requestAuthorization(center, wait: explicitAuthorizationWait)
    guard let settings = currentSettings(center) else {
        throw HelperError(.failed, "The notification settings did not arrive in time.")
    }
    var fields = statusFields(settings)
    fields["ok"] = true
    fields["granted"] = granted
    if let detail {
        fields["detail"] = detail
    }
    return fields
}

/// `notify {id, title, body}`: post one notification. Asks for permission
/// on first use.
func handleNotify(_ request: Request) throws -> Fields {
    let id = try request.identifier("id")
    let title = try request.text("title", min: 1, max: 80)
    let body = try request.text("body", min: 0, max: 200)
    let center = try notificationCenter()
    guard var settings = currentSettings(center) else {
        throw HelperError(.failed, "The notification settings did not arrive in time.")
    }
    if settings.authorizationStatus == .notDetermined {
        _ = requestAuthorization(center, wait: firstUseAuthorizationWait)
        guard let updated = currentSettings(center) else {
            throw HelperError(.failed, "The notification settings did not arrive in time.")
        }
        settings = updated
    }
    guard isAllowed(settings.authorizationStatus) else {
        throw HelperError(.notificationsDenied, "Notifications for Apassy are \(authorizationName(settings.authorizationStatus)). The event stays in the inbox.")
    }

    let content = UNMutableNotificationContent()
    content.title = title
    content.body = body
    content.threadIdentifier = "apassy-events"
    content.sound = .default
    let notification = UNNotificationRequest(identifier: id, content: content, trigger: nil)

    let done = DispatchSemaphore(value: 0)
    let box = ResultBox<Error?>()
    center.add(notification) { error in
        box.set(error)
        done.signal()
    }
    if done.wait(timeout: .now() + .seconds(5)) == .timedOut {
        throw HelperError(.failed, "The notification system did not accept the notification in time.")
    }
    if let error = box.get() ?? nil {
        let ns = error as NSError
        if ns.domain == UNErrorDomain && ns.code == UNError.Code.notificationsNotAllowed.rawValue {
            throw HelperError(.notificationsDenied, "Notifications for Apassy are not allowed. The event stays in the inbox.")
        }
        throw HelperError(.failed, "The notification failed: \(ns.domain) \(ns.code).")
    }

    var fields = statusFields(settings)
    fields["ok"] = true
    fields["delivered"] = delivered(center, id: id)
    return fields
}

/// True when Notification Center lists the notification with this id within
/// two seconds. The notification is already posted; this only reports it.
func delivered(_ center: UNUserNotificationCenter, id: String) -> Bool {
    let deadline = DispatchTime.now() + .seconds(2)
    while DispatchTime.now() < deadline {
        let done = DispatchSemaphore(value: 0)
        let box = ResultBox<Bool>()
        center.getDeliveredNotifications { list in
            box.set(list.contains { $0.request.identifier == id })
            done.signal()
        }
        if done.wait(timeout: deadline) == .success, box.get() == true {
            return true
        }
        Thread.sleep(forTimeInterval: 0.1)
    }
    return false
}
