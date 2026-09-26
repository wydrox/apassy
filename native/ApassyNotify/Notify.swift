// Native notifications with UNUserNotificationCenter (goal items N1 and N2).
//
// Preview rule (ADR 0010, goal N2): the caller sends the event type and the
// agent name only. The notifier builds the title and the body from fixed
// templates. It refuses a request with any other field, so a caller cannot
// put a command, a user request, or a value into a notification.
//
// Measured on macOS 27 (docs/operations/native-app.md, "Notification
// research"):
// - usernotificationsd accepts a client only when the signing identifier of
//   the process is the bundle ID of its app bundle. Else it needs the private
//   entitlement `com.apple.private.usernotifications.bundle-identifiers`. So
//   the notifier is the main program of its own bundle, signed with the
//   bundle ID `com.wydrox.apassy.notify`.
// - usernoted then looks up the bundle ID in LaunchServices. When
//   LaunchServices does not know the bundle, the request fails with
//   UNErrorDomain error 1 ("Notifications are not allowed for this
//   application"). An AppKit check-in (NSApplication) registers the running
//   bundle. So the notifier checks in before it asks for permission or posts.
// - The order is important. usernoted looks up the client once, when the
//   process first connects (`UNUserNotificationCenter.current()`). A lookup
//   before the check-in fails, and the connection keeps the failure: the
//   permission request then fails at once, with no prompt. So the check-in
//   comes first, and the notifier gets the center after it.
// - macOS shows the permission prompt only while the requesting process
//   waits. When the notifier stops waiting, macOS removes the prompt, and the
//   permission stays "denied". A new request then fails at once, with no
//   prompt. Only System Settings > Notifications > Apassy can turn it on.
//   So only `notify_authorize` asks, after the owner selects "Allow
//   notifications" in the app. `notify` never asks: an unattended prompt
//   would end as "denied".

import AppKit
import Foundation
import UserNotifications

/// How long `notify_authorize` keeps the permission prompt on the screen.
let explicitAuthorizationWait: DispatchTimeInterval = .seconds(120)

/// The bundle ID of the notifier. Notifications and the permission belong to it.
let notifierBundleID = "com.wydrox.apassy.notify"
/// Largest agent name, in characters. The Rust client has the same limit.
let maxAgentNameCharacters = 40

/// The event types of goal item N1. The raw value is the wire name.
enum NotificationEvent: String {
    case approvalWaiting = "approval_waiting"
    case requestBlocked = "request_blocked"
}

/// The only texts that the notifier shows (goal item N2).
func preview(_ event: NotificationEvent, agent: String) -> (title: String, body: String) {
    switch event {
    case .approvalWaiting:
        return ("Approval waiting", "Agent \"\(agent)\" waits for your decision. Open Apassy to review.")
    case .requestBlocked:
        return ("Request blocked", "Apassy blocked a request from agent \"\(agent)\".")
    }
}

/// The fields that a `notify` or `preview` request can have.
let notifyFields: Set<String> = ["cmd", "id", "event", "agent"]

/// The event and the agent name of a request, checked.
func eventAndAgent(_ request: Request) throws -> (NotificationEvent, String) {
    let extra = Set(request.fields.keys).subtracting(notifyFields)
    guard extra.isEmpty else {
        throw HelperError(.invalidRequest, "The notifier builds the text itself. A request has only id, event, and agent.")
    }
    guard let event = NotificationEvent(rawValue: try request.string("event")) else {
        throw HelperError(.invalidRequest, "The field \"event\" must be approval_waiting or request_blocked.")
    }
    let agent = try request.text("agent", min: 1, max: maxAgentNameCharacters)
    guard !agent.trimmingCharacters(in: .whitespaces).isEmpty else {
        throw HelperError(.invalidRequest, "The field \"agent\" must not be blank.")
    }
    return (event, agent)
}

/// Outside the notifier bundle, the notification commands return
/// `notifications_unavailable`, before any contact with macOS.
func requireNotifierBundle() throws {
    let bundle = Bundle.main
    guard bundle.bundleURL.pathExtension == "app", bundle.bundleIdentifier == notifierBundleID else {
        throw HelperError(.notificationsUnavailable, "The notifier is not inside ApassyNotify.app, so it cannot send notifications.")
    }
}

/// The notification center of the notifier bundle, without a check-in. Use
/// it only to read the settings.
func notificationCenter() throws -> UNUserNotificationCenter {
    try requireNotifierBundle()
    return UNUserNotificationCenter.current()
}

/// The notification center of the notifier bundle, after the AppKit check-in
/// registered the running bundle with LaunchServices. The notifier has no
/// window, no Dock icon, and no menu. The check-in must come before the first
/// use of the center (see the note at the top of this file).
func checkedInNotificationCenter() throws -> UNUserNotificationCenter {
    try requireNotifierBundle()
    let app = NSApplication.shared
    _ = app.setActivationPolicy(.prohibited)
    app.finishLaunching()
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

/// The result of a permission request.
enum AuthorizationAnswer {
    /// The owner answered, or macOS had a decision already.
    case answered(granted: Bool)
    /// The owner did not answer within the wait. The prompt can stay on the
    /// screen, and a later answer still counts.
    case noAnswer
    /// macOS refused the request without a prompt. The text has no secret.
    case refused(String)
}

/// Ask for permission. Waits at most `wait` for the owner's choice.
func requestAuthorization(_ center: UNUserNotificationCenter, wait: DispatchTimeInterval) -> AuthorizationAnswer {
    let done = DispatchSemaphore(value: 0)
    let box = ResultBox<(Bool, Error?)>()
    center.requestAuthorization(options: [.alert, .sound]) { granted, error in
        box.set((granted, error))
        done.signal()
    }
    if done.wait(timeout: .now() + wait) == .timedOut {
        return .noAnswer
    }
    guard let (granted, error) = box.get() else {
        return .refused("The permission request returned no result.")
    }
    if let error {
        let ns = error as NSError
        return .refused("\(ns.domain) \(ns.code): \(ns.localizedDescription)")
    }
    return .answered(granted: granted)
}

/// `notify_status`: authorization and delivery settings. Never prompts, and
/// does not register the bundle.
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
/// decided yet. Waits for the owner's choice. A refusal by macOS without a
/// prompt is the error `failed`, so the app shows it (goal item N3).
func handleNotifyAuthorize(_ request: Request) throws -> Fields {
    let center = try checkedInNotificationCenter()
    let answer = requestAuthorization(center, wait: explicitAuthorizationWait)
    if case .refused(let detail) = answer {
        throw HelperError(.failed, "macOS refused the notification permission request without a prompt: \(detail)")
    }
    guard let settings = currentSettings(center) else {
        throw HelperError(.failed, "The notification settings did not arrive in time.")
    }
    var fields = statusFields(settings)
    fields["ok"] = true
    if case .answered(let granted) = answer {
        fields["granted"] = granted
    } else {
        fields["granted"] = false
        fields["detail"] = "The owner did not answer the notification permission prompt in time."
    }
    return fields
}

/// `preview {event, agent}`: the title and the body that `notify` shows.
/// Posts nothing.
func handlePreview(_ request: Request) throws -> Fields {
    let (event, agent) = try eventAndAgent(request)
    let text = preview(event, agent: agent)
    return ["ok": true, "title": text.title, "body": text.body]
}

/// `notify {id, event, agent}`: post one notification with the fixed text.
/// Never asks for permission (see the note at the top of this file).
func handleNotify(_ request: Request) throws -> Fields {
    let id = try request.identifier("id")
    let (event, agent) = try eventAndAgent(request)
    let text = preview(event, agent: agent)
    let center = try checkedInNotificationCenter()
    guard let settings = currentSettings(center) else {
        throw HelperError(.failed, "The notification settings did not arrive in time.")
    }
    if settings.authorizationStatus == .notDetermined {
        throw HelperError(.notificationsDenied, "The owner has not allowed notifications for Apassy yet. The event stays in the inbox.")
    }
    guard isAllowed(settings.authorizationStatus) else {
        throw HelperError(.notificationsDenied, "Notifications for Apassy are \(authorizationName(settings.authorizationStatus)). The event stays in the inbox.")
    }

    let content = UNMutableNotificationContent()
    content.title = text.title
    content.body = text.body
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
        Thread.sleep(forTimeInterval: 0.02)
    }
    return false
}

/// LaunchServices started the notifier, for example after a click on an
/// Apassy notification. The notifier serves no request in this case. It
/// only opens the Apassy app that contains it, and exits.
func openContainingApp() -> Never {
    guard let executable = Bundle.main.executableURL?.path,
          let app = containingApp(of: executable)
    else {
        exit(0)
    }
    let done = DispatchSemaphore(value: 0)
    NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: app), configuration: NSWorkspace.OpenConfiguration()) { _, _ in
        done.signal()
    }
    _ = done.wait(timeout: .now() + .seconds(10))
    exit(0)
}
