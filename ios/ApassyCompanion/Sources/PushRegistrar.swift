import ApassyVaultKit
import UIKit
import UserNotifications

/// Private aggregate question alerts through the relay. The payload identifies no request,
/// vault, or agent. Opening an alert opens the refreshed Requests list. The app creates no local
/// notification and never adds private metadata to an APNs payload.
/// Permission is requested only when the owner enables notifications.
@MainActor
final class PushRegistrar: NSObject, PushPermission {
    static let shared = PushRegistrar()

    /// Where a new device token goes (`QuestionsModel.receivePushToken`).
    var onToken: ((Data) -> Void)?
    /// The owner opened a notification: show the Requests tab.
    var onOpen: (() -> Void)?
    /// The owner opened a notification: refresh the Requests list (`QuestionsModel`).
    private var onOpenQuestion: (@MainActor () -> Void)?
    private var onRegistrationFailure: (@MainActor (String) -> Void)?
    private var onForeground: (@MainActor () -> Void)?
    private var requestsVisible = false

    /// The `aps-environment` of this build: a debug build is signed for the development
    /// environment, TestFlight and the App Store for production.
    var environment: PushEnvironment {
        #if DEBUG
            .development
        #else
            .production
        #endif
    }

    func authorization() async -> RequestNotificationAuthorization {
        let settings = await UNUserNotificationCenter.current().notificationSettings()
        switch settings.authorizationStatus {
        case .notDetermined: return .notDetermined
        case .denied: return .denied
        case .provisional, .ephemeral: return .quiet
        case .authorized:
            return settings.alertSetting == .enabled ? .allowed : .quiet
        @unknown default: return .denied
        }
    }

    func observeRegistrationFailures(_ handler: @escaping @MainActor (String) -> Void) {
        onRegistrationFailure = handler
    }

    func observeForegroundRequests(_ handler: @escaping @MainActor () -> Void) {
        onForeground = handler
    }

    func setRequestsVisible(_ visible: Bool) { requestsVisible = visible }

    func deliveredRequestIdentifiers() async -> [String] {
        await UNUserNotificationCenter.current().deliveredNotifications()
            .filter { $0.request.trigger is UNPushNotificationTrigger }
            .map { $0.request.identifier }
    }

    func removeDeliveredRequests(identifiers: [String]) {
        guard !identifiers.isEmpty else { return }
        UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: identifiers)
    }

    fileprivate func registrationFailed(_ error: any Error) {
        onRegistrationFailure?(error.localizedDescription)
    }

    fileprivate func foregroundPresentation() -> UNNotificationPresentationOptions {
        onForeground?()
        return requestsVisible ? [] : [.banner, .sound]
    }

    func requestAuthorization() async -> Bool {
        let center = UNUserNotificationCenter.current()
        let granted = (try? await center.requestAuthorization(options: [.alert, .sound])) ?? false
        return granted
    }

    func registerForPushes() {
        UIApplication.shared.registerForRemoteNotifications()
    }

    /// The owner turned notifications off: iOS delivers nothing more, also from a team that keeps
    /// the token until its vault opens on this iPhone.
    func unregisterForPushes() {
        UIApplication.shared.unregisterForRemoteNotifications()
    }

    func observeOpens(_ handler: @escaping @MainActor () -> Void) {
        onOpenQuestion = handler
    }

    fileprivate func received(token: Data) {
        onToken?(token)
    }

    fileprivate func opened() {
        onOpenQuestion?()
        onOpen?()
    }
}

extension PushRegistrar: UNUserNotificationCenterDelegate {
    /// Refresh quietly only when the relevant unlocked list is visible. A detail, another tab,
    /// or a hidden vault still gets a banner; the private payload cannot identify its request.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        await MainActor.run { PushRegistrar.shared.foregroundPresentation() }
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse
    ) async {
        await MainActor.run { PushRegistrar.shared.opened() }
    }
}

/// The app delegate of SwiftUI's adaptor: the device token of APNs, the delegate of the
/// notification center, and no keyboards of other apps.
final class AppDelegate: NSObject, UIApplicationDelegate {
    /// No keyboard of another app in Apassy: such a keyboard sees every key, so it could read a
    /// pasted secret or a passphrase. The system keyboard stays. This is app-wide, as in other
    /// password managers.
    func application(
        _ application: UIApplication,
        shouldAllowExtensionPointIdentifier extensionPointIdentifier: UIApplication.ExtensionPointIdentifier
    ) -> Bool {
        extensionPointIdentifier != .keyboard
    }

    func application(
        _ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        UNUserNotificationCenter.current().delegate = PushRegistrar.shared
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        PushRegistrar.shared.received(token: deviceToken)
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: any Error) {
        PushRegistrar.shared.registrationFailed(error)
    }
}
