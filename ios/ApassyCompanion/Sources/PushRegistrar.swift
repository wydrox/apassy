import ApassyVaultKit
import UIKit
import UserNotifications

/// Notifications of questions through the relay (contract relay-questions-v1, section 14.2). The
/// relay asks Apple to show a fixed text, "A question is waiting"; the notification holds no
/// question. Opening it opens the Decisions tab (`onOpen`, through `RootModel`), and Decisions opens
/// the newest question that waits (`QuestionsModel.notificationOpened`). The app makes no local
/// notification of its own.
///
/// The permission is asked when the owner turns notifications on in Questions, never at launch.
/// Each launch with notifications on asks iOS for the device token again, and the token goes to
/// the relay (`PUT /v1/push/token`).
@MainActor
final class PushRegistrar: NSObject, PushPermission {
    static let shared = PushRegistrar()

    /// Where a new device token goes (`QuestionsModel.receivePushToken`).
    var onToken: ((Data) -> Void)?
    /// The owner opened a notification: show the Decisions tab.
    var onOpen: (() -> Void)?
    /// The owner opened a notification: open the newest question (`QuestionsModel`).
    private var onOpenQuestion: (@MainActor () -> Void)?

    /// The `aps-environment` of this build: a debug build is signed for the development
    /// environment, TestFlight and the App Store for production.
    var environment: PushEnvironment {
        #if DEBUG
            .development
        #else
            .production
        #endif
    }

    func requestAuthorization() async -> Bool {
        let center = UNUserNotificationCenter.current()
        let granted = (try? await center.requestAuthorization(options: [.alert, .sound])) ?? false
        return granted
    }

    func registerForPushes() {
        UIApplication.shared.registerForRemoteNotifications()
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
    /// In the foreground the Decisions list updates by itself; the banner still shows, so the owner
    /// sees a question that arrives while another tab is open.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        [.banner, .sound]
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse
    ) async {
        await MainActor.run { PushRegistrar.shared.opened() }
    }
}

/// The app delegate of SwiftUI's adaptor: only the device token of APNs and the delegate of the
/// notification center.
final class AppDelegate: NSObject, UIApplicationDelegate {
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
        // No token (no network, or no aps-environment in a build without the capability): the
        // questions still show while Apassy is open.
    }
}
