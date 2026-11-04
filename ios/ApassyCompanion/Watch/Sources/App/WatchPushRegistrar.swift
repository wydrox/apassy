import ApassyVaultKit
import UserNotifications
import WatchKit

/// The system side of "Notifications on this watch" (push-gateway-v1 section 11): the permission,
/// the APNs registration, and the token, which goes to `WatchNotificationsModel` and from there to
/// the core (a handle at the push gateway; the token never reaches a relay).
@MainActor
final class WatchPushRegistrar: NSObject, WatchPushPermission {
    static let shared = WatchPushRegistrar()

    /// Where a new device token goes.
    var onToken: ((Data) -> Void)?
    /// Where a failed registration goes.
    var onFailure: ((String) -> Void)?

    /// The `aps-environment` of this build: a debug build is signed for development, TestFlight and
    /// the App Store for production.
    var environment: PushEnvironment {
        #if DEBUG
            .development
        #else
            .production
        #endif
    }

    func requestAuthorization() async -> Bool {
        (try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])) ?? false
    }

    func registerForPushes() { WKApplication.shared().registerForRemoteNotifications() }

    func unregisterForPushes() { WKApplication.shared().unregisterForRemoteNotifications() }

    fileprivate func received(token: Data) { onToken?(token) }

    fileprivate func failed(_ error: any Error) { onFailure?(error.localizedDescription) }
}

/// The app delegate of SwiftUI's adaptor: the APNs device token of the watch.
@MainActor
final class WatchAppDelegate: NSObject, WKApplicationDelegate {
    func didRegisterForRemoteNotifications(withDeviceToken deviceToken: Data) {
        WatchPushRegistrar.shared.received(token: deviceToken)
    }

    func didFailToRegisterForRemoteNotificationsWithError(_ error: any Error) {
        WatchPushRegistrar.shared.failed(error)
    }
}
