import ApassyVaultKit
import Foundation
import UserNotifications

/// The Notification Service Extension of the iPhone app (push-gateway-v1 section 12). A push of a
/// node can carry a sealed summary (`s`). The extension opens it with the summary key of a
/// questions team, which the app keeps in the Keychain group `com.wydrox.apassy.push`, and shows
/// its title and body. Without a summary, with no key that opens it, after 5 seconds, or on any
/// failure, the notification keeps the fixed text "A question is waiting".
///
/// The extension makes no network request, opens no vault, and logs nothing.
final class NotificationService: UNNotificationServiceExtension {
    /// The summary keys are read and tried within this time, else the text stays fixed.
    private static let deadline: TimeInterval = 5

    private var contentHandler: ((UNNotificationContent) -> Void)?
    private var original: UNNotificationContent?

    override func didReceive(
        _ request: UNNotificationRequest, withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
    ) {
        self.contentHandler = contentHandler
        original = request.content
        let started = Date()
        let keys = KeychainPushSummaryKeyStore.forThisApp(watch: false)?.loadAll() ?? []
        guard Date().timeIntervalSince(started) < Self.deadline,
            let texts = PushSummaryNotification.texts(
                userInfo: request.content.userInfo, keys: keys, now: Date(), device: .iphone),
            let content = request.content.mutableCopy() as? UNMutableNotificationContent
        else {
            deliver(request.content)
            return
        }
        content.title = texts.title
        content.body = texts.body
        // The sealed summary is not kept with the delivered notification.
        content.userInfo[PushSummaryNotification.payloadKey] = nil
        deliver(content)
    }

    override func serviceExtensionTimeWillExpire() {
        if let original { deliver(original) }
    }

    private func deliver(_ content: UNNotificationContent) {
        guard let handler = contentHandler else { return }
        contentHandler = nil
        handler(content)
    }
}
