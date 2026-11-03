import Foundation
import Observation

/// What the watch app asks the system for its notifications: the permission, the APNs
/// registration, and the `aps-environment` of the build.
@MainActor
public protocol WatchPushPermission: AnyObject {
    var environment: PushEnvironment { get }
    func requestAuthorization() async -> Bool
    func registerForPushes()
    func unregisterForPushes()
}

/// "Notifications on this watch" (push-gateway-v1 section 11, ADR 0039 section 7). Off by default:
/// without it the iPhone's alert is mirrored to the watch while the iPhone is locked. On, the watch
/// registers its own handle at the push gateway (the core, kind `watch`) for its one questions
/// team, and keeps the summary key of that team for its Notification Service Extension. The
/// hosted relay has no watch push: the core says so and the setting shows it.
@MainActor
@Observable
public final class WatchNotificationsModel {
    public enum Status: Equatable, Sendable {
        case off
        /// Waiting for the APNs token or for the replica to open.
        case registering
        case on
        /// The owner did not allow notifications for Apassy on this watch.
        case denied
        case failed(String)
    }

    public static let enabledKey = "ApassyWatchNotificationsOn"

    public private(set) var enabled: Bool
    public private(set) var status: Status

    @ObservationIgnored private let service: (any WatchService)?
    @ObservationIgnored private weak var permission: (any WatchPushPermission)?
    @ObservationIgnored private let keys: (any PushSummaryKeyStore)?
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private var token: Data?

    public init(
        service: (any WatchService)?, permission: (any WatchPushPermission)?, keys: (any PushSummaryKeyStore)?,
        defaults: UserDefaults = .standard
    ) {
        self.service = service
        self.permission = permission
        self.keys = keys
        self.defaults = defaults
        enabled = defaults.bool(forKey: Self.enabledKey)
        status = enabled ? .registering : .off
    }

    /// The text under the switch, nil when there is nothing to say.
    public var footnote: String? {
        switch status {
        case .off: "Without this, alerts reach the watch from your iPhone while it is locked."
        case .registering: "Turning on…"
        case .on: "Access requests alert this watch directly."
        case .denied: "Notifications are off for Apassy in the Watch app on your iPhone."
        case .failed(let message): message
        }
    }

    /// At launch and when the app becomes active: register again while the setting is on.
    public func refresh() async {
        guard enabled else { return }
        if let token {
            await send(token)
        } else {
            permission?.registerForPushes()
        }
    }

    public func setEnabled(_ on: Bool) async {
        if on {
            guard let permission, await permission.requestAuthorization() else {
                status = .denied
                return
            }
            enabled = true
            defaults.set(true, forKey: Self.enabledKey)
            status = .registering
            token = nil
            permission.registerForPushes()
        } else {
            enabled = false
            defaults.set(false, forKey: Self.enabledKey)
            token = nil
            status = .off
            permission?.unregisterForPushes()
            keys?.removeAll()
            try? await service?.pushTokenClear()
        }
    }

    /// The APNs token of this launch.
    public func receiveToken(_ token: Data) async {
        guard enabled else { return }
        self.token = token
        await send(token)
    }

    public func registrationFailed(_ message: String) {
        guard enabled else { return }
        status = .failed(message)
    }

    private func send(_ token: Data) async {
        guard let service, let permission else { return }
        do {
            try await service.pushTokenSet(token: token, environment: permission.environment)
            guard enabled else { return }
            status = .on
            if let keys, let summary = try? await service.pushSummaryKeys() {
                // One team: the watch's keys are exactly those of the core.
                keys.sync(summary, known: [])
            }
        } catch let error as VaultError where error.code == .locked || error.code == .noQuestions {
            // The replica is not open yet: the next refresh sends it.
            status = .registering
        } catch {
            status = .failed(error.localizedDescription)
        }
    }
}
