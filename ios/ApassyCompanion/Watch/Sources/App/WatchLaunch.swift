import ApassyVaultCore
import ApassyVaultKit
import Foundation
import SwiftUI

/// Makes the model of the app: the core over the data folder of the watch, or, in a Simulator or
/// Debug build, the synthetic states of the launch arguments (ios/README.md):
///
/// - `-ApassyWatchPreview <state>`: `WatchPreviewState`, synthetic data only.
/// - `-ApassyWatchConnectLink <link>`: start a connection as if the iPhone had sent the code.
/// - `-ApassyWatchScrollToEnd YES`: open the request and Connected screens at their end, for
///   screenshots of the answers and results.
enum WatchLaunch {
    /// Where a long screen opens: its top, or (Debug and Simulator, `-ApassyWatchScrollToEnd`) its end.
    static var scrollAnchor: UnitPoint? {
        #if DEBUG || targetEnvironment(simulator)
            UserDefaults.standard.bool(forKey: "ApassyWatchScrollToEnd") ? .bottom : nil
        #else
            nil
        #endif
    }

    /// The model of the app and of "Notifications on this watch".
    @MainActor
    static func makeModels() -> (WatchAppModel, WatchNotificationsModel) {
        let model = makeModel()
        let notifications = WatchNotificationsModel(
            service: notificationService, permission: WatchPushRegistrar.shared,
            keys: KeychainPushSummaryKeyStore.forThisApp(watch: true))
        return (model, notifications)
    }

    /// The core of the app, for the notifications: nil in a preview or when it did not start.
    @MainActor private static var notificationService: (any WatchService)?

    @MainActor
    static func makeModel() -> WatchAppModel {
        #if DEBUG || targetEnvironment(simulator)
            if let value = UserDefaults.standard.string(forKey: "ApassyWatchPreview"),
                let state = WatchPreviewState(rawValue: value)
            {
                return WatchPreview.model(state)
            }
            let launchLink = UserDefaults.standard.string(forKey: "ApassyWatchConnectLink")
        #else
            let launchLink: String? = nil
        #endif
        let name = WatchDeviceName.current()
        let keys = KeychainWatchAnswerKeys()
        let replica = KeychainWatchReplicaStore()
        do {
            let service = try WatchCoreService(
                dataDirectory: try dataDirectory(), deviceName: WatchConnectLink.defaultName(deviceName: name))
            notificationService = service
            return WatchAppModel(service: service, keys: keys, replica: replica, deviceName: name, launchLink: launchLink)
        } catch {
            return WatchAppModel(
                service: nil, keys: keys, replica: replica, deviceName: name,
                startupError: "Apassy couldn't open its data on this watch. \(error.localizedDescription)")
        }
    }

    /// `Library/Application Support/Apassy` of the app, private and out of backups: the replica
    /// vault, the connection, and the access guards.
    private static func dataDirectory() throws -> URL {
        var directory = URL.applicationSupportDirectory.appending(path: "Apassy", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try directory.setResourceValues(values)
        return directory
    }
}
