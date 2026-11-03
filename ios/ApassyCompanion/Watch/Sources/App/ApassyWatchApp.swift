// Apassy on the Apple Watch (ADR 0039).
//
// The watch answers access requests only: Allow once while it is unlocked on the wrist, or Deny.
// It holds no credential, never shows run questions, and has its own relay key and answer key. The
// iPhone scans the Connect code of the Mac and hands it to the watch; the owner confirms on the Mac.

import ApassyVaultKit
import SwiftUI
import WatchKit

@main
struct ApassyWatchApp: App {
    @WKApplicationDelegateAdaptor(WatchAppDelegate.self) private var delegate
    @State private var model: WatchAppModel
    @State private var notifications: WatchNotificationsModel
    @State private var receiver: WatchLinkReceiver
    @Environment(\.scenePhase) private var scenePhase

    init() {
        let (model, notifications) = WatchLaunch.makeModels()
        _model = State(initialValue: model)
        _notifications = State(initialValue: notifications)
        _receiver = State(initialValue: WatchLinkReceiver { link in await model.receiveLink(link) })
        let registrar = WatchPushRegistrar.shared
        registrar.onToken = { token in Task { await notifications.receiveToken(token) } }
        registrar.onFailure = { message in notifications.registrationFailed(message) }
    }

    var body: some Scene {
        WindowGroup {
            WatchRootView(model: model)
                .environment(notifications)
                .onAppear { receiver.activate() }
                .onChange(of: model.connectionReport, initial: true) { _, report in receiver.publish(report) }
        }
        .onChange(of: scenePhase, initial: true) { _, phase in
            // While the setting is on, each activation registers again: the replica is open now.
            if phase == .active { Task { await notifications.refresh() } }
        }
    }
}
