// Apassy on the Apple Watch (ADR 0039).
//
// The watch answers access requests only: Allow once while it is unlocked on the wrist, or Deny.
// It holds no credential, never shows run questions, and has its own relay key and answer key. The
// iPhone scans the Connect code of the Mac and hands it to the watch; the owner confirms on the Mac.

import ApassyVaultKit
import SwiftUI

@main
struct ApassyWatchApp: App {
    @State private var model: WatchAppModel
    @State private var receiver: WatchLinkReceiver

    init() {
        let model = WatchLaunch.makeModel()
        _model = State(initialValue: model)
        _receiver = State(initialValue: WatchLinkReceiver { link in await model.receiveLink(link) })
    }

    var body: some Scene {
        WindowGroup {
            WatchRootView(model: model)
                .onAppear { receiver.activate() }
        }
    }
}
