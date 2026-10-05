import ApassyCompanionKit
import SwiftUI

enum AppTab: Hashable {
    case inbox
    case activity
    case mac
}

/// The three tabs. It asks the Mac for the inbox every 2 s while the app is active.
struct MainTabView: View {
    let session: SessionModel
    @State private var tab = AppTab.inbox
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        TabView(selection: $tab) {
            Tab("Inbox", systemImage: "tray.full", value: AppTab.inbox) {
                InboxView(session: session)
            }
            .badge(session.waitingCount)
            Tab("Activity", systemImage: "list.bullet.rectangle", value: AppTab.activity) {
                ActivityView(session: session)
            }
            Tab("Mac", systemImage: "desktopcomputer", value: AppTab.mac) {
                MacView(session: session)
            }
        }
        .tabBarMinimizeBehavior(.onScrollDown)
        // The task starts when the app leaves the background and is cancelled when it goes there,
        // so the polling stops in the background and refreshes at once on return. A short
        // inactive moment (the Face ID prompt, a permission dialog) does not end it.
        .task(id: CoverPolicy.polls(in: AppPhase(scenePhase))) {
            if CoverPolicy.polls(in: AppPhase(scenePhase)) { await session.poll() }
        }
        // One alert for the whole app: each tab is alive in the TabView, so an alert on each of
        // them would present at the same time.
        .alert(
            "Apassy could not finish",
            isPresented: Binding(
                get: { session.actionError != nil },
                set: { if !$0 { session.actionError = nil } })
        ) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(session.actionError ?? "")
        }
    }
}

#if DEBUG
    #Preview {
        MainTabView(session: .preview())
    }
#endif
