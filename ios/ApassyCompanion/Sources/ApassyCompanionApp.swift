// The iPhone companion of Apassy (ADR 0014).
//
// The app shows the runs that wait on the Mac and sends the owner's decision. It never holds a
// secret. It keeps the inbox and the activity in memory only, and it covers its content whenever it
// is not active (except behind its own system prompts), so the app switcher never shows a command.

import SwiftUI

@main
struct ApassyCompanionApp: App {
    @State private var app = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView(app: app)
        }
    }
}

/// Pairing when no pairing is stored, else the main tabs.
struct RootView: View {
    let app: AppModel
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        Group {
            switch app.phase {
            case .starting:
                ProgressView()
                    .task { app.start() }
            case .loadFailed(let message):
                ContentUnavailableView {
                    Label("Apassy cannot read its pairing", systemImage: "exclamationmark.triangle")
                } description: {
                    Text(message)
                } actions: {
                    Button("Try again") { app.start() }
                        .buttonStyle(.borderedProminent)
                }
            case .pairing(let model):
                PairingFlowView(model: model)
            case .paired(let session):
                MainTabView(session: session)
            }
        }
        .onChange(of: scenePhase, initial: true) { _, phase in
            PrivacyCover.shared.setPhase(AppPhase(phase))
        }
    }
}
