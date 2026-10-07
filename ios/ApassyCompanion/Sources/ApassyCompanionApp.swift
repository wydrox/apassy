// Apassy on the iPhone (ADR 0020, ADR 0023).
//
// The app holds the owner's vault (it syncs with the Mac through the relay), and approves the runs
// that wait on the Mac. A secret leaves the vault only for the owner, after Face ID or the
// passphrase, each time. The app writes no secret and no command to disk or to a log, drops
// revealed values when it leaves the screen, and covers its content whenever it is not active
// (except behind its own system prompts), so the app switcher shows nothing of it.

import SwiftUI

@main
struct ApassyCompanionApp: App {
    @State private var root = RootModel()

    var body: some Scene {
        WindowGroup {
            RootView(root: root)
        }
    }
}

/// The welcome, the join flow, the companion alone, or the vault: its lock screen or its tabs.
struct RootView: View {
    let root: RootModel
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        Group {
            switch root.screen {
            case .starting:
                ProgressView()
                    .task { await root.start() }
            case .failed(let message):
                ContentUnavailableView {
                    Label("Apassy cannot open the vault", systemImage: "exclamationmark.triangle")
                } description: {
                    Text(message)
                } actions: {
                    Button("Try again") { Task { await root.start() } }
                        .buttonStyle(.borderedProminent)
                    Button("Only approve agent runs") { root.approveOnly() }
                        .buttonStyle(.bordered)
                }
            case .welcome:
                AppWelcomeView()
            case .join(let model):
                JoinFlowView(model: model)
            case .companion:
                CompanionOnlyView()
            case .vault:
                if let vault = root.vault {
                    Group {
                        if vault.isUnlocked {
                            VaultTabView()
                        } else {
                            LockView()
                        }
                    }
                    .environment(vault)
                }
            }
        }
        .environment(root)
        .onChange(of: scenePhase, initial: true) { _, phase in
            PrivacyCover.shared.setPhase(AppPhase(phase))
            root.scenePhaseChanged(AppPhase(phase))
        }
        // The passphrase prompt of the owner check shows in a window of its own, above sheets.
        .onChange(of: root.vault?.gate.prompt?.id, initial: true) {
            OwnerPromptWindow.shared.update(root.vault?.gate)
        }
    }
}

/// No vault on this iPhone: the approval of runs, with Settings to add a vault later.
struct CompanionOnlyView: View {
    @Environment(RootModel.self) private var root
    @State private var showsSettings = false

    var body: some View {
        ApprovalsView(app: root.companion, onSettings: { showsSettings = true })
            .safeAreaInset(edge: .top, spacing: 0) {
                // Before pairing, the owner can still go back and add a vault instead.
                if !root.companionIsPaired {
                    HStack {
                        Button("Back", systemImage: "chevron.backward") { root.route() }
                        Spacer()
                        Button("Add your vault") { root.addVault() }
                    }
                    .buttonStyle(.glass)
                    .padding(.horizontal, 16)
                    .padding(.top, 4)
                }
            }
            .companionPolling(root.companion)
            .sheet(isPresented: $showsSettings) {
                SettingsView()
                    .environment(root)
            }
    }
}
