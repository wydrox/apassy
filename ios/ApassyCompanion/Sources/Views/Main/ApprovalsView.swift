import ApassyCompanionKit
import SwiftUI

/// The approval of agent runs (ADR 0020): the pairing flow when this iPhone is not paired, else
/// the Inbox, the Activity, and the Mac.
struct ApprovalsView: View {
    let app: AppModel
    /// Opens Settings, from a toolbar button of the paired companion.
    var onSettings: (() -> Void)?

    var body: some View {
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
            CompanionView(session: session, onSettings: onSettings)
        }
    }
}

enum CompanionSection: String, CaseIterable, Identifiable {
    case inbox
    case activity
    case mac

    var id: String { rawValue }

    var label: String {
        switch self {
        case .inbox: "Inbox"
        case .activity: "Activity"
        case .mac: "Mac"
        }
    }
}

/// The paired companion: the Inbox, the Activity, and the Mac as a segmented control at the top of
/// one navigation stack.
struct CompanionView: View {
    let session: SessionModel
    var onSettings: (() -> Void)?
    @State private var section = CompanionSection.inbox

    var body: some View {
        NavigationStack {
            Group {
                switch section {
                case .inbox:
                    InboxView(session: session)
                        .connectionCapsule(session)
                case .activity:
                    ActivityView(session: session)
                        .connectionCapsule(session)
                case .mac:
                    MacView(session: session)
                }
            }
            .navigationTitle("Approvals")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if let onSettings {
                    ToolbarItem(placement: .topBarLeading) {
                        Button(action: onSettings) {
                            Label("Settings", systemImage: "gearshape")
                        }
                    }
                }
                ToolbarItem(placement: .principal) {
                    Picker("Section", selection: $section) {
                        ForEach(CompanionSection.allCases) { section in
                            Text(section == .inbox && session.waitingCount > 0
                                ? "Inbox (\(session.waitingCount))" : section.label)
                                .tag(section)
                        }
                    }
                    .pickerStyle(.segmented)
                    .frame(maxWidth: 320)
                }
            }
        }
        // One alert for the companion: the sections share the session.
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

extension View {
    /// Ask the Mac for the inbox every 2 s while the app is not in the background and the
    /// companion is paired. A short inactive moment (the Face ID prompt) does not end it.
    func companionPolling(_ app: AppModel) -> some View {
        modifier(CompanionPolling(app: app))
    }
}

private struct CompanionPolling: ViewModifier {
    let app: AppModel
    @Environment(\.scenePhase) private var scenePhase

    private var session: SessionModel? {
        if case .paired(let session) = app.phase { return session }
        return nil
    }

    private struct Key: Equatable {
        var polls: Bool
        var session: ObjectIdentifier?
    }

    func body(content: Content) -> some View {
        content
            .task(id: Key(polls: CoverPolicy.polls(in: AppPhase(scenePhase)), session: session.map(ObjectIdentifier.init))) {
                if CoverPolicy.polls(in: AppPhase(scenePhase)), let session { await session.poll() }
            }
    }
}

#if DEBUG
    #Preview {
        CompanionView(session: .preview())
    }
#endif
