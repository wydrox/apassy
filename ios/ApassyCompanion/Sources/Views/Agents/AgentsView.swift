import SwiftUI

/// The Agents tab (ADR 0026 §8). The agents, their use, and their exceptions live in the vault of
/// the Mac and do not sync, and the Mac does not send them yet (stage5-plan.md, "The Mac feed").
/// So the tab shows no list and no invented data: it says where the agents are, by the state of
/// this iPhone (`AgentsReach`), with the one action that helps now.
struct AgentsView: View {
    let questions: QuestionsModel?
    let companion: AppModel
    @Environment(RootModel.self) private var root: RootModel?
    @Environment(VaultUI.self) private var ui: VaultUI?
    @State private var showsConnect = false

    private var reach: AgentsReach {
        var wifiMac: String?
        if case .paired(let session) = companion.phase { wifiMac = session.macName }
        return AgentsReach(
            questions: questions?.phase, removed: questions?.status.removed ?? false, wifiMac: wifiMac)
    }

    var body: some View {
        NavigationStack {
            let reach = reach
            ContentUnavailableView {
                Label(reach.title, systemImage: "laptopcomputer")
            } description: {
                Text(reach.message)
            } actions: {
                switch reach.action {
                case .connect:
                    Button("Connect this iPhone") { showsConnect = true }
                        .buttonStyle(.borderedProminent)
                case .openDecisions:
                    Button("Open Decisions") { ui?.tab = .decisions }
                        .buttonStyle(.bordered)
                case nil:
                    EmptyView()
                }
            }
            .navigationTitle("Agents")
        }
        // The same sheet as "Connect this iPhone" in Decisions.
        .sheet(
            isPresented: $showsConnect,
            onDismiss: {
                let opensCompanion = questions?.attach == .companion
                questions?.dismissAttach()
                if opensCompanion { root?.openPreparedCompanion() }
            }
        ) {
            if let questions { ConnectQuestionsView(model: questions) }
        }
    }
}

#if DEBUG
    #Preview {
        AgentsView(questions: nil, companion: AppModel())
    }
#endif
