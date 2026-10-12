import SwiftUI

/// The Agents tab (ADR 0026 §8). The agents, their use, and their exceptions live in the vault of
/// the Mac and do not sync, so until the Mac sends them (stage5-plan.md, "The Mac feed") the tab
/// says where they are and shows nothing else: no invented data.
struct AgentsView: View {
    var body: some View {
        NavigationStack {
            ContentUnavailableView {
                Label("Available when the Mac is connected", systemImage: "cpu")
            } description: {
                Text("Your Mac keeps the list of agents and their exceptions. They will show here when the Mac sends them.")
            }
            .navigationTitle("Agents")
        }
    }
}

#if DEBUG
    #Preview {
        AgentsView()
    }
#endif
