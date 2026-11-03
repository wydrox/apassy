import ApassyVaultKit
import SwiftUI

/// A2: one access request. The facts come first, the answers after them, so the owner scrolls past
/// every scope fact (Digital Crown) before answering. The result takes the place of the buttons.
struct RequestDetailView: View {
    let model: WatchAppModel
    let id: String

    private var requests: WatchRequestsModel { model.requests }

    var body: some View {
        Group {
            if let request = requests.request(id) {
                // Changes by itself only at the expiry and at the end of the wait for the Mac.
                TimelineView(.explicit(requests.deadlines(for: id))) { context in
                    detail(request, phase: requests.phase(for: id, at: context.date))
                }
            } else {
                ContentUnavailableView {
                    Label(WatchRequestText.unavailable, systemImage: "clock")
                }
            }
        }
        .navigationTitle("Request")
        // A confirmed answer from this watch, Allowed or Denied alike; none for an outcome first
        // seen in the list.
        .sensoryFeedback(.success, trigger: requests.isConfirmedHere(id)) { old, new in !old && new }
    }

    private func detail(_ request: RelayAccessRequest, phase: WatchRequestPhase) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                RequestFactsView(request: request)
                AnswerControlsView(
                    request: request, phase: phase,
                    onAnswer: { choice in requests.answer(id, choice: choice) },
                    onDone: { model.path.removeAll() })
                NavigationLink(value: WatchRoute.identities(id)) {
                    Text("Exact identities")
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

#Preview("Request") {
    WatchRootView(model: WatchPreview.model(.detail))
}

#Preview("Deny only") {
    WatchRootView(model: WatchPreview.model(.denyonly))
}

#Preview("Allowed") {
    WatchRootView(model: WatchPreview.model(.allowed))
}
