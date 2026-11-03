import ApassyVaultKit
import SwiftUI

/// A2: one access request. The facts come first, the answers after them, so the owner scrolls past
/// every scope fact (Digital Crown) before answering. The result takes the place of the buttons.
struct RequestDetailView: View {
    let model: WatchAppModel
    let id: String
    @Environment(\.watchSampleNote) private var sampleNote

    private var requests: WatchRequestsModel { model.requests }

    var body: some View {
        Group {
            if let request = requests.request(id) {
                // Redraws by itself only at the expiry and at the end of the wait for the Mac. The
                // timeline only triggers the redraw: its first date is the future expiry, so the
                // phase always uses the real time.
                TimelineView(.explicit(requests.deadlines(for: id))) { _ in
                    detail(request, phase: requests.currentPhase(for: id))
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
                if let sampleNote {
                    Text(sampleNote)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                NavigationLink(value: WatchRoute.identities(id)) {
                    Text("Exact identities")
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            // The margins of watchOS: the text keeps clear of the rounded edges of the screen.
            .scenePadding(.horizontal)
        }
        .defaultScrollAnchor(WatchLaunch.scrollAnchor)
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
