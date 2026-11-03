import ApassyVaultKit
import SwiftUI

/// The one navigation stack of the watch: setup until the watch is connected, then Requests, with
/// Request and Exact identities above it (flow spec, section 2).
struct WatchRootView: View {
    @Bindable var model: WatchAppModel
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        NavigationStack(path: $model.path) {
            screen
                .navigationDestination(for: WatchRoute.self) { route in
                    switch route {
                    case .request(let id): RequestDetailView(model: model, id: id)
                    case .identities(let id): ExactIdentitiesView(requests: model.requests, id: id)
                    }
                }
        }
        // The replica opens when the app becomes active and suspends in the background; in the
        // background a signature is cancelled and the requests are dropped.
        .task(id: scenePhase) { await model.scenePhaseChanged(WatchScenePhase(scenePhase)) }
    }

    @ViewBuilder
    private var screen: some View {
        switch model.screen {
        case .starting:
            ProgressView()
        case .unavailable(let message):
            ContentUnavailableView {
                Label("Apassy can't open", systemImage: "exclamationmark.triangle")
            } description: {
                Text(verbatim: message)
            }
        case .connect(let problem):
            ConnectView(problem: problem, removed: false)
        case .removed:
            ConnectView(problem: nil, removed: true)
        case .connecting:
            ConnectingView { model.cancelConnect() }
        case .words(let words):
            CheckWordsView(words: words) { model.cancelConnect() }
        case .connected(let vault, let macs):
            ConnectedView(vault: vault, macs: macs) { model.finishConnecting() }
        case .requests:
            RequestsView(model: model)
        }
    }
}

#Preview("Requests") {
    WatchRootView(model: WatchPreview.model(.requests))
}

#Preview("Not connected") {
    WatchRootView(model: WatchPreview.model(.unpaired))
}
