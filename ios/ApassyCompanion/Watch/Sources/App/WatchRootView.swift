import ApassyVaultKit
import SwiftUI

/// The one navigation stack of the watch: setup until the watch is connected, then Requests, with
/// Request and Exact identities above it (flow spec, section 2).
struct WatchRootView: View {
    @Bindable var model: WatchAppModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var showsSample = false

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
        // The replica opens when the app becomes active and suspends in the background. The
        // background cancels a signature and drops the requests at once, in the change itself.
        .onChange(of: scenePhase, initial: true) { _, phase in
            model.setScenePhase(WatchScenePhase(phase))
        }
        .sheet(isPresented: $showsSample) { WatchSampleView() }
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
            ConnectView(problem: problem, removed: false, onSample: { showsSample = true })
        case .removed:
            ConnectView(problem: nil, removed: true, onSample: { showsSample = true })
        case .connecting:
            ConnectingView { model.cancelConnect() }
        case .words(let words):
            CheckWordsView(words: words) { model.cancelConnect() }
        case .connected(let vault, let macs):
            ConnectedView(vault: vault, macs: macs, allowOff: model.requests.allowOffReason) {
                model.finishConnecting()
            }
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
