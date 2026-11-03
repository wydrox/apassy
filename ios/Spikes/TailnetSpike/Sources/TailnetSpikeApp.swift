import SwiftUI

/// The iPhone tailnet spike (plan s8 unit T0, ADR 0040). Spike only: not a part of the Apassy
/// app. The owner's test is in docs/design/spike-tsnet-ios.md.
@main
struct TailnetSpikeApp: App {
    @StateObject private var model: SpikeModel

    init() {
        // stderr, the log pipe, and the no-logs mode of Go come before the first node.
        SpikeBoot.early()
        _model = StateObject(wrappedValue: SpikeModel())
    }

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
        }
    }
}
