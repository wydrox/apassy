import ApassyVaultDemo
import ApassyVaultKit
import SwiftUI

/// "See a Sample" on a watch with no vault: one synthetic access request of "Mac mini (demo)" with
/// Allow once and Deny, answered in memory (`DemoWatch`). Closing the sheet drops it.
struct WatchSampleView: View {
    @State private var model = DemoWatch.model()

    var body: some View {
        WatchRootView(model: model)
            .environment(\.watchSampleNote, DemoWatch.wristNote)
    }
}

extension EnvironmentValues {
    /// The note of the sample under the answers of a request; nil outside the sample.
    @Entry var watchSampleNote: String? = nil
}
