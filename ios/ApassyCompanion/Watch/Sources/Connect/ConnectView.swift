import ApassyVaultKit
import SwiftUI

/// S1: the watch is not connected. Setup starts on the iPhone, which scans the code of the Mac;
/// the watch has no camera. No spinner: the status is a label.
struct ConnectView: View {
    /// Why the last attempt failed.
    let problem: WatchConnectProblem?
    /// A Mac removed this watch.
    let removed: Bool
    /// "See a Sample": a synthetic request answered in memory (`WatchSampleView`).
    var onSample: (() -> Void)? = nil

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                if removed {
                    Text("This watch was removed")
                        .font(.headline)
                        .accessibilityAddTraits(.isHeader)
                    Text("A Mac removed this watch. To answer again, connect it again.")
                } else {
                    Text("Connect to your Mac")
                        .font(.headline)
                        .accessibilityAddTraits(.isHeader)
                }
                if let problem {
                    Label {
                        Text(verbatim: problem.text)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle")
                    }
                    .font(.footnote)
                }
                Text("On your iPhone, open Apassy › Settings › Devices › Add Apple Watch.")
                Label("Waiting for your iPhone", systemImage: "iphone")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Text("This watch answers access requests only. Your passwords stay on your Mac and iPhone.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                if let onSample {
                    Button("See a Sample", systemImage: "theatermasks", action: onSample)
                        .accessibilityHint("Shows a sample access request. Nothing is sent.")
                }
            }
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            // The margins of watchOS: the text keeps clear of the rounded edges of the screen.
            .scenePadding(.horizontal)
        }
        .navigationTitle("Apassy")
    }
}

#Preview("Connect") {
    NavigationStack { ConnectView(problem: nil, removed: false) }
}

#Preview("Words differ") {
    NavigationStack { ConnectView(problem: .wordsDiffer, removed: false) }
}

#Preview("Removed") {
    NavigationStack { ConnectView(problem: nil, removed: true) }
}
