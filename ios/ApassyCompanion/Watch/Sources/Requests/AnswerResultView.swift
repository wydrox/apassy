import ApassyVaultKit
import SwiftUI

/// A4: the result that the Mac confirmed, in the past tense, with its deadline and what is still
/// checked, then Done. A subtle ending: a symbol and a haptic, nothing more.
struct AnswerResultView: View {
    let result: WatchResult
    /// The escaped name of the asking Mac.
    let mac: String
    let onDone: () -> Void

    var body: some View {
        let lines = result.lines(mac: mac)
        VStack(alignment: .leading, spacing: 8) {
            Label {
                Text(verbatim: result.headline)
                    .font(.headline)
            } icon: {
                Image(systemName: result.symbol)
            }
            .accessibilityAddTraits(.isHeader)
            ForEach(lines.indices, id: \.self) { index in
                Text(verbatim: lines[index])
                    .font(.footnote)
            }
            Button(action: onDone) {
                Text("Done")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
        }
        .fixedSize(horizontal: false, vertical: true)
    }
}
