import ApassyVaultKit
import SwiftUI

/// S5: the setup ends on what the watch can and cannot do. No confetti: this is a security product.
struct ConnectedView: View {
    /// The escaped name of the vault.
    let vault: String
    /// The escaped names of the Macs.
    let macs: [String]
    /// Why Allow once is off on this watch (an older Mac wrote no answer key), or nil.
    let allowOff: String?
    let onDone: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                Label {
                    Text("Connected")
                        .font(.headline)
                } icon: {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                }
                .accessibilityAddTraits(.isHeader)
                Text(verbatim: scope)
                if let allowOff {
                    Label {
                        Text(verbatim: allowOff)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle")
                    }
                    .font(.footnote)
                } else {
                    Text("Allow once works while this watch is unlocked on your wrist. Run approvals stay on your iPhone and Mac.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Button(action: onDone) {
                    Text("Done")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
            }
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            // The margins of watchOS: the text keeps clear of the rounded edges of the screen.
            .scenePadding(.horizontal)
        }
        .defaultScrollAnchor(WatchLaunch.scrollAnchor)
    }

    private var scope: String {
        let on = macs.isEmpty ? "" : " on \(WatchRequestText.list(macs, conjunction: "and"))"
        return "This watch answers access requests for “\(vault)”\(on)."
    }
}

#Preview {
    ConnectedView(vault: WatchPreview.vault.name, macs: [WatchPreview.mac], allowOff: nil) {}
}

#Preview("Mac update needed") {
    ConnectedView(
        vault: WatchPreview.vault.name, macs: [WatchPreview.mac],
        allowOff: "Update Apassy on your Mac to connect this watch.") {}
}
