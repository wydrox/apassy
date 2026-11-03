import ApassyVaultKit
import SwiftUI

/// One row of Requests: who asks for what, on which Mac, and until when. One VoiceOver element,
/// redacted in Always On.
struct RequestRow: View {
    let request: RelayAccessRequest
    let date: Date

    var body: some View {
        let card = request.card
        VStack(alignment: .leading, spacing: 2) {
            Text(verbatim: WatchRequestText.title(card))
                .font(.headline)
                .lineLimit(3)
            Text(verbatim: WatchRequestText.onMac(card))
                .font(.footnote)
                .foregroundStyle(.secondary)
            if WatchRequestText.isProduction(card) {
                Text("Production")
                    .font(.footnote.weight(.semibold))
            }
            Text(verbatim: WatchRequestText.rowStatus(request, at: date))
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .fixedSize(horizontal: false, vertical: true)
        .privacySensitive()
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: WatchRequestText.rowAccessibility(request, at: date)))
    }
}
