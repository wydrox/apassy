import ApassyVaultKit
import SwiftUI

/// A3: the exact identities of a request, read-only, monospaced, and wrapping.
struct ExactIdentitiesView: View {
    let requests: WatchRequestsModel
    let id: String

    var body: some View {
        Group {
            if let request = requests.request(id) {
                let card = request.card
                List {
                    identity("Agent id", card.agent.id)
                    identity("Mac id", card.asker.device)
                    identity("Vault id", card.vault_id)
                    identity("Credential id", "\(card.item.local_id) / \(card.item.uuid)")
                    identity("Revision", card.item.revision)
                    identity("Request id", card.request_id)
                }
                .privacySensitive()
            } else {
                ContentUnavailableView {
                    Label(WatchRequestText.unavailable, systemImage: "clock")
                }
            }
        }
        .navigationTitle("Exact identities")
    }

    private func identity(_ name: String, _ value: String) -> some View {
        LabeledContent {
            Text(verbatim: WatchRequestText.escaped(value))
                .font(.footnote.monospaced())
                .fixedSize(horizontal: false, vertical: true)
        } label: {
            Text(name)
        }
    }
}
