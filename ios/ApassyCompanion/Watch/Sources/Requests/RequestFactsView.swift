import ApassyVaultKit
import SwiftUI

/// The scope facts of a request, in the order of the flow spec (A2, items 1 to 8). Every host and
/// the full folder wrap; nothing is truncated. Redacted in Always On.
struct RequestFactsView: View {
    let request: RelayAccessRequest

    var body: some View {
        let card = request.card
        VStack(alignment: .leading, spacing: 8) {
            Text(verbatim: WatchRequestText.title(card))
                .font(.headline)
                .accessibilityAddTraits(.isHeader)
            Text(verbatim: WatchRequestText.askedOn(card))
                .font(.footnote)
                .foregroundStyle(.secondary)
            Divider()
            Text(verbatim: WatchRequestText.environment(card))
                .font(.body.weight(.semibold))
            Text(verbatim: WatchRequestText.delivery(card))
                .font(.footnote)
            FactView(name: "Action", value: card.action.map(WatchRequestText.escaped) ?? WatchRequestText.notSpecified)
            FactView(name: "Hosts") {
                if card.hosts.isEmpty {
                    Text(WatchRequestText.notSpecified)
                } else {
                    ForEach(card.hosts, id: \.self) { host in
                        Text(verbatim: WatchRequestText.escaped(host))
                            .font(.body.monospaced())
                    }
                }
            }
            FactView(name: "Project") {
                Text(verbatim: card.project.map { WatchRequestText.escaped($0.label) } ?? WatchRequestText.notSpecified)
                if !card.cwd.isEmpty {
                    Text(verbatim: WatchRequestText.escaped(card.cwd))
                        .font(.footnote.monospaced())
                }
            }
            FactView(name: "The agent says", value: WatchRequestText.escaped(card.reason))
            Text(verbatim: "Agent id \(WatchRequestText.escaped(card.agent.id))")
                .font(.footnote)
            Text(verbatim: WatchRequestText.hostProvenance(card))
                .font(.footnote)
            Text(verbatim: WatchRequestText.until(card))
                .font(.footnote)
            Text(WatchRequestText.scopeSource)
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .fixedSize(horizontal: false, vertical: true)
        .privacySensitive()
    }
}
