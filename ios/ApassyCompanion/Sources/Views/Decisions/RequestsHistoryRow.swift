import ApassyVaultKit
import SwiftUI

struct RequestsHistoryRow: View {
    let entry: RequestHistoryEntry
    let vaultName: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            RequestsRowLink(route: .history(entry.id)) {
                RequestsRowSummary(
                    title: entry.title,
                    requester: AgentName.display(entry.agent),
                    project: entry.project,
                    vault: vaultName ?? "Not available",
                    device: entry.deviceName
                ) {
                    Text(entry.action.capitalized)
                        .font(.subheadline.weight(.medium))
                    Label(RequestHistoryPresentation.status(entry), systemImage: RequestHistoryPresentation.symbol(entry))
                        .font(.subheadline)
                    Text(Date(timeIntervalSince1970: TimeInterval(entry.firstSeenAt)), style: .time)
                        .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 4)
    }
}
