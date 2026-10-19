import SwiftUI

/// Shared hierarchy for live requests and saved metadata; unavailable context is never inferred.
struct RequestsRowSummary<Metadata: View>: View {
    let title: String
    let requester: String?
    let project: String?
    let vault: String?
    let device: String
    @ViewBuilder let metadata: () -> Metadata

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.headline)
                .fixedSize(horizontal: false, vertical: true)
            if let requester {
                Text("\(requester) · \(project ?? "Project not reported")")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Text(vault.map { "Vault: \($0) · \(device)" } ?? device)
                .font(.subheadline)
                .foregroundStyle(.secondary)
            metadata()
        }
        .padding(.vertical, 4)
        .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
        .accessibilityElement(children: .combine)
    }
}
