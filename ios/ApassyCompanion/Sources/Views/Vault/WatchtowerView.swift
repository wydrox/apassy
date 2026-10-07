import ApassyVaultKit
import SwiftUI

/// Weak, reused, and old passwords, and conflict copies. The core checks the passwords in memory
/// and answers item IDs only.
struct WatchtowerView: View {
    @Environment(VaultModel.self) private var vault

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("Watchtower")
                .vaultDestinations()
                .refreshable { await vault.refreshWatchtower() }
                .task { await vault.refreshWatchtower() }
        }
    }

    @ViewBuilder
    private var content: some View {
        if let report = vault.watchtower {
            if report.issueCount == 0 {
                ContentUnavailableView {
                    Label("All clear", systemImage: "checkmark.shield.fill")
                } description: {
                    Text(
                        "No weak, reused, or old passwords, and no conflict copies. \(checked(report))."
                    )
                }
            } else {
                list(report)
            }
        } else {
            ProgressView()
        }
    }

    private func checked(_ report: WatchtowerReport) -> String {
        report.checked == 1 ? "1 password checked" : "\(report.checked) passwords checked"
    }

    private func list(_ report: WatchtowerReport) -> some View {
        List {
            Section {
                HStack(spacing: 14) {
                    Image(systemName: "exclamationmark.shield.fill")
                        .font(.largeTitle)
                        .foregroundStyle(.orange)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(report.issueCount == 1 ? "1 item needs a look" : "\(report.issueCount) items need a look")
                            .font(.headline)
                        Text(checked(report))
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }
                .accessibilityElement(children: .combine)
            }
            rows("Weak passwords", report.weak, footer: "Short or easy to guess. Change them on the website, then here.")
            ForEach(Array(report.reused.enumerated()), id: \.offset) { index, group in
                rows(
                    index == 0 ? "Reused passwords" : nil, group,
                    footer: "These \(group.count) items use the same password. Give each its own.")
            }
            rows("Old passwords", report.old, footer: "Not changed for more than a year.")
            rows(
                "Conflict copies", report.conflicts,
                footer: "A sync kept both versions of an item. Keep the one you need and archive the other.")
        }
    }

    @ViewBuilder
    private func rows(_ title: String?, _ ids: [UInt64], footer: String) -> some View {
        let items = ids.compactMap { vault.item($0) }
        if !items.isEmpty {
            Section {
                ForEach(items) { item in
                    ItemListRow(item: item)
                }
            } header: {
                if let title { Text(title) }
            } footer: {
                Text(footer)
            }
        }
    }
}
