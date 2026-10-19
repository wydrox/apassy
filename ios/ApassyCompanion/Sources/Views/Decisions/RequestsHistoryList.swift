import ApassyVaultKit
import SwiftUI

/// The same read-only results are used in History and its contextual search sheet.
struct RequestsHistoryList: View {
    let model: QuestionsModel
    let query: String
    let filter: RequestHistoryPresentation.Filter

    private var entries: [RequestHistoryEntry] {
        model.history.filter { entry in
            let matchesFilter = filter == .all || (filter == .allowed && entry.outcome == "approved")
                || (filter == .denied && entry.outcome == "denied")
            let text = [entry.title, entry.agent, entry.project ?? "", entry.deviceName, entry.action,
                model.historyVaults.first { $0.vaultID == entry.vaultID }?.vaultName ?? ""]
                .joined(separator: " ")
            return matchesFilter && (query.isEmpty || text.localizedStandardContains(query))
        }
        .sorted { $0.firstSeenAt == $1.firstSeenAt ? $0.id < $1.id : $0.firstSeenAt > $1.firstSeenAt }
    }

    private var grouped: [Date: [RequestHistoryEntry]] {
        Dictionary(grouping: entries) {
            Calendar.current.startOfDay(for: Date(timeIntervalSince1970: TimeInterval($0.firstSeenAt)))
        }
    }

    var body: some View {
        RequestsList {
            if model.historyLoading && model.history.isEmpty {
                ProgressView("Loading history…")
                    .frame(maxWidth: .infinity)
                    .listRowBackground(Color.clear)
            } else if entries.isEmpty && model.historyError == nil
                && model.historyVaults.allSatisfy({ $0.availability == .available }) {
                ContentUnavailableView {
                    Label(query.isEmpty && filter == .all ? "No history yet" : "No matching requests", systemImage: "clock")
                } description: {
                    if !query.isEmpty { Text("Try another name.") }
                }
                .listRowBackground(Color.clear)
            }
            if let error = model.historyError {
                Section {
                    Label("Couldn’t refresh", systemImage: "exclamationmark.triangle")
                    Text(historyMessage(for: error)).font(.subheadline).foregroundStyle(.secondary)
                    Button("Retry", action: refresh).frame(minHeight: 44)
                }
            }
            ForEach(model.historyVaults.filter { $0.availability != .available }, id: \.vaultID) { vault in
                Section {
                    Label("\(vault.vaultName) \(vault.availability == .locked ? "is locked" : "is unavailable")",
                        systemImage: vault.availability == .locked ? "lock" : "exclamationmark.triangle")
                    if let error = vault.error {
                        Text(historyMessage(for: error)).font(.footnote).foregroundStyle(.secondary)
                    }
                }
            }
            ForEach(grouped.keys.sorted(by: >), id: \.self) { day in
                Section(RequestHistoryPresentation.dayTitle(day)) {
                    ForEach(grouped[day] ?? [], id: \.id) { entry in
                        RequestsHistoryRow(entry: entry,
                            vaultName: model.historyVaults.first { $0.vaultID == entry.vaultID }?.vaultName)
                    }
                }
            }
            Section {
            } footer: {
                Text("Vault requests seen on this iPhone · Last 30 days · Up to 1,000 per vault. Wi-Fi requests are not saved here.")
            }
        }
        .refreshable { await model.refreshHistory() }
    }

    private func refresh() { Task { await model.refreshHistory() } }

    private func historyMessage(for error: String) -> LocalizedStringResource {
        if error.contains("history_migration_blocked") {
            return "History needs its previous key. Encrypted history is preserved."
        }
        if error.contains("history_key_missing") {
            return "The history key is unavailable. Encrypted history is preserved."
        }
        if error.contains("history_storage_unavailable") {
            return "History storage is unavailable. Encrypted history is preserved."
        }
        return "History couldn’t be read. Encrypted history is preserved."
    }
}
