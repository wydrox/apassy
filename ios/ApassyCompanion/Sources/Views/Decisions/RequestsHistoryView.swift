import ApassyVaultKit
import SwiftUI

struct RequestsHistoryView: View {
    let model: QuestionsModel
    @Binding var query: String
    @Binding var filter: RequestHistoryPresentation.Filter
    @State private var clearVaultID: String?
    @State private var showsClearConfirmation = false
    @State private var showsSearch = false

    private var clearableVaults: [RequestHistoryVault] {
        guard !model.historyLoading, model.historyError == nil else { return [] }
        let now = Int64(Date().timeIntervalSince1970)
        return model.historyVaults.filter { vault in
            vault.availability == .available && !vault.entries.isEmpty
                && !vault.entries.contains { entry in
                    entry.attemptedAt != nil && entry.outcome == nil && entry.expiresAt > now
                }
        }
    }

    private var clearVaultName: String {
        model.historyVaults.first { $0.vaultID == clearVaultID }?.vaultName ?? "this vault’s"
    }

    var body: some View {
        RequestsHistoryList(model: model, query: query, filter: filter)
        .task { await model.refreshHistory() }
        .onChange(of: model.historyVaults.filter { $0.availability == .available }.map(\.vaultID)) { old, current in
            if !Set(old).isSubset(of: Set(current)) { query = "" }
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu("History options", systemImage: query.isEmpty && filter == .all ? "ellipsis" : "line.3.horizontal.decrease") {
                    Button("Search History", systemImage: "magnifyingglass") { showsSearch = true }
                    if !query.isEmpty {
                        Button("Clear Search", systemImage: "xmark.circle") { query = "" }
                    }
                    Picker("History filter", selection: $filter) {
                        ForEach(RequestHistoryPresentation.Filter.allCases) { Text($0.rawValue).tag($0) }
                    }
                    if !clearableVaults.isEmpty {
                        Section {
                            ForEach(clearableVaults, id: \.vaultID) { vault in
                                Button("Clear \(vault.vaultName) History", role: .destructive) {
                                    clearVaultID = vault.vaultID
                                    showsClearConfirmation = true
                                }
                            }
                        }
                    }
                }
                .accessibilityValue(filter == .all ? (query.isEmpty ? "All requests" : "Search active") : "\(filter.rawValue) requests")
            }
        }
        .sheet(isPresented: $showsSearch) {
            RequestsHistorySearchSheet(model: model, query: $query, filter: $filter)
        }
        .confirmationDialog("Clear \(clearVaultName) history on this iPhone?", isPresented: $showsClearConfirmation, titleVisibility: .visible) {
            Button("Clear History", role: .destructive, action: clearHistory)
            Button("Cancel", role: .cancel) { clearVaultID = nil }
        } message: {
            Text("This deletes saved request metadata from this iPhone. It does not change any permissions or Mac records.")
        }
    }

    private func clearHistory() {
        guard let clearVaultID,
            clearableVaults.contains(where: { $0.vaultID == clearVaultID }) else {
            self.clearVaultID = nil
            return
        }
        Task { await model.clearLocalHistory(vaultID: clearVaultID) }
        self.clearVaultID = nil
    }
}
