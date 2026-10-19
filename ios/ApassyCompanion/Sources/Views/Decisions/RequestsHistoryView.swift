import ApassyVaultKit
import SwiftUI

struct RequestsHistoryView: View {
    let model: QuestionsModel
    @Binding var query: String
    @Binding var filter: RequestHistoryPresentation.Filter
    @State private var clearVaultID: String?
    @State private var showsClearConfirmation = false

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

    private var clearableVaults: [RequestHistoryVault] {
        model.historyVaults.filter {
            $0.availability == .unavailable || ($0.availability == .available && !$0.entries.isEmpty)
        }
    }

    private var clearVaultName: String {
        model.historyVaults.first { $0.vaultID == clearVaultID }?.vaultName ?? "this vault’s"
    }

    private var grouped: [Date: [RequestHistoryEntry]] {
        Dictionary(grouping: entries) { Calendar.current.startOfDay(for: Date(timeIntervalSince1970: TimeInterval($0.firstSeenAt))) }
    }

    var body: some View {
        List {
            Section {
                Picker("History filter", selection: $filter) {
                    ForEach(RequestHistoryPresentation.Filter.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .listRowSeparator(.hidden)
            } header: {
                Text("Vault requests · Seen on this iPhone").textCase(nil)
            }
            if model.historyLoading && model.history.isEmpty {
                ProgressView("Loading history…").frame(maxWidth: .infinity)
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
                    Text(error).font(.subheadline).foregroundStyle(.secondary)
                    Button("Retry", action: refresh).frame(minHeight: 44)
                }
            }
            ForEach(model.historyVaults.filter { $0.availability != .available }, id: \.vaultID) { vault in
                Section {
                    Label("\(vault.vaultName) \(vault.availability == .locked ? "is locked" : "is unavailable")", systemImage: "lock")
                    if let error = vault.error { Text(error).font(.footnote).foregroundStyle(.secondary) }
                }
            }
            ForEach(grouped.keys.sorted(by: >), id: \.self) { day in
                Section(RequestHistoryPresentation.dayTitle(day)) {
                    ForEach(grouped[day] ?? [], id: \.id) { entry in
                        NavigationLink(value: DecisionRoute.history(entry.id)) {
                            VStack(alignment: .leading, spacing: 6) {
                                Text(entry.title).font(.headline)
                                Text([AgentName.display(entry.agent), entry.project].compactMap { $0 }.joined(separator: " · "))
                                    .font(.subheadline).foregroundStyle(.secondary)
                                Label(RequestHistoryPresentation.status(entry), systemImage: RequestHistoryPresentation.symbol(entry))
                                    .font(.subheadline)
                                Text(Date(timeIntervalSince1970: TimeInterval(entry.firstSeenAt)), style: .time)
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            .padding(.vertical, 4)
                            .accessibilityElement(children: .combine)
                        }
                    }
                }
            }
            Section {
            } footer: {
                Text("Last 30 days · Up to 1,000 requests per vault. Wi-Fi requests are not saved here.")
            }
        }
        .searchable(text: $query, prompt: "Search history")
        .refreshable { await model.refreshHistory() }
        .task { await model.refreshHistory() }
        .onChange(of: model.historyVaults.filter { $0.availability == .available }.map(\.vaultID)) { old, current in
            if !Set(old).isSubset(of: Set(current)) { query = "" }
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu("History options", systemImage: "ellipsis.circle") {
                    ForEach(clearableVaults, id: \.vaultID) { vault in
                        Button("Clear \(vault.vaultName) History", role: .destructive) {
                            clearVaultID = vault.vaultID
                            showsClearConfirmation = true
                        }
                    }
                }
                .disabled(clearableVaults.isEmpty)
            }
        }
        .confirmationDialog("Clear \(clearVaultName) history on this iPhone?", isPresented: $showsClearConfirmation, titleVisibility: .visible) {
            Button("Clear History", role: .destructive, action: clearHistory)
            Button("Cancel", role: .cancel) { clearVaultID = nil }
        } message: {
            Text("This deletes saved request metadata from this iPhone. It does not change any permissions or Mac records.")
        }
    }

    private func refresh() { Task { await model.refreshHistory() } }
    private func clearHistory() {
        guard let clearVaultID else { return }
        Task { await model.clearLocalHistory(vaultID: clearVaultID) }
        self.clearVaultID = nil
    }
}
