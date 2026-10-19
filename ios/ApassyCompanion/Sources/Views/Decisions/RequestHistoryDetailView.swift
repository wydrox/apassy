import ApassyVaultKit
import SwiftUI

/// Resolves the row from the authorized model on every update, so locking removes its metadata.
struct RequestHistoryDetailView: View {
    let model: QuestionsModel
    let entryID: String

    var body: some View {
        Group {
            if let entry = model.history.first(where: { $0.id == entryID }) {
                List {
                    Section {
                        Text(entry.title).font(.title2.bold())
                        Label(RequestHistoryPresentation.status(entry), systemImage: RequestHistoryPresentation.symbol(entry))
                        LabeledContent("Execution", value: "Not reported")
                    }
                    Section("Request") {
                        LabeledContent("Requester", value: AgentName.display(entry.agent))
                        LabeledContent("Project", value: entry.project ?? "Not reported")
                        LabeledContent("Vault", value: model.historyVaults.first { $0.vaultID == entry.vaultID }?.vaultName ?? "Not available")
                        LabeledContent("Device", value: entry.deviceName)
                        LabeledContent("Action", value: entry.action.capitalized)
                        LabeledContent("Environment", value: entry.production ? "Production or unconfirmed" : "Development")
                    }
                    Section("Answer and confirmation") {
                        if let selectedKind = entry.selectedKind {
                            LabeledContent("Selected scope", value: RequestHistoryPresentation.scope(selectedKind))
                        }
                        if let confirmedKind = entry.confirmedKind {
                            LabeledContent("Confirmed scope", value: RequestHistoryPresentation.scope(confirmedKind))
                        }
                        LabeledContent("Confirmation", value: entry.confirmedAt == nil ? "Not reported" : "Confirmed by \(entry.confirmedBy ?? entry.deviceName)")
                        if let confirmed = entry.confirmedAt {
                            LabeledContent("Confirmed at", value: Date(timeIntervalSince1970: TimeInterval(confirmed)).formatted(date: .abbreviated, time: .shortened))
                        }
                        if let sent = entry.sentAt {
                            LabeledContent("Answer sent", value: Date(timeIntervalSince1970: TimeInterval(sent)).formatted(date: .abbreviated, time: .shortened))
                        } else if let attempted = entry.attemptedAt {
                            LabeledContent("Answer attempted", value: Date(timeIntervalSince1970: TimeInterval(attempted)).formatted(date: .abbreviated, time: .shortened))
                        }
                    }
                    Section {
                        LabeledContent("First seen", value: Date(timeIntervalSince1970: TimeInterval(entry.firstSeenAt)).formatted(date: .abbreviated, time: .shortened))
                        LabeledContent("Last seen", value: Date(timeIntervalSince1970: TimeInterval(entry.lastSeenAt)).formatted(date: .abbreviated, time: .shortened))
                    } footer: {
                        Text("Commands and request text are not saved. An authorization result does not report whether a command ran.")
                    }
                }
            } else {
                ContentUnavailableView("History unavailable", systemImage: "lock", description: Text("The vault may be locked or this local record was removed."))
            }
        }
        .navigationTitle("Request history")
        .navigationBarTitleDisplayMode(.inline)
    }
}
