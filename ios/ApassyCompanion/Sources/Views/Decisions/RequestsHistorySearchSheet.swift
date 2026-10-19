import SwiftUI

/// Search has its own native navigation chrome, so the Requests picker never shifts.
struct RequestsHistorySearchSheet: View {
    @Environment(\.dismiss) private var dismiss
    let model: QuestionsModel
    @Binding var query: String
    @Binding var filter: RequestHistoryPresentation.Filter

    var body: some View {
        NavigationStack {
            RequestsHistoryList(model: model, query: query, filter: filter)
                .accessibilityIdentifier("requests.history.searchResults")
                .navigationTitle("Search History")
                .navigationBarTitleDisplayMode(.inline)
                .searchable(text: $query, prompt: "Search history")
                .searchPresentationToolbarBehavior(.avoidHidingContent)
                .toolbar {
                    ToolbarItem(placement: .topBarLeading) {
                        Menu("Filter history", systemImage: filter == .all ? "line.3.horizontal.decrease" : "line.3.horizontal.decrease.circle.fill") {
                            Picker("History filter", selection: $filter) {
                                ForEach(RequestHistoryPresentation.Filter.allCases) { Text($0.rawValue).tag($0) }
                            }
                        }
                    }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Done", action: dismiss.callAsFunction)
                    }
                }
                .navigationDestination(for: DecisionRoute.self) { route in
                    if case .history(let id) = route {
                        RequestHistoryDetailView(model: model, entryID: id)
                    }
                }
        }
        .presentationDragIndicator(.visible)
    }
}
