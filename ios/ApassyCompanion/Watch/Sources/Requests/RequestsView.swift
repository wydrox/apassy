import ApassyVaultKit
import SwiftUI

/// A1: the access requests that wait, newest first. The gear opens This watch.
struct RequestsView: View {
    @Bindable var model: WatchAppModel
    /// The first list took more than about 2 s: show the empty or error state, not a spinner.
    @State private var checkedLong = false

    private var requests: WatchRequestsModel { model.requests }

    var body: some View {
        // A coarse timeline: "Until" becomes "Expired" within a minute; there is no countdown.
        TimelineView(.everyMinute) { context in
            content(at: context.date)
        }
        .navigationTitle("Requests")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("This watch", systemImage: "gearshape") { model.showsSettings = true }
                    .labelStyle(.iconOnly)
            }
        }
        .sheet(isPresented: $model.showsSettings) {
            ThisWatchView(model: model)
        }
        .task(id: model.isLive) {
            guard model.isLive else { return }
            await model.liveUpdates()
        }
        // Restarts when the list is dropped in the background and read again.
        .task(id: requests.loaded) {
            checkedLong = false
            guard !requests.loaded else { return }
            do { try await Task.sleep(for: .seconds(2)) } catch { return }
            checkedLong = true
        }
    }

    @ViewBuilder
    private func content(at date: Date) -> some View {
        if requests.rows.isEmpty {
            if !requests.loaded && !checkedLong {
                ProgressView("Checking…")
            } else if let notice = requests.notice {
                ContentUnavailableView {
                    Label(notice.title, systemImage: "exclamationmark.triangle")
                } description: {
                    Text(verbatim: notice.message)
                }
            } else if let failure = requests.failure {
                ContentUnavailableView {
                    Label("Can't check for requests", systemImage: "wifi.exclamationmark")
                } description: {
                    Text(verbatim: failure)
                }
            } else {
                ContentUnavailableView {
                    Label("No access requests waiting", systemImage: "checkmark.shield")
                } description: {
                    Text("When an agent asks for a credential, the request appears here.")
                }
            }
        } else {
            List {
                if let notice = requests.notice {
                    Section {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(verbatim: notice.title)
                                .font(.headline)
                            Text(verbatim: notice.message)
                                .font(.footnote)
                        }
                        .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Section {
                    ForEach(requests.rows) { request in
                        NavigationLink(value: WatchRoute.request(request.id)) {
                            RequestRow(request: request, date: date)
                        }
                    }
                } footer: {
                    footer
                }
            }
        }
    }

    @ViewBuilder
    private var footer: some View {
        if let since = requests.offlineSince {
            Text(verbatim: "Offline. Showing requests from \(since.formatted(date: .omitted, time: .shortened)).")
        } else if let reason = requests.allowOffReason {
            Text(verbatim: reason)
        }
    }
}

#Preview("Requests") {
    WatchRootView(model: WatchPreview.model(.requests))
}

#Preview("Empty") {
    WatchRootView(model: WatchPreview.model(.empty))
}
