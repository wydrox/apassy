import ApassyCompanionKit
import SwiftUI

/// The runs that wait, then the open access requests, under a floating status capsule.
struct InboxView: View {
    let session: SessionModel
    /// The run in the sheet. It is a copy of the run as the owner opened it.
    @State private var opened: PendingRun?

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("Inbox")
                .connectionCapsule(session)
        }
        .sheet(item: $opened) { run in
            RunDetailView(session: session, run: run)
        }
    }

    @ViewBuilder
    private var content: some View {
        if session.showsConnectionScreen(rows: session.waitingCount) {
            ConnectionUnavailableView(session: session)
        } else if session.waitingCount == 0 {
            ContentUnavailableView(
                "Nothing waits", systemImage: "tray",
                description: Text("When an agent needs your approval, the run shows here."))
        } else {
            list
        }
    }

    /// A section title. While the Mac does not answer, the list is the last one that arrived.
    private func header(_ title: String) -> String {
        session.state == .connected ? title : "\(title) (last known, not up to date)"
    }

    private var list: some View {
        List {
            if !session.runs.isEmpty {
                Section(header("Waiting for you")) {
                    ForEach(session.runs) { run in
                        Button {
                            opened = run
                        } label: {
                            RunRow(run: run, timeout: session.approvalTimeout, fetchedAt: session.fetchedAt)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            if !session.accessRequests.isEmpty {
                Section(header("Access requests")) {
                    ForEach(session.accessRequests) { request in
                        AccessRequestRow(request: request, isDenying: session.denying.contains(request.id)) {
                            Task { await session.deny(request) }
                        }
                    }
                }
            }
        }
        .scrollEdgeEffectStyle(.soft, for: .top)
        .refreshable { await session.refresh() }
    }
}

/// The state of the connection as a full screen, for when there is no inbox to show.
struct ConnectionUnavailableView: View {
    let session: SessionModel
    @Environment(\.openURL) private var openURL

    var body: some View {
        switch session.state {
        case .connecting:
            ProgressView("Connecting to \(session.macName)")
        case .connected:
            ProgressView()
        case .unreachable:
            unavailable("Mac not reachable", "wifi.exclamationmark", CompanionError.notReachable.errorDescription)
        case .localNetworkDenied:
            unavailable(
                "Allow local network access", "network.slash", CompanionError.localNetworkDenied.errorDescription,
                showsSettings: true)
        case .pinMismatch:
            unavailable(
                "Not the Mac you paired with", "exclamationmark.shield",
                CompanionError.pinMismatchOnAllHosts.errorDescription, showsForget: true)
        case .problem(let message):
            unavailable("Problem with the Mac", "exclamationmark.triangle", message)
        }
    }

    /// The buttons are in the content, not in a floating bar, so they are not glass.
    private func unavailable(
        _ title: String, _ symbol: String, _ message: String?, showsSettings: Bool = false,
        showsForget: Bool = false
    ) -> some View {
        ContentUnavailableView {
            Label(title, systemImage: symbol)
        } description: {
            Text(message ?? "")
        } actions: {
            Button("Try again") { Task { await session.refresh() } }
                .buttonStyle(.bordered)
            if showsSettings {
                Button("Open Settings") {
                    if let url = URL(string: UIApplication.openSettingsURLString) { openURL(url) }
                }
                .buttonStyle(.bordered)
            }
            if showsForget {
                ForgetMacButton(session: session)
                    .buttonStyle(.bordered)
            }
        }
    }
}

#if DEBUG
    #Preview("Inbox") {
        InboxView(session: .preview())
    }

    #Preview("Nothing waits") {
        InboxView(session: .preview(inbox: Inbox(runs: [], accessRequests: [], activity: [])))
    }

    #Preview("Not reachable") {
        InboxView(session: .preview(inbox: nil, state: .unreachable))
    }

    #Preview("Not reachable, nothing waited") {
        InboxView(session: .preview(inbox: Inbox(runs: [], accessRequests: [], activity: []), state: .unreachable))
    }

    #Preview("Not the paired Mac") {
        InboxView(session: .preview(state: .pinMismatch))
    }
#endif
