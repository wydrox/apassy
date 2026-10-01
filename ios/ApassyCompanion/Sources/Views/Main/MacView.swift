import ApassyCompanionKit
import SwiftUI

/// The Mac this iPhone is paired with, this iPhone, and the way to unpair.
struct MacView: View {
    let session: SessionModel
    @State private var confirmingUnpair = false
    @Environment(\.openURL) private var openURL

    var body: some View {
        NavigationStack {
            List {
                connection
                macSection
                iPhoneSection
                unpairSection
                if session.state == .pinMismatch { forgetSection }
            }
            .scrollEdgeEffectStyle(.soft, for: .top)
            .navigationTitle("Mac")
            .refreshable {
                await session.refresh()
                await session.refreshStatus()
            }
            .task { await session.refreshStatus() }
        }
    }

    // MARK: Sections

    private var connection: some View {
        Section("Connection") {
            Label(stateTitle, systemImage: stateSymbol)
            if let detail = stateDetail {
                Text(detail)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            if session.state == .localNetworkDenied {
                Button("Open Settings") {
                    if let url = URL(string: UIApplication.openSettingsURLString) { openURL(url) }
                }
            }
        }
    }

    private var macSection: some View {
        Section("Your Mac") {
            LabeledContent("Name", value: session.macName)
            LabeledContent("Last address that answered", value: session.lastGoodHost ?? "None yet")
            if let status = session.status {
                LabeledContent("Apassy on the Mac", value: status.appVersion)
                LabeledContent("Time to decide", value: seconds(status.approvalTimeoutSeconds))
            }
        }
    }

    private var iPhoneSection: some View {
        Section {
            LabeledContent("Name", value: session.status?.device.name ?? "\u{2013}")
            LabeledContent(
                "Paired",
                value: Date(timeIntervalSince1970: TimeInterval(session.record.pairedAt))
                    .formatted(date: .abbreviated, time: .shortened))
            LabeledContent("Keys", value: session.keysInSecureEnclave ? "In the Secure Enclave" : "Software (Simulator)")
        } header: {
            Text("This iPhone")
        } footer: {
            if session.keysInSecureEnclave {
                Text("The keys never leave this iPhone. Each approval needs Face ID.")
            } else {
                Text("Simulator: keys are not in the Secure Enclave. This build is for development only.")
            }
        }
    }

    private var unpairSection: some View {
        Section {
            Button("Unpair this iPhone", role: .destructive) {
                confirmingUnpair = true
            }
            .disabled(session.isEnding)
            .confirmationDialog("Unpair this iPhone?", isPresented: $confirmingUnpair, titleVisibility: .visible) {
                Button("Unpair", role: .destructive) {
                    Task { await session.unpair() }
                }
            } message: {
                Text(
                    "The Mac stops listing this iPhone and this iPhone deletes its keys. If the Mac is not reachable, the keys are deleted anyway.")
            }
        } footer: {
            Text("You can also remove this iPhone in Settings > iPhone companion in Apassy on your Mac.")
        }
    }

    private var forgetSection: some View {
        Section {
            ForgetMacButton(session: session)
        } footer: {
            Text(
                "The device that answers does not have the certificate of the Mac you paired with. The Mac may have been reset, or another device answers.")
        }
    }

    // MARK: Text

    private var stateTitle: String {
        switch session.state {
        case .connecting: "Connecting"
        case .connected: "Connected"
        case .unreachable: "Not reachable"
        case .localNetworkDenied: "Local network access is off"
        case .pinMismatch: "Not the Mac you paired with"
        case .problem: "Problem"
        }
    }

    private var stateSymbol: String {
        switch session.state {
        case .connecting: "arrow.triangle.2.circlepath"
        case .connected: "checkmark.circle.fill"
        case .unreachable: "wifi.exclamationmark"
        case .localNetworkDenied: "network.slash"
        case .pinMismatch: "exclamationmark.shield.fill"
        case .problem: "exclamationmark.triangle.fill"
        }
    }

    private var stateDetail: String? {
        switch session.state {
        case .connecting, .connected: nil
        case .unreachable: CompanionError.notReachable.errorDescription
        case .localNetworkDenied: CompanionError.localNetworkDenied.errorDescription
        case .pinMismatch: CompanionError.pinMismatchOnAllHosts.errorDescription
        case .problem(let message): message
        }
    }

    private func seconds(_ value: Int) -> String {
        Duration.seconds(value).formatted(.units(allowed: [.minutes, .seconds], width: .wide))
    }
}

#if DEBUG
    #Preview("Mac") {
        MacView(session: .preview())
    }

    #Preview("Mac, not the paired one") {
        MacView(session: .preview(state: .pinMismatch))
    }
#endif
