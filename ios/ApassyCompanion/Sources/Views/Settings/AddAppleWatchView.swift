import ApassyVaultKit
import SwiftUI

/// Settings > Devices > Add Apple Watch (ADR 0039 section 6, flow spec S2): this iPhone scans the
/// Connect code of the Mac and hands it to Apassy on the watch, which has no camera. The iPhone
/// never uses the link and never keeps it; the watch makes its own keys and shows the words.
struct AddAppleWatchView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var step = Step.ready
    /// The scanned code on its way to the watch: in memory for the one send, then dropped.
    @State private var outgoing: Outgoing?

    private struct Outgoing: Equatable {
        let id = UUID()
        let link: String
    }

    private enum Step: Equatable {
        case ready
        case scanning
        case sending
        case sent
        /// The scan was not a Connect code of a Mac.
        case notConnectCode
        /// The code did not reach the watch, or the watch refused it (its sentence).
        case failed(String?)
    }

    private var watch: AppleWatchLink { .shared }

    var body: some View {
        Form {
            Section {
                numbered(1, "On your Mac, open Apassy › Settings › Devices › Add an iPhone or a Mac…")
                numbered(2, "Scan the code with this iPhone.")
                numbered(3, "Check the words on your watch and your Mac.")
            } footer: {
                Text("This iPhone only passes the code to your watch. The watch makes its own keys.")
            }
            switch step {
            case .scanning:
                Section {
                    CodeScannerPanel(
                        accessibilityLabel: "Camera for the Connect code", use: "to read the Connect code on your Mac"
                    ) { code in received(code) }
                    Button("Cancel", role: .cancel) { step = .ready }
                }
            case .sending:
                Section {
                    HStack {
                        ProgressView()
                        Text("Sending the code to your watch…")
                    }
                }
            case .sent:
                Section {
                    Label("Sent to your watch. Check the words on your watch and your Mac.", systemImage: "checkmark.circle.fill")
                    Button("Done") { dismiss() }
                }
            case .ready, .notConnectCode, .failed:
                Section {
                    Button("Scan the Code on Your Mac", systemImage: "qrcode.viewfinder") { step = .scanning }
                        .disabled(!watch.isPaired || !watch.isReachable)
                    Button("Cancel", role: .cancel) { dismiss() }
                } footer: {
                    if let problem {
                        Text(verbatim: problem)
                    }
                }
            }
        }
        .navigationTitle("Add Apple Watch")
        .navigationBarTitleDisplayMode(.inline)
        .task { watch.activate() }
        .task(id: outgoing?.id) {
            guard let link = outgoing?.link else { return }
            let result = await watch.send(link: link)
            outgoing = nil
            switch result {
            case .sent: step = .sent
            case .refused(let message): step = .failed(message.isEmpty ? nil : message)
            case .failed: step = .failed(nil)
            }
        }
    }

    /// Why the scan cannot start, or why the last code did not reach the watch.
    private var problem: String? {
        if !watch.isPaired { return "Pair an Apple Watch with this iPhone first." }
        switch step {
        case .failed(let message?):
            return "Couldn't send the code to your watch. Keep the watch near this iPhone and try again. \(message)"
        case .failed(nil):
            return "Couldn't send the code to your watch. Keep the watch near this iPhone and try again."
        case .notConnectCode:
            return "This is not an Apassy Connect code. On your Mac, open Apassy › Settings › Devices › Add an iPhone or a Mac…"
        default:
            break
        }
        if !watch.isReachable { return "Open Apassy on your Apple Watch, then try again." }
        return nil
    }

    private func numbered(_ number: Int, _ text: LocalizedStringKey) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(number, format: .number)
                .monospacedDigit()
                .foregroundStyle(.secondary)
            Text(text)
        }
        .accessibilityElement(children: .combine)
    }

    /// A scanned code goes to the watch at once and is not kept.
    private func received(_ code: String) {
        guard step == .scanning else { return }
        guard WatchConnectLink.isConnectLink(code) else {
            step = .notConnectCode
            return
        }
        guard watch.isReachable else {
            step = .ready
            return
        }
        step = .sending
        outgoing = Outgoing(link: code.trimmingCharacters(in: .whitespacesAndNewlines))
    }
}

#Preview {
    NavigationStack { AddAppleWatchView() }
}
