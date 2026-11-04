import ApassyVaultKit
import SwiftUI

/// Settings > Devices > Add Apple Watch (ADR 0039 section 6, flow spec S2): this iPhone scans the
/// Connect code of the Mac and hands it to Apassy on the watch, which has no camera. The iPhone
/// never uses the link and never keeps it; the watch makes its own keys and shows the words.
struct AddAppleWatchView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var scan = WatchConnectScan()

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
            switch scan.step {
            case .scanning:
                Section {
                    CodeScannerPanel(
                        accessibilityLabel: "Camera for the Connect code", use: "to read the Connect code on your Mac"
                    ) { code in scan.receive(code, isReachable: watch.isReachable) }
                    Button("Cancel", role: .cancel) { scan.cancelScanning() }
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
            case .ready, .failed:
                Section {
                    Button("Scan the Code on Your Mac", systemImage: "qrcode.viewfinder") { scan.startScanning() }
                        .disabled(!watch.isPaired || !watch.isWatchAppInstalled || !watch.isReachable)
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
        .task(id: scan.outgoing?.id) {
            guard let link = scan.outgoing?.link else { return }
            let result = await watch.send(link: link)
            scan.sent(result)
        }
    }

    /// Why the scan cannot start, or why the last code did not reach the watch.
    private var problem: String? {
        if case .failed(let message) = scan.step { return message }
        if !watch.isPaired { return "Pair an Apple Watch with this iPhone first." }
        if !watch.isWatchAppInstalled { return AppleWatchLink.installHint }
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
}

#Preview {
    NavigationStack { AddAppleWatchView() }
}
