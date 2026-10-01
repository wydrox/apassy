import ApassyCompanionKit
import SwiftUI

/// The phone has sent its keys and waits for the Mac.
struct ConnectingView: View {
    let model: PairingModel
    let macName: String

    var body: some View {
        PairingScreen {
            VStack(spacing: 24) {
                ProgressView()
                    .controlSize(.extraLarge)
                PairingHero(
                    symbol: "lock.iphone", title: "Connecting to \(macName)",
                    message: "Approve the pairing with Face ID if the iPhone asks. It makes the approval key sign once.")
            }
        } actions: {
            Button {
                model.backToWelcome()
            } label: {
                Text("Cancel").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glass)
        }
    }
}

/// The code that the owner types on the Mac. Only this iPhone shows it (contract 5.3).
struct CodeView: View {
    let model: PairingModel
    let macName: String
    let code: String
    let expiresAt: Date
    @ScaledMetric(relativeTo: .largeTitle) private var codeSize: CGFloat = 60

    var body: some View {
        PairingScreen {
            VStack(spacing: 24) {
                Text("Type this code in Apassy on your Mac")
                    .font(.title2.bold())
                    .multilineTextAlignment(.center)
                Text(code)
                    .font(.system(size: codeSize, weight: .semibold, design: .monospaced))
                    .minimumScaleFactor(0.5)
                    .lineLimit(1)
                    .padding(.vertical, 8)
                    .accessibilityLabel(spoken(code))
                VStack(spacing: 8) {
                    HStack(spacing: 10) {
                        ProgressView()
                        Text("Waiting for you to confirm on \(macName)")
                            .foregroundStyle(.secondary)
                    }
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let left = max(0, Int(expiresAt.timeIntervalSince(context.date).rounded(.down)))
                        Text("The code works for \(WaitClock.text(left)) more")
                            .font(.footnote.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    if let note = model.waitNote {
                        CalloutView(symbol: "wifi.exclamationmark", text: note)
                    }
                }
                Text(
                    "The Mac asks for Touch ID or your password after you type the code. To stop, select Cancel here and in Apassy on your Mac."
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            }
        } actions: {
            Button {
                model.backToWelcome()
            } label: {
                Text("Cancel").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glass)
        }
    }

    /// The digits one by one, so VoiceOver does not read "three hundred forty-eight thousand".
    private func spoken(_ code: String) -> String {
        code.filter(\.isNumber).map(String.init).joined(separator: ", ")
    }
}

/// The pairing worked.
struct PairedView: View {
    let model: PairingModel
    let macName: String
    @State private var appeared = false

    var body: some View {
        PairingScreen {
            PairingHero(
                symbol: "checkmark.seal.fill", tint: .green, title: "Paired with \(macName)",
                message: "Runs that wait for you show in the Inbox. Each approval asks for Face ID on this iPhone.")
        } actions: {
            Button {
                model.finish()
            } label: {
                Text("Continue").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
        }
        .onAppear { appeared = true }
        .sensoryFeedback(.success, trigger: appeared)
    }
}

#if DEBUG
    #Preview("Connecting") {
        ConnectingView(
            model: PairingModel(store: InMemoryPairingStore(), notice: nil, deviceName: "Test iPhone") { _, _ in },
            macName: "Mac mini")
    }

    #Preview("Code") {
        CodeView(
            model: PairingModel(store: InMemoryPairingStore(), notice: nil, deviceName: "Test iPhone") { _, _ in },
            macName: "Mac mini", code: "348 942", expiresAt: Date().addingTimeInterval(272))
    }

    #Preview("Paired") {
        PairedView(
            model: PairingModel(store: InMemoryPairingStore(), notice: nil, deviceName: "Test iPhone") { _, _ in },
            macName: "Mac mini")
    }

    #Preview("Denied") {
        PairingFlowView(
            model: {
                let model = PairingModel(store: InMemoryPairingStore(), notice: nil, deviceName: "Test iPhone") { _, _ in }
                model.step = .failed(
                    title: "The Mac refused the link", message: CompanionError.linkRejected.errorDescription ?? "")
                return model
            }())
    }
#endif
