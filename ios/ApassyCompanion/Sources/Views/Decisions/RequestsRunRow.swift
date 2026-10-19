import ApassyCompanionKit
import SwiftUI

/// Wi-Fi runs do not report a verified credential environment, so grants require full review.
struct RequestsRunRow: View {
    let session: SessionModel
    let run: PendingRun
    let now: Date
    let hold: () -> Void
    let dismissReceipt: () -> Void
    @Environment(\.dynamicTypeSize) private var typeSize
    @Binding var receipt: RequestsLocalReceipt

    private var sending: Bool { receipt == .sending }
    private var denied: Bool { receipt == .denied }
    private var error: String? {
        if case .failed(let message) = receipt { return message }
        return nil
    }
    @State private var tapGuard = AnswerGuard()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            RequestsRowLink(route: .run(sourceID: session.requestSourceID, run: run)) {
                RequestsRowSummary(
                    title: run.envNames.isEmpty ? "Command request" : run.envNames.joined(separator: ", "),
                    requester: AgentName.display(run.agent),
                    project: CommandDisplay.folderTail(run.cwd),
                    vault: nil,
                    device: session.macName
                ) {
                    Text(CommandDisplay.line(run.command)).font(.callout.monospaced())
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if sending {
                ProgressView("Sending denial…")
            } else if denied {
                Label("Denied · Confirmed by \(session.macName)", systemImage: "xmark.circle")
                    .font(.subheadline.weight(.medium))
                Text("Execution: Not reported").font(.footnote).foregroundStyle(.secondary)
                Button("Done", action: dismissReceipt).buttonStyle(.bordered).frame(minHeight: 44)
            } else {
                if let error { Text(error).font(.footnote).foregroundStyle(.secondary) }
                let layout = typeSize.isAccessibilitySize ? AnyLayout(VStackLayout(alignment: .leading)) : AnyLayout(HStackLayout())
                layout {
                    Button("Deny", role: .destructive, action: deny)
                        .frame(maxWidth: .infinity, minHeight: 44)
                        .disabled(!session.canDenyFromList(run: run, now: now))
                        .accessibilityLabel("Deny command requested by \(AgentName.display(run.agent))")
                    NavigationLink("Review", value: DecisionRoute.run(sourceID: session.requestSourceID, run: run))
                        .frame(maxWidth: .infinity, minHeight: 44)
                        .accessibilityLabel("Review command requested by \(AgentName.display(run.agent))")
                }
                .buttonStyle(.bordered)
            }
        }
        .padding(.vertical, 4)
        .onAppear { tapGuard.arm(now: .now) }
        .onChange(of: run.digest) { _, _ in tapGuard.arm(now: .now) }
    }

    private func deny() {
        guard tapGuard.accepts(now: .now), session.canDenyFromList(run: run, now: .now), !sending else { return }
        hold()
        receipt = .sending
        Task {
            do {
                try await session.denyFromList(run)
                receipt = .denied
                AccessibilityNotification.Announcement("Denied. Confirmed by \(session.macName).").post()
            } catch {
                receipt = .failed(error.localizedDescription)
                AccessibilityNotification.Announcement(error.localizedDescription).post()
            }
        }
    }
}
