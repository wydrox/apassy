import ApassyCompanionKit
import SwiftUI

struct RequestsAccessRow: View {
    let session: SessionModel
    let request: AccessRequest
    let hold: () -> Void
    let dismissReceipt: () -> Void
    @Binding var receipt: RequestsLocalReceipt

    private var sending: Bool { receipt == .sending }
    private var denied: Bool { receipt == .denied }
    private var error: String? {
        if case .failed(let message) = receipt { return message }
        return nil
    }
    @State private var tapGuard = AnswerGuard()

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(request.itemName).font(.headline)
            Text("\(AgentName.display(request.agent)) asks for access").font(.subheadline)
            if let folder = CommandDisplay.folderTail(request.cwd) {
                Text(folder).font(.subheadline).foregroundStyle(.secondary)
            }
            if !request.reason.isEmpty {
                Text("The agent says: \(request.reason)").font(.callout).foregroundStyle(.secondary)
            }
            Label("Review access on Mac", systemImage: "desktopcomputer").font(.subheadline)
            if sending {
                ProgressView("Sending denial…")
            } else if denied {
                Label("Denied · Confirmed by \(session.macName)", systemImage: "xmark.circle")
                    .font(.subheadline.weight(.medium))
                Button("Done", action: dismissReceipt).buttonStyle(.bordered).frame(minHeight: 44)
            } else {
                if let error { Text(error).font(.footnote).foregroundStyle(.secondary) }
                Button("Deny", role: .destructive, action: deny)
                    .buttonStyle(.bordered).frame(minWidth: 44, minHeight: 44)
                    .disabled(!session.canDenyAccessFromList(request, now: .now))
                    .accessibilityLabel("Deny access to \(request.itemName) for \(AgentName.display(request.agent))")
            }
        }
        .padding(.vertical, 4)
        .onAppear { tapGuard.arm(now: .now) }
    }

    private func deny() {
        guard tapGuard.accepts(now: .now), session.canDenyAccessFromList(request, now: .now), !sending else { return }
        hold()
        receipt = .sending
        Task {
            do {
                try await session.denyAccessFromList(request)
                receipt = .denied
                AccessibilityNotification.Announcement("Access denied. Confirmed by \(session.macName).").post()
            } catch {
                receipt = .failed(error.localizedDescription)
                AccessibilityNotification.Announcement(error.localizedDescription).post()
            }
        }
    }
}
