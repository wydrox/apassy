import ApassyCompanionKit
import ApassyVaultKit
import SwiftUI

/// Navigation and answers are sibling controls; tapping one never activates another.
struct RequestsWaitingRow: View {
    let model: QuestionsModel
    let question: RemoteQuestion
    let now: Date
    @Environment(\.dynamicTypeSize) private var typeSize
    @State private var tapGuard = AnswerGuard()
    @State private var commentQuestion: RemoteQuestion?

    private var actions: RequestListActions { model.listActions(for: question, now: now) }
    private var delivery: QuestionsModel.Delivery? { model.delivery(for: question) }
    private var isSending: Bool { delivery == .sending }
    private var hasReceipt: Bool {
        if isSending { return true }
        if case .sent = delivery { return true }
        return model.receiptQuestions.contains { $0.requestIdentity == question.requestIdentity }
            && model.outcome(for: question) != nil
    }
    private var status: String? {
        if isSending { return "Sending answer…" }
        return model.outcome(for: question)?.text ?? model.deliveryText(for: question)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            RequestsRowLink(route: .question(question.requestIdentity)) {
                RequestsRowSummary(
                    title: question.credentialTitle,
                    requester: question.card.map { AgentName.display($0.run.agent) },
                    project: question.card?.question.project?.label,
                    vault: question.vaultName ?? "Not reported",
                    device: question.askerName
                ) {
                    if let card = question.card {
                        Text("\(card.question.action.label) · \(Decisions.environment(card.question.items))")
                            .font(.subheadline.weight(.medium))
                        if card.question.items.contains(where: { $0.production && !$0.unconfirmed }) {
                            DecisionTag(text: "Production", tint: .red)
                        }
                        if card.question.items.count > 1 {
                            Text(card.question.items.map(\.name).joined(separator: ", "))
                                .font(.subheadline).foregroundStyle(.secondary)
                        }
                        if actions.canAllowOnce { Text("Access: This request only").font(.subheadline) }
                        Text(CommandDisplay.line(card.run.command))
                            .font(.callout.monospaced()).fixedSize(horizontal: false, vertical: true)
                    } else {
                        Label("This question could not be read", systemImage: "lock.trianglebadge.exclamationmark")
                            .font(.subheadline).foregroundStyle(.secondary)
                    }
                    if !hasReceipt {
                        Text("\(Decisions.clock(question.secondsLeft(now: now))) left")
                            .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                            .accessibilityLabel("Expires at \(Date(timeIntervalSince1970: TimeInterval(question.expiresAt)).formatted(date: .omitted, time: .shortened))")
                    }
                }
            }
            if hasReceipt {
                VStack(alignment: .leading, spacing: 6) {
                    if isSending {
                        ProgressView("Sending answer…")
                    } else if let status {
                        Label(status, systemImage: receiptSymbol).font(.subheadline.weight(.medium))
                    }
                    if question.settle != nil {
                        Text("Execution: Not reported").font(.footnote).foregroundStyle(.secondary)
                    }
                }
                let layout = typeSize.isAccessibilitySize ? AnyLayout(VStackLayout(alignment: .leading)) : AnyLayout(HStackLayout())
                layout {
                    if model.needsConfirmation(for: question) {
                        Button("Check Again", action: refresh).frame(minHeight: 44)
                    }
                    Button("Done", action: dismissReceipt).frame(minHeight: 44).disabled(isSending)
                }
                .buttonStyle(.bordered)
            } else {
                if case .failed(let message) = delivery {
                    Text(message).font(.footnote).foregroundStyle(.secondary)
                }
                let layout = typeSize.isAccessibilitySize ? AnyLayout(VStackLayout(alignment: .leading)) : AnyLayout(HStackLayout())
                layout {
                    Button("Dismiss", role: .destructive, action: deny)
                        .frame(maxWidth: .infinity, minHeight: 44).disabled(!actions.canDeny)
                        .accessibilityLabel("Dismiss \(question.credentialTitle)")
                    if let card = question.card {
                        let bar = AnswerBar.make(for: card)
                        ForEach([bar.primary, bar.secondaryApproval].compactMap { $0 }) { choice in
                            Button(choice.label) { send(choice) }
                                .buttonStyle(.borderedProminent)
                                .frame(maxWidth: .infinity, minHeight: 44)
                                .disabled(!actions.canDeny)
                        }
                    }
                }
                .buttonStyle(.bordered)
                Button("Dismiss with comment", role: .destructive) {
                    guard tapGuard.accepts(now: .now), actions.canDeny else { return }
                    commentQuestion = question
                }
                .disabled(!actions.canDeny)
            }
        }
        .padding(.vertical, 4)
        .onAppear { tapGuard.arm(now: .now) }
        .onChange(of: question.card) { _, _ in tapGuard.arm(now: .now) }
        .onChange(of: status) { _, value in announce(value) }
        .sheet(item: $commentQuestion) { snapshot in
            DismissCommentSheet { answer in
                Task { await model.send(.init(answer: answer, label: "Dismiss with comment", destructive: true), for: snapshot) }
            }
        }
    }

    private var receiptSymbol: String {
        switch model.outcome(for: question)?.tone {
        case .allowed: "checkmark.circle"
        case .denied: "xmark.circle"
        default: "clock"
        }
    }

    private func deny() {
        guard tapGuard.accepts(now: .now), actions.canDeny, let card = question.card else { return }
        Task { await model.send(AnswerBar.make(for: card).deny, for: question) }
    }

    private func send(_ choice: AnswerBar.Choice) {
        guard tapGuard.accepts(now: .now), actions.canDeny else { return }
        Task { await model.send(choice, for: question) }
    }

    private func refresh() { Task { await model.refresh() } }
    private func dismissReceipt() { model.dismissReceipt(for: question) }
    private func announce(_ value: String?) {
        if let value { AccessibilityNotification.Announcement(value).post() }
    }
}
