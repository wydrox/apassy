import ApassyVaultKit
import SwiftUI

/// The answers of a request and their state (A2 items 9 and 10, A3, A4). Allow once and Deny span
/// the width, have the same height, and are apart; only Allow once is prominent, and neither is
/// selected when the screen opens. Deny never needs a check of the wrist.
struct AnswerControlsView: View {
    let request: RelayAccessRequest
    let phase: WatchRequestPhase
    let onAnswer: (AccessChoice) -> Void
    let onDone: () -> Void
    /// Wrist down (Always On): the buttons look unavailable.
    @Environment(\.isLuminanceReduced) private var isLuminanceReduced

    var body: some View {
        let card = request.card
        let offersAllow = WatchRequestRules.offersAllowOnce(card)
        VStack(alignment: .leading, spacing: 10) {
            switch phase {
            case .decide(let allowOnce, let notes):
                ForEach(notes.indices, id: \.self) { index in
                    Text(verbatim: notes[index])
                        .font(.footnote)
                }
                buttons(allowOnce: allowOnce, enabled: !isLuminanceReduced)
                if allowOnce { footnote }
            case .checkingWrist:
                Label(WatchRequestText.checkingWrist, systemImage: "applewatch")
                    .font(.footnote)
                buttons(allowOnce: true, enabled: false)
                footnote
            case .sending:
                HStack(spacing: 6) {
                    ProgressView()
                        .frame(width: 20, height: 20)
                    Text(WatchRequestText.sending)
                }
            case .sent:
                Text(verbatim: WatchRequestText.sent(card))
                buttons(allowOnce: offersAllow, enabled: false)
            case .notConfirmed:
                Text(verbatim: WatchRequestText.notConfirmed(card))
                buttons(allowOnce: offersAllow, enabled: false)
            case .ended:
                Text(verbatim: WatchRequestText.ended(card))
            case .expired:
                Text(WatchRequestText.expired)
                buttons(allowOnce: offersAllow, enabled: false)
            case .result(let result):
                AnswerResultView(result: result, mac: WatchRequestText.mac(card), onDone: onDone)
            case .unavailable:
                Text(WatchRequestText.unavailable)
            }
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    private func buttons(allowOnce: Bool, enabled: Bool) -> some View {
        VStack(spacing: 10) {
            if allowOnce {
                Button {
                    onAnswer(.allow_once)
                } label: {
                    Text("Allow once")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
            }
            Button(role: .destructive) {
                onAnswer(.deny)
            } label: {
                Text("Deny")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
        }
        .disabled(!enabled)
    }

    private var footnote: some View {
        Text(WatchRequestText.allowFootnote)
            .font(.footnote)
            .foregroundStyle(.secondary)
    }
}
