import ApassyVaultKit
import SwiftUI

extension View {
    /// Read the questions and wait for new ones while the app is not in the background.
    func questionsPolling(_ model: QuestionsModel?) -> some View {
        modifier(QuestionsPolling(model: model))
    }
}

private struct QuestionsPolling: ViewModifier {
    let model: QuestionsModel?
    @Environment(\.scenePhase) private var scenePhase

    func body(content: Content) -> some View {
        content
            .task(id: CoverPolicy.polls(in: AppPhase(scenePhase))) {
                if CoverPolicy.polls(in: AppPhase(scenePhase)), let model { await model.watch() }
            }
    }
}

/// The Decisions tab of the vault (ADR 0026 §8): `DecisionsView`, with the questions through the
/// relay and the runs of the Mac on this Wi-Fi in one list. The tab shell calls this initializer.
struct ApprovalsHub: View {
    let questions: QuestionsModel?
    let companion: AppModel
    var onSettings: (() -> Void)?

    var body: some View {
        DecisionsView(questions: questions, companion: companion, onSettings: onSettings)
        #if DEBUG && targetEnvironment(simulator)
            .decisionsPreviewSeed(questions)
        #endif
    }
}
