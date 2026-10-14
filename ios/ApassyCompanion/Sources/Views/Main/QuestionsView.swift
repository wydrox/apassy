import ApassyVaultKit
import SwiftUI

/// Connect a vault from iCloud Drive to its notifications team: the link of the Mac, the two
/// safety words while the Mac confirms, then done.
struct ConnectQuestionsView: View {
    @Bindable var model: QuestionsModel
    @State private var link = ""
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                switch model.attach {
                case nil, .failed:
                    Section {
                        TextField("Name of this iPhone", text: $model.deviceName)
                            .textInputAutocapitalization(.words)
                            .autocorrectionDisabled()
                    } header: {
                        Text("Name of this iPhone")
                    } footer: {
                        Text(
                            JoinModel.deviceNameProblem(model.deviceName)
                                ?? "Your Mac shows this name, so two devices are told apart.")
                    }
                    Section {
                        CodeScannerPanel(
                            accessibilityLabel: "Camera for the device link", use: "to read the link of your Mac"
                        ) { code in
                            link = code
                            Task { await model.startAttach(link: code) }
                        }
                        .frame(minHeight: 240)
                        TextField("Or paste the link", text: $link, axis: .vertical)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        Button("Connect") { Task { await model.startAttach(link: link) } }
                            .disabled(!QuestionsModel.isConnectionCode(link))
                    } footer: {
                        if case .failed(let message) = model.attach {
                            Text(message).foregroundStyle(.red)
                        } else {
                            Text("On your Mac: Settings > Devices > Notifications through the relay > Add an iPhone.")
                        }
                    }
                case .companion:
                    Section { ProgressView("Opening companion pairing…") }
                case .starting:
                    Section { ProgressView("Connecting…") }
                case .waiting(let info):
                    Section {
                        Text(info.words.joined(separator: " "))
                            .font(.largeTitle.bold())
                            .frame(maxWidth: .infinity)
                    } header: {
                        Text("Your Mac shows these words")
                    } footer: {
                        Text(
                            "Confirm on the Mac only when it shows the same two words. Then this iPhone gets the questions of \(info.team)."
                        )
                    }
                case .attached:
                    Section {
                        Label("Connected. The questions of this vault show here.", systemImage: "checkmark.circle")
                    }
                }
            }
            .navigationTitle("Connect this iPhone")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    if model.attach == .companion {
                        EmptyView()
                    } else if model.attach == .attached {
                        Button("Done") { dismiss() }
                    } else {
                        Button("Cancel") {
                            model.cancelAttach()
                            dismiss()
                        }
                    }
                }
            }
            .onChange(of: model.attach) { _, step in
                if step == .companion { dismiss() }
            }
        }
    }
}

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
