import ApassyVaultKit
import SwiftUI
import UIKit

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
                            Text("On your Mac: Settings > Devices > Get approvals on your iPhone. Use the same vault from iCloud Drive on this iPhone. After reinstalling, remove the old iPhone in Devices on the Mac, then make a new pairing code.")
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
                        Text("Confirm on the Mac only when it shows all the same words. Keep that screen open while Apassy transfers the connection keys.")
                        if let notice = model.attachNotice { Text(notice).foregroundStyle(.orange) }
                    }
                case .attached:
                    Section {
                        Label("Connected. Requests from your Mac appear on this iPhone on any network.", systemImage: "checkmark.circle")
                        Button("Open Requests") { dismiss() }
                    }
                    RequestsNotificationSettings(model: model)
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
            #if targetEnvironment(simulator)
            .task {
                if ProcessInfo.processInfo.arguments.contains("-ApassyPreviewVault"),
                    let link = UserDefaults.standard.string(forKey: "ApassyConnectLink") {
                    await model.startAttach(link: link)
                }
            }
            #endif
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
    var isPresented = false

    var body: some View {
        DecisionsView(questions: questions, companion: companion, onSettings: onSettings, isPresented: isPresented)
    }
}

/// Owner preference and the effective OS/registration state, shared by General settings.
struct RequestsNotificationSettings: View {
    let model: QuestionsModel
    @Environment(\.openURL) private var openURL
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        Section {
            Toggle("Request Notifications", isOn: Binding(
                get: { model.notificationsOn },
                set: { enabled in Task { await model.setNotifications(enabled) } }))
            Text(model.notificationSettingsMessage)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if model.notificationNeedsSettings {
                Button("Open Settings") {
                    if let url = URL(string: UIApplication.openSettingsURLString) { openURL(url) }
                }
            }
            if model.notificationCanRetry {
                Button("Retry Registration") { Task { await model.retryNotifications() } }
            }
            if let pending = model.notificationsPendingText {
                Text(pending).font(.footnote).foregroundStyle(.secondary)
            }
        } header: {
            Text("Notifications")
        } footer: {
            Text("Alerts say only “A question is waiting”. Apple receives no request, vault, or agent details. An alert opens the Requests list. Registration does not guarantee delivery.")
        }
        .task { await model.refreshNotificationStatus() }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { Task { await model.refreshNotificationStatus() } }
        }
    }
}
