import ApassyVaultKit
import SwiftUI

/// Import from another app, or export to one, with Apple's credential exchange. The system shows
/// the other app; this screen says what moves, and what happened, in counts only.
struct CredentialExchangeView: View {
    enum Mode { case importing, exporting }

    let model: CredentialExchangeModel
    let mode: Mode
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            switch model.state {
            case .working(let text):
                Section {
                    HStack(spacing: 12) {
                        ProgressView()
                        Text(text)
                    }
                }
            case .exportPaused:
                Section {
                    Label(
                        model.canResumeExport
                            ? "Apassy is open again. Continue to finish the export."
                            : model.exportWaitsForAnotherVault
                                ? "Select the vault where you started the export. Then unlock it to continue."
                                : "Apassy locked while you picked the other app. Unlock Apassy to continue.",
                        systemImage: "lock")
                    Button("Continue export", systemImage: "square.and.arrow.up") {
                        Task { await model.resumeExport() }
                    }
                    .disabled(!model.canResumeExport)
                    Button("Cancel export", role: .cancel) { model.cancelPausedExport() }
                } footer: {
                    Text("Apassy sends no credentials while the export is paused. It asks for Face ID again before it continues.")
                }
            case .finished(let text):
                Section {
                    Label(text, systemImage: "checkmark.circle")
                }
                if model.duplicateGroups > 0 {
                    Section {
                        NavigationLink {
                            DuplicatesView(vault: model.vault)
                        } label: {
                            Label("Review duplicates (\(model.duplicateGroups))", systemImage: "square.on.square")
                        }
                    } footer: {
                        Text("Some items of the vault hold the same credential. Merge them, or keep them as they are.")
                    }
                    // Count again when the owner comes back from the duplicates.
                    .onAppear { Task { await model.refreshDuplicates() } }
                }
                Section {
                    Button("Done") { close() }
                }
            case .failed(let text):
                Section {
                    Label(text, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                }
                Section {
                    Button("Done") { close() }
                }
            case .idle, .importWaiting:
                if mode == .importing || model.state == .importWaiting {
                    importStart
                } else {
                    exportStart
                }
            }
        }
        .navigationTitle(mode == .importing ? "Import" : "Move to another app")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if mode == .importing {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { close() }
                        .disabled(model.isWorking)
                }
            }
        }
        .interactiveDismissDisabled(model.isWorking)
    }

    @ViewBuilder
    private var importStart: some View {
        if model.state == .importWaiting {
            Section {
                Text("Another app sent its logins, passkeys, one-time passwords, and other items to Apassy. They go into this vault and sync with it.")
                Button("Import", systemImage: "square.and.arrow.down") {
                    Task { await model.importNow() }
                }
                Button("Not now", role: .cancel) {
                    model.cancelImport()
                    dismiss()
                }
            } footer: {
                Text("Apassy keeps logins, passkeys with their extension data, and one-time passwords. Cards, Wi-Fi networks, documents, addresses, notes, and custom fields become items of the kind Other, with their numbers and secrets hidden. API keys and SSH keys keep their kinds. A passkey for a login that is in the vault already goes on that login.")
            }
        } else {
            Section {
                Text("To import, open the other app (for example Passwords or 1Password), choose Export, and pick Apassy.")
            }
        }
    }

    private var exportStart: some View {
        Section {
            Text("Move your logins, one-time passwords, and passkeys to another app on this iPhone that takes them, such as Passwords. You pick the app in the next step. Apassy keeps its own copy.")
            Button("Export to another app", systemImage: "square.and.arrow.up") {
                Task { await model.export() }
            }
        } footer: {
            Text("The export holds your passwords and the keys of your passkeys. It goes straight to the app you pick; Apassy writes no file. To import into Apassy, start the export in the other app and pick Apassy.")
        }
    }

    private func close() {
        model.dismiss()
        if mode == .importing { dismiss() }
    }
}
