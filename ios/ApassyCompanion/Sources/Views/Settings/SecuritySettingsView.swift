import ApassyVaultKit
import ApassyCompanionKit
import SwiftUI

/// Settings > Security: Face ID unlock, the lock, and the time a copied secret stays.
struct SecuritySettingsView: View {
    /// Closes the Settings sheet (`dismiss` here would only go back to the root).
    let close: DismissAction
    @Environment(RootModel.self) private var root
    /// Read in `task`: the frequency is a keychain item, which the demo never reads.
    @State private var frequency = FaceIDFrequency.everyTime
    @State private var changingFrequency = false
    @State private var frequencyError: String?

    var body: some View {
        Form {
            Section {
                Picker("Ask for Face ID", selection: $frequency) {
                    ForEach(FaceIDFrequency.allCases) { Text($0.label).tag($0) }
                }
                .disabled(changingFrequency || root.isDemo)
                .onChange(of: frequency) { _, value in
                    guard !root.isDemo, value != FaceIDWindow.app.frequency else { return }
                    changingFrequency = true
                    Task {
                        PrivacyCover.shared.beginSystemPrompt()
                        do {
                            try await FaceIDWindow.app.changeFrequency(value)
                            frequencyError = nil
                        } catch { frequencyError = error.localizedDescription }
                        frequency = FaceIDWindow.app.frequency
                        changingFrequency = false
                        PrivacyCover.shared.endSystemPrompt()
                    }
                }
                if let frequencyError { Text(frequencyError).foregroundStyle(.red) }
            } footer: {
                Text(
                    root.isDemo
                        ? "The demo asks for Face ID each time. This setting is not available in the demo."
                        : "After you confirm with Face ID, Apassy doesn't ask again in this app until the time is up or your iPhone locks. AutoFill always asks."
                )
            }
            if let vault = root.vault, vault.hasVault, vault.isUnlocked {
                SecuritySections(vault: vault, close: close)
            } else {
                Section {
                    Text("Add a vault to set Face ID, the lock, and the clipboard time.")
                        .foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("Security")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            if !root.isDemo { frequency = FaceIDWindow.app.frequency }
        }
    }
}

/// The sections of Security for an unlocked vault.
private struct SecuritySections: View {
    let vault: VaultModel
    let close: DismissAction

    @State private var askingFaceIDPassphrase = false
    @State private var faceIDPassphrase = ""
    @State private var faceIDError: String?

    var body: some View {
        @Bindable var settings = vault.settings
        Group {
            Section {
                if vault.gate.biometry != .none {
                    Toggle(
                        "Unlock with \(vault.gate.biometry.name)",
                        isOn: Binding(
                            get: { vault.faceIDUnlockOn && vault.hasStoredPassphrase },
                            set: { on in
                                if on {
                                    faceIDError = nil
                                    askingFaceIDPassphrase = true
                                } else {
                                    vault.disableFaceIDUnlock()
                                }
                            }))
                }
                Picker("Lock after", selection: $settings.lockAfter) {
                    ForEach(LockAfter.allCases) { Text($0.label).tag($0) }
                }
                if let faceIDError {
                    Text(faceIDError)
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
                Button("Lock now", systemImage: "lock") {
                    close()
                    Task { await vault.lock() }
                }
            } header: {
                Text("Unlock")
            }
            Section {
                Picker("Clear copied secrets after", selection: $settings.clearAfter) {
                    ForEach(ClearAfter.allCases) { Text($0.label).tag($0) }
                }
            } header: {
                Text("Clipboard")
            } footer: {
                Text("A copied secret stays on this iPhone only, not on your other devices.")
            }
        }
        .alert("Turn on \(vault.gate.biometry.name)", isPresented: $askingFaceIDPassphrase) {
            SecureField("Passphrase", text: $faceIDPassphrase)
            Button("Cancel", role: .cancel) { faceIDPassphrase = "" }
            Button("Turn On") { enableFaceID() }
        } message: {
            Text("Type the passphrase of “\(vault.vault?.name ?? "")”. Apassy keeps it behind \(vault.gate.biometry.name) on this iPhone.")
        }
    }

    private func enableFaceID() {
        let typed = faceIDPassphrase
        faceIDPassphrase = ""
        Task {
            do {
                try await vault.enableFaceIDUnlock(passphrase: typed)
                faceIDError = nil
            } catch {
                faceIDError = error.localizedDescription
            }
        }
    }
}
