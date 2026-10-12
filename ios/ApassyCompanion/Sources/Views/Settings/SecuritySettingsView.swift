import ApassyVaultKit
import SwiftUI

/// Settings > Security: Face ID unlock, the lock, and the time a copied secret stays.
struct SecuritySettingsView: View {
    /// Closes the Settings sheet (`dismiss` here would only go back to the root).
    let close: DismissAction
    @Environment(RootModel.self) private var root

    var body: some View {
        Form {
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
