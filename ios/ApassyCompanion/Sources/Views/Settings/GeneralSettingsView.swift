import ApassyVaultKit
import AuthenticationServices
import SwiftUI

/// Settings > General: the vault and the other vaults, removing the vault from this iPhone, import
/// and export, and AutoFill.
struct GeneralSettingsView: View {
    /// Closes the Settings sheet (`dismiss` here would only go back to the root).
    let close: DismissAction
    @Environment(RootModel.self) private var root

    var body: some View {
        Form {
            if let vault = root.vault, vault.hasVault, vault.isUnlocked {
                GeneralVaultSections(vault: vault, close: close)
            } else {
                Section {
                    Text("No vault is on this iPhone. Add the vault of your Mac to see your logins and keys here.")
                    Button("Add your vault", systemImage: "plus") {
                        close()
                        root.addVault()
                    }
                } header: {
                    Text("Vault")
                }
            }
        }
        .navigationTitle("General")
        .navigationBarTitleDisplayMode(.inline)
    }
}

/// The sections of General for an unlocked vault.
private struct GeneralVaultSections: View {
    let vault: VaultModel
    let close: DismissAction
    @Environment(RootModel.self) private var root
    @Environment(\.scenePhase) private var scenePhase

    @State private var working = false
    @State private var confirmingRemove = false
    @State private var removeError: VaultError?
    @State private var autoFillOn: Bool?

    var body: some View {
        Group {
            Section {
                if vault.vaults.count > 1 {
                    Picker(
                        "Vault",
                        selection: Binding(
                            get: { vault.vault?.id ?? "" },
                            set: { id in
                                close()
                                Task { await vault.select(vaultID: id) }
                            })
                    ) {
                        ForEach(vault.vaults) { Text($0.name).tag($0.id) }
                    }
                } else {
                    LabeledContent("Name", value: vault.vault?.name ?? "")
                }
                Button("Add another vault", systemImage: "plus") {
                    close()
                    root.addVault()
                }
                Button("Remove “\(vault.vault?.name ?? "")” from this iPhone", role: .destructive) {
                    confirmingRemove = true
                }
                .disabled(working)
            } header: {
                Text("Vault")
            } footer: {
                Text(vault.vault?.isICloud == true
                    ? "This removes the local vault and stored passphrase. The file in iCloud Drive stays."
                    : "This removes the vault from this iPhone and from the relay. The vault stays on your Macs.")
            }
            if let exchange = root.exchange {
                Section {
                    NavigationLink {
                        CredentialExchangeView(model: exchange, mode: .exporting)
                    } label: {
                        Label("Move to another app", systemImage: "arrow.left.arrow.right")
                    }
                } header: {
                    Text("Import and export")
                } footer: {
                    Text("Logins, one-time passwords, and passkeys move between Apassy and another app through iOS, after Face ID. To import, start the export in the other app and pick Apassy.")
                }
            }
            autoFill
        }
        .confirmationDialog(
            "Remove “\(vault.vault?.name ?? "")” from this iPhone?", isPresented: $confirmingRemove,
            titleVisibility: .visible
        ) {
            Button("Remove", role: .destructive) { remove(force: false) }
        } message: {
            Text(vault.vault?.isICloud == true
                ? "This removes the local vault, sync state, and stored passphrase. The file in iCloud Drive stays."
                : "This removes the vault, sync state, and stored passphrase from this iPhone. Your Macs keep the vault.")
        }
        .alert(
            "The relay did not answer",
            isPresented: Binding(get: { removeError != nil }, set: { if !$0 { removeError = nil } }),
            presenting: removeError
        ) { _ in
            Button("Remove anyway", role: .destructive) { remove(force: true) }
            Button("Cancel", role: .cancel) {}
        } message: { error in
            Text(
                "\(error.message) Remove anyway deletes the vault on this iPhone, and the relay keeps listing this iPhone until a Mac removes it (Devices… > Remove)."
            )
        }
    }

    // MARK: AutoFill

    private var autoFill: some View {
        Section {
            Text(
                "Apassy can fill your passwords and one-time codes, sign in with passkeys, and save new passkeys in Safari and in apps. Turn on Apassy in Settings > General > AutoFill & Passwords. Each one asks for Face ID."
            )
            LabeledContent("AutoFill", value: autoFillOn == nil ? "Checking" : (autoFillOn == true ? "On" : "Off"))
            Button("Open AutoFill settings", systemImage: "gear") {
                Task { try? await ASSettingsHelper.openCredentialProviderAppSettings() }
            }
        } header: {
            Text("AutoFill")
        }
        .task(id: scenePhase) {
            autoFillOn = await ASCredentialIdentityStore.shared.state().isEnabled
        }
    }

    // MARK: Actions

    private func remove(force: Bool) {
        working = true
        Task {
            defer { working = false }
            do {
                try await vault.removeVault(force: force)
                close()
                root.didRemoveVault()
            } catch let error as VaultError where !force && (error.code == .relayUnreachable || error.code == .locked) {
                removeError = error
            } catch {
                vault.alert = error.localizedDescription
            }
        }
    }
}
