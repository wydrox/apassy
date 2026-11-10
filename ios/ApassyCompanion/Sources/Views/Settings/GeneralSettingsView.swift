import ApassyVaultKit
import AuthenticationServices
import SwiftUI

/// Settings > General: the vault and the other vaults, removing the vault from this iPhone, import
/// and export, AutoFill, and the plan of Apassy Connect (text only).
struct GeneralSettingsView: View {
    /// Closes the Settings sheet (`dismiss` here would only go back to the root).
    let close: DismissAction
    @Environment(RootModel.self) private var root

    var body: some View {
        Form {
            if let questions = root.questions {
                RequestsNotificationSettings(model: questions)
            }
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
            ConnectPlanSection()
        }
        .navigationTitle("General")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: Apassy Connect row
// Plan s7 section 6 (App Store Review Guideline 3.1): this block shows text only. No Button, Link,
// NavigationLink, menu, gesture, URL, price, or currency; `ConnectPlanRowTests` reads this block of
// the source and fails on any of them. The texts come from `ConnectPlanRow` (VaultText.swift).

/// The row "Apassy Connect": the plan of the account of this iPhone ("Connect Personal · renews
/// 3 Dec 2026", "Not on Connect", …) and "Managed in Apassy on your Mac", as text.
struct ConnectPlanSection: View {
    @Environment(RootModel.self) private var root
    @State private var status: ConnectStatus?
    @State private var failed = false

    var body: some View {
        let content = ConnectPlanRow.content(status, failed: failed)
        Section {
            VStack(alignment: .leading, spacing: 4) {
                LabeledContent(content.title, value: content.value)
                ForEach(content.lines, id: \.self) { line in
                    Text(verbatim: line)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("general.connect")
        }
        .task { await load() }
    }

    private func load() async {
        // The demo has no account: the row says so and asks nothing.
        guard !root.isDemo, let service = root.vault?.service else {
            status = ConnectStatus(state: .none)
            return
        }
        do {
            status = try await service.connectStatus()
            failed = false
        } catch {
            failed = true
        }
    }
}

// MARK: End of the Apassy Connect row

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
    @State private var autoFillError: String?

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
                    if root.isDemo { root.showNotAvailableInDemo() } else { confirmingRemove = true }
                }
                .disabled(working)
            } header: {
                Text("Vault")
            } footer: {
                Text(
                    vault.vault?.isICloud == true
                        ? "This removes the local vault and stored passphrase. The file in iCloud Drive stays."
                        : "This removes the vault from this iPhone and from the relay. The vault stays on your Macs.")
            }
            Section {
                if let exchange = root.exchange {
                    NavigationLink {
                        CredentialExchangeView(model: exchange, mode: .exporting)
                    } label: {
                        Label("Move to another app", systemImage: "arrow.left.arrow.right")
                    }
                } else if root.isDemo {
                    // The demo moves nothing to or from another app.
                    Button("Move to another app", systemImage: "arrow.left.arrow.right") {
                        root.showNotAvailableInDemo()
                    }
                }
                NavigationLink {
                    DuplicatesView(vault: vault)
                } label: {
                    Label("Find duplicates", systemImage: "square.on.square")
                }
            } header: {
                Text("Import and export")
            } footer: {
                Text(
                    root.isDemo
                        ? "Import, export, and moving to another app are not available in the demo. Find duplicates works on the sample data."
                        : root.exchange == nil
                        ? "Find duplicates merges items that hold the same credential. The others go to the archive."
                        : "Logins, one-time passwords, and passkeys move between Apassy and another app through iOS, after Face ID. To import, start the export in the other app and pick Apassy. Find duplicates merges items that hold the same credential; the others go to the archive."
                )
            }
            if root.isDemo { demoAutoFill } else { autoFill }
        }
        .confirmationDialog(
            "Remove “\(vault.vault?.name ?? "")” from this iPhone?", isPresented: $confirmingRemove,
            titleVisibility: .visible
        ) {
            Button("Remove", role: .destructive) { remove(force: false) }
        } message: {
            Text(
                vault.vault?.isICloud == true
                    ? "This removes the local vault, sync state, and stored passphrase. The file in iCloud Drive stays."
                    : "This removes the vault, sync state, and stored passphrase from this iPhone. Your Macs keep the vault."
            )
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

    /// The demo gives iOS no item, so AutoFill never shows one: nothing to set up.
    private var demoAutoFill: some View {
        Section {
            Text(
                "AutoFill is not available in the demo. The sample items stay inside the app: Safari and other apps never see them."
            )
            .foregroundStyle(.secondary)
        } header: {
            Text("AutoFill")
        }
    }

    private var autoFill: some View {
        Section {
            Text(
                "Apassy can fill your passwords and one-time codes, sign in with passkeys, and save new passkeys in Safari and in apps. Turn on Apassy in Settings > General > AutoFill & Passwords. Using a credential requires an owner check with device authentication or the vault passphrase."
            )
            LabeledContent("AutoFill", value: autoFillOn == nil ? "Checking" : (autoFillOn == true ? "On" : "Off"))
            Button("Open AutoFill settings", systemImage: "gear") {
                Task {
                    do { try await ASSettingsHelper.openCredentialProviderAppSettings() } catch {
                        autoFillError =
                            "AutoFill settings could not open. Open Settings > General > AutoFill & Passwords and turn on Apassy."
                    }
                }
            }
            if let autoFillError {
                Label(autoFillError, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.secondary)
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
