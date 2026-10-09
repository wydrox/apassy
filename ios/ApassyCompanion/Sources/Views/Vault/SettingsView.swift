import ApassyVaultKit
import AuthenticationServices
import SwiftUI

/// Settings: the vault and its sync, security, AutoFill, the approval of runs, and about.
struct SettingsView: View {
    @Environment(RootModel.self) private var root
    @Environment(VaultUI.self) private var ui: VaultUI?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                if let vault = root.vault, vault.hasVault, vault.isUnlocked {
                    VaultSettingsSections(vault: vault)
                } else {
                    Section {
                        Text("No vault is on this iPhone. Add the vault of your Mac to see your logins and keys here.")
                        Button("Add your vault", systemImage: "plus") {
                            dismiss()
                            root.addVault()
                        }
                    } header: {
                        Text("Vault")
                    }
                }
                approvals
                about
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private var approvals: some View {
        Section {
            switch root.companion.phase {
            case .paired(let session):
                LabeledContent("Paired with", value: session.macName)
            default:
                LabeledContent("Approvals", value: "Not paired")
            }
            if let ui {
                Button("Open Approvals", systemImage: "checkmark.seal") {
                    ui.tab = .approvals
                    dismiss()
                }
            }
        } header: {
            Text("Approve agent runs")
        } footer: {
            Text("Runs that wait on your Mac show in Approvals while this iPhone and the Mac are on the same network.")
        }
    }

    private var about: some View {
        Section {
            LabeledContent("Apassy", value: appVersion)
            if let info = root.vault?.info {
                LabeledContent("Vault core", value: "\(info.version), schema \(info.schema)")
            }
            NavigationLink("Licenses") { LicensesView() }
        } header: {
            Text("About")
        } footer: {
            Text(
                "The vault is encrypted on this iPhone with your passphrase. Apassy keeps no copy of the passphrase except behind Face ID, if you turn it on."
            )
        }
    }

    private var appVersion: String {
        let short = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        return "\(short) (\(build))"
    }
}

/// The sections of an unlocked vault.
private struct VaultSettingsSections: View {
    let vault: VaultModel
    @Environment(RootModel.self) private var root
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase

    @State private var newPassphrase = ""
    @State private var passphraseError: String?
    @State private var working = false
    @State private var confirmingRelayCopy = false
    @State private var confirmingRemove = false
    @State private var removeError: VaultError?
    @State private var askingFaceIDPassphrase = false
    @State private var faceIDPassphrase = ""
    @State private var faceIDError: String?
    @State private var autoFillOn: Bool?
    @State private var showsICloudPicker = false
    @State private var reconnectModel: ICloudReconnectModel?

    var body: some View {
        @Bindable var settings = vault.settings
        Group {
            vaultSection
            syncProblem
            Section {
                Button("Add another vault", systemImage: "plus") {
                    dismiss()
                    root.addVault()
                }
                Button("Remove “\(vault.vault?.name ?? "")” from this iPhone", role: .destructive) {
                    confirmingRemove = true
                }
                .disabled(working)
            } footer: {
                Text(vault.vault?.isICloud == true
                    ? "This removes the local vault and stored passphrase. The file in iCloud Drive stays."
                    : "This removes the vault from this iPhone and from the relay. The vault stays on your Macs.")
            }
            Section("Security") {
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
                Picker("Clear copied secrets after", selection: $settings.clearAfter) {
                    ForEach(ClearAfter.allCases) { Text($0.label).tag($0) }
                }
                if let faceIDError {
                    Text(faceIDError)
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
                Button("Lock now", systemImage: "lock") {
                    dismiss()
                    Task { await vault.lock() }
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
        .sheet(isPresented: $showsICloudPicker) {
            ICloudVaultFilePicker { url in
                showsICloudPicker = false
                guard let url, let reconnectModel else { return }
                Task {
                    vault.stopSync()
                    if await reconnectModel.reconnect(url) {
                        await vault.didJoin()
                    }
                    vault.startSync()
                }
            }
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
        .alert("Turn on \(vault.gate.biometry.name)", isPresented: $askingFaceIDPassphrase) {
            SecureField("Passphrase", text: $faceIDPassphrase)
            Button("Cancel", role: .cancel) { faceIDPassphrase = "" }
            Button("Turn On") { enableFaceID() }
        } message: {
            Text("Type the passphrase of “\(vault.vault?.name ?? "")”. Apassy keeps it behind \(vault.gate.biometry.name) on this iPhone.")
        }
    }

    // MARK: Vault and sync

    @ViewBuilder
    private var vaultSection: some View {
        Section {
            if vault.vaults.count > 1 {
                Picker(
                    "Vault",
                    selection: Binding(
                        get: { vault.vault?.id ?? "" },
                        set: { id in
                            dismiss()
                            Task { await vault.select(vaultID: id) }
                        })
                ) {
                    ForEach(vault.vaults) { Text($0.name).tag($0.id) }
                }
            } else {
                LabeledContent("Name", value: vault.vault?.name ?? "")
            }
            if vault.vault?.syncs == true {
                LabeledContent("Sync service", value: vault.vault?.isICloud == true ? "iCloud Drive" : "Apassy relay")
                LabeledContent("Sync") {
                    Text(vault.syncStatus?.message ?? "Not synced yet")
                        .multilineTextAlignment(.trailing)
                }
                LabeledContent("Last sync") {
                    if let date = VaultText.date(vault.syncStatus?.lastSyncAt) {
                        Text(date, format: .relative(presentation: .named))
                    } else {
                        Text("Never")
                    }
                }
                Button {
                    Task { await vault.syncNow() }
                } label: {
                    HStack {
                        Label("Sync now", systemImage: "arrow.triangle.2.circlepath")
                        if vault.isSyncing {
                            Spacer()
                            ProgressView()
                        }
                    }
                }
                .disabled(vault.isSyncing)
                if vault.vault?.isRelay == true {
                    NavigationLink("Devices") { DevicesView(vault: vault) }
                }
                if vault.vault?.isICloud == true {
                    Button("Select the iCloud file again", systemImage: "icloud") {
                        guard let entry = vault.vault else { return }
                        if reconnectModel == nil {
                            reconnectModel = ICloudReconnectModel(service: vault.service, vaultID: entry.id)
                        }
                        showsICloudPicker = true
                    }
                    .disabled(reconnectModel?.isWorking == true)
                    Text("If sync cannot find the file, select the same .apassy file in Files > iCloud Drive > Apassy.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    if let message = reconnectModel?.message {
                        Text(message).font(.footnote).foregroundStyle(.red)
                    }
                }
            } else {
                Text("This vault is only on this iPhone.")
                    .foregroundStyle(.secondary)
            }
        } header: {
            Text("Vault")
        } footer: {
            if vault.vault?.isICloud == true {
                Text("Personal sync through iCloud Drive is free. The iCloud file stays when you remove this local vault.")
            } else if vault.vault?.isRelay == true {
                Text("Team sync uses the Apassy relay.")
            }
        }
    }

    @ViewBuilder
    private var syncProblem: some View {
        switch (vault.syncStatus?.state, vault.vault?.isRelay == true) {
        case (.needsPassphrase?, _):
            Section {
                Text("Type the new passphrase of “\(vault.vault?.name ?? "")” to go on syncing.")
                SecureField("New passphrase", text: $newPassphrase)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                if let passphraseError {
                    Text(passphraseError).font(.footnote).foregroundStyle(.red)
                }
                Button("Use the new passphrase") { takeNewPassphrase() }
                    .disabled(newPassphrase.isEmpty || working)
            } header: {
                Text("The passphrase changed on a Mac")
            }
        case (.staleCopy?, true), (.forkedCopy?, true):
            Section {
                Text(
                    vault.syncStatus?.state == .staleCopy
                        ? "The relay serves an older copy of the vault than this iPhone saw. A Mac may have restored a backup."
                        : "The copy on the relay does not have the last change of this iPhone. Another device may have replaced it."
                )
                Button("Use the relay copy") { confirmingRelayCopy = true }
                    .disabled(working)
                if let passphraseError {
                    Text(passphraseError).font(.footnote).foregroundStyle(.red)
                }
            } header: {
                Text("The relay copy differs")
            } footer: {
                Text("Changes on this iPhone that are not in the relay copy are lost.")
            }
            .confirmationDialog("Use the relay copy?", isPresented: $confirmingRelayCopy, titleVisibility: .visible) {
                Button("Use the relay copy", role: .destructive) { useRelayCopy() }
            } message: {
                Text("This iPhone takes the copy on the relay. Its own changes that are not in that copy are lost.")
            }
        case (.removed?, true):
            Section {
                Label("A Mac removed this iPhone from the vault.", systemImage: "iphone.slash")
                Text("This iPhone does not sync any more. Remove the vault here, then add it again from the Mac if you need it.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        default:
            EmptyView()
        }
    }

    // MARK: AutoFill

    private var autoFill: some View {
        Section {
            Text(
                "Apassy can fill your passwords in Safari and in apps. Turn on Apassy in Settings > General > AutoFill & Passwords. Each fill asks for Face ID."
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
                dismiss()
                root.didRemoveVault()
            } catch let error as VaultError where !force && (error.code == .relayUnreachable || error.code == .locked) {
                removeError = error
            } catch {
                vault.alert = error.localizedDescription
            }
        }
    }

    private func takeNewPassphrase() {
        let typed = newPassphrase
        newPassphrase = ""
        working = true
        Task {
            defer { working = false }
            do {
                try await vault.takeNewPassphrase(typed)
                passphraseError = nil
            } catch {
                passphraseError = error.localizedDescription
            }
        }
    }

    private func useRelayCopy() {
        working = true
        Task {
            defer { working = false }
            do {
                try await vault.useRelayCopy()
                passphraseError = nil
            } catch {
                passphraseError = error.localizedDescription
            }
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

/// The devices of the relay team of the vault.
struct DevicesView: View {
    let vault: VaultModel
    @State private var devices: [RelayDevice]?
    @State private var error: String?

    var body: some View {
        Group {
            if let devices {
                List(devices) { device in
                    HStack(spacing: 12) {
                        Image(systemName: device.this ? "iphone" : "desktopcomputer")
                            .foregroundStyle(.tint)
                            .frame(width: 28)
                            .accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(device.name)
                            if device.this {
                                Text("This iPhone")
                                    .font(.footnote)
                                    .foregroundStyle(.secondary)
                            } else if let date = VaultText.date(device.lastSeenAt) {
                                Text("Seen \(date, format: .relative(presentation: .named))")
                                    .font(.footnote)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    .accessibilityElement(children: .combine)
                }
            } else if let error {
                ContentUnavailableView {
                    Label("The relay did not answer", systemImage: "wifi.exclamationmark")
                } description: {
                    Text(error)
                } actions: {
                    Button("Try again") { Task { await load() } }
                        .buttonStyle(.bordered)
                }
            } else {
                ProgressView()
            }
        }
        .navigationTitle("Devices")
        .task { await load() }
        .refreshable { await load() }
    }

    private func load() async {
        do {
            devices = try await vault.devices()
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }
}
