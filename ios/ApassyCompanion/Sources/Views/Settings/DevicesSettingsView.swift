import ApassyVaultKit
import SwiftUI

/// Settings > Devices: the sync of the vault (its state, "Sync now", the devices of the team, a new
/// passphrase, the relay copy), the questions through the relay, the Mac on Wi-Fi (the
/// companion), and Add Apple Watch (ADR 0039) when a watch with Apassy is paired.
struct DevicesSettingsView: View {
    /// Closes the Settings sheet (`dismiss` here would only go back to the root).
    let close: DismissAction
    @Environment(RootModel.self) private var root
    @Environment(VaultUI.self) private var ui: VaultUI?

    var body: some View {
        Form {
            if let vault = root.vault, vault.hasVault, vault.isUnlocked {
                SyncSettingsSections(vault: vault)
            }
            Section {
                QuestionsStateRow()
                MacPairingRow()
                AppleWatchRow()
                if let ui {
                    Button("Open Requests", systemImage: "checkmark.circle") {
                        ui.tab = .decisions
                        close()
                    }
                }
            } header: {
                Text("Approve agent runs")
            } footer: {
                Text(
                    "Questions through the relay reach this iPhone on any network. Runs from the Mac on Wi-Fi show while this iPhone and the Mac are on the same network. Both show in Decisions."
                )
            }
        }
        .navigationTitle("Devices")
        .navigationBarTitleDisplayMode(.inline)
        .task { AppleWatchLink.shared.activate() }
    }
}

/// The questions through the relay: connected or not.
struct QuestionsStateRow: View {
    @Environment(RootModel.self) private var root

    var body: some View {
        LabeledContent("Questions through the relay", value: state)
    }

    private var state: String {
        switch root.questions?.phase {
        case .ready?:
            root.questions?.namesVaults == true ? "Connected, \(root.questions?.vaults.count ?? 0) vaults" : "Connected"
        case .locked?: "Locked"
        case .off?: "Not connected"
        case .failed?: "Not available"
        case .loading?, nil: "Checking"
        }
    }
}

/// The paired Apple Watch (ADR 0039): whether Apassy is on it and connected, what it needs when
/// it is not, and Add Apple Watch while it is not connected.
struct AppleWatchRow: View {
    private var watch: AppleWatchLink { .shared }

    var body: some View {
        if watch.isSupported {
            LabeledContent("Apple Watch", value: state)
            if watch.isPaired, !watch.isWatchAppInstalled {
                Text(verbatim: AppleWatchLink.installHint)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            if watch.canAddWatch, !isConnected {
                NavigationLink(value: SettingsView.Page.addAppleWatch) {
                    Label("Add Apple Watch", systemImage: "applewatch")
                }
            }
        }
    }

    private var isConnected: Bool {
        if case .connected = watch.report { true } else { false }
    }

    private var state: String {
        guard watch.isActivated else { return "Checking" }
        guard watch.isPaired else { return "Not paired" }
        guard watch.isWatchAppInstalled else { return "Apassy not installed" }
        switch watch.report {
        case .connected(let vault)?: return vault.isEmpty ? "Connected" : "Connected to “\(vault)”"
        case .removed?: return "Removed by a Mac"
        case .notConnected?, nil: return "Not connected"
        }
    }
}

/// The Mac that this iPhone approves runs for on the local network (the companion).
struct MacPairingRow: View {
    @Environment(RootModel.self) private var root

    var body: some View {
        switch root.companion.phase {
        case .paired(let session):
            LabeledContent("Paired with", value: session.macName)
        default:
            LabeledContent("Mac on Wi-Fi", value: "Not paired")
        }
    }
}

/// The sync sections of an unlocked vault.
private struct SyncSettingsSections: View {
    let vault: VaultModel

    @State private var newPassphrase = ""
    @State private var passphraseError: String?
    @State private var working = false
    @State private var confirmingRelayCopy = false
    @State private var showsICloudPicker = false
    @State private var reconnectModel: ICloudReconnectModel?

    var body: some View {
        Group {
            syncSection
            syncProblem
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
    }

    @ViewBuilder
    private var syncSection: some View {
        Section {
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
                    NavigationLink("Team devices") { DevicesView(vault: vault) }
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
            Text("Sync of “\(vault.vault?.name ?? "")”")
        } footer: {
            if vault.vault?.isICloud == true {
                Text(
                    "Sync through iCloud Drive is free. The iCloud file stays when you remove this local vault."
                )
            } else if vault.vault?.isRelay == true {
                Text("This vault syncs through the Apassy relay. The relay keeps only an encrypted copy.")
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
                Text(
                    "This iPhone does not sync any more. Remove the vault in General, then add it again from the Mac if you need it."
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
            }
        default:
            EmptyView()
        }
    }

    // MARK: Actions

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
}
