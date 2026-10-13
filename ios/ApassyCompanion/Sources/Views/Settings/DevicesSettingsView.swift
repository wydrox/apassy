import ApassyVaultKit
import SwiftUI

/// Settings > Devices (flow spec I3): what this iPhone does (it approves, and how the vault
/// syncs), the plan when the Mac wrote one, the sync of the vault (its state, "Sync now", the
/// devices, a new passphrase, the relay copy), and "Pair on this network" for a Mac on this Wi-Fi.
struct DevicesSettingsView: View {
    /// Closes the Settings sheet (`dismiss` here would only go back to the root).
    let close: DismissAction
    @Environment(RootModel.self) private var root
    @Environment(VaultUI.self) private var ui: VaultUI?
    @State private var showsConnect = false
    @State private var showsPairing = false

    private var openVault: VaultModel? {
        guard let vault = root.vault, vault.hasVault, vault.isUnlocked else { return nil }
        return vault
    }

    var body: some View {
        ScrollViewReader { proxy in
            form
            #if targetEnvironment(simulator)
                .task { await seedFromLaunchArgument(proxy) }
            #endif
        }
    }

    private var form: some View {
        Form {
            Section {
                ThisIPhoneRow()
                VaultSyncRow()
                if let plan = openVault?.planSummary {
                    PlanRow(summary: plan)
                }
                if root.questions?.phase != .ready {
                    if openVault != nil {
                        Button("Connect to your Mac", systemImage: "qrcode.viewfinder") { showsConnect = true }
                    } else if root.vault?.hasVault != true {
                        Button("Open your vault from iCloud Drive", systemImage: "icloud") {
                            close()
                            root.connect(.openVault)
                        }
                    }
                }
                if let ui {
                    Button("Open Decisions", systemImage: "checkmark.circle") {
                        ui.tab = .decisions
                        close()
                    }
                }
            } footer: {
                Text(
                    "Each question goes to every device. The first answer counts. Apassy Connect sees no command and no credential."
                )
            }
            if let vault = openVault {
                SyncSettingsSections(vault: vault)
            }
            Section {
                Button {
                    showsPairing = true
                } label: {
                    DeviceStatusRow(
                        symbol: "wifi", title: "Pair on this network", detail: pairingDetail, tint: .gray)
                }
                .tint(.primary)
            } header: {
                Text("Advanced")
                    .id("advanced")
            } footer: {
                Text("For a Mac on the same Wi-Fi as this iPhone, without Apassy Connect. Runs show in Decisions while both are on that network.")
            }
        }
        .navigationTitle("Devices")
        .navigationBarTitleDisplayMode(.inline)
        // A swipe down ends a connection that waits for the Mac.
        .sheet(isPresented: $showsConnect, onDismiss: { root.questions?.cancelAttach() }) {
            ConnectSheet().environment(root)
        }
        .sheet(isPresented: $showsPairing) {
            ApprovalsView(app: root.companion)
                .presentationDragIndicator(.visible)
                .environment(root)
        }
    }

    private var pairingDetail: String {
        if case .paired(let session) = root.companion.phase { return "Paired with \(session.macName)" }
        return "Not paired"
    }

    #if targetEnvironment(simulator)
        /// Development aids: `-ApassyOpen settings:devices:advanced` scrolls to Advanced; with
        /// `-ApassyPreviewVault -ApassyPreviewDecisions list`, the preview vault is connected to the
        /// questions of its Mac, as after "Connect to your Mac".
        private func seedFromLaunchArgument(_ proxy: ScrollViewProxy) async {
            if UserDefaults.standard.string(forKey: "ApassyOpen") == "settings:devices:advanced" {
                try? await Task.sleep(for: .milliseconds(500))
                proxy.scrollTo("advanced", anchor: .top)
            }
            guard UserDefaults.standard.string(forKey: "ApassyPreviewDecisions") != nil,
                let service = root.vault?.service as? PreviewVaultService, let questions = root.questions
            else { return }
            await service.setQuestions(enabled: true, questions: [])
            await questions.refresh()
        }
    #endif
}

/// A row of Devices: a symbol in a tile, a title, and one line of what it does.
struct DeviceStatusRow: View {
    let symbol: String
    let title: String
    let detail: String
    var tint: Color = .blue
    @ScaledMetric(relativeTo: .body) private var side: CGFloat = 30

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: side * 0.5, weight: .medium))
                .foregroundStyle(.white)
                .frame(width: side, height: side)
                .background(tint.gradient, in: .rect(cornerRadius: side * 0.27, style: .continuous))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(detail)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// This iPhone: how it approves, and whether the questions of the Mac reach it.
struct ThisIPhoneRow: View {
    @Environment(RootModel.self) private var root

    var body: some View {
        DeviceStatusRow(symbol: "iphone", title: "This iPhone", detail: detail, tint: connected ? .green : .gray)
    }

    private var connected: Bool { root.questions?.phase == .ready }

    private var detail: String {
        let biometry = root.vault?.gate.biometry ?? .none
        let approves = biometry == .none ? "Needs Face ID to approve" : "Approves with \(biometry.name)"
        switch root.questions?.phase {
        case .ready?:
            return "\(approves) · Connected"
        case .failed?:
            return "\(approves) · Not available"
        case .loading?:
            return "\(approves) · Checking"
        case .off?, nil:
            if case .paired(let session) = root.companion.phase {
                return "\(approves) · On this Wi-Fi with \(session.macName)"
            }
            return "\(approves) · Not connected"
        }
    }
}

/// How the vault reaches this iPhone.
struct VaultSyncRow: View {
    @Environment(RootModel.self) private var root

    var body: some View {
        DeviceStatusRow(symbol: symbol, title: title, detail: detail)
    }

    private var entry: VaultEntry? {
        guard let vault = root.vault, vault.hasVault else { return nil }
        return vault.vault
    }

    private var title: String {
        guard let entry else { return "Vault" }
        return "Vault “\(entry.name)”"
    }

    private var symbol: String {
        if entry?.isICloud == true { return "icloud.fill" }
        if entry?.isRelay == true { return "arrow.triangle.2.circlepath" }
        return "lock.fill"
    }

    private var detail: String {
        guard let entry else { return "Not on this iPhone" }
        if entry.isICloud { return "Syncs through iCloud Drive" }
        if entry.isRelay { return "Syncs through Apassy" }
        return "Only on this iPhone"
    }
}

/// The plan that the Mac wrote into the vault. There is no purchase on the iPhone (ADR 0027).
struct PlanRow: View {
    let summary: PlanSummary

    var body: some View {
        DeviceStatusRow(symbol: "person.crop.circle", title: "Plan: \(summary.plan)", detail: detail, tint: .gray)
    }

    private var detail: String {
        if let date = VaultText.date(summary.renewsAt) {
            return "Renews \(date.formatted(date: .abbreviated, time: .omitted)) · Change it on your Mac"
        }
        return "Change it on your Mac"
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
            Text("Sync of “\(vault.vault?.name ?? "")”")
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
                Text("This iPhone does not sync any more. Remove the vault in General, then add it again from the Mac if you need it.")
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
