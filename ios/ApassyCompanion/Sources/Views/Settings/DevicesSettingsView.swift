import ApassyVaultDemo
import ApassyVaultKit
import SwiftUI

/// Settings > Devices: the sync of the vault (its state, "Sync now", the devices of the team, a new
/// passphrase, the relay copy), the questions through the relay, the Mac on Wi-Fi (the
/// companion), and Add Apple Watch (ADR 0039) when a watch with Apassy is paired.
///
/// Each route uses the words of `docs/design/devices-settings-mockup.html`: "via your Mac" for a
/// node on the tailnet (a pinned relay), "via Apassy relay", and "Wi-Fi".
struct DevicesSettingsView: View {
    /// Closes the Settings sheet (`dismiss` here would only go back to the root).
    let close: DismissAction
    @Environment(RootModel.self) private var root
    @Environment(VaultUI.self) private var ui: VaultUI?
    @State private var connect: ConnectStatus?

    var body: some View {
        Form {
            if let vault = root.vault, vault.hasVault, vault.isUnlocked {
                SyncSettingsSections(vault: vault)
            }
            Section {
                MacReachRow(connect: connect)
                QuestionsStateRow()
                MacPairingRow()
                if root.isDemo {
                    // The demo pairs nothing: no Mac, no watch, no relay.
                    Button("Pair with a Mac", systemImage: "qrcode.viewfinder") { root.showNotAvailableInDemo() }
                    Button("Add Apple Watch", systemImage: "applewatch") { root.showNotAvailableInDemo() }
                } else {
                    AppleWatchRow()
                }
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
                    root.isDemo
                        ? "In the demo, the questions come from “\(DemoVault.macName)”, a Mac of sample data. Pairing, the relay, and the Apple Watch are not available in the demo."
                        : "Questions via your Mac reach this iPhone on any network while Tailscale is on. Questions via Apassy relay reach it on any network. Runs from the Mac on Wi-Fi show while this iPhone and the Mac are on the same network. All show in Requests."
                )
            }
            if !root.isDemo, ConnectDevicesText.shows(connect) {
                ConnectAccountSection(status: connect) { await loadConnect() }
            }
        }
        .navigationTitle("Devices")
        .navigationBarTitleDisplayMode(.inline)
        .task { if !root.isDemo { AppleWatchLink.shared.activate() } }
        .task {
            // The Connect route shows only when the core reports its dial (plan s7 unit I2).
            guard !root.isDemo else { return }
            await loadConnect()
        }
    }

    private func loadConnect() async {
        connect = try? await root.vault?.service.connectStatus()
    }
}

/// "Apassy Connect" of Settings > Devices (plan s7 unit I3), only while this iPhone is a device of an
/// account (also one that removed it): one quiet line for the devices that this iPhone could not
/// verify, and the one control of the account, "Forget This iPhone…" with a confirmation, which calls
/// `connect_forget`. Leaving an account is no purchase action (plan section 6): no price, no plan
/// choice, and no link here. After it, this iPhone can join an account again.
struct ConnectAccountSection: View {
    let status: ConnectStatus?
    /// Reads `connect_status` again.
    let reload: () async -> Void
    @Environment(RootModel.self) private var root
    @State private var confirming = false
    @State private var working = false
    @State private var failure: String?

    var body: some View {
        Section {
            if status?.removed == true {
                Text(verbatim: ConnectPlanRow.removedLine)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            if let line = ConnectDevicesText.notVerifiedLine(status) {
                Text(verbatim: line)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("devices.connectNotVerified")
            }
            Button(ConnectDevicesText.forgetButton, role: .destructive) { confirming = true }
                .disabled(working)
                .accessibilityIdentifier("devices.connectForget")
            if let failure {
                Text(verbatim: failure).font(.footnote).foregroundStyle(.red)
            }
        } header: {
            Text(verbatim: ConnectDevicesText.header)
        } footer: {
            Text(verbatim: ConnectDevicesText.footer)
        }
        .confirmationDialog(ConnectDevicesText.confirmTitle, isPresented: $confirming, titleVisibility: .visible) {
            Button(ConnectDevicesText.confirmButton, role: .destructive) { forget() }
        } message: {
            Text(verbatim: ConnectDevicesText.confirmMessage(status))
        }
    }

    private func forget() {
        guard let service = root.vault?.service else { return }
        working = true
        Task {
            defer { working = false }
            do {
                _ = try await service.connectForget()
                failure = nil
            } catch {
                failure = ConnectDevicesText.forgetFailed
            }
            await reload()
        }
    }
}

/// "Reaches your Mac through: Tailscale, Apassy Connect, Wi-Fi" (plan s7 unit I1): the routes that
/// reach a Mac now. Apassy Connect shows only when the core reports that it dials through it.
struct MacReachRow: View {
    /// The Connect status of this iPhone (`connect_status`), nil until it is known.
    let connect: ConnectStatus?
    @Environment(RootModel.self) private var root

    var body: some View {
        let questionRoutes = root.questions?.phase == .ready ? (root.questions?.questionRoutes ?? []) : []
        let routes = MacReach.routes(
            vaults: root.vault?.vaults ?? [], questionRoutes: questionRoutes.map(\.route),
            wifiPaired: root.companionIsPaired, connect: connect)
        if let line = MacReach.line(routes) {
            Text(verbatim: line)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("devices.macReach")
        }
        // A quiet state of the dial: no error, no hint (section 5.15).
        if let line = MacReach.dialLine(connect) {
            Text(verbatim: line)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("devices.macReachDial")
        }
    }
}

/// The questions of the vaults: connected or not, and their route. "via your Mac" for a team on a
/// node (the relay inside the Mac app, over Tailscale), with the node's name; "via Apassy relay"
/// else. A node that does not answer adds one quiet line.
struct QuestionsStateRow: View {
    @Environment(RootModel.self) private var root

    var body: some View {
        let routes = root.questions?.phase == .ready ? (root.questions?.questionRoutes ?? []) : []
        let ended = root.questions?.relayEnded == true
        if routes.isEmpty, ended {
            LabeledContent("Questions", value: RelayEndedNotice.value)
        } else if routes.isEmpty {
            LabeledContent("Questions", value: state)
        } else if routes.count == 1, let only = routes.first {
            route(title: "Questions", only.route, words: only.nodeWordsLine)
        } else {
            ForEach(routes) { item in
                route(title: "Questions of “\(item.vault.vaultName)”", item.route, words: item.nodeWordsLine)
            }
        }
        if let line = root.questions?.tailscaleOffLine {
            Text(line)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("devices.tailscaleOff")
        }
        // ADR 0037 D14: the free approvals through the hosted relay end. Text only (3.1). A team
        // on a node is not on the hosted relay.
        if routes.contains(where: { $0.route == .viaApassyRelay }) {
            Text(FreeRelayNotice.questions)
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        // Plan s7 R3: the hosted relay ended them. One calm line: no price, no link (3.1).
        if ended {
            Text(verbatim: RelayEndedNotice.line)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("devices.relayEnded")
        }
    }

    private func route(title: String, _ route: DeviceRoute, words: String? = nil) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            LabeledContent(title, value: route.text)
            if let detail = route.detail {
                Text(detail)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            if let words {
                Text(words)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("devices.questionsRoute")
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

/// The Mac that this iPhone approves runs for on the local network (the companion): "<Mac> on
/// Wi-Fi" with its state. This is the only place that shows the Wi-Fi state (ADR 0028 stage 1).
struct MacPairingRow: View {
    @Environment(RootModel.self) private var root

    var body: some View {
        switch root.companion.phase {
        case .paired(let session):
            VStack(alignment: .leading, spacing: 4) {
                LabeledContent("\(session.macName) on Wi-Fi", value: session.state.wifiText)
                if session.state != .connected, let fetchedAt = session.fetchedAt {
                    Text("Last updated \(fetchedAt.formatted(date: .omitted, time: .shortened))")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("devices.macOnWiFi")
            if session.state != .connected {
                Button("Retry \(session.macName) on Wi-Fi") { Task { await session.refresh() } }
                    .frame(minHeight: 44)
            }
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
                LabeledContent("Sync service", value: Self.serviceText(vault.vault))
                if let entry = vault.vault, let detail = DeviceRoute.of(entry)?.detail {
                    Text(detail)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                if let notice = FreeRelayNotice.relaySyncLine(for: vault.vault) {
                    Text(notice)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
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
            } else if vault.vault?.isNode == true {
                Text(
                    "This vault syncs through the relay inside Apassy on your Mac, over Tailscale. It keeps only an encrypted copy. Turn on Tailscale on this iPhone to sync."
                )
            } else if vault.vault?.isRelay == true {
                Text("This vault syncs through the Apassy relay. The relay keeps only an encrypted copy.")
            }
        }
    }

    /// The value of "Sync service": "iCloud Drive", or the route word of a relay vault.
    static func serviceText(_ entry: VaultEntry?) -> String {
        guard let entry else { return "Apassy relay" }
        if entry.isICloud { return "iCloud Drive" }
        return DeviceRoute.of(entry)?.text ?? "Apassy relay"
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
