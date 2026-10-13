import ApassyVaultCore
import ApassyVaultKit
import AuthenticationServices
import Foundation
import Observation
import UIKit

/// Which part of the app shows: the welcome, the connect flow, the companion alone, or the vault
/// (its lock screen or its tabs). It owns the vault model and the companion model.
@MainActor
@Observable
final class RootModel {
    enum Screen {
        case starting
        /// The vault core could not start: no App Group, or the core failed.
        case failed(String)
        /// No vault and no pairing.
        case welcome
        /// "Connect to your Mac": the code of the Mac decides what comes (`ConnectModel`).
        case connect(ConnectModel)
        /// No vault: only the approval of agent runs on this Wi-Fi.
        case companion
        /// The lock screen or the tabs of the vault.
        case vault
    }

    private(set) var screen: Screen = .starting
    let companion = AppModel()
    let settings = VaultSettings(defaults: SharedContainer.defaults)
    private(set) var vault: VaultModel?
    /// Questions through the relay of the selected vault (contract relay-questions-v1).
    private(set) var questions: QuestionsModel?
    /// The owner opened the notification of a question: the vault tabs show Questions.
    var questionsRequested = false
    /// Imports from and exports to another app (Apple's credential exchange).
    private(set) var exchange: CredentialExchangeModel?
    /// An import token that arrived before the vault model existed (a cold start).
    @ObservationIgnored private var earlyImportToken: UUID?
    /// Where Cancel of the join flow goes back to.
    @ObservationIgnored private var beforeJoin: Screen = .welcome
    @ObservationIgnored private var vaultBeforeAdd: String?

    var companionIsPaired: Bool {
        if case .paired = companion.phase { return true }
        return false
    }

    // MARK: Start

    func start() async {
        if case .starting = companion.phase { companion.start() }
        if vault == nil {
            do {
                let made = try makeVault()
                vault = made
                exchange = CredentialExchangeModel(vault: made, system: Self.exchangeSystem())
                makeQuestions(service: made.service)
                if let token = earlyImportToken {
                    earlyImportToken = nil
                    exchange?.receive(token: token)
                }
            } catch {
                screen = .failed(error.localizedDescription)
                return
            }
        }
        guard let vault else { return }
        await vault.start()
        if let error = vault.startError {
            screen = .failed(error)
            return
        }
        route()
    }

    /// Show the vault when there is one, else the companion when it is paired, else the welcome.
    func route() {
        if vault?.hasVault == true {
            screen = .vault
        } else if companionIsPaired {
            screen = .companion
        } else {
            screen = .welcome
        }
    }

    // MARK: Actions

    /// "Connect to your Mac" and "Paste a link instead" on the welcome, "Add another vault" in
    /// Settings, and "Open your vault from iCloud Drive" in Settings > Devices.
    func connect(_ start: ConnectModel.Start = .scan) {
        guard let vault else { return }
        if case .connect = screen { return }
        vault.stopSync()
        beforeJoin = screen
        vaultBeforeAdd = vault.vault?.id
        if case .failed = beforeJoin { beforeJoin = .welcome }
        screen = .connect(
            makeConnect(
                vault: vault, start: start, attachesSelectedVault: false,
                onFinished: { [weak self] _ in self?.finishAddVault() },
                onCancel: { [weak self] in self?.cancelAddVault() }))
    }

    /// "Connect to your Mac" for the vault that is open (Decisions, Settings > Devices): it joins
    /// the notifications team of the Mac. The caller shows the flow in a sheet and closes it at the end.
    func connectSelectedVault(onEnd: @escaping @MainActor () -> Void) -> ConnectModel? {
        guard let vault, vault.hasVault, vault.isUnlocked else { return nil }
        return makeConnect(
            vault: vault, start: .scan, attachesSelectedVault: true, onFinished: { _ in onEnd() },
            onCancel: { onEnd() })
    }

    private func makeConnect(
        vault: VaultModel, start: ConnectModel.Start, attachesSelectedVault: Bool,
        onFinished: @escaping @MainActor (VaultEntry?) -> Void, onCancel: @escaping @MainActor () -> Void
    ) -> ConnectModel {
        let companion = companion
        return ConnectModel(
            start: start, attachesSelectedVault: attachesSelectedVault,
            selectedVaultName: attachesSelectedVault ? vault.vault?.name : nil, service: vault.service,
            passphraseStore: vault.passphraseStore, settings: settings, biometry: vault.gate.biometry,
            deviceName: settings.deviceName ?? DeviceName.current(), questions: questions,
            isAway: { [weak vault] in vault?.isInBackground ?? false },
            answerKey: { try EnclaveAnswerSigner().publicKey() },
            pairing: {
                switch companion.phase {
                case .pairing(let model): return .ready(model)
                case .paired: return .paired
                case .loadFailed(let message): return .unavailable(message)
                case .starting: return .unavailable("Apassy is still reading the pairing of this iPhone. Try again.")
                }
            },
            onFinished: onFinished, onCancel: onCancel)
    }

    private func finishAddVault() {
        Task {
            await vault?.didJoin()
            route()
        }
    }

    func cancelAddVault() {
        Task {
            if let id = vaultBeforeAdd { try? await vault?.service.select(vaultID: id) }
            await vault?.didJoin()
            screen = beforeJoin
            if vault?.hasVault == true || companionIsPaired { route() }
            vault?.startSync()
        }
    }

    /// "Pair on this network" when the vault core cannot start: the approval of runs on this Wi-Fi.
    func approveOnly() {
        screen = .companion
    }

    /// The vault left this iPhone: the next vault, the companion, or the welcome.
    func didRemoveVault() {
        route()
    }

    /// The scene phase changed: the vault closes in the background and opens again on return.
    /// Synchronous, so the vault knows at once that the app is away, before anything awaits.
    func scenePhaseChanged(_ phase: AppPhase) {
        guard let vault else { return }
        switch phase {
        case .background:
            if case .connect(let model) = screen { model.enterBackground() }
            vault.enterBackground()
        case .active:
            if case .connect(let model) = screen { model.enterForeground() }
            vault.enterForeground()
        case .inactive: break
        }
    }

    // MARK: Credential exchange

    /// iOS opened Apassy to import what another app exports. The import waits for the unlock and
    /// the owner check; the token alone reads nothing.
    func receiveCredentialExchange(_ activity: NSUserActivity) {
        guard activity.activityType == ASCredentialExchangeActivity,
            let token = activity.userInfo?[ASCredentialImportToken] as? UUID
        else { return }
        if let exchange {
            exchange.receive(token: token)
        } else {
            earlyImportToken = token
        }
    }

    /// The managers of the system. The export keeps one manager from the sheet to the hand-off.
    private static func exchangeSystem() -> CredentialExchangeModel.System {
        let session = ExportSession()
        return CredentialExchangeModel.System(
            importCredentials: { token in try await ASCredentialImportManager().importCredentials(token: token) },
            requestExport: { try await session.request() },
            exportCredentials: { data in try await session.send(data) })
    }

    // MARK: Questions

    private func makeQuestions(service: any VaultService) {
        let push = PushRegistrar.shared
        let model = QuestionsModel(
            service: service, signer: EnclaveAnswerSigner(), push: push,
            deviceName: settings.deviceName ?? DeviceName.current(), defaults: SharedContainer.defaults)
        questions = model
        push.onToken = { [weak model] token in
            Task { await model?.receivePushToken(token) }
        }
        push.onOpen = { [weak self] in self?.questionsRequested = true }
    }

    // MARK: The service

    private func makeVault() throws -> VaultModel {
        let service = try makeService()
        let settings = settings
        let gate = OwnerGate(check: PromptTrackingOwnerCheck(inner: BiometricOwnerCheck()), service: service)
        var hooks = VaultModel.Hooks()
        hooks.copy = { value, secret in
            SecureClipboard.copy(value, secret: secret, seconds: settings.clearAfter.seconds)
            Toast.shared.show(secret ? "Copied. Clears in \(settings.clearAfter.label)." : "Copied")
        }
        let publisher = IdentityPublisher()
        hooks.replaceIdentities = { identities, vaultID in publisher.replace(identities, vaultID: vaultID) }
        hooks.removeAllIdentities = { publisher.removeAll() }
        hooks.beginBackgroundWork = { BackgroundWork.begin($0) }
        return VaultModel(
            service: service, settings: settings, gate: gate,
            passphraseStore: PromptTrackingPassphraseStore(inner: KeychainPassphraseStore()), hooks: hooks)
    }

    private func makeService() throws -> any VaultService {
        #if targetEnvironment(simulator)
            // Development aids of the Simulator: a vault of synthetic data in memory. The AutoFill
            // extension reads the flag and uses the same synthetic data.
            let arguments = ProcessInfo.processInfo.arguments
            let preview = arguments.contains("-ApassyPreviewVault")
            let empty = arguments.contains("-ApassyPreviewEmpty")
            SharedContainer.defaults.set(preview || empty, forKey: "ApassyPreviewVault")
            if empty { return PreviewVaultService(empty: true) }
            if preview {
                return PreviewVaultService(empty: false, unlocked: arguments.contains("-ApassyPreviewUnlocked"))
            }
        #endif
        guard let directory = SharedContainer.dataDirectory() else {
            throw VaultError(
                .io, "Apassy cannot open its data folder on this iPhone: the App Group of the app is missing.")
        }
        return try CoreVaultService(
            dataDirectory: directory, deviceName: settings.deviceName ?? DeviceName.current(), role: .app)
    }
}

/// Gives iOS the logins, passkeys, and one-time passwords for AutoFill without holding up the vault: the identity store
/// of iOS can take long to answer (in the Simulator it sometimes never does), and the list is only
/// a hint. The latest request wins: a request that a newer one overtook while it waited is
/// skipped, a call that does not end holds up the next one for 10 s at most, and a removal never
/// waits, so usernames leave iOS when the vault leaves this iPhone.
@MainActor
private final class IdentityPublisher {
    private var generation = 0
    /// The request whose call to iOS runs now.
    private var running: Int?

    func replace(_ identities: IdentitySet, vaultID: String) {
        submit(waits: true) { await CredentialIdentitySync.replace(with: identities, vaultID: vaultID) }
    }

    func removeAll() {
        submit(waits: false) { await CredentialIdentitySync.removeAll() }
    }

    private func submit(waits: Bool, _ work: @escaping @Sendable () async -> Void) {
        generation += 1
        let mine = generation
        Task { [weak self] in
            guard let self else { return }
            var waited = 0
            while waits, running != nil, waited < 100 {
                try? await Task.sleep(for: .milliseconds(100))
                waited += 1
            }
            guard mine == generation else { return }
            running = mine
            await work()
            if running == mine { running = nil }
        }
    }
}

/// One export of the credential exchange: the sheet of the system, then the hand-off with the same
/// manager. Apassy has one AutoFill extension, so the manager exports for it.
@MainActor
private final class ExportSession {
    /// The manager is not Sendable, and its calls are not isolated. One export uses it from one
    /// task, one call after the other, so it never runs two calls at once.
    private struct Manager: @unchecked Sendable {
        let manager: ASCredentialExportManager
    }

    private var current: Manager?

    func request() async throws -> ASExportedCredentialData.FormatVersion {
        guard let window = Self.window() else { throw VaultError(.internal, "Apassy has no window to show the export in.") }
        let manager = Manager(manager: ASCredentialExportManager(presentationAnchor: window))
        current = manager
        return try await Self.request(manager, extensionID: Bundle.main.bundleIdentifier.map { $0 + ".autofill" })
    }

    func send(_ data: ASExportedCredentialData) async throws {
        guard let manager = current else { throw VaultError(.internal, "The export was not started.") }
        defer { current = nil }
        try await Self.send(manager, data)
    }

    private nonisolated static func request(_ box: Manager, extensionID: String?) async throws
        -> ASExportedCredentialData.FormatVersion
    {
        try await box.manager.requestExport(for: extensionID).formatVersion
    }

    private nonisolated static func send(_ box: Manager, _ data: ASExportedCredentialData) async throws {
        try await box.manager.exportCredentials(data)
    }

    private static func window() -> UIWindow? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        let windows = scenes.flatMap(\.windows)
        return windows.first(where: \.isKeyWindow) ?? windows.first
    }
}
