import ApassyVaultCore
import ApassyVaultKit
import Foundation
import Observation
import UIKit

/// Which part of the app shows: the welcome, the join flow, the companion alone, or the vault
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
        case addVault
        case iCloud(ICloudVaultModel)
        case join(JoinModel)
        /// No vault: only the approval of agent runs.
        case companion
        /// The lock screen or the tabs of the vault.
        case vault
    }

    private(set) var screen: Screen = .starting
    let companion = AppModel()
    let settings = VaultSettings(defaults: SharedContainer.defaults)
    private(set) var vault: VaultModel?
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
                vault = try makeVault()
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

    /// "Add your vault" on the welcome, and "Add another vault" in Settings.
    func addVault() {
        guard let vault else { return }
        switch screen {
        case .addVault, .iCloud, .join: return
        default: break
        }
        vault.stopSync()
        beforeJoin = screen
        vaultBeforeAdd = vault.vault?.id
        if case .failed = beforeJoin { beforeJoin = .welcome }
        screen = .addVault
    }

    func joinTeam() {
        guard case .addVault = screen, let vault else { return }
        screen = .join(
            JoinModel(
                service: vault.service, passphraseStore: vault.passphraseStore, settings: settings,
                biometry: vault.gate.biometry, deviceName: settings.deviceName ?? DeviceName.current(),
                isAway: { [weak vault] in vault?.isInBackground ?? false },
                onFinished: { [weak self] _ in self?.finishAddVault() },
                onCancel: { [weak self] in self?.cancelAddVault() }))
    }

    func addICloudVault() {
        guard case .addVault = screen, let vault else { return }
        screen = .iCloud(
            ICloudVaultModel(
                service: vault.service, passphraseStore: vault.passphraseStore, settings: settings,
                biometry: vault.gate.biometry,
                isAway: { [weak vault] in vault?.isInBackground ?? false },
                onFinished: { [weak self] _ in self?.finishAddVault() },
                onCancel: { [weak self] in self?.cancelAddVault() }))
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

    /// "Only approve agent runs" on the welcome.
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
            if case .iCloud(let model) = screen { model.enterBackground() }
            vault.enterBackground()
        case .active:
            if case .iCloud(let model) = screen { model.enterForeground() }
            vault.enterForeground()
        case .inactive: break
        }
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

/// Gives iOS the logins for the QuickType bar without holding up the vault: the identity store
/// of iOS can take long to answer (in the Simulator it sometimes never does), and the list is only
/// a hint. The latest request wins: a request that a newer one overtook while it waited is
/// skipped, a call that does not end holds up the next one for 10 s at most, and a removal never
/// waits, so usernames leave iOS when the vault leaves this iPhone.
@MainActor
private final class IdentityPublisher {
    private var generation = 0
    /// The request whose call to iOS runs now.
    private var running: Int?

    func replace(_ identities: [CredentialIdentity], vaultID: String) {
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
