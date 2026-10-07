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
        if case .join = screen { return }
        vault.stopSync()
        beforeJoin = screen
        if case .failed = beforeJoin { beforeJoin = .welcome }
        screen = .join(
            JoinModel(
                service: vault.service, passphraseStore: vault.passphraseStore, settings: settings,
                biometry: vault.gate.biometry, deviceName: settings.deviceName ?? DeviceName.current(),
                onFinished: { [weak self] _ in
                    guard let self else { return }
                    Task {
                        await self.vault?.didJoin()
                        self.route()
                    }
                },
                onCancel: { [weak self] in
                    guard let self else { return }
                    screen = beforeJoin
                    if case .welcome = screen { route() }
                    self.vault?.startSync()
                }))
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
    func scenePhaseChanged(_ phase: AppPhase) async {
        guard let vault else { return }
        switch phase {
        case .background: await vault.didEnterBackground()
        case .active: await vault.didBecomeActive()
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

/// Gives iOS the logins for the QuickType bar, one change after the other, without holding up the
/// vault: the identity store of iOS can take long to answer (in the Simulator it sometimes never
/// does), and the list is only a hint.
@MainActor
private final class IdentityPublisher {
    private var last: Task<Void, Never>?

    func replace(_ identities: [CredentialIdentity], vaultID: String) {
        enqueue { await CredentialIdentitySync.replace(with: identities, vaultID: vaultID) }
    }

    func removeAll() {
        enqueue { await CredentialIdentitySync.removeAll() }
    }

    private func enqueue(_ work: @escaping @Sendable () async -> Void) {
        let previous = last
        last = Task.detached {
            await previous?.value
            await work()
        }
    }
}
