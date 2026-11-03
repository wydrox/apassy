import ApassyVaultKit
import Foundation
import Observation

/// The demo of the app ("Try the Demo", `-ApassyDemo YES`): a vault of synthetic data
/// (`DemoData`) with the models of the real screens over it, so every flow runs with simulated
/// outcomes. App Review and new users try the app without a Mac.
///
/// Nothing of the demo leaves this object:
/// - the vault is `PreviewVaultService` in memory: no file, no core, no network, no relay;
/// - the settings and the question choices are in `DemoDefaults`, never the App Group;
/// - no passphrase is stored (`DemoPassphraseStore`), and the answer keys are software keys in
///   memory (`DemoAnswerSigners`): no keychain;
/// - the vault model publishes no AutoFill identity (the hooks do nothing), and no push is set up;
/// - its Face ID checks use a new `LAContext` each, never the Face ID window of the real vaults.
///
/// The app shows it instead of the real vaults, which stay as they are, and drops it on Leave Demo.
@MainActor
@Observable
final class DemoSession {
    /// What the demo may do outside itself: the pasteboard and the owner checks.
    struct System {
        /// Put a fake value on the pasteboard, with the clear time of the demo settings.
        var copy: @MainActor (_ value: String, _ secret: Bool, _ clearAfter: ClearAfter) -> Void
        /// The check before a reveal or a copy (Face ID, else the demo passphrase).
        var ownerCheck: any OwnerCheck
        /// The check before an answer that gives authority (Allow Once): the reason is the one of
        /// the real answer.
        var confirmAnswer: DemoConfirm
    }

    enum Phase: Equatable {
        case starting
        case ready
        case failed(String)
        case ended
    }

    private(set) var phase = Phase.starting
    let vault: VaultModel
    let questions: QuestionsModel
    let agents: AgentsModel
    @ObservationIgnored let service: PreviewVaultService
    @ObservationIgnored let signers: DemoAnswerSigners
    @ObservationIgnored let defaults: DemoDefaults

    init(system: System) {
        let service = PreviewVaultService(
            vaultID: DemoData.vaultID, name: DemoData.vaultName, passphrase: DemoData.passphrase)
        let defaults = DemoDefaults()
        let settings = VaultSettings(defaults: defaults)
        // The demo stays open while the owner looks at AutoFill settings or another app.
        settings.lockAfter = .fifteenMinutes
        settings.deviceName = DemoData.deviceName
        var hooks = VaultModel.Hooks()
        hooks.copy = { [settings] value, secret in system.copy(value, secret, settings.clearAfter) }
        // `replaceIdentities`, `removeAllIdentities`, `endFaceIDWindow`, and
        // `beginBackgroundWork` keep their defaults, which do nothing: the demo never reaches the
        // identity store of AutoFill, nor the Face ID window of the real vaults.
        let vault = VaultModel(
            service: service, settings: settings, gate: OwnerGate(check: system.ownerCheck, service: service),
            passphraseStore: DemoPassphraseStore(), hooks: hooks)
        let signers = DemoAnswerSigners(confirm: system.confirmAnswer)
        let questions = QuestionsModel(
            service: service, signers: signers, push: nil, deviceName: DemoData.deviceName, defaults: defaults,
            onCompanionCode: { _ in DemoText.unavailable })
        questions.follow(vault)
        let agents = AgentsModel(
            service: service, signers: signers,
            registeredKey: { [weak questions] vaultID, team in
                questions?.registeredAnswerKey(vaultID: vaultID, team: team)
            })
        vault.agents = agents
        self.service = service
        self.defaults = defaults
        self.signers = signers
        self.vault = vault
        self.questions = questions
        self.agents = agents
    }

    var isReady: Bool { phase == .ready }

    /// Fill the vault and open it.
    func start() async {
        guard phase == .starting else { return }
        do {
            try await DemoData.seed(service, signers: signers)
        } catch {
            phase = .failed(error.localizedDescription)
            return
        }
        await vault.start()
        guard phase == .starting else { return }
        await questions.refresh()
        await agents.refresh()
        phase = vault.isUnlocked ? .ready : .failed(vault.startError ?? "The demo did not open.")
    }

    /// Leave Demo: lock the vault and drop every value, key, and setting of the demo.
    func end() async {
        guard phase != .ended else { return }
        phase = .ended
        vault.stopSync()
        await vault.lock()
        _ = try? await service.removeVault(id: DemoData.vaultID, force: true)
        signers.removeAll()
        defaults.clear()
    }
}
