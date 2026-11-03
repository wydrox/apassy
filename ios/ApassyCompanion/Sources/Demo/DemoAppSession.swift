import ApassyCompanionKit
import ApassyVaultDemo
import ApassyVaultKit
import Foundation
import LocalAuthentication

/// What a vault session of the app touches outside its memory: the vault core over the App Group
/// folder (and the relay), the App Group defaults, the keychain, the AutoFill identity store of
/// iOS, the push registration, and the pasteboard. `RootModel` builds the real vault from it. The
/// demo gets it too and uses only the pasteboard: a copy of a fake value is part of the demo. The
/// model tests pass a world that fails on every other call.
@MainActor
protocol AppWorld: AnyObject {
    /// Put a value on the pasteboard, cleared after `clearAfter` when `secret`.
    func copy(_ value: String, secret: Bool, clearAfter: ClearAfter)
    /// The vault core over the App Group folder.
    func makeCoreService(deviceName: String?) throws -> any VaultService
    /// The App Group defaults, shared with the AutoFill extension.
    func sharedSettings() -> any SettingsStore
    /// The passphrases behind Face ID in the keychain.
    func keychainPassphraseStore() -> any PassphraseStore
    /// The answer keys in the keychain (the Secure Enclave on a device).
    func keychainAnswerKeyStore() -> any AnswerKeyStore
    /// Give iOS the AutoFill identities of a vault (`ASCredentialIdentityStore`).
    func replaceIdentities(_ identities: IdentitySet, vaultID: String) async
    /// Remove every AutoFill identity.
    func removeAllIdentities() async
    /// The notification permission and the APNs registration.
    func pushPermission() -> any PushPermission
    /// End the Face ID window of the app (its frequency is a keychain item).
    func endFaceIDWindow()
}

/// The models of the demo ("Try the Demo", `-ApassyDemo`): the vault, its questions, and its
/// agents over the in-memory `DemoSession`, with the same screens as a real vault. Settings,
/// passphrases, and answer keys stay in memory; no AutoFill identity is given to iOS; no push is
/// registered; no request leaves the app. Drop the object to leave the demo.
@MainActor
final class DemoAppSession {
    let demo: DemoSession
    let settings: VaultSettings
    let answerSigners: DemoAnswerSigners
    let vault: VaultModel
    let questions: QuestionsModel
    let agents: AgentsModel
    /// Held here: `QuestionsModel` keeps its push permission weakly.
    let push: DemoPush

    /// - Parameters:
    ///   - world: the app; the demo calls only its pasteboard.
    ///   - ownerCheck: the check before a reveal or a copy (the app passes Face ID).
    ///   - confirm: the Face ID check of an Allow Once, an answer, and a read of the stored
    ///     passphrase. The app passes the real prompt with the same reason text.
    ///   - canUseFaceID: whether Allow Once is offered (Face ID is set up on this iPhone).
    ///   - notAvailable: shows "Not available in the demo".
    init(
        demo: DemoSession, world: any AppWorld, ownerCheck: any OwnerCheck,
        confirm: @escaping @Sendable (String) async -> Bool, canUseFaceID: @escaping @Sendable () -> Bool = { true },
        notAvailable: @escaping @MainActor () -> Void = {}, timing: VaultModel.Timing = VaultModel.Timing()
    ) {
        self.demo = demo
        let settings = VaultSettings(defaults: demo.settings)
        self.settings = settings
        let signers = DemoAnswerSigners(key: demo.answerKey, confirm: confirm, canUseFaceID: canUseFaceID)
        answerSigners = signers
        var hooks = VaultModel.Hooks()
        hooks.copy = { [weak world, weak settings] value, secret in
            world?.copy(value, secret: secret, clearAfter: settings?.clearAfter ?? .oneMinute)
        }
        let vault = VaultModel(
            service: demo.service, settings: settings,
            gate: OwnerGate(check: ownerCheck, service: demo.service, passphraseHint: DemoAppSession.passphraseHint),
            passphraseStore: demo.passphraseStore, hooks: hooks, timing: timing)
        self.vault = vault
        let push = DemoPush(notAvailable: notAvailable)
        self.push = push
        let questions = QuestionsModel(
            service: demo.service, signers: signers, push: push, deviceName: settings.deviceName ?? "iPhone (demo)",
            defaults: demo.settings,
            onCompanionCode: { _ in DemoAppSession.notAvailableText },
            onDeviceName: { [weak settings] name in settings?.deviceName = name })
        questions.follow(vault)
        self.questions = questions
        let agents = AgentsModel(
            service: demo.service, signers: signers,
            registeredKey: { [weak questions] vaultID, team in questions?.registeredAnswerKey(vaultID: vaultID, team: team) },
            keys: questions.agentKeys)
        vault.agents = agents
        self.agents = agents
    }

    /// The text of an action that needs a Mac, the relay, or iOS outside the app.
    static let notAvailableText = "Not available in the demo."

    /// What the passphrase prompts of the demo say.
    static let passphraseHint = "The passphrase of the demo is “\(DemoVault.passphrase)”."
}

/// The answer key of this iPhone in the demo, for every team: a key in memory. Each signature
/// asks `confirm` first (the Face ID prompt with the reason of the answer).
struct DemoAnswerSigners: AnswerSigners {
    let key: DemoAnswerKey
    let confirm: @Sendable (String) async -> Bool
    let canUseFaceID: @Sendable () -> Bool

    var faceIDWindow: FaceIDWindow? { nil }

    func joinKey(team: String?) throws -> Data { key.publicKey }

    func signer(team: String?, registered: Data?) -> (any AnswerSigner)? {
        guard registered == nil || registered == key.publicKey else { return nil }
        return DemoAnswerSigner(key: key, confirm: confirm, canUseFaceID: canUseFaceID)
    }

    func renew(team: String?) throws -> Data { key.publicKey }
}

struct DemoAnswerSigner: AnswerSigner {
    let key: DemoAnswerKey
    let confirm: @Sendable (String) async -> Bool
    let canUseFaceID: @Sendable () -> Bool

    var canSignAccess: Bool { canUseFaceID() }

    func signAccess(_ message: Data, reason: String, authentication: ApprovalAuthentication) async throws -> Data {
        guard await confirm(reason), !authentication.isCancelled else { throw CompanionKeyError.cancelled }
        return try key.sign(message)
    }

    func publicKey() throws -> Data { key.publicKey }

    func sign(_ message: Data, reason: String) async throws -> Data {
        guard await confirm(reason) else { throw CompanionKeyError.cancelled }
        return try key.sign(message)
    }

    func renew() throws -> Data { key.publicKey }
}

/// The notifications of the demo: off. Turning them on says "Not available in the demo"; nothing
/// is asked from iOS and no token is registered.
@MainActor
final class DemoPush: PushPermission {
    private let notAvailable: @MainActor () -> Void

    init(notAvailable: @escaping @MainActor () -> Void) {
        self.notAvailable = notAvailable
    }

    func authorization() async -> RequestNotificationAuthorization { .notDetermined }
    func observeRegistrationFailures(_ handler: @escaping @MainActor (String) -> Void) {}
    func setRequestsVisible(_ visible: Bool) {}
    func observeForegroundRequests(_ handler: @escaping @MainActor () -> Void) {}
    func deliveredRequestIdentifiers() async -> [String] { [] }
    func removeDeliveredRequests(identifiers: [String]) {}

    func requestAuthorization() async -> Bool {
        notAvailable()
        return false
    }

    func registerForPushes() {}
    func unregisterForPushes() {}
    var environment: PushEnvironment { .development }
    func observeOpens(_ handler: @escaping @MainActor () -> Void) {}
}

/// The Face ID prompt of the demo: the same prompt as a real Allow Once (biometry only, no
/// fallback button, no reuse of an earlier match), with the reason text of the action. It reads
/// and writes no keychain item.
enum DemoFaceID {
    static func confirm(_ reason: String) async -> Bool {
        let context = LAContext()
        defer { context.invalidate() }
        context.localizedFallbackTitle = ""
        context.touchIDAuthenticationAllowableReuseDuration = 0
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else { return false }
        do {
            return try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        } catch {
            return false
        }
    }

    /// Whether Face ID (or Touch ID) can check this iPhone's owner.
    static var available: Bool {
        let context = LAContext()
        defer { context.invalidate() }
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }
}
