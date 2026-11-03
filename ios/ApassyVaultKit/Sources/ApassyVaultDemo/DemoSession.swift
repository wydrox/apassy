import ApassyVaultKit
import CryptoKit
import Foundation

/// One run of the demo: the vault, its settings, its stored passphrase, and its answer key, all in
/// memory. Leave the demo by dropping the session: nothing of it stays, because nothing was ever
/// written outside it (no file, no defaults, no keychain item, no AutoFill identity, no request).
@MainActor
public final class DemoSession {
    /// The demo vault, unlocked, with its synthetic content.
    public let service: PreviewVaultService
    /// The passphrase of the demo vault "behind Face ID": in memory, after the check of `confirm`.
    public let passphraseStore: DemoPassphraseStore
    /// The settings of the demo: in memory, never the App Group defaults.
    public let settings: MemorySettingsStore
    /// The answer key of this iPhone in the demo: a P-256 key in memory, never in the keychain or
    /// the Secure Enclave.
    public let answerKey: DemoAnswerKey

    /// A new demo.
    ///
    /// - Parameter confirm: the owner check before the stored passphrase is read (the app passes
    ///   the real Face ID check; tests pass their own). True when the owner confirmed.
    public static func open(
        confirm: @escaping @Sendable (_ reason: String) async -> Bool, now: Date = Date()
    ) async -> DemoSession {
        let key = DemoAnswerKey()
        let service = await DemoVault.make(answerKey: key.publicKey, now: now)
        return DemoSession(service: service, answerKey: key, confirm: confirm)
    }

    private init(
        service: PreviewVaultService, answerKey: DemoAnswerKey, confirm: @escaping @Sendable (String) async -> Bool
    ) {
        self.service = service
        self.answerKey = answerKey
        passphraseStore = DemoPassphraseStore(
            stored: [DemoVault.vaultID: DemoVault.passphrase], confirm: confirm)
        settings = MemorySettingsStore(Self.initialSettings)
    }

    /// The settings of a new demo: "Unlock with Face ID" on, and the lock after five minutes away,
    /// so a short trip to another app does not ask for the passphrase.
    static let initialSettings: [String: Any] = [
        "faceIDUnlock.\(DemoVault.vaultID)": true,
        "lockAfter": 300,
        "deviceName": "iPhone (demo)",
    ]
}

/// The answer key of the demo: a P-256 key in this process only. Immutable after `init`.
public final class DemoAnswerKey: @unchecked Sendable {
    private let key = P256.Signing.PrivateKey()

    public init() {}

    /// The public key (X9.63), as the row of this iPhone holds it.
    public var publicKey: Data { key.publicKey.x963Representation }

    /// A signature (DER) of `message`.
    public func sign(_ message: Data) throws -> Data {
        try key.signature(for: message).derRepresentation
    }
}

/// The passphrase of the demo vault "behind Face ID": a dictionary in memory. A read asks the
/// owner check first, as the keychain item of a real vault does.
public final class DemoPassphraseStore: PassphraseStore, @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [String: String]
    private let confirm: @Sendable (String) async -> Bool

    public init(stored: [String: String] = [:], confirm: @escaping @Sendable (String) async -> Bool) {
        self.stored = stored
        self.confirm = confirm
    }

    public func hasPassphrase(vaultID: String) -> Bool { lock.withLock { stored[vaultID] != nil } }

    public func save(_ passphrase: String, vaultID: String) throws {
        lock.withLock { stored[vaultID] = passphrase }
    }

    public func read(vaultID: String, reason: String) async throws -> String {
        guard await confirm(reason) else { throw VaultError(.cancelled, "The check was cancelled.") }
        guard let passphrase = lock.withLock({ stored[vaultID] }) else {
            throw VaultError(.locked, "No passphrase is stored for this vault.")
        }
        return passphrase
    }

    public func remove(vaultID: String) {
        _ = lock.withLock { stored.removeValue(forKey: vaultID) }
    }

    public func readSession(reason: String) async throws -> any PassphraseReads {
        guard await confirm(reason) else { throw VaultError(.cancelled, "The check was cancelled.") }
        return Reads(store: self)
    }

    private final class Reads: PassphraseReads, @unchecked Sendable {
        private let lock = NSLock()
        private var store: DemoPassphraseStore?

        init(store: DemoPassphraseStore) { self.store = store }

        func read(vaultID: String) async throws -> String {
            guard let store = lock.withLock({ store }),
                let passphrase = store.lock.withLock({ store.stored[vaultID] })
            else { throw VaultError(.locked, "No passphrase is stored for this vault.") }
            return passphrase
        }

        func end() { lock.withLock { store = nil } }
    }
}
