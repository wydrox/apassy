import ApassyCompanionKit
import ApassyVaultKit
import Foundation
import LocalAuthentication

// The parts of the demo (`DemoSession`) that stand in for the keychain, the shared defaults, and
// the Secure Enclave. Each one keeps its state in memory only, so the demo writes nothing to disk,
// to the App Group, or to the keychain. No UIKit: the model tests compile this file.

/// Text of the demo, in one place.
enum DemoText {
    static let banner = "Demo — sample data only"
    static let leave = "Leave Demo"
    static let tryIt = "Try the Demo"
    static let unavailable = "Not available in the demo"
}

/// Defaults in memory: the demo's settings, favorites, and question choices go here, never to the
/// App Group or to the defaults of the app. Every getter and setter that a model calls is
/// overridden, so nothing reaches the domain of the superclass.
final class DemoDefaults: UserDefaults {
    private let lock = NSLock()
    private var values: [String: Any] = [:]

    init() {
        // A suite name of its own, never read: every call below stays in `values`.
        super.init(suiteName: "com.wydrox.apassy.demo.memory")!
    }

    /// The keys that the demo set, for the tests.
    var storedKeys: Set<String> { lock.withLock { Set(values.keys) } }

    override func object(forKey defaultName: String) -> Any? { lock.withLock { values[defaultName] } }

    override func set(_ value: Any?, forKey defaultName: String) {
        lock.withLock {
            if let value { values[defaultName] = value } else { values[defaultName] = nil }
        }
    }

    override func set(_ value: Bool, forKey defaultName: String) { set(NSNumber(value: value) as Any?, forKey: defaultName) }
    override func set(_ value: Int, forKey defaultName: String) { set(NSNumber(value: value) as Any?, forKey: defaultName) }
    override func set(_ value: Double, forKey defaultName: String) { set(NSNumber(value: value) as Any?, forKey: defaultName) }
    override func set(_ value: Float, forKey defaultName: String) { set(NSNumber(value: value) as Any?, forKey: defaultName) }
    override func set(_ url: URL?, forKey defaultName: String) { set(url as Any?, forKey: defaultName) }

    override func removeObject(forKey defaultName: String) { _ = lock.withLock { values.removeValue(forKey: defaultName) } }

    override func string(forKey defaultName: String) -> String? { object(forKey: defaultName) as? String }
    override func array(forKey defaultName: String) -> [Any]? { object(forKey: defaultName) as? [Any] }
    override func stringArray(forKey defaultName: String) -> [String]? { object(forKey: defaultName) as? [String] }
    override func dictionary(forKey defaultName: String) -> [String: Any]? { object(forKey: defaultName) as? [String: Any] }
    override func data(forKey defaultName: String) -> Data? { object(forKey: defaultName) as? Data }
    override func url(forKey defaultName: String) -> URL? { object(forKey: defaultName) as? URL }
    override func bool(forKey defaultName: String) -> Bool { (object(forKey: defaultName) as? NSNumber)?.boolValue ?? false }
    override func integer(forKey defaultName: String) -> Int { (object(forKey: defaultName) as? NSNumber)?.intValue ?? 0 }
    override func double(forKey defaultName: String) -> Double { (object(forKey: defaultName) as? NSNumber)?.doubleValue ?? 0 }
    override func float(forKey defaultName: String) -> Float { (object(forKey: defaultName) as? NSNumber)?.floatValue ?? 0 }

    override func dictionaryRepresentation() -> [String: Any] { lock.withLock { values } }

    /// Drop everything (Leave Demo).
    func clear() { lock.withLock { values = [:] } }
}

/// The demo keeps no passphrase behind Face ID: "Unlock with Face ID" is not offered, and a save
/// is refused. It never touches the keychain.
struct DemoPassphraseStore: PassphraseStore {
    func hasPassphrase(vaultID: String) -> Bool { false }

    func save(_ passphrase: String, vaultID: String) throws {
        throw VaultError(.notAllowed, DemoText.unavailable)
    }

    func read(vaultID: String, reason: String) async throws -> String {
        throw VaultError(.locked, DemoText.unavailable)
    }

    func remove(vaultID: String) {}

    func readSession(reason: String) async throws -> any PassphraseReads {
        throw VaultError(.cancelled, DemoText.unavailable)
    }
}

/// The owner check of an answer in the demo: the same prompt as the real answer (Face ID, with the
/// reason text of the answer), then a signature with a key in memory.
typealias DemoConfirm = @Sendable (_ reason: String) async -> Bool

enum DemoFaceID {
    /// A new `LAContext` with the reason of the answer: Face ID (or Touch ID) when it is set up,
    /// else the passcode of the iPhone. An iPhone with neither cannot run the check, and the demo
    /// holds nothing real, so the answer goes on.
    static let check: DemoConfirm = { reason in
        let context = LAContext()
        defer { context.invalidate() }
        #if !os(watchOS) && !os(macOS)
            context.touchIDAuthenticationAllowableReuseDuration = 0
        #endif
        let policy: LAPolicy =
            context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            ? .deviceOwnerAuthenticationWithBiometrics : .deviceOwnerAuthentication
        guard context.canEvaluatePolicy(policy, error: nil) else { return true }
        if policy == .deviceOwnerAuthenticationWithBiometrics { context.localizedFallbackTitle = "" }
        do {
            return try await context.evaluatePolicy(policy, localizedReason: reason)
        } catch {
            return false
        }
    }
}

/// The answer keys of the demo: software P-256 keys in memory, one per team, never saved. Each
/// signature asks `confirm` first.
final class DemoAnswerSigners: AnswerSigners, @unchecked Sendable {
    private let lock = NSLock()
    private var keys: [String: SoftwareKeys] = [:]
    private let confirm: DemoConfirm

    init(confirm: @escaping DemoConfirm) {
        self.confirm = confirm
    }

    var teams: Set<String> { lock.withLock { Set(keys.keys) } }

    private static func team(_ team: String?) -> String { team ?? "shared" }

    func joinKey(team: String?) throws -> Data {
        lock.withLock {
            let name = Self.team(team)
            if let existing = keys[name] { return existing.approvalPublicKey }
            let made = SoftwareKeys()
            keys[name] = made
            return made.approvalPublicKey
        }
    }

    func signer(team: String?, registered: Data?) -> (any AnswerSigner)? {
        let name = Self.team(team)
        guard let key = lock.withLock({ keys[name] }) else { return nil }
        if let registered, registered != key.approvalPublicKey { return nil }
        return DemoAnswerSigner(keys: key, confirm: confirm, renew: { [weak self] in try self?.renew(team: team) ?? Data() })
    }

    func renew(team: String?) throws -> Data {
        lock.withLock {
            let made = SoftwareKeys()
            keys[Self.team(team)] = made
            return made.approvalPublicKey
        }
    }

    /// Drop every key (Leave Demo).
    func removeAll() { lock.withLock { keys = [:] } }
}

struct DemoAnswerSigner: AnswerSigner {
    let keys: SoftwareKeys
    let confirm: DemoConfirm
    let renewKey: @Sendable () throws -> Data

    init(keys: SoftwareKeys, confirm: @escaping DemoConfirm, renew: @escaping @Sendable () throws -> Data) {
        self.keys = keys
        self.confirm = confirm
        self.renewKey = renew
    }

    var canSignAccess: Bool { true }

    func signAccess(_ message: Data, reason: String, authentication: ApprovalAuthentication) async throws -> Data {
        guard !authentication.isCancelled else { throw CompanionKeyError.cancelled }
        guard await confirm(reason) else { throw CompanionKeyError.cancelled }
        guard !authentication.isCancelled else { throw CompanionKeyError.cancelled }
        return try await keys.signApproval(message, reason: reason)
    }

    func publicKey() throws -> Data { keys.approvalPublicKey }

    func sign(_ message: Data, reason: String) async throws -> Data {
        guard await confirm(reason) else { throw CompanionKeyError.cancelled }
        return try await keys.signApproval(message, reason: reason)
    }

    func renew() throws -> Data { try renewKey() }
}

/// The pairing of the demo: none, and none can be saved. The demo's companion is never started.
struct DemoPairingStore: PairingStore {
    func load() throws -> PairingRecord? { nil }
    func save(_ record: PairingRecord) throws { throw VaultError(.notAllowed, DemoText.unavailable) }
    func delete() throws {}
}
