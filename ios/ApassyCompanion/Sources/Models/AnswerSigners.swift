import ApassyCompanionKit
import Foundation

/// Signs the answers that give authority with the answer key, after Face ID for each answer
/// (contract relay-questions-v1, section 5.3).
protocol AnswerSigner: Sendable {
    var canSignAccess: Bool { get }
    func signAccess(_ message: Data, reason: String, authentication: ApprovalAuthentication) async throws -> Data
    /// The public key (X9.63).
    func publicKey() throws -> Data
    /// A signature (DER). The owner sees `reason` in the Face ID prompt.
    func sign(_ message: Data, reason: String) async throws -> Data
    /// A new key, after a new Face ID enrollment made the old one unusable.
    func renew() throws -> Data
}

extension AnswerSigner {
    var canSignAccess: Bool { false }
    func signAccess(_ message: Data, reason: String, authentication: ApprovalAuthentication) async throws -> Data {
        throw CompanionKeyError.biometryUnavailable
    }
}

/// The answer keys of this iPhone: one per questions team, so that a new key for one vault (after
/// a removal, or a new Face ID enrollment) leaves the rows of the other vaults as they are.
protocol AnswerSigners: Sendable {
    /// The key that a join or a connection to `team` sends to the Mac that confirms it: the key of
    /// that team, made now when the team has none. Nil `team` (a link without one): the shared key.
    func joinKey(team: String?) throws -> Data
    /// The signer for the row of this iPhone in `team`, which holds the answer key `registered`
    /// (nil: not known yet). Nil when this iPhone has no key for the team. It makes no key.
    func signer(team: String?, registered: Data?) -> (any AnswerSigner)?
    /// A new key for `team` only. The keys of the other teams stay.
    func renew(team: String?) throws -> Data
}

/// One signer for every team: the tests that have one vault.
struct SharedAnswerSigners: AnswerSigners {
    let signer: any AnswerSigner

    func joinKey(team: String?) throws -> Data { try signer.publicKey() }

    func signer(team: String?, registered: Data?) -> (any AnswerSigner)? { signer }

    func renew(team: String?) throws -> Data { try signer.renew() }
}

/// Where the answer keys are kept, by keychain service.
protocol AnswerKeyStore: Sendable {
    func load(service: String) throws -> (any CompanionKeys)?
    /// New keys under `service`; older keys under the same service are replaced.
    func create(service: String) throws -> any CompanionKeys
}

/// The keychain: the Secure Enclave, bound to the current biometric set with no passcode fallback
/// (as the companion approval key), under keychain services of their own so the companion pairing
/// keeps its keys. The Simulator has software keys.
struct KeychainAnswerKeyStore: AnswerKeyStore {
    func load(service: String) throws -> (any CompanionKeys)? { try CompanionKeyStore.loadExisting(service: service) }

    func create(service: String) throws -> any CompanionKeys { try CompanionKeyStore.createNew(service: service) }
}

/// One answer key per questions team, under `com.wydrox.apassy.questions.<team id>`.
///
/// Before, one key under `com.wydrox.apassy.questions` answered for every team. A team whose row
/// holds that key keeps using it: the key that the core reports for the row decides, so no
/// registration breaks. The shared key is never replaced or deleted here; a team leaves it only
/// when it gets its own key (a new connection, or `renew`).
struct TeamAnswerSigners: AnswerSigners {
    static let sharedService = "com.wydrox.apassy.questions"

    static func service(team: String) -> String { "\(sharedService).\(team)" }

    var store: any AnswerKeyStore = KeychainAnswerKeyStore()

    func joinKey(team: String?) throws -> Data {
        let service = team.map { Self.service(team: $0) } ?? Self.sharedService
        return try (store.load(service: service) ?? store.create(service: service)).approvalPublicKey
    }

    func signer(team: String?, registered: Data?) -> (any AnswerSigner)? {
        guard let service = resolvedService(team: team, registered: registered) else { return nil }
        return KeyAnswerSigner(
            service: service, renewService: team.map { Self.service(team: $0) } ?? Self.sharedService, store: store)
    }

    func renew(team: String?) throws -> Data {
        try store.create(service: team.map { Self.service(team: $0) } ?? Self.sharedService).approvalPublicKey
    }

    /// The service of the key that answers for the row in `team`: the one whose public key the row
    /// holds, else the team's own key, else the shared key of an earlier version.
    func resolvedService(team: String?, registered: Data?) -> String? {
        let shared = (try? store.load(service: Self.sharedService)) ?? nil
        guard let team else { return shared == nil ? nil : Self.sharedService }
        let ownService = Self.service(team: team)
        let own = (try? store.load(service: ownService)) ?? nil
        if let registered {
            if own?.approvalPublicKey == registered { return ownService }
            if shared?.approvalPublicKey == registered { return Self.sharedService }
            return nil
        }
        if own != nil { return ownService }
        return shared == nil ? nil : Self.sharedService
    }
}

/// The key under one keychain service. `renew` makes the key of the team, never the shared key
/// that other teams may still use.
private struct KeyAnswerSigner: AnswerSigner {
    let service: String
    let renewService: String
    let store: any AnswerKeyStore
    var canSignAccess: Bool {
        #if targetEnvironment(simulator)
        true // Explicit Simulator software keys are fixture evidence only.
        #else
        ApprovalAuthentication.faceIDAvailable
        #endif
    }
    func signAccess(_ message: Data, reason: String, authentication: ApprovalAuthentication) async throws -> Data {
        #if targetEnvironment(simulator)
        try await Task.sleep(for:.seconds(5))
        guard !authentication.isCancelled else { throw CompanionKeyError.cancelled }
        return try await keys().signApproval(message,reason:reason)
        #else
        try await keys().signAccessApproval(message, reason: reason, authentication: authentication)
        #endif
    }

    func publicKey() throws -> Data { try keys().approvalPublicKey }

    func sign(_ message: Data, reason: String) async throws -> Data {
        try await keys().signApproval(message, reason: reason)
    }

    func renew() throws -> Data { try store.create(service: renewService).approvalPublicKey }

    private func keys() throws -> any CompanionKeys {
        guard let keys = try store.load(service: service) else { throw CompanionKeyError.biometryChanged }
        return keys
    }
}
