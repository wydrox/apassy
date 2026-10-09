import Foundation

/// An error of the vault core (contract ios-core-v1, section 4). `message` is plain
/// English for the owner and never holds a value.
public struct VaultError: Error, Sendable, Equatable, LocalizedError {
    public enum Code: String, Sendable {
        case invalidInput = "invalid_input"
        case notAllowed = "not_allowed"
        case noVault = "no_vault"
        case locked
        case wrongPassphrase = "wrong_passphrase"
        case notFound = "not_found"
        case conflict
        case storage
        case unsupportedSchema = "unsupported_schema"
        case linkInvalid = "link_invalid"
        case joinRefused = "join_refused"
        case safetyMismatch = "safety_mismatch"
        case relayUnreachable = "relay_unreachable"
        case rateLimited = "rate_limited"
        case removed
        case needsPassphrase = "needs_passphrase"
        case damaged
        case staleCopy = "stale_copy"
        case forkedCopy = "forked_copy"
        case busy
        case tooLarge = "too_large"
        case io
        case `internal`
        /// The owner cancelled Face ID or the passphrase sheet (app side, not the core).
        case cancelled
        /// A passkey of the request's exclude list is in the vault (registration).
        case excluded
        /// The relying party accepts no algorithm that Apassy has (ES256).
        case unsupportedAlgorithm = "unsupported_algorithm"
        /// The passkey is in the vault already (import).
        case exists
        /// A passkey key that is not a P-256 PKCS#8 key.
        case badKey = "bad_key"
    }

    public var code: Code
    public var message: String
    /// True if the core accepted a new passphrase before a later sync step failed.
    public var rekeyed: Bool

    public init(_ code: Code, _ message: String, rekeyed: Bool = false) {
        self.code = code
        self.message = message
        self.rekeyed = rekeyed
    }

    public var errorDescription: String? { message }
}

/// The vault of this iPhone: the calls of the core (contract section 5), as async
/// functions. `CoreVaultService` (module ApassyVaultCore) runs them in the Rust core;
/// `PreviewVaultService` keeps synthetic data in memory, for previews and tests.
///
/// Every function may block for a while (a sync, a key derivation), so callers run
/// them off the main actor; the implementations do that themselves.
public protocol VaultService: Sendable {
    // 5.1 Vaults and the lock
    func info() async throws -> CoreInfo
    func select(vaultID: String) async throws
    /// `keep`: the core keeps the passphrase in memory until `lock`, so `resume` can
    /// open the vault again after `suspend` (the app's auto-lock time).
    func unlock(passphrase: String, keep: Bool) async throws
    func lock() async throws
    /// Close the vault when the app leaves the screen, keeping a kept passphrase. The
    /// vault's file lock must not stay held in the background (contract section 1).
    func suspend() async throws
    /// Open the vault again with the kept passphrase. False when there is none.
    func resume() async throws -> Bool
    func checkPassphrase(_ passphrase: String) async throws -> Bool
    func createLocalVault(name: String, passphrase: String) async throws -> VaultEntry
    /// Returns whether this iPhone left the relay team.
    func removeVault(id: String, force: Bool) async throws -> Bool

    /// Open an encrypted vault from iCloud Drive. Keep the selected file in iCloud Drive.
    func openICloudVault(url: URL, name: String, passphrase: String) async throws -> VaultEntry
    /// Connect an unlocked vault to its iCloud file after an identity check.
    func reconnectICloudVault(url: URL, vaultID: String) async throws

    // 5.2 Joining a vault
    /// `deviceName`: the name that the Mac shows for this iPhone.
    func joinStart(link: String, deviceName: String) async throws -> JoinInfo
    func joinPoll() async throws -> JoinInfo
    func joinCancel() async throws
    func joinFinish(passphrase: String) async throws -> VaultEntry

    // 5.3 Items
    func items(archived: ArchiveFilter) async throws -> [ItemRow]
    func item(id: UInt64) async throws -> ItemDetail
    func reveal(id: UInt64, field: String) async throws -> String
    func totp(id: UInt64, field: String) async throws -> TotpCode
    func history(id: UInt64) async throws -> [ItemEvent]
    func save(id: UInt64?, revision: UInt64?, draft: ItemDraft) async throws -> SavedItem
    func archive(id: UInt64, archived: Bool) async throws
    func delete(id: UInt64, revision: UInt64) async throws

    // 5.4 Passwords and Watchtower
    func generate(_ options: GeneratorOptions) async throws -> GeneratedPassword
    func strength(_ value: String) async throws -> Strength
    func watchtower() async throws -> WatchtowerReport

    // 5.5 Sync
    func sync() async throws -> SyncStatus
    func syncStatus() async throws -> SyncStatus
    /// True when the selected sync source has changes, or local iCloud changes need sync.
    func syncWait(timeout: Int) async throws -> Bool
    /// After `needsPassphrase`. Store the typed passphrase for Face ID only when `rekeyed`.
    func takeNewPassphrase(_ passphrase: String) async throws -> PassphraseChange
    func useRelayCopy() async throws -> SyncStatus
    func devices() async throws -> [RelayDevice]

    // 5.7 AutoFill
    func autofillList(domains: [String]) async throws -> AutofillList
    func autofillCredential(id: UInt64) async throws -> FillCredential
    func credentialIdentities() async throws -> [CredentialIdentity]
    /// The logins and the passkeys for the QuickType bar and the passkey sheet of iOS.
    func identitySet() async throws -> IdentitySet

    // Passkeys (contract: passkey_*). The core signs only after the caller checked the owner
    // for this request: AutoFill unlocks the vault for each request, the app asks `OwnerGate`.
    /// The passkeys of `rpID`; only those in `allowed` when it is not empty.
    func passkeys(rpID: String, allowed: [Data]) async throws -> [PasskeyCandidate]
    func passkeyAssert(_ request: PasskeyAssertionRequest) async throws -> PasskeyAssertion
    func passkeyRegister(_ request: PasskeyRegistration) async throws -> PasskeyCreated
    /// The app only, after the owner check.
    func passkeyImport(_ accounts: [PasskeyImportAccount]) async throws -> PasskeyImportResult
    /// The app only, after the owner check. A login with a password stays, without its passkey. A
    /// login without a password is deleted whole (`PasskeyRemovalPlan` says which).
    func passkeyRemove(id: UInt64, revision: UInt64) async throws
    /// The app only, after the owner check: what Apple's credential exchange hands to another
    /// app, passkey keys included. Never written to a file.
    func credentialExport() async throws -> CredentialExport
}

public extension VaultService {
    func openICloudVault(url: URL, name: String, passphrase: String) async throws -> VaultEntry {
        throw VaultError(.notAllowed, "This service cannot open an iCloud vault.")
    }

    func reconnectICloudVault(url: URL, vaultID: String) async throws {
        throw VaultError(.notAllowed, "This service cannot connect an iCloud vault.")
    }

    func identitySet() async throws -> IdentitySet {
        IdentitySet(passwords: try await credentialIdentities(), passkeys: [], codes: [])
    }

    func passkeys(rpID: String, allowed: [Data]) async throws -> [PasskeyCandidate] { [] }

    func passkeyAssert(_ request: PasskeyAssertionRequest) async throws -> PasskeyAssertion {
        throw VaultError(.notAllowed, "This vault has no passkeys.")
    }

    func passkeyRegister(_ request: PasskeyRegistration) async throws -> PasskeyCreated {
        throw VaultError(.notAllowed, "This vault cannot save passkeys.")
    }

    func passkeyImport(_ accounts: [PasskeyImportAccount]) async throws -> PasskeyImportResult {
        throw VaultError(.notAllowed, "This vault cannot import passkeys.")
    }

    func passkeyRemove(id: UInt64, revision: UInt64) async throws {
        throw VaultError(.notAllowed, "This vault has no passkeys.")
    }

    func credentialExport() async throws -> CredentialExport {
        throw VaultError(.notAllowed, "This vault cannot export.")
    }
}
