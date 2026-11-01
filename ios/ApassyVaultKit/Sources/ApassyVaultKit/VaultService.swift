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
        // Questions through the relay (section 5.10).
        /// The vault has no questions team.
        case noQuestions = "no_questions"
        /// This iPhone has no `trusted_device` row or answer key in the vault yet, or its key changed.
        case notRegistered = "not_registered"
        /// The vault row of this iPhone has another answer key (for example after a Face ID change).
        case answerKeyChanged = "answer_key_changed"
        /// The card did not pass a check; the message says what to do.
        case unreadable
        case alreadyAnswered = "already_answered"
        case expired
        case notRouted = "not_routed"
        case tooManyAnswers = "too_many_answers"
        /// The time of the answer is too old to send again: answer again.
        case staleAnswer = "stale_answer"
        case pushUnavailable = "push_unavailable"
        /// The `vault_id` of an answer is not the vault of its question.
        case wrongVault = "wrong_vault"
        // The agents of the Macs (section 5.12).
        /// The relay does not carry the feeds yet.
        case feedUnavailable = "feed_unavailable"
        /// The time of the action is too old to send again: do it again, with Face ID again.
        case staleAction = "stale_action"
        /// The feed of the Mac is more than a day old: no action until it reports again.
        case staleFeed = "stale_feed"
        case tooManyActions = "too_many_actions"
        /// The relay asks this iPhone to wait a minute before it reads the feeds again.
        case feedRate = "feed_rate"
        /// The service has no such call (an older core; app side, not the core).
        case unsupported
        case accessUnavailable = "access_unavailable"
        case historyStorageUnavailable = "history_storage_unavailable"
        case historyKeyMissing = "history_key_missing"
        case historyFull = "history_full"
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
    /// `answerKey`: the Secure Enclave answer key of this iPhone (X9.63) for the Mac that confirms.
    func joinStart(link: String, deviceName: String, answerKey: Data?) async throws -> JoinInfo
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

    // 5.10 Questions through the relay (contract relay-questions-v1). The app only.
    func requestHistory() async throws -> RequestHistorySnapshot
    func clearRequestHistory(vaultID: String) async throws
    func questionsList() async throws -> QuestionsList
    func accessRequestsList() async throws -> AccessRequestsSnapshot
    func accessRequestsHistory() async throws -> AccessRequestsSnapshot
    func accessRequestPrepare(_ request: RelayAccessRequest, choice: AccessChoice) async throws -> PreparedAccessAnswer
    func accessRequestAnswer(_ request: RelayAccessRequest, choice: AccessChoice, prepared: PreparedAccessAnswer, signature: Data?) async throws -> SentAccessAnswer
    func accessRequestCancelPrepared() async
    /// Make the questions context of `vaultID` without selecting it (a vault that is not open
    /// after `resume`, or after the app started): the core opens the vault, reads what its
    /// questions need, and closes it again. Returns the status of its questions team
    /// (`enabled: false` without one). `wrong_passphrase`, `busy` (AutoFill holds the vault), or
    /// `locked` (a lock or a suspend came first).
    func questionsUnlock(vaultID: String, passphrase: String) async throws -> QuestionsStatus
    /// True when the relay has new or changed questions (a long poll of at most 25 s).
    func questionsWait(timeout: Int) async throws -> Bool
    func questionOpen(qid: String) async throws -> RemoteQuestion
    /// The exact answer string and its time, to sign with the answer key after Face ID.
    func questionAnswerString(qid: String, answer: RemoteAnswer) async throws -> PreparedAnswer
    /// Seal and post an answer. `signature` (DER, by the answer key) for an answer that needs Face
    /// ID; nil for the others, which the core signs with the relay key of this iPhone.
    func questionAnswer(qid: String, answer: RemoteAnswer, time: Int64, signature: Data?) async throws -> SentAnswer
    /// The two calls above for the question of `vaultID` (`RemoteQuestion.vaultID`). Nil: the core
    /// uses the vault that owns the qid.
    func questionAnswerString(qid: String, answer: RemoteAnswer, vaultID: String?) async throws -> PreparedAnswer
    func questionAnswer(qid: String, answer: RemoteAnswer, time: Int64, signature: Data?, vaultID: String?)
        async throws -> SentAnswer
    /// Check that the vault row of this iPhone has this Secure Enclave answer key (X9.63). It writes
    /// nothing: the Mac that confirmed the join writes the row.
    func answerKeyRegister(publicKey: Data) async throws -> AnswerKeyRegistration
    /// Send the APNs token to the questions team of the selected vault; a core that keeps the
    /// questions of every unlocked vault sends it to the team of each.
    func pushTokenSet(token: Data, environment: PushEnvironment) async throws
    /// Remove the token from the relay, as `pushTokenSet` reaches it. `pending`: the vaults whose
    /// team keeps it until they open (a core that keeps every unlocked vault; else empty).
    func pushTokenClear() async throws -> PushCleared
    /// Join the notifications-only team of the selected vault with the device link of the Mac.
    /// `answerKey`: the answer key of this iPhone (X9.63), which goes to the Mac that confirms.
    func joinAttach(link: String, deviceName: String, answerKey: Data) async throws -> AttachInfo
    func joinAttachPoll() async throws -> AttachInfo
    func joinAttachCancel() async throws

    // 5.11 Folders, adding by paste, and the options of a credential. The app syncs after each
    // change, as after `save`.
    /// The folders, depth first. The AutoFill extension may read them.
    func folders() async throws -> [Folder]
    /// A folder in `parent` (nil: the top level). `exists` when a sibling has the name.
    func createFolder(parent: String?, name: String) async throws -> Folder
    func renameFolder(uuid: String, name: String) async throws
    /// Move a folder with its subfolders and credentials into `parent` (nil: the top level).
    func moveFolder(uuid: String, parent: String?) async throws
    /// Delete a folder. Its credentials and subfolders go to its parent. Returns the count of
    /// credentials that moved. No credential is deleted.
    func deleteFolder(uuid: String) async throws -> Int
    /// Put a credential in `folder` (nil: the top level).
    func setItemFolder(id: UInt64, folder: String?) async throws
    /// The credentials of a paste, without a secret value (a secret field has a masked preview).
    func detect(text: String) async throws -> [DetectedCredential]
    /// Detect `text` again in the core and add the picked rows (`pick`: indexes of `detect`; nil:
    /// all) to `folder` in one transaction. `titles`: a typed title for some rows, by index.
    func addPasted(text: String, folder: String?, pick: [Int]?, titles: [Int: String]) async throws
        -> [PastedItem]
    /// "Always ask me" and the environment, with the owner as its source. The core does not check
    /// the owner: ask for Face ID first when turning "Always ask me" off or choosing an
    /// environment other than production, as the Mac does.
    func setItemOptions(id: UInt64, alwaysAsk: Bool?, environment: CredentialEnvironment?) async throws

    // 5.12 The agents of the Macs (contract relay-feed-v1). The app only. An older service throws
    // `VaultError.feedUnsupported` (`Feed.swift`).
    /// The agents of every vault with a questions context, as the feeds of their Macs show them.
    func feedList() async throws -> FeedList
    /// True when a feed changed (a long poll of at most 25 s). Only while the Agents tab shows.
    func feedWait(timeout: Int) async throws -> Bool
    /// The action string of a removal, to sign with the answer key of `teamID` after Face ID when
    /// `needsFaceID`. `actionID` and `time`: those of an earlier try (a retry); nil for new ones.
    func feedActionString(_ removal: FeedRemoval, actionID: String?, time: Int64?) async throws -> PreparedFeedAction
    /// Seal and post a removal with the `actionID` and `time` of `feedActionString`. `signature`
    /// (DER, by the answer key) for a Face ID kind; nil for `only`, which the core signs.
    func feedAction(_ removal: FeedRemoval, actionID: String, time: Int64, signature: Data?) async throws
        -> SentFeedAction
    /// The state of a posted action; a long poll of `timeout` seconds (0 to 25) while it is open.
    func feedActionWait(actionID: String, vaultID: String?, timeout: Int) async throws -> FeedActionOutcome
}

public extension VaultService {
    func accessRequestsHistory() async throws -> AccessRequestsSnapshot { throw VaultError(.notAllowed, "Update Apassy to view access history.") }
    func accessRequestsList() async throws -> AccessRequestsSnapshot { throw VaultError(.notAllowed, "Update Apassy to answer access requests.") }
    func accessRequestPrepare(_ request: RelayAccessRequest, choice: AccessChoice) async throws -> PreparedAccessAnswer { throw VaultError(.notAllowed, "Review access on the Mac.") }
    func accessRequestAnswer(_ request: RelayAccessRequest, choice: AccessChoice, prepared: PreparedAccessAnswer, signature: Data?) async throws -> SentAccessAnswer { throw VaultError(.notAllowed, "Review access on the Mac.") }
    func accessRequestCancelPrepared() async {}
    func requestHistory() async throws -> RequestHistorySnapshot {
        throw VaultError(.notAllowed, "Update Apassy to view saved request history.")
    }

    func clearRequestHistory(vaultID: String) async throws {
        throw VaultError(.notAllowed, "Update Apassy to clear saved request history.")
    }

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

    // An older service has no folders and no paste detection. The app must not offer them then.

    func folders() async throws -> [Folder] {
        throw VaultError(.notAllowed, "This vault has no folders. Update Apassy.")
    }

    func createFolder(parent: String?, name: String) async throws -> Folder {
        throw VaultError(.notAllowed, "This vault has no folders. Update Apassy.")
    }

    func renameFolder(uuid: String, name: String) async throws {
        throw VaultError(.notAllowed, "This vault has no folders. Update Apassy.")
    }

    func moveFolder(uuid: String, parent: String?) async throws {
        throw VaultError(.notAllowed, "This vault has no folders. Update Apassy.")
    }

    func deleteFolder(uuid: String) async throws -> Int {
        throw VaultError(.notAllowed, "This vault has no folders. Update Apassy.")
    }

    func setItemFolder(id: UInt64, folder: String?) async throws {
        throw VaultError(.notAllowed, "This vault has no folders. Update Apassy.")
    }

    func detect(text: String) async throws -> [DetectedCredential] {
        throw VaultError(.notAllowed, "This vault cannot add a pasted credential. Update Apassy.")
    }

    func addPasted(text: String, folder: String?, pick: [Int]?, titles: [Int: String]) async throws
        -> [PastedItem]
    {
        throw VaultError(.notAllowed, "This vault cannot add a pasted credential. Update Apassy.")
    }

    func setItemOptions(id: UInt64, alwaysAsk: Bool?, environment: CredentialEnvironment?) async throws {
        throw VaultError(.notAllowed, "This vault cannot change the options of a credential. Update Apassy.")
    }

    /// An older service keeps the questions of the selected vault only.
    func questionsUnlock(vaultID: String, passphrase: String) async throws -> QuestionsStatus {
        throw VaultError(.notAllowed, "This vault cannot read the questions of another vault. Update Apassy.")
    }
}
