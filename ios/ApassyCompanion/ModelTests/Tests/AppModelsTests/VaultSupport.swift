import ApassyVaultKit
import Foundation
import Synchronization

@testable import AppModels

// Test doubles and helpers of the vault model tests.

/// An owner check that answers as told and counts its calls.
final class ScriptedOwnerCheck: OwnerCheck {
    private struct State {
        var answer: Bool
        var biometry: Biometry
        var reasons: [String] = []
    }

    private let state: Mutex<State>

    init(answer: Bool = true, biometry: Biometry = .faceID) {
        state = Mutex(State(answer: answer, biometry: biometry))
    }

    var answer: Bool {
        get { state.withLock { $0.answer } }
        set { state.withLock { $0.answer = newValue } }
    }

    var biometry: Biometry {
        get { state.withLock { $0.biometry } }
        set { state.withLock { $0.biometry = newValue } }
    }

    /// How many times the model asked.
    var calls: Int { state.withLock { $0.reasons.count } }

    /// The reasons that were shown, in order.
    var reasons: [String] { state.withLock { $0.reasons } }

    func confirm(reason: String) async -> Bool {
        state.withLock { state in
            state.reasons.append(reason)
            return state.answer
        }
    }
}

/// A passphrase store in memory. `readError` makes `read` throw, the way iOS does after a new
/// Face ID enrollment.
final class MemoryPassphraseStore: PassphraseStore {
    private struct State {
        var values: [String: String] = [:]
        var readError: VaultError?
    }

    private let state = Mutex(State())

    init() {}

    var readError: VaultError? {
        get { state.withLock { $0.readError } }
        set { state.withLock { $0.readError = newValue } }
    }

    /// The stored passphrase of a vault, without a Face ID prompt.
    func stored(vaultID: String) -> String? {
        state.withLock { $0.values[vaultID] }
    }

    func hasPassphrase(vaultID: String) -> Bool {
        state.withLock { $0.values[vaultID] != nil }
    }

    func save(_ passphrase: String, vaultID: String) throws {
        state.withLock { $0.values[vaultID] = passphrase }
    }

    func read(vaultID: String, reason: String) async throws -> String {
        let outcome: Result<String, VaultError> = state.withLock { state in
            if let error = state.readError { return .failure(error) }
            if let value = state.values[vaultID] { return .success(value) }
            return .failure(VaultError(.locked, "No passphrase is stored."))
        }
        return try outcome.get()
    }

    func remove(vaultID: String) {
        state.withLock { _ = $0.values.removeValue(forKey: vaultID) }
    }
}

/// A vault service that forwards to a `PreviewVaultService` and lets a test watch and steer the
/// sync. `sync()` is counted and answers with the current status at once (the preview waits
/// 600 ms), and `syncWait` answers from a script.
actor SpyVaultService: VaultService {
    private struct State {
        var syncCount = 0
        var syncWaits: [Bool]
        var syncError: VaultError?
        var syncDelay: Duration?
        var syncMutationTitle: String?
        var syncStatusOverride: SyncStatus?
        var resumeDelay: Duration?
        var unlockError: VaultError?
        var iCloudOpenDelay: Duration?
        var iCloudOpenCount = 0
        var iCloudError: VaultError?
        var removeError: VaultError?
        var passphraseChangeDelay: Duration?
        var passphraseChangeResult: PassphraseChange?
        var passphraseChangeCount = 0
        var reconnects: [(URL, String)] = []
    }

    private let inner: PreviewVaultService
    private nonisolated let state: Mutex<State>

    init(
        inner: PreviewVaultService = PreviewVaultService(empty: false, unlocked: true), syncWaits: [Bool] = [],
        syncError: VaultError? = nil
    ) {
        self.inner = inner
        state = Mutex(State(syncWaits: syncWaits, syncError: syncError))
    }

    /// How many times `sync()` was called.
    nonisolated var syncCount: Int { state.withLock { $0.syncCount } }

    nonisolated var syncDelay: Duration? {
        get { state.withLock { $0.syncDelay } }
        set { state.withLock { $0.syncDelay = newValue } }
    }
    nonisolated var syncMutationTitle: String? {
        get { state.withLock { $0.syncMutationTitle } }
        set { state.withLock { $0.syncMutationTitle = newValue } }
    }

    nonisolated var syncStatusOverride: SyncStatus? {
        get { state.withLock { $0.syncStatusOverride } }
        set { state.withLock { $0.syncStatusOverride = newValue } }
    }

    /// How long `resume()` takes, to let a test go to the background meanwhile.
    nonisolated var resumeDelay: Duration? {
        get { state.withLock { $0.resumeDelay } }
        set { state.withLock { $0.resumeDelay = newValue } }
    }

    /// An error that `unlock` throws instead of unlocking, or nil.
    nonisolated var unlockError: VaultError? {
        get { state.withLock { $0.unlockError } }
        set { state.withLock { $0.unlockError = newValue } }
    }

    /// Whether the core has the vault open now.
    func coreUnlocked() async throws -> Bool { try await inner.info().unlocked }

    /// An error that `sync()` throws, or nil.
    nonisolated var syncError: VaultError? {
        get { state.withLock { $0.syncError } }
        set { state.withLock { $0.syncError = newValue } }
    }

    nonisolated var iCloudOpenCount: Int { state.withLock { $0.iCloudOpenCount } }
    nonisolated var iCloudOpenDelay: Duration? {
        get { state.withLock { $0.iCloudOpenDelay } }
        set { state.withLock { $0.iCloudOpenDelay = newValue } }
    }
    nonisolated var iCloudError: VaultError? {
        get { state.withLock { $0.iCloudError } }
        set { state.withLock { $0.iCloudError = newValue } }
    }
    nonisolated var removeError: VaultError? {
        get { state.withLock { $0.removeError } }
        set { state.withLock { $0.removeError = newValue } }
    }
    nonisolated var passphraseChangeDelay: Duration? {
        get { state.withLock { $0.passphraseChangeDelay } }
        set { state.withLock { $0.passphraseChangeDelay = newValue } }
    }
    nonisolated var passphraseChangeResult: PassphraseChange? {
        get { state.withLock { $0.passphraseChangeResult } }
        set { state.withLock { $0.passphraseChangeResult = newValue } }
    }
    nonisolated var passphraseChangeCount: Int { state.withLock { $0.passphraseChangeCount } }

    nonisolated var reconnects: [(URL, String)] { state.withLock { $0.reconnects } }

    func openICloudVault(url: URL, name: String, passphrase: String) async throws -> VaultEntry {
        let delay = state.withLock { state in
            state.iCloudOpenCount += 1
            return state.iCloudOpenDelay
        }
        if let delay { try? await Task.sleep(for: delay) }
        if let error = iCloudError { throw error }
        guard passphrase == "passphrase" else { throw VaultError(.wrongPassphrase, "The passphrase does not open this vault.") }
        var entry = try await inner.createLocalVault(name: name, passphrase: "test passphrase for local fixture")
        entry.syncSource = "icloud"
        return entry
    }
    func reconnectICloudVault(url: URL, vaultID: String) async throws {
        if let error = iCloudError { throw error }
        state.withLock { $0.reconnects.append((url, vaultID)) }
    }

    // 5.1
    func info() async throws -> CoreInfo { try await inner.info() }
    func select(vaultID: String) async throws { try await inner.select(vaultID: vaultID) }
    func unlock(passphrase: String, keep: Bool) async throws {
        if let error = unlockError { throw error }
        try await inner.unlock(passphrase: passphrase, keep: keep)
    }
    func suspend() async throws { try await inner.suspend() }
    func resume() async throws -> Bool {
        if let delay = resumeDelay { try? await Task.sleep(for: delay) }
        return try await inner.resume()
    }
    func lock() async throws { try await inner.lock() }
    func checkPassphrase(_ passphrase: String) async throws -> Bool { try await inner.checkPassphrase(passphrase) }
    func createLocalVault(name: String, passphrase: String) async throws -> VaultEntry {
        try await inner.createLocalVault(name: name, passphrase: passphrase)
    }
    func removeVault(id: String, force: Bool) async throws -> Bool {
        if let error = removeError { throw error }
        return try await inner.removeVault(id: id, force: force)
    }

    // 5.2
    func joinStart(link: String, deviceName: String) async throws -> JoinInfo {
        try await inner.joinStart(link: link, deviceName: deviceName)
    }
    func joinPoll() async throws -> JoinInfo { try await inner.joinPoll() }
    func joinCancel() async throws { try await inner.joinCancel() }
    func joinFinish(passphrase: String) async throws -> VaultEntry { try await inner.joinFinish(passphrase: passphrase) }

    // 5.3
    func items(archived: ArchiveFilter) async throws -> [ItemRow] { try await inner.items(archived: archived) }
    func item(id: UInt64) async throws -> ItemDetail { try await inner.item(id: id) }
    func reveal(id: UInt64, field: String) async throws -> String { try await inner.reveal(id: id, field: field) }
    func totp(id: UInt64, field: String) async throws -> TotpCode { try await inner.totp(id: id, field: field) }
    func history(id: UInt64) async throws -> [ItemEvent] { try await inner.history(id: id) }
    func save(id: UInt64?, revision: UInt64?, draft: ItemDraft) async throws -> SavedItem {
        try await inner.save(id: id, revision: revision, draft: draft)
    }
    func archive(id: UInt64, archived: Bool) async throws { try await inner.archive(id: id, archived: archived) }
    func delete(id: UInt64, revision: UInt64) async throws { try await inner.delete(id: id, revision: revision) }

    // 5.4
    func generate(_ options: GeneratorOptions) async throws -> GeneratedPassword { try await inner.generate(options) }
    func strength(_ value: String) async throws -> Strength { try await inner.strength(value) }
    func watchtower() async throws -> WatchtowerReport { try await inner.watchtower() }

    // 5.5
    func sync() async throws -> SyncStatus {
        let error = state.withLock { state in
            state.syncCount += 1
            return state.syncError
        }
        if let title = syncMutationTitle {
            _ = try await inner.save(id: nil, revision: nil,
                draft: ItemDraft(title: title, kind: .login, notes: "", tags: [],
                    fields: [.named("username", "synced-user", secret: false)]))
        }
        if let delay = syncDelay { try? await Task.sleep(for: delay) }
        if let error { throw error }
        return try await inner.syncStatus()
    }

    func syncStatus() async throws -> SyncStatus {
        if let status = syncStatusOverride { return status }
        return try await inner.syncStatus()
    }

    func syncWait(timeout: Int) async throws -> Bool {
        let next: Bool? = state.withLock { state in
            state.syncWaits.isEmpty ? nil : state.syncWaits.removeFirst()
        }
        if let next { return next }
        try? await Task.sleep(for: .milliseconds(20))
        return false
    }

    func takeNewPassphrase(_ passphrase: String) async throws -> PassphraseChange {
        let (delay, result) = state.withLock { state in
            state.passphraseChangeCount += 1
            return (state.passphraseChangeDelay, state.passphraseChangeResult)
        }
        if let delay { try? await Task.sleep(for: delay) }
        if let result { return result }
        return try await inner.takeNewPassphrase(passphrase)
    }
    func useRelayCopy() async throws -> SyncStatus { try await inner.useRelayCopy() }
    func devices() async throws -> [RelayDevice] { try await inner.devices() }

    // 5.7
    func autofillList(domains: [String]) async throws -> AutofillList { try await inner.autofillList(domains: domains) }
    func autofillCredential(id: UInt64) async throws -> FillCredential { try await inner.autofillCredential(id: id) }
    func credentialIdentities() async throws -> [CredentialIdentity] { try await inner.credentialIdentities() }
}

// MARK: Settings

/// Removes the defaults files that earlier test runs left in `~/Library/Preferences`. A suite
/// cannot be removed at the end of a run, because the system writes its file after the last
/// test, so the next run cleans up once, before its first suite.
private let removedOldSuites: Void = {
    let folder = FileManager.default.homeDirectoryForCurrentUser.appending(path: "Library/Preferences")
    let names = (try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? []
    for name in names where name.hasPrefix("apassy-tests-") && name.hasSuffix(".plist") {
        try? FileManager.default.removeItem(at: folder.appending(path: name))
    }
}()

/// A new, empty defaults suite.
func makeDefaults() -> UserDefaults {
    _ = removedOldSuites
    return UserDefaults(suiteName: "apassy-tests-\(UUID())")!
}

/// Settings on a defaults suite of their own.
@MainActor
func makeSettings() -> VaultSettings {
    VaultSettings(defaults: makeDefaults())
}

// MARK: The vault model

/// What the model asked the app to do, and the clock of the model.
@MainActor
final class VaultRecorder {
    struct Copy: Equatable {
        let value: String
        let secret: Bool
    }

    var copies: [Copy] = []
    /// The vault IDs of each `replaceIdentities` call.
    var replacedIdentities: [String] = []
    var removedAllIdentities = 0
    /// The time that the model sees: the continuous clock, moved by the test.
    var now = ContinuousClock.now
}

/// The vault ID of the preview vault.
let previewVaultID = "4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c"

/// A model with short times and hooks that record. Nothing is started: call `start()`.
@MainActor
func makeVault(
    service: any VaultService = PreviewVaultService(empty: false, unlocked: false),
    check: ScriptedOwnerCheck = ScriptedOwnerCheck(),
    store: MemoryPassphraseStore = MemoryPassphraseStore(),
    settings: VaultSettings = makeSettings()
) -> (VaultModel, VaultRecorder) {
    let recorder = VaultRecorder()
    var hooks = VaultModel.Hooks()
    hooks.copy = { [recorder] value, secret in
        recorder.copies.append(VaultRecorder.Copy(value: value, secret: secret))
    }
    hooks.replaceIdentities = { [recorder] _, vaultID in
        recorder.replacedIdentities.append(vaultID)
    }
    hooks.removeAllIdentities = { [recorder] in
        recorder.removedAllIdentities += 1
    }
    var timing = VaultModel.Timing()
    timing.waitTimeout = 1
    timing.firstBackoff = .milliseconds(10)
    timing.maxBackoff = .milliseconds(40)
    timing.saveDebounce = .milliseconds(30)
    timing.now = { [recorder] in recorder.now }
    let gate = OwnerGate(check: check, service: service)
    let model = VaultModel(
        service: service, settings: settings, gate: gate, passphraseStore: store, hooks: hooks, timing: timing)
    return (model, recorder)
}

// MARK: Rows

/// A row for the query tests.
func makeRow(
    _ id: UInt64, _ title: String, kind: ItemKind = .login, subtitle: String = "", websites: [String] = [],
    tags: [String] = [], archived: Bool = false, changedAt: Int64? = nil
) -> ItemRow {
    ItemRow(
        id: id, revision: 1, title: title, kind: kind, subtitle: subtitle, websites: websites, tags: tags,
        archived: archived, hasTotp: false, conflictOf: nil, addedAt: nil, changedAt: changedAt, usedAt: nil)
}
