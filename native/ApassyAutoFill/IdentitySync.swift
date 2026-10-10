// The identities of the vault for the system (QuickType bar, the passkey sheet, the
// code suggestions). Only metadata: website, user name, credential ID, user handle,
// item ID. No password, no code, no key.
//
// Only a process with the AutoFill entitlement of this provider may write the store:
// the extension, or the containing app. The Rust app forbids unsafe code and cannot
// call AuthenticationServices, so the extension replaces the whole list each time it
// runs: when the owner turns AutoFill on (configuration), and at the start of every
// request. The app answers `credential_identities` with all passkeys (not filtered by
// website), the logins with a password, and the logins with a one-time code.

import AuthenticationServices
import Foundation

/// More identities than this are not sent to the system.
let maxIdentities = 20_000

/// How long a new passkey waits for the system list before the request ends anyway.
let identityPublishTimeout: Duration = .seconds(3)

/// What the system list says about itself (`ASCredentialIdentityStoreState`).
struct IdentityStoreState: Sendable, Equatable {
    var isEnabled: Bool
    /// When false, the system wants the whole list each time (a single save is outside its contract).
    var supportsIncrementalUpdates: Bool
}

/// The system list of identities. A seam for the tests; the product uses `SystemIdentityStore`.
@MainActor
protocol IdentityStoring {
    func state() async -> IdentityStoreState
    func replace(_ identities: [any ASCredentialIdentity]) async throws
    func save(_ identities: [any ASCredentialIdentity]) async throws
}

@MainActor
struct SystemIdentityStore: IdentityStoring {
    func state() async -> IdentityStoreState {
        let state = await ASCredentialIdentityStore.shared.state()
        return IdentityStoreState(isEnabled: state.isEnabled, supportsIncrementalUpdates: state.supportsIncrementalUpdates)
    }

    func replace(_ identities: [any ASCredentialIdentity]) async throws {
        try await ASCredentialIdentityStore.shared.replaceCredentialIdentities(identities)
    }

    func save(_ identities: [any ASCredentialIdentity]) async throws {
        try await ASCredentialIdentityStore.shared.saveCredentialIdentities(identities)
    }
}

/// The end of one store operation, awaited by the callers that asked for it. A waiter may
/// give up after a timeout; the operation goes on without it.
@MainActor
private final class Completion {
    private var outcome: Result<Int, any Error>?
    private var waiters: [Int: CheckedContinuation<Result<Int, any Error>?, Never>] = [:]
    private var nextWaiter = 0

    func finish(_ result: Result<Int, any Error>) {
        guard outcome == nil else { return }
        outcome = result
        let waiting = waiters
        waiters = [:]
        for continuation in waiting.values { continuation.resume(returning: result) }
    }

    /// Nil: not finished within `timeout`.
    func wait(timeout: Duration? = nil) async -> Result<Int, any Error>? {
        if let outcome { return outcome }
        let id = nextWaiter
        nextWaiter += 1
        return await withCheckedContinuation { continuation in
            waiters[id] = continuation
            if let timeout {
                Task { [weak self] in
                    try? await Task.sleep(for: timeout)
                    self?.expire(id)
                }
            }
        }
    }

    private func expire(_ id: Int) {
        waiters.removeValue(forKey: id)?.resume(returning: nil)
    }
}

/// Everything that writes the system list in this process goes through one coordinator, one
/// store operation at a time, in arrival order. Two things would otherwise lose a passkey that
/// the owner just saved:
///
/// 1. A full refresh that fetched its snapshot before the passkey existed and replaces the list
///    after the passkey was saved. The coordinator keeps a short journal of the passkeys it
///    published; a refresh adds the ones published after its fetch began, right before its
///    replace is issued. A refresh whose fetch began after the publish is the truth (the owner
///    may have deleted the passkey since) and gets nothing added.
/// 2. A replace that is already inside the store (XPC) when the save is issued, and lands after
///    it. No save is issued while another operation is in flight: it waits its turn.
///
/// Nothing holds a lock across an await: all state belongs to the main actor. The price of
/// the queue: while one store operation hangs, the save of a new passkey waits behind it, so
/// the registration ends after its timeout without the passkey in the system list. The save
/// is still queued and lands when the earlier operation returns, or never if the store never
/// answers; the passkey is in the vault either way, and the next refresh publishes it.
@MainActor
final class IdentityCoordinator {
    static let system = IdentityCoordinator(store: SystemIdentityStore())

    /// The journal never holds more than this many passkeys (it empties as soon as no fetch is outstanding).
    static let journalLimit = 64

    private struct Published {
        let sequence: Int
        let identity: ASPasskeyCredentialIdentity
    }

    private struct Fetch {
        /// Which fetch began later: the later one is the fresher view.
        let order: Int
        /// The number of passkeys published when the fetch began.
        let mark: Int
    }

    private struct Refresh {
        let fetch: Fetch
        let identities: [any ASCredentialIdentity]
        let completion: Completion
    }

    private struct Save {
        let published: Published
        let completion: Completion
    }

    private let store: any IdentityStoring
    private var journal: [Published] = []
    private var publishedCount = 0
    private var fetchCount = 0
    private var fetching: [Int: Int] = [:]
    private var newestFetch = 0
    private var busy = false
    /// Saves at or below this mark are covered by a snapshot the store successfully applied.
    private var appliedMark = 0
    /// A snapshot fetched before this mark cannot be merged with the incomplete journal.
    private var evictedThrough = 0
    private var refreshWaiting: Refresh?
    private var savesWaiting: [Save] = []

    init(store: any IdentityStoring) {
        self.store = store
    }

    /// Passkeys queued behind another store operation (for the tests).
    var queuedSaves: Int { savesWaiting.count }
    var refreshQueued: Bool { refreshWaiting != nil }
    var journalCount: Int { journal.count }
    var fetchesOutstanding: Int { fetching.count }

    // MARK: - Full refresh

    /// Ask the app for the identities and replace the store. Returns the number in the snapshot.
    /// `isEnabled`: the caller just read the state of the store and it is on.
    func refresh(_ send: (Data) async throws -> Data, isEnabled: Bool = false) async throws -> Int {
        let fetch = beginFetch()
        defer { endFetch(fetch) }
        let answer = try decodeAnswer(try await send(try encodeCall(IdentitiesCall())), as: IdentitiesAnswer.self)
        let identities = IdentitySync.makeIdentities(answer)
        if !isEnabled {
            guard await store.state().isEnabled else {
                return 0
            }
        }
        let completion = Completion()
        submit(Refresh(fetch: fetch, identities: identities, completion: completion))
        return try await completion.wait()?.get() ?? 0
    }

    // MARK: - One new passkey

    /// Make a passkey that Apassy just saved visible to the next sign-in sheet. Never throws: the
    /// passkey is already in the vault, so a system list that is off, failing, or slow must not
    /// fail the registration. Waits at most `timeout` for everything (the state, the queue behind
    /// an earlier operation, the save or the full replace); what is not done by then goes on in
    /// the background. With a system list that takes incremental updates it saves the one
    /// identity; otherwise it replaces the whole list from the app.
    func publish(_ passkey: PasskeyEntry, send: @escaping (Data) async throws -> Data, timeout: Duration) async {
        guard let identity = IdentitySync.passkeyIdentity(passkey) else { return }
        // Before the first await: any refresh that fetched earlier merges this passkey.
        publishedCount += 1
        let published = Published(sequence: publishedCount, identity: identity)
        journal.append(published)
        if journal.count > Self.journalLimit {
            let evicted = journal.count - Self.journalLimit
            evictedThrough = max(evictedThrough, journal[evicted - 1].sequence)
            journal.removeFirst(evicted)
        }

        let ended = Completion()
        Task {
            await self.publishNow(published, send: send)
            ended.finish(.success(0))
        }
        _ = await ended.wait(timeout: timeout)
    }

    private func publishNow(_ published: Published, send: @escaping (Data) async throws -> Data) async {
        let state = await store.state()
        guard state.isEnabled else { return }
        providerLog.info("the system list takes incremental updates: \(state.supportsIncrementalUpdates, privacy: .public)")
        if state.supportsIncrementalUpdates {
            let completion = Completion()
            savesWaiting.append(Save(published: published, completion: completion))
            if savesWaiting.count > Self.journalLimit { savesWaiting.removeFirst().completion.finish(.success(0)) }
            pump()
            if case .failure? = await completion.wait() {
                providerLog.info("the system list refused a new passkey")
            }
        } else {
            do {
                _ = try await refresh(send, isEnabled: true)
            } catch {
                providerLog.info("the system list was not replaced for a new passkey")
            }
        }
    }

    // MARK: - The queue

    private func beginFetch() -> Fetch {
        fetchCount += 1
        let fetch = Fetch(order: fetchCount, mark: publishedCount)
        fetching[fetch.order] = fetch.mark
        prune()
        return fetch
    }

    private func endFetch(_ fetch: Fetch) {
        fetching.removeValue(forKey: fetch.order)
        prune()
    }

    /// The journal is only for fetches that are still outstanding.
    private func prune() {
        let floor = fetching.values.min() ?? publishedCount
        journal.removeAll { $0.sequence <= floor }
    }

    private func submit(_ refresh: Refresh) {
        let count = refresh.identities.count
        // A snapshot from a fetch that began before the one already queued or applied is stale: it
        // could bring back what the owner deleted since.
        guard refresh.fetch.order > newestFetch else {
            refresh.completion.finish(.success(count))
            return
        }
        newestFetch = refresh.fetch.order
        if let older = refreshWaiting {
            older.completion.finish(.success(older.identities.count))
        }
        refreshWaiting = refresh
        pump()
    }

    /// Start the next store operation, if none is running.
    private func pump() {
        guard !busy else { return }
        if let refresh = refreshWaiting {
            refreshWaiting = nil
            // The journal lost passkeys published after this fetch began: the snapshot would drop them.
            guard refresh.fetch.mark >= evictedThrough else {
                refresh.completion.finish(.success(refresh.identities.count))
                pump()
                return
            }
            // The replace carries every passkey that was published after the fetch began. Saves
            // waiting now are either in it or older than the fetch (the snapshot decides).
            let saves = savesWaiting
            savesWaiting = []
            let identities = merged(refresh)
            busy = true
            Task {
                do {
                    try await self.store.replace(identities)
                    self.appliedMark = max(self.appliedMark, refresh.fetch.mark)
                    refresh.completion.finish(.success(refresh.identities.count))
                    for save in saves { save.completion.finish(.success(0)) }
                } catch {
                    refresh.completion.finish(.failure(error))
                    // The passkeys still need their own save.
                    self.savesWaiting = saves + self.savesWaiting
                }
                self.busy = false
                self.pump()
            }
        } else if !savesWaiting.isEmpty {
            // Also covers saves that entered the queue after the fresher replace was issued.
            let covered = savesWaiting.filter { $0.published.sequence <= appliedMark }
            let saves = savesWaiting.filter { $0.published.sequence > appliedMark }
            savesWaiting = []
            for save in covered { save.completion.finish(.success(0)) }
            guard !saves.isEmpty else { return }
            busy = true
            Task {
                do {
                    try await self.store.save(saves.map { $0.published.identity })
                    for save in saves { save.completion.finish(.success(1)) }
                } catch {
                    for save in saves { save.completion.finish(.failure(error)) }
                }
                self.busy = false
                self.pump()
            }
        }
    }

    private func merged(_ refresh: Refresh) -> [any ASCredentialIdentity] {
        let known = Set(refresh.identities.compactMap { ($0 as? ASPasskeyCredentialIdentity)?.credentialID })
        var seen = known
        var extra: [any ASCredentialIdentity] = []
        for entry in journal where entry.sequence > refresh.fetch.mark && seen.insert(entry.identity.credentialID).inserted {
            extra.append(entry.identity)
        }
        guard !extra.isEmpty else { return refresh.identities }
        return Array(refresh.identities.prefix(max(0, maxIdentities - extra.count))) + extra
    }
}

@MainActor
enum IdentitySync {
    /// Ask the app for the identities and replace the store. Returns the number stored.
    static func refresh(_ send: (Data) async throws -> Data, coordinator: IdentityCoordinator = .system) async throws -> Int {
        try await coordinator.refresh(send)
    }

    /// Make one passkey that Apassy just saved visible to the next sign-in sheet, without waiting
    /// for a full refresh. Never throws; waits at most `timeout`. See `IdentityCoordinator`.
    static func publish(
        _ passkey: PasskeyEntry, send: @escaping (Data) async throws -> Data, coordinator: IdentityCoordinator = .system,
        timeout: Duration = identityPublishTimeout
    ) async {
        await coordinator.publish(passkey, send: send, timeout: timeout)
    }

    static func passkeyIdentity(_ passkey: PasskeyEntry) -> ASPasskeyCredentialIdentity? {
        guard isRelyingPartyHost(passkey.rpId),
              let credential = wireBytes(passkey.credentialId, max: 1023),
              let handle = wireBytes(passkey.userHandle, max: 64)
        else {
            return nil
        }
        let name = visibleText(passkey.userName.isEmpty ? passkey.userDisplayName : passkey.userName, max: 128)
        return ASPasskeyCredentialIdentity(
            relyingPartyIdentifier: passkey.rpId, userName: name, credentialID: credential, userHandle: handle,
            recordIdentifier: String(passkey.id))
    }

    static func makeIdentities(_ answer: IdentitiesAnswer) -> [any ASCredentialIdentity] {
        var result: [any ASCredentialIdentity] = []
        for passkey in answer.passkeys {
            if let identity = passkeyIdentity(passkey) { result.append(identity) }
        }
        for login in answer.identities {
            guard let service = serviceIdentifier(login.host) else { continue }
            result.append(ASPasswordCredentialIdentity(
                serviceIdentifier: service, user: visibleText(login.username, max: 128), recordIdentifier: String(login.id)))
        }
        for code in answer.totp {
            guard let service = serviceIdentifier(code.host) else { continue }
            let label = visibleText(code.username.isEmpty ? code.title : code.username, max: 128)
            result.append(ASOneTimeCodeCredentialIdentity(
                serviceIdentifier: service, label: label, recordIdentifier: String(code.id)))
        }
        return Array(result.prefix(maxIdentities))
    }

    /// A host as the core writes it ("example.com" or "example.com:8443").
    static func serviceIdentifier(_ host: String) -> ASCredentialServiceIdentifier? {
        let parts = host.split(separator: ":", omittingEmptySubsequences: false)
        guard let name = parts.first, isRelyingPartyHost(String(name)) else { return nil }
        if parts.count == 1 {
            return ASCredentialServiceIdentifier(identifier: host, type: .domain)
        }
        guard parts.count == 2, let port = UInt16(parts[1]), port > 0 else { return nil }
        return ASCredentialServiceIdentifier(identifier: "https://\(host)", type: .URL)
    }

    static func isRelyingPartyHost(_ host: String) -> Bool {
        !host.isEmpty && host.utf8.count <= 253 && !host.hasPrefix(".") && !host.hasSuffix(".")
            && host.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x41 && $0 <= 0x5A) || $0 == 0x2D || $0 == 0x2E || $0 == 0x5F }
    }
}
