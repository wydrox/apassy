// Tests of the new passkey in the system list (native/ApassyAutoFill/IdentitySync.swift,
// ProviderModel.saveRegistration): the identity reaches the system list after the checked
// answer of the app and before macOS hears that the registration is done, a store that is off,
// failing, or slow never fails a saved passkey, and no older refresh drops the passkey (the
// races are held open with gates, not with sleeps). A fake app and fake stores: no vault, no
// system list.

import AuthenticationServices
import CryptoKit
import Foundation

/// A one-shot gate: tasks that wait are held until `open`.
@MainActor
final class Gate {
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func open() {
        isOpen = true
        let waiting = waiters
        waiters = []
        for continuation in waiting { continuation.resume() }
    }

    func wait() async {
        if isOpen { return }
        await withCheckedContinuation { waiters.append($0) }
    }
}

/// Polls a condition of the test (not an ordering: the order is held by gates).
@MainActor
func waitFor(_ what: String, _ condition: () -> Bool) async {
    for _ in 0..<5000 {
        if condition() { return }
        try? await Task.sleep(for: .milliseconds(1))
    }
    expect(false, "waited for \(what)")
}

@MainActor
final class EventLog {
    private(set) var events: [String] = []
    func add(_ event: String) { events.append(event) }
}

/// A store with the behavior of the real one for the lists: `replace` sets the list, `save`
/// upserts by credential ID. A call can be held at a gate while it is "inside the system"; it
/// applies only after the gate opens. Operations that overlap are counted.
@MainActor
final class ListIdentityStore: IdentityStoring {
    var enabled = true
    var incremental = true
    private(set) var list: [Data] = []
    private(set) var log: [String] = []
    private(set) var replaced: [[Data]] = []
    private(set) var running = 0
    private(set) var mostRunning = 0
    var stateGate: Gate?
    var replaceGate: Gate?
    var saveGate: Gate?
    var failNextReplace = false
    let stateEntered = Gate()
    let replaceEntered = Gate()
    private let events: EventLog?

    init(events: EventLog? = nil) {
        self.events = events
    }

    func state() async -> IdentityStoreState {
        events?.add("store.state")
        stateEntered.open()
        if let gate = stateGate {
            stateGate = nil
            await gate.wait()
        }
        return IdentityStoreState(isEnabled: enabled, supportsIncrementalUpdates: incremental)
    }

    func replace(_ identities: [any ASCredentialIdentity]) async throws {
        events?.add("store.replace")
        begin()
        defer { running -= 1 }
        replaceEntered.open()
        if let gate = replaceGate {
            replaceGate = nil
            await gate.wait()
        }
        if failNextReplace {
            failNextReplace = false
            log.append("replace.failed")
            throw ProviderFailure.failed("store")
        }
        list = ids(identities)
        replaced.append(list)
        log.append("replace(\(identities.count))")
    }

    func save(_ identities: [any ASCredentialIdentity]) async throws {
        events?.add("store.save")
        begin()
        if let gate = saveGate {
            saveGate = nil
            await gate.wait()
        }
        for id in ids(identities) where !list.contains(id) { list.append(id) }
        log.append("save(\(identities.count))")
        running -= 1
    }

    private func begin() {
        running += 1
        mostRunning = max(mostRunning, running)
    }

    private func ids(_ identities: [any ASCredentialIdentity]) -> [Data] {
        identities.compactMap { ($0 as? ASPasskeyCredentialIdentity)?.credentialID }
    }
}

/// The store of the first tests: off, failing, or hanging.
@MainActor
final class FakeIdentityStore: IdentityStoring {
    enum Mode { case enabled, disabled, failing, hanging }
    let mode: Mode
    let log: EventLog
    private(set) var saved: [[any ASCredentialIdentity]] = []
    private(set) var replaced: [[any ASCredentialIdentity]] = []

    init(_ mode: Mode, log: EventLog) {
        self.mode = mode
        self.log = log
    }

    func state() async -> IdentityStoreState {
        log.add("store.state")
        if mode == .hanging { try? await Task.sleep(for: .seconds(60)) }
        return IdentityStoreState(isEnabled: mode != .disabled, supportsIncrementalUpdates: true)
    }

    func replace(_ identities: [any ASCredentialIdentity]) async throws {
        log.add("store.replace")
        replaced.append(identities)
    }

    func save(_ identities: [any ASCredentialIdentity]) async throws {
        log.add("store.save")
        if mode == .failing { throw ProviderFailure.failed("store") }
        saved.append(identities)
    }
}

private func wireResult(_ result: [String: Any]) -> Data {
    json(["ok": true, "result": result])
}

private func opOf(_ body: Data) -> String {
    (try? JSONSerialization.jsonObject(with: body) as? [String: Any])?["op"] as? String ?? ""
}

/// The passkey of the number `n` as the app lists it, and as `publish` takes it.
private func passkeyEntry(_ n: UInt8, id: UInt64? = nil) -> PasskeyEntry {
    PasskeyEntry(
        id: id ?? UInt64(n), title: "", rpId: "example.com", userName: "user\(n)", userDisplayName: "user\(n)",
        credentialId: credentialData(n).base64EncodedString(), userHandle: Data([n]).base64EncodedString())
}

private func credentialData(_ n: UInt8) -> Data {
    Data(repeating: n, count: 16)
}

private func identitiesAnswer(_ numbers: [UInt8]) -> Data {
    wireResult([
        "identities": [], "totp": [],
        "passkeys": numbers.map { n in
            ["id": Int(n), "title": "", "rp_id": "example.com", "user_name": "user\(n)", "user_display_name": "user\(n)",
             "credential_id": credentialData(n).base64EncodedString(), "user_handle": Data([n]).base64EncodedString()]
        },
    ])
}

/// What a sign-in sheet sees: the system list. The fresh app, not the test, decides what is in it.
@MainActor
private func appSnapshot(_ numbers: [UInt8]) -> (Data) async throws -> Data {
    let answer = identitiesAnswer(numbers)
    return { _ in answer }
}

@MainActor
private func register(
    mode: FakeIdentityStore.Mode, appAnswer: @escaping (Data) -> Data?, attach: UInt64? = nil, existing: [[String: Any]] = []
) async -> (events: [String], outcome: ProviderOutcome?, store: FakeIdentityStore, registerCall: [String: Any]?) {
    let log = EventLog()
    let store = FakeIdentityStore(mode, log: log)
    var outcome: ProviderOutcome?
    var registerCall: [String: Any]?
    let model = ProviderModel(
        finish: { result in
            log.add("finish")
            outcome = result
        },
        send: { body in
            let op = opOf(body)
            log.add("app.\(op)")
            if op == "autofill_list" { return wireResult(["matches": existing, "others": []]) }
            if op == "passkey_register" { registerCall = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] }
            if let answer = appAnswer(body) { return answer }
            throw ProviderFailure.cancelled
        },
        identities: IdentityCoordinator(store: store))
    model.startRegistration(RegistrationRequest(
        rpID: "example.com", userName: "ada@example.com", userHandle: Data([9, 8, 7, 6]), clientDataHash: Data(repeating: 7, count: 32),
        algorithms: [-7], excluded: [], needsLargeBlob: false))
    for _ in 0..<200 {
        if case .register = model.screen { break }
        try? await Task.sleep(for: .milliseconds(10))
    }
    if let attach { model.attachTarget = attach }
    model.saveRegistration()
    for _ in 0..<400 where outcome == nil {
        try? await Task.sleep(for: .milliseconds(10))
        if case .problem = model.screen { break }
    }
    return (log.events, outcome, store, registerCall)
}

@MainActor
func identityPublishTests() async {
    let key = P256.Signing.PrivateKey()
    let newID = Data((0..<32).map { UInt8($0) })
    let attestation = attestationObject(rpID: "example.com", flags: 0x5D, credentialID: newID, point: key.publicKey.rawRepresentation)
    func good(_ body: Data) -> Data? {
        guard opOf(body) == "passkey_register" else { return nil }
        return wireResult(["id": 4, "credential_id": newID.base64EncodedString(), "attestation_object": attestation.base64EncodedString()])
    }

    // The happy path: state, then save, after the app answer and before the end.
    let happy = await register(mode: .enabled, appAnswer: good)
    expect(happy.events == ["app.autofill_list", "app.passkey_register", "store.state", "store.save", "finish"],
           "a new passkey is saved to the system list after the checked answer and before the end")
    if case .passkeyRegistration(let credential)? = happy.outcome {
        expect(credential.credentialID == newID && credential.relyingParty == "example.com", "the registration still ends with the new credential")
    } else {
        expect(false, "the registration still ends with the new credential")
    }
    let identity = happy.store.saved.first?.first as? ASPasskeyCredentialIdentity
    expect(happy.store.saved.count == 1 && happy.store.saved[0].count == 1, "one identity is saved, not the whole list")
    expect(identity?.relyingPartyIdentifier == "example.com" && identity?.userName == "ada@example.com"
           && identity?.credentialID == newID && identity?.userHandle == Data([9, 8, 7, 6]) && identity?.recordIdentifier == "4",
           "the saved identity keeps the website, the user name, the credential ID, the user handle, and the item ID")

    // Off, failing, or hanging store: the saved passkey still reaches macOS.
    let disabled = await register(mode: .disabled, appAnswer: good)
    expect(disabled.events == ["app.autofill_list", "app.passkey_register", "store.state", "finish"] && disabled.store.saved.isEmpty,
           "a disabled system list saves nothing and does not fail the registration")
    if case .passkeyRegistration? = disabled.outcome { expect(true, "disabled: registered") } else { expect(false, "disabled: registered") }
    let failing = await register(mode: .failing, appAnswer: good)
    expect(failing.events == ["app.autofill_list", "app.passkey_register", "store.state", "store.save", "finish"],
           "a failing system list does not fail the registration")
    if case .passkeyRegistration? = failing.outcome { expect(true, "failing: registered") } else { expect(false, "failing: registered") }

    // Nothing is published when the app refuses, or the answer fails the checks.
    let cancelled = await register(mode: .enabled, appAnswer: { _ in nil })
    expect(!cancelled.events.contains("store.state") && !cancelled.events.contains("store.save"), "a cancelled owner check publishes nothing")
    let other = await register(mode: .enabled, appAnswer: { body in
        guard opOf(body) == "passkey_register" else { return nil }
        return wireResult(["id": 4, "credential_id": Data([1, 2, 3]).base64EncodedString(), "attestation_object": attestation.base64EncodedString()])
    })
    expect(!other.events.contains("store.state") && !other.events.contains("store.save"), "an answer that fails the checks publishes nothing")
    expect(!other.events.contains("finish"), "an answer that fails the checks does not end as a registration")

    // A passkey attached to an existing login is published with the item ID of that login.
    let existingLogin: [String: Any] = [
        "id": 77, "title": "Example", "username": "ada@example.com", "website": "example.com", "has_totp": false, "revision": 3, "has_passkey": false,
    ]
    let attached = await register(mode: .enabled, appAnswer: { body in
        guard opOf(body) == "passkey_register" else { return nil }
        let attachID = ((try? JSONSerialization.jsonObject(with: body)) as? [String: Any])?["attach_id"] as? Int
        return wireResult(["id": attachID ?? 900, "credential_id": newID.base64EncodedString(), "attestation_object": attestation.base64EncodedString()])
    }, attach: 77, existing: [existingLogin])
    let attachedIdentity = attached.store.saved.first?.first as? ASPasskeyCredentialIdentity
    expect(attached.registerCall?["attach_id"] as? Int == 77 && attached.registerCall?["attach_revision"] as? Int == 3,
           "the registration asks the app to attach the passkey to the chosen login")
    expect(attachedIdentity?.recordIdentifier == "77" && attachedIdentity?.credentialID == newID,
           "a passkey attached to an existing login is published with the item ID of that login, not a new one")
    if case .passkeyRegistration? = attached.outcome { expect(true, "attach: registered") } else { expect(false, "attach: registered") }

    // A store that never answers waits only for the timeout.
    let slowLog = EventLog()
    let hanging = FakeIdentityStore(.hanging, log: slowLog)
    let start = ContinuousClock.now
    await IdentitySync.publish(
        passkeyEntry(4), send: { _ in throw ProviderFailure.cancelled }, coordinator: IdentityCoordinator(store: hanging), timeout: .milliseconds(100))
    expect(ContinuousClock.now - start < .seconds(5) && hanging.saved.isEmpty, "a system list that never answers is waited for only up to the timeout")

    // An entry that makes no valid identity is skipped without touching the store.
    let skippedLog = EventLog()
    let skipped = FakeIdentityStore(.enabled, log: skippedLog)
    await IdentitySync.publish(
        PasskeyEntry(id: 5, title: "", rpId: "bad host", userName: "x", userDisplayName: "x", credentialId: "AQID", userHandle: "AQID"),
        send: { _ in throw ProviderFailure.cancelled }, coordinator: IdentityCoordinator(store: skipped))
    expect(skippedLog.events.isEmpty, "an entry with an invalid website is not published")

    await nonIncrementalTests(newID: newID, attestation: attestation)
    await raceTests()
}

// MARK: - A system list that wants the whole list

@MainActor
private func nonIncrementalTests(newID: Data, attestation: Data) async {
    let events = EventLog()
    let store = ListIdentityStore(events: events)
    store.incremental = false
    var outcome: ProviderOutcome?
    let model = ProviderModel(
        finish: { result in
            events.add("finish")
            outcome = result
        },
        send: { body in
            let op = opOf(body)
            events.add("app.\(op)")
            switch op {
            case "autofill_list": return wireResult(["matches": [], "others": []])
            case "passkey_register":
                return wireResult(["id": 4, "credential_id": newID.base64EncodedString(), "attestation_object": attestation.base64EncodedString()])
            case "credential_identities":
                return wireResult([
                    "identities": [], "totp": [],
                    "passkeys": [["id": 3, "title": "", "rp_id": "example.com", "user_name": "old", "user_display_name": "old",
                                  "credential_id": credentialData(3).base64EncodedString(), "user_handle": Data([3]).base64EncodedString()],
                                 ["id": 4, "title": "", "rp_id": "example.com", "user_name": "ada@example.com", "user_display_name": "ada@example.com",
                                  "credential_id": newID.base64EncodedString(), "user_handle": Data([9, 8, 7, 6]).base64EncodedString()]],
                ])
            default: throw ProviderFailure.cancelled
            }
        },
        identities: IdentityCoordinator(store: store))
    model.startRegistration(RegistrationRequest(
        rpID: "example.com", userName: "ada@example.com", userHandle: Data([9, 8, 7, 6]), clientDataHash: Data(repeating: 7, count: 32),
        algorithms: [-7], excluded: [], needsLargeBlob: false))
    await waitFor("the registration form") { if case .register = model.screen { return true } else { return false } }
    model.saveRegistration()
    await waitFor("the end of the registration") { outcome != nil }
    expect(events.events == ["app.autofill_list", "app.passkey_register", "store.state", "app.credential_identities", "store.replace", "finish"],
           "a system list without incremental updates gets the whole list from the app, replaced, and no single save")
    expect(store.log == ["replace(2)"] && store.list == [credentialData(3), newID] && !events.events.contains("store.save"),
           "the whole list holds the old and the new passkey")
    if case .passkeyRegistration? = outcome { expect(true, "non-incremental: registered") } else { expect(false, "non-incremental: registered") }

    // The app cannot be asked (locked, gone): the registration is not failed, and nothing is saved.
    let blocked = ListIdentityStore()
    blocked.incremental = false
    await IdentitySync.publish(
        passkeyEntry(8), send: { _ in throw ProviderFailure.locked }, coordinator: IdentityCoordinator(store: blocked), timeout: .seconds(5))
    expect(blocked.log.isEmpty, "without incremental updates and without the app, nothing is saved")
}

// MARK: - Races with an older refresh

@MainActor
private func raceTests() async {
    let publishTimeout: Duration = .seconds(30)
    func app(_ n: UInt8) -> (Data) async throws -> Data { { _ in throw ProviderFailure.failed("no refresh expected for \(n)") } }

    // A1: a refresh took its snapshot (without the new passkey) and waits for its fetch to end;
    // the passkey is published; the old snapshot goes on to the store and still carries the passkey.
    do {
        let store = ListIdentityStore()
        let coordinator = IdentityCoordinator(store: store)
        let fetched = Gate()
        let hold = Gate()
        let earlier = Task { @MainActor in
            try await IdentitySync.refresh({ _ in
                let snapshot = identitiesAnswer([1, 2])
                fetched.open()
                await hold.wait()
                return snapshot
            }, coordinator: coordinator)
        }
        await fetched.wait()
        await IdentitySync.publish(passkeyEntry(9), send: app(9), coordinator: coordinator, timeout: publishTimeout)
        expect(store.list == [credentialData(9)], "A1: the passkey is in the system list before the older refresh goes on")
        hold.open()
        _ = try? await earlier.value
        expect(store.list == [credentialData(1), credentialData(2), credentialData(9)],
               "A1: an older snapshot taken before the publish replaces the list and keeps the new passkey")
        expect(store.log == ["save(1)", "replace(3)"] && store.mostRunning == 1, "A1: one store operation at a time, save then replace")
        expect(coordinator.journalCount == 0 && coordinator.fetchesOutstanding == 0, "A1: the journal is empty once the older fetch is over")
    }

    // A2: the same, with the refresh held at the state of the store (after its fetch).
    do {
        let store = ListIdentityStore()
        let coordinator = IdentityCoordinator(store: store)
        store.stateGate = Gate()
        let release = store.stateGate!
        let earlier = Task { @MainActor in try await IdentitySync.refresh(appSnapshot([1, 2]), coordinator: coordinator) }
        await store.stateEntered.wait()
        await IdentitySync.publish(passkeyEntry(9), send: app(9), coordinator: coordinator, timeout: publishTimeout)
        release.open()
        _ = try? await earlier.value
        expect(store.list == [credentialData(1), credentialData(2), credentialData(9)],
               "A2: a refresh held at the state of the store keeps the passkey published meanwhile")
    }

    // B1: the replace of the older snapshot is already inside the store (not yet applied) when the
    // passkey is published. The save waits for it, then lands: the passkey survives.
    do {
        let store = ListIdentityStore()
        let coordinator = IdentityCoordinator(store: store)
        let inside = Gate()
        store.replaceGate = inside
        let earlier = Task { @MainActor in try await IdentitySync.refresh(appSnapshot([1, 2]), coordinator: coordinator) }
        await store.replaceEntered.wait()
        let published = Task { @MainActor in
            await IdentitySync.publish(passkeyEntry(9), send: app(9), coordinator: coordinator, timeout: publishTimeout)
        }
        await waitFor("the save to queue behind the replace") { coordinator.queuedSaves == 1 }
        expect(store.log.isEmpty && store.running == 1, "B1: no save is issued while the replace is inside the store")
        inside.open()
        _ = try? await earlier.value
        await published.value
        expect(store.log == ["replace(2)", "save(1)"] && store.mostRunning == 1, "B1: the save lands after the replace, never beside it")
        expect(store.list == [credentialData(1), credentialData(2), credentialData(9)], "B1: the passkey survives a replace that was already issued")
    }

    // B2: the same replace hangs longer than the publish waits. The registration ends on time,
    // and the save still lands when the replace returns.
    do {
        let store = ListIdentityStore()
        let coordinator = IdentityCoordinator(store: store)
        let inside = Gate()
        store.replaceGate = inside
        let earlier = Task { @MainActor in try await IdentitySync.refresh(appSnapshot([1, 2]), coordinator: coordinator) }
        await store.replaceEntered.wait()
        let start = ContinuousClock.now
        await IdentitySync.publish(passkeyEntry(9), send: app(9), coordinator: coordinator, timeout: .milliseconds(100))
        expect(ContinuousClock.now - start < .seconds(5), "B2: the publish is bounded although an earlier store operation hangs")
        expect(coordinator.queuedSaves == 1 && store.list.isEmpty, "B2: the passkey is still queued, nothing was written meanwhile")
        inside.open()
        _ = try? await earlier.value
        await waitFor("the queued save") { store.list.contains(credentialData(9)) }
        expect(store.list == [credentialData(1), credentialData(2), credentialData(9)] && store.mostRunning == 1,
               "B2: the queued save lands after the hung replace returns")
    }

    // B3: replace inside the store, passkey queued, then a fresh refresh (fetched after the publish)
    // without the passkey, because the owner deleted it. The fresh view wins, nothing is resurrected.
    do {
        let store = ListIdentityStore()
        let coordinator = IdentityCoordinator(store: store)
        let inside = Gate()
        store.replaceGate = inside
        let earlier = Task { @MainActor in try await IdentitySync.refresh(appSnapshot([1, 2]), coordinator: coordinator) }
        await store.replaceEntered.wait()
        let published = Task { @MainActor in
            await IdentitySync.publish(passkeyEntry(9), send: app(9), coordinator: coordinator, timeout: publishTimeout)
        }
        await waitFor("the save to queue behind the replace") { coordinator.queuedSaves == 1 }
        let fresh = Task { @MainActor in try await IdentitySync.refresh(appSnapshot([1, 2]), coordinator: coordinator) }
        await waitFor("the fresh refresh to queue") { coordinator.refreshQueued }
        inside.open()
        _ = try? await earlier.value
        _ = try? await fresh.value
        await published.value
        expect(store.log == ["replace(2)", "replace(2)"] && store.list == [credentialData(1), credentialData(2)] && store.mostRunning == 1,
               "B3: a fresh refresh after the publish decides; the deleted passkey is not saved again")
    }

    // R1/R1b: publish waits at state(), while a fresher snapshot omits the deleted passkey.
    // Release state either after the replace or while it is in flight. Await the publisher
    // itself so the final assertion cannot race with the late save.
    for duringReplace in [false, true] {
        let label = duringReplace ? "R1b" : "R1"
        let store = ListIdentityStore()
        let coordinator = IdentityCoordinator(store: store)
        let stateHeld = Gate()
        store.stateGate = stateHeld
        let published = Task { @MainActor in
            await IdentitySync.publish(passkeyEntry(9), send: app(9), coordinator: coordinator, timeout: publishTimeout)
        }
        await store.stateEntered.wait()
        let inside = Gate()
        if duringReplace { store.replaceGate = inside }
        let fresh = Task { @MainActor in try await IdentitySync.refresh(appSnapshot([1]), coordinator: coordinator) }
        if duringReplace {
            await store.replaceEntered.wait()
            stateHeld.open()
            await waitFor("late save queued behind the fresh replace") { coordinator.queuedSaves == 1 }
            inside.open()
        }
        let count = try? await fresh.value
        stateHeld.open()
        await published.value
        expect(count == 1 && store.log == ["replace(1)"] && store.list == [credentialData(1)] && store.mostRunning == 1,
               "\(label): a late state answer cannot resurrect a passkey omitted by a successful fresh replace")
        expect(coordinator.queuedSaves == 0 && store.running == 0, "\(label): the covered save completes without issuing a store write")
    }

    // R1c/R1d: a fresh replace that fails has not decided the system list. The late save
    // is still necessary, whether state returns after the failure or during the replace.
    for duringReplace in [false, true] {
        let label = duringReplace ? "R1d" : "R1c"
        let store = ListIdentityStore()
        let coordinator = IdentityCoordinator(store: store)
        let stateHeld = Gate()
        store.stateGate = stateHeld
        store.failNextReplace = true
        let published = Task { @MainActor in
            await IdentitySync.publish(passkeyEntry(9), send: app(9), coordinator: coordinator, timeout: publishTimeout)
        }
        await store.stateEntered.wait()
        let inside = Gate()
        if duringReplace { store.replaceGate = inside }
        let fresh = Task { @MainActor in try await IdentitySync.refresh(appSnapshot([1]), coordinator: coordinator) }
        if duringReplace {
            await store.replaceEntered.wait()
            stateHeld.open()
            await waitFor("late save queued behind the failing fresh replace") { coordinator.queuedSaves == 1 }
            inside.open()
        }
        let count = try? await fresh.value
        stateHeld.open()
        await published.value
        expect(count == nil && store.log == ["replace.failed", "save(1)"] && store.list == [credentialData(9)] && store.mostRunning == 1,
               "\(label): a failed fresh replace does not suppress the still-needed late save")
    }

    // D1: published, saved, then deleted in the vault; the next refresh omits it.
    do {
        let store = ListIdentityStore()
        let coordinator = IdentityCoordinator(store: store)
        await IdentitySync.publish(passkeyEntry(9), send: app(9), coordinator: coordinator, timeout: publishTimeout)
        _ = try? await IdentitySync.refresh(appSnapshot([1]), coordinator: coordinator)
        expect(store.list == [credentialData(1)], "D1: a refresh after the publish removes a passkey that is gone from the vault")
    }

    // D2: an older refresh (fetched before the publish) is still waiting while a fresh refresh
    // (after the publish, without the deleted passkey) is applied; the older one is dropped, not applied.
    do {
        let store = ListIdentityStore()
        let coordinator = IdentityCoordinator(store: store)
        let fetched = Gate()
        let hold = Gate()
        let older = Task { @MainActor in
            try await IdentitySync.refresh({ _ in
                let snapshot = identitiesAnswer([1, 2])
                fetched.open()
                await hold.wait()
                return snapshot
            }, coordinator: coordinator)
        }
        await fetched.wait()
        await IdentitySync.publish(passkeyEntry(9), send: app(9), coordinator: coordinator, timeout: publishTimeout)
        _ = try? await IdentitySync.refresh(appSnapshot([1]), coordinator: coordinator)
        hold.open()
        let count = try? await older.value
        expect(count == 2 && store.log == ["save(1)", "replace(1)"] && store.list == [credentialData(1)],
               "D2: an older snapshot arriving after a fresher one is dropped, and the deleted passkey stays deleted")
        expect(coordinator.journalCount == 0 && coordinator.fetchesOutstanding == 0, "D2: nothing is kept after the fetches end")
    }

    // R2/J: the first eviction (65 keys) and repeated evictions (70 keys) keep a bounded
    // journal. An older snapshot cannot replace the list using an incomplete journal.
    for extra in [1, 6] {
        let label = extra == 1 ? "R2" : "J"
        let numbers = Array(UInt8(1)...UInt8(IdentityCoordinator.journalLimit + extra))
        let store = ListIdentityStore()
        let coordinator = IdentityCoordinator(store: store)
        let fetched = Gate()
        let hold = Gate()
        let older = Task { @MainActor in
            try await IdentitySync.refresh({ _ in
                fetched.open()
                await hold.wait()
                return identitiesAnswer([])
            }, coordinator: coordinator)
        }
        await fetched.wait()
        for n in numbers {
            await IdentitySync.publish(passkeyEntry(n), send: app(n), coordinator: coordinator, timeout: publishTimeout)
        }
        expect(coordinator.journalCount == IdentityCoordinator.journalLimit, "\(label): the journal never holds more than its limit")
        expect(store.list == numbers.map(credentialData), "\(label): every published passkey is saved before the older fetch returns")
        hold.open()
        _ = try? await older.value
        expect(store.list == numbers.map(credentialData) && store.replaced.isEmpty,
               "\(label): dropping an older snapshot preserves all passkeys, including those evicted from the journal")
        expect(coordinator.journalCount == 0 && coordinator.fetchesOutstanding == 0,
               "\(label): the journal is empty when no fetch is outstanding")
    }

    await modelRaceTest()
}

/// The same race end to end: an earlier request of the process (a sign-in sheet) starts its quiet
/// refresh, a registration of the same process publishes, the old snapshot goes on to the store.
@MainActor
private func modelRaceTest() async {
    let key = P256.Signing.PrivateKey()
    let newID = Data((0..<32).map { UInt8($0) })
    let attestation = attestationObject(rpID: "example.com", flags: 0x5D, credentialID: newID, point: key.publicKey.rawRepresentation)
    let store = ListIdentityStore()
    let coordinator = IdentityCoordinator(store: store)
    let fetched = Gate()
    let hold = Gate()
    let earlier = ProviderModel(finish: { _ in }, send: { body in
        switch opOf(body) {
        case "credential_identities":
            let snapshot = identitiesAnswer([1])
            fetched.open()
            await hold.wait()
            return snapshot
        case "passkey_list": return wireResult(["passkeys": []])
        default: return wireResult(["matches": [], "others": []])
        }
    }, identities: coordinator)
    earlier.startPasskeyList(domains: ["example.com"], request: AssertionRequest(rpID: "example.com", clientDataHash: Data(repeating: 7, count: 32), allowed: []))
    await fetched.wait()
    earlier.cancel()

    let finished = Gate()
    let registration = ProviderModel(finish: { _ in finished.open() }, send: { body in
        switch opOf(body) {
        case "passkey_register":
            return wireResult(["id": 4, "credential_id": newID.base64EncodedString(), "attestation_object": attestation.base64EncodedString()])
        default: return wireResult(["matches": [], "others": []])
        }
    }, identities: coordinator)
    registration.startRegistration(RegistrationRequest(
        rpID: "example.com", userName: "ada@example.com", userHandle: Data([9, 8, 7, 6]), clientDataHash: Data(repeating: 7, count: 32),
        algorithms: [-7], excluded: [], needsLargeBlob: false))
    await waitFor("the registration form") { if case .register = registration.screen { return true } else { return false } }
    registration.saveRegistration()
    await finished.wait()
    expect(store.list == [newID], "M: the new passkey is in the system list when the registration ends")
    hold.open()
    await waitFor("the older refresh to replace") { store.log.count == 2 }
    expect(store.list.contains(newID) && store.list.contains(credentialData(1)),
           "M: the quiet refresh of an earlier request, ended after the registration, keeps the new passkey")
}
