import Foundation
import Testing
@testable import ApassyVaultKit

@Suite struct KeychainHistoryKeyStoreTests {
    private let vaultID = "4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c"
    private let secondVaultID = "5f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c"

    @Test func createsOnceAndReusesPersistedKeyAcrossStoreInstances() {
        let fake = FakeHistoryKeyBackend()
        let first = KeychainHistoryKeyStore(backend: fake.backend)
        let key = first.key(vaultID: vaultID, mayCreate: true)
        #expect(key == .key(Data(repeating: 1, count: 32)))
        #expect(first.key(vaultID: vaultID, mayCreate: true) == key)
        let reopened = KeychainHistoryKeyStore(backend: fake.backend)
        #expect(reopened.key(vaultID: vaultID, mayCreate: false) == key)
        #expect(fake.snapshot.generated == 1)
        #expect(fake.snapshot.added == [vaultID])
    }

    @Test func missingWithoutPermissionNeverGeneratesOrWrites() {
        let fake = FakeHistoryKeyBackend()
        let store = KeychainHistoryKeyStore(backend: fake.backend)
        #expect(store.key(vaultID: vaultID, mayCreate: false) == .missing)
        #expect(fake.snapshot.generated == 0)
        #expect(fake.snapshot.added.isEmpty)
        #expect(fake.snapshot.keys.isEmpty)
    }

    @Test func readFailureDoesNotResetAnExistingKey() {
        let original = Data(repeating: 42, count: 32)
        let fake = FakeHistoryKeyBackend(keys: [vaultID: original], readUnavailable: true)
        let store = KeychainHistoryKeyStore(backend: fake.backend)
        #expect(store.key(vaultID: vaultID, mayCreate: true) == .unavailable)
        #expect(fake.snapshot.keys == [vaultID: original])
        #expect(fake.snapshot.generated == 0)
        #expect(fake.snapshot.added.isEmpty)
    }

    @Test(arguments: [0, 31, 33]) func corruptLengthNeverReplacesKey(count: Int) {
        let corrupt = Data(repeating: 42, count: count)
        let fake = FakeHistoryKeyBackend(keys: [vaultID: corrupt])
        let store = KeychainHistoryKeyStore(backend: fake.backend)
        #expect(store.key(vaultID: vaultID, mayCreate: true) == .unavailable)
        #expect(fake.snapshot.keys == [vaultID: corrupt])
        #expect(fake.snapshot.generated == 0)
        #expect(fake.snapshot.added.isEmpty)
    }

    @Test func duplicateAddRereadsWinnerInsteadOfReturningUnpersistedCandidate() {
        let winner = Data(repeating: 99, count: 32)
        let fake = FakeHistoryKeyBackend(duplicateWinner: winner)
        let store = KeychainHistoryKeyStore(backend: fake.backend)
        #expect(store.key(vaultID: vaultID, mayCreate: true) == .key(winner))
        #expect(fake.snapshot.keys[vaultID] == winner)
        #expect(fake.snapshot.read == [vaultID, vaultID])
        #expect(fake.snapshot.generated == 1)
    }

    @Test func duplicateAddWithCorruptWinnerFailsWithoutReplacingIt() {
        let corrupt = Data(repeating: 99, count: 31)
        let fake = FakeHistoryKeyBackend(duplicateWinner: corrupt)
        let store = KeychainHistoryKeyStore(backend: fake.backend)
        #expect(store.key(vaultID: vaultID, mayCreate: true) == .unavailable)
        #expect(fake.snapshot.keys[vaultID] == corrupt)
        #expect(fake.snapshot.added == [vaultID])
    }

    @Test func differentVaultsKeepIndependentKeysAndExactAccountBinding() {
        let fake = FakeHistoryKeyBackend()
        let store = KeychainHistoryKeyStore(backend: fake.backend)
        #expect(store.key(vaultID: vaultID, mayCreate: true) == .key(Data(repeating: 1, count: 32)))
        #expect(store.key(vaultID: secondVaultID, mayCreate: true) == .key(Data(repeating: 2, count: 32)))
        #expect(store.key(vaultID: vaultID, mayCreate: false) == .key(Data(repeating: 1, count: 32)))
        #expect(fake.snapshot.added == [vaultID, secondVaultID])
        #expect(fake.snapshot.keys.count == 2)
    }

    @Test func failedAddDoesNotReturnOrPretendToPersistCandidate() {
        let fake = FakeHistoryKeyBackend(addUnavailable: true)
        let store = KeychainHistoryKeyStore(backend: fake.backend)
        #expect(store.key(vaultID: vaultID, mayCreate: true) == .unavailable)
        #expect(fake.snapshot.keys.isEmpty)
    }

    @Test func failedRandomGenerationDoesNotWrite() {
        let fake = FakeHistoryKeyBackend(randomUnavailable: true)
        let store = KeychainHistoryKeyStore(backend: fake.backend)
        #expect(store.key(vaultID: vaultID, mayCreate: true) == .unavailable)
        #expect(fake.snapshot.added.isEmpty)
    }

    @Test(arguments: [String(repeating: "a", count: 16), String(repeating: "f", count: 64),
                      "01234567-89ab-cdef", String(repeating: "-", count: 16)])
    func acceptsCoreCompatibleLegacyVaultIDs(id: String) {
        let fake = FakeHistoryKeyBackend()
        let store = KeychainHistoryKeyStore(backend: fake.backend)
        #expect(KeychainHistoryKeyStore.isValidVaultID(id))
        #expect(store.key(vaultID: id, mayCreate: false) == .missing)
        #expect(fake.snapshot.read == [id])
    }

    @Test(arguments: ["", String(repeating: "a", count: 15), String(repeating: "a", count: 65),
                      "0123456789abcdeF", "0123456789abcdeg", "../0123456789abcdef",
                      "0123456789abcde\n", "0123456789abcdé", "0123456789abcde\0"])
    func invalidVaultIDsNeverReachBackend(id: String) {
        let fake = FakeHistoryKeyBackend()
        let store = KeychainHistoryKeyStore(backend: fake.backend)
        #expect(!KeychainHistoryKeyStore.isValidVaultID(id))
        #expect(store.key(vaultID: id, mayCreate: true) == .unavailable)
        #expect(fake.snapshot.read.isEmpty)
        #expect(fake.snapshot.generated == 0)
        #expect(fake.snapshot.added.isEmpty)
    }
}

/// Every test supplies this backend explicitly; none can call Security APIs.
private final class FakeHistoryKeyBackend: @unchecked Sendable {
    struct State {
        var keys: [String: Data]
        var read: [String] = []
        var added: [String] = []
        var generated = 0
    }

    private let lock = NSLock()
    private var state: State
    private let readUnavailable: Bool
    private let addUnavailable: Bool
    private let randomUnavailable: Bool
    private let duplicateWinner: Data?

    init(keys: [String: Data] = [:], readUnavailable: Bool = false, addUnavailable: Bool = false,
         randomUnavailable: Bool = false, duplicateWinner: Data? = nil) {
        state = State(keys: keys)
        self.readUnavailable = readUnavailable
        self.addUnavailable = addUnavailable
        self.randomUnavailable = randomUnavailable
        self.duplicateWinner = duplicateWinner
    }

    var snapshot: State { lock.withLock { state } }

    var backend: KeychainHistoryKeyStore.Backend {
        .init(read: { [self] id in
            lock.withLock {
                state.read.append(id)
                if readUnavailable { return .unavailable }
                return state.keys[id].map { .value($0) } ?? .missing
            }
        }, add: { [self] id, key in
            lock.withLock {
                state.added.append(id)
                if addUnavailable { return .unavailable }
                if let duplicateWinner {
                    state.keys[id] = duplicateWinner
                    return .duplicate
                }
                guard state.keys[id] == nil else { return .duplicate }
                state.keys[id] = key
                return .added
            }
        }, randomKey: { [self] in
            lock.withLock {
                state.generated += 1
                return randomUnavailable ? nil : Data(repeating: UInt8(state.generated), count: 32)
            }
        })
    }
}
