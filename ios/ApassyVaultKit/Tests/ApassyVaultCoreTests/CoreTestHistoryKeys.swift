import ApassyVaultKit
import Foundation

/// Synthetic device-local keys for core integration tests. No Security API is used.
/// Keep this object across service restarts to model the same device's Keychain.
final class CoreTestHistoryKeys: @unchecked Sendable {
    struct Snapshot {
        let readVaultIDs: [String]
        let createdVaultIDs: [String]
        let generationCount: Int
    }

    private let lock = NSLock()
    private var keys: [String: Data] = [:]
    private var readVaultIDs: [String] = []
    private var createdVaultIDs: [String] = []
    private var generationCount = 0

    var snapshot: Snapshot {
        lock.withLock {
            Snapshot(readVaultIDs: readVaultIDs, createdVaultIDs: createdVaultIDs,
                     generationCount: generationCount)
        }
    }

    var store: KeychainHistoryKeyStore {
        KeychainHistoryKeyStore(backend: .init(read: { [self] vaultID in
            lock.withLock {
                readVaultIDs.append(vaultID)
                return keys[vaultID].map { .value($0) } ?? .missing
            }
        }, add: { [self] vaultID, key in
            lock.withLock {
                guard keys[vaultID] == nil else { return .duplicate }
                keys[vaultID] = key
                createdVaultIDs.append(vaultID)
                return .added
            }
        }, randomKey: { [self] in
            lock.withLock {
                generationCount += 1
                return Data(repeating: UInt8(truncatingIfNeeded: generationCount), count: 32)
            }
        }))
    }
}
