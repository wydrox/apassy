import CryptoKit
import Foundation

/// Answer keys in memory, for previews and tests. They are never written to the keychain, and
/// no check of the wrist runs: `refusesWrist` stands in for a locked watch or one off the wrist.
public final class MemoryWatchAnswerKeys: WatchAnswerKeys, @unchecked Sendable {
    private let lock = NSLock()
    private var keys: [String: P256.Signing.PrivateKey] = [:]
    private var refuses: Bool
    private var signatures = 0
    public let canSign: Bool
    /// How long a check of the wrist takes.
    private let checkTime: Duration

    public init(canSign: Bool = true, refusesWrist: Bool = false, checkTime: Duration = .zero) {
        self.canSign = canSign
        self.refuses = refusesWrist
        self.checkTime = checkTime
    }

    /// The number of signatures so far.
    public var signatureCount: Int { lock.withLock { signatures } }

    public func setRefusesWrist(_ value: Bool) { lock.withLock { refuses = value } }

    public func create(team: String) throws -> Data {
        let key = P256.Signing.PrivateKey()
        lock.withLock { keys[team] = key }
        return key.publicKey.x963Representation
    }

    public func publicKey(team: String) -> Data? {
        lock.withLock { keys[team]?.publicKey.x963Representation }
    }

    public func delete(team: String) { _ = lock.withLock { keys.removeValue(forKey: team) } }

    public func attempt(team: String) -> any WatchSigningAttempt { Attempt(keys: self, team: team) }

    fileprivate func sign(_ message: Data, team: String) throws -> Data {
        try lock.withLock {
            guard !refuses else { throw WatchKeyError.notOnWrist }
            guard let key = keys[team] else { throw WatchKeyError.noKey }
            signatures += 1
            return try key.signature(for: message).derRepresentation
        }
    }

    fileprivate var wristCheckTime: Duration { checkTime }

    private final class Attempt: WatchSigningAttempt, @unchecked Sendable {
        private let keys: MemoryWatchAnswerKeys
        private let team: String
        private let lock = NSLock()
        private var ended = false

        init(keys: MemoryWatchAnswerKeys, team: String) {
            self.keys = keys
            self.team = team
        }

        func sign(_ message: Data) async throws -> Data {
            guard !lock.withLock({ ended }) else { throw WatchKeyError.cancelled }
            if keys.wristCheckTime > .zero {
                try? await Task.sleep(for: keys.wristCheckTime)
            }
            defer { cancel() }
            guard !lock.withLock({ ended }) else { throw WatchKeyError.cancelled }
            return try keys.sign(message, team: team)
        }

        func cancel() { lock.withLock { ended = true } }
    }
}
