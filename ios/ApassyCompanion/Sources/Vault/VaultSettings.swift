import ApassyVaultKit
import Foundation
import Observation

/// How long the vault stays unlocked after the owner leaves the app.
enum LockAfter: Int, CaseIterable, Identifiable, Sendable {
    case immediately = 0
    case oneMinute = 60
    case fiveMinutes = 300
    case fifteenMinutes = 900
    case oneHour = 3600

    var id: Int { rawValue }

    var label: String {
        switch self {
        case .immediately: "Immediately"
        case .oneMinute: "1 minute"
        case .fiveMinutes: "5 minutes"
        case .fifteenMinutes: "15 minutes"
        case .oneHour: "1 hour"
        }
    }

    /// Whether the vault locks on return, after the app was left at `leftAt`. "Immediately" locks
    /// when the app goes to the background; on return it locks too, in case that did not happen.
    /// The times are of the continuous clock: it counts while the iPhone sleeps, and setting the
    /// clock of the iPhone back does not move it.
    func locks(leftAt: ContinuousClock.Instant?, now: ContinuousClock.Instant) -> Bool {
        guard let leftAt else { return false }
        return now - leftAt >= .seconds(rawValue)
    }
}

/// How long a copied secret stays on the pasteboard.
enum ClearAfter: Int, CaseIterable, Identifiable, Sendable {
    case thirtySeconds = 30
    case oneMinute = 60
    case ninetySeconds = 90
    case twoMinutes = 120
    case fiveMinutes = 300

    var id: Int { rawValue }
    var seconds: TimeInterval { TimeInterval(rawValue) }

    var label: String {
        switch self {
        case .thirtySeconds: "30 seconds"
        case .oneMinute: "1 minute"
        case .ninetySeconds: "90 seconds"
        case .twoMinutes: "2 minutes"
        case .fiveMinutes: "5 minutes"
        }
    }
}

/// The settings of the vault on this iPhone, in the defaults that the app shares with the AutoFill
/// extension. No secret is kept here: item IDs, choices, and the name of this iPhone.
@MainActor
@Observable
final class VaultSettings {
    private enum Key {
        static let lockAfter = "lockAfter"
        static let clearAfter = "clearCopiedAfter"
        static let deviceName = "deviceName"
        static func favorites(_ vaultID: String) -> String { "favorites.\(vaultID)" }
        static func faceIDUnlock(_ vaultID: String) -> String { "faceIDUnlock.\(vaultID)" }
    }

    @ObservationIgnored private let defaults: UserDefaults

    var lockAfter: LockAfter {
        didSet { defaults.set(lockAfter.rawValue, forKey: Key.lockAfter) }
    }

    var clearAfter: ClearAfter {
        didSet { defaults.set(clearAfter.rawValue, forKey: Key.clearAfter) }
    }

    /// The name of this iPhone that the owner confirmed when joining a vault.
    var deviceName: String? {
        didSet { defaults.set(deviceName, forKey: Key.deviceName) }
    }

    /// Bumped on each change of the favorites or the Face ID choice, so views that read them update.
    private(set) var storeVersion = 0

    init(defaults: UserDefaults) {
        self.defaults = defaults
        lockAfter = LockAfter(rawValue: defaults.object(forKey: Key.lockAfter) as? Int ?? 0) ?? .immediately
        clearAfter = ClearAfter(rawValue: defaults.object(forKey: Key.clearAfter) as? Int ?? 60) ?? .oneMinute
        deviceName = defaults.string(forKey: Key.deviceName)
    }

    // MARK: Favorites

    /// The favorite items of a vault, in the order the owner added them.
    func favorites(vaultID: String) -> [UInt64] {
        _ = storeVersion
        let stored = defaults.array(forKey: Key.favorites(vaultID)) as? [NSNumber] ?? []
        return stored.map(\.uint64Value)
    }

    func setFavorites(_ ids: [UInt64], vaultID: String) {
        defaults.set(ids.map { NSNumber(value: $0) }, forKey: Key.favorites(vaultID))
        storeVersion += 1
    }

    func isFavorite(_ id: UInt64, vaultID: String) -> Bool {
        favorites(vaultID: vaultID).contains(id)
    }

    func toggleFavorite(_ id: UInt64, vaultID: String) {
        var ids = favorites(vaultID: vaultID)
        if let index = ids.firstIndex(of: id) { ids.remove(at: index) } else { ids.append(id) }
        setFavorites(ids, vaultID: vaultID)
    }

    // MARK: Face ID unlock

    /// Whether the owner turned on "Unlock with Face ID" for the vault. The passphrase itself is
    /// in the keychain (`PassphraseStore`); this flag remembers the choice when iOS dropped the
    /// keychain item after a new Face ID enrollment, so the app can store it again.
    func faceIDUnlock(vaultID: String) -> Bool {
        _ = storeVersion
        return defaults.bool(forKey: Key.faceIDUnlock(vaultID))
    }

    func setFaceIDUnlock(_ on: Bool, vaultID: String) {
        defaults.set(on, forKey: Key.faceIDUnlock(vaultID))
        storeVersion += 1
    }

    /// Forget everything of a vault that left this iPhone.
    func forget(vaultID: String) {
        defaults.removeObject(forKey: Key.favorites(vaultID))
        defaults.removeObject(forKey: Key.faceIDUnlock(vaultID))
        storeVersion += 1
    }
}
