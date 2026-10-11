import Foundation

/// The App Group and the shared keychain of the app and its AutoFill extension
/// (ADR 0023). Both targets have the same entitlements.
public enum SharedContainer {
    /// The App Group of the app and the extension.
    public static let appGroup = "group.com.wydrox.apassy.companion"

    /// The keychain access group, without the team prefix.
    public static let keychainGroupSuffix = "com.wydrox.apassy.shared"

    /// The keychain access group with the team prefix of this build (Info.plist key
    /// `ApassyAppIdentifierPrefix`, set to `$(AppIdentifierPrefix)`). nil in `swift test`.
    public static var keychainGroup: String? {
        guard let prefix = Bundle.main.object(forInfoDictionaryKey: "ApassyAppIdentifierPrefix") as? String,
            !prefix.isEmpty, !prefix.hasPrefix("$(")
        else { return nil }
        return prefix + keychainGroupSuffix
    }

    /// `Library/Application Support/Apassy` in the App Group container: the data folder
    /// of the core. nil when the App Group is not in the entitlements.
    public static func dataDirectory() -> URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)?
            .appending(path: "Library/Application Support/Apassy", directoryHint: .isDirectory)
    }

    /// The settings shared by the app and the extension.
    public static var defaults: UserDefaults {
        UserDefaults(suiteName: appGroup) ?? .standard
    }
}

/// Keeps the passphrase of each vault in the keychain behind Face ID (ADR 0023): the
/// item has `.biometryCurrentSet` and `WhenPasscodeSetThisDeviceOnly`, so it never
/// leaves this iPhone, needs a Face ID match for each read, and is gone after a new
/// Face ID enrollment or when the passcode is turned off. The app and the extension
/// share it through the keychain access group.
public protocol PassphraseStore: Sendable {
    /// Whether a passphrase is stored for the vault. Never asks for Face ID.
    func hasPassphrase(vaultID: String) -> Bool
    /// Store or replace the passphrase. Never asks for Face ID.
    func save(_ passphrase: String, vaultID: String) throws
    /// Read the passphrase after a Face ID match. `reason` is the text of the prompt.
    /// Throws `VaultError(.cancelled, …)` when the owner cancels, and
    /// `VaultError(.locked, …)` when the item is gone (a new Face ID enrollment).
    func read(vaultID: String, reason: String) async throws -> String
    /// Remove the passphrase.
    func remove(vaultID: String)
}

/// The kind of biometry of this iPhone, for the texts ("Face ID", "Touch ID").
public enum Biometry: Sendable, Equatable {
    case faceID, touchID, opticID, none

    public var name: String {
        switch self {
        case .faceID: "Face ID"
        case .touchID: "Touch ID"
        case .opticID: "Optic ID"
        case .none: "Passcode"
        }
    }

    public var symbol: String {
        switch self {
        case .faceID: "faceid"
        case .touchID: "touchid"
        case .opticID: "opticid"
        case .none: "lock"
        }
    }
}

/// The owner check before a secret leaves the vault: a reveal, a copy, a fill
/// (ADR 0023, as ADR 0021 for the browser). A fresh biometric match each time, with
/// no reuse window. Without biometry the app asks for the passphrase instead, and
/// checks it with `VaultService.checkPassphrase`.
public protocol OwnerCheck: Sendable {
    /// The biometry of this iPhone, or `.none` when it is not set up.
    var biometry: Biometry { get }
    /// Ask for Face ID (or Touch ID). True on a match; false when the owner cancels or
    /// biometry is not available (the caller then asks for the passphrase).
    func confirm(reason: String) async -> Bool
}
