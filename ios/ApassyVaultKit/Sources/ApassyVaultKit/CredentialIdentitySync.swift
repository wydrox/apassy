#if os(iOS)
import AuthenticationServices

/// The logins that iOS shows in the QuickType bar (ADR 0023): a username and a host per
/// website, never a password. The app replaces them after each unlock, save, and sync
/// that changed the vault; the AutoFill extension fills only after Face ID.
public enum CredentialIdentitySync {
    /// Replace every identity of Apassy with `identities` of the vault `vaultID`. The
    /// record identifier of each is `<vaultID>:<item id>`.
    public static func replace(with identities: [CredentialIdentity], vaultID: String) async {
        // Written with the AutoFill extension.
    }

    /// Remove every identity of Apassy (the vault left this iPhone).
    public static func removeAll() async {
        // Written with the AutoFill extension.
    }

    /// The item of a record identifier, when it belongs to `vaultID`.
    public static func itemID(of recordIdentifier: String?, vaultID: String) -> UInt64? {
        guard let recordIdentifier else { return nil }
        let parts = recordIdentifier.split(separator: ":", maxSplits: 1)
        guard parts.count == 2, parts[0] == vaultID else { return nil }
        return UInt64(parts[1])
    }
}
#endif
