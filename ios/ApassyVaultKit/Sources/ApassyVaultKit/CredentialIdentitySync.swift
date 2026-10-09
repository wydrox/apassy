#if os(iOS)
import AuthenticationServices

/// The logins that iOS shows in the QuickType bar (ADR 0023): a username and a host per
/// website, never a password. The app replaces them after each unlock, save, and sync
/// that changed the vault; the AutoFill extension fills only after Face ID.
public enum CredentialIdentitySync {
    /// Replace every identity of Apassy with `identities` of the vault `vaultID`. The
    /// record identifier of each is `<vaultID>:<item id>`.
    public static func replace(with identities: [CredentialIdentity], vaultID: String) async {
        let store = ASCredentialIdentityStore.shared
        // The store is off until the owner turns Apassy on in Settings > General >
        // AutoFill & Passwords; a write then fails.
        guard await store.state().isEnabled else { return }
        var seen = Set<String>()
        let entries: [any ASCredentialIdentity] = identities.compactMap { identity in
            let record = recordIdentifier(of: identity.id, vaultID: vaultID)
            // A login with two websites on the same host gives one suggestion.
            guard seen.insert(record + "@" + identity.host).inserted else { return nil }
            return ASPasswordCredentialIdentity(
                serviceIdentifier: ASCredentialServiceIdentifier(identifier: identity.host, type: .domain),
                user: identity.username, recordIdentifier: record)
        }
        // A hint list: when iOS does not take it, the extension still lists every login.
        try? await store.replaceCredentialIdentities(entries)
    }

    /// Remove every identity of Apassy (the vault left this iPhone).
    public static func removeAll() async {
        try? await ASCredentialIdentityStore.shared.removeAllCredentialIdentities()
    }

    /// The record identifier of an item of `vaultID`.
    static func recordIdentifier(of itemID: UInt64, vaultID: String) -> String {
        "\(vaultID):\(itemID)"
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
