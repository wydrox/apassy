#if os(iOS)
import AuthenticationServices

/// The logins, passkeys, and one-time passwords that iOS suggests (ADR 0023): a username and a
/// host per website, the relying party, username, credential ID, and user handle of each passkey,
/// and a label and a host per one-time password; never a password, a code, or a key. The app
/// replaces them after each unlock, save, and sync that changed the vault; the AutoFill extension
/// adds a passkey that it just made, and fills only after Face ID.
public enum CredentialIdentitySync {
    /// Replace every identity of Apassy with `identities` of the vault `vaultID`. The
    /// record identifier of each is `<vaultID>:<item id>`.
    public static func replace(with identities: IdentitySet, vaultID: String) async {
        let store = ASCredentialIdentityStore.shared
        // The store is off until the owner turns Apassy on in Settings > General >
        // AutoFill & Passwords; a write then fails.
        guard await store.state().isEnabled else { return }
        var seen = Set<String>()
        var entries: [any ASCredentialIdentity] = identities.passwords.compactMap { identity in
            let record = recordIdentifier(of: identity.id, vaultID: vaultID)
            // A login with two websites on the same host gives one suggestion.
            guard seen.insert(record + "@" + identity.host).inserted else { return nil }
            return ASPasswordCredentialIdentity(
                serviceIdentifier: ASCredentialServiceIdentifier(identifier: identity.host, type: .domain),
                user: identity.username, recordIdentifier: record)
        }
        // A credential ID is unique per website: filter by website and ID.
        for passkey in PasskeyIdentityFilter.unique(identities.passkeys) {
            entries.append(identity(of: passkey, vaultID: vaultID))
        }
        for code in identities.codes {
            let record = recordIdentifier(of: code.id, vaultID: vaultID)
            guard seen.insert("code:" + record + "@" + code.host).inserted else { continue }
            entries.append(
                ASOneTimeCodeCredentialIdentity(
                    serviceIdentifier: ASCredentialServiceIdentifier(identifier: code.host, type: .domain),
                    label: code.label, recordIdentifier: record))
        }
        // A hint list: when iOS does not take it, the extension still lists every login.
        try? await store.replaceCredentialIdentities(entries)
    }

    /// Add one passkey (the extension made it; the app replaces the whole list at its next unlock).
    public static func add(_ passkey: PasskeyIdentity, vaultID: String) async {
        let store = ASCredentialIdentityStore.shared
        guard await store.state().isEnabled else { return }
        try? await store.saveCredentialIdentities([identity(of: passkey, vaultID: vaultID)])
    }

    /// Remove every identity of Apassy (the vault left this iPhone).
    public static func removeAll() async {
        try? await ASCredentialIdentityStore.shared.removeAllCredentialIdentities()
    }

    static func identity(of passkey: PasskeyIdentity, vaultID: String) -> ASPasskeyCredentialIdentity {
        ASPasskeyCredentialIdentity(
            relyingPartyIdentifier: passkey.rpID, userName: passkey.userName, credentialID: passkey.credentialID,
            userHandle: passkey.userHandle, recordIdentifier: recordIdentifier(of: passkey.id, vaultID: vaultID))
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
