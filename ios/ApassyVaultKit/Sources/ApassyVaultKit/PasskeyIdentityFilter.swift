import Foundation

/// Which passkeys go to the identity store of iOS. Plain data only: a relying party, a username,
/// a credential ID, and a user handle; never a key.
public enum PasskeyIdentityFilter {
    /// A credential ID is unique per relying party, not across them: an import can bring equal
    /// IDs for two websites. One identity per relying party and credential ID, the first one
    /// wins, and the order is kept.
    public static func unique(_ passkeys: [PasskeyIdentity]) -> [PasskeyIdentity] {
        struct Key: Hashable {
            let rpID: String
            let credentialID: Data
        }
        var seen = Set<Key>()
        return passkeys.filter { seen.insert(Key(rpID: $0.rpID, credentialID: $0.credentialID)).inserted }
    }
}
