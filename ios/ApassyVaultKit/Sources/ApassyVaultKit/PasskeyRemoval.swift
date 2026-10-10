import Foundation

/// What "remove the passkey" does to a login, and the words that say so before the owner
/// confirms.
///
/// The core keeps the login only when it has a password with a value. A login without one has no
/// other way in, so the core deletes the entire item: notes, tags, websites, one-time passwords,
/// custom details, history, and agent access. The deletion syncs. The screen must say this, and
/// must name the action for what it does.
///
/// The row tells whether the password has a value (`ItemRow.hasPassword`). A stored password
/// field with no value counts as no password. When the row does not say (an older core), the
/// plan warns of the deletion: it never promises that the login stays.
public struct PasskeyRemovalPlan: Equatable, Sendable {
    public enum Effect: Equatable, Sendable {
        /// The login keeps its password and every other field.
        case removesPasskey
        /// The login has no password with a value: the whole item goes.
        case deletesLogin
        /// The core did not say if there is a password. The whole item may go.
        case mayDeleteLogin
    }

    public let effect: Effect
    /// The item and the revision that the owner saw: the removal acts on this revision only.
    public let itemID: UInt64
    public let revision: UInt64
    public let itemTitle: String
    public let website: String

    /// nil when the item has no passkey.
    public init?(detail: ItemDetail) {
        guard let passkey = detail.passkey else { return nil }
        switch detail.row.hasPassword {
        case true?:
            // The fields must agree. If the password is not among them, trust neither.
            let listed = detail.fields.contains { $0.name == "password" && $0.secret }
            effect = listed ? .removesPasskey : .mayDeleteLogin
        case false?:
            effect = .deletesLogin
        case nil:
            effect = .mayDeleteLogin
        }
        itemID = detail.row.id
        revision = detail.row.revision
        itemTitle = detail.row.title
        website = passkey.rpID
    }

    /// True when the whole login goes, or may go. Only a password with a value says otherwise.
    public var deletesLogin: Bool { effect != .removesPasskey }

    /// The title of the button and of the menu entry.
    public var actionTitle: String {
        deletesLogin ? "Delete login" : "Remove passkey"
    }

    public var systemImage: String {
        deletesLogin ? "trash" : "person.badge.minus"
    }

    public var dialogTitle: String {
        deletesLogin ? "Delete the login “\(itemTitle)”?" : "Remove the passkey of “\(itemTitle)”?"
    }

    public var message: String {
        switch effect {
        case .removesPasskey:
            return
                "The login keeps its password and its other fields. \(website) keeps its copy of the public key until you remove it there."
        case .deletesLogin:
            return
                "This login has no password. Apassy cannot remove only the passkey. It deletes the entire login: the passkey, notes, tags, websites, one-time password codes, custom details, history, and agent access. The deletion syncs to your other devices. To keep this data, cancel. Then add a password with Edit, or archive the login."
        case .mayDeleteLogin:
            return
                "Apassy cannot confirm that this login has a password. Without one, Apassy cannot remove only the passkey. It deletes the entire login: the passkey, notes, tags, websites, one-time password codes, custom details, history, and agent access. The deletion syncs to your other devices. To keep this data, cancel. Then update Apassy, or add a password with Edit."
        }
    }

    /// The reason that the owner check shows.
    public var ownerReason: String {
        switch effect {
        case .removesPasskey: "Remove the passkey of “\(itemTitle)”"
        case .deletesLogin: "Delete the login “\(itemTitle)” and its passkey"
        case .mayDeleteLogin: "Remove the passkey of “\(itemTitle)”. Apassy deletes the login if it has no password"
        }
    }

    /// The footer of the passkey section. The ordinary screens never show or copy the key; the
    /// owner can still move it to another app, with the system export, after the owner check.
    public static func footer(website: String) -> String {
        "Apassy signs in to \(website) with this passkey after Face ID. The key stays in the vault and syncs with it. These screens never show or copy the key. After Face ID, you can export it to another app with Settings > Move to another app."
    }
}
