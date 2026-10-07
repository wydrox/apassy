#if canImport(UIKit)
import UIKit
import UniformTypeIdentifiers

/// Copies to the pasteboard of this iPhone only (ADR 0023): `localOnly` keeps a copy
/// off Universal Clipboard, so it never reaches a Mac where an agent could read the
/// pasteboard, and `expirationDate` makes iOS clear it. A secret is also marked
/// concealed, for clipboard tools that honor the marker.
@MainActor
public enum SecureClipboard {
    /// The marker of nspasteboard.org for a value that a clipboard history skips.
    static let concealedType = "org.nspasteboard.ConcealedType"

    /// Copy `value`. A secret expires after `seconds`; a plain value after 10 minutes.
    public static func copy(_ value: String, secret: Bool, seconds: TimeInterval) {
        var item: [String: Any] = [UTType.utf8PlainText.identifier: value]
        if secret { item[concealedType] = Data() }
        let lifetime = secret ? max(10, seconds) : 600
        UIPasteboard.general.setItems(
            [item],
            options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(lifetime)])
    }

    /// Clear the pasteboard when it still holds a copy of Apassy.
    public static func clearIfOurs(changeCount: Int) {
        if UIPasteboard.general.changeCount == changeCount {
            UIPasteboard.general.items = []
        }
    }

    /// The change count after the last copy, for `clearIfOurs`.
    public static var changeCount: Int { UIPasteboard.general.changeCount }
}
#endif
