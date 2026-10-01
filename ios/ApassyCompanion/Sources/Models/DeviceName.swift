import ApassyCompanionKit
import UIKit

/// The name that the Mac lists this iPhone under, before the owner edits it.
enum DeviceName {
    /// The name of the iPhone, made to fit the rules of the Mac (contract section 2, "Characters").
    /// iOS may give apps a generic name such as "iPhone".
    @MainActor
    static func current() -> String {
        TextRules.deviceName(from: UIDevice.current.name, fallback: "iPhone")
    }
}
