import Foundation

/// Where the settings of the app are kept: the App Group defaults (`SharedContainer.defaults`) for a
/// real vault, or `MemorySettingsStore` for the demo, which writes nothing to disk. The calls are
/// the ones of `UserDefaults` that the app uses, so `UserDefaults` conforms as it is.
public protocol SettingsStore: AnyObject {
    func object(forKey defaultName: String) -> Any?
    func set(_ value: Any?, forKey defaultName: String)
    func removeObject(forKey defaultName: String)
    func bool(forKey defaultName: String) -> Bool
    func string(forKey defaultName: String) -> String?
    func array(forKey defaultName: String) -> [Any]?
    func stringArray(forKey defaultName: String) -> [String]?
}

extension UserDefaults: SettingsStore {}

/// Settings in memory only (the demo). Nothing goes to `UserDefaults` or to a file; the values go
/// with the object.
public final class MemorySettingsStore: SettingsStore, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: Any]

    public init(_ values: [String: Any] = [:]) {
        self.values = values
    }

    /// The keys that hold a value, for the tests.
    public var keys: Set<String> { lock.withLock { Set(values.keys) } }

    public func object(forKey defaultName: String) -> Any? { lock.withLock { values[defaultName] } }

    public func set(_ value: Any?, forKey defaultName: String) {
        lock.withLock { values[defaultName] = value }
    }

    public func removeObject(forKey defaultName: String) {
        _ = lock.withLock { values.removeValue(forKey: defaultName) }
    }

    public func bool(forKey defaultName: String) -> Bool {
        switch object(forKey: defaultName) {
        case let value as Bool: value
        case let value as NSNumber: value.boolValue
        case let value as String: ["yes", "true", "1"].contains(value.lowercased())
        default: false
        }
    }

    public func string(forKey defaultName: String) -> String? {
        switch object(forKey: defaultName) {
        case let value as String: value
        case let value as NSNumber: value.stringValue
        default: nil
        }
    }

    public func array(forKey defaultName: String) -> [Any]? { object(forKey: defaultName) as? [Any] }

    public func stringArray(forKey defaultName: String) -> [String]? { object(forKey: defaultName) as? [String] }
}
