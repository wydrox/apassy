import WatchKit

/// The name of this watch, for the link name (`WatchConnectLink.defaultName` cuts it to 17 bytes).
enum WatchDeviceName {
    @MainActor
    static func current() -> String { WKInterfaceDevice.current().name }
}
