import WatchKit

/// The name of this watch, for the link name. `WatchConnectLink.defaultName` cuts it to 17 UTF-8
/// bytes at a character boundary. A generic system name ("Apple Watch") is kept as it is: it fits,
/// and the Mac labels the row of a watch itself.
enum WatchDeviceName {
    @MainActor
    static func current() -> String { WKInterfaceDevice.current().name }
}
