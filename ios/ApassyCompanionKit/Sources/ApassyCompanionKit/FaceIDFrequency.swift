import Foundation

public enum FaceIDFrequency: String, CaseIterable, Sendable, Identifiable {
    case everyTime = "every_time", oneMinute = "1m", fiveMinutes = "5m"
    case fifteenMinutes = "15m", oneHour = "1h", untilLock = "until_lock"
    public var id: String { rawValue }
    public var label: String {
        switch self {
        case .everyTime: "Every time"
        case .oneMinute: "1 minute"
        case .fiveMinutes: "5 minutes"
        case .fifteenMinutes: "15 minutes"
        case .oneHour: "1 hour"
        case .untilLock: "Until the iPhone locks"
        }
    }
    var seconds: TimeInterval? {
        switch self {
        case .everyTime: 0
        case .oneMinute: 60
        case .fiveMinutes: 300
        case .fifteenMinutes: 900
        case .oneHour: 3600
        case .untilLock: nil
        }
    }
}
