import Foundation
import Observation

/// The iPhone's Add Apple Watch scanner, independent of the camera and WatchConnectivity so a
/// Simulator or a test can feed the exact scanned text through the same path as the view.
@MainActor @Observable
public final class WatchConnectScan {
    public enum Step: Equatable {
        case ready, scanning, sending, sent
        case failed(String)
    }

    public enum SendResult: Equatable, Sendable {
        case sent
        case refused(String)
        case failed
    }

    public struct Outgoing: Equatable {
        public let id = UUID()
        public let link: String
    }

    public private(set) var step = Step.ready
    /// In memory for one send only. Neither the iPhone nor this model stores the code.
    public private(set) var outgoing: Outgoing?

    public init() {}

    public func startScanning() { step = .scanning }
    public func cancelScanning() { step = .ready }

    public func receive(_ code: String, isReachable: Bool) {
        guard step == .scanning else { return }
        let link = code.trimmingCharacters(in: .whitespacesAndNewlines)
        if link.contains("/pair#apassy_tcd_") {
            step = .failed("This code sets up a node, not an Apple Watch. On your Mac, open Apassy › Settings › Devices › Add an iPhone or a Mac…")
        } else if WatchConnectLink.team(of: link) != nil, !link.contains("&handoff=") {
            step = .failed("This code only syncs a vault. Update Apassy on your Mac, then make a new code in Settings › Devices › Add an iPhone or a Mac…")
        } else if !WatchConnectLink.isConnectLink(link) {
            step = .failed("This is not an Apassy Connect code. On your Mac, open Apassy › Settings › Devices › Add an iPhone or a Mac…")
        } else if !isReachable {
            step = .failed("The code wasn't sent. Open Apassy on your Apple Watch, keep it near this iPhone, then scan again.")
        } else {
            outgoing = Outgoing(link: link)
            step = .sending
        }
    }

    public func sent(_ result: SendResult) {
        outgoing = nil
        switch result {
        case .sent:
            step = .sent
        case .refused(let message) where !message.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty:
            step = .failed(message)
        case .refused, .failed:
            step = .failed("Couldn't send the code to your watch. Open Apassy on your Apple Watch, keep it near this iPhone, and try again.")
        }
    }
}
