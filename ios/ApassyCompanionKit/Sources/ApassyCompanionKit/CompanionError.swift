// The errors of the client. Each message is for the owner.

import Foundation

/// A request to the Mac failed.
public enum CompanionError: Error, Equatable, LocalizedError {
    /// No host answered.
    case notReachable
    /// iOS refused local network access.
    case localNetworkDenied
    /// Every host answered with another certificate. The UI offers "Forget this Mac".
    case pinMismatchOnAllHosts
    /// The Mac answered with an error (contract section 4).
    case server(status: Int, code: String, message: String)
    /// The Mac does not know this device, or the owner removed it. The UI deletes the pairing.
    case unpaired
    /// The clocks differ by more than 60 s. The message is the text of the Mac.
    case clockSkew(message: String)
    /// The pairing request was refused: the link may be used, or the window is over.
    case linkRejected
    /// The pairing window is over.
    case linkExpired
    /// A first approval may have arrived, and the retry found no waiting run or no answer.
    case approvalUnconfirmed
    /// The Mac answered with something that is not in the contract.
    case invalidResponse
    /// The input is out of the contract, so nothing was sent.
    case invalidInput(String)

    public var errorDescription: String? {
        switch self {
        case .notReachable:
            return "Your Mac is not reachable. Check that both devices are on the same Wi-Fi network, that Apassy is unlocked on the Mac, and that \"Allow the iPhone app on this network\" is on."
        case .localNetworkDenied:
            return "Allow local network access for Apassy in Settings > Privacy & Security > Local Network."
        case .pinMismatchOnAllHosts:
            return "The device that answered is not the Mac you paired with, or the Mac was reset. Select \"Forget this Mac\" and pair again."
        case .server(_, _, let message):
            return message
        case .unpaired:
            return "This iPhone is no longer paired with the Mac. Pair it again."
        case .clockSkew(let message):
            return "\(message) Set the date and time of the iPhone and the Mac to automatic."
        case .linkRejected:
            return "This link does not work. Another device may have used it. Select Cancel on your Mac and make a new code."
        case .linkExpired:
            return "This pairing code has expired. Select \"Pair an iPhone\" on your Mac to make a new one."
        case .approvalUnconfirmed:
            return "The Mac may have approved this run. Check Activity."
        case .invalidResponse:
            return "The Mac answered with something that Apassy does not understand. Update Apassy on the Mac and on the iPhone."
        case .invalidInput(let message):
            return message
        }
    }

    /// The error for an answer with a status outside 200 to 299.
    static func from(status: Int, body: Data) -> CompanionError {
        guard let envelope = try? JSONDecoder().decode(ErrorEnvelope.self, from: body) else {
            return .server(
                status: status, code: "unknown",
                message: "The Mac answered with an unexpected error (HTTP \(status)).")
        }
        let code = envelope.error.code
        let message = envelope.error.message
        if status == 401 && code == "unpaired" { return .unpaired }
        if status == 401 && code == "clock_skew" { return .clockSkew(message: message) }
        return .server(status: status, code: code, message: message)
    }

    /// The error after every host failed, when none answered.
    static func from(failures: [TransportFailure]) -> CompanionError {
        if !failures.isEmpty && failures.allSatisfy({ $0 == .pinMismatch }) { return .pinMismatchOnAllHosts }
        if failures.contains(.localNetworkDenied) { return .localNetworkDenied }
        return .notReachable
    }
}
