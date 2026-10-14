import Foundation

/// What the Agents tab says (ADR 0026 §8) while the Mac does not send its agents to the iPhone.
/// The agents, their use, and their exceptions are rows of the Mac's vault that do not sync; the
/// feed that will carry them (stage5-plan.md, section D) does not exist yet. So the tab never
/// shows a list, and it must not say "when the Mac is connected" to an owner whose Mac already
/// sends its questions here: it says where the agents are, and offers what this iPhone can do now.
enum AgentsReach: Equatable {
    /// The questions are still loading and no Mac is paired on Wi-Fi.
    case checking
    /// No questions through the relay and no Mac paired on Wi-Fi.
    case notConnected
    /// Questions through the relay, or a Mac paired on Wi-Fi (its name, when it is known).
    case connected(mac: String?)

    enum Action: Equatable {
        /// "Connect this iPhone": the questions through the relay, as in Decisions.
        case connect
        /// "Open Decisions": where the questions of the agents arrive.
        case openDecisions
    }

    /// - Parameters:
    ///   - questions: the phase of the questions through the relay, or nil without a vault model.
    ///   - removed: the owner removed this iPhone from the questions on a Mac.
    ///   - wifiMac: the name of the Mac paired on Wi-Fi, or nil when none is paired.
    init(questions: QuestionsModel.Phase?, removed: Bool, wifiMac: String?) {
        if let wifiMac {
            self = .connected(mac: wifiMac)
            return
        }
        switch questions {
        case .ready where !removed: self = .connected(mac: nil)
        case .loading: self = .checking
        case .ready, .off, .failed, nil: self = .notConnected
        }
    }

    var title: String { "Agents run on your Mac" }

    var message: String {
        switch self {
        case .checking:
            "The list of agents and their exceptions is on your Mac. Open Agents there to see them."
        case .notConnected:
            "The list of agents and their exceptions is on your Mac. Open Agents there to see them. To answer agents on this iPhone, connect it to your Mac."
        case .connected(let mac):
            "Questions from \(mac ?? "your Mac") arrive in Decisions. The list of agents and their exceptions stays on the Mac for now: open Agents there to see them or to remove an exception."
        }
    }

    var action: Action? {
        switch self {
        case .checking: nil
        case .notConnected: .connect
        case .connected: .openDecisions
        }
    }
}
