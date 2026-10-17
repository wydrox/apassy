import Foundation

/// What the Agents tab says (ADR 0026 §8) while no Mac sends its agents to the iPhone. The agents,
/// their use, and their exceptions are rows of the Mac's vault that do not sync; a Mac publishes
/// them through the relay feed (contract relay-feed-v1, `AgentsModel`), and until one does, or with
/// a relay or a core without the feed, the tab shows no list. It must not say "when the Mac is
/// connected" to an owner whose Mac already sends its questions here: it says where the agents are,
/// and offers what this iPhone can do now.
enum AgentsReach: Equatable {
    /// The questions are still loading (or locked) and no Mac is paired on Wi-Fi.
    case checking
    /// No questions through the relay and no Mac paired on Wi-Fi.
    case notConnected
    /// Questions through the relay, or a Mac paired on Wi-Fi (its name, when it is known).
    case connected(mac: String?)

    enum Action: Equatable {
        /// "Connect this iPhone": the questions through the relay, as in Decisions.
        case connect
        /// "Open Requests": where the questions of the agents arrive.
        case openDecisions
        /// "Pair with the Mac on Wi-Fi": the companion, which brings the requests of the agents.
        case pairOnWiFi

        var title: String {
            switch self {
            case .connect: "Connect this iPhone"
            case .openDecisions: "Open Requests"
            case .pairOnWiFi: "Pair with the Mac on Wi-Fi"
            }
        }
    }

    /// Another place that shows a part of the Mac's vault which does not reach this iPhone.
    enum Place: Equatable {
        /// Decisions › Requests, while no Mac is paired on Wi-Fi (a paired Mac sends them).
        case requests
        /// Decisions › Suggestions: they never leave the Mac yet.
        case suggestions
        /// A credential › Agent use.
        case agentUse
        /// A credential › Rules from your answers.
        case rules
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
        // Locked: the questions may well be connected; say nothing about it until they open.
        case .loading, .locked: self = .checking
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

extension AgentsReach {
    /// What `place` says: where its data lives. Never "when the Mac is connected": a connected
    /// Mac does not send it either.
    func note(_ place: Place) -> String {
        switch place {
        case .requests:
            "Requests from agents show in Apassy on your Mac. To see them here too, pair this iPhone with the Mac on Wi-Fi."
        case .suggestions:
            "Suggestions come from your Mac. They show in Apassy on the Mac."
        case .agentUse:
            switch self {
            case .connected:
                "Which agents used this credential is on your Mac. Their questions about it arrive in Decisions."
            case .notConnected:
                "Which agents used this credential is on your Mac. Connect this iPhone to answer their questions here."
            case .checking:
                "Which agents used this credential is on your Mac."
            }
        case .rules:
            "The rules from your answers are kept on your Mac. Open this credential there to see or remove them."
        }
    }

    /// The one action of `place` that helps now, if any.
    func action(_ place: Place) -> Action? {
        switch place {
        case .requests: .pairOnWiFi
        case .suggestions, .rules: nil
        case .agentUse: action
        }
    }
}
