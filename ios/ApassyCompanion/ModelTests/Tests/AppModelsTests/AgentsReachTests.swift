import Foundation
import Testing

@testable import AppModels

/// The Agents tab while the Mac does not send its agents: it never tells an owner whose Mac is
/// connected that the agents show "when the Mac is connected".
@Suite("Agents reach")
struct AgentsReachTests {
    @Test("questions through the relay: connected, and the action opens Decisions")
    func relayQuestions() {
        let reach = AgentsReach(questions: .ready, removed: false, wifiMac: nil)
        #expect(reach == .connected(mac: nil))
        #expect(reach.action == .openDecisions)
        #expect(reach.message.hasPrefix("Questions from your Mac arrive in Decisions."))
    }

    @Test("a Mac paired on Wi-Fi is named, with or without the questions")
    func wifiMac() {
        for phase: QuestionsModel.Phase? in [.ready, .off, .loading, .failed("relay down"), nil] {
            let reach = AgentsReach(questions: phase, removed: false, wifiMac: "Mac mini")
            #expect(reach == .connected(mac: "Mac mini"))
            #expect(reach.action == .openDecisions)
            #expect(reach.message.hasPrefix("Questions from Mac mini arrive in Decisions."))
        }
    }

    @Test("no questions and no Mac on Wi-Fi: connect this iPhone")
    func notConnected() {
        for phase: QuestionsModel.Phase? in [.off, .failed("relay down"), nil] {
            let reach = AgentsReach(questions: phase, removed: false, wifiMac: nil)
            #expect(reach == .notConnected)
            #expect(reach.action == .connect)
        }
    }

    @Test("an iPhone removed from the questions is not connected")
    func removed() {
        let reach = AgentsReach(questions: .ready, removed: true, wifiMac: nil)
        #expect(reach == .notConnected)
        #expect(reach.action == .connect)
    }

    @Test("while the questions load, no action and no claim about the connection")
    func checking() {
        let reach = AgentsReach(questions: .loading, removed: false, wifiMac: nil)
        #expect(reach == .checking)
        #expect(reach.action == nil)
    }

    @Test("no state says the agents show when the Mac is connected")
    func neverTheOldPromise() {
        let all: [AgentsReach] = [.checking, .notConnected, .connected(mac: nil), .connected(mac: "Mac mini")]
        for reach in all {
            #expect(reach.title == "Agents run on your Mac")
            #expect(!reach.message.localizedCaseInsensitiveContains("when the Mac is connected"))
            #expect(reach.message.contains("on your Mac") || reach.message.contains("on the Mac"))
        }
    }
}

/// The other places that showed "Available when the Mac is connected": Decisions › Requests and
/// Suggestions, and a credential's Agent use and Rules. Each says where its data lives.
@Suite("Mac places")
struct MacPlacesTests {
    static let all: [AgentsReach] = [.checking, .notConnected, .connected(mac: nil), .connected(mac: "Mac mini")]
    static let places: [AgentsReach.Place] = [.requests, .suggestions, .agentUse, .rules]

    @Test("suggestions come from the Mac, with no action, in every state")
    func suggestions() {
        for reach in Self.all {
            #expect(reach.note(.suggestions) == "Suggestions come from your Mac. They show in Apassy on the Mac.")
            #expect(reach.action(.suggestions) == nil)
        }
    }

    @Test("requests without a Mac on Wi-Fi: they are on the Mac, and pairing on Wi-Fi brings them")
    func requests() {
        for reach in Self.all {
            #expect(reach.note(.requests).hasPrefix("Requests from agents show in Apassy on your Mac."))
            #expect(reach.action(.requests) == .pairOnWiFi)
        }
        #expect(AgentsReach.Action.pairOnWiFi.title == "Pair with the Mac on Wi-Fi")
    }

    @Test("agent use of a credential: Open Decisions when connected, Connect this iPhone when not")
    func agentUse() {
        #expect(AgentsReach.connected(mac: nil).action(.agentUse) == .openDecisions)
        #expect(
            AgentsReach.connected(mac: nil).note(.agentUse)
                == "Which agents used this credential is on your Mac. Their questions about it arrive in Decisions.")
        #expect(AgentsReach.notConnected.action(.agentUse) == .connect)
        #expect(AgentsReach.notConnected.note(.agentUse).hasSuffix("Connect this iPhone to answer their questions here."))
        #expect(AgentsReach.checking.action(.agentUse) == nil)
        #expect(AgentsReach.checking.note(.agentUse) == "Which agents used this credential is on your Mac.")
    }

    @Test("rules stay on the Mac, with no action")
    func rules() {
        for reach in Self.all {
            #expect(reach.note(.rules).hasPrefix("The rules from your answers are kept on your Mac."))
            #expect(reach.action(.rules) == nil)
        }
    }

    @Test("no place says it is available when the Mac is connected, and each names the Mac")
    func neverTheOldPromise() {
        for reach in Self.all {
            for place in Self.places {
                let note = reach.note(place)
                #expect(!note.localizedCaseInsensitiveContains("when the Mac is connected"))
                #expect(note.contains("your Mac") || note.contains("the Mac"))
            }
        }
    }

    @Test("a locked list of questions makes no claim about the connection")
    func locked() {
        let reach = AgentsReach(questions: .locked, removed: false, wifiMac: nil)
        #expect(reach == .checking)
        #expect(reach.action == nil)
    }
}
