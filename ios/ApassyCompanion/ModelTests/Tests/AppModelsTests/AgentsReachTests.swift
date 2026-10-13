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
