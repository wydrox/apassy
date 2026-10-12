import ApassyCompanionKit
import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

@Suite("Decisions")
struct DecisionsTests {
    private static let now = Date(timeIntervalSince1970: 1_790_000_000)

    private static func question(_ qid: String, waited: TimeInterval, runID: String = "1") -> RemoteQuestion {
        var question = PreviewVaultService.sampleQuestion(qid: qid, now: now.addingTimeInterval(-waited))
        question.card?.run.id = runID
        return question
    }

    private static func run(_ id: String, waited: Int?, agent: String = "codex", command: [String] = ["git", "push"])
        -> PendingRun
    {
        PendingRun(
            id: id, agent: agent, command: command, cwd: "/Users/me/Dev/shop", envNames: ["GITHUB_TOKEN"],
            purpose: "", risk: "", userRequest: "", requestSource: "", agentRequest: "", remember: nil,
            digest: String(repeating: "ab", count: 32), waitingSeconds: waited)
    }

    @Test("questions and runs are one list, newest first; a run of unknown age goes last")
    func mergedOrder() {
        let rows = Decisions.waiting(
            questions: [Self.question("q-old", waited: 200), Self.question("q-new", waited: 8)],
            runs: [Self.run("r-unknown", waited: nil), Self.run("r-mid", waited: 30)],
            runTimeout: 120, fetchedAt: Self.now, now: Self.now)
        #expect(rows.map(\.id) == ["question-q-new", "run-r-mid", "question-q-old", "run-r-unknown"])
    }

    @Test("an expired or settled question is not waiting")
    func onlyOpenQuestions() {
        var settled = Self.question("settled", waited: 10)
        settled.state = .settled
        let rows = Decisions.waiting(
            questions: [Self.question("expired", waited: 300), settled, Self.question("open", waited: 299)], runs: [],
            runTimeout: 120, fetchedAt: nil, now: Self.now)
        #expect(rows.map(\.id) == ["question-open"])
    }

    @Test("a run that a question already shows is listed once, as the question")
    func noDuplicates() {
        let question = Self.question("q", waited: 5, runID: "77")
        let card = question.card!.run
        let same = Self.run("77", waited: 5, agent: card.agent, command: card.command)
        let otherAgent = Self.run("77", waited: 5, agent: "codex", command: card.command)
        let rows = Decisions.waiting(
            questions: [question], runs: [same], runTimeout: 120, fetchedAt: Self.now, now: Self.now)
        #expect(rows.map(\.id) == ["question-q"])
        let both = Decisions.waiting(
            questions: [question], runs: [otherAgent], runTimeout: 120, fetchedAt: Self.now, now: Self.now)
        #expect(both.count == 2)
    }

    @Test("the time left: 5 minutes for a question, the Mac's timeout for a run")
    func timeLeft() {
        let later = Self.now.addingTimeInterval(10)
        let rows = Decisions.waiting(
            questions: [Self.question("q", waited: 8)], runs: [Self.run("r", waited: 12), Self.run("u", waited: nil)],
            runTimeout: 120, fetchedAt: Self.now, now: later)
        #expect(rows.map { $0.secondsLeft(now: later) } == [282, 98, nil])
        #expect(rows.map { $0.secondsLeft(now: Self.now) } == [292, 108, nil])
        #expect(rows[0].secondsLeft(now: Self.now.addingTimeInterval(400)) == 0)
        #expect(Decisions.clock(292) == "4:52")
        #expect(Decisions.clock(59) == "0:59")
        #expect(Decisions.secondsLeft(until: Self.now, now: Self.now.addingTimeInterval(-0.2)) == 1)
    }

    @Test("a row names the credential, the agent and the project, and marks production")
    func rows() {
        let rows = Decisions.waiting(
            questions: [Self.question("q", waited: 1)], runs: [Self.run("r", waited: 1)], runTimeout: 120,
            fetchedAt: Self.now, now: Self.now)
        #expect(rows[0].title == "Shop database +1")
        #expect(rows[0].subtitle == "Claude Code · synthetic-shop")
        #expect(rows[0].production)
        #expect(rows[1].title == "GITHUB_TOKEN")
        #expect(rows[1].subtitle == "Codex · shop")
        #expect(!rows[1].production)
    }

    @Test("agent names and the environment of a question")
    func names() {
        #expect(AgentName.display("claude-code") == "Claude Code")
        #expect(AgentName.display("my-agent") == "my-agent")
        let items = PreviewVaultService.sampleQuestion().card!.question.items
        #expect(Decisions.environment(items) == "Production")
        #expect(Decisions.environment([items[1]]) == "Production?")
        var development = items[1]
        development.unconfirmed = false
        #expect(Decisions.environment([development]) == "Development")
    }
}
