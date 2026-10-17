import ApassyCompanionKit
import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

@Suite("Decisions")
struct DecisionsTests {
    private static let now = Date(timeIntervalSince1970: 1_790_000_000)
    /// The Mac that asks the sample questions, paired on this Wi-Fi.
    private static let mac = PreviewVaultService.sampleQuestion().askerName

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
            runTimeout: 120, fetchedAt: Self.now, pairedMac: Self.mac, now: Self.now)
        #expect(rows.map(\.id) == ["question-q-new", "run-r-mid", "question-q-old", "run-r-unknown"])
    }

    @Test("an expired or settled question is not waiting")
    func onlyOpenQuestions() {
        var settled = Self.question("settled", waited: 10)
        settled.state = .settled
        let rows = Decisions.waiting(
            questions: [Self.question("expired", waited: 300), settled, Self.question("open", waited: 299)], runs: [],
            runTimeout: 120, fetchedAt: nil, pairedMac: Self.mac, now: Self.now)
        #expect(rows.map(\.id) == ["question-open"])
    }

    @Test("a run that a question already shows is listed once, as the question")
    func noDuplicates() {
        let question = Self.question("q", waited: 5, runID: "77")
        let card = question.card!.run
        let same = Self.run("77", waited: 5, agent: card.agent, command: card.command)
        let otherAgent = Self.run("77", waited: 5, agent: "codex", command: card.command)
        let rows = Decisions.waiting(
            questions: [question], runs: [same], runTimeout: 120, fetchedAt: Self.now, pairedMac: Self.mac,
            now: Self.now)
        #expect(rows.map(\.id) == ["question-q"])
        let both = Decisions.waiting(
            questions: [question], runs: [otherAgent], runTimeout: 120, fetchedAt: Self.now, pairedMac: Self.mac,
            now: Self.now)
        #expect(both.count == 2)
    }

    @Test("a sent question is recent and its matching run cannot be answered again")
    func sentQuestionIsNotActionable() {
        var question = Self.question("sent", waited: 5, runID: "77")
        question.answered = .approveOnce
        let card = question.card!.run
        let run = Self.run("77", waited: 5, agent: card.agent, command: card.command)
        let rows = Decisions.waiting(
            questions: [question], runs: [run], runTimeout: 120, fetchedAt: Self.now,
            pairedMac: Self.mac, now: Self.now)
        #expect(rows.isEmpty)
    }

    @Test("a question from another Mac never hides a run of the paired Mac")
    func noDuplicatesAcrossMacs() {
        let question = Self.question("q", waited: 5, runID: "77")
        let card = question.card!.run
        let same = Self.run("77", waited: 5, agent: card.agent, command: card.command)
        let otherMac = Decisions.waiting(
            questions: [question], runs: [same], runTimeout: 120, fetchedAt: Self.now, pairedMac: "Mac Studio",
            now: Self.now)
        #expect(otherMac.map(\.id) == ["question-q", "run-77"])
        let unpaired = Decisions.waiting(
            questions: [question], runs: [same], runTimeout: 120, fetchedAt: Self.now, pairedMac: nil, now: Self.now)
        #expect(unpaired.count == 2)
        // The listener writes the name cut to 40 characters; the trusted device writes it whole.
        let long = String(repeating: "m", count: 39) + " Pro Max"
        var longQuestion = question
        longQuestion.askerName = long
        let cut = Decisions.waiting(
            questions: [longQuestion], runs: [same], runTimeout: 120, fetchedAt: Self.now,
            pairedMac: String(long.prefix(40)), now: Self.now)
        #expect(cut.map(\.id) == ["question-q"])
        #expect(Decisions.sameMac("Mac mini\n", "Mac mini"))
        #expect(!Decisions.sameMac("Mac mini", "Mac mini 2"))
        #expect(!Decisions.sameMac("", ""))
    }

    @Test("the tab badge counts the rows of Decisions: a run that a question shows counts once")
    @MainActor
    func badge() async {
        let mac = ScriptedConnection()
        let session = SessionModel(
            record: PreviewData.record, mac: mac, keysInSecureEnclave: false,
            store: InMemoryPairingStore(PreviewData.record), onEnded: { _ in })
        let now = Date()
        var question = PreviewVaultService.sampleQuestion(qid: "q", now: now)
        question.askerName = PreviewData.record.macName
        let card = question.card!.run
        let shown = Self.run("77", waited: 3, agent: card.agent, command: card.command)
        question.card?.run.id = shown.id
        let other = Self.run("78", waited: 3)
        await mac.setInbox(Inbox(runs: [shown, other], accessRequests: PreviewData.inbox.accessRequests, activity: []))
        await session.refresh()
        #expect(session.macName == PreviewData.record.macName)
        #expect(session.accessRequests.count == 1)

        // One question, the run it shows, another run, and one request: three rows, not four.
        #expect(Decisions.waiting(questions: [question], session: session, now: now).count == 2)
        #expect(Decisions.badge(questions: [question], session: session, now: now) == 3)
        #expect(Decisions.badge(questions: [question], session: nil, now: now) == 1)
        #expect(Decisions.badge(questions: [], session: session, now: now) == 3)
        // A question from another Mac does not hide the paired Mac's run.
        question.askerName = "Mac Studio"
        #expect(Decisions.badge(questions: [question], session: session, now: now) == 4)
    }

    @Test("a tap right after a decision appears or changes does not answer")
    func answerGuard() {
        var guarded = AnswerGuard()
        #expect(guarded.accepts(now: Self.now))
        guarded.arm(now: Self.now)
        #expect(!guarded.accepts(now: Self.now))
        #expect(!guarded.accepts(now: Self.now.addingTimeInterval(0.49)))
        #expect(guarded.accepts(now: Self.now.addingTimeInterval(0.5)))
        guarded.arm(now: Self.now.addingTimeInterval(2))
        #expect(!guarded.accepts(now: Self.now.addingTimeInterval(2.1)))
    }

    @Test("the time left: 5 minutes for a question, the Mac's timeout for a run")
    func timeLeft() {
        let later = Self.now.addingTimeInterval(10)
        let rows = Decisions.waiting(
            questions: [Self.question("q", waited: 8)], runs: [Self.run("r", waited: 12), Self.run("u", waited: nil)],
            runTimeout: 120, fetchedAt: Self.now, pairedMac: Self.mac, now: later)
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
            fetchedAt: Self.now, pairedMac: Self.mac, now: Self.now)
        #expect(rows[0].title == "Shop database +1")
        #expect(rows[0].subtitle == "Claude Code · synthetic-shop")
        #expect(rows[0].production)
        #expect(rows[1].title == "GITHUB_TOKEN")
        #expect(rows[1].subtitle == "Codex · shop")
        #expect(!rows[1].production)
        let noFolder = PendingRun(
            id: "f", agent: "codex", command: ["ls"], cwd: nil, envNames: [], purpose: "", risk: "", userRequest: "",
            requestSource: "", agentRequest: "", remember: nil, digest: String(repeating: "ab", count: 32),
            waitingSeconds: 1)
        let row = Decisions.waiting(
            questions: [], runs: [noFolder], runTimeout: 120, fetchedAt: Self.now, pairedMac: Self.mac,
            now: Self.now)
        #expect(row[0].subtitle == "Codex")
        #expect(row[0].title == "ls")
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
