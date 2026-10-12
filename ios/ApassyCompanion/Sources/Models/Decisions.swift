import ApassyCompanionKit
import ApassyVaultKit
import Foundation

/// One row of "Waiting" in Decisions (ADR 0026 §8): a question through the relay, or a run of the
/// Mac paired on this Wi-Fi (ADR 0020). Both block an agent until the owner answers.
struct WaitingDecision: Identifiable, Equatable {
    enum Source: Equatable {
        case question(RemoteQuestion)
        case run(PendingRun)
    }

    let source: Source
    /// When it started to wait, or nil when the Mac did not say.
    let createdAt: Date?
    /// When an answer is too late, or nil when the Mac did not say.
    let deadline: Date?

    var id: String {
        switch source {
        case .question(let question): "question-\(question.qid)"
        case .run(let run): "run-\(run.id)"
        }
    }

    /// Seconds left, rounded up, never below 0; nil when the deadline is not known.
    func secondsLeft(now: Date) -> Int? {
        deadline.map { Decisions.secondsLeft(until: $0, now: now) }
    }

    /// The agent, as the owner knows it ("Claude Code").
    var agent: String {
        switch source {
        case .question(let question): AgentName.display(question.card?.run.agent ?? question.askerName)
        case .run(let run): AgentName.display(run.agent)
        }
    }

    /// The first line of the row: the credential of a question; the variables of a run, or its
    /// command when it has none.
    var title: String {
        switch source {
        case .question(let question): return question.credentialTitle
        case .run(let run):
            guard let first = run.envNames.first else { return CommandDisplay.line(run.command) }
            return run.envNames.count > 1 ? "\(first) +\(run.envNames.count - 1)" : first
        }
    }

    /// The second line: "Claude Code · acme-billing".
    var subtitle: String {
        switch source {
        case .question(let question):
            [agent, question.card?.question.project?.label].compactMap { $0 }.joined(separator: " · ")
        case .run(let run):
            [agent, run.cwd?.split(separator: "/").last.map(String.init)].compactMap { $0 }
                .joined(separator: " · ")
        }
    }

    /// A production credential: the row has a red dot.
    var production: Bool {
        if case .question(let question) = source {
            return question.card?.question.items.contains(where: \.production) ?? false
        }
        return false
    }
}

/// The logic of the Decisions list.
enum Decisions {
    /// How long a question through the relay waits (ADR 0025 §3e).
    static let questionLifetime = 300

    /// Seconds from `now` to `deadline`, rounded up, never below 0 (as `clock` on the Mac).
    static func secondsLeft(until deadline: Date, now: Date) -> Int {
        Int(max(0, deadline.timeIntervalSince(now)).rounded(.up))
    }

    /// "4:52".
    static func clock(_ seconds: Int) -> String { WaitClock.text(seconds) }

    /// Everything that waits for the owner, newest first, in one list: the open questions through
    /// the relay that have not expired, and the runs of the paired Mac. A run that a question
    /// already shows (the same run of the same agent) is not shown twice; the question is richer.
    /// A run whose waiting time the Mac did not say goes last.
    static func waiting(
        questions: [RemoteQuestion], runs: [PendingRun], runTimeout: Int, fetchedAt: Date?, now: Date
    ) -> [WaitingDecision] {
        let at = Int64(now.timeIntervalSince1970)
        let open = questions.filter { $0.state == .open && $0.expiresAt > at }
        var rows = open.map { question in
            WaitingDecision(
                source: .question(question), createdAt: Date(timeIntervalSince1970: TimeInterval(question.createdAt)),
                deadline: Date(timeIntervalSince1970: TimeInterval(question.expiresAt)))
        }
        for run in runs where !open.contains(where: { shows($0, run) }) {
            var created: Date?
            var deadline: Date?
            if let fetchedAt, let waited = run.waitingSeconds {
                created = fetchedAt.addingTimeInterval(-TimeInterval(max(0, waited)))
                deadline = fetchedAt.addingTimeInterval(TimeInterval(max(0, runTimeout - max(0, waited))))
            }
            rows.append(WaitingDecision(source: .run(run), createdAt: created, deadline: deadline))
        }
        // A stable sort: equal times keep the order above (questions first).
        return rows.enumerated().sorted { lhs, rhs in
            switch (lhs.element.createdAt, rhs.element.createdAt) {
            case (let l?, let r?) where l != r: return l > r
            case (nil, _?): return false
            case (_?, nil): return true
            default: return lhs.offset < rhs.offset
            }
        }.map(\.element)
    }

    /// The environment of a question: "Production", "Production?" (production only by default:
    /// the owner can correct it), or "Development".
    static func environment(_ items: [QuestionInfo.Item]) -> String {
        if items.contains(where: { $0.production && !$0.unconfirmed }) { return "Production" }
        if items.contains(where: \.unconfirmed) { return "Production?" }
        return "Development"
    }

    /// Whether `question` is the same run as `run`: the asking Mac sends each waiting run to the
    /// relay too.
    private static func shows(_ question: RemoteQuestion, _ run: PendingRun) -> Bool {
        guard let card = question.card else { return false }
        return card.run.id == run.id && card.run.agent == run.agent && card.run.command == run.command
    }
}

/// The names of the agents as the owner knows them.
enum AgentName {
    private static let known = [
        "claude-code": "Claude Code", "claude": "Claude Code", "codex": "Codex", "t3-code": "T3 Code",
        "cursor": "Cursor", "gemini-cli": "Gemini CLI", "opencode": "OpenCode",
    ]

    /// "claude-code" → "Claude Code"; an agent Apassy does not know keeps its name.
    static func display(_ agent: String) -> String {
        known[agent.lowercased()] ?? agent
    }
}

extension RemoteQuestion {
    /// The credential of the row: the first item, and how many more.
    var credentialTitle: String {
        guard let items = card?.question.items, let first = items.first else { return "A question" }
        return items.count > 1 ? "\(first.name) +\(items.count - 1)" : first.name
    }

    /// Seconds left until the question expires, rounded up, never below 0.
    func secondsLeft(now: Date) -> Int {
        Decisions.secondsLeft(until: Date(timeIntervalSince1970: TimeInterval(expiresAt)), now: now)
    }
}
