import ApassyVaultKit
import CryptoKit
import Foundation
import Testing

@testable import ApassyVaultCore

/// An iPhone with two vaults, each with its own questions team, against the real core and two
/// fake Macs (`ios/ApassyCore/examples/questions_macs.rs`, built by `scripts/build-ios-core.sh mac`)
/// on the fake relay of the core's tests. Synthetic values only; no network beyond 127.0.0.1.
@Suite struct CoreMultiVaultQuestionsTests {
    @Test(.timeLimit(.minutes(2))) func twoVaultsOnOneIPhone() async throws {
        guard let binary = Self.macsBinary() else {
            Issue.record("Build it with scripts/build-ios-core.sh mac")
            return
        }
        let dir = FileManager.default.temporaryDirectory.appending(path: "apassy-core-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }

        let macs = MacsProcess(binary: binary)
        try macs.start()
        defer { macs.stop() }

        // a. Both vaults join through the links of the two Macs.
        let ready = try await macs.event("ready", timeout: 30)
        let passphrase = try #require(ready["passphrase"] as? String)
        let links = try #require(ready["links"] as? [String: String])

        let core = try CoreVaultService(dataDirectory: dir, deviceName: "Test iPhone", role: .app)
        let key = P256.Signing.PrivateKey()
        for name in ["Personal", "Work"] {
            let link = try #require(links[name])
            _ = try await core.joinStart(link: link, deviceName: "Test iPhone", answerKey: key.publicKey.x963Representation)
            // The Mac confirms, writes the row of this iPhone, and syncs; only then may the poll
            // download the copy, or the copy would not hold the row yet.
            let confirmed = try await macs.event("confirmed", timeout: 20)
            #expect(confirmed["vault"] as? String == name)
            try await Self.eventually("the join of \(name) got ready", timeout: 20) {
                try await core.joinPoll().state == .ready
            }
            let entry = try await core.joinFinish(passphrase: passphrase)
            #expect(entry.name == name)
        }
        let vaults = try await core.info().vaults
        let personal = try #require(vaults.first { $0.name == "Personal" }).id
        let work = try #require(vaults.first { $0.name == "Work" }).id
        #expect(personal != work)

        // b. A fresh session: Work is the selected vault, Personal gets its context by questionsUnlock.
        try await core.lock()
        try await core.unlock(passphrase: passphrase, keep: true)
        #expect(try await core.info().selected == work)
        try macs.send("ask")

        // c. The questions of both vaults, each with its card.
        let names = [personal: "Personal", work: "Work"]
        let unlocked = try await core.questionsUnlock(vaultID: personal, passphrase: passphrase)
        #expect(unlocked.enabled && unlocked.registered)
        let both = try await Self.openQuestions(core, count: 2)
        #expect(Set(both.vaults?.map(\.vaultID) ?? []) == [personal, work])
        #expect(both.vaults?.count == 2)
        try Self.expectOneQuestionEach(both, names: names)

        // d. A suspend drops the context of Personal; the selected vault keeps its question.
        try await core.suspend()
        #expect(try await core.resume())
        let resumed = try await Self.openQuestions(core, count: 1)
        #expect(resumed.vaults?.map(\.vaultID) == [work])
        #expect(Set(resumed.questions.compactMap(\.vaultID)) == [work])

        // e. questionsUnlock brings Personal back, and only with its own passphrase.
        do {
            _ = try await core.questionsUnlock(vaultID: personal, passphrase: "wrong-pass-123")
            Issue.record("a wrong passphrase unlocked the questions of a vault")
        } catch let error as VaultError {
            #expect(error.code == .wrongPassphrase)
        }
        let status = try await core.questionsUnlock(vaultID: personal, passphrase: passphrase)
        #expect(status.enabled && status.registered)
        let again = try await Self.openQuestions(core, count: 2)
        #expect(again.vaults?.count == 2)
        #expect(Set(again.vaults?.map(\.vaultID) ?? []) == [personal, work])
        try Self.expectOneQuestionEach(again, names: names)
        let personalQ = try #require(again.questions.first { $0.vaultID == personal })
        let workQ = try #require(again.questions.first { $0.vaultID == work })

        // f. The answer names the vault of the question: Work does not know the question of Personal.
        do {
            _ = try await core.questionAnswer(
                qid: personalQ.qid, answer: RemoteAnswer(kind: .deny), time: Int64(Date().timeIntervalSince1970),
                signature: nil, vaultID: work)
            Issue.record("a question was answered through the wrong vault")
        } catch let error as VaultError {
            #expect(error.code == .wrongVault)
        }

        // g. Personal is approved with the answer key, Work is denied.
        let prepared = try await core.questionAnswerString(
            qid: personalQ.qid, answer: RemoteAnswer(kind: .approveOnce), vaultID: personal)
        #expect(prepared.needsFaceID)
        let signature = try key.signature(for: Data(prepared.answerString.utf8)).derRepresentation
        _ = try await core.questionAnswer(
            qid: personalQ.qid, answer: RemoteAnswer(kind: .approveOnce), time: prepared.time,
            signature: signature, vaultID: personal)
        _ = try await core.questionAnswer(
            qid: workQ.qid, answer: RemoteAnswer(kind: .deny), time: Int64(Date().timeIntervalSince1970),
            signature: nil, vaultID: work)

        // h. Each Mac got the answer of its own vault.
        var outcomes: [String: String] = [:]
        for _ in 0..<2 {
            let event = try await macs.event("settled", timeout: 30)
            outcomes[try #require(event["vault"] as? String)] = event["outcome"] as? String
        }
        #expect(outcomes == ["Personal": "approved", "Work": "denied"])

        // i. questionsUnlock of the open selected vault checks its passphrase too.
        do {
            _ = try await core.questionsUnlock(vaultID: work, passphrase: "wrong-pass-123")
            Issue.record("a wrong passphrase passed for the open vault")
        } catch let error as VaultError {
            #expect(error.code == .wrongPassphrase)
        }

        // j. Notifications off with Work open only: Personal keeps the token until it opens.
        try await core.suspend()
        #expect(try await core.resume())
        let cleared = try await core.pushTokenClear()
        #expect(cleared.cleared == [work])
        #expect(cleared.pending == [personal])
    }

    // MARK: helpers

    /// `APASSY_QUESTIONS_MACS`, or `ios/ApassyCore/build/questions-macs` of this checkout.
    static func macsBinary() -> URL? {
        var path = ProcessInfo.processInfo.environment["APASSY_QUESTIONS_MACS"].map { URL(fileURLWithPath: $0) }
        if path == nil {
            var repo = URL(fileURLWithPath: #filePath)
            for _ in 0..<5 { repo.deleteLastPathComponent() }
            path = repo.appending(path: "ios/ApassyCore/build/questions-macs")
        }
        guard let path, FileManager.default.isExecutableFile(atPath: path.path(percentEncoded: false)) else {
            return nil
        }
        return path
    }

    /// Run `check` every 100 ms until it holds.
    static func eventually(
        _ what: String, timeout: TimeInterval, _ check: () async throws -> Bool
    ) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while try await !check() {
            guard Date() < deadline else {
                Issue.record("Timed out: \(what)")
                throw CancellationError()
            }
            try await Task.sleep(for: .milliseconds(100))
        }
    }

    /// The list once it has `count` open questions with a card.
    static func openQuestions(_ core: CoreVaultService, count: Int) async throws -> QuestionsList {
        var last = QuestionsList.off
        try await eventually("\(count) open questions with a card", timeout: 20) {
            last = try await core.questionsList()
            return last.questions.filter { $0.state == .open && $0.card != nil }.count >= count
        }
        return last
    }

    /// Two questions, one of each vault, with the name of their vault.
    static func expectOneQuestionEach(_ list: QuestionsList, names: [String: String]) throws {
        let open = list.questions.filter { $0.state == .open && $0.card != nil }
        #expect(open.count == 2)
        #expect(Set(open.compactMap(\.vaultID)) == Set(names.keys))
        for question in open {
            #expect(question.vaultName == question.vaultID.flatMap { names[$0] })
        }
    }
}

/// The helper program with two fake Macs: JSON lines on stdout, `ask` lines on stdin.
final class MacsProcess: @unchecked Sendable {
    private let process = Process()
    private let input = Pipe()
    private let output = Pipe()
    private let lock = NSLock()
    private var events: [[String: Any]] = []
    private var buffer = Data()

    init(binary: URL) {
        process.executableURL = binary
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.standardError
    }

    func start() throws {
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            self?.take(handle.availableData)
        }
        try process.run()
    }

    func stop() {
        output.fileHandleForReading.readabilityHandler = nil
        try? input.fileHandleForWriting.close()
        if process.isRunning { process.terminate() }
    }

    func send(_ line: String) throws {
        try input.fileHandleForWriting.write(contentsOf: Data((line + "\n").utf8))
    }

    private func take(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }
        buffer.append(data)
        while let newline = buffer.firstIndex(of: 0x0A) {
            let line = buffer[buffer.startIndex..<newline]
            buffer.removeSubrange(buffer.startIndex...newline)
            if let object = try? JSONSerialization.jsonObject(with: line) as? [String: Any] {
                events.append(object)
            }
        }
    }

    private func pop(_ name: String) -> [String: Any]? {
        lock.lock()
        defer { lock.unlock() }
        guard let at = events.firstIndex(where: { $0["event"] as? String == name }) else { return nil }
        return events.remove(at: at)
    }

    /// The next event named `name` (others stay for later calls).
    func event(_ name: String, timeout: TimeInterval) async throws -> [String: Any] {
        let deadline = Date().addingTimeInterval(timeout)
        while true {
            if let event = pop(name) { return event }
            guard Date() < deadline, process.isRunning || hasEvents else {
                Issue.record("No \"\(name)\" event from the fake Macs within \(Int(timeout)) s")
                throw CancellationError()
            }
            try await Task.sleep(for: .milliseconds(50))
        }
    }

    private var hasEvents: Bool {
        lock.lock()
        defer { lock.unlock() }
        return !events.isEmpty
    }
}
