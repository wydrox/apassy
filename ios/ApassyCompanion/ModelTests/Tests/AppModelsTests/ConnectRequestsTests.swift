import ApassyCompanionKit
import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

/// Connect requests on the iPhone (card v2 `kind = connect`, contract relay-questions-v1 section
/// 7.4) and ADR 0028 stage 1 in Requests.
@MainActor
@Suite("Connect requests and Wi-Fi only")
struct ConnectRequestsTests {
    @MainActor
    final class Fixture {
        let service = PreviewVaultService()
        let signer = ScriptedSigner()
        let model: QuestionsModel

        init() {
            let suite = "connect-\(UUID().uuidString)"
            let defaults = UserDefaults(suiteName: suite)!
            defaults.removePersistentDomain(forName: suite)
            model = QuestionsModel(
                service: service, signer: signer, push: ScriptedPush(allows: true), deviceName: "Test iPhone",
                defaults: defaults, retryInterval: .milliseconds(10))
        }

        func withConnect() async -> RemoteQuestion {
            let question = PreviewVaultService.sampleConnectQuestion()
            await service.setQuestions(enabled: true, questions: [question])
            await model.refresh()
            return question
        }
    }

    @Test("a connect card decodes from the core, next to a run card that has none")
    func decodesConnect() throws {
        let json = """
            {"qid":"oKGio6SlpqeoqaqrrK2urw","vault_id":"v1","vault_name":"Personal","state":"open",
             "asker_name":"Mac mini (office)","created_at":1790000000,"expires_at":1790000300,
             "problem":null,"card":null,"settle":null,"answered":null,
             "connect":{"asker_device":"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d","created_at":1790000000,
              "id":"cr_7Hq2xN","client_name":"Grok Bot","mac_name":"Mac mini (office)","code":"K7Q-4MD",
              "expires_at":1790000300,"digest":"414fa0828bfabc762b01548be58bda38868fd5c216a63daf70839aea21a61bcc"}}
            """
        let question = try JSONDecoder().decode(RemoteQuestion.self, from: Data(json.utf8))
        let connect = try #require(question.connect)
        #expect(question.card == nil)
        #expect(connect.clientName == "Grok Bot")
        #expect(connect.macName == "Mac mini (office)")
        #expect(connect.code == "K7Q-4MD")
        #expect(connect.id == "cr_7Hq2xN")
        #expect(connect.expiresAt == 1_790_000_300)
        // A run card from the core has no `connect` key at all.
        var run = try JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
        run.removeValue(forKey: "connect")
        let decoded = try JSONDecoder().decode(
            RemoteQuestion.self, from: JSONSerialization.data(withJSONObject: run))
        #expect(decoded.connect == nil)
    }

    @Test("a connect request waits in Requests as \"<name> wants to connect\"")
    func waitsInRequests() async {
        let fixture = Fixture()
        let question = await fixture.withConnect()
        #expect(fixture.model.waitingCount == 1)
        let rows = Decisions.waiting(questions: fixture.model.questions, session: nil, now: Date())
        #expect(rows.count == 1)
        #expect(rows[0].title == "Grok Bot wants to connect")
        #expect(rows[0].subtitle == "Mac mini (office)")
        #expect(rows[0].agent == "Grok Bot")
        #expect(question.credentialTitle == "Grok Bot wants to connect")
        #expect(fixture.model.canAnswerConnect(fixture.model.questions[0], now: Date()))
        // The run actions of a connect card stay off: it is answered with Deny or Allow only.
        #expect(!fixture.model.listActions(for: fixture.model.questions[0], now: Date()).canDeny)
    }

    @Test("Allow asks for Face ID for this answer and sends allow_connect with the signature")
    func allowNeedsFaceID() async throws {
        let fixture = Fixture()
        let question = await fixture.withConnect()
        await fixture.model.answerConnect(allow: true, for: fixture.model.questions[0])
        #expect(fixture.signer.reasons == ["allow \"Grok Bot\" to connect to Mac mini (office)"])
        let sent = await fixture.service.sentAnswers()
        #expect(sent.map(\.answer.kind) == [.allowConnect])
        #expect(sent[0].signature == Data("signature".utf8))
        #expect(fixture.model.delivery(for: question) == .sent(.allowConnect))
        #expect(!fixture.model.canAnswerConnect(fixture.model.questions[0], now: Date()))
        // Sent once: a second tap sends nothing.
        await fixture.model.answerConnect(allow: true, for: fixture.model.questions[0])
        #expect(await fixture.service.sentAnswers().count == 1)
    }

    @Test("Deny goes without Face ID")
    func denyNeedsNoFaceID() async {
        let fixture = Fixture()
        let question = await fixture.withConnect()
        await fixture.model.answerConnect(allow: false, for: question)
        #expect(fixture.signer.reasons.isEmpty)
        let sent = await fixture.service.sentAnswers()
        #expect(sent.map(\.answer.kind) == [.deny])
        #expect(sent.allSatisfy { $0.signature == nil })
    }

    @Test("a cancelled Face ID sends nothing")
    func cancelledFaceID() async {
        let fixture = Fixture()
        let question = await fixture.withConnect()
        fixture.signer.fail(with: .cancelled)
        await fixture.model.answerConnect(allow: true, for: question)
        #expect(await fixture.service.sentAnswers().isEmpty)
        #expect(fixture.model.delivery(for: question) == nil)
    }

    @Test("a run card never sends a connect answer, and a connect card never sends a run answer")
    func kindsStayApart() async {
        let fixture = Fixture()
        let run = PreviewVaultService.sampleQuestion()
        await fixture.service.setQuestions(enabled: true, questions: [run])
        await fixture.model.refresh()
        await fixture.model.answerConnect(allow: true, for: fixture.model.questions[0])
        #expect(await fixture.service.sentAnswers().isEmpty)
        let connected = Fixture()
        let question = await connected.withConnect()
        await connected.model.send(
            AnswerBar.Choice(answer: RemoteAnswer(kind: .approve), label: "Allow"), for: question)
        #expect(await connected.service.sentAnswers().isEmpty)
        #expect(AnswerKind.allowConnect.rawValue == "allow_connect")
        #expect(RemoteAnswer(kind: .allowConnect).needsFaceID)
    }

    @Test("the Face ID text names the client and the Mac without control characters or quotes")
    func faceIDText() {
        #expect(
            QuestionsModel.connectFaceIDReason(client: "Grok \"Bot\"\n", mac: "Mac mini")
                == "allow \"Grok Bot\" to connect to Mac mini")
        let long = String(repeating: "x", count: 60)
        #expect(QuestionsModel.connectFaceIDReason(client: long, mac: "M").contains(String(repeating: "x", count: 40) + "\""))
    }

    @Test("the card tells the owner to allow only when the browser page shows the same code")
    func codeWarning() {
        #expect(
            QuestionsModel.connectCodeWarning(code: "K7Q-4MD")
                == "Allow only if the page in your browser shows this code: K7Q-4MD.")
    }

    // MARK: ADR 0028 stage 1

    @Test("one quiet line for each vault whose requests do not come through the relay")
    func wifiOnlyLines() {
        let entries = [(id: "a", name: "Personal"), (id: "b", name: "Work"), (id: "c", name: "Family")]
        #expect(
            Decisions.wifiOnlyVaults(entries: entries, selected: "a", selectedOff: true, withoutQuestions: ["c"])
                == ["Personal", "Family"])
        #expect(
            Decisions.wifiOnlyVaults(entries: entries, selected: "a", selectedOff: false, withoutQuestions: [])
                .isEmpty)
        #expect(
            Decisions.wifiOnlyVaults(entries: entries, selected: nil, selectedOff: true, withoutQuestions: ["b"])
                == ["Work"])
        #expect(
            Decisions.wifiOnlyLine(vault: "Personal")
                == "Requests from Personal reach this iPhone only on the same Wi-Fi as the Mac. Turn on relay questions on the Mac.")
    }

    @Test("without a vault model there is no quiet line")
    func noQuietLineWithoutVaults() async {
        let fixture = Fixture()
        await fixture.model.refresh()
        #expect(fixture.model.phase == .off)
        #expect(fixture.model.wifiOnlyVaultNames.isEmpty)
    }

    @Test("the Wi-Fi state shows in Settings › Devices only")
    func wifiStateOnlyInSettings() throws {
        #expect(SessionModel.ConnectionState.connected.wifiText == "Connected")
        #expect(SessionModel.ConnectionState.connecting.wifiText == "Connecting")
        #expect(SessionModel.ConnectionState.unreachable.wifiText == "Not on this Wi-Fi")
        #expect(SessionModel.ConnectionState.problem("x").wifiText == "Unavailable")
        // Requests has no "<Mac> is unavailable" card any more; it has the quiet line.
        let sources = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("Sources")
        let requests = try String(
            contentsOf: sources.appendingPathComponent("Views/Decisions/DecisionsView.swift"), encoding: .utf8)
        #expect(!requests.contains("wifi.exclamationmark"))
        #expect(!requests.contains("macName) is unavailable"))
        #expect(requests.contains("wifiOnlyVaultNames"))
        let devices = try String(
            contentsOf: sources.appendingPathComponent("Views/Settings/DevicesSettingsView.swift"), encoding: .utf8)
        #expect(devices.contains("on Wi-Fi\", value: session.state.wifiText"))
    }
}
