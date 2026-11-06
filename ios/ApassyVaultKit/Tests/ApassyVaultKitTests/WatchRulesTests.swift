import Foundation
import Security
import Testing
@testable import ApassyVaultKit

/// The pure rules of the Apple Watch (ADR 0039, flow spec A1 to A4, S1 to S5).
@Suite struct WatchRulesTests {
    private let now = Date(timeIntervalSince1970: 1_800_000_100)
    private var seconds: UInt64 { UInt64(now.timeIntervalSince1970) }
    private let key = Data([4] + [UInt8](repeating: 7, count: 64))

    private func request(
        action: String? = "deploy", hosts: [String] = ["api.github.com"], project: String? = "shop",
        cwd: String = "/Users/owner/Dev/shop", valid: [AccessChoice] = [.deny, .allow_once], reason: String? = nil,
        state: String = "open", expiresIn: Int64 = 200
    ) -> RelayAccessRequest {
        WatchPreview.request(
            action: action, hosts: hosts, project: project, cwd: cwd, validAnswers: valid, localReviewReason: reason,
            state: state, answerKey: key, created: seconds - 100, expires: UInt64(Int64(seconds) + expiresIn))
    }

    // MARK: - The Connect code and the name

    @Test func aConnectCodeNeedsATeamAndAHandoff() {
        #expect(WatchConnectLink.isConnectLink(WatchPreview.link))
        #expect(WatchConnectLink.isConnectLink("  \(WatchPreview.link)\n"))
        #expect(WatchConnectLink.team(of: WatchPreview.link) == "t_7k2m5q4x3c")
        // A plain device link cannot connect a watch.
        #expect(!WatchConnectLink.isConnectLink("https://relay.example.test/join#apassy_lnk_t_7k2m5q4x3c_0123456789abcdef"))
        // A handoff without a device link of the relay.
        #expect(!WatchConnectLink.isConnectLink("apassy://pair?code=1&handoff=2.a.b.c"))
        // A team that is not lower-case base32.
        #expect(!WatchConnectLink.isConnectLink("apassy_lnk_t_7K2M5Q4X3C_0123456789abcdef&handoff=2.a.b.c"))
        #expect(WatchConnectLink.team(of: "apassy_lnk_t_7k2m5q4x3c_&handoff=2") == nil)
    }

    @Test func theNameOfTheWatchFitsSeventeenBytes() {
        let cut = WatchConnectLink.defaultName(deviceName: "Rafal’s Apple Watch Ultra")
        #expect(cut == "Rafal’s Apple W")
        #expect(cut.utf8.count <= WatchConnectLink.maxNameBytes)
        // Never half a character.
        #expect(WatchConnectLink.defaultName(deviceName: "⌚️⌚️⌚️⌚️") == "⌚️⌚️")
        // A space at the end of the cut goes.
        #expect(WatchConnectLink.defaultName(deviceName: "Personal Watches X") == "Personal Watches")
        #expect(WatchConnectLink.defaultName(deviceName: "Work Watch Series") == "Work Watch Series")
        #expect(WatchConnectLink.defaultName(deviceName: "Work Watch Series X") == "Work Watch Series")
        #expect(WatchConnectLink.defaultName(deviceName: "") == "Apple Watch")
        // A generic system name is kept.
        #expect(WatchConnectLink.defaultName(deviceName: "Apple Watch") == "Apple Watch")
        #expect(WatchConnectLink.defaultName(deviceName: " \t ") == "Apple Watch")
        #expect(WatchConnectLink.defaultName(deviceName: "\u{7}Watch") == "Watch")
    }

    // MARK: - The wire

    @Test func theStatusDecodesWithAndWithoutTheRowOfTheWatch() throws {
        let ready = try JSONDecoder().decode(
            WatchStatus.self,
            from: Data(#"{"state":"ready","vault":{"id":"v1","name":"Personal"},"macs":["Studio Mac"],"own":{"found":true,"answer_key_matches":false}}"#.utf8))
        #expect(ready.state == .ready)
        #expect(ready.vault == WatchVault(id: "v1", name: "Personal"))
        #expect(ready.macs == ["Studio Mac"])
        #expect(ready.own == WatchStatus.Own(found: true, answerKeyMatches: false))
        let unpaired = try JSONDecoder().decode(
            WatchStatus.self, from: Data(#"{"state":"unpaired","vault":null,"macs":[],"own":null}"#.utf8))
        #expect(unpaired.state == .unpaired && unpaired.vault == nil && unpaired.own == nil)
        let locked = try JSONDecoder().decode(WatchStatus.self, from: Data(#"{"state":"locked"}"#.utf8))
        #expect(locked.state == .locked && locked.macs.isEmpty)
        #expect(throws: (any Error).self) {
            try JSONDecoder().decode(WatchStatus.self, from: Data(#"{"state":"paired"}"#.utf8))
        }
    }

    @Test func theConnectionDecodesWaitingAndAttached() throws {
        let waiting = try JSONDecoder().decode(
            WatchConnectInfo.self,
            from: Data(#"{"state":"waiting","words":["amber","cobalt","harbor","lunar","orbit","velvet"],"expires_at":1800000600}"#.utf8))
        #expect(waiting.state == .waiting)
        #expect(waiting.words.count == 6)
        #expect(waiting.expiresAt == 1_800_000_600)
        let attached = try JSONDecoder().decode(
            WatchConnectInfo.self, from: Data(#"{"state":"attached","vault":{"id":"v1","name":"Studio Mac"}}"#.utf8))
        #expect(attached.state == .attached && attached.words.isEmpty)
        #expect(attached.vault?.name == "Studio Mac")
    }

    @Test func theConnectProblemsUseTheWordsOfTheSpec() {
        #expect(WatchConnectProblem.of(VaultError(.joinRefused, "x")) == .wordsDiffer)
        #expect(WatchConnectProblem.of(VaultError(.linkInvalid, "x")) == .codeExpired)
        #expect(WatchConnectProblem.of(VaultError(.relayUnreachable, "x")) == .relayUnreachable(detail: nil))
        #expect(WatchConnectProblem.of(VaultError(.rateLimited, "x")) == .relayUnreachable(detail: nil))
        #expect(
            WatchConnectProblem.relayUnreachable(detail: nil).text
                == "Couldn't reach the relay. Check that this watch is online, then start again on your iPhone.")
        #expect(
            WatchConnectProblem.relayUnreachable(detail: "connect: URLError -1009").text
                == "Couldn't reach the relay. Check that this watch is online, then start again on your iPhone.\n\nDetails: connect: URLError -1009")
        #expect(
            WatchConnectProblem.of(VaultError(.macUpdateNeeded, "Update Apassy on your Mac to connect this watch."))
                == .other("Update Apassy on your Mac to connect this watch."))
        #expect(WatchConnectProblem.wordsDiffer.text == "The words didn't match, so nothing was connected. Start again on your iPhone.")
        #expect(WatchConnectProblem.codeExpired.text == "The code expired. Show a new code on your Mac.")
    }

    // MARK: - Text

    @Test func agentTextIsEscaped() {
        #expect(WatchRequestText.escaped(#"a\b"#) == #"a\\b"#)
        #expect(WatchRequestText.escaped("\u{202E}gnp.exe") == #"\u{202e}gnp.exe"#)
        #expect(WatchRequestText.escaped("one\ntwo") == #"one\u{a}two"#)
        // Line and paragraph separators break lines in a label: shown, never applied. The iPhone
        // uses the same function.
        #expect(AccessText.escaped("ok\u{2028}Allow") == #"ok\u{2028}Allow"#)
        #expect(AccessText.escaped("ok\u{2029}Allow") == #"ok\u{2029}Allow"#)
        #expect(WatchRequestText.escaped("a\u{2028}b") == AccessText.escaped("a\u{2028}b"))
        let card = request().card
        #expect(WatchRequestText.title(card) == "Claude Code asks for GitHub token")
        #expect(WatchRequestText.askedOn(card) == "Asked on Studio Mac · Personal")
        #expect(WatchRequestText.environment(card) == "Production")
        #expect(WatchRequestText.delivery(card) == "Real value reaches the process")
        #expect(WatchRequestText.hostProvenance(card) == "Agent-reported host (not verified): claude-code")
    }

    @Test func theRowSaysUntilOrHowItEnded() {
        let open = request()
        #expect(WatchRequestText.rowStatus(open, at: now).hasPrefix("Until "))
        #expect(WatchRequestText.rowStatus(open, at: now.addingTimeInterval(300)) == "Expired")
        #expect(WatchRequestText.rowStatus(request(state: "expired"), at: now) == "Expired")
        #expect(WatchRequestText.rowStatus(WatchPreview.settled(open, choice: .allow_once, byWatch: false), at: now) == "Allowed once")
        #expect(WatchRequestText.rowStatus(WatchPreview.settled(open, choice: .deny, byWatch: true), at: now) == "Denied")
        let label = WatchRequestText.rowAccessibility(open, at: now)
        #expect(label.hasPrefix("Claude Code asks for GitHub token on Studio Mac, Production, until "))
    }

    // MARK: - Deny only

    @Test func anIncompleteScopeIsDenyOnlyAndSaysWhatIsMissing() {
        let card = request(action: nil, hosts: []).card
        #expect(WatchRequestRules.missingScope(card) == ["the action", "the hosts"])
        #expect(!WatchRequestRules.offersAllowOnce(card))
        #expect(WatchRequestRules.denyOnlyNote(card) == "Review on Studio Mac: this request does not specify the action or the hosts.")
        let three = request(action: "", hosts: [], project: nil).card
        #expect(WatchRequestRules.denyOnlyNote(three)
            == "Review on Studio Mac: this request does not specify the action, the hosts, or the project.")
        let folder = request(cwd: "").card
        #expect(WatchRequestRules.missingScope(folder) == ["the folder"])
    }

    @Test func aCardWithoutAllowOnceGivesTheReasonOfTheMac() {
        let card = request(valid: [.deny], reason: "Production needs a review on the Mac.").card
        #expect(WatchRequestRules.denyOnlyNote(card) == "Review on Studio Mac: Production needs a review on the Mac.")
        #expect(WatchRequestRules.phase(of: request(valid: [.deny]), progress: nil, allowBlock: nil, at: now)
            == .decide(allowOnce: false, notes: ["Review on Studio Mac."]))
        #expect(WatchRequestRules.denyOnlyNote(request().card) == nil)
    }

    // MARK: - The phases of A2

    @Test func aCompleteRequestOffersBothAnswers() {
        #expect(WatchRequestRules.phase(of: request(), progress: nil, allowBlock: nil, at: now)
            == .decide(allowOnce: true, notes: []))
        #expect(WatchRequestRules.phase(of: request(), progress: nil, allowBlock: "Update Apassy on your Mac to connect this watch.", at: now)
            == .decide(allowOnce: false, notes: ["Update Apassy on your Mac to connect this watch."]))
        #expect(WatchRequestRules.phase(of: nil, progress: nil, allowBlock: nil, at: now) == .unavailable)
    }

    @Test func aRefusedWristCheckKeepsDeny() {
        #expect(WatchRequestRules.phase(of: request(), progress: .refused, allowBlock: nil, at: now)
            == .decide(allowOnce: true, notes: ["Allow once needs this watch unlocked on your wrist. Nothing was sent."]))
    }

    @Test func aSentAnswerIsNotConfirmedAfterSixtySecondsOrTheExpiry() {
        let sent = WatchAnswerProgress.sent(.allow_once, at: now)
        #expect(WatchRequestRules.phase(of: request(), progress: sent, allowBlock: nil, at: now.addingTimeInterval(59)) == .sent)
        #expect(WatchRequestRules.phase(of: request(), progress: sent, allowBlock: nil, at: now.addingTimeInterval(60)) == .notConfirmed)
        #expect(WatchRequestRules.phase(of: request(expiresIn: 30), progress: sent, allowBlock: nil, at: now.addingTimeInterval(31))
            == .notConfirmed)
        #expect(WatchRequestRules.phase(of: request(), progress: .uncertain(.deny), allowBlock: nil, at: now) == .notConfirmed)
    }

    @Test func expiryEndsTheDecisionAndTheWristCheck() {
        let late = now.addingTimeInterval(201)
        #expect(WatchRequestRules.phase(of: request(), progress: nil, allowBlock: nil, at: late) == .expired)
        #expect(WatchRequestRules.phase(of: request(), progress: .checkingWrist, allowBlock: nil, at: late) == .expired)
        #expect(WatchRequestRules.phase(of: request(), progress: .checkingWrist, allowBlock: nil, at: now) == .checkingWrist)
        #expect(WatchRequestRules.phase(of: request(state: "expired"), progress: nil, allowBlock: nil, at: now) == .expired)
        #expect(!WatchRequestRules.isActionable(request(), at: late))
        // Ended without a receipt that the watch can check.
        #expect(WatchRequestRules.phase(of: request(state: "settled"), progress: nil, allowBlock: nil, at: now) == .ended)
    }

    @Test func aConfirmedAnswerOfThisWatchIsAnsweredOnThisWatch() throws {
        let allowed = WatchPreview.settled(request(), choice: .allow_once, byWatch: true)
        let phase = WatchRequestRules.phase(of: allowed, progress: .sent(.allow_once, at: now), allowBlock: nil, at: now)
        guard case .result(let result) = phase else {
            Issue.record("not a result: \(phase)")
            return
        }
        #expect(result.outcome == .allowedOnce && result.byThisWatch)
        #expect(result.headline == "Allowed once")
        let lines = result.lines(mac: "Studio Mac")
        #expect(lines.first?.hasPrefix("Consent recorded for one attempt before ") == true)
        #expect(lines.contains("The bouncer still checks the command and may ask you."))
        #expect(lines.contains("Check on Studio Mac for remaining availability."))
        #expect(lines.last == "Answered on This watch")
        #expect(!lines.contains("Access expired"))
        let past = WatchRequestRules.result(
            of: try #require(allowed.receipt), card: allowed.card, progress: nil, at: now.addingTimeInterval(201))
        #expect(past.lines(mac: "Studio Mac").contains("Access expired"))
    }

    @Test func anAnswerOfAnotherDeviceIsNeverCreditedToThisWatch() throws {
        let iphone = WatchPreview.settled(request(), choice: .deny, byWatch: false)
        let receipt = try #require(iphone.receipt)
        let elsewhere = WatchRequestRules.result(of: receipt, card: iphone.card, progress: .sent(.deny, at: now), at: now)
        #expect(!elsewhere.byThisWatch)
        #expect(elsewhere.answeredOn == "Synthetic iPhone")
        #expect(elsewhere.lines(mac: "Studio Mac") == ["Nothing was allowed.", "Answered on Synthetic iPhone"])
        // A watch answered, but not with the answer of this watch.
        let watch = WatchPreview.settled(request(), choice: .allow_once, byWatch: true)
        let other = WatchRequestRules.result(
            of: try #require(watch.receipt), card: watch.card, progress: .sent(.deny, at: now), at: now)
        #expect(!other.byThisWatch)
        // Seen in the list only: no answer of this watch.
        let seen = WatchRequestRules.result(of: try #require(watch.receipt), card: watch.card, progress: nil, at: now)
        #expect(!seen.byThisWatch)
    }

    @Test func theKeyOfTheRowMustBeTheKeyOfThisWatch() {
        #expect(WatchRequestRules.keyMatches(request(), own: key))
        #expect(!WatchRequestRules.keyMatches(request(), own: Data([4] + [UInt8](repeating: 8, count: 64))))
        #expect(!WatchRequestRules.keyMatches(request(), own: nil))
    }

    @Test func theAnswerKeyPolicyIsInOnePlace() {
        #expect(WatchAnswerKeyPolicy.flags == [.privateKeyUsage, .userPresence])
        #expect((WatchAnswerKeyPolicy.protection as String) == (kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String))
        #expect(WatchAnswerKeyPolicy.service(team: "t_7k2m5q4x3c") == "com.wydrox.apassy.watch.answer-key.t_7k2m5q4x3c")
    }
}
