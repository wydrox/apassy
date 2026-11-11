import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

/// Plan s7 unit I3 on the iPhone: "Forget This iPhone…" and the line of the devices that are not
/// verified in Settings > Devices, a malformed code of "Add a device…", and the end of the free
/// approvals through the hosted relay. Plan section 6 (App Store Review Guideline 3.1): no text here
/// names a price, a currency, a plan to buy, or a link. Synthetic values only.
@MainActor
@Suite("Apassy Connect account on the iPhone")
struct ConnectAccountTests {
    static let devices = [
        ConnectDevice(deviceID: "dev_m2k7q3x4ab", name: "MacBook Pro", platform: "mac", isThisDevice: false, verified: true),
        ConnectDevice(deviceID: "dev_p4n6r2t7bc", name: "iPhone", platform: "iphone", isThisDevice: true, verified: true),
    ]

    static func account(
        removed: Bool = false, devices: [ConnectDevice] = devices, listVerified: Bool? = nil
    ) -> ConnectStatus {
        ConnectStatus(
            state: .account, removed: removed, accountID: "acc_k7m2q4x3ca", deviceName: "iPhone",
            plan: ConnectPlan(plan: "personal", status: .active, entitled: true), devices: devices,
            listVerified: listVerified)
    }

    static func unverified(_ name: String) -> ConnectDevice {
        ConnectDevice(deviceID: "dev_q5m3s7v2cd", name: name, platform: "mac", isThisDevice: false, verified: false)
    }

    /// Words and signs of a purchase surface (plan section 6), for every text of this unit.
    static let banned = ConnectPlanRowTests.banned.filter { $0 != ".cc" } + ["Connect Personal", "paid", "plan"]

    static var texts: [String] {
        [
            ConnectDevicesText.header, ConnectDevicesText.forgetButton, ConnectDevicesText.confirmTitle,
            ConnectDevicesText.confirmButton, ConnectDevicesText.confirmOnAccount, ConnectDevicesText.confirmRemoved,
            ConnectDevicesText.footer, ConnectDevicesText.forgetFailed, ConnectDevicesText.listNotVerifiedLine,
            ConnectPlanRow.removedLine,
            RelayEndedNotice.value, RelayEndedNotice.line, JoinModel.connectCodeInvalid,
            ConnectDevicesText.notVerifiedLine(account(devices: [unverified("Mac Studio")]))!,
            ConnectDevicesText.notVerifiedLine(account(devices: [unverified("Mac Studio"), unverified("iMac")]))!,
        ]
    }

    @Test("no text of this unit names a price, a currency, a purchase, or a link")
    func noPurchaseText() {
        for text in Self.texts {
            for word in Self.banned {
                #expect(!text.contains(word), "\(word) in “\(text)”")
            }
            #expect(text.range(of: #"\d+[.,]\d{2}"#, options: .regularExpression) == nil, "\(text)")
            #expect(!text.contains("https://"), "\(text)")
        }
    }

    // MARK: Settings > Devices

    @Test("the section shows only on an account, also a removed one")
    func sectionShows() {
        #expect(ConnectDevicesText.shows(Self.account()))
        #expect(ConnectDevicesText.shows(Self.account(removed: true)))
        #expect(!ConnectDevicesText.shows(ConnectStatus(state: .none)))
        #expect(!ConnectDevicesText.shows(nil))
    }

    @Test("one quiet line counts the devices that are not verified, and names none")
    func notVerifiedLine() {
        #expect(ConnectDevicesText.notVerifiedLine(Self.account()) == nil)
        #expect(
            ConnectDevicesText.notVerifiedLine(Self.account(devices: Self.devices + [Self.unverified("Mac Studio")]))
                == "1 device of the account is not verified. Check Apassy on your Mac.")
        #expect(
            ConnectDevicesText.notVerifiedLine(
                Self.account(devices: Self.devices + [Self.unverified("Mac Studio"), Self.unverified("iMac")]))
                == "2 devices of the account are not verified. Check Apassy on your Mac.")
        // After a removal the list is not this iPhone's account any more; without one, no line.
        #expect(ConnectDevicesText.notVerifiedLine(Self.account(removed: true, devices: [Self.unverified("iMac")])) == nil)
        #expect(ConnectDevicesText.notVerifiedLine(ConnectStatus(state: .none)) == nil)
        #expect(ConnectDevicesText.notVerifiedLine(nil) == nil)
    }

    @Test("a device list that did not verify has its own line, in the place of the count")
    func listNotVerifiedLine() async throws {
        let line = "Apassy could not verify the device list from Connect. Nothing was changed."
        #expect(ConnectDevicesText.listNotVerifiedLine == line)
        let unverified = Self.devices.map { Self.unverified($0.name) }
        #expect(ConnectDevicesText.notVerifiedLine(Self.account(devices: unverified, listVerified: false)) == line)
        // Also with no device listed.
        #expect(ConnectDevicesText.notVerifiedLine(Self.account(devices: [], listVerified: false)) == line)
        // A verified list, or none known (Connect did not answer, an older core): as before.
        #expect(ConnectDevicesText.notVerifiedLine(Self.account(listVerified: true)) == nil)
        #expect(
            ConnectDevicesText.notVerifiedLine(Self.account(devices: [Self.unverified("iMac")], listVerified: true))
                == "1 device of the account is not verified. Check Apassy on your Mac.")
        #expect(
            ConnectDevicesText.notVerifiedLine(Self.account(devices: [Self.unverified("iMac")], listVerified: nil))
                == "1 device of the account is not verified. Check Apassy on your Mac.")
        // After a removal: no line.
        #expect(ConnectDevicesText.notVerifiedLine(Self.account(removed: true, listVerified: false)) == nil)

        let service = PreviewVaultService(empty: true)
        await service.setConnectAccount("acc_k7m2q4x3ca", devices: Self.devices, listVerified: false)
        #expect(ConnectDevicesText.notVerifiedLine(try await service.connectStatus()) == line)
    }

    @Test("the confirmation says what Forget does, on an account and after a removal")
    func confirmation() {
        #expect(ConnectDevicesText.forgetButton == "Forget This iPhone…")
        #expect(ConnectDevicesText.confirmMessage(Self.account()) == ConnectDevicesText.confirmOnAccount)
        #expect(ConnectDevicesText.confirmMessage(Self.account(removed: true)) == ConnectDevicesText.confirmRemoved)
        #expect(ConnectDevicesText.confirmOnAccount.contains("Your Mac lists this iPhone until you remove it there."))
    }

    @Test("Forget calls connect_forget, and then this iPhone joins an account again")
    func forgetThenJoinAgain() async throws {
        let service = PreviewVaultService(empty: true)
        await service.setConnectAccount("acc_k7m2q4x3ca", removed: true)
        #expect(ConnectDevicesText.shows(try await service.connectStatus()))
        #expect(try await service.connectForget())
        let after = try await service.connectStatus()
        #expect(after.state == .none)
        #expect(!ConnectDevicesText.shows(after))
        #expect(ConnectPlanRow.content(after).value == "Not on Connect")

        let fixture = ConnectJoinModelTests.Fixture(service: service)
        fixture.model.handleCode(ConnectJoinModelTests.code)
        await fixture.model.start()
        #expect(await waitUntil { fixture.model.step == .connectDone(confirmer: "MacBook Pro") })
        #expect(try await service.connectStatus().state == .account)
    }

    /// The code of a block between `start` and `end` in a source of the app, without comments.
    static func source(_ path: String, from start: String, to end: String) throws -> String {
        let file = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
            .appending(path: path)
        let text = try String(contentsOf: file, encoding: .utf8)
        let from = try #require(text.range(of: start))
        let to = try #require(text.range(of: end, range: from.upperBound..<text.endIndex))
        return text[from.lowerBound..<to.lowerBound]
            .split(separator: "\n", omittingEmptySubsequences: false)
            .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }
            .map { line in line.range(of: "///").map { String(line[..<$0.lowerBound]) } ?? String(line) }
            .joined(separator: "\n")
    }

    @Test("the section has one control (and its confirmation), no link, URL, price, or plan choice")
    func sectionSourceHasOneControl() throws {
        let code = try Self.source(
            "Sources/Views/Settings/DevicesSettingsView.swift", from: "struct ConnectAccountSection",
            to: "/// \"Reaches your Mac through")
        #expect(code.components(separatedBy: "Button(").count - 1 == 2, "the control and the button of its confirmation")
        #expect(code.contains("ConnectDevicesText.forgetButton, role: .destructive"))
        #expect(code.contains("ConnectDevicesText.confirmButton, role: .destructive"))
        #expect(code.contains(".confirmationDialog("))
        #expect(code.contains("connectForget()"))
        for token in [
            "Link", "NavigationLink", "ShareLink", "Menu", "openURL", "onTapGesture", "TapGesture", "contextMenu",
            "swipeActions", "URL(", "http", "Toggle", "Picker", ".sheet", "fullScreenCover", "€", "EUR", "price",
            "subscribe", "Subscribe", "checkout", "portal", "connectJoin",
        ] {
            #expect(!code.contains(token), "\(token) in the Apassy Connect section of Settings > Devices")
        }
    }

    // MARK: The code of "Add a device…"

    @Test("a malformed Connect code gets the core's reason and goes nowhere")
    func malformedCode() async throws {
        let secret = String(repeating: "cd", count: 32)
        let fingerprint = String(repeating: "ab", count: 16)
        for text in [
            // The form before the key fingerprint (PR #134).
            "apassy_alk_acc_k7m2q4x3ca_\(secret)",
            "apassy_alk_acc_k7m2q4x3ca_\(secret)_\(fingerprint.uppercased())",
            "apassy_alk_acc_k7m2q4x3ca_\(secret)_\(fingerprint.dropLast(2))",
            "apassy_alk_acc_k7m2q4x3ca_\(secret)-\(fingerprint)",
            "apassy_alk_",
        ] {
            let service = PreviewVaultService(empty: true)
            let fixture = ConnectJoinModelTests.Fixture(service: service)
            fixture.model.handleCode(text)
            #expect(fixture.model.step == .instructions, "\(text)")
            #expect(fixture.model.scanNote == JoinModel.connectCodeInvalid, "\(text)")
            #expect(await service.connectLinks().isEmpty, "nothing was sent for \(text)")
        }
    }

    @Test("the reason is the core's own text for link_invalid")
    func reasonIsTheCores() throws {
        let file = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "ApassyCore/src/core/connect.rs")
        let core = try String(contentsOf: file, encoding: .utf8)
        #expect(core.contains("\"\(JoinModel.connectCodeInvalid)\""))
    }

    // MARK: The end of the free hosted paths

    @MainActor
    final class Questions {
        let service = PreviewVaultService(empty: false, unlocked: false)
        let vault: VaultModel
        let questions: QuestionsModel

        init(ended: Bool) async {
            let suite = "questions-ended-\(UUID().uuidString)"
            let defaults = UserDefaults(suiteName: suite)!
            defaults.removePersistentDomain(forName: suite)
            await service.setQuestions(enabled: true, questions: [])
            await service.setQuestionsRelayEnded(ended)
            (vault, _) = makeVault(service: service, settings: makeSettings())
            questions = QuestionsModel(
                service: service, signers: SharedAnswerSigners(signer: ScriptedSigner()), push: nil,
                deviceName: "Test iPhone", defaults: defaults, retryInterval: .milliseconds(10))
            questions.follow(vault)
            await vault.start()
            await vault.unlock(passphrase: PreviewVaultService.passphrase)
            await questions.reopenFinished()
            await questions.refresh()
        }
    }

    @Test("an ended team is one calm state: no route, no notice of the free relay, no failure")
    func relayEnded() async {
        let ended = await Questions(ended: true)
        #expect(ended.questions.phase == .ready)
        #expect(ended.questions.relayEnded)
        #expect(ended.questions.questionRoutes.isEmpty, "the route row gives way to the calm state")
        #expect(RelayEndedNotice.value == "Ended")
        #expect(
            RelayEndedNotice.line
                == "Approvals through apassy-relay.wyderka.cc have ended. Pair this iPhone again from Apassy on your Mac.")

        let live = await Questions(ended: false)
        #expect(!live.questions.relayEnded)
        #expect(live.questions.questionRoutes.map(\.route) == [.viaApassyRelay])
    }

    @Test("the Devices row shows the calm state in the place of the route, with no control")
    func relayEndedSource() throws {
        let code = try Self.source(
            "Sources/Views/Settings/DevicesSettingsView.swift", from: "struct QuestionsStateRow",
            to: "private func route(")
        #expect(code.contains("RelayEndedNotice.value"))
        #expect(code.contains("RelayEndedNotice.line"))
        #expect(!code.contains("Button("), "the questions row has no control")
    }
}
