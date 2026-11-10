import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

/// The row "Apassy Connect" of Settings > General and the line "Reaches your Mac through: …" of
/// Settings > Devices (plan s7 unit I1). Plan section 6 (App Store Review Guideline 3.1): the iPhone
/// shows the plan of its account as text, and never a price, a currency, a purchase word, a button,
/// or a link. Synthetic values only.
@Suite("Apassy Connect row")
struct ConnectPlanRowTests {
    static let utc = TimeZone(identifier: "UTC")!
    /// 3 Dec 2026 and 12 Jan 2027, at noon UTC.
    static let renews: Int64 = 1_796_299_200
    static let ends: Int64 = 1_799_755_200

    static func account(_ plan: ConnectPlan?, removed: Bool = false, stale: Bool = false) -> ConnectStatus {
        ConnectStatus(
            state: .account, removed: removed, accountID: "acc_k7m2q4x3ca", deviceName: "iPhone", plan: plan,
            stale: stale)
    }

    /// Every state that the row can show, with its expected value.
    static let cases: [(name: String, status: ConnectStatus?, failed: Bool, value: String)] = [
        ("checking", nil, false, "Checking"),
        ("unavailable", nil, true, "Not available"),
        ("notOnConnect", ConnectStatus(state: .none), false, "Not on Connect"),
        ("notOnConnect after a removal", ConnectStatus(state: .none, removed: true), false, "Not on Connect"),
        (
            "account without a plan", account(ConnectPlan(plan: nil, status: .none, entitled: false)), false,
            "Not on Connect"
        ),
        ("pending", account(ConnectPlan(plan: "personal", status: .pending, entitled: false)), false, "Not on Connect"),
        (
            "active", account(ConnectPlan(plan: "personal", status: .active, entitled: true, renewsAt: renews)), false,
            "Connect Personal · renews 3 Dec 2026"
        ),
        (
            "trialing", account(ConnectPlan(plan: "personal", status: .trialing, entitled: true, renewsAt: renews)),
            false, "Connect Personal · renews 3 Dec 2026"
        ),
        (
            "team", account(ConnectPlan(plan: "team", status: .active, entitled: true, renewsAt: renews)), false,
            "Connect Team · renews 3 Dec 2026"
        ),
        (
            "family organizer",
            account(
                ConnectPlan(
                    plan: "family", status: .active, entitled: true, renewsAt: renews,
                    group: .init(kind: "family", role: "owner"), people: .init(active: 3, of: 4))), false,
            "Connect Family · 3 of 4 people"
        ),
        (
            "family member",
            account(
                ConnectPlan(
                    plan: "family", status: .active, entitled: true, renewsAt: renews,
                    group: .init(kind: "family", role: "member"), people: .init(active: 3, of: 4))), false,
            "Connect Family · 3 of 4 people"
        ),
        (
            "pastDue",
            account(
                ConnectPlan(plan: "personal", status: .pastDue, entitled: true, graceUntil: renews)), false, "Past due"
        ),
        (
            "ending", account(ConnectPlan(plan: "personal", status: .active, entitled: true, endsAt: ends)), false,
            "Ends 12 Jan 2027"
        ),
        (
            "read only",
            account(
                ConnectPlan(
                    plan: "personal", status: .readOnly, entitled: false, readOnlyUntil: ends, deleteAt: ends + 86_400)),
            false, "Ends 12 Jan 2027"
        ),
        (
            "suspended",
            account(ConnectPlan(plan: "personal", status: .suspended, entitled: false, deleteAt: ends)), false,
            "Not on Connect"
        ),
        (
            "a newer state", account(ConnectPlan(plan: "personal", status: .unknown, entitled: false)), false,
            "Not on Connect"
        ),
        ("stale without a plan", account(nil, stale: true), false, "Not available"),
    ]

    /// Words and signs that would make the row a purchase surface (plan section 6, 3.1.1, 3.1.3(f)).
    static let banned = [
        "€", "$", "£", "EUR", "eur ", "USD", "price", "Price", "a month", "a year", "/month", "per ",
        "trial", "Trial", "Buy", "buy", "Subscribe", "subscribe", "Upgrade", "upgrade", "Renew ", "Manage subscription",
        "checkout", "Checkout", "portal", "http", "www.", ".cc", "/pricing", "/connect", "website", "web site",
    ]

    @Test("each state shows exactly its text and nothing that leads to a purchase")
    func everyState() {
        for item in Self.cases {
            let content = ConnectPlanRow.content(item.status, failed: item.failed, timeZone: Self.utc)
            #expect(content.title == "Apassy Connect", "\(item.name)")
            #expect(content.value == item.value, "\(item.name)")
            for text in [content.title, content.value] + content.lines {
                for word in Self.banned {
                    #expect(!text.contains(word), "\(word) in “\(text)” (\(item.name))")
                }
                // No amount such as "3.00" or "3,00", and no "from 3".
                #expect(text.range(of: #"\d+[.,]\d{2}"#, options: .regularExpression) == nil, "\(text)")
                #expect(text.range(of: #"(?i)from\s*\d"#, options: .regularExpression) == nil, "\(text)")
            }
        }
    }

    @Test("the row says where the plan is managed only for an account, as text")
    func managedLine() {
        #expect(ConnectPlanRow.managedLine == "Managed in Apassy on your Mac")
        for item in Self.cases {
            let row = ConnectPlanRow.of(item.status, failed: item.failed)
            let content = ConnectPlanRow.content(item.status, failed: item.failed, timeZone: Self.utc)
            #expect(content.lines.contains(ConnectPlanRow.managedLine) == row.isOnAccount, "\(item.name)")
        }
        let none = ConnectPlanRow.content(ConnectStatus(state: .none), timeZone: Self.utc)
        #expect(none.lines.isEmpty, "no line at all without an account: no call to action")
        let removed = ConnectPlanRow.content(ConnectStatus(state: .none, removed: true), timeZone: Self.utc)
        #expect(removed.lines == [ConnectPlanRow.removedLine])
    }

    @Test("a removed account and devices that are not verified are text lines")
    func removedAndNotVerified() {
        let removed = ConnectStatus(state: .account, removed: true, accountID: "acc_k7m2q4x3ca", deviceName: "iPhone")
        let removedContent = ConnectPlanRow.content(removed, timeZone: Self.utc)
        #expect(removedContent.value == "Not on Connect")
        #expect(removedContent.lines == [ConnectPlanRow.removedLine])

        let devices = [
            ConnectDevice(deviceID: "dev_m2k7q3x4ab", name: "MacBook Pro", platform: "mac", isThisDevice: false, verified: true),
            ConnectDevice(deviceID: "dev_p4n6r2t7bc", name: "Mac Studio", platform: "mac", isThisDevice: false, verified: false),
            ConnectDevice(deviceID: "dev_q5m3s7v2cd", name: "iPad", platform: "iphone", isThisDevice: false, verified: false),
        ]
        var active = Self.account(ConnectPlan(plan: "personal", status: .active, entitled: true, renewsAt: Self.renews))
        active.devices = devices
        let content = ConnectPlanRow.content(active, timeZone: Self.utc)
        #expect(content.lines == [ConnectPlanRow.managedLine, "Not verified: Mac Studio, iPad"])

        for text in removedContent.lines + content.lines {
            for word in Self.banned {
                #expect(!text.contains(word), "\(word) in “\(text)”")
            }
        }
    }

    @Test("a stale answer keeps the last plan")
    func stale() {
        let plan = ConnectPlan(plan: "personal", status: .active, entitled: true, renewsAt: Self.renews)
        #expect(
            ConnectPlanRow.content(Self.account(plan, stale: true), timeZone: Self.utc).value
                == "Connect Personal · renews 3 Dec 2026")
    }

    @Test("the plan states of the core decode, also an unknown one")
    func decoding() throws {
        let json = """
            {"state":"account","account_id":"acc_k7m2q4x3ca","device_name":"iPhone","dial_route":false,
             "plan":{"plan":"family","status":"past_due","entitled":true,"renews_at":null,"ends_at":null,
             "grace_until":1793801700,"read_only_until":null,"delete_at":null,
             "group":{"kind":"family","role":"member"},"people":{"active":3,"of":4}}}
            """
        let status = try JSONDecoder().decode(ConnectStatus.self, from: Data(json.utf8))
        #expect(status.plan?.status == .pastDue)
        #expect(status.plan?.people == ConnectPlan.People(active: 3, of: 4))
        #expect(status.removed == false && status.stale == false)
        #expect(ConnectPlanRow.of(status) == .pastDue)
        let newer = try JSONDecoder().decode(
            ConnectPlan.self, from: Data(#"{"plan":"personal","status":"paused_by_owner","entitled":false}"#.utf8))
        #expect(newer.status == .unknown)
    }

    /// The block of the row in the source of Settings > General.
    static func rowSource() throws -> String {
        let file = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
            .appending(path: "Sources/Views/Settings/GeneralSettingsView.swift")
        let text = try String(contentsOf: file, encoding: .utf8)
        let start = try #require(text.range(of: "// MARK: Apassy Connect row"))
        let end = try #require(text.range(of: "// MARK: End of the Apassy Connect row"))
        // The code of the block, without its comments (which name what it must not have).
        return text[start.upperBound..<end.lowerBound]
            .split(separator: "\n", omittingEmptySubsequences: false)
            .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }
            .map { line in line.range(of: "///").map { String(line[..<$0.lowerBound]) } ?? String(line) }
            .joined(separator: "\n")
    }

    @Test("the row in Settings > General has no button, link, menu, gesture, URL, price, or currency")
    func rowSourceHasNoAction() throws {
        let code = try Self.rowSource()
        #expect(code.contains("ConnectPlanRow.content"), "the row shows the texts of ConnectPlanRow")
        #expect(code.contains("struct ConnectPlanSection"))
        for token in [
            "Button", "Link", "NavigationLink", "ShareLink", "Menu", "openURL", "onTapGesture", "TapGesture",
            "contextMenu", "swipeActions", "URL(", "http", "Toggle", "Picker", ".sheet", "fullScreenCover",
            "€", "EUR", "price", "subscribe", "Subscribe", "checkout", "portal",
        ] {
            #expect(!code.contains(token), "\(token) in the Apassy Connect row")
        }
    }

    // MARK: Settings > Devices

    @Test("the route line names each route that reaches the Mac")
    func routeLine() {
        #expect(MacReach.line([.tailscale]) == "Reaches your Mac through: Tailscale")
        #expect(MacReach.line([.connect]) == "Reaches your Mac through: Apassy Connect")
        #expect(MacReach.line([.wifi]) == "Reaches your Mac through: Wi-Fi")
        #expect(MacReach.line([.wifi, .tailscale]) == "Reaches your Mac through: Tailscale, Wi-Fi")
        #expect(
            MacReach.line([.wifi, .connect, .tailscale]) == "Reaches your Mac through: Tailscale, Apassy Connect, Wi-Fi")
        #expect(MacReach.line([]) == nil)
    }

    @Test("the routes come from the node vaults, the questions, the companion, and the Connect dial")
    func routes() {
        let node = DeviceRouteTests.entry(relay: DeviceRouteTests.origin, pin: DeviceRouteTests.pin, name: "Mac mini")
        let hosted = DeviceRouteTests.entry(relay: "https://apassy-relay.wyderka.cc")
        let onAccount = Self.account(ConnectPlan(plan: "personal", status: .active, entitled: true))
        var dialing = onAccount
        dialing.dialRoute = true
        #expect(MacReach.routes(vaults: [node], questionRoutes: [], wifiPaired: false, connect: nil) == [.tailscale])
        #expect(
            MacReach.routes(vaults: [hosted], questionRoutes: [.viaYourMac(name: nil)], wifiPaired: false, connect: nil)
                == [.tailscale])
        #expect(MacReach.routes(vaults: [hosted], questionRoutes: [.viaApassyRelay], wifiPaired: false, connect: nil) == [])
        #expect(MacReach.routes(vaults: [], questionRoutes: [], wifiPaired: true, connect: nil) == [.wifi])
        // An account alone is no route: Apassy Connect shows only when the core dials through it (I2).
        #expect(MacReach.routes(vaults: [], questionRoutes: [], wifiPaired: false, connect: onAccount) == [])
        #expect(MacReach.routes(vaults: [], questionRoutes: [], wifiPaired: false, connect: dialing) == [.connect])
        #expect(
            MacReach.routes(vaults: [node], questionRoutes: [], wifiPaired: true, connect: dialing)
                == [.tailscale, .connect, .wifi])
        var removed = ConnectStatus(state: .none)
        removed.dialRoute = true
        #expect(MacReach.routes(vaults: [], questionRoutes: [], wifiPaired: false, connect: removed) == [])
    }
}

/// Joining an Apassy Connect account from the scan of the vault flow (plan s7 unit I1).
@MainActor
@Suite("Apassy Connect join")
struct ConnectJoinModelTests {
    static let code = "apassy_alk_acc_k7m2q4x3ca_" + String(repeating: "cd", count: 32) + "_" + String(repeating: "ab", count: 16)

    @MainActor
    final class Fixture {
        let service = PreviewVaultService(empty: true)
        var cancelled = 0
        var finished: [VaultEntry] = []
        var model: JoinModel!

        init() {
            model = JoinModel(
                service: service, passphraseStore: MemoryPassphraseStore(), settings: makeSettings(),
                biometry: .faceID, deviceName: "Test iPhone", pollInterval: .milliseconds(20),
                connectPollInterval: .milliseconds(20),
                onFinished: { [unowned self] vault in finished.append(vault) },
                onCancel: { [unowned self] in cancelled += 1 })
        }
    }

    @Test("the code of Add a device… goes to the name, then the six words, then the Mac's confirmation")
    func joins() async {
        let fixture = Fixture()
        fixture.model.handleCode("  \(Self.code)\n")
        #expect(fixture.model.step == .name(link: Self.code))
        await fixture.model.start()
        guard case .connectWaiting(let join) = fixture.model.step else {
            Issue.record("not waiting: \(fixture.model.step)")
            return
        }
        #expect(join.words.count == 6)
        #expect(join.confirmer == "MacBook Pro")
        #expect(await waitUntil { fixture.model.step == .connectDone(confirmer: "MacBook Pro") })
        #expect(await fixture.service.connectLinks() == [Self.code])
        let status = try? await fixture.service.connectStatus()
        #expect(status?.state == .account)
        fixture.model.complete()
        #expect(fixture.cancelled == 1)
        #expect(fixture.finished.isEmpty, "Apassy Connect adds no vault")
    }

    @Test("a code that is not a Connect code is not taken as one")
    func notACode() {
        for text in [
            "apassy_alk_acc_k7m2q4x3ca_" + String(repeating: "cd", count: 31),
            "apassy_alk_acc_K7M2Q4X3CA_" + String(repeating: "cd", count: 32),
            "apassy_alk_t_7k2m5q4x3c_" + String(repeating: "cd", count: 32),
            "https://apassy.wyderka.cc/connect/join#apassy_gin_grp_k7m2q4x3ca_" + String(repeating: "cd", count: 32),
        ] {
            #expect(connectLinkCode(text) == nil, "\(text)")
            let fixture = Fixture()
            fixture.model.handleCode(text)
            #expect(fixture.model.step == .instructions)
            #expect(fixture.model.scanNote != nil)
        }
        #expect(connectLinkCode(" \(Self.code) ") == Self.code)
    }

    @Test("a refusal of the Mac ends the join with its reason; Cancel reaches the core")
    func refusedAndCancelled() async {
        let fixture = Fixture()
        fixture.model.handleCode(Self.code)
        await fixture.service.failNextConnect(VaultError(.alreadyConnected, "On Connect already."))
        await fixture.model.start()
        #expect(fixture.model.step == .failed(title: "This iPhone is on Apassy Connect already", message: "On Connect already."))

        let other = Fixture()
        other.model.handleCode(Self.code)
        await other.model.start()
        await other.model.cancel()
        #expect(other.cancelled == 1)
        let status = try? await other.service.connectStatus()
        #expect(status?.state == ConnectStatus.State.none)
        #expect(status?.join == nil)
    }
}
