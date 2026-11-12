import Foundation
import Synchronization
import Testing
@testable import ApassyVaultKit

/// Apassy Connect on this iPhone (contract ios-core-v1 section 5.14, plan s7 unit I1): the wire of
/// the core, the code of "Add a device…", and the Keychain store of the account key. Synthetic
/// values only.
@Suite struct ConnectTests {
    static let code = "apassy_alk_acc_k7m2q4x3ca_" + String(repeating: "cd", count: 32) + "_" + String(repeating: "ab", count: 16)

    @Test func theStatusOfTheCoreDecodes() throws {
        let none = try JSONDecoder().decode(ConnectStatus.self, from: Data(#"{"state":"none","plan":null,"dial_route":false}"#.utf8))
        #expect(none == ConnectStatus(state: .none))
        let removed = try JSONDecoder().decode(
            ConnectStatus.self, from: Data(#"{"state":"none","removed":true,"plan":null,"dial_route":false}"#.utf8))
        #expect(removed.removed)
        let removedAccount = try JSONDecoder().decode(
            ConnectStatus.self,
            from: Data(
                #"{"state":"account","removed":true,"account_id":"acc_k7m2q4x3ca","device_name":"iPhone","plan":null,"dial_route":false}"#
                    .utf8))
        #expect(removedAccount.state == .account && removedAccount.removed)
        let json = """
            {"state":"account","account_id":"acc_k7m2q4x3ca","device_name":"iPhone","stale":true,"dial_route":false,
             "plan":{"plan":"personal","status":"active","entitled":true,"renews_at":1796299200,"ends_at":null,
             "grace_until":null,"read_only_until":null,"delete_at":null,"group":null,"people":null}}
            """
        let account = try JSONDecoder().decode(ConnectStatus.self, from: Data(json.utf8))
        #expect(account.state == .account)
        #expect(account.stale)
        #expect(account.plan?.renewsAt == 1_796_299_200)
        #expect(account.plan?.status == .active)
        #expect(account.devices.isEmpty)
        let listed = try JSONDecoder().decode(
            ConnectStatus.self,
            from: Data(
                """
                {"state":"account","account_id":"acc_k7m2q4x3ca","device_name":"iPhone","dial_route":false,"plan":null,
                 "devices":[{"device_id":"dev_m2k7q3x4ab","name":"MacBook Pro","platform":"mac","this":false,"verified":true},
                 {"device_id":"dev_p4n6r2t7bc","name":"Mac Studio","platform":"mac","this":false,"verified":false}]}
                """.utf8))
        #expect(listed.devices.count == 2)
        #expect(listed.unverifiedDevices.map(\.name) == ["Mac Studio"])
    }

    @Test func aJoinOfTheCoreDecodes() throws {
        let json = """
            {"state":"waiting","account_id":"acc_k7m2q4x3ca","confirmer":"MacBook Pro",
             "words":["blaze","cable","flute","board","seal","tiger"],"expires_at":1790000600}
            """
        let join = try JSONDecoder().decode(ConnectJoin.self, from: Data(json.utf8))
        #expect(join.words.joined(separator: " ") == "blaze cable flute board seal tiger")
        #expect(join.state == .waiting)
        #expect(join.confirmer == "MacBook Pro")
    }

    @Test func onlyTheCodeOfAddADeviceIsAConnectCode() {
        #expect(connectLinkCode(Self.code) == Self.code)
        #expect(connectLinkCode("\n \(Self.code) \t") == Self.code)
        let secret = String(repeating: "cd", count: 32)
        for text in [
            "", "apassy_alk_", Self.code + "0", String(Self.code.dropLast()),
            "apassy_alk_acc_k7m2q4x3ca_" + secret,
            "apassy_alk_acc_k7m2q4x3ca_" + secret + "_" + String(repeating: "ab", count: 15),
            "apassy_alk_acc_k7m2q4x3ca_" + secret + "_" + String(repeating: "AB", count: 16),
            "apassy_alk_acc_k7m2q4x3c1_" + secret + "_" + String(repeating: "ab", count: 16),
            "apassy_alk_acc_k7m2q4x3ca-" + secret + "_" + String(repeating: "ab", count: 16),
            "apassy_alk_acc_k7m2q4x3ca_" + String(repeating: "CD", count: 32) + "_" + String(repeating: "ab", count: 16),
            "apassy_lnk_t_7k2m5q4x3c_" + secret,
            "https://apassy.wyderka.cc/link#" + Self.code,
        ] {
            #expect(connectLinkCode(text) == nil, "\(text)")
        }
    }

    final class FakeKeychain: Sendable {
        let key = Mutex<Data?>(nil)
        let unavailable = Mutex(false)

        var backend: KeychainAccountKeyStore.Backend {
            KeychainAccountKeyStore.Backend(
                read: { [self] in
                    if unavailable.withLock({ $0 }) { return .unavailable }
                    return key.withLock { $0 }.map { .value($0) } ?? .missing
                },
                write: { [self] data in
                    if unavailable.withLock({ $0 }) { return false }
                    key.withLock { $0 = data }
                    return true
                },
                delete: { [self] in
                    if unavailable.withLock({ $0 }) { return nil }
                    return key.withLock { stored in
                        defer { stored = nil }
                        return stored != nil
                    }
                })
        }
    }

    @Test func theAccountKeyStoreKeepsOneKeyAndReportsAnUnavailableKeychain() {
        let keychain = FakeKeychain()
        let store = KeychainAccountKeyStore(backend: keychain.backend)
        #expect(store.read() == .missing)
        let document = Data(repeating: 7, count: 138)
        #expect(store.write(document))
        #expect(store.read() == .value(document))
        let other = Data(repeating: 9, count: 138)
        #expect(store.write(other))
        #expect(store.read() == .value(other))
        // Nothing empty or larger than the core reads.
        #expect(!store.write(Data()))
        #expect(!store.write(Data(repeating: 1, count: KeychainAccountKeyStore.capacity + 1)))
        keychain.unavailable.withLock { $0 = true }
        #expect(store.read() == .unavailable)
        #expect(!store.write(document))
        #expect(store.delete() == nil)
        keychain.unavailable.withLock { $0 = false }
        #expect(store.delete() == true)
        #expect(store.delete() == false)
        #expect(store.read() == .missing)
    }

    @Test func thePreviewJoinsAfterTwoPollsAndForgets() async throws {
        let service = PreviewVaultService(empty: true)
        #expect(try await service.connectStatus().state == .none)
        let join = try await service.connectJoin(link: Self.code, deviceName: "iPhone")
        #expect(join.accountID == "acc_k7m2q4x3ca")
        #expect(join.words == PreviewVaultService.connectWords)
        #expect(try await service.connectJoinPoll().state == .waiting)
        #expect(try await service.connectJoinPoll().state == .confirmed)
        #expect(try await service.connectStatus().state == .account)
        await #expect(throws: VaultError.self) { try await service.connectJoin(link: Self.code, deviceName: "iPhone") }
        #expect(try await service.connectForget())
        #expect(try await service.connectStatus().state == .none)
        #expect(try await service.connectForget() == false)
    }
}

/// The wire of plan s7 unit I3: `connect_status` as the contract has it now (`devices` with
/// `verified`, `removed` with an account, `dial_route`, `dial_state`), and the end of the free hosted
/// paths in the answers of the questions and the feed (`relay_ended`). Synthetic values only.
@Suite struct ConnectStatusWireTests {
    /// The example of ios-core-v1 section 5.14, with a field of a newer core.
    static let contract = """
        {"state": "account", "account_id": "acc_k7m2q4x3ca", "device_name": "iPhone", "dial_route": false, "dial_state": "unused",
         "plan": {"plan": "family", "status": "active", "entitled": true, "renews_at": 1796299200, "ends_at": null,
                  "grace_until": null, "read_only_until": null, "delete_at": null,
                  "group": {"kind": "family", "role": "member"}, "people": {"active": 3, "of": 4}},
         "devices": [{"device_id": "dev_m2k7q3x4ab", "name": "MacBook Pro", "platform": "mac", "this": false, "verified": true},
                     {"device_id": "dev_p4n6r2t7bc", "name": "iPhone", "platform": "iphone", "this": true, "verified": true}],
         "a_field_of_a_newer_core": {"x": 1}}
        """

    static func decode(_ json: String) throws -> ConnectStatus {
        try JSONDecoder().decode(ConnectStatus.self, from: Data(json.utf8))
    }

    @Test func theExampleOfTheContractDecodesWithEveryField() throws {
        let status = try Self.decode(Self.contract)
        #expect(status.state == .account)
        #expect(status.accountID == "acc_k7m2q4x3ca")
        #expect(status.deviceName == "iPhone")
        #expect(!status.removed && !status.stale && !status.dialRoute)
        #expect(status.dialState == .unused)
        #expect(status.plan?.people == ConnectPlan.People(active: 3, of: 4))
        #expect(status.plan?.group == ConnectPlan.Group(kind: "family", role: "member"))
        #expect(status.devices.map(\.deviceID) == ["dev_m2k7q3x4ab", "dev_p4n6r2t7bc"])
        #expect(status.devices.map(\.isThisDevice) == [false, true])
        #expect(status.unverifiedDevices.isEmpty)
    }

    @Test func everyStateOfTheDialDecodesAndANewerOneIsUnknown() throws {
        let states: [(String, ConnectDialState)] = [
            ("unused", .unused), ("connected", .connected), ("not_on_connect", .notOnConnect),
            ("mac_offline", .macOffline), ("limit", .limit), ("unreachable", .unreachable), ("refused", .refused),
            ("paused_by_a_newer_core", .unknown),
        ]
        for (text, state) in states {
            let status = try Self.decode(
                #"{"state":"account","account_id":"acc_k7m2q4x3ca","plan":null,"dial_route":true,"dial_state":"\#(text)"}"#)
            #expect(status.dialState == state, "\(text)")
            #expect(status.dialRoute)
        }
        // An older core: no `dial_state`, and no `dial_route`.
        let older = try Self.decode(#"{"state":"none","plan":null}"#)
        #expect(older.dialState == .unused && !older.dialRoute)
    }

    @Test func aRemovedAccountKeepsItsAccountAndTheOptionalFieldsMayBeMissing() throws {
        let removed = try Self.decode(
            #"{"state":"account","removed":true,"account_id":"acc_k7m2q4x3ca","dial_route":false,"dial_state":"not_on_connect"}"#)
        #expect(removed.state == .account && removed.removed)
        #expect(removed.plan == nil && removed.devices.isEmpty && removed.deviceName == nil)
        #expect(removed.dialState == .notOnConnect)
        let joining = try Self.decode(
            #"{"state":"none","plan":null,"dial_route":false,"dial_state":"unused","join":{"state":"waiting","account_id":"acc_k7m2q4x3ca","confirmer":"MacBook Pro","words":["a","b","c","d","e","f"],"expires_at":1790000600}}"#)
        #expect(joining.join?.confirmer == "MacBook Pro")
    }

    @Test func aDeviceWithoutVerifiedIsNotVerifiedAndAnUnreadableOneIsLeftOut() throws {
        let status = try Self.decode(
            """
            {"state":"account","account_id":"acc_k7m2q4x3ca","plan":null,
             "devices":[{"device_id":"dev_m2k7q3x4ab","name":"MacBook Pro","platform":"mac","this":false,"verified":false},
                        {"device_id":"dev_p4n6r2t7bc","name":"Mac Studio"},
                        {"name":"no id"},
                        {"device_id":"dev_q5m3s7v2cd","name":"iPhone","platform":"iphone","this":true,"verified":true,"new":1}]}
            """)
        #expect(status.devices.map(\.name) == ["MacBook Pro", "Mac Studio", "iPhone"])
        #expect(status.unverifiedDevices.map(\.name) == ["MacBook Pro", "Mac Studio"])
    }

    @Test func whetherTheDeviceListVerifiedDecodesAndIsNilWhenMissing() throws {
        let verified = try Self.decode(
            #"{"state":"account","account_id":"acc_k7m2q4x3ca","plan":null,"list_verified":true}"#)
        #expect(verified.listVerified == true)
        let refused = try Self.decode(
            """
            {"state":"account","account_id":"acc_k7m2q4x3ca","plan":null,"list_verified":false,
             "devices":[{"device_id":"dev_m2k7q3x4ab","name":"MacBook Pro","platform":"mac","this":false,"verified":false}]}
            """)
        #expect(refused.listVerified == false)
        #expect(refused.unverifiedDevices.map(\.name) == ["MacBook Pro"])
        // Connect did not answer, an older core, or a value this app cannot read: nil.
        let stale = try Self.decode(#"{"state":"account","account_id":"acc_k7m2q4x3ca","plan":null,"stale":true}"#)
        #expect(stale.listVerified == nil)
        let unreadable = try Self.decode(#"{"state":"account","account_id":"acc_k7m2q4x3ca","plan":null,"list_verified":"yes"}"#)
        #expect(unreadable.listVerified == nil)
        #expect(try Self.decode(Self.contract).listVerified == nil)
        // An encoded status decodes to the same value.
        #expect(try JSONDecoder().decode(ConnectStatus.self, from: JSONEncoder().encode(refused)) == refused)
    }

    @Test func thePreviewReportsADeviceListThatDidNotVerify() async throws {
        let service = PreviewVaultService(empty: true)
        let mac = ConnectDevice(deviceID: "dev_m2k7q3x4ab", name: "MacBook Pro", platform: "mac", isThisDevice: false, verified: true)
        await service.setConnectAccount("acc_k7m2q4x3ca", devices: [mac])
        #expect(try await service.connectStatus().listVerified == true)
        await service.setConnectAccount("acc_k7m2q4x3ca", devices: [mac], listVerified: false)
        let refused = try await service.connectStatus()
        #expect(refused.listVerified == false)
        #expect(refused.unverifiedDevices.map(\.name) == ["MacBook Pro"])
        await service.setConnectAccount("acc_k7m2q4x3ca", removed: true)
        #expect(try await service.connectStatus().listVerified == nil)
        _ = try await service.connectForget()
        #expect(try await service.connectStatus().listVerified == nil)
    }

    @Test func theEndOfTheHostedRelayDecodesInTheQuestionsAndTheFeed() throws {
        let list = try JSONDecoder().decode(
            QuestionsList.self,
            from: Data(
                """
                {"status":{"enabled":true,"team_id":"t_7k2m5q4x3c","relay_device_id":2,"has_key":true,"registered":true,
                           "removed":false,"relay_ended":true},
                 "questions":[],
                 "vaults":[{"vault_id":"4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c","vault_name":"Personal","error":"relay_ended",
                            "status":{"enabled":true,"has_key":true,"relay_ended":true}}]}
                """.utf8))
        #expect(list.status.relayEnded)
        #expect(list.vaults?.first?.status.relayEnded == true)
        #expect(list.vaults?.first?.error == VaultError.Code.relayEnded.rawValue)
        // Absent: not ended; and an answer with it encodes it again.
        let plain = try JSONDecoder().decode(
            QuestionsStatus.self, from: Data(#"{"enabled":true,"has_key":true}"#.utf8))
        #expect(!plain.relayEnded)
        let again = try JSONDecoder().decode(QuestionsStatus.self, from: JSONEncoder().encode(list.status))
        #expect(again.relayEnded)
        let feed = try JSONDecoder().decode(
            FeedList.self,
            from: Data(
                #"{"vaults":[{"vault_id":"4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c","vault_name":"Personal","team_id":"t_7k2m5q4x3c","registered":true,"answer_key":true,"error":"relay_ended","relay_ended":true,"macs":[]}]}"#
                    .utf8))
        #expect(feed.vaults.first?.relayEnded == true)
        #expect(VaultError.Code(rawValue: "relay_ended") == .relayEnded)
    }

    @Test func anAccountFileOfAnEarlierVersionDecodesAsJoinAgain() throws {
        let again = try Self.decode(
            #"{"state":"account","join_again":true,"plan":null,"dial_route":false,"dial_state":"unused"}"#)
        #expect(again.state == .account && again.joinAgain && !again.removed)
        #expect(again.accountID == nil && again.plan == nil && again.devices.isEmpty && again.listVerified == nil)
        // Missing (every other status, an older core): false.
        #expect(try Self.decode(Self.contract).joinAgain == false)
        #expect(try Self.decode(#"{"state":"none","plan":null,"dial_route":false}"#).joinAgain == false)
    }

    @Test func thePreviewAsksToJoinAgainUntilForgetThenJoins() async throws {
        let service = PreviewVaultService(empty: true)
        await service.setConnectAccount("acc_k7m2q4x3ca", joinAgain: true)
        let again = try await service.connectStatus()
        #expect(again.state == .account && again.joinAgain && !again.removed)
        #expect(again.accountID == nil && again.plan == nil && again.devices.isEmpty)
        // As the core: a join waits for the forget.
        await #expect(throws: VaultError.self) {
            _ = try await service.connectJoin(link: ConnectTests.code, deviceName: "Test iPhone")
        }
        #expect(try await service.connectForget())
        #expect(try await service.connectStatus().state == .none)
        _ = try await service.connectJoin(link: ConnectTests.code, deviceName: "Test iPhone")
        _ = try await service.connectJoinPoll()
        #expect(try await service.connectJoinPoll().state == .confirmed)
        let joined = try await service.connectStatus()
        #expect(joined.state == .account && !joined.joinAgain)
    }

    @Test func aSyncThatWaitsForADeviceOfTheAccountDecodesAsItsOwnState() throws {
        let status = try JSONDecoder().decode(
            SyncStatus.self,
            from: Data(
                #"{"enabled":true,"state":"waits_for_device","message":"Waiting for another device of this account to sync. Nothing was changed.","version":4,"last_sync_at":null,"pushed":false,"merged":null}"#
                    .utf8))
        #expect(status.state == .waitsForDevice)
        #expect(VaultError.Code(rawValue: "waits_for_device") == .waitsForDevice)
    }

    @Test func thePreviewForgetsARemovedAccountAndJoinsAgain() async throws {
        let service = PreviewVaultService(empty: true)
        await service.setConnectAccount("acc_k7m2q4x3ca", removed: true)
        let removed = try await service.connectStatus()
        #expect(removed.state == .account && removed.removed)
        #expect(try await service.connectForget())
        #expect(try await service.connectStatus().state == .none)
        #expect(try await service.connectForget() == false)
        _ = try await service.connectJoin(link: ConnectTests.code, deviceName: "Test iPhone")
        _ = try await service.connectJoinPoll()
        #expect(try await service.connectJoinPoll().state == .confirmed)
        #expect(try await service.connectStatus().state == .account)
        #expect(await service.connectForgets() == 2)
    }
}
