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
