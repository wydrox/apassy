import Foundation
import Testing
@testable import ApassyVaultKit

/// The sealed summary of push-gateway-v1 section 12, with the vectors of section 18.
@Suite struct PushSummaryTests {
    private let team = "t_7k2m5q4x3c"
    private let questionKey = Data((0xc0...0xdf).map { UInt8($0) })
    private let before = Date(timeIntervalSince1970: 1_790_000_100)
    private let summary =
        "ICEiIyQlJicoKSorLZYy_9V2mK8YOxL9BrISycdM3QC8LastsrSZ2rydHt5kH7FQOVw3Z9Fcdh4X0rBDP0peQmDtu1ueo2qMc8jG-HaJeH5MYA7UnBcbZRxtOLpdrfxf1XCmrKUi-gmLBZxFvggJiX35uKUAdZwfhwUqeu6y8tnLbItuN-Yk4e_Jkqawp39RHi3ux-0DNm4DCs1Nlnki8MWzWpS7q_Yf1-3uwYdSdBlr-qq7uI6GCJiJ-79H4cte4JJnY8GQ0RvTh9ZbxyqpdIhFpoe0V1w2ZgierYd-NuopbMxBWD0nepd9qDJGCGmbMZG1CwxXrjC_l2986y7k_EjhkwIbDdeBxTVnZ67guVWth1D8h-UMVEvCKR3zc2ANEQ1Qrr-skb_eNEo0hnj6Bvx6MiFWKwMUV_PcRAFVpb7so6XLs1i2bkYSzEv-w_buoaz-EnNnMD70ddE-FuZDqHiWaar_Wo0dSHz5qf5hcXNT6x185swuTpTL8sKUr32di0Qa0ObJE6BCpMOdFlxGtaKrb7bu1svCr0nLWDhMhi2Tp8ibOnvYKei4HFG251WGQ8AxcJl_7m_NTDOq4bDlEOOaOgSF7KiofJolVL4sBk8oFlaTgp2-Jvn4rFU1c04OaWJGQfOaJIvpnRXa883CBzSKZ2sNaovOg00TUiQ8Dc31pqs-ZzE8xHmg7E7YbmDyG3-UPiey7OE407l9"

    private var key: PushSummary.Key { PushSummary.key(teamID: team, questionKey: questionKey)! }

    @Test func theSummaryKeyIsTheContractVector() {
        #expect(PushSummary.text(of: key) == "K-iD_0Xo0XYWPOS-Iz7HiP6Cs2rdeAtf21jMtRLg-Zc")
        #expect(PushSummary.Key(teamID: team, key: "K-iD_0Xo0XYWPOS-Iz7HiP6Cs2rdeAtf21jMtRLg-Zc") != nil)
        #expect(PushSummary.Key(teamID: team, key: "K-iD") == nil)
        #expect(PushSummary.key(teamID: team, questionKey: Data(count: 31)) == nil)
    }

    @Test func theVectorSummaryOpens() throws {
        let content = try #require(PushSummary.open(summary, keys: [key], now: before))
        #expect(content.team == team)
        #expect(content.qid == "oKGio6SlpqeoqaqrrK2urw")
        #expect(content.expiresAt == 1_790_000_400)
        #expect(content.kind == .access)
        #expect(content.title == "Access request")
        #expect(content.body == "Claude Code wants “Stripe test key”")
    }

    @Test func aSummaryFailsClosed() {
        // Another team's key, after the expiry, a short text, an altered byte.
        let other = PushSummary.key(teamID: "t_other00000", questionKey: questionKey)!
        #expect(PushSummary.open(summary, keys: [other], now: before) == nil)
        let wrong = PushSummary.key(teamID: team, questionKey: Data(repeating: 1, count: 32))!
        #expect(PushSummary.open(summary, keys: [wrong], now: before) == nil)
        #expect(PushSummary.open(summary, keys: [key], now: Date(timeIntervalSince1970: 1_790_000_400)) == nil)
        #expect(PushSummary.open(String(summary.dropLast()), keys: [key], now: before) == nil)
        var bytes = [UInt8](Base64URL.decode(summary)!)
        bytes[100] ^= 1
        #expect(PushSummary.open(Base64URL.encode(Data(bytes)), keys: [key], now: before) == nil)
        #expect(PushSummary.open(summary, keys: [], now: before) == nil)
    }

    @Test func aWrongKeyFirstStillOpens() {
        let wrong = PushSummary.key(teamID: "t_wrong00000", questionKey: Data(repeating: 2, count: 32))!
        #expect(PushSummary.open(summary, keys: [wrong, key], now: before)?.team == team)
        // At most 16 keys are tried.
        let many = Array(repeating: wrong, count: 16) + [key]
        #expect(PushSummary.open(summary, keys: many, now: before) == nil)
    }

    @Test func theNotificationTextFollowsTheDevice() {
        let info: [AnyHashable: Any] = ["aps": ["alert": ["title": "Apassy"]], "s": summary]
        let iphone = PushSummaryNotification.texts(userInfo: info, keys: [key], now: before, device: .iphone)
        #expect(iphone?.title == "Access request")
        #expect(iphone?.body == "Claude Code wants “Stripe test key”")
        // An access request shows on the watch as on the iPhone.
        let watch = PushSummaryNotification.texts(userInfo: info, keys: [key], now: before, device: .watch)
        #expect(watch?.body == "Claude Code wants “Stripe test key”")
        // No summary, or one that does not open: the fixed text stays.
        #expect(PushSummaryNotification.texts(userInfo: ["aps": [String: Any]()], keys: [key], now: before, device: .iphone) == nil)
        #expect(PushSummaryNotification.texts(userInfo: ["s": 5], keys: [key], now: before, device: .iphone) == nil)
    }

    @Test func theTextRules() {
        #expect(PushSummary.validText("Run waiting", maxBytes: 64))
        #expect(!PushSummary.validText("", maxBytes: 64))
        #expect(!PushSummary.validText(String(repeating: "a", count: 65), maxBytes: 64))
        #expect(!PushSummary.validText("line\nbreak", maxBytes: 64))
        #expect(!PushSummary.validText("bidi\u{202E}text", maxBytes: 64))
        #expect(PushSummary.validText(String(repeating: "é", count: 32), maxBytes: 64))
        #expect(!PushSummary.validText(String(repeating: "é", count: 33), maxBytes: 64))
    }

    @Test func aStoreSyncKeepsKnownTeamsAndDropsLeftOnes() {
        let store = MemoryPushSummaryKeyStore()
        let a = PushSummaryKey(teamID: "t_a", key: "K-iD_0Xo0XYWPOS-Iz7HiP6Cs2rdeAtf21jMtRLg-Zc")
        let b = PushSummaryKey(teamID: "t_b", key: "K-iD_0Xo0XYWPOS-Iz7HiP6Cs2rdeAtf21jMtRLg-Zc")
        store.sync([a, b], known: [])
        #expect(store.teamIDs() == ["t_a", "t_b"])
        // t_b's vault is not open now but still known: it keeps its key; t_a was left.
        store.sync([], known: ["t_b"])
        #expect(store.teamIDs() == ["t_b"])
        #expect(store.loadAll().map(\.teamID) == ["t_b"])
        store.removeAll()
        #expect(store.teamIDs().isEmpty)
    }
}
