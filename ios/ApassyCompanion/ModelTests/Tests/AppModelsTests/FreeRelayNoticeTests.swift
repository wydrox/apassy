import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

/// The notice of ADR 0037 D14 in Settings > Devices (plan s7 unit N1).
@Suite("FreeRelayNotice")
struct FreeRelayNoticeTests {
    @Test("both lines name the release that ends the free paths")
    func namesTheVersion() {
        #expect(FreeRelayNotice.questions.contains("end with Apassy \(FreeRelayNotice.endVersion)."))
        #expect(FreeRelayNotice.relaySync.contains("free until Apassy \(FreeRelayNotice.endVersion)."))
        #expect(FreeRelayNotice.questions.contains("Tailscale"))
        #expect(FreeRelayNotice.questions.contains("Apassy Connect"))
        #expect(FreeRelayNotice.relaySync.contains("sync home (free)"))
    }

    @Test("the lines show no price and no purchase step (App Review 3.1)")
    func noPurchaseText() {
        for line in [FreeRelayNotice.questions, FreeRelayNotice.relaySync] {
            for banned in [
                "€", "EUR", "$", "a month", "a year", "price", "Buy", "Subscribe", "Upgrade", "Renew",
                "subscription", "paid", "http", "/pricing", "/connect", "Connect Personal",
                "Connect Family", "Connect Team",
            ] {
                #expect(!line.contains(banned), "\(banned) in \(line)")
            }
        }
    }

    @Test("only the hosted relay gets the sync line")
    func onlyTheHostedRelay() {
        #expect(FreeRelayNotice.isHosted("https://apassy-relay.wyderka.cc"))
        #expect(FreeRelayNotice.isHosted("https://apassy-relay.wyderka.cc/"))
        #expect(FreeRelayNotice.isHosted("https://APASSY-RELAY.wyderka.cc:443"))
        #expect(!FreeRelayNotice.isHosted("https://relay.example.test"))
        #expect(!FreeRelayNotice.isHosted("https://apassy-relay.wyderka.cc.example.test"))
        #expect(!FreeRelayNotice.isHosted("https://apassy-relay.wyderka.cc:8443"))
        #expect(!FreeRelayNotice.isHosted("http://apassy-relay.wyderka.cc"))
        #expect(!FreeRelayNotice.isHosted("http://127.0.0.1:8080"))
        #expect(!FreeRelayNotice.isHosted(nil))

        let hosted = VaultEntry(
            id: "4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c", name: "Personal",
            relayURL: "https://apassy-relay.wyderka.cc", teamID: "t_7k2m5q4x3c", deviceID: 2, addedAt: 0)
        let ownRelay = VaultEntry(
            id: "5f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c", name: "Work",
            relayURL: "https://relay.example.test", teamID: "t_7k2m5q4x3d", deviceID: 2, addedAt: 0)
        let icloud = VaultEntry(
            id: "6f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c", name: "Family",
            relayURL: "https://apassy-relay.wyderka.cc", teamID: nil, deviceID: nil, addedAt: 0,
            syncSource: "icloud")
        #expect(FreeRelayNotice.relaySyncLine(for: hosted) == FreeRelayNotice.relaySync)
        #expect(FreeRelayNotice.relaySyncLine(for: ownRelay) == nil)
        #expect(FreeRelayNotice.relaySyncLine(for: icloud) == nil)
        #expect(FreeRelayNotice.relaySyncLine(for: nil) == nil)
    }
}
