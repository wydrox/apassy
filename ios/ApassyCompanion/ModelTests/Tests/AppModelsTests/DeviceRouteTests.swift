import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

/// The route words of the device rows in Settings > Devices (`docs/design/devices-settings-mockup.html`,
/// plan S2–S3 unit N6): "via your Mac" for a node on the tailnet, "via Apassy relay", "Wi-Fi", and
/// the quiet Tailscale line. Synthetic values only.
@Suite("Device routes")
struct DeviceRouteTests {
    static let pin = "u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE"
    static let origin = "https://100.64.0.7:8444"

    static func entry(id: String = "4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c", relay: String?, pin: String? = nil,
        name: String? = nil, source: String? = nil) -> VaultEntry
    {
        VaultEntry(
            id: id, name: "Personal", relayURL: relay, teamID: relay == nil ? nil : "t_7k2m5q4x3c",
            deviceID: relay == nil ? nil : 3, addedAt: 1, syncSource: source, pin: pin, nodeName: name)
    }

    @Test("the four words of the mockup")
    func words() {
        #expect(DeviceRoute.viaYourMac(name: nil).text == "via your Mac")
        #expect(DeviceRoute.viaYourMac(name: "Mac mini").text == "via your Mac")
        #expect(DeviceRoute.viaApassyRelay.text == "via Apassy relay")
        #expect(DeviceRoute.wifi.text == "Wi-Fi")
        #expect(DeviceRoute.viaYourMac(name: "Mac mini").detail == "Through Tailscale to Mac mini.")
        #expect(DeviceRoute.viaYourMac(name: nil).detail == "Through Tailscale to your Mac.")
        #expect(DeviceRoute.viaApassyRelay.detail == nil)
    }

    @Test("the sync route of a vault: a pinned relay is via your Mac, a hosted one via Apassy relay, none else")
    func vaultRoutes() {
        #expect(DeviceRoute.of(Self.entry(relay: Self.origin, pin: Self.pin, name: "Mac mini")) == .viaYourMac(name: "Mac mini"))
        #expect(DeviceRoute.of(Self.entry(relay: Self.origin, pin: Self.pin)) == .viaYourMac(name: nil))
        #expect(DeviceRoute.of(Self.entry(relay: "https://apassy-relay.wyderka.cc")) == .viaApassyRelay)
        #expect(DeviceRoute.of(Self.entry(relay: nil)) == nil)
        #expect(DeviceRoute.of(Self.entry(relay: nil, source: "icloud")) == nil)
        // A pinned node is never the hosted relay: no free-relay notice for it.
        #expect(FreeRelayNotice.relaySyncLine(for: Self.entry(relay: Self.origin, pin: Self.pin)) == nil)
    }

    @Test("the route of a questions team takes the node's name from the entry of its origin")
    func questionRoutes() {
        let entries = [
            Self.entry(id: "a", relay: "https://apassy-relay.wyderka.cc"),
            Self.entry(id: "b", relay: Self.origin, pin: Self.pin, name: "Mac mini"),
        ]
        let node = QuestionsStatus(enabled: true, node: NodeInfo(origin: Self.origin))
        #expect(DeviceRoute.of(node, entries: entries) == .viaYourMac(name: "Mac mini"))
        #expect(DeviceRoute.of(node, entries: []) == .viaYourMac(name: nil))
        let other = QuestionsStatus(enabled: true, node: NodeInfo(origin: "https://100.64.0.9:8444"))
        #expect(DeviceRoute.of(other, entries: entries) == .viaYourMac(name: nil))
        #expect(DeviceRoute.of(QuestionsStatus(enabled: true), entries: entries) == .viaApassyRelay)
        // An entry without a pin never names a node, even with the same origin.
        let unpinned = [Self.entry(id: "c", relay: Self.origin, name: "Not a node")]
        #expect(DeviceRoute.of(node, entries: unpinned) == .viaYourMac(name: nil))
    }

    @Test("the Tailscale line names each node once")
    func tailscaleLine() {
        func node(_ id: String, _ name: String?) -> UnreachableNode {
            UnreachableNode(id: id, vaultName: id, nodeName: name)
        }
        #expect(DeviceRoute.tailscaleOffLine([]) == nil)
        #expect(DeviceRoute.tailscaleOffLine([node("a", nil)]) == "Turn on Tailscale on this iPhone to reach your Mac.")
        #expect(DeviceRoute.tailscaleOffLine([node("a", "Mac mini")]) == "Turn on Tailscale on this iPhone to reach Mac mini.")
        #expect(
            DeviceRoute.tailscaleOffLine([node("a", "Mac mini"), node("b", "Mac mini")])
                == "Turn on Tailscale on this iPhone to reach Mac mini.")
        #expect(
            DeviceRoute.tailscaleOffLine([node("a", "Mac mini"), node("b", nil)])
                == "Turn on Tailscale on this iPhone to reach Mac mini.")
        #expect(
            DeviceRoute.tailscaleOffLine([node("a", "Mac mini"), node("b", "MacBook Pro")])
                == "Turn on Tailscale on this iPhone to reach Mac mini and MacBook Pro.")
    }
}
