import Foundation
import Testing
@testable import ApassyVaultKit

@MainActor
@Suite struct WatchConnectScanTests {
    // Synthetic contract values, in the exact order emitted by LinkCode::for_origin and
    // PairingChannel::link on Mac 0.5.17. No real pairing capability or user vault.
    private let code = "apassy_lnk_t_7k2m5q4x3c_" + String(repeating: "ab", count: 32)
    private let pin = "u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE"
    private var handoff: String {
        "2.oKGio6SlpqeoqaqrrK2urw.\(String(repeating: "A", count: 43)).BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts"
    }
    private var pinned: String {
        "https://100.64.0.7:8444/link#\(code)&pin=\(pin)&alt=apassy-mini.tail0123.ts.net:8444&name=Mac%20mini&handoff=\(handoff)"
    }

    @Test func theMacsPinnedAndHostedCodesGoToTheWatchUnchanged() {
        for link in [pinned, "https://relay.example.test/link#\(code)&handoff=\(handoff)"] {
            let scan = WatchConnectScan()
            scan.startScanning()
            scan.receive("  \(link)\n", isReachable: true)
            #expect(scan.step == .sending)
            #expect(scan.outgoing?.link == link)
            let outgoing = scan.outgoing
            // DataScanner may update or tap the same item while the handoff is sending.
            scan.receive(link, isReachable: true)
            #expect(scan.outgoing == outgoing)
            scan.sent(.sent)
            #expect(scan.step == .sent)
            #expect(scan.outgoing == nil)
        }
    }

    @Test func eachRefusedScanShowsAnActionableMessage() {
        let cases = [
            ("https://100.64.0.7:8444/pair#apassy_tcd_\(String(repeating: "cd", count: 32))&pin=\(pin)", "sets up a node"),
            ("https://relay.example.test/link#\(code)", "only syncs a vault"),
            ("https://example.test/not-apassy", "not an Apassy Connect code"),
            ("", "not an Apassy Connect code"),
        ]
        for (link, expected) in cases {
            let scan = WatchConnectScan()
            scan.startScanning()
            scan.receive(link, isReachable: true)
            guard case .failed(let message) = scan.step else {
                Issue.record("A refused scan must show its reason")
                continue
            }
            #expect(message.contains(expected))
            #expect(message.contains("Settings › Devices"))
            #expect(scan.outgoing == nil)
        }
    }

    @Test func aWatchThatBecameUnreachableDoesNotSilentlyDropTheScan() {
        let scan = WatchConnectScan()
        scan.startScanning()
        scan.receive(pinned, isReachable: false)
        guard case .failed(let message) = scan.step else {
            Issue.record("A watch that closed after scanning started must leave an error")
            return
        }
        #expect(message.contains("code wasn't sent"))
        #expect(message.contains("Open Apassy on your Apple Watch"))
        #expect(scan.outgoing == nil)
        scan.startScanning()
        scan.receive(pinned, isReachable: true)
        #expect(scan.step == .sending)
    }

    @Test func everyDeliveryRefusalShowsAReasonAndDropsTheCode() {
        let refusal = "This watch is connected already. Remove it in This watch first."
        for result in [WatchConnectScan.SendResult.failed, .refused(""), .refused("  \n"), .refused(refusal)] {
            let scan = WatchConnectScan()
            scan.startScanning()
            scan.receive(pinned, isReachable: true)
            scan.sent(result)
            guard case .failed(let message) = scan.step else {
                Issue.record("A failed send must show its reason")
                continue
            }
            #expect(!message.isEmpty)
            if result == .refused(refusal) { #expect(message == refusal) }
            #expect(scan.outgoing == nil)
        }
    }
}
