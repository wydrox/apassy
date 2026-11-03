import ApassyVaultKit
import Foundation

/// "See a Sample" on a watch that is not connected: one synthetic access request of
/// "Mac mini (demo)" with Allow once and Deny, answered in memory. The watch core, the keys, and
/// the replica are the in-memory ones of the previews: nothing is written, nothing is sent.
///
/// The answer key is a key in memory, so Allow once cannot run the check that the watch is
/// unlocked on the wrist: that check is the key of a connected vault (`KeychainWatchAnswerKeys`).
/// The sample says so (`wristNote`).
public enum DemoWatch {
    /// The name of the sample watch.
    public static let deviceName = "Apple Watch (demo)"
    /// The note of the sample about the check of the wrist.
    public static let wristNote =
        "Sample only. Allow once here does not check that the watch is unlocked on your wrist: that check needs the key of a connected vault."

    /// The vault of the sample.
    public static let vault = WatchVault(id: "d070dc14-a3ac-42c2-95aa-cc85d6d58900", name: DemoVault.name)

    /// A new sample: connected, with the request open on the screen.
    @MainActor
    public static func model(now: Date = Date()) -> WatchAppModel {
        let keys = MemoryWatchAnswerKeys(checkTime: .milliseconds(600))
        let key = (try? keys.create(team: DemoVault.team)) ?? Data()
        let request = request(answerKey: key, now: now)
        let service = PreviewWatchService(
            state: .ready, vault: vault, macs: [DemoVault.macName], requests: [request], settles: true)
        let replica = MemoryWatchReplicaStore(
            WatchReplicaSecret(passphrase: "synthetic-demo-watch-passphrase", team: DemoVault.team))
        return WatchAppModel(
            service: service, keys: keys, replica: replica, deviceName: deviceName,
            path: [.request(request.id)], pollInterval: .seconds(1))
    }

    /// The access request of the sample: Claude Code asks to use the GitHub key once.
    public static func request(answerKey: Data, now: Date = Date()) -> RelayAccessRequest {
        let created = UInt64(now.timeIntervalSince1970) - 15
        return DemoVault.access(
            id: "demo-watch-81", agent: "Claude Code", host: "claude-code", item: "GitHub", binding: "GITHUB_TOKEN",
            hosts: ["api.github.com"], reason: "Push the release tag of the demo project.", project: "acme-billing",
            created: created, expires: created + UInt64(DemoVault.waitLifetime), state: "open", answerKey: answerKey,
            rowVaultID: vault.id)
    }
}
