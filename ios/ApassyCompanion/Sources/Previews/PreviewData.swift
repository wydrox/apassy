import ApassyCompanionKit
import Foundation

#if DEBUG

/// Synthetic data for the `#Preview` blocks: no real host, folder, or secret. It exists in a Debug
/// build only, so no sample command or address is in the Release app.
enum PreviewData {
    static let record = PairingRecord(
        deviceID: "d4c0ffee00000000000000000000beef", macName: "Mac mini",
        hosts: ["Mac-mini.local", "192.0.2.20"], port: 48620, pin: Data(repeating: 0x11, count: 32),
        pairedAt: 1_790_000_000, lastGoodHost: "Mac-mini.local")

    static let migrateRun = PendingRun(
        id: "123456789012345", agent: "claude-code", command: ["npm", "run", "migrate"],
        cwd: "/Users/me/Dev/shop", envNames: ["DATABASE_URL"], purpose: "Apply the new migration.",
        risk: "production credential: always asks the owner",
        userRequest: "Deploy the new schema to staging.", requestSource: "from the host hook",
        agentRequest: "I will apply the migration so the staging schema matches the code.",
        remember: RememberOffer(pattern: "npm run migrate", approvals: 1, needed: 3),
        digest: String(repeating: "ab", count: 32), waitingSeconds: 12)

    static let quotedRun = PendingRun(
        id: "123456789012346", agent: "codex",
        command: ["curl", "-H", "Accept: application/json", "https://api.example.test/v1/orders?limit=5"],
        cwd: "/Users/me/Dev/shop/services/orders", envNames: ["API_TOKEN", "API_BASE_URL"],
        purpose: "", risk: "the command sends a token to a host that Apassy has not seen",
        userRequest: "", requestSource: "from the agent", agentRequest: "List the newest orders.",
        remember: nil, digest: String(repeating: "cd", count: 32), waitingSeconds: nil)

    static let accessRequest = AccessRequest(
        id: "42", agent: "codex", itemName: "Payments test key",
        reason: "The user asked me to test checkout.", cwd: "/Users/me/Dev/shop", requestedAt: 1_790_000_000)

    static let activity = [
        ActivityEntry(
            id: "991", at: Int64(Date().timeIntervalSince1970) - 90, agent: "claude-code", decision: "deny",
            summary: "payments charges list", reason: "The command prints a secret."),
        ActivityEntry(
            id: "990", at: Int64(Date().timeIntervalSince1970) - 3_600, agent: "codex", decision: "allow",
            summary: "git status", reason: "A read of the project."),
        ActivityEntry(
            id: "989", at: Int64(Date().timeIntervalSince1970) - 86_400, agent: "claude-code", decision: "error",
            summary: "npm test", reason: "The run ended before it started."),
    ]

    static let inbox = Inbox(
        runs: [migrateRun, quotedRun], accessRequests: [accessRequest], activity: activity)

    static let status: StatusInfo = {
        let json = """
            {"v":1,"mac_name":"Mac mini","app_version":"0.2.1","approval_timeout_seconds":120,\
            "device":{"id":"d4c0ffee00000000000000000000beef","name":"Test iPhone","paired_at":1790000000}}
            """
        // The JSON is a constant of this file, so a failure here is a bug in the preview data.
        return try! JSONDecoder().decode(StatusInfo.self, from: Data(json.utf8))
    }()
}

/// A Mac that answers with the preview data and accepts every decision.
struct PreviewConnection: MacConnection {
    var lastGoodHost: String? { "Mac-mini.local" }

    func status() async throws -> StatusInfo { PreviewData.status }
    func inbox() async throws -> Inbox { PreviewData.inbox }

    func approve(run: PendingRun, remember: Bool) async throws -> ApproveOutcome {
        try await Task.sleep(for: .seconds(1))
        return remember ? .approvedAndRemembered : .approved
    }

    func deny(run: PendingRun) async throws {
        try await Task.sleep(for: .milliseconds(400))
    }

    func denyAccessRequest(id: String) async throws {
        try await Task.sleep(for: .milliseconds(400))
    }

    func unpair() async throws {}
}

#endif
