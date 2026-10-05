import ApassyCompanionKit

/// What the screens ask of the Mac. `CompanionClient` is the real one. The previews use a fixed one.
protocol MacConnection: Sendable {
    /// The host that answered last.
    var lastGoodHost: String? { get async }
    func status() async throws -> StatusInfo
    func inbox() async throws -> Inbox
    func approve(run: PendingRun, remember: Bool) async throws -> ApproveOutcome
    func deny(run: PendingRun) async throws
    func denyAccessRequest(id: String) async throws
    func unpair() async throws
}

extension CompanionClient: MacConnection {}
