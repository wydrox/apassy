// Not built for watchOS: the Apple Watch uses WatchCoreService (ADR 0039).
#if !os(watchOS)
import ApassyVaultKit
import Foundation

/// Apassy Connect (contract ios-core-v1 section 5.14): this iPhone joins the account of a Mac and
/// reads its plan. The app only; the core refuses the AutoFill extension.
extension CoreVaultService {
    public func connectJoin(link: String, deviceName: String) async throws -> ConnectJoin {
        try await call("connect_join", ["link": link, "device_name": deviceName])
    }

    public func connectJoinPoll() async throws -> ConnectJoin { try await call("connect_join_poll") }

    public func connectJoinCancel() async throws { try await call("connect_join_cancel") }

    public func connectStatus() async throws -> ConnectStatus { try await call("connect_status") }

    private struct Forgot: Decodable, Sendable { var forgotten: Bool }

    public func connectForget() async throws -> Bool { try await call("connect_forget", as: Forgot.self).forgotten }
}
#endif
