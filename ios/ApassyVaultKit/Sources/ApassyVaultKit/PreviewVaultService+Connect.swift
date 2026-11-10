import Foundation

/// Apassy Connect in memory (contract ios-core-v1 section 5.14): a join waits for two polls, then
/// this iPhone is a device of a synthetic account with the plan of `connectPlan`. No value is real.
struct PreviewConnect {
    var join: ConnectJoin?
    var polls = 0
    var accountID: String?
    var plan = ConnectPlan(plan: nil, status: .none, entitled: false)
    /// Test support: the next `connectJoin` or `connectJoinPoll` fails with this error.
    var nextError: VaultError?
    /// Test support: the links of each `connectJoin`, in order.
    var links: [String] = []
}

extension PreviewVaultService {
    public static let connectWords = ["blaze", "cable", "flute", "board", "seal", "tiger"]

    public func connectJoin(link: String, deviceName: String) async throws -> ConnectJoin {
        if let error = connectState.nextError {
            connectState.nextError = nil
            throw error
        }
        guard let code = connectLinkCode(link) else {
            throw VaultError(.linkInvalid, "This code does not work.")
        }
        guard connectState.accountID == nil else {
            throw VaultError(.alreadyConnected, "This iPhone is a device of an Apassy Connect account already.")
        }
        connectState.links.append(code)
        connectState.polls = 0
        let account = String(code.dropFirst("apassy_alk_".count).prefix(14))
        let join = ConnectJoin(
            state: .waiting, accountID: account, confirmer: "MacBook Pro", words: Self.connectWords,
            expiresAt: Int64(Date().timeIntervalSince1970) + 600)
        connectState.join = join
        return join
    }

    public func connectJoinPoll() async throws -> ConnectJoin {
        if let error = connectState.nextError {
            connectState.nextError = nil
            connectState.join = nil
            throw error
        }
        guard var join = connectState.join else { throw VaultError(.invalidInput, "No join waits.") }
        connectState.polls += 1
        if connectState.polls >= 2 {
            join.state = .confirmed
            connectState.join = nil
            connectState.accountID = join.accountID
        }
        return join
    }

    public func connectJoinCancel() async throws { connectState.join = nil }

    public func connectStatus() async throws -> ConnectStatus {
        guard let account = connectState.accountID else {
            return ConnectStatus(state: .none, join: connectState.join)
        }
        return ConnectStatus(state: .account, accountID: account, deviceName: "iPhone", plan: connectState.plan)
    }

    public func connectForget() async throws -> Bool {
        let had = connectState.accountID != nil
        connectState = PreviewConnect()
        return had
    }

    /// Test support: the plan of the synthetic account.
    public func setConnectPlan(_ plan: ConnectPlan) { connectState.plan = plan }

    /// Test support: make the next `connectJoin` or `connectJoinPoll` fail with `error`.
    public func failNextConnect(_ error: VaultError) { connectState.nextError = error }

    /// Test support: the codes that `connectJoin` got.
    public func connectLinks() -> [String] { connectState.links }
}
