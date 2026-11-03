import Foundation

/// What this watch did with one access request. Sent and uncertain answers outlive a trip to the
/// background, so a sent answer never looks unanswered.
public enum WatchAnswerProgress: Equatable, Sendable {
    /// Allow once: the watch checks that it is unlocked on the wrist.
    case checkingWrist
    /// The answer is being prepared or posted.
    case sending(AccessChoice)
    /// The relay took the answer at `at`; the Mac has not confirmed it yet.
    case sent(AccessChoice, at: Date)
    /// An answer was posted, but its result is not known.
    case uncertain(AccessChoice)
    /// The system refused Allow once (locked, off the wrist, no passcode). Nothing was sent.
    case refused
    /// Nothing was sent, for this reason.
    case failed(String)

    /// The answer that this watch sent or may have sent.
    public var postedChoice: AccessChoice? {
        switch self {
        case .sent(let choice, _), .uncertain(let choice): choice
        default: nil
        }
    }
}

/// The confirmed result of an access request (screen A4).
public struct WatchResult: Equatable, Sendable {
    public enum Outcome: Equatable, Sendable { case allowedOnce, denied, grantedOnMac, expired, invalidated }

    public let outcome: Outcome
    /// "This watch", or the escaped name of the answering device.
    public let answeredOn: String?
    /// This watch sent the answer that the Mac confirmed.
    public let byThisWatch: Bool
    /// The deadline of the consent.
    public let until: UInt64
    /// The request has expired since.
    public let accessExpired: Bool

    public var symbol: String {
        switch outcome {
        case .allowedOnce: "checkmark.circle.fill"
        case .denied: "xmark.circle"
        case .grantedOnMac: "checkmark.circle"
        case .expired: "clock"
        case .invalidated: "exclamationmark.circle"
        }
    }

    public var headline: String {
        switch outcome {
        case .allowedOnce: "Allowed once"
        case .denied: "Denied"
        case .grantedOnMac: "Access granted on the Mac"
        case .expired: "Expired"
        case .invalidated: "Access request invalidated"
        }
    }

    /// The lines under the headline, in order.
    public func lines(mac: String) -> [String] {
        var lines: [String]
        switch outcome {
        case .allowedOnce:
            lines = [
                "Consent recorded for one attempt before \(WatchRequestText.time(until)).",
                "The bouncer still checks the command and may ask you.",
                "Check on \(mac) for remaining availability.",
            ]
            if accessExpired { lines.append("Access expired") }
        case .denied, .expired: lines = ["Nothing was allowed."]
        case .grantedOnMac: lines = []
        case .invalidated: lines = ["Review on the Mac."]
        }
        if let answeredOn { lines.append("Answered on \(answeredOn)") }
        return lines
    }
}

/// The state of the Request screen (A2).
public enum WatchRequestPhase: Equatable, Sendable {
    /// The owner decides. `allowOnce`: Allow once is offered. `notes`: why only Deny, or what failed.
    case decide(allowOnce: Bool, notes: [String])
    case checkingWrist
    case sending
    case sent
    /// 60 s with no confirmation, past the expiry, or an answer whose result is not known.
    case notConfirmed
    /// The request ended without a receipt that this watch can check.
    case ended
    case expired
    case result(WatchResult)
    /// The request left the list.
    case unavailable
}

/// The rules of the answer screens, without UI (ADR 0033 section 7, flow spec A1 to A4).
public enum WatchRequestRules {
    /// After this long without a confirmation, a sent answer is "Not confirmed".
    public static let confirmationWait: TimeInterval = 60

    public static func isExpired(_ request: RelayAccessRequest, at date: Date) -> Bool {
        request.state == "expired" || date.timeIntervalSince1970 >= Double(request.card.expires_at)
    }

    /// Open, not answered, and not expired: an answer can be sent.
    public static func isActionable(_ request: RelayAccessRequest, at date: Date) -> Bool {
        request.state == "open" && request.receipt == nil && !isExpired(request, at: date)
    }

    /// The fields that the request does not specify, in the order of the screen. Any one makes
    /// the request Deny only.
    public static func missingScope(_ card: RelayAccessCard) -> [String] {
        var missing: [String] = []
        if card.action?.isEmpty ?? true { missing.append("the action") }
        if card.hosts.isEmpty { missing.append("the hosts") }
        if card.project == nil { missing.append("the project") }
        if card.cwd.isEmpty { missing.append("the folder") }
        return missing
    }

    /// The card offers Allow once, and its scope is complete.
    public static func offersAllowOnce(_ card: RelayAccessCard) -> Bool {
        card.valid_answers.contains(.allow_once) && missingScope(card).isEmpty
    }

    /// Why the request is Deny only, or nil when it offers Allow once.
    public static func denyOnlyNote(_ card: RelayAccessCard) -> String? {
        guard !offersAllowOnce(card) else { return nil }
        let mac = WatchRequestText.mac(card)
        let missing = missingScope(card)
        if !missing.isEmpty {
            return "Review on \(mac): this request does not specify \(WatchRequestText.list(missing))."
        }
        if let reason = card.local_review_reason, !reason.isEmpty {
            return "Review on \(mac): \(WatchRequestText.escaped(reason))"
        }
        return "Review on \(mac)."
    }

    /// Whether the answer key that the Mac registered for this watch (`answer_key` of the row) is
    /// `own` (the public key of this watch for the team).
    public static func keyMatches(_ request: RelayAccessRequest, own: Data?) -> Bool {
        guard let own, let registered = request.answer_key.flatMap(Base64URL.decode) else { return false }
        return registered == own
    }

    /// The state of the Request screen.
    ///
    /// - Parameters:
    ///   - request: the request in the list, or nil when it left the list.
    ///   - progress: what this watch did with it.
    ///   - allowBlock: why this watch cannot sign Allow once, or nil when it can.
    public static func phase(
        of request: RelayAccessRequest?, progress: WatchAnswerProgress?, allowBlock: String?, at now: Date
    ) -> WatchRequestPhase {
        guard let request else { return .unavailable }
        let card = request.card
        if let receipt = request.receipt {
            return .result(result(of: receipt, card: card, progress: progress, at: now))
        }
        let expired = isExpired(request, at: now)
        var failure: String?
        switch progress {
        case .checkingWrist?:
            if !expired { return .checkingWrist }
        case .sending?:
            return .sending
        case .sent(_, let at)?:
            return expired || now.timeIntervalSince(at) >= confirmationWait ? .notConfirmed : .sent
        case .uncertain?:
            return .notConfirmed
        case .refused?:
            failure = WatchKeyError.notOnWrist.errorDescription
        case .failed(let message)?:
            failure = message
        case nil:
            break
        }
        if expired { return .expired }
        if request.state != "open" { return .ended }
        if let denyOnly = denyOnlyNote(card) {
            return .decide(allowOnce: false, notes: [denyOnly] + (failure.map { [$0] } ?? []))
        }
        if let allowBlock {
            return .decide(allowOnce: false, notes: [allowBlock] + (failure.map { [$0] } ?? []))
        }
        return .decide(allowOnce: true, notes: failure.map { [$0] } ?? [])
    }

    /// The confirmed result. It is "by this watch" when this watch posted the same answer and a
    /// watch answered: the receipt has no identity of this watch to compare.
    public static func result(
        of receipt: AccessReceipt, card: RelayAccessCard, progress: WatchAnswerProgress?, at now: Date
    ) -> WatchResult {
        let outcome: WatchResult.Outcome =
            switch receipt.outcome {
            case "allowed_once": .allowedOnce
            case "denied": .denied
            case "granted_on_mac": .grantedOnMac
            case "expired": .expired
            default: .invalidated
            }
        let byThisWatch =
            progress?.postedChoice.map { $0.rawValue == receipt.kind } == true && receipt.device_kind == "watch"
        let answeredOn = byThisWatch ? "This watch" : receipt.device_name.map(WatchRequestText.escaped)
        return WatchResult(
            outcome: outcome, answeredOn: answeredOn, byThisWatch: byThisWatch, until: receipt.expires_at,
            accessExpired: now.timeIntervalSince1970 >= Double(card.expires_at))
    }
}
