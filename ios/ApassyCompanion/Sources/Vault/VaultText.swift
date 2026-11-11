import ApassyVaultKit
import Foundation

/// Text rules of the vault screens that need no UI: how a value is grouped and colored, how a
/// label reads inside a sentence, and how a website opens.
enum VaultText {
    /// The kind of a character in a secret, for its color: digits and symbols stand out from
    /// letters, so the owner can tell `0` from `O` and `l` from `1`.
    enum CharacterClass: Equatable, Sendable {
        case letter
        case digit
        case symbol
        case space
    }

    static func characterClass(_ character: Character) -> CharacterClass {
        if character.isWhitespace { return .space }
        if character.isASCII, character.isNumber { return .digit }
        if character.isLetter { return .letter }
        return .symbol
    }

    /// A one-time code in groups of three: "123456" is "123 456", "12345678" is "12 345 678".
    static func groupedCode(_ code: String) -> String {
        var groups: [String] = []
        var rest = Substring(code)
        while !rest.isEmpty {
            let size = rest.count % 3 == 0 ? 3 : rest.count % 3
            groups.append(String(rest.prefix(size)))
            rest = rest.dropFirst(size)
        }
        return groups.joined(separator: " ")
    }

    /// The digits of a code one by one, so VoiceOver does not read it as one number.
    static func spokenCode(_ code: String) -> String {
        code.filter(\.isNumber).map(String.init).joined(separator: ", ")
    }

    /// A label inside a sentence: "Password" reads "password", "API key" stays as it is.
    static func phrase(_ label: String) -> String {
        let characters = Array(label)
        guard let first = characters.first, first.isUppercase else { return label }
        if characters.count > 1, characters[1].isUppercase { return label }
        return first.lowercased() + String(characters.dropFirst())
    }

    /// The URL to open for a website value; `https://` when it has no scheme. Only http and https.
    static func websiteURL(_ value: String) -> URL? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let text = trimmed.contains("://") ? trimmed : "https://\(trimmed)"
        guard let url = URL(string: text), let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "http",
            url.host() != nil
        else { return nil }
        return url
    }

    /// The host of a website for a row: "github.com".
    static func host(_ value: String) -> String {
        guard let host = websiteURL(value)?.host() else { return value }
        return host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
    }

    /// Whether `text` is a device link of the relay: the link `<relay>/link#apassy_lnk_…`, or the
    /// bare token. Returns the trimmed link, or nil.
    static func joinLink(from text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains(where: \.isNewline) else { return nil }
        if trimmed.hasPrefix("apassy_lnk_") || trimmed.contains("/link#apassy_lnk_") { return trimmed }
        return nil
    }

    /// Whether `link` is a device link of a node: its fragment has the pin of the node
    /// (contract node-pairing-v1 section 5). The core parses and checks the whole link.
    static func isPinnedLink(_ link: String) -> Bool {
        guard let fragment = link.split(separator: "#", maxSplits: 1).dropFirst().first else { return false }
        return fragment.contains("&pin=")
    }

    /// Whether `text` is a node pairing link, `<origin>/pair#apassy_tcd_…`: a Mac makes a team
    /// with it on a Linux node (node-pairing-v1 section 6). An iPhone never uses one.
    static func isNodePairingLink(_ text: String) -> Bool {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.contains("/pair#apassy_tcd_") || trimmed.hasPrefix("apassy_tcd_")
    }

    /// The team of a device link of the relay, `apassy_lnk_<team id>_<hex>` (a team id is `t_` and
    /// 10 of a-z and 2-7), alone or after `/link#`, or nil. It picks the answer key of the team;
    /// the core checks the whole link.
    static func linkTeam(_ text: String) -> String? {
        guard let start = text.range(of: "apassy_lnk_") else { return nil }
        let code = text[start.upperBound...].prefix { $0 != "&" && !$0.isWhitespace }
        let team = code.prefix(12)
        let base32 = Set("abcdefghijklmnopqrstuvwxyz234567")
        let hex = Set("0123456789abcdef")
        guard team.count == 12, team.hasPrefix("t_"), team.dropFirst(2).allSatisfy(base32.contains),
            code.dropFirst(12).first == "_", code.count > 13, code.dropFirst(13).allSatisfy(hex.contains)
        else { return nil }
        return String(team)
    }

    /// Whether `text` is a one-time password setup code: an `otpauth://totp/` URI.
    static func otpURI(from text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.lowercased().hasPrefix("otpauth://totp/") ? trimmed : nil
    }

    /// The date of a time of the core (Unix seconds).
    static func date(_ seconds: Int64?) -> Date? {
        seconds.map { Date(timeIntervalSince1970: TimeInterval($0)) }
    }

    /// The start of a passkey ID in hex, in groups of four, to tell two passkeys apart.
    static func shortID(_ id: Data) -> String {
        let hex = id.prefix(6).map { String(format: "%02x", $0) }.joined()
        var groups: [String] = []
        var rest = Substring(hex)
        while !rest.isEmpty {
            groups.append(String(rest.prefix(4)))
            rest = rest.dropFirst(4)
        }
        return groups.joined(separator: " ") + (id.count > 6 ? "…" : "")
    }
}

/// The notice of ADR 0037 D14 (plan s7 unit N1) in Settings > Devices: the free approvals
/// and the free relay sync on the hosted relay end with `endVersion`. Text only: App Review
/// guideline 3.1 allows no price, no button, and no link to a checkout or a pricing page, so
/// the choice is made in Apassy on the Mac.
enum FreeRelayNotice {
    /// The release that ends the free paths. The same as `FREE_RELAY_PATHS_END_VERSION` in
    /// `src/relay/membership.rs`; a Rust test reads this line.
    static let endVersion = "0.5.20"
    /// The hosted relay, `DEFAULT_RELAY_URL` of the core.
    static let hostedHost = "apassy-relay.wyderka.cc"

    /// Under "Questions through the relay" while the questions are connected.
    static let questions =
        "Free approvals through apassy-relay.wyderka.cc end with Apassy \(endVersion). Your Mac can keep them free over Tailscale, or use Apassy Connect. Choose in Apassy on your Mac."

    /// Under "Sync service" while the vault syncs through the hosted relay.
    static let relaySync =
        "Relay sync on apassy-relay.wyderka.cc is free until Apassy \(endVersion). Then the hosted store is part of Apassy Connect; your own Mac or Linux node can be the sync home (free). Choose in Apassy on your Mac."

    /// Whether `url` is the hosted relay. A relay that the owner runs is never the hosted one.
    static func isHosted(_ url: String?) -> Bool {
        guard let text = url?.trimmingCharacters(in: .whitespaces),
            let parts = URLComponents(string: text),
            parts.scheme?.lowercased() == "https",
            parts.host?.lowercased() == hostedHost,
            parts.port == nil || parts.port == 443,
            parts.path.isEmpty || parts.path == "/",
            parts.query == nil, parts.user == nil
        else { return false }
        return true
    }

    /// The line under "Sync service" for a vault, or nil.
    static func relaySyncLine(for vault: VaultEntry?) -> String? {
        guard let vault, vault.isRelay, isHosted(vault.relayURL) else { return nil }
        return relaySync
    }
}

/// The route words of Settings > Devices (`docs/design/devices-settings-mockup.html`, plan S2–S3
/// D9): where the sync or the questions of a vault go. A pinned relay is a node on the tailnet: the
/// relay inside the Mac app (plan unit N6 shows "via your Mac" for it).
enum DeviceRoute: Equatable {
    /// A node on the tailnet, behind its pinned certificate. `name` is the node's name from its
    /// link, a label only.
    case viaYourMac(name: String?)
    /// A relay with system trust: the hosted Apassy relay, or a relay that the owner runs.
    case viaApassyRelay
    /// The Mac on the same Wi-Fi (the companion, ADR 0028).
    case wifi

    /// The route word of the mockup.
    var text: String {
        switch self {
        case .viaYourMac: "via your Mac"
        case .viaApassyRelay: "via Apassy relay"
        case .wifi: "Wi-Fi"
        }
    }

    /// The line under the route, or nil: how a node is reached.
    var detail: String? {
        guard case .viaYourMac(let name) = self else { return nil }
        if let name { return "Through Tailscale to \(name)." }
        return "Through Tailscale to your Mac."
    }

    /// The line with the node words, or nil: "Node words to compare: noodle monkey dinner sled
    /// guitar garden". Safety words to compare with the words that the Mac shows for its node: a
    /// check for a person, never proof of the node or the trust (contract node-pairing-v1 section
    /// 4a, N8-7). The core checks the whole pin.
    static func nodeWordsLine(_ node: NodeInfo?) -> String? {
        node?.nodeWords.map { "Node words to compare: \($0)" }
    }

    /// The route of the sync of `vault`, or nil for a vault without relay sync (only on this
    /// iPhone, or in iCloud Drive).
    static func of(_ vault: VaultEntry) -> DeviceRoute? {
        guard vault.isRelay else { return nil }
        return vault.isNode ? .viaYourMac(name: vault.nodeName) : .viaApassyRelay
    }

    /// The route of a questions team: its node when the core names one, with the name of the
    /// vault entry of that origin.
    static func of(_ status: QuestionsStatus, entries: [VaultEntry]) -> DeviceRoute {
        guard status.node != nil else { return .viaApassyRelay }
        return .viaYourMac(name: nodeName(of: status, entries: entries))
    }

    /// The node's name of a questions team: from the status, else from a vault entry on this
    /// iPhone with the same origin and a pin.
    static func nodeName(of status: QuestionsStatus, entries: [VaultEntry]) -> String? {
        guard let node = status.node else { return nil }
        if let name = node.name { return name }
        return entries.first { $0.pin != nil && $0.relayURL == node.origin && $0.nodeName != nil }?.nodeName
    }

    /// The one quiet line while nodes do not answer: "Turn on Tailscale on this iPhone to reach
    /// <Mac>." Nil when every node answered.
    static func tailscaleOffLine(_ nodes: [UnreachableNode]) -> String? {
        guard !nodes.isEmpty else { return nil }
        var names: [String] = []
        for node in nodes {
            let name = node.nodeName ?? "your Mac"
            if !names.contains(name) { names.append(name) }
        }
        // A named Mac with an unnamed one: "your Mac" says nothing more.
        if names.count > 1 { names.removeAll { $0 == "your Mac" } }
        let list: String
        switch names.count {
        case 1: list = names[0]
        case 2: list = "\(names[0]) and \(names[1])"
        // English only, as every text of the app: no locale of the iPhone changes it.
        default: list = names.dropLast().joined(separator: ", ") + ", and " + names[names.count - 1]
        }
        return "Turn on Tailscale on this iPhone to reach \(list)."
    }
}

/// The row "Apassy Connect" of Settings > General (plan s7 unit I1, section 6): the plan of the
/// account of this iPhone, as text. App Store Review Guideline 3.1 allows the iPhone to show the
/// plan of the account it belongs to and where it is managed; it never shows a price, a currency,
/// a comparison, a trial, or a button or link that leads to a purchase. So this type has text only:
/// no action, no URL.
enum ConnectPlanRow: Equatable {
    /// The status is not known yet.
    case checking
    /// The core gave no status (no network and no earlier answer, or the Keychain is locked).
    case unavailable
    case notOnConnect
    /// Connect says this iPhone is no device of its account any more (a Mac removed it, or the
    /// account was deleted), or the Keychain lost the key. The key and the account file stay until
    /// "Forget This iPhone…" in Settings > Devices.
    case removed
    /// "Connect Personal · renews 3 Dec 2026" (or Team).
    case active(plan: String?, renews: Date?)
    /// "Connect Family · 3 of 4 people".
    case family(active: Int, of: Int)
    case pastDue
    /// "Ends 12 Jan 2027".
    case ending(Date)

    static let title = "Apassy Connect"
    /// The only line about where the plan is managed: text, no link.
    static let managedLine = "Managed in Apassy on your Mac"
    /// The line of `.removed`: what happened, and where this iPhone forgets the account (text, no
    /// link).
    static let removedLine =
        "This iPhone is no longer a device of its Apassy Connect account. To join an account again, forget it in Settings > Devices."

    /// What the row shows: its value and the lines under it, all of them text.
    struct Content: Equatable {
        var title: String
        var value: String
        var lines: [String]
    }

    /// The row of `status`. `failed`: the last `connect_status` failed.
    static func of(_ status: ConnectStatus?, failed: Bool = false) -> ConnectPlanRow {
        guard let status else { return failed ? .unavailable : .checking }
        // `removed` comes with an account; a core never sends it without one, but the row would say
        // the same.
        if status.removed { return .removed }
        guard status.state == .account else { return .notOnConnect }
        guard let plan = status.plan else { return .unavailable }
        switch plan.status {
        case .active, .trialing:
            if let ends = VaultText.date(plan.endsAt) { return .ending(ends) }
            if plan.plan == "family", let people = plan.people { return .family(active: people.active, of: people.of) }
            return .active(plan: plan.plan, renews: VaultText.date(plan.renewsAt))
        case .pastDue:
            return .pastDue
        case .readOnly:
            return VaultText.date(plan.readOnlyUntil).map(ConnectPlanRow.ending) ?? .notOnConnect
        case .none, .pending, .suspended, .unknown:
            return .notOnConnect
        }
    }

    /// The name of a plan: "Connect Personal", "Connect Family", "Connect Team".
    static func planName(_ plan: String?) -> String {
        switch plan {
        case "personal": "Connect Personal"
        case "family": "Connect Family"
        case "team": "Connect Team"
        default: title
        }
    }

    /// A day as the row shows it: "3 Dec 2026". English, as every text of the app.
    static func day(_ date: Date, timeZone: TimeZone = .current) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.timeZone = timeZone
        formatter.dateFormat = "d MMM yyyy"
        return formatter.string(from: date)
    }

    func value(timeZone: TimeZone = .current) -> String {
        switch self {
        case .checking: "Checking"
        case .unavailable: "Not available"
        case .notOnConnect: "Not on Connect"
        case .removed: "Removed from the account"
        case .active(let plan, let renews):
            renews.map { "\(Self.planName(plan)) · renews \(Self.day($0, timeZone: timeZone))" } ?? Self.planName(plan)
        case .family(let active, let of): "Connect Family · \(active) of \(of) people"
        case .pastDue: "Past due"
        case .ending(let date): "Ends \(Self.day(date, timeZone: timeZone))"
        }
    }

    /// Whether this iPhone is on an account in this state: only then does the row say where the
    /// plan is managed. Without an account the iPhone says nothing more (no call to action).
    var isOnAccount: Bool {
        switch self {
        case .active, .family, .pastDue, .ending: true
        case .checking, .unavailable, .notOnConnect, .removed: false
        }
    }

    /// The whole row for `status`. The devices that are not verified have their line in Settings >
    /// Devices (`ConnectDevicesText`), next to the account's control.
    static func content(_ status: ConnectStatus?, failed: Bool = false, timeZone: TimeZone = .current) -> Content {
        let row = of(status, failed: failed)
        var lines: [String] = []
        if row.isOnAccount { lines.append(managedLine) }
        if row == .removed { lines.append(removedLine) }
        return Content(title: title, value: row.value(timeZone: timeZone), lines: lines)
    }
}

/// The section "Apassy Connect" of Settings > Devices (plan s7 unit I3): one quiet line for the
/// devices of the account that this iPhone could not verify, and the one control "Forget This
/// iPhone…". Leaving an account is no purchase action (plan section 6); no text here names a plan, a
/// price, or a purchase.
enum ConnectDevicesText {
    static let header = "Apassy Connect"
    static let forgetButton = "Forget This iPhone…"
    static let confirmTitle = "Forget This iPhone?"
    static let confirmButton = "Forget This iPhone"
    /// The message of the confirmation while this iPhone is a device of the account.
    static let confirmOnAccount =
        "This iPhone forgets its Apassy Connect account and its account key. Your Mac lists this iPhone until you remove it there. To join again, use a new code from Apassy on your Mac."
    /// The message of the confirmation after the removal.
    static let confirmRemoved =
        "This iPhone forgets its Apassy Connect account and its account key. To join an account again, use a new code from Apassy on your Mac."
    /// The footer while the section shows.
    static let footer = "Your vaults, approvals over Tailscale, and Wi-Fi stay on this iPhone."
    /// After a forget that failed.
    static let forgetFailed = "This iPhone could not forget the account. Try again."

    /// Whether the section shows: only on an account (also a removed one). Without an account the
    /// iPhone shows nothing here: no call to action.
    static func shows(_ status: ConnectStatus?) -> Bool { status?.state == .account }

    /// "1 device of the account is not verified. Check Apassy on your Mac.", or nil when every
    /// device is verified. After a removal the list is not the iPhone's any more: nil.
    static func notVerifiedLine(_ status: ConnectStatus?) -> String? {
        guard let status, status.state == .account, !status.removed else { return nil }
        let count = status.unverifiedDevices.count
        switch count {
        case 0: return nil
        case 1: return "1 device of the account is not verified. Check Apassy on your Mac."
        default: return "\(count) devices of the account are not verified. Check Apassy on your Mac."
        }
    }

    /// The message of the confirmation for `status`.
    static func confirmMessage(_ status: ConnectStatus?) -> String {
        status?.removed == true ? confirmRemoved : confirmOnAccount
    }
}

/// The end of the free approvals through the hosted relay (plan s7 section 5, R3): the hosted relay
/// answers the questions, the feed, and the push of the team with 410, and the core calls it no
/// more. One calm state in the place of "Questions": no price, no link, nothing to buy.
enum RelayEndedNotice {
    /// The value of the row "Questions".
    static let value = "Ended"
    static let line =
        "Approvals through apassy-relay.wyderka.cc have ended. Pair this iPhone again from Apassy on your Mac."
}

/// The line "Reaches your Mac through: …" of Settings > Devices (plan s7 unit I1): how this
/// iPhone reaches its Mac now. Apassy Connect shows only when the core reports its dial (unit I2).
enum MacReach: Equatable, CaseIterable {
    case tailscale
    case connect
    case wifi

    var word: String {
        switch self {
        case .tailscale: "Tailscale"
        case .connect: "Apassy Connect"
        case .wifi: "Wi-Fi"
        }
    }

    /// The quiet line of the dial when no route is in use through it (section 5.15): "Mac is offline"
    /// (`mac_offline`) or "Not on Connect" (`not_on_connect`); nil for every other state, which the
    /// app does not show. No hint, no plan, no purchase.
    static func dialLine(_ connect: ConnectStatus?) -> String? {
        guard let connect, !connect.dialRoute, !connect.removed else { return nil }
        switch connect.dialState {
        case .macOffline: return "Mac is offline"
        case .notOnConnect: return "Not on Connect"
        case .unused, .connected, .limit, .unreachable, .refused, .unknown: return nil
        }
    }

    /// "Reaches your Mac through: Tailscale", or nil when no route reaches a Mac.
    static func line(_ routes: [MacReach]) -> String? {
        let ordered = allCases.filter(routes.contains)
        guard !ordered.isEmpty else { return nil }
        return "Reaches your Mac through: " + ordered.map(\.word).joined(separator: ", ")
    }

    /// The routes: Tailscale for a vault or a questions team on a node (the relay inside the Mac
    /// app, over the tailnet) while the tailnet reaches it, Apassy Connect in its place when the core
    /// dials through it (`dial_route`: the tailnet did not answer), Wi-Fi for a paired companion.
    static func routes(
        vaults: [VaultEntry], questionRoutes: [DeviceRoute], wifiPaired: Bool, connect: ConnectStatus?
    ) -> [MacReach] {
        var routes: [MacReach] = []
        let onNode =
            vaults.contains(where: \.isNode)
            || questionRoutes.contains { if case .viaYourMac = $0 { true } else { false } }
        let dialing = connect?.state == .account && connect?.removed != true && connect?.dialRoute == true
        if dialing {
            routes.append(.connect)
        } else if onNode {
            routes.append(.tailscale)
        }
        if wifiPaired { routes.append(.wifi) }
        return routes
    }
}
