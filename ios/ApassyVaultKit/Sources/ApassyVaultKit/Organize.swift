import Foundation

// Folders, adding by paste, and the options of a credential (contract ios-core-v1, section 5.11;
// ADR 0026 §4, §5, §8; ADR 0025 §4). The rules are the Mac's.

/// Where a credential acts (the declaration's environment).
public enum CredentialEnvironment: String, Codable, Sendable, CaseIterable, Identifiable {
    case production, staging, development, local

    public var id: String { rawValue }

    /// "Production", "Staging", "Development", "Local", as on the Mac.
    public var label: String {
        switch self {
        case .production: "Production"
        case .staging: "Staging"
        case .development: "Development"
        case .local: "Local"
        }
    }
}

/// Where a declaration value came from. The bouncer is more careful with a default or a value
/// from usage: the Mac shows the environment of such a credential as not confirmed.
public enum DeclarationSource: String, Codable, Sendable {
    /// The owner set or confirmed it.
    case owner
    /// A signal of the credential (a value prefix, a variable name) found it.
    case signal
    /// The use of the credential suggested it.
    case usage
    /// Nothing found it: the most sensitive value.
    case `default`

    /// The owner or a signal set it (the Mac's "known" environment).
    public var isConfirmed: Bool { self == .owner || self == .signal }
}

/// A folder of the vault (contract `folders`). Folders nest at most `maxDepth` levels.
public struct Folder: Codable, Sendable, Hashable, Identifiable {
    public static let maxDepth = 4
    public static let maxNameBytes = 64

    public var uuid: String
    /// nil at the top level.
    public var parent: String?
    public var name: String
    public var position: Int64
    /// The credentials directly in the folder that are not archived.
    public var count: Int

    public var id: String { uuid }

    public init(uuid: String, parent: String?, name: String, position: Int64, count: Int) {
        self.uuid = uuid
        self.parent = parent
        self.name = name
        self.position = position
        self.count = count
    }
}

public extension [Folder] {
    /// The names from the top level to `uuid`; empty for nil or a folder that is not here.
    func path(to uuid: String?) -> [String] {
        var names: [String] = []
        var seen: Set<String> = []
        var at = uuid
        while let current = at, !seen.contains(current), let folder = first(where: { $0.uuid == current }) {
            seen.insert(current)
            names.insert(folder.name, at: 0)
            at = folder.parent
        }
        return names
    }

    /// The subfolders of `parent` (nil: the top level), in the order of the core.
    func children(of parent: String?) -> [Folder] { filter { $0.parent == parent } }
}

/// A field of a detected credential. `preview` is the value of a plain field, and a mask for a
/// secret field (a public value prefix such as `sk_live_` or a URL scheme, then dots). No secret
/// value leaves the core.
public struct DetectedField: Codable, Sendable, Hashable, Identifiable {
    public var name: String
    public var label: String
    public var secret: Bool
    public var preview: String

    public var id: String { name }

    public init(name: String, label: String, secret: Bool, preview: String) {
        self.name = name
        self.label = label
        self.secret = secret
        self.preview = preview
    }
}

/// One credential that the detection of a paste found (contract `detect`): one row of "New
/// Credential". It has no secret value.
public struct DetectedCredential: Codable, Sendable, Hashable, Identifiable {
    /// The position in the answer; `addPasted(pick:)` names rows by it.
    public var index: Int
    public var title: String
    public var kind: ItemKind
    /// The provider label, such as "Stripe"; nil for a value without a provider.
    public var provider: String?
    /// The variable for agent processes, such as `STRIPE_SECRET_KEY`.
    public var envName: String?
    /// The known API hosts of the provider.
    public var hosts: [String]
    public var environment: CredentialEnvironment
    /// `signal` or `default`. The Mac shows the environment cap only for a signal.
    public var environmentSource: DeclarationSource
    /// `low`, `medium`, or `high`.
    public var risk: String
    /// The line of a `.env` entry, from 1; nil for a single value.
    public var line: Int?
    /// "Stripe live · STRIPE_SECRET_KEY · production".
    public var summary: String
    public var fields: [DetectedField]

    public var id: Int { index }

    public init(
        index: Int, title: String, kind: ItemKind, provider: String?, envName: String?, hosts: [String],
        environment: CredentialEnvironment, environmentSource: DeclarationSource, risk: String, line: Int?,
        summary: String, fields: [DetectedField]
    ) {
        self.index = index
        self.title = title
        self.kind = kind
        self.provider = provider
        self.envName = envName
        self.hosts = hosts
        self.environment = environment
        self.environmentSource = environmentSource
        self.risk = risk
        self.line = line
        self.summary = summary
        self.fields = fields
    }

    enum CodingKeys: String, CodingKey {
        case index, title, kind, provider, hosts, environment, risk, line, summary, fields
        case envName = "env_name"
        case environmentSource = "environment_source"
    }

    /// The cap of the row, as the Mac's `row_cap`: the environment that a signal found, red for
    /// production. A default shows none: the bouncer treats it as production until the owner answers.
    public var cap: (label: String, red: Bool)? {
        guard environmentSource == .signal else { return nil }
        switch environment {
        case .production: return ("Production", true)
        case .development, .local: return ("Development", false)
        case .staging: return ("Staging", false)
        }
    }

    /// "Stripe · STRIPE_SECRET_KEY · api.stripe.com", as the Mac's row line.
    public var rowLine: String {
        var parts = [provider ?? kind.label]
        if let envName { parts.append(envName) }
        if let host = hosts.first { parts.append(host) }
        return parts.joined(separator: " · ")
    }
}

/// A credential that `addPasted` saved.
public struct PastedItem: Codable, Sendable, Hashable, Identifiable {
    public var id: UInt64
    public var revision: UInt64
    /// The stored title (a title that another item has gets " 2").
    public var title: String
    /// "Stripe live · STRIPE_SECRET_KEY · production", with the stored title and variable.
    public var summary: String

    public init(id: UInt64, revision: UInt64, title: String, summary: String) {
        self.id = id
        self.revision = revision
        self.title = title
        self.summary = summary
    }
}

/// What "Add" sends besides the text: the folder, the rows to add, and typed titles.
public extension VaultService {
    /// Add every detected credential of `text` to `folder`.
    func addPasted(text: String, folder: String?) async throws -> [PastedItem] {
        try await addPasted(text: text, folder: folder, pick: nil, titles: [:])
    }
}
