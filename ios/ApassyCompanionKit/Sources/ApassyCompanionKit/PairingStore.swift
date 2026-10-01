// The pairing record on this phone (contract section 8).

import Foundation
import Security
import Synchronization

/// What the phone keeps about the Mac it paired with. It holds no secret: the private keys are in
/// the Secure Enclave, and the pairing secret is gone after the pairing.
public struct PairingRecord: Codable, Sendable, Equatable {
    public var deviceID: String
    public var macName: String
    public var hosts: [String]
    public var port: UInt16
    /// SHA-256 of the Mac certificate DER, 32 bytes.
    public var pin: Data
    /// When the phone paired, Unix seconds.
    public var pairedAt: Int64
    /// The host that answered last, or nil.
    public var lastGoodHost: String?

    public init(
        deviceID: String,
        macName: String,
        hosts: [String],
        port: UInt16,
        pin: Data,
        pairedAt: Int64,
        lastGoodHost: String? = nil
    ) {
        self.deviceID = deviceID
        self.macName = macName
        self.hosts = hosts
        self.port = port
        self.pin = pin
        self.pairedAt = pairedAt
        self.lastGoodHost = lastGoodHost
    }

    /// The endpoint of the Mac.
    public var endpoint: CompanionEndpoint {
        CompanionEndpoint(hosts: hosts, port: port, pin: pin)
    }
}

/// Where the pairing record lives.
public protocol PairingStore: Sendable {
    /// The record, or nil when this phone is not paired.
    func load() throws -> PairingRecord?
    /// Save the record. An older record is replaced.
    func save(_ record: PairingRecord) throws
    /// Delete the record and the keys.
    func delete() throws
}

/// The record as JSON in the keychain: this device only, not synchronized, readable only while
/// the phone is unlocked.
public struct KeychainPairingStore: PairingStore {
    static let account = "pairing-record"

    public let service: String

    public init(service: String = CompanionKeychain.service) {
        self.service = service
    }

    public func load() throws -> PairingRecord? {
        guard let data = try KeychainItems.load(service: service, account: Self.account) else { return nil }
        return try JSONDecoder().decode(PairingRecord.self, from: data)
    }

    public func save(_ record: PairingRecord) throws {
        try KeychainItems.save(
            JSONEncoder().encode(record), service: service, account: Self.account,
            accessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
    }

    /// Delete the record and both keys. The keys go first, so a failure leaves a record that the
    /// owner can still delete.
    public func delete() throws {
        try CompanionKeyStore.deleteAll(service: service)
        try KeychainItems.delete(service: service, account: Self.account)
    }
}

/// A store in memory, for tests and previews. It has no keys to delete.
public final class InMemoryPairingStore: PairingStore {
    private let record: Mutex<PairingRecord?>

    public init(_ record: PairingRecord? = nil) {
        self.record = Mutex(record)
    }

    public func load() throws -> PairingRecord? {
        record.withLock { $0 }
    }

    public func save(_ record: PairingRecord) throws {
        self.record.withLock { $0 = record }
    }

    public func delete() throws {
        record.withLock { $0 = nil }
    }
}
