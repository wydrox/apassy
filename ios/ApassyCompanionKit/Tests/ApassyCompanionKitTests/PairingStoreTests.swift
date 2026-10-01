import Foundation
import Testing

@testable import ApassyCompanionKit

@Suite("Pairing store")
struct PairingStoreTests {
    static let record = PairingRecord(
        deviceID: Vectors.deviceID, macName: "Mac mini", hosts: ["Mac-mini.local", "192.168.1.20"], port: 48620,
        pin: Data(repeating: 9, count: 32), pairedAt: 1_790_000_000, lastGoodHost: "192.168.1.20")

    @Test("the record round trips as JSON")
    func json() throws {
        let data = try JSONEncoder().encode(Self.record)
        #expect(try JSONDecoder().decode(PairingRecord.self, from: data) == Self.record)
    }

    @Test("the record has no secret")
    func noSecret() throws {
        let text = String(decoding: try JSONEncoder().encode(Self.record), as: UTF8.self)
        for word in ["secret", "private", "proof", "signature"] {
            #expect(!text.lowercased().contains(word))
        }
    }

    @Test("the endpoint comes from the record")
    func endpoint() {
        #expect(Self.record.endpoint == CompanionEndpoint(hosts: Self.record.hosts, port: 48620, pin: Self.record.pin))
    }

    @Test("an in-memory store loads, saves, replaces, and deletes")
    func inMemory() throws {
        let store = InMemoryPairingStore()
        #expect(try store.load() == nil)
        try store.save(Self.record)
        #expect(try store.load() == Self.record)
        var newer = Self.record
        newer.lastGoodHost = "Mac-mini.local"
        try store.save(newer)
        #expect(try store.load() == newer)
        try store.delete()
        #expect(try store.load() == nil)
        try store.delete()
    }

    @Test("the keychain store uses the service of the companion, this device only")
    func keychainService() {
        #expect(KeychainPairingStore().service == "com.wydrox.apassy.companion")
        #expect(CompanionKeychain.service == "com.wydrox.apassy.companion")
    }
}
