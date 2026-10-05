import Foundation
import Testing

@testable import ApassyCompanionKit

@Suite("Keychain", .serialized)
struct KeychainTests {
    static func service() -> String { "com.wydrox.apassy.companion.test.\(UUID().uuidString)" }

    @Test("software keys are saved, loaded, replaced, and deleted")
    func softwareKeys() throws {
        let service = Self.service()
        defer { try? SoftwareKeys.delete(service: service) }
        #expect(try SoftwareKeys.load(service: service) == nil)
        let created = try SoftwareKeys.create(service: service)
        let loaded = try #require(try SoftwareKeys.load(service: service))
        #expect(loaded.requestPublicKey == created.requestPublicKey)
        #expect(loaded.approvalPublicKey == created.approvalPublicKey)
        let replaced = try SoftwareKeys.create(service: service)
        #expect(replaced.requestPublicKey != created.requestPublicKey)
        #expect(try #require(try SoftwareKeys.load(service: service)).requestPublicKey == replaced.requestPublicKey)
        try SoftwareKeys.delete(service: service)
        #expect(try SoftwareKeys.load(service: service) == nil)
    }

    @Test("the keychain store saves, loads, and replaces the record, and delete removes it and the keys")
    func pairingStore() throws {
        let service = Self.service()
        let store = KeychainPairingStore(service: service)
        defer { try? store.delete() }
        #expect(try store.load() == nil)
        let keys = try SoftwareKeys.create(service: service)
        try store.save(PairingStoreTests.record)
        #expect(try store.load() == PairingStoreTests.record)
        var newer = PairingStoreTests.record
        newer.lastGoodHost = "Mac-mini.local"
        try store.save(newer)
        #expect(try store.load() == newer)
        #expect(try SoftwareKeys.load(service: service)?.requestPublicKey == keys.requestPublicKey)
        try store.delete()
        #expect(try store.load() == nil)
        #expect(try SoftwareKeys.load(service: service) == nil)
    }
}
