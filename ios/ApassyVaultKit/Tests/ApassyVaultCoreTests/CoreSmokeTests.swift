import ApassyVaultKit
import Foundation
import Testing

@testable import ApassyVaultCore

@Suite struct CoreSmokeTests {
    @Test func coreStartsAndAnswers() async throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "apassy-core-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let core = try CoreVaultService(dataDirectory: dir, deviceName: "Test iPhone", role: .app)
        do {
            _ = try await core.info()
        } catch let error as VaultError {
            #expect(error.code == .internal)
        }
    }
}
