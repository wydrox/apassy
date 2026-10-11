import Foundation
import Testing
@testable import ApassyVaultKit

@Suite struct ICloudModelTests {
    @Test func syncSourcePreservesLegacyDecodingAndInitializer() throws {
        let old = try JSONDecoder().decode(VaultEntry.self, from: Data("""
            {"id":"old","name":"Team","relay_url":"https://relay.example.test","team_id":"team","device_id":1,"added_at":0}
            """.utf8))
        #expect(old.syncSource == nil)
        #expect(old.isRelay)
        #expect(old.syncs)
        let local = VaultEntry(id: "local", name: "Local", relayURL: nil, teamID: nil, deviceID: nil, addedAt: 0)
        #expect(!local.syncs)
        let cloud = try JSONDecoder().decode(VaultEntry.self, from: Data("""
            {"id":"cloud","name":"Personal","added_at":0,"sync_source":"icloud"}
            """.utf8))
        #expect(cloud.isICloud)
        #expect(!cloud.isRelay)
        #expect(cloud.syncs)
        let json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(cloud)) as? [String: Any]
        #expect(json?["sync_source"] as? String == "icloud")
    }

    @Test func personalPreviewUsesICloudWithoutRelayDevices() async throws {
        let preview = PreviewVaultService()
        #expect(try await preview.info().selectedVault?.isICloud == true)
        #expect(try await preview.devices().isEmpty)
        #expect(try await preview.syncStatus().message == "Saved to the iCloud file.")
        await #expect(throws: VaultError.self) { _ = try await preview.useRelayCopy() }
        let cloud = try await preview.openICloudVault(url: URL(fileURLWithPath: "/synthetic.apassy"),
            name: "Personal", passphrase: PreviewVaultService.passphrase)
        #expect(cloud.isICloud)
        #expect(try await preview.info().selected == cloud.id)
        try await preview.reconnectICloudVault(url: URL(fileURLWithPath: "/synthetic.apassy"), vaultID: cloud.id)
        #expect(!(try await preview.removeVault(id: cloud.id, force: false)))
    }
}
