import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

@MainActor
@Suite("VaultSettings")
struct VaultSettingsTests {
    private let now = ContinuousClock.now

    @Test("a vault that was never left does not lock")
    func neverLeft() {
        #expect(!LockAfter.immediately.locks(leftAt: nil, now: now))
        #expect(!LockAfter.oneHour.locks(leftAt: nil, now: now))
    }

    @Test("Immediately locks at once")
    func immediately() {
        #expect(LockAfter.immediately.locks(leftAt: now, now: now))
    }

    @Test("1 minute locks at 60 seconds and not before")
    func oneMinute() {
        let left = now - .seconds(59)
        #expect(!LockAfter.oneMinute.locks(leftAt: left, now: now))
        #expect(LockAfter.oneMinute.locks(leftAt: now - .seconds(60), now: now))
        #expect(LockAfter.oneMinute.locks(leftAt: now - .seconds(61), now: now))
    }

    @Test("the defaults are Immediately and 1 minute")
    func defaults() {
        let settings = makeSettings()
        #expect(settings.lockAfter == .immediately)
        #expect(settings.clearAfter == .oneMinute)
        #expect(settings.deviceName == nil)
    }

    @Test("the choices survive a new settings object on the same defaults")
    func persistence() {
        let defaults = makeDefaults()
        let first = VaultSettings(defaults: defaults)
        first.lockAfter = .fifteenMinutes
        first.clearAfter = .twoMinutes
        first.deviceName = "Test iPhone"
        first.setFavorites([4, 2], vaultID: "v1")
        first.setFaceIDUnlock(true, vaultID: "v1")

        let second = VaultSettings(defaults: defaults)
        #expect(second.lockAfter == .fifteenMinutes)
        #expect(second.clearAfter == .twoMinutes)
        #expect(second.clearAfter.seconds == 120)
        #expect(second.deviceName == "Test iPhone")
        #expect(second.favorites(vaultID: "v1") == [4, 2])
        #expect(second.faceIDUnlock(vaultID: "v1"))
    }

    @Test("a favorite is added at the end and removed by a second toggle")
    func favorites() {
        let settings = makeSettings()
        settings.toggleFavorite(5, vaultID: "v1")
        settings.toggleFavorite(3, vaultID: "v1")
        settings.toggleFavorite(9, vaultID: "v1")
        #expect(settings.favorites(vaultID: "v1") == [5, 3, 9])
        #expect(settings.isFavorite(3, vaultID: "v1"))

        settings.toggleFavorite(3, vaultID: "v1")
        #expect(settings.favorites(vaultID: "v1") == [5, 9])
        #expect(!settings.isFavorite(3, vaultID: "v1"))
        #expect(settings.favorites(vaultID: "v2").isEmpty)
    }

    @Test("the Face ID choice belongs to one vault")
    func faceIDPerVault() {
        let settings = makeSettings()
        #expect(!settings.faceIDUnlock(vaultID: "v1"))
        settings.setFaceIDUnlock(true, vaultID: "v1")
        #expect(settings.faceIDUnlock(vaultID: "v1"))
        #expect(!settings.faceIDUnlock(vaultID: "v2"))
    }

    @Test("forget clears the favorites and the Face ID choice of one vault")
    func forget() {
        let settings = makeSettings()
        settings.toggleFavorite(1, vaultID: "v1")
        settings.setFaceIDUnlock(true, vaultID: "v1")
        settings.toggleFavorite(2, vaultID: "v2")
        let before = settings.storeVersion

        settings.forget(vaultID: "v1")
        #expect(settings.favorites(vaultID: "v1").isEmpty)
        #expect(!settings.faceIDUnlock(vaultID: "v1"))
        #expect(settings.favorites(vaultID: "v2") == [2])
        #expect(settings.storeVersion > before)
    }
}
