import Foundation
import LocalAuthentication
import Security

/// Only the containing app opts into this singleton. AutoFill uses nil providers.
/// One lease at a time prevents simultaneous use/mutation of an LAContext.
public final class FaceIDWindow: @unchecked Sendable {
    public static let app = FaceIDWindow()
    private let lock = NSLock()
    private var state: FaceIDWindowState<LAContext> = {
        // ContinuousClock includes time asleep; changing the wall clock cannot extend a window.
        let start = ContinuousClock.now
        return FaceIDWindowState(
            now: {
                let elapsed = start.duration(to: .now).components
                return Double(elapsed.seconds) + Double(elapsed.attoseconds) / 1e18
            }, factory: { LAContext() }, invalidate: { $0.invalidate() })
    }()
    private var active: LAContext?
    private var enrollment: Data?
    private var timer: DispatchWorkItem?

    private init() {
        state.configure(Self.loadFrequency())
    }

    public var frequency: FaceIDFrequency { lock.withLock { state.frequency } }

    public func end() {
        lock.withLock {
            timer?.cancel(); timer = nil
            state.end()
            active?.invalidate()
        }
    }

    public func authenticate(reason: String) async throws -> FaceIDLease {
        let probe = LAContext()
        let available = probe.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        let hash = available ? probe.domainState.biometry.stateHash : nil
        probe.invalidate()
        let (context, reused, generation) = try lock.withLock {
            guard active == nil else { throw CompanionKeyError.cancelled }
            if hash == nil || hash != enrollment { state.end(); enrollment = hash }
            let result = state.acquire()
            active = result.0
            return result
        }
        do {
            if !reused {
                context.localizedFallbackTitle = ""
                context.touchIDAuthenticationAllowableReuseDuration = 0
                guard try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
                else { throw CompanionKeyError.cancelled }
            }
            try lock.withLock {
                guard state.authenticated(context, generation: generation) else { throw CompanionKeyError.cancelled }
                if !reused, let seconds = state.frequency.seconds, seconds > 0 {
                    let work = DispatchWorkItem { [weak self] in self?.expire() }
                    timer?.cancel(); timer = work
                    DispatchQueue.global().asyncAfter(deadline: .now() + seconds, execute: work)
                }
            }
            return FaceIDLease(context: context, isValid: { [self] in
                lock.withLock { state.expire(); return state.generation == generation }
            }) { [self] failed in
                lock.withLock {
                    active = nil
                    if failed { state.end() }
                    if failed || state.frequency == .everyTime { context.invalidate() }
                }
            }
        } catch {
            lock.withLock { active = nil; state.end(); context.invalidate() }
            throw error
        }
    }

    private func expire() { lock.withLock { state.expire() } }

    /// A separate context always asks, even while the old window is open.
    public func changeFrequency(_ value: FaceIDFrequency) async throws {
        end()
        let context = LAContext()
        let generation = try lock.withLock {
            guard active == nil else { throw CompanionKeyError.cancelled }
            active = context
            return state.generation
        }
        defer {
            lock.withLock { if active === context { active = nil } }
            context.invalidate()
        }
        context.localizedFallbackTitle = ""
        context.touchIDAuthenticationAllowableReuseDuration = 0
        guard try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "Change how often Apassy asks for Face ID") else { throw CompanionKeyError.cancelled }
        try lock.withLock {
            guard state.generation == generation else { throw CompanionKeyError.cancelled }
            state.configure(.everyTime)
            var item = Self.settingQuery
            let data = Data(value.rawValue.utf8)
            let status = SecItemUpdate(item as CFDictionary, [kSecValueData as String: data] as CFDictionary)
            if status == errSecItemNotFound {
                item[kSecValueData as String] = data
                item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
                let added = SecItemAdd(item as CFDictionary, nil)
                guard added == errSecSuccess else { throw CompanionKeyError.failed(code: added) }
            } else if status != errSecSuccess { throw CompanionKeyError.failed(code: status) }
            state.configure(value)
        }
    }

    private static var settingQuery: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "com.wydrox.apassy.app.face-id-frequency",
         kSecAttrAccount as String: "frequency", kSecUseDataProtectionKeychain as String: true]
    }
    private static func loadFrequency() -> FaceIDFrequency {
        var query = settingQuery
        query[kSecReturnData as String] = true
        let context = LAContext()
        context.interactionNotAllowed = true
        defer { context.invalidate() }
        query[kSecUseAuthenticationContext as String] = context
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data, let code = String(data: data, encoding: .utf8)
        else { return .everyTime }
        return FaceIDFrequency(rawValue: code) ?? .everyTime
    }
}

public final class FaceIDLease: @unchecked Sendable {
    public let context: LAContext
    private let validity: () -> Bool
    public var isValid: Bool { lock.withLock { release != nil } && validity() }
    private let lock = NSLock()
    private var release: ((Bool) -> Void)?
    init(context: LAContext, isValid: @escaping () -> Bool, release: @escaping (Bool) -> Void) {
        self.context = context; self.validity = isValid; self.release = release
    }
    public func end(failed: Bool = false) {
        let action = lock.withLock { let action = release; release = nil; return action }
        action?(failed)
    }
    deinit { end() }
}
