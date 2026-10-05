// The keys of this build: the Secure Enclave on a device, software keys in the simulator.

import Foundation

/// Makes, loads, and deletes the device keys of the right kind for this build.
public enum CompanionKeyStore {
    /// Whether this build keeps its private keys in the Secure Enclave.
    public static var usesSecureEnclave: Bool {
        #if targetEnvironment(simulator)
            return false
        #else
            return true
        #endif
    }

    /// Make new keys. Older keys are replaced.
    ///
    /// - Throws: `CompanionKeyError.noSecureEnclave` or `.notEnrolled` on a device that cannot pair.
    public static func createNew(service: String = CompanionKeychain.service) throws -> any CompanionKeys {
        #if targetEnvironment(simulator)
            return try SoftwareKeys.create(service: service)
        #else
            return try SecureEnclaveKeys.create(service: service)
        #endif
    }

    /// The keys of an earlier pairing, or nil when there are none.
    public static func loadExisting(service: String = CompanionKeychain.service) throws -> (any CompanionKeys)? {
        #if targetEnvironment(simulator)
            return try SoftwareKeys.load(service: service)
        #else
            return try SecureEnclaveKeys.load(service: service)
        #endif
    }

    /// Delete the keys.
    public static func deleteAll(service: String = CompanionKeychain.service) throws {
        try SoftwareKeys.delete(service: service)
        #if !targetEnvironment(simulator)
            try SecureEnclaveKeys.delete(service: service)
        #endif
    }
}
