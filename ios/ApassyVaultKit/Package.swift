// swift-tools-version: 6.0
// The Swift side of the iPhone vault core (ADR 0023, contract docs/contracts/ios-core-v1.md).
//
// - ApassyVaultKit: the typed models, the VaultService protocol, an in-memory service for
//   previews and tests, the Face ID passphrase store, the owner check, and the clipboard.
//   Apple frameworks only.
// - ApassyVaultCore: VaultService over the Rust core (ApassyCore.xcframework). Build the
//   framework first: scripts/build-ios-core.sh
import PackageDescription

let strict: [SwiftSetting] = [.enableUpcomingFeature("ExistentialAny")]

let package = Package(
    name: "ApassyVaultKit",
    platforms: [.iOS("26.0"), .macOS("15.0")],
    products: [
        .library(name: "ApassyVaultKit", targets: ["ApassyVaultKit"]),
        .library(name: "ApassyVaultCore", targets: ["ApassyVaultCore"]),
    ],
    targets: [
        .target(name: "ApassyVaultKit", swiftSettings: strict),
        .binaryTarget(name: "ApassyCoreFFI", path: "../ApassyCore/build/ApassyCore.xcframework"),
        .target(
            name: "ApassyVaultCore",
            dependencies: ["ApassyVaultKit", "ApassyCoreFFI"],
            swiftSettings: strict,
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("CoreFoundation"),
            ]
        ),
        .testTarget(name: "ApassyVaultKitTests", dependencies: ["ApassyVaultKit"], swiftSettings: strict),
        .testTarget(name: "ApassyVaultCoreTests", dependencies: ["ApassyVaultCore"], swiftSettings: strict),
    ]
)
