// swift-tools-version: 6.2
// The wire kit of the Apassy iPhone companion (ADR 0014, contract companion-v1).
// Apple frameworks only. It builds and tests on macOS with `swift test`.

import PackageDescription

let package = Package(
    name: "ApassyCompanionKit",
    platforms: [
        .iOS(.v26),
        .macOS(.v15),
    ],
    products: [
        .library(name: "ApassyCompanionKit", targets: ["ApassyCompanionKit"]),
        .executable(name: "companion-interop", targets: ["companion-interop"]),
    ],
    targets: [
        .target(
            name: "ApassyCompanionKit",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        // The driver of the interop check (scripts/companion-interop.sh). It runs on macOS.
        .executableTarget(
            name: "companion-interop",
            dependencies: ["ApassyCompanionKit"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "ApassyCompanionKitTests",
            dependencies: ["ApassyCompanionKit"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
