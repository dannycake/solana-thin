// swift-tools-version: 5.9
// A CI-only manifest. It tests the committed Swift against an XCFramework built
// from the current tree (a path target), so the Swift job does not depend on a
// published release. .github/workflows/swift.yml copies this next to the
// package's Sources and Tests and the freshly built XCFramework.
import PackageDescription

let package = Package(
    name: "SolanaThin",
    platforms: [.macOS(.v12)],
    products: [
        .library(name: "SolanaThin", targets: ["SolanaThin"]),
    ],
    targets: [
        .binaryTarget(name: "solana_thin_ffiFFI", path: "solana_thin_ffiFFI.xcframework"),
        .target(
            name: "SolanaThin",
            dependencies: ["solana_thin_ffiFFI"],
            path: "Sources/SolanaThin"
        ),
        .testTarget(
            name: "SolanaThinTests",
            dependencies: ["SolanaThin"],
            path: "Tests/SolanaThinTests",
            resources: [.copy("vectors")]
        ),
    ]
)
