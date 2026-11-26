// swift-tools-version: 5.9
import PackageDescription

// A Swift package for the solana-thin verifier.
//
// `Sources/SolanaThin/solana_thin_ffi.swift` is generated from the Rust crate
// with UniFFI (see docs/BINDINGS.md); regenerate it when the binding's
// interface changes. `solana_thin_ffiFFI` is the compiled library, shipped as
// an XCFramework attached to the matching GitHub release.
let package = Package(
    name: "SolanaThin",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "SolanaThin", targets: ["SolanaThin"]),
    ],
    targets: [
        .binaryTarget(
            name: "solana_thin_ffiFFI",
            url: "https://github.com/dannycake/solana-thin/releases/download/v0.1.0/solana_thin_ffiFFI.xcframework.zip",
            checksum: "128305df3bfcbfdf3ab3be723c11458cb40982819d03a9be1c0238bffe9e0b6a"
        ),
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
