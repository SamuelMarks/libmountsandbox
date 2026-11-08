// swift-tools-version: 5.7

import PackageDescription
import Foundation

let packageDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let buildDir = URL(fileURLWithPath: packageDir).appendingPathComponent("../../build").standardized.path
#if os(macOS)
let dylibPath = "\(buildDir)/libmountsandbox.dylib"
#else
let dylibPath = "\(buildDir)/libmountsandbox.so"
#endif

let package = Package(
    name: "MountSandbox",
    products: [
        .library(
            name: "MountSandbox",
            targets: ["MountSandbox"]),
    ],
    targets: [
        .target(
            name: "CMountSandbox",
            linkerSettings: [
                .unsafeFlags([dylibPath, "-Xlinker", "-rpath", "-Xlinker", buildDir])
            ]
        ),
        .target(
            name: "MountSandbox",
            dependencies: ["CMountSandbox"]),
        .testTarget(
            name: "MountSandboxTests",
            dependencies: ["MountSandbox"]),
    ]
)
