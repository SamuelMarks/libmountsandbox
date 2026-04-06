// swift-tools-version: 5.7

import PackageDescription

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
                .unsafeFlags(["-L../../build", "-lmountsandbox", "-Xlinker", "-rpath", "-Xlinker", "../../build"])
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
