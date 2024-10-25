// swift-tools-version: 5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "tkey-mpc-swift",
    platforms: [
        .iOS(.v14), .macOS(.v11)
    ],
    products: [
        .library(
            name: "tkey",
            targets: ["tkey"]),
    ],
    dependencies: [
        .package(name: "TorusUtils", url: "https://github.com/torusresearch/torus-utils-swift", from: "10.0.0"),
        // dev dependencies only
        .package(name:"jwt-kit", url: "https://github.com/vapor/jwt-kit.git", from: "4.0.0"),
    ],
    targets: [
        .binaryTarget(name: "libtkey",
                      path: "Sources/libtkey/libtkey.xcframework"
        ),
        .target(name: "lib",
               dependencies: ["libtkey"],
                path: "Sources/libtkey"
        ),
        .target(
            name: "tkey",
            dependencies: ["lib", "TorusUtils"],
            path: "Sources/ThresholdKey"
        ),
        .testTarget(
            name: "tkey-pkgTests",
            dependencies: ["tkey", .product(name: "JWTKit", package: "jwt-kit")],
            path: "Tests/tkeypkgTests"
        ),
    ]
)
