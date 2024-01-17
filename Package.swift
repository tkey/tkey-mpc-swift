// swift-tools-version: 5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "tkey-mpc-swift",
    platforms: [
        .iOS(.v13), .macOS(.v10_15)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "tkey-mpc-swift",
            targets: ["tkey-mpc-swift"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        .package(name: "TorusUtils", url: "https://github.com/torusresearch/torus-utils-swift" , .branch("feat/wrap-secp256")),
        // dev dependencies only
        .package(name:"CryptoSwift", url: "https://github.com/krzyzanowskim/CryptoSwift.git",from: "1.5.1"),
        .package(name:"jwt-kit", url: "https://github.com/vapor/jwt-kit.git", from: "4.0.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .binaryTarget(name: "libtkey",
                      path: "Sources/libtkey/libtkey.xcframework"
        ),
        .target(name: "lib",
               dependencies: ["libtkey"],
                path: "Sources/libtkey"
        ),
        .target(
            name: "tkey-mpc-swift",
            dependencies: ["lib", "TorusUtils"],
            path: "Sources/ThresholdKey"
        ),
        .testTarget(
            name: "tkey-pkgTests",
            dependencies: ["tkey-mpc-swift", "CryptoSwift", .product(name: "JWTKit", package: "jwt-kit")],
            path: "Tests/tkeypkgTests"
        ),
    ]
)
