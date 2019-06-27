// swift-tools-version:5.0

import PackageDescription

let package = Package(
    name: "GDisco",
    products: [
        .library(
            name: "GDisco",
            targets: ["GDisco"]),
    ],
    dependencies: [
        .package(path: "../GStrobe"),
        .package(url: "https://github.com/nixberg/monocypher-swift", from: "0.0.2"),
    ],
    targets: [
        .target(
            name: "GDisco",
            dependencies: ["GStrobe", "Monocypher"]),
        .testTarget(
            name: "GDiscoTests",
            dependencies: ["GDisco"]),
    ]
)
