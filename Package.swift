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
        .package(url: "https://github.com/nixberg/GStrobe", .branch("master")),
        .package(url: "https://github.com/nixberg/Ristretto255", .branch("master")),
    ],
    targets: [
        .target(
            name: "GDisco",
            dependencies: ["GStrobe", "Ristretto255"]),
        .testTarget(
            name: "GDiscoTests",
            dependencies: ["GDisco"]),
    ]
)
