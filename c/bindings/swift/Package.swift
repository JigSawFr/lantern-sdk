// swift-tools-version:5.9
// A sketch of Lantern for Swift (iOS, macOS), over the C API: an example,
// not a package to depend on. Build the C library first and point SwiftPM
// at it (c/README.md):
//   cmake -S c -B build/c -DCMAKE_BUILD_TYPE=Release -DLANTERN_C_BUILD_TESTS=OFF
//   cmake --build build/c && cmake --install build/c --prefix "$PREFIX"
//   swift build --package-path c/bindings/swift -Xcc -I"$PREFIX/include" -Xlinker -L"$PREFIX/lib"
import PackageDescription

let package = Package(
    name: "Lantern",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "Lantern", targets: ["Lantern"]),
    ],
    targets: [
        // lantern.h, through a module map; links liblantern_c
        .systemLibrary(name: "CLantern", path: "Sources/CLantern"),
        .target(name: "Lantern", dependencies: ["CLantern"]),
        .testTarget(name: "LanternTests", dependencies: ["Lantern", "CLantern"]),
    ]
)
