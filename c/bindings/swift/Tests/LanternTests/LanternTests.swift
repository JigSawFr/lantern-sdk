// The Swift sketch over the C library: its version, a fingerprint, and a
// handshake through a transport of Swift (the specification's example
// server, "Living room shelf").
import Foundation
import XCTest

@testable import Lantern

final class ExampleServer: Transport {
    var requests: [String] = []

    func send(method: String, url: String, headers: [(String, String)], body: Data) throws -> HTTPResponse {
        requests.append("\(method) \(url)")
        // spec/examples/v1/handshake.json
        let handshake = #"{"schema":1,"uid":"6f1c2a8e-4b7d-4e2a-9c31-8d5e2f0a7b14","name":"Living room shelf","software":{"name":"ExampleShelf","version":"2.7.0"},"base":"/api/lantern","versions":[1],"platforms":["switch","android"],"motd":"New this week: two co-op games.","account":{"name":"lea","state":"active","scopes":["library","saves"],"bound":true,"rating_cap":{"age":12}},"features":{"library":1,"titles":1,"changes":1,"sections":1,"homebrew":1,"saves":1,"cheats":1,"requests":0,"pairing":1,"signatures":1,"admin":0},"language":"en","auth":{"bearer_only":true,"skew":300},"limits":{"page_size":500,"save_body":8388608,"save_size":1073741824,"saves_kept_per_title":10}}"#
        return HTTPResponse(status: 200, headers: [("Content-Type", "application/json")], body: Data(handshake.utf8))
    }
}

final class LanternTests: XCTestCase {
    func testVersion() {
        XCTAssertGreaterThanOrEqual(Lantern.version, 1)
        XCTAssertEqual(Lantern.specDraft, "0.4")
    }

    func testShortForm() {
        XCTAssertEqual(Lantern.shortForm(Lantern.sha256(Array("abc".utf8))), "BA78 16BF 8F01 CFEA")
    }

    func testHandshake() throws {
        let server = ExampleServer()
        let client = try Client(origin: "https://shelf.example.org", userAgent: "LanternSwift/0.4",
                                platform: "switch", transport: server)
        let shake = try XCTUnwrap(client.handshake())
        XCTAssertEqual(shake.name, "Living room shelf")
        XCTAssertEqual(shake.base, "/api/lantern")
        XCTAssertEqual(client.offers(lantern_family(LANTERN_FAMILY_LIBRARY)), 1)
        XCTAssertEqual(server.requests, ["GET https://shelf.example.org/.well-known/lantern"])
    }

    func testErrors() {
        XCTAssertThrowsError(try Client(origin: "http://shelf.example.org", userAgent: "LanternSwift/0.4",
                                        transport: ExampleServer())) { error in
            XCTAssertEqual((error as? LanternError)?.status, lantern_status(LANTERN_ERROR_USAGE))
        }
    }
}
