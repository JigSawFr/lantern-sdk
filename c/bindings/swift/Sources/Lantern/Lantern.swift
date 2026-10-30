// A sketch of a Swift binding over the C API: the app's HTTP stack as the
// transport (URLSession, called synchronously from the client's thread),
// errors as Swift errors, a client freed with its object. The rest of the
// API follows the same pattern.
import CLantern
import Foundation

public enum Lantern {
    /// lantern_version(): the C API version the library was built with.
    public static var version: UInt32 { lantern_version() }
    /// The specification's draft the library follows ("0.4").
    public static var specDraft: String { String(cString: lantern_spec_draft()) }

    /// The SHA-256 of `bytes`.
    public static func sha256(_ bytes: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        bytes.withUnsafeBufferPointer { lantern_sha256($0.baseAddress, $0.count, &out) }
        return out
    }

    /// The short fingerprint of a SHA-256 ("3F9A 1C07 B2E4 55D0"), shown next to a pairing code.
    public static func shortForm(_ sha256: [UInt8]) -> String {
        precondition(sha256.count == 32, "a SHA-256 is 32 bytes")
        var out = [CChar](repeating: 0, count: 20)
        sha256.withUnsafeBufferPointer { lantern_short_form($0.baseAddress, &out) }
        return String(cString: out)
    }
}

/// A lantern_error: its status (LANTERN_ERROR_*), and § 12's problem+json when the server sent one.
public struct LanternError: Error, CustomStringConvertible {
    public let status: Int32
    public let httpStatus: Int
    public let code: String
    public let detail: String

    init(_ error: lantern_error) {
        var copy = error
        status = error.status
        httpStatus = Int(error.http_status)
        code = withUnsafeBytes(of: &copy.code_text) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) }
        detail = withUnsafeBytes(of: &copy.detail) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) }
    }

    public var description: String { "\(String(cString: lantern_status_name(status))): \(detail)" }
}

func newError() -> lantern_error {
    var error = lantern_error()
    error.struct_size = MemoryLayout<lantern_error>.size
    return error
}

func check(_ status: lantern_status, _ error: lantern_error) throws {
    if status < 0 {
        throw LanternError(error)
    }
}

func string(_ text: lantern_str) -> String {
    // Every lantern_str is NUL-terminated as well
    String(cString: text.data)
}

/// What the server answered.
public struct HTTPResponse {
    public var status: Int
    public var headers: [(String, String)]
    public var body: Data

    public init(status: Int, headers: [(String, String)], body: Data) {
        self.status = status
        self.headers = headers
        self.body = body
    }
}

/// The app's HTTP stack, called on the client's thread, which waits for it.
/// It does TLS (and pins the server's key, SPEC.md 5.3), follows no
/// redirect, and adds no header but Host and the body's framing.
public protocol Transport: AnyObject {
    func send(method: String, url: String, headers: [(String, String)], body: Data) throws -> HTTPResponse
}

/// The C callbacks' `user`: the Swift transport.
final class TransportBox {
    let transport: Transport

    init(_ transport: Transport) {
        self.transport = transport
    }

    func send(_ request: UnsafePointer<lantern_request>, _ response: OpaquePointer,
              _ failure: UnsafeMutablePointer<lantern_error>?) -> lantern_status {
        let r = request.pointee
        var headers: [(String, String)] = []
        for i in 0..<r.header_count {
            headers.append((string(r.headers[i].name), string(r.headers[i].value)))
        }
        let body = r.body_size == 0 ? Data() : Data(bytes: r.body, count: r.body_size)
        let answer: HTTPResponse
        do {
            answer = try transport.send(method: string(r.method_name), url: string(r.url), headers: headers, body: body)
        } catch {
            lantern_error_set(failure, lantern_status(LANTERN_ERROR_TRANSPORT), "\(error)")
            return lantern_status(LANTERN_ERROR_TRANSPORT)
        }
        if !lantern_response_status(response, UInt16(clamping: answer.status)) {
            return lantern_status(LANTERN_OK)
        }
        for (name, value) in answer.headers {
            let goOn = name.withCString { n in
                value.withCString { v in lantern_response_header(response, n, strlen(n), v, strlen(v)) }
            }
            if !goOn {
                return lantern_status(LANTERN_OK)
            }
        }
        _ = answer.body.withUnsafeBytes { raw in
            lantern_response_body(response, raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
        }
        return lantern_status(LANTERN_OK)
    }
}

/// What the handshake says of the server.
public struct Server {
    public let uid: String
    public let name: String
    public let base: String
}

/// A lantern_client: one thread at a time.
public final class Client {
    private let box: TransportBox
    private var transport: OpaquePointer?
    private var client: OpaquePointer?

    public init(origin: String, userAgent: String, platform: String? = nil, transport: Transport) throws {
        box = TransportBox(transport)
        var callbacks = lantern_transport_callbacks()
        callbacks.struct_size = MemoryLayout<lantern_transport_callbacks>.size
        callbacks.user = Unmanaged.passUnretained(box).toOpaque()
        callbacks.send = { user, request, response, error in
            let box = Unmanaged<TransportBox>.fromOpaque(user!).takeUnretainedValue()
            return box.send(request!, response!, error)
        }
        var error = newError()
        try check(lantern_transport_create(&callbacks, nil, &self.transport, &error), error)
        var config = lantern_client_config()
        config.struct_size = MemoryLayout<lantern_client_config>.size
        config.transport = self.transport
        // The client copies the strings
        let status: lantern_status = origin.withCString { o in
            userAgent.withCString { u in
                (platform ?? "").withCString { p in
                    config.origin = o
                    config.user_agent = u
                    config.platform = platform == nil ? nil : p
                    return lantern_client_create(&config, &self.client, &error)
                }
            }
        }
        if status < 0 {
            // Every stored property is set, so deinit runs after this throw:
            // it frees the transport (and a null client), once
            throw LanternError(error)
        }
    }

    deinit {
        lantern_client_free(client)
        lantern_transport_free(transport)
    }

    /// GET /.well-known/lantern; nil for a handshake of a newer schema (SPEC.md 3.2).
    public func handshake() throws -> Server? {
        var error = newError()
        var shake: OpaquePointer?
        let status = lantern_client_handshake(client, &shake, &error)
        if status == lantern_status(LANTERN_ABSENT) {
            return nil
        }
        try check(status, error)
        defer { lantern_handshake_free(shake) }
        return Server(uid: string(lantern_handshake_get_uid(shake)), name: string(lantern_handshake_get_name(shake)),
                      base: string(lantern_handshake_get_base(shake)))
    }

    /// The schema the server writes for a family, 0 when it does not offer it.
    public func offers(_ family: lantern_family) -> UInt64 {
        lantern_client_offers(client, family)
    }
}
