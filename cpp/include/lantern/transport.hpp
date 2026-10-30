// The transport: the library speaks HTTP through it, and has no networking
// of its own. The app gives one: adapters/curl (libcurl and the platform's
// TLS) and adapters/mbedtls (mbedTLS, for the consoles) are two, optional
// targets; adapters/posix, plain HTTP on loopback only, serves the tests.
//
// A transport sends one request and hands the answer to a ResponseHandler
// as it comes: its status, each header, then the body in chunks. It does
// TLS, and checks a server's key through a ServerTrust (tls.hpp) when the
// app gives one (SPEC.md § 5.3); it
// follows no redirect, and adds no header of its own but Host and those of
// the body's framing (Content-Length).
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/error.hpp>
#include <lantern/sha256.hpp>

namespace lantern
{

enum class Method : std::uint8_t
{
    get,
    head,
    post,
    put,
    patch,
    delete_, // NOLINT(readability-identifier-naming): `delete` is a keyword
};

[[nodiscard]] std::string_view method_name(Method method) noexcept;

struct Header
{
    std::string_view name;
    std::string_view value;
};

struct Request
{
    Method method = Method::get;
    // Absolute: scheme, host, port, path and query.
    std::string_view url;
    std::span<const Header> headers;
    std::span<const std::byte> body;
};

class ResponseHandler
{
  public:
    ResponseHandler()                                  = default;
    ResponseHandler(const ResponseHandler&)            = default;
    ResponseHandler(ResponseHandler&&)                 = default;
    ResponseHandler& operator=(const ResponseHandler&) = default;
    ResponseHandler& operator=(ResponseHandler&&)      = default;
    virtual ~ResponseHandler()                         = default;

    // Each returns false to stop the transfer: the transport then stops
    // reading and returns (its error, if it gives one, is not looked at).
    [[nodiscard]] virtual bool on_status(std::uint16_t status) = 0;
    // Once per header line, names as the server wrote them (compare them
    // ignoring case); a header repeated comes as many times.
    [[nodiscard]] virtual bool on_header(std::string_view name, std::string_view value) = 0;
    // The body, decoded from its transfer coding (chunked), in order.
    [[nodiscard]] virtual bool on_body(std::span<const std::byte> chunk) = 0;
};

class Transport
{
  public:
    Transport()                            = default;
    Transport(const Transport&)            = default;
    Transport(Transport&&)                 = default;
    Transport& operator=(const Transport&) = default;
    Transport& operator=(Transport&&)      = default;
    virtual ~Transport()                   = default;

    // Sends the request and delivers the answer; an error of
    // Category::transport when it could not, or when the answer was cut
    // (what the handler got so far stays valid: a download resumes from it).
    [[nodiscard]] virtual Result<void> send(const Request& request, ResponseHandler& handler) = 0;
};

// Where a request signer adds its headers.
class HeaderSink
{
  public:
    HeaderSink()                             = default;
    HeaderSink(const HeaderSink&)            = default;
    HeaderSink(HeaderSink&&)                 = default;
    HeaderSink& operator=(const HeaderSink&) = default;
    HeaderSink& operator=(HeaderSink&&)      = default;
    virtual ~HeaderSink()                    = default;

    [[nodiscard]] virtual Result<void> add(std::string_view name, std::string_view value) = 0;
};

// What a request signer sees of a request, before it is sent.
struct SigningInput
{
    std::string_view method; // "GET"
    std::string_view target; // the whole URL
    std::string_view authority; // host[:port], as in the URL
    std::string_view path; // path and query
    std::span<const Header> headers;
    // The SHA-256 of the body, when there is one.
    std::optional<Digest> content_digest;
    // A poll of a pairing made with a key (SPEC.md § 5.4): signed although
    // it carries no Authorization.
    bool keyed_poll = false;
};

// The hook of device-bound tokens (SPEC.md § 5.4, RFC 9421 HTTP message
// signatures): it sees each request's method, target, headers and body
// digest, and adds its own headers (Signature-Input, Signature,
// Content-Digest). DeviceSigner (http_signature.hpp) is the client's; the
// client calls it last, after every other header is set, and only for a
// request to the server's origin (§ 2).
class RequestSigner
{
  public:
    RequestSigner()                                = default;
    RequestSigner(const RequestSigner&)            = default;
    RequestSigner(RequestSigner&&)                 = default;
    RequestSigner& operator=(const RequestSigner&) = default;
    RequestSigner& operator=(RequestSigner&&)      = default;
    virtual ~RequestSigner()                       = default;

    [[nodiscard]] virtual Result<void> sign(const SigningInput& request, HeaderSink& headers) = 0;
};

} // namespace lantern
