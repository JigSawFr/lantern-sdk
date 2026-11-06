// The server core (SPEC.md § 17, Lantern Core): what answers a request of
// the protocol's routes, with no HTTP framework and no socket of its own.
// An adapter (adapters/posix/server_posix.hpp for tests and demos, an app's
// own HTTP server) hands `Server::handle()` a ServerRequest, as the framework
// parsed it, and sends the ServerResponse it gets back.
//
// What it serves so far is Lantern Core, read-only, and the families that
// give a device its token:
//
// - the handshake, at /.well-known/lantern and at <base>/v1 (§ 4.2), which
//   lists only the families the server serves (`library`, and `pairing` and
//   `signatures` when it has accounts) and says who calls;
// - the platforms (§ 4.3), the apps' listing with its filters, sorts, pages
//   and cursors (§ 6.2) and what a device is missing (§ 6.3);
// - the files, with `Range` and `Repr-Digest` (§ 6.6);
// - with an AccountStore (accounts.hpp): Bearer tokens kept as hashes and
//   checked with their scopes (§ 5.1), pairing (§ 5.2: the code, the poll
//   address, the limits per address), the approval page that shows the
//   server's key (§ 5.3), and device-bound tokens, whose requests carry an
//   HTTP message signature checked as § 5.4 says, with the replay window of
//   the injected Clock;
// - the validators and caching headers of § 14, errors as problem+json
//   (§ 12), the `schema` rule and the bounds of § 13 on the documents it
//   reads (§ 3.2), and browsers (§ 2.5): CORS for the origins the app
//   allows, preflights, Strict-Transport-Security over HTTPS (§ 2).
//
// Approving a pairing is the app's: its own page, once the user is signed in
// there, calls Server::approve_pairing(). Invitations, administration,
// titles, homebrew, cheat sets, saves, requests, events, peers, sync and
// discovery are not here yet: a request for one is a route the server does
// not have (404), and the handshake says so (`features`). JSON is sent as it
// is written, never compressed (§ 2.1 asks a server to, as a SHOULD).
//
// A Server keeps nothing that a request changes but what the AccountStore
// keeps, the replay window and the limits per address, which it guards
// itself: handle() may be called from several threads when the Library's and
// the AccountStore's methods can be.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

#include <lantern/accounts.hpp>
#include <lantern/device_key.hpp>
#include <lantern/error.hpp>
#include <lantern/http_signature.hpp>
#include <lantern/memory.hpp>
#include <lantern/sha256.hpp>
#include <lantern/transport.hpp>
#include <lantern/types.hpp>

namespace lantern
{

// A request, as the adapter hands it over. It only looks at what the
// adapter owns: every view stays valid while handle() runs.
struct QueryParam
{
    std::string_view name; // percent-decoded, "+" a space
    std::string_view value;
};

struct ServerRequest
{
    std::string_view method; // upper case: "GET"
    std::string_view path; // percent-decoded, without the query
    // The query's parameters in the order they were sent, a name given
    // twice twice (§ 2.4: a 400); empty values are read as absent.
    std::span<const QueryParam> query;
    std::span<const Header> headers;
    std::span<const std::byte> body; // read only for the routes that take one
    std::string_view scheme; // "https" or "http", the one the request came by; empty: ServerOptions::scheme
    std::string_view target; // the request target as sent, path and query
    std::string_view remote; // the caller's address, as text

    // The first header of that name (compared ignoring case).
    [[nodiscard]] std::optional<std::string_view> header(std::string_view name) const noexcept;
    // The first parameter of that name with a value.
    [[nodiscard]] std::optional<std::string_view> param(std::string_view name) const noexcept;
};

// A request target split: the path, then the query's parameters, each
// percent-decoded (the query's "+" is a space). Refused (Category::invalid_response)
// for a target that is not a path, or a path or a parameter with a bad escape
// or a control character: an adapter answers 400.
struct ParsedTarget
{
    using allocator_type = Allocator;

    String path;
    Vector<std::pair<String, String>> query;

    ParsedTarget()
        : ParsedTarget(allocator_type {})
    {
    }
    explicit ParsedTarget(const allocator_type& allocator)
        : path(allocator)
        , query(allocator)
    {
    }
};

[[nodiscard]] Result<ParsedTarget> parse_target(std::string_view target, const Allocator& allocator = {});

// A response's headers, in the order they were set, names as written.
class ResponseHeaders
{
  public:
    using allocator_type = Allocator;

    ResponseHeaders()
        : ResponseHeaders(allocator_type {})
    {
    }
    explicit ResponseHeaders(const allocator_type& allocator)
        : entries_(allocator)
    {
    }

    // Sets the header, replacing those of that name (ignoring case).
    void set(std::string_view name, std::string_view value);
    // Adds one, keeping those of that name.
    void add(std::string_view name, std::string_view value);
    void erase(std::string_view name);
    [[nodiscard]] std::optional<std::string_view> get(std::string_view name) const noexcept;
    [[nodiscard]] const Vector<std::pair<String, String>>& entries() const noexcept { return entries_; }

  private:
    Vector<std::pair<String, String>> entries_;
};

// Reads a file's bytes where they are (a drive, a card, memory), so that a
// large file is never held whole.
class FileReader
{
  public:
    FileReader()                             = default;
    FileReader(const FileReader&)            = default;
    FileReader(FileReader&&)                 = default;
    FileReader& operator=(const FileReader&) = default;
    FileReader& operator=(FileReader&&)      = default;
    virtual ~FileReader()                    = default;

    // Fills `buffer` from `offset` on, as far as the file goes: the bytes
    // read, fewer than asked only at the file's end (0 beyond it).
    [[nodiscard]] virtual Result<std::size_t> read(std::uint64_t offset, std::span<std::byte> buffer) = 0;
};

// A file in memory, for the files that are small and for the tests.
class MemoryFileReader final : public FileReader
{
  public:
    MemoryFileReader(std::span<const std::byte> bytes, const Allocator& allocator)
        : bytes_(bytes.begin(), bytes.end(), allocator)
    {
    }

    [[nodiscard]] Result<std::size_t> read(std::uint64_t offset, std::span<std::byte> buffer) override;
    [[nodiscard]] std::span<const std::byte> bytes() const noexcept { return bytes_; }

  private:
    Vector<std::byte> bytes_;
};

// A file the library serves: its size and SHA-256 are known beforehand (a
// server hashes a file before it lists it, § 6.1).
struct LibraryFile
{
    using allocator_type = Allocator;

    std::uint64_t size = 0;
    Digest sha256 {};
    String content_type;
    std::shared_ptr<FileReader> reader;

    LibraryFile()
        : LibraryFile(allocator_type {})
    {
    }
    explicit LibraryFile(const allocator_type& allocator)
        : content_type("application/octet-stream", allocator)
    {
    }
};

// What the listing of apps may be narrowed by (§ 6.2); empty: not narrowed.
// The server applies every one itself, so a library may ignore them.
struct AppsFilter
{
    std::string_view platform;
    std::string_view type;
    std::string_view format;
    std::string_view title_id;
    std::string_view q; // a part of the name, ignoring case
};

// What a server serves. Every method is called per request: answer with
// what is there now (a database query, a folder scanned and kept...).
class Library
{
  public:
    Library()                          = default;
    Library(const Library&)            = default;
    Library(Library&&)                 = default;
    Library& operator=(const Library&) = default;
    Library& operator=(Library&&)      = default;
    virtual ~Library()                 = default;

    // The platforms the library has something for (§ 4.3), served ones
    // only (not `web`), each once.
    [[nodiscard]] virtual Result<Vector<String>> platforms(const Allocator& allocator) = 0;
    // The apps, every variant of every game: at least those `filter` keeps.
    // Each app's `file` is a path of the server, <base>/v1/files/<name>.
    [[nodiscard]] virtual Result<Vector<App>> apps(const AppsFilter& filter, const Allocator& allocator) = 0;
    // The file of <base>/v1/files/<name>: an app's package. Nothing for a
    // name it does not have.
    [[nodiscard]] virtual Result<std::optional<LibraryFile>> file(
        std::string_view name, const Allocator& allocator)
        = 0;
};

// An app a MemoryLibrary is given: its identity (§ 6.1). The library fills
// `id`, `size`, `sha256` and `file` from the package's bytes.
struct AppDraft
{
    std::string_view platform;
    std::string_view title_id;
    std::string_view app_id;
    std::string_view type;
    std::uint64_t version_code = 0;
    std::string_view version_name;
    std::string_view name;
    std::string_view format;
    std::string_view added; // a UTC time: 2026-10-10T12:00:00Z
    std::span<const std::string_view> requires_; // the tokens a device must provide, 8 at most
    std::span<const AppInclude> includes; // the versions it contains, 16 at most
    std::span<const std::string_view> mirrors; // other addresses of its bytes, 8 at most (§ 19.2)
};

// A Library held in memory: a reference to read, the base of tests and
// demos. It refuses an app that breaks § 6.1 or its platform's profile
// (Annex A). Not thread-safe while apps are being added.
class MemoryLibrary final : public Library
{
  public:
    // `base`: the server's, "/api/lantern": the `file` of each app is
    // <base>/v1/files/<name>.
    explicit MemoryLibrary(std::string_view base = "/api/lantern", const Allocator& allocator = {});

    // Serves the package `content` as an app. Its id comes from what
    // identifies it (platform, app_id, version_code, format, requires), so
    // that the same call gives the same app.
    [[nodiscard]] Result<App> add_app(const AppDraft& draft, std::span<const std::byte> content);
    [[nodiscard]] std::size_t size() const noexcept { return apps_.size(); }

    [[nodiscard]] Result<Vector<String>> platforms(const Allocator& allocator) override;
    [[nodiscard]] Result<Vector<App>> apps(const AppsFilter& filter, const Allocator& allocator) override;
    [[nodiscard]] Result<std::optional<LibraryFile>> file(
        std::string_view name, const Allocator& allocator) override;

  private:
    struct Stored
    {
        String name;
        Digest sha256 {};
        std::shared_ptr<MemoryFileReader> reader;
    };

    Allocator allocator_;
    String base_;
    Vector<App> apps_;
    Vector<Stored> files_;
};

struct ServerFile
{
    std::shared_ptr<FileReader> reader;
    std::uint64_t offset = 0;
    std::uint64_t length = 0;
};

// The answer, for the adapter to send. `Content-Length` is always among
// the headers, HEAD's and 304's included (whose body is empty); `Date` and
// the connection's own headers are the adapter's. A file is read by the
// adapter from `file->reader`, `file->length` bytes from `file->offset`,
// never held whole.
struct ServerResponse
{
    using allocator_type = Allocator;

    std::uint16_t status = 200;
    ResponseHeaders headers;
    String body;
    std::optional<ServerFile> file;

    ServerResponse()
        : ServerResponse(allocator_type {})
    {
    }
    explicit ServerResponse(const allocator_type& allocator)
        : headers(allocator)
        , body(allocator)
    {
    }
};

// "OK", "Not Found"...: the reason phrase of a status.
[[nodiscard]] std::string_view status_text(std::uint16_t status) noexcept;

// An error as problem+json (§ 12) with no request to look at: for an
// adapter that cannot read the request (a malformed head, a body beyond its
// limit). `code` is § 12's: the status gives the others.
[[nodiscard]] ServerResponse problem_response(
    std::uint16_t status, Code code, std::string_view detail, const Allocator& allocator = {});

struct ServerOptions
{
    // The server's UUID, which never changes: lower case, version 4 or 7 (§ 4.2).
    std::string_view uid;
    // What clients show.
    std::string_view name;
    // The routes' prefix: a path, "/api/lantern".
    std::string_view base = "/api/lantern";
    // The scheme a request came by when its own says none.
    std::string_view scheme = "https";
    // The origins whose pages may read this server (§ 2.5): "https://app.example.org",
    // or "*" for every one; none by default. An allowed origin gets
    // Access-Control-Allow-Origin on every answer, errors included, and its
    // preflights are answered without a token. No cookie is ever read or set,
    // and Access-Control-Allow-Credentials is never sent.
    std::span<const std::string_view> cors_origins;
    // Strict-Transport-Security (§ 2, L-2-11) goes on every answer that came
    // over HTTPS; `hsts` sends it too when TLS ends before the server (a
    // proxy). `hsts_max_age`: 15552000 seconds (six months) or more.
    bool hsts                  = false;
    std::uint32_t hsts_max_age = 31536000;
    // The largest page, 1 to 1000 (§ 13); `limits.page_size` says it.
    std::uint32_t page_limit        = 500;
    std::uint32_t default_page_size = 100;
    // How long a cursor lives, in seconds; then 410.
    std::uint32_t cursor_lifetime = 3600;
    // The handshake's `software` and `motd` (whose language is English).
    std::string_view software_name;
    std::string_view software_version;
    std::string_view motd;

    // Tokens, pairing and signatures (§ 5). The store of the accounts, the
    // devices and the pairings; without it the server is anonymous, takes
    // no token and offers neither `pairing` nor `signatures`. It must
    // outlive the server.
    AccountStore* accounts = nullptr;
    // A server that is private answers a call without a token with 401 on
    // the routes that need one; the handshake and pairing stay open to every
    // caller (§ 4.2). Public (the default): an anonymous caller reads the
    // library. Needs `accounts`.
    bool require_auth = false;
    // Issue and take only tokens bound to a device key (§ 5.4): a pairing
    // without `key` is a 400 `key_required`, a token without one a 401
    // `signature_required`. `auth.bearer_only` in the handshake says it.
    bool bound_only = false;
    // How many seconds a signature's `created` may differ from the clock
    // (`auth.skew`), 60 to 900. A nonce is kept twice as long.
    std::uint32_t skew = default_skew;
    // The most nonces kept at once; past it, a signed request is a 429 until
    // the oldest expire. A nonce is never forgotten early (L-5.4-9).
    std::uint32_t nonce_limit = 65536;
    // The approval page (§ 5.2, § 5.3): a path of this server, which then
    // shows the code and the short fingerprint of `spki` and approves
    // nothing, or an absolute URL of the app's own page.
    std::string_view verify = "/pair";
    // The SHA-256 of the server's TLS key, its DER SubjectPublicKeyInfo
    // (§ 5.3): the approval page shows its short form. None when the server
    // is plain HTTP on loopback, or a CA vouches for it.
    std::optional<Digest> spki;
    // Seconds a new token lives; 0: until it is revoked.
    std::uint32_t token_lifetime = 0;
    // A pairing's code: seconds between two polls (1 to 60), seconds it
    // lives (1 to 600).
    std::uint32_t pairing_interval = 5;
    std::uint32_t pairing_expires  = 600;
    // Pairing requests per address in a window of seconds (L-5.2-8), then 429.
    std::uint32_t pairing_requests = 30;
    std::uint32_t pairing_window   = 60;
    // Wrong invitation codes per address in a window of seconds, then 429.
    std::uint32_t invitation_attempts = 10;
    std::uint32_t invitation_window   = 600;
};

namespace detail
{
struct ServerState;
}

class Server
{
  public:
    // Checks the options (the uid, the base, the origins, the limits); the
    // cursors are sealed with a secret drawn now from `random`, which also
    // draws the tokens, the codes and the nonces' keys of a server with
    // accounts. `library`, `random` and `clock` must outlive the server.
    [[nodiscard]] static Result<Server> create(Library& library, const ServerOptions& options,
        RandomSource& random, Clock& clock, const Allocator& allocator = {});

    // The answer to `request`: never an error, a failure of the library is
    // a 500 `internal` (§ 12).
    [[nodiscard]] ServerResponse handle(const ServerRequest& request) const;

    [[nodiscard]] std::string_view base() const noexcept;

    // The app's side of a pairing (§ 5.2): its approval page, once the user
    // is signed in there, looks the code up as the user typed it (case,
    // spaces and dashes ignored), shows the device, the scopes it asks for
    // and this server's fingerprint, and approves or refuses. Nothing waits
    // under that code: nothing. Needs `accounts`.
    [[nodiscard]] Result<std::optional<PendingPairing>> waiting_pairing(
        std::string_view code, const Allocator& allocator = {}) const;
    // Approves the pairing for the account `user`: the scopes it asked for
    // (those of `scopes` among them, or all when `scopes` is empty) that the
    // account holds. The token waits for the device's next poll. Gives the
    // scopes granted; nothing when no pairing waits under that code;
    // Category::usage for an account that does not exist.
    [[nodiscard]] Result<std::optional<Vector<String>>> approve_pairing(std::string_view code,
        std::string_view user, std::span<const std::string_view> scopes = {},
        const Allocator& allocator = {}) const;
    // Refuses it: the device's next poll is a 410. False when no pairing waits under that code.
    [[nodiscard]] Result<bool> refuse_pairing(std::string_view code) const;

  private:
    explicit Server(std::shared_ptr<const detail::ServerState> state) noexcept
        : state_(std::move(state))
    {
    }

    std::shared_ptr<const detail::ServerState> state_;
};

} // namespace lantern
