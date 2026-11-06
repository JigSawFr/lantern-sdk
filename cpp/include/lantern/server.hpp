// The server core (SPEC.md § 17, Lantern Core): what answers a request of
// the protocol's routes, with no HTTP framework and no socket of its own.
// An adapter (adapters/posix/server_posix.hpp for tests and demos, an app's
// own HTTP server) hands `Server::handle()` a ServerRequest, as the framework
// parsed it, and sends the ServerResponse it gets back.
//
// What it serves so far is Lantern Core, read-only, the families that give a
// device its token, the save backups, the requests and the administration:
//
// - the handshake, at /.well-known/lantern and at <base>/v1 (§ 4.2), which
//   lists only the families the server serves (`library`, those the library
//   offers, and `pairing` and `signatures` when it has accounts) and says who
//   calls;
// - the platforms (§ 4.3), the apps' listing with its filters, sorts, pages
//   and cursors (§ 6.2) and what a device is missing (§ 6.3);
// - the files, with `Range` and `Repr-Digest` (§ 6.6);
// - the families a Library offers beside the apps: changes (§ 6.4) with
//   `since` tokens sealed like cursors, sections (§ 6.5), and the titles
//   (§ 7): one, many at once, their changes and their images (`media`);
// - the homebrew (§ 8): the listing with its filters, an entry with its
//   manifests, and the updates of what a device has installed; the packages
//   are files like an app's (§ 6.6);
// - the cheat sets (§ 10): the listing, a set's text, and, for a token with
//   the scope `cheats.write`, writing them when the library takes writes;
// - with an AccountStore (accounts.hpp): Bearer tokens kept as hashes and
//   checked with their scopes (§ 5.1), pairing (§ 5.2: the code, the poll
//   address, the limits per address), the approval page that shows the
//   server's key (§ 5.3), and device-bound tokens, whose requests carry an
//   HTTP message signature checked as § 5.4 says, with the replay window of
//   the injected Clock;
// - with a SaveStore (saves.hpp) and accounts: the save backups of § 9, for
//   the scope `saves`: the listing, a backup's archive and its removal, a
//   save sent in one request, and the resumable upload (open, HEAD for where
//   it stands, PATCH a chunk, DELETE), the whole archive's SHA-256 and every
//   Content-Digest checked, the backups kept per title, the limits in the
//   handshake; and `encrypted_saves` (§ 9.4), a backup encrypted on the
//   device kept as sent, never read. A large body reaches the store piece
//   by piece: an adapter that does not buffer it gives the request a
//   `BodyReader` (see ServerRequest::stream).
// - with a RequestStore (requests.hpp) and accounts: the requests for games of
//   § 11, for the scope `requests`: the account's own, asking (the same open
//   title gives the open request), withdrawing; the admin decides them
//   (below). Server::settle_requests() marks done those whose title has an
//   app now;
// - with an AccountStore that administers (accounts.hpp): the invitations of
//   § 5.5 (a device pairs with one and is approved at once, for the account
//   and the scopes it holds, the number of devices counted, the attempts per
//   address limited), the rating caps of § 5.6 (a capped token does not see
//   the titles, apps, homebrew and cheat sets above its cap, nor their
//   files), and the administration API of § 5.7, for the scope `admin`:
//   accounts, devices, the pairings waiting, the invitations, deleting an
//   account (its save backups and requests included) and deciding requests.
// - the validators and caching headers of § 14, errors as problem+json
//   (§ 12), the `schema` rule and the bounds of § 13 on the documents it
//   reads (§ 3.2), and browsers (§ 2.5): CORS for the origins the app
//   allows, preflights, Strict-Transport-Security over HTTPS (§ 2).
//
// - with ServerOptions::events (§ 18): the stream at <base>/v1/events and the
//   long poll `changes?since=&wait=`, one journal of events in memory whose
//   ids are tokens of `changes` (resuming with Last-Event-ID or ?since=, a
//   410 for an id too old), a heartbeat, the streams a token may hold, and
//   each caller told only of what it may read (its scopes, account,
//   platform and rating cap). The server records `request`, `save` and
//   `pairing` events itself, `library` events when the Library tells it
//   (Library::observe(); MemoryLibrary does, Server::library_changed() is
//   for any other) and `shutdown` on Server::shutdown(). The core has no
//   thread and no timer: a stream is an EventStream the adapter steps with
//   its own clock, a long poll a response with `hold_ms` that the adapter
//   waits out (see ServerResponse).
// - with ServerOptions::grant_seed (§ 19.3), the family `peers` of a server:
//   the grant key's public half in the handshake (`peers.key`,
//   `peers.grant_lifetime`) and the grants at <base>/v1/grants/sha256/<hex>,
//   signed for an app or a homebrew package the caller may read. The peers
//   themselves (§ 19.4) are consoles, not servers: PeerGate (peers.hpp);
// - with a SyncStore (sync_store.hpp) and accounts: the sync of § 20, for the
//   scopes `sync.read` and `sync.write`: the overview with the device's id,
//   the collections `wishes` and `installed` read whole or after a revision
//   (pages, `410` for deletions gone), written item by item by the merge
//   rule with `If-Match`, the generation and the limit of items checked, a
//   device writing its own item of `installed` only, and erasing a
//   collection or all of them. The event `sync` tells the account's devices.
//
// Approving a pairing is the app's, or an admin's: the app's own page, once
// the user is signed in there, calls Server::approve_pairing(); an admin app
// uses the administration API. Discovery, mirrors and the other families are not here yet: a
// request for one is a route the server does not have (404), and the
// handshake says so (`features`). JSON is sent as it is written, never
// compressed (§ 2.1 asks a server to, as a SHOULD).
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

class SaveStore;
class RequestStore;
class SyncStore;

// A request, as the adapter hands it over. It only looks at what the
// adapter owns: every view stays valid while handle() runs.
struct QueryParam
{
    std::string_view name; // percent-decoded, "+" a space
    std::string_view value;
};

// A request's body, read from where the adapter keeps it (a socket, a file)
// piece by piece, for the routes that take bodies too large to buffer.
class BodyReader
{
  public:
    BodyReader()                             = default;
    BodyReader(const BodyReader&)            = default;
    BodyReader(BodyReader&&)                 = default;
    BodyReader& operator=(const BodyReader&) = default;
    BodyReader& operator=(BodyReader&&)      = default;
    virtual ~BodyReader()                    = default;

    // Fills `buffer` with the next bytes, as many as are there now: the bytes
    // read, 0 at the body's end. An error (the connection was cut) ends the request.
    [[nodiscard]] virtual Result<std::size_t> read(std::span<std::byte> buffer) = 0;
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
    // A body the adapter did not buffer: `body` is then empty, `stream_length`
    // bytes (Content-Length) are to be read from `stream`, which the server
    // reads only on the routes that take a body of that size (the save
    // uploads of § 9.2 and § 9.3) and answers 413 on every other; nothing
    // read, the adapter closes the connection after the answer. Null: the
    // body is `body`.
    BodyReader* stream          = nullptr;
    std::uint64_t stream_length = 0;
    std::string_view scheme; // "https" or "http", the one the request came by; empty: ServerOptions::scheme
    std::string_view target; // the request target as sent, path and query
    std::string_view remote; // the caller's address, as text
    // For a request the server held (ServerResponse::hold_ms), which the
    // adapter calls handle() with again, unchanged: `resumed` is true (the
    // signature of the first call was checked, and its nonce taken once) and
    // `waited_ms` the milliseconds it has been held so far. Never set from
    // what a client sent.
    bool resumed            = false;
    std::uint64_t waited_ms = 0;

    // The first header of that name (compared ignoring case).
    [[nodiscard]] std::optional<std::string_view> header(std::string_view name) const noexcept;
    // The first parameter of that name with a value.
    [[nodiscard]] std::optional<std::string_view> param(std::string_view name) const noexcept;
    // The body's size in bytes, buffered or not.
    [[nodiscard]] std::uint64_t body_size() const noexcept
    {
        return stream != nullptr ? stream_length : static_cast<std::uint64_t>(body.size());
    }
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

// Where a journal stands (§ 6.4): the epoch changes when the journal starts
// over (a token of another epoch is too old), positions grow with each
// change, and `oldest` is the oldest position it still answers from.
struct JournalPosition
{
    using allocator_type = Allocator;

    String epoch;
    std::uint64_t position = 0;
    std::uint64_t oldest   = 0;

    JournalPosition()
        : JournalPosition(allocator_type {})
    {
    }
    explicit JournalPosition(const allocator_type& allocator)
        : epoch(allocator)
    {
    }
};

// What changed in the apps since a position (§ 6.4): the apps added and
// still there, and the ids of those removed.
struct AppChanges
{
    using allocator_type = Allocator;

    Vector<App> added;
    Vector<String> removed;

    AppChanges()
        : AppChanges(allocator_type {})
    {
    }
    explicit AppChanges(const allocator_type& allocator)
        : added(allocator)
        , removed(allocator)
    {
    }
};

// What changed in the titles since a position (§ 7.3): the titles added or
// changed, those removed, and whether the journal gives only a part of them
// (`more`: the client asks again with the new token).
struct TitleDelta
{
    using allocator_type = Allocator;

    Vector<Title> titles;
    Vector<RemovedTitle> removed;
    bool more = false;

    TitleDelta()
        : TitleDelta(allocator_type {})
    {
    }
    explicit TitleDelta(const allocator_type& allocator)
        : titles(allocator)
        , removed(allocator)
    {
    }
};

// A library's change journal, for <base>/v1/changes and
// <base>/v1/titles/changes (§ 6.4, § 7.3). The server seals its positions
// into the `since` tokens it gives.
class Journal
{
  public:
    Journal()                          = default;
    Journal(const Journal&)            = default;
    Journal(Journal&&)                 = default;
    Journal& operator=(const Journal&) = default;
    Journal& operator=(Journal&&)      = default;
    virtual ~Journal()                 = default;

    [[nodiscard]] virtual Result<JournalPosition> position(const Allocator& allocator) = 0;
    // `platform` empty: every platform.
    [[nodiscard]] virtual Result<AppChanges> app_changes(
        std::uint64_t after, std::string_view platform, const Allocator& allocator)
        = 0;
    // `languages`: the request's Accept-Language, as written (empty: none).
    [[nodiscard]] virtual Result<TitleDelta> title_changes(std::uint64_t after, std::string_view platform,
        std::string_view languages, const Allocator& allocator)
        = 0;
};

// What changed in a library, for the event `library` (§ 18.2): the family
// (`apps`, `titles`, `homebrew` or `cheats`), the platform, and what a rating
// cap reads it by: its title (apps, titles and cheat sets), or its own
// ratings (homebrew). A caller gets the event only for the changes it may see.
struct LibraryChange
{
    std::string_view family;
    std::string_view platform;
    std::string_view title_id; // empty: none
    // The ratings a cap reads when there is no title (homebrew); null: read by the title.
    const Vector<Rating>* ratings = nullptr;
};

// Told by a Library that its content changed. The server registers itself
// when it offers events (ServerOptions::events); it may be called from any
// thread the library changes on, and must not be called back from.
class LibraryObserver
{
  public:
    LibraryObserver()                                  = default;
    LibraryObserver(const LibraryObserver&)            = default;
    LibraryObserver(LibraryObserver&&)                 = default;
    LibraryObserver& operator=(const LibraryObserver&) = default;
    LibraryObserver& operator=(LibraryObserver&&)      = default;
    virtual ~LibraryObserver()                         = default;

    virtual void library_changed(std::span<const LibraryChange> changes) = 0;
};

// What a server serves. Every method is called per request: answer with
// what is there now (a database query, a folder scanned and kept...). The
// families beyond the apps (titles, sections, changes, homebrew, cheats) are
// offered when the library says so: by default it offers none.
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

    // Titles (§ 7), the family `titles`: offered when this is true.
    [[nodiscard]] virtual bool offers_titles() { return false; }
    // Every title, its texts in the best of `languages` it has (the request's
    // Accept-Language as written, or empty). The server narrows them by
    // platform and id itself.
    [[nodiscard]] virtual Result<Vector<Title>> titles(
        std::string_view /*languages*/, const Allocator& allocator)
    {
        return Vector<Title>(allocator);
    }
    // The image of <base>/v1/media/<name> that a title shows: nothing for a
    // name it does not have.
    [[nodiscard]] virtual Result<std::optional<LibraryFile>> media(
        std::string_view /*name*/, const Allocator& /*allocator*/)
    {
        return std::optional<LibraryFile> {};
    }

    // Sections (§ 6.5), the family `sections`: offered when this is true.
    [[nodiscard]] virtual bool offers_sections() { return false; }
    // Every shelf the library curates, its title in the best of `languages`.
    // The server leaves out the apps a caller does not see (another platform)
    // and the shelves left empty.
    [[nodiscard]] virtual Result<Vector<Section>> sections(
        std::string_view /*languages*/, const Allocator& allocator)
    {
        return Vector<Section>(allocator);
    }

    // Homebrew (§ 8), the family `homebrew`: offered when this is true. The
    // packages are files, served by file() like an app's.
    [[nodiscard]] virtual bool offers_homebrew() { return false; }
    // Every entry with the manifests of its packages (the server leaves them
    // out of listings), its texts in the best of `languages`. The server
    // narrows them by platform, kind, genre and name itself, and reads a
    // kind it does not know as `app` (§ 8.1).
    [[nodiscard]] virtual Result<Vector<Homebrew>> homebrew(
        std::string_view /*languages*/, const Allocator& allocator)
    {
        return Vector<Homebrew>(allocator);
    }

    // Cheat sets (§ 10), the family `cheats`: offered when this is true.
    [[nodiscard]] virtual bool offers_cheats() { return false; }
    // Every set, whatever its platform and title.
    [[nodiscard]] virtual Result<Vector<CheatSet>> cheats(const Allocator& allocator)
    {
        return Vector<CheatSet>(allocator);
    }
    // The text of <base>/v1/cheats/<id>: nothing for an id it does not have.
    [[nodiscard]] virtual Result<std::optional<LibraryFile>> cheat_file(
        std::string_view /*id*/, const Allocator& /*allocator*/)
    {
        return std::optional<LibraryFile> {};
    }
    // Whether clients may write sets (POST, PUT and DELETE, with the scope
    // `cheats.write`); a server that does not answers 405 (§ 10).
    [[nodiscard]] virtual bool writes_cheats() { return false; }
    // Keeps `set` (the server has checked it, § 10 and Annex A; `source` is
    // never empty) under a new id, or, when `replacing` is not empty, as the
    // text and note of that set. The set it answers has the id, `size`,
    // `sha256` and `updated` of what is kept.
    [[nodiscard]] virtual Result<CheatSet> write_cheat(
        const CheatWrite& /*set*/, std::string_view /*replacing*/, const Allocator& /*allocator*/)
    {
        return fail(Category::unsupported, "this library takes no cheat set");
    }
    // Forgets the set of that id; false when there is none.
    [[nodiscard]] virtual Result<bool> delete_cheat(std::string_view /*id*/)
    {
        return fail(Category::unsupported, "this library takes no cheat set");
    }

    // The change journal (§ 6.4): the family `changes` is offered when there
    // is one, and /v1/titles/changes answers 410 to any token when there is
    // none. It must outlive the server.
    [[nodiscard]] virtual Journal* journal() { return nullptr; }

    // Who is told of the changes the library makes by itself (§ 18.2); null
    // for none. A library that never changes by itself, or whose app calls
    // Server::library_changed(), ignores it.
    virtual void observe(LibraryObserver* /*observer*/) { }
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
// (Annex A), a title that breaks § 7.1, a homebrew that breaks § 8 and a
// cheat set that breaks § 10. It serves the apps; the titles, the sections,
// the homebrew, the cheat sets and the journal only once it is told to
// (offer_titles(), add_title(), add_section(), add_homebrew(), add_cheat(),
// keep_journal(): call the last before the first change, which is all a
// journal knows). Not thread-safe while anything is being added; the server
// calls its cheat methods one at a time.
class MemoryLibrary final : public Library, public Journal
{
  public:
    // `base`: the server's, "/api/lantern": the `file` of each app is
    // <base>/v1/files/<name>.
    explicit MemoryLibrary(std::string_view base = "/api/lantern", const Allocator& allocator = {});

    // Serves the package `content` as an app. Its id comes from what
    // identifies it (platform, app_id, version_code, format, requires), so
    // that the same call gives the same app.
    [[nodiscard]] Result<App> add_app(const AppDraft& draft, std::span<const std::byte> content);
    // Stops serving the app of that id; false when there is none.
    bool remove_app(std::string_view id);
    [[nodiscard]] std::size_t size() const noexcept { return apps_.size(); }

    // Keeps a change journal of the last `keep` changes (1 to 1,000,000):
    // the family `changes`.
    [[nodiscard]] Result<void> keep_journal(std::size_t keep = 10000);

    // The family `titles`, with no title yet (add_title() offers it too).
    void offer_titles() noexcept { titles_offered_ = true; }
    // Serves the title; one of that platform and id is replaced. It refuses
    // what § 7.1 or Annex A do not allow.
    [[nodiscard]] Result<Title> add_title(const Title& title);
    // False when there is none of that platform and id.
    bool remove_title(std::string_view platform, std::string_view title_id);
    // Serves an image on this server's origin, by its content: `extension` is
    // png, jpg, webp or gif. The Image it gives (url, sha256) goes into a
    // title; the caller adds its width and height.
    [[nodiscard]] Result<Image> add_media(std::span<const std::byte> content, std::string_view extension);

    // A shelf (§ 6.5): its id, its title and its apps' ids in order; one of
    // that id is replaced. Offers the family `sections`.
    [[nodiscard]] Result<Section> add_section(
        std::string_view id, std::string_view title, std::span<const std::string_view> apps);
    // False when there is none of that id.
    bool remove_section(std::string_view id);

    // The family `homebrew`, with no entry yet (add_homebrew() offers it too).
    void offer_homebrew() noexcept { homebrew_offered_ = true; }
    // Serves the entry; one of that platform and id is replaced. `contents`
    // holds the bytes of `entry.package`, then of each of `entry.packages`.
    // Each package has the `size` and `sha256` of its bytes (they are
    // signed, § 8.4) and the `manifest_sha256` of its manifest; the library
    // gives it the `file` it serves it at. It refuses what § 8 or Annex A do
    // not allow: paths, roots, architectures, a signature that does not
    // verify (or by several keys), a port's data, requirements.
    [[nodiscard]] Result<Homebrew> add_homebrew(
        const Homebrew& entry, std::span<const std::span<const std::byte>> contents);
    // False when there is none of that platform and id.
    bool remove_homebrew(std::string_view platform, std::string_view id);

    // The family `cheats`, with no set yet (add_cheat() offers it too).
    void offer_cheats() noexcept { cheats_offered_ = true; }
    // Takes writes from clients with the scope `cheats.write` (§ 10).
    void accept_cheat_writes(bool accept = true) noexcept { cheat_writes_ = accept; }
    // Serves a set from its text; `set.source` empty is "Lantern". One of the
    // same platform, title, build and source is replaced. It refuses what
    // § 10 and the platform's profile (Annex A) do not allow.
    [[nodiscard]] Result<CheatSet> add_cheat(const CheatWrite& set);
    // False when there is none of that id.
    bool remove_cheat(std::string_view id);

    [[nodiscard]] Result<Vector<String>> platforms(const Allocator& allocator) override;
    [[nodiscard]] Result<Vector<App>> apps(const AppsFilter& filter, const Allocator& allocator) override;
    [[nodiscard]] Result<std::optional<LibraryFile>> file(
        std::string_view name, const Allocator& allocator) override;
    [[nodiscard]] bool offers_titles() override { return titles_offered_; }
    [[nodiscard]] Result<Vector<Title>> titles(
        std::string_view languages, const Allocator& allocator) override;
    [[nodiscard]] Result<std::optional<LibraryFile>> media(
        std::string_view name, const Allocator& allocator) override;
    [[nodiscard]] bool offers_sections() override { return sections_offered_; }
    [[nodiscard]] Result<Vector<Section>> sections(
        std::string_view languages, const Allocator& allocator) override;
    [[nodiscard]] bool offers_homebrew() override { return homebrew_offered_; }
    [[nodiscard]] Result<Vector<Homebrew>> homebrew(
        std::string_view languages, const Allocator& allocator) override;
    [[nodiscard]] bool offers_cheats() override { return cheats_offered_; }
    [[nodiscard]] Result<Vector<CheatSet>> cheats(const Allocator& allocator) override;
    [[nodiscard]] Result<std::optional<LibraryFile>> cheat_file(
        std::string_view id, const Allocator& allocator) override;
    [[nodiscard]] bool writes_cheats() override { return cheat_writes_; }
    [[nodiscard]] Result<CheatSet> write_cheat(
        const CheatWrite& set, std::string_view replacing, const Allocator& allocator) override;
    [[nodiscard]] Result<bool> delete_cheat(std::string_view id) override;
    [[nodiscard]] Journal* journal() override { return keep_ > 0 ? this : nullptr; }
    // Tells the observer of each app, title, homebrew entry and cheat set added or removed.
    void observe(LibraryObserver* observer) override { observer_ = observer; }

    [[nodiscard]] Result<JournalPosition> position(const Allocator& allocator) override;
    [[nodiscard]] Result<AppChanges> app_changes(
        std::uint64_t after, std::string_view platform, const Allocator& allocator) override;
    [[nodiscard]] Result<TitleDelta> title_changes(std::uint64_t after, std::string_view platform,
        std::string_view languages, const Allocator& allocator) override;

  private:
    struct Stored
    {
        String name;
        Digest sha256 {};
        std::shared_ptr<MemoryFileReader> reader;
        String content_type;
    };

    // One change: an app added or removed, or a title put or removed.
    struct Entry
    {
        using allocator_type = Allocator;

        enum class Kind : std::uint8_t
        {
            app_added,
            app_removed,
            title,
        };
        std::uint64_t position = 0;
        Kind kind              = Kind::title;
        String platform;
        String key; // the app's id, the title's title_id

        explicit Entry(const allocator_type& allocator)
            : platform(allocator)
            , key(allocator)
        {
        }
        Entry(const Entry& other, const allocator_type& allocator)
            : position(other.position)
            , kind(other.kind)
            , platform(other.platform, allocator)
            , key(other.key, allocator)
        {
        }
        Entry(Entry&& other, const allocator_type& allocator)
            : position(other.position)
            , kind(other.kind)
            , platform(std::move(other.platform), allocator)
            , key(std::move(other.key), allocator)
        {
        }
        Entry(const Entry&)            = default;
        Entry(Entry&&)                 = default;
        Entry& operator=(const Entry&) = default;
        Entry& operator=(Entry&&)      = default;
        ~Entry()                       = default;
    };

    void record(Entry::Kind kind, std::string_view platform, std::string_view key);
    void notify(std::string_view family, std::string_view platform, std::string_view title_id,
        const Vector<Rating>* ratings = nullptr) const;
    // Serves `content` as a file of this library, once; the address it is served at.
    String keep_file(std::span<const std::byte> content, const Digest& sha256);
    // Whether an app or a package of a homebrew is served from that file.
    [[nodiscard]] bool uses_file(std::string_view name) const noexcept;
    // Stops serving the files only `gone` used.
    void drop_unused_files(const Homebrew& gone);
    [[nodiscard]] Result<CheatSet> put_cheat(const CheatWrite& given, std::string_view replacing);
    [[nodiscard]] bool has_app(std::string_view id) const noexcept;
    [[nodiscard]] const Title* find_title(
        std::string_view platform, std::string_view title_id) const noexcept;

    Allocator allocator_;
    String base_;
    Vector<App> apps_;
    Vector<Stored> files_;
    Vector<Stored> media_;
    Vector<Title> titles_;
    Vector<Section> sections_;
    Vector<Homebrew> homebrew_;
    Vector<CheatSet> cheats_;
    Vector<Stored> cheat_files_;
    bool titles_offered_   = false;
    bool sections_offered_ = false;
    bool homebrew_offered_ = false;
    bool cheats_offered_   = false;
    bool cheat_writes_     = false;
    // The journal, kept when `keep_` is above 0
    std::size_t keep_ = 0;
    String epoch_;
    Vector<Entry> entries_;
    std::uint64_t sequence_    = 0;
    std::uint64_t floor_       = 0;
    LibraryObserver* observer_ = nullptr;
};

// An event stream (§ 18.1) an adapter sends, a step at a time: the core has
// no thread and no timer, the adapter keeps the clock.
class EventStream
{
  public:
    EventStream()                              = default;
    EventStream(const EventStream&)            = delete;
    EventStream& operator=(const EventStream&) = delete;
    EventStream(EventStream&&)                 = delete;
    EventStream& operator=(EventStream&&)      = delete;
    // Frees the stream's slot (§ 18.4): drop it when the client leaves.
    virtual ~EventStream() = default;

    // Appends to `out` what the stream says at `now_ms`, a count of
    // milliseconds from a steady clock of the adapter's (any origin, never
    // going back). The first step gives `retry`, `ready` and the events
    // after the id the client came with; then events as they are recorded,
    // and a comment at least every `heartbeat` seconds. False once the
    // stream is over (the server stops, the token no longer holds, the
    // stream's hour is up): `out` then holds its last bytes, and the adapter
    // closes the connection. Call it again within a heartbeat at most; every
    // few tens of milliseconds gives events in good time.
    [[nodiscard]] virtual bool step(std::uint64_t now_ms, String& out) = 0;
};

struct ServerFile
{
    std::shared_ptr<FileReader> reader;
    std::uint64_t offset = 0;
    std::uint64_t length = 0;
};

// The answer, for the adapter to send. `Content-Length` is always among
// the headers, HEAD's and 304's included (whose body is empty), but for a
// stream's; `Date` and the connection's own headers are the adapter's. A file
// is read by the adapter from `file->reader`, `file->length` bytes from
// `file->offset`, never held whole.
//
// With the events of ServerOptions::events, two more cases are the adapter's:
//
// - `stream` is set (status 200, no Content-Length, no body): after the
//   head, the adapter calls stream->step() as often as its clock lets it and
//   writes what it appends, until it gives false or the client leaves, then
//   closes the connection and drops the stream.
// - `hold_ms` is not 0 (a long poll, § 18.3, with nothing to say yet): it is
//   not an answer. The adapter holds the request until Server::event_mark()
//   is not `hold_mark` any more, or `hold_ms` milliseconds have passed, then
//   calls handle() again with the same request, `resumed` and
//   ServerRequest::waited_ms the time held; the new response may hold again.
struct ServerResponse
{
    using allocator_type = Allocator;

    std::uint16_t status = 200;
    ResponseHeaders headers;
    String body;
    std::optional<ServerFile> file;
    std::shared_ptr<EventStream> stream;
    std::uint32_t hold_ms   = 0;
    std::uint64_t hold_mark = 0;

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

// The limits of the saves (§ 4.2, § 9), the handshake's `limits.save_body`,
// `save_size` and `saves_kept_per_title`, and an upload's `chunk_size`.
struct SaveLimits
{
    // The largest save sent in one request.
    std::uint64_t body = std::uint64_t { 8 } << 20U;
    // The largest save at all (an upload's `size`).
    std::uint64_t size = std::uint64_t { 1 } << 30U;
    // The backups kept per title, platform and account; the oldest beyond are dropped.
    std::uint32_t kept = 10;
    // An upload's chunk_size.
    std::uint64_t chunk = std::uint64_t { 1 } << 20U;
    // How long an upload may take before it is gone.
    std::uint32_t upload_hours = 24;
};

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

    // Save backups (§ 9), for the accounts with the scope `saves`: where they
    // are kept. Needs `accounts`; without it the server offers no `saves`.
    // It must outlive the server.
    SaveStore* saves = nullptr;
    SaveLimits save_limits;
    // Keep backups encrypted on the device (§ 9.4, `encrypted_saves`); false:
    // a backup sent with an `encryption` is a 400 (L-9.4-5).
    bool encrypted_saves = true;

    // Requests for games (§ 11), for the accounts with the scope `requests`:
    // where they are kept. Needs `accounts`; without it the server offers no
    // `requests`. It must outlive the server.
    RequestStore* requests = nullptr;

    // Sync (§ 20), for the accounts with the scopes `sync.read` and `sync.write`: where it is kept. Needs
    // `accounts`; without it the server offers no `sync`. It must outlive the server.
    SyncStore* sync = nullptr;

    // Peers (§ 19.3): the seed of the server's grant key, 32 bytes of an Ed25519 key; with it the server
    // offers `peers` (it also needs a library that serves files, which every Library does). Keep it, for
    // grants alone: peers learn its public key from the handshake. None: no `peers`.
    std::optional<std::array<std::uint8_t, 32>> grant_seed;
    // `peers.grant_lifetime`: the seconds a grant lives, 1 to 900.
    std::uint32_t grant_lifetime = 600;

    // The administration API (§ 5.7) and the invitations (§ 5.5), when the
    // account store administers (AccountStore::administers()); false: neither.
    bool admin = true;

    // Events (§ 18): the stream at <base>/v1/events and the long poll of
    // `changes`. Only for an adapter that steps streams and holds requests
    // (see ServerResponse): the POSIX one does. Streams and held requests
    // use the library and the account store while they last: drop them
    // before either.
    bool events = false;
    // `limits.heartbeat`: the most seconds between two lines of a stream,
    // 5 to 60.
    std::uint32_t heartbeat = 15;
    // `limits.event_streams`: the streams a token may hold at once (an
    // anonymous caller: an address), 1 at least.
    std::uint32_t event_streams = 2;
    // `limits.wait`: the longest wait of a long poll, in seconds, 30 to 300.
    std::uint32_t wait_limit = 60;
    // The events kept for resuming, 1 to 1,000,000; an id older than the
    // last of them is a 410.
    std::uint32_t events_kept = 10000;
    // How long a stream lives before the server ends it (the client resumes
    // with the last id it read), in seconds, 60 at least.
    std::uint32_t stream_lifetime = 3600;
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

    // Marks `done` (§ 11) the open requests for a title that has an app in
    // the library now; the number marked. The library is read when asked, so
    // the app calls this when its library changes. Needs `requests`.
    [[nodiscard]] Result<std::size_t> settle_requests() const;

    // Events (§ 18). The library changed, for a Library that does not tell
    // the server itself (Library::observe()): the event `library` goes to the
    // callers who may see a change. Nothing without `events`.
    void library_changed(std::span<const LibraryChange> changes) const;
    // The server stops on purpose (L-18.2-2): every stream gives `shutdown`
    // and ends, and the held long polls answer at once. Later streams begin
    // with `shutdown`.
    void shutdown() const;
    // A number that changes whenever an event is recorded or the server shuts
    // down: the adapter compares it with ServerResponse::hold_mark.
    [[nodiscard]] std::uint64_t event_mark() const noexcept;

  private:
    explicit Server(std::shared_ptr<const detail::ServerState> state) noexcept
        : state_(std::move(state))
    {
    }

    std::shared_ptr<const detail::ServerState> state_;
};

} // namespace lantern
