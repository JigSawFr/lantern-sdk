// Events (SPEC.md § 18): what changed, pushed by the server as it happens.
//
// - SseParser reads Server-Sent Events (the WHATWG HTML standard's
//   event-stream) as the transport hands the body over, chunk by chunk:
//   lines and events bounded, `retry`, `id` (Last-Event-ID), comments (the
//   heartbeats). It allocates its buffers once, from the app's resource.
// - Client::events() (client.hpp) opens <base>/v1/events, resumes from
//   EventStreamState::last_id, and gives the app each event it knows, of a
//   schema it reads (L-18.1-5); Client::wait_changes() is the long poll of
//   § 18.3, for a client that cannot keep a connection open.
// - The read_*_event functions read an event's document by its kind.
//
// The library has no timers: the transport's read timeout is what notices
// a stream gone silent. Client::event_silence_limit() gives twice the
// server's heartbeat (§ 18.1), the time after which a client connects
// again; EventStreamState::reconnect_delay() how long it waits first
// (L-18.1-9).
#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/document.hpp>
#include <lantern/error.hpp>
#include <lantern/memory.hpp>

namespace lantern
{

// One event as the stream gives it: views valid during the call.
struct SseEvent
{
    std::string_view id; // the last event id the stream set (it carries over)
    std::string_view event; // "message" when the stream named none
    std::string_view data; // the data lines, joined by '\n'
};

class SseHandler
{
  public:
    SseHandler()                             = default;
    SseHandler(const SseHandler&)            = default;
    SseHandler(SseHandler&&)                 = default;
    SseHandler& operator=(const SseHandler&) = default;
    SseHandler& operator=(SseHandler&&)      = default;
    virtual ~SseHandler()                    = default;

    // An event; false stops the parser (feed() then returns at once).
    [[nodiscard]] virtual bool on_event(const SseEvent& event) = 0;
    // A comment line (": heartbeat"): the stream is alive.
    [[nodiscard]] virtual bool on_comment(std::string_view /*text*/) { return true; }
    // A `retry` field: the milliseconds to wait before connecting again.
    virtual void on_retry(std::uint32_t /*milliseconds*/) { }
};

struct SseLimits
{
    // A line, field name and value included.
    std::size_t max_line = std::size_t { 8 } * 1024;
    // An event's data, its lines joined: § 13 gives an event's `data` 4 KiB.
    std::size_t max_data = std::size_t { 8 } * 1024;
    // An `id`: a token of /v1/changes.
    std::size_t max_id = 512;
};

class SseParser
{
  public:
    explicit SseParser(Allocator allocator = {}, const SseLimits& limits = {});

    // The next bytes of the stream, in any cut. An error (Category::limit,
    // or invalid_response for a stream that is not UTF-8) ends the stream:
    // every later call returns it again.
    [[nodiscard]] Result<void> feed(std::span<const std::byte> bytes, SseHandler& handler);
    // Whether the handler asked to stop.
    [[nodiscard]] bool stopped() const noexcept { return stopped_; }
    // The last event id the stream set: what Last-Event-ID resumes from.
    [[nodiscard]] std::string_view last_event_id() const noexcept { return last_id_; }
    // Starts over, for a new connection (the last event id is kept).
    void reset() noexcept;

  private:
    [[nodiscard]] Result<void> line(SseHandler& handler);
    [[nodiscard]] Result<void> dispatch(SseHandler& handler);

    SseLimits limits_;
    String line_;
    String data_;
    String event_;
    String id_;
    String last_id_;
    std::optional<Error> error_;
    bool started_     = false; // past a leading BOM
    bool after_cr_    = false;
    bool stopped_     = false;
    std::uint8_t bom_ = 0; // bytes of a leading BOM matched so far
};

// § 18.2's events. A later version may add others: a client ignores them.
enum class EventKind : std::uint8_t
{
    ready,
    library,
    request,
    pairing,
    save,
    sync,
    shutdown,
};

[[nodiscard]] std::optional<EventKind> event_kind(std::string_view name) noexcept;
[[nodiscard]] std::string_view event_kind_name(EventKind kind) noexcept;

// An event the app gets: one of § 18.2's, whose document is of a schema
// this library reads. `data` is its JSON, for the read_*_event functions.
struct StreamEvent
{
    EventKind kind = EventKind::ready;
    std::string_view id;
    std::string_view data;
};

// `library`: something of those families changed on those platforms.
struct LibraryEvent
{
    using allocator_type = Allocator;
    Vector<String> families;
    Vector<String> platforms;
    explicit LibraryEvent(const allocator_type& allocator = {})
        : families(allocator)
        , platforms(allocator)
    {
    }
};

// `request`: one of the account's requests, made, changed or withdrawn.
struct RequestEvent
{
    using allocator_type = Allocator;
    String id;
    String platform;
    String title_id;
    String status; // empty when deleted
    bool deleted = false;
    explicit RequestEvent(const allocator_type& allocator = {})
        : id(allocator)
        , platform(allocator)
        , title_id(allocator)
        , status(allocator)
    {
    }
};

// `pairing`: a pairing waiting for approval (§ 5.7), its code and key to
// compare with the console's screen.
struct PairingEvent
{
    using allocator_type = Allocator;
    String id;
    String code;
    String device;
    String key;
    String expires;
    explicit PairingEvent(const allocator_type& allocator = {})
        : id(allocator)
        , code(allocator)
        , device(allocator)
        , key(allocator)
        , expires(allocator)
    {
    }
};

// `save`: a backup kept, for the account.
struct SaveEvent
{
    using allocator_type = Allocator;
    String platform;
    String title_id;
    String save_id;
    String created;
    String device;
    explicit SaveEvent(const allocator_type& allocator = {})
        : platform(allocator)
        , title_id(allocator)
        , save_id(allocator)
        , created(allocator)
        , device(allocator)
    {
    }
};

// `sync`: a collection changed (§ 20).
struct SyncEvent
{
    using allocator_type = Allocator;
    String collection;
    std::uint64_t rev = 0;
    explicit SyncEvent(const allocator_type& allocator = {})
        : collection(allocator)
    {
    }
};

// `shutdown`: the server stops; connect again after `retry` seconds.
struct ShutdownEvent
{
    using allocator_type = Allocator;
    std::optional<std::uint64_t> retry;
    explicit ShutdownEvent(const allocator_type& /*allocator*/ = {}) { }
};

// Each reads an event's document with the `schema` rule: absent for a newer
// one (an event the client then ignores, L-18.1-5).
[[nodiscard]] Read<LibraryEvent> read_library_event(std::string_view data, const DecodeOptions& options = {});
[[nodiscard]] Read<RequestEvent> read_request_event(std::string_view data, const DecodeOptions& options = {});
[[nodiscard]] Read<PairingEvent> read_pairing_event(std::string_view data, const DecodeOptions& options = {});
[[nodiscard]] Read<SaveEvent> read_save_event(std::string_view data, const DecodeOptions& options = {});
[[nodiscard]] Read<SyncEvent> read_sync_event(std::string_view data, const DecodeOptions& options = {});
[[nodiscard]] Read<ShutdownEvent> read_shutdown_event(
    std::string_view data, const DecodeOptions& options = {});

class EventHandler
{
  public:
    EventHandler()                               = default;
    EventHandler(const EventHandler&)            = default;
    EventHandler(EventHandler&&)                 = default;
    EventHandler& operator=(const EventHandler&) = default;
    EventHandler& operator=(EventHandler&&)      = default;
    virtual ~EventHandler()                      = default;

    // Each event the client knows; false closes the stream.
    [[nodiscard]] virtual bool on_event(const StreamEvent& event) = 0;
    // A heartbeat: nothing changed, the stream is alive.
    [[nodiscard]] virtual bool on_heartbeat() { return true; }
};

// What the app keeps between streams: where to resume, and how long to wait.
struct EventStreamState
{
    // The last event's id: Last-Event-ID on the next stream. Empty: the
    // stream starts from now (its `ready` gives where).
    std::array<char, 512> last_id {};
    std::size_t last_id_size = 0;
    // The server's `retry`, in milliseconds (§ 18.1); a `shutdown`'s, longer.
    std::uint32_t retry_ms = 5000;
    // Connections that failed in a row, for the backoff (Annex B.2).
    std::uint32_t failures = 0;

    [[nodiscard]] std::string_view last_id_view() const noexcept { return { last_id.data(), last_id_size }; }
    void set_last_id(std::string_view id) noexcept;
    // § 18.1's 410: the token is too old. Read again what is shown, and
    // connect without a token.
    void forget_position() noexcept { last_id_size = 0; }
    // L-18.1-9: `retry` at least, doubled for each failure in a row (with
    // the app's jitter, `jitter` from 0 to 1, Annex B.2), five minutes at most.
    [[nodiscard]] std::chrono::milliseconds reconnect_delay(double jitter = 0.0) const noexcept;
};

} // namespace lantern
