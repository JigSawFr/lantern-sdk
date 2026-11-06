// SPEC.md § 18: the events of a server. A journal in memory (EventHub) of
// what happened, with who may see each event; the stream of § 18.1, an
// EventStream an adapter steps with its own clock; and the long poll of
// § 18.3, which `changes` answers, or holds (ServerResponse::hold_ms) when
// nothing has happened yet. Event ids are tokens of `changes`
// (seal_event_since()), so that a stream and `changes?since=` resume from the
// same place. The core starts no thread and reads no clock of its own here.
#include <algorithm>
#include <array>
#include <charconv>
#include <limits>

#include <lantern/encoding.hpp>
#include <lantern/sha256.hpp>
#include <lantern/tls.hpp>

#include "server_internal.hpp"

namespace lantern
{

namespace
{

using detail::Answer;
using detail::Caller;
using detail::EventRecord;
using detail::ProblemError;
using detail::ServerState;

// The milliseconds a client waits before it connects again (`retry`, L-18.1-2).
constexpr std::uint32_t retry_ms = 5000;

void append_number(String& out, std::uint64_t value)
{
    std::array<char, 24> text {};
    const auto result = std::to_chars(text.data(), text.data() + text.size(), value);
    out.append(text.data(), static_cast<std::size_t>(result.ptr - text.data()));
}

// One event as the stream writes it: its id, type, and document on one line.
void append_event(String& out, std::string_view id, std::string_view event, std::string_view data)
{
    out.append("id: ");
    out.append(id);
    out.append("\nevent: ");
    out.append(event);
    out.append("\ndata: ");
    out.append(data);
    out.append("\n\n");
}

// What a caller reads of the events (§ 18.2): the scopes it holds.
struct Audience
{
    bool library  = false;
    bool requests = false;
    bool saves    = false;
    bool admin    = false;

    static Audience of(const ServerState& state, const Caller& caller)
    {
        Audience audience;
        audience.library  = !detail::check_scope(state, caller, "library").has_value();
        audience.requests = !detail::check_scope(state, caller, "requests").has_value();
        audience.saves    = !detail::check_scope(state, caller, "saves").has_value();
        audience.admin    = !detail::check_scope(state, caller, "admin").has_value();
        return audience;
    }

    [[nodiscard]] bool holds(std::string_view scope) const noexcept
    {
        if (scope == "library")
            return library;
        if (scope == "requests")
            return requests;
        if (scope == "saves")
            return saves;
        return scope == "admin" && admin;
    }
};

// The token of an event: `changes?since=` takes it and resumes just after it (L-18.1-1).
String token_of(const ServerState& state, const EventRecord& record)
{
    return detail::seal_event_since(state, record.journal_epoch, record.journal_position, record.seq);
}

void add_unique(Vector<String>& words, std::string_view word)
{
    if (std::ranges::none_of(words, [&](const String& item) { return item == word; }))
        words.emplace_back(word);
}

// The document of `record` for this caller, or nothing when it may not see it (§ 18.2): of its scopes and
// account, of its platform when it named one (`platform` empty: none), and within its rating cap.
std::optional<String> shown(const ServerState& state, const Caller& caller, const Audience& audience,
    const detail::CapFilter& cap, std::string_view platform, const EventRecord& record)
{
    // The event `request` also goes to the scope admin, whoever's request it is (§ 11)
    const bool admin_sees = record.event == "request" && audience.admin;
    if (!audience.holds(record.scope) && !admin_sees)
        return std::nullopt;
    if (record.event == "library")
    {
        // Only the families and platforms of which the caller sees a change (L-18.2-1)
        Vector<String> families(state.allocator);
        Vector<String> platforms(state.allocator);
        for (const detail::EventChange& change : record.changes)
        {
            if (!platform.empty() && change.platform != platform)
                continue;
            const bool hidden = change.by_ratings
                ? cap.hides(change.ratings)
                : (!change.title_id.empty() && cap.hides_title(change.platform, change.title_id));
            if (hidden)
                continue;
            add_unique(families, change.family);
            add_unique(platforms, change.platform);
        }
        if (families.empty())
            return std::nullopt;
        std::ranges::sort(families);
        std::ranges::sort(platforms);
        String out(state.allocator);
        json::Writer w(out);
        w.begin_object();
        w.key("schema");
        w.number(known_schema);
        w.key("families");
        w.begin_array();
        for (const String& family : families)
            w.string(family);
        w.end_array();
        w.key("platforms");
        w.begin_array();
        for (const String& item : platforms)
            w.string(item);
        w.end_array();
        w.end_object();
        return out;
    }
    if (!record.user.empty() && record.user != caller.name && !admin_sees)
        return std::nullopt;
    if (!platform.empty() && !record.platform.empty() && record.platform != platform)
        return std::nullopt;
    if (!record.title_id.empty() && !record.platform.empty()
        && cap.hides_title(record.platform, record.title_id))
        return std::nullopt;
    String out(record.data, state.allocator);
    if (admin_sees && !record.user.empty() && out.ends_with('}'))
    {
        // An admin reads whose request it is
        out.pop_back();
        out.append(",\"user\":");
        json::Writer::escape(out, record.user);
        out.push_back('}');
    }
    return out;
}

// Calls `visit(record, document)` for each event after `after` that the caller may see, in order, under the
// hub's lock; gives the last event it examined, or nothing when `after` fell out of the journal.
template <typename Visit>
std::optional<std::uint64_t> scan(const ServerState& state, const Caller& caller, const Audience& audience,
    const detail::CapFilter& cap, std::string_view platform, std::uint64_t after, std::uint64_t* mark,
    const Visit& visit)
{
    const detail::EventHub& hub = state.hub;
    const std::scoped_lock lock(hub.mutex);
    if (mark != nullptr)
        *mark = hub.mark.load();
    if (after < hub.floor)
        return std::nullopt;
    std::size_t from = 0;
    if (!hub.events.empty() && after + 1 > hub.events.front().seq)
        from = static_cast<std::size_t>(after + 1 - hub.events.front().seq);
    for (std::size_t i = from; i < hub.events.size(); ++i)
    {
        const EventRecord& record = hub.events[i];
        if (record.seq <= after)
            continue;
        if (const auto document = shown(state, caller, audience, cap, platform, record))
            visit(record, *document);
    }
    return hub.seq;
}

// The event a stream or a long poll starts after: the token's, or now's; 400 for a token never given,
// 410 for one too old (L-18.1-4).
std::expected<std::uint64_t, ProblemError> event_start(
    const ServerState& state, std::optional<std::string_view> since)
{
    const detail::EventHub& hub = state.hub;
    if (!since)
    {
        const std::scoped_lock lock(hub.mutex);
        return hub.seq;
    }
    const auto place = detail::open_event_since(state, *since);
    if (!place)
        return std::unexpected(place.error());
    const std::scoped_lock lock(hub.mutex);
    if (place->epoch != hub.epoch || place->seq < hub.floor)
        return std::unexpected(detail::gone(
            state, "This event id is too old for this server: read again, then connect without one."));
    if (place->seq > hub.seq)
        return std::unexpected(detail::bad_request(state, "Unknown event id: one this server never gave."));
    return place->seq;
}

ProblemError slow_down(const ServerState& state, std::string_view detail_text)
{
    ProblemError error = detail::make_problem(state, 429, Code::slow_down, detail_text);
    error.headers.set("Retry-After", detail::number_text(state.heartbeat, state.allocator));
    return error;
}

// A stream's slot, for a token (a hash of its header) or an address (§ 18.4).
bool take_slot(const ServerState& state, std::string_view key)
{
    detail::EventHub& hub = state.hub;
    const std::scoped_lock lock(hub.mutex);
    const auto found         = hub.streams.find(String(key, state.allocator));
    const std::uint32_t held = found == hub.streams.end() ? 0 : found->second;
    if (held >= state.event_streams)
        return false;
    hub.streams[String(key, state.allocator)] = held + 1;
    return true;
}

void release_slot(const ServerState& state, std::string_view key)
{
    detail::EventHub& hub = state.hub;
    const std::scoped_lock lock(hub.mutex);
    const auto found = hub.streams.find(String(key, state.allocator));
    if (found == hub.streams.end())
        return;
    if (found->second > 1)
        --found->second;
    else
        hub.streams.erase(found);
}

// Where the library's journal stands now (an empty place without one).
JournalPosition journal_now(const ServerState& state)
{
    JournalPosition now(state.allocator);
    if (Journal* journal = state.library->journal())
    {
        if (auto found = journal->position(state.allocator))
            now = std::move(*found);
    }
    return now;
}

// What a stream looks at of the hub at each step.
struct Snapshot
{
    bool stopping      = false;
    std::uint64_t mark = 0;
    std::uint64_t seq  = 0;
};

Snapshot snapshot(const ServerState& state)
{
    const std::scoped_lock lock(state.hub.mutex);
    return { state.hub.stopping, state.hub.mark.load(), state.hub.seq };
}

// A stream's body (§ 18.1), stepped by the adapter.
class StreamBody final : public EventStream
{
  public:
    StreamBody(std::shared_ptr<const ServerState> state, Caller caller, std::string_view platform,
        std::string_view authorization, std::string_view slot, std::uint64_t after, std::string_view ready_id)
        : state_(std::move(state))
        , caller_(std::move(caller))
        , platform_(platform, state_->allocator)
        , authorization_(authorization, state_->allocator)
        , slot_(slot, state_->allocator)
        , ready_id_(ready_id, state_->allocator)
        , audience_(Audience::of(*state_, caller_))
        , last_(after)
    {
    }
    StreamBody(const StreamBody&)            = delete;
    StreamBody& operator=(const StreamBody&) = delete;
    StreamBody(StreamBody&&)                 = delete;
    StreamBody& operator=(StreamBody&&)      = delete;
    ~StreamBody() override { release_slot(*state_, slot_); }

    [[nodiscard]] bool step(std::uint64_t now_ms, String& out) override
    {
        if (over_)
            return false;
        const std::size_t before = out.size();
        const bool first         = !started_;
        if (first)
        {
            started_ = true;
            born_    = now_ms;
            beat_    = now_ms;
            out.append("retry: ");
            append_number(out, retry_ms);
            out.append("\n\n");
            append_event(out, ready_id_, "ready", R"({"schema":1})");
        }
        else if (now_ms >= born_ && now_ms - born_ >= std::uint64_t { state_->stream_lifetime } * 1000)
        {
            // The client resumes with the last id it read
            over_ = true;
            return false;
        }

        const Snapshot hub = snapshot(*state_);
        if (hub.stopping)
        {
            // L-18.2-2: the client connects again after `retry` seconds at least
            const JournalPosition now = journal_now(*state_);
            const String id           = detail::seal_event_since(*state_, now.epoch, now.position, hub.seq);
            String data(R"({"schema":1,"retry":)", state_->allocator);
            append_number(data, std::max<std::uint64_t>(1, retry_ms / 1000));
            data.push_back('}');
            append_event(out, id, "shutdown", data);
            over_ = true;
            return false;
        }
        if (first || hub.mark != seen_mark_)
        {
            seen_mark_ = hub.mark;
            if ((!first && !refresh()) || !deliver(out))
            {
                over_ = true;
                return false;
            }
        }
        if (out.size() != before)
            beat_ = now_ms;
        else if (now_ms >= beat_ && now_ms - beat_ >= std::uint64_t { state_->heartbeat } * 1000)
        {
            // A token revoked, or an account frozen or deleted, ends its stream by its next heartbeat
            // (L-18.1-8)
            if (!refresh())
            {
                over_ = true;
                return false;
            }
            out.append(": heartbeat\n\n");
            beat_ = now_ms;
        }
        return true;
    }

  private:
    // Reads the token again: false once it no longer holds. The caller's scopes and cap follow the account's.
    [[nodiscard]] bool refresh()
    {
        if (authorization_.empty())
            return true;
        const Header header { "Authorization", authorization_ };
        ServerRequest again;
        again.headers = std::span<const Header>(&header, 1);
        auto now      = detail::identify(*state_, again);
        if (!now || now->state != Caller::State::active)
            return false;
        caller_   = std::move(*now);
        audience_ = Audience::of(*state_, caller_);
        return true;
    }

    // The events after the last one given that the caller may see; false when the stream cannot go on.
    [[nodiscard]] bool deliver(String& out)
    {
        const auto cap = detail::CapFilter::of(*state_, caller_);
        if (!cap)
            return false;
        const auto reached = scan(*state_, caller_, audience_, *cap, platform_, last_, nullptr,
            [&](const EventRecord& record, const String& document)
            { append_event(out, token_of(*state_, record), record.event, document); });
        // Behind the journal: the client resumes with its last id, and learns (410) that it must read again
        if (!reached)
            return false;
        last_ = *reached;
        return true;
    }

    std::shared_ptr<const ServerState> state_;
    Caller caller_;
    String platform_;
    String authorization_;
    String slot_;
    String ready_id_;
    Audience audience_;
    std::uint64_t last_;
    std::uint64_t seen_mark_ = 0;
    std::uint64_t born_      = 0;
    std::uint64_t beat_      = 0;
    bool started_            = false;
    bool over_               = false;
};

bool all_digits(std::string_view text) noexcept
{
    return !text.empty() && std::ranges::all_of(text, [](char c) { return c >= '0' && c <= '9'; });
}

} // namespace

namespace detail
{

void record_event(const ServerState& state, std::string_view event, std::string_view data,
    std::string_view scope, std::string_view user, std::string_view platform, std::string_view title_id,
    std::span<const LibraryChange> changes)
{
    if (!state.events)
        return;
    // Where the library's journal stands: the event's id resumes `changes` from there
    String epoch(state.allocator);
    std::uint64_t position = 0;
    if (Journal* journal = state.library->journal())
    {
        if (auto now = journal->position(state.allocator))
        {
            epoch    = std::move(now->epoch);
            position = now->position;
        }
    }
    EventHub& hub = state.hub;
    const std::scoped_lock lock(hub.mutex);
    hub.events.emplace_back();
    EventRecord& record = hub.events.back();
    record.seq          = ++hub.seq;
    record.event.assign(event);
    record.data.assign(data);
    record.scope.assign(scope);
    record.user.assign(user);
    record.platform.assign(platform);
    record.title_id.assign(title_id);
    record.journal_epoch    = std::move(epoch);
    record.journal_position = position;
    for (const LibraryChange& change : changes)
    {
        record.changes.emplace_back();
        EventChange& kept = record.changes.back();
        kept.family.assign(change.family);
        kept.platform.assign(change.platform);
        kept.title_id.assign(change.title_id);
        if (change.ratings != nullptr)
        {
            kept.by_ratings = true;
            kept.ratings    = *change.ratings;
        }
    }
    while (hub.events.size() > hub.keep)
    {
        hub.floor = hub.events.front().seq;
        hub.events.pop_front();
    }
    hub.mark.fetch_add(1);
}

void record_library_event(const ServerState& state, std::span<const LibraryChange> changes)
{
    if (!state.events || changes.empty())
        return;
    record_event(state, "library", R"({"schema":1})", "library", {}, {}, {}, changes);
}

void ServerState::library_changed(std::span<const LibraryChange> changes)
{
    record_library_event(*this, changes);
}

void record_save_event(const ServerState& state, std::string_view user, const Save& save)
{
    if (!state.events)
        return;
    String data(state.allocator);
    json::Writer w(data);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    w.key("platform");
    w.string(save.platform);
    w.key("title_id");
    w.string(save.title_id);
    w.key("save_id");
    w.string(save.save_id);
    w.key("created");
    w.string(save.created);
    if (!save.device.empty())
    {
        w.key("device");
        w.string(save.device);
    }
    w.end_object();
    record_event(state, "save", data, "saves", user, save.platform, save.title_id);
}

void record_request_event(const ServerState& state, const StoredRequest& request, bool deleted)
{
    if (!state.events)
        return;
    String data(state.allocator);
    json::Writer w(data);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    w.key("id");
    w.string(request.id);
    w.key("platform");
    w.string(request.platform);
    w.key("title_id");
    w.string(request.title_id);
    if (deleted)
    {
        w.key("deleted");
        w.boolean(true);
    }
    else
    {
        w.key("status");
        w.string(request.status);
    }
    w.end_object();
    record_event(state, "request", data, "requests", request.user, request.platform, request.title_id);
}

void record_pairing_event(const ServerState& state, const PendingPairing& pairing)
{
    if (!state.events)
        return;
    String data(state.allocator);
    json::Writer w(data);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    w.key("id");
    w.string(pairing.id);
    w.key("code");
    w.string(pairing.code);
    w.key("device");
    w.string(pairing.device);
    if (pairing.key)
    {
        const auto fingerprint
            = short_form(Sha256::of(std::as_bytes(std::span<const std::uint8_t>(*pairing.key))));
        w.key("key");
        w.string(std::string_view(fingerprint.data(), fingerprint.size()));
    }
    w.key("expires");
    w.string(utc_text(pairing.expires, state.allocator));
    w.end_object();
    record_event(state, "pairing", data, "admin", {}, {}, {});
}

std::optional<ProblemError> check_events(const ServerState& state, const Caller& caller)
{
    for (const std::string_view scope : { "library", "requests", "saves", "admin" })
    {
        if (!check_scope(state, caller, scope))
            return std::nullopt;
    }
    // None of the four: say what the first would have needed
    return check_scope(state, caller, "library");
}

String changes_token(const ServerState& state, const JournalPosition& journal)
{
    if (!state.events)
        return seal_since(state, 's', journal.epoch, journal.position);
    std::uint64_t seq = 0;
    {
        const std::scoped_lock lock(state.hub.mutex);
        seq = state.hub.seq;
    }
    return seal_event_since(state, journal.epoch, journal.position, seq);
}

Answer events_route(const ServerState& state, const ServerRequest& request, const Caller& caller)
{
    const auto platform = platform_param(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    // The query wins over the header, for a client that cannot set it (L-18.1-3)
    std::optional<std::string_view> since = request.param("since");
    if (!since)
    {
        const std::string_view header = trim(request.header("Last-Event-ID").value_or(std::string_view {}));
        if (!header.empty())
            since = header;
    }
    const auto start = event_start(state, since);
    if (!start)
        return std::unexpected(start.error());

    JournalPosition now(state.allocator);
    if (Journal* journal = state.library->journal())
    {
        auto found = journal->position(state.allocator);
        if (!found)
            return std::unexpected(internal_error(state));
        now = std::move(*found);
    }
    // The id of ready is the token it starts from: the one the client gave, or now's
    const String ready
        = since ? String(*since, state.allocator) : seal_event_since(state, now.epoch, now.position, *start);

    // A token holds so many streams, an anonymous caller's address as many
    String slot(state.allocator);
    const std::string_view authorization = request.header("Authorization").value_or(std::string_view {});
    if (authorization.empty())
    {
        slot.assign("a:");
        slot.append(request.remote);
    }
    else
    {
        const auto hex = to_hex(Sha256::of(authorization));
        slot.assign("t:");
        slot.append(hex.data(), hex.size());
    }
    if (!take_slot(state, slot))
    {
        String why("At most ", state.allocator);
        why.append(number_text(state.event_streams, state.allocator));
        why.append(" event streams at once (SPEC.md § 18.4).");
        return std::unexpected(slow_down(state, why));
    }
    ServerResponse response(state.allocator);
    response.status = 200;
    response.headers.set("Content-Type", "text/event-stream; charset=utf-8");
    response.headers.set("Cache-Control", "no-store");
    response.headers.set("X-Accel-Buffering", "no");
    response.headers.set("Vary", "Authorization, Lantern-Platform");
    // From here the stream owns the slot, and frees it
    response.stream = std::make_shared<StreamBody>(state.shared_from_this(), caller,
        platform->value_or(std::string_view {}), authorization, slot, *start, ready);
    return response;
}

Answer long_poll_route(const ServerState& state, const ServerRequest& request, const Caller& caller)
{
    const std::string_view wait_text = request.param("wait").value_or(std::string_view {});
    const auto since                 = request.param("since");
    if (!all_digits(wait_text) || !since)
        return std::unexpected(
            bad_request(state, "wait is a number of seconds, from 0, with since (SPEC.md § 18.3)."));
    // A wait above limits.wait is lowered to it (L-18.3-1)
    std::uint64_t seconds = 0;
    const auto parsed     = std::from_chars(wait_text.data(), wait_text.data() + wait_text.size(), seconds);
    if (parsed.ec != std::errc {} || seconds > state.wait_limit)
        seconds = state.wait_limit;
    const auto platform = platform_param(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    const auto start = event_start(state, since);
    if (!start)
        return std::unexpected(start.error());
    const auto cap = CapFilter::of(state, caller);
    if (!cap)
        return std::unexpected(cap.error());
    const Audience audience = Audience::of(state, caller);

    String events(state.allocator);
    std::size_t found  = 0;
    std::uint64_t mark = 0;
    const auto examined
        = scan(state, caller, audience, *cap, platform->value_or(std::string_view {}), *start, &mark,
            [&](const EventRecord& record, const String& document)
            {
                if (found > 0)
                    events.push_back(',');
                ++found;
                json::Writer item(events);
                item.begin_object();
                item.key("id");
                item.string(token_of(state, record));
                item.key("event");
                item.string(record.event);
                item.key("data");
                item.raw(document);
                item.end_object();
            });
    if (!examined)
        return std::unexpected(
            gone(state, "This event id is too old for this server: read again, then connect without one."));

    bool stopping = false;
    {
        const std::scoped_lock lock(state.hub.mutex);
        stopping = state.hub.stopping;
    }
    // The first of the two: an event the caller may see, or the wait (a HEAD does not wait)
    const std::uint64_t limit = seconds * 1000;
    if (found == 0 && !stopping && request.method != "HEAD" && request.waited_ms < limit)
    {
        ServerResponse held(state.allocator);
        held.status  = 200;
        held.hold_ms = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(limit - request.waited_ms, std::numeric_limits<std::uint32_t>::max()));
        held.hold_mark = mark;
        return held;
    }

    // The apps added and removed since, as `changes` gives them
    JournalPosition now(state.allocator);
    AppChanges changes(state.allocator);
    if (Journal* journal = state.library->journal())
    {
        auto at = journal->position(state.allocator);
        if (!at)
            return std::unexpected(internal_error(state));
        now = std::move(*at);
        if (!check_library(state, caller))
        {
            const auto after = open_since(state, 's', *since, now);
            if (!after)
                return std::unexpected(after.error());
            auto read
                = journal->app_changes(*after, platform->value_or(std::string_view {}), state.allocator);
            if (!read)
                return std::unexpected(internal_error(state));
            changes = std::move(*read);
            std::erase_if(
                changes.added, [&](const App& app) { return cap->hides_title(app.platform, app.title_id); });
        }
    }
    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    write_app_changes(w, changes);
    w.key("since");
    w.string(seal_event_since(state, now.epoch, now.position, *examined));
    w.key("events");
    String list("[", state.allocator);
    list.append(events);
    list.push_back(']');
    w.raw(list);
    w.end_object();
    ServerResponse response = json_response(state, request, std::move(out), 200, false);
    response.headers.set("Cache-Control", "no-store");
    return response;
}

} // namespace detail

void Server::library_changed(std::span<const LibraryChange> changes) const
{
    detail::record_library_event(*state_, changes);
}

void Server::shutdown() const
{
    detail::EventHub& hub = state_->hub;
    const std::scoped_lock lock(hub.mutex);
    hub.stopping = true;
    hub.mark.fetch_add(1);
}

std::uint64_t Server::event_mark() const noexcept
{
    return state_->hub.mark.load();
}

} // namespace lantern
