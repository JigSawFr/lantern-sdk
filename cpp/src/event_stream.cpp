// Events (SPEC.md § 18): the stream, read as the transport hands it over,
// and long polling.
#include <lantern/client.hpp>

#include "client_internal.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <system_error>

namespace lantern
{

using detail::add_query;
using detail::equal_ignoring_case;
using detail::header_value;

namespace
{

bool event_stream_type(std::string_view content_type) noexcept
{
    std::string_view type = content_type.substr(0, content_type.find(';'));
    while (!type.empty() && type.back() == ' ')
        type.remove_suffix(1);
    return equal_ignoring_case(type, "text/event-stream");
}

} // namespace

// Between the transport and the app: the status, the error's body when
// there is one, else the stream through the SSE parser, and each event the
// client knows to the app's handler.
class Client::EventReceiver final : public ResponseHandler, private SseHandler
{
  public:
    EventReceiver(Client& client, EventStreamState& state, EventHandler& handler)
        : client_(client)
        , state_(state)
        , handler_(handler)
        , parser_(client.allocator_)
        , error_body_(client.allocator_)
        , retry_after_(client.allocator_)
    {
    }

    bool on_status(std::uint16_t status) override
    {
        status_ = status;
        return true;
    }

    bool on_header(std::string_view name, std::string_view value) override
    {
        if (equal_ignoring_case(name, "Content-Type"))
            stream_type_ = event_stream_type(value);
        else if (equal_ignoring_case(name, "Retry-After") && value.size() < 32)
            retry_after_.assign(value);
        return true;
    }

    bool on_body(std::span<const std::byte> chunk) override
    {
        if (status_ != 200)
        {
            if (chunk.size()
                > client_.max_error_body_ - std::min(client_.max_error_body_, error_body_.size()))
                return false;
            error_body_.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            return true;
        }
        if (!stream_type_)
            return stop(
                Error::make(Category::invalid_response, "an event stream that is not text/event-stream"));
        if (auto fed = parser_.feed(chunk, *this); !fed)
            return stop(fed.error());
        return !parser_.stopped() && !error_;
    }

    [[nodiscard]] std::uint16_t status() const noexcept { return status_; }
    [[nodiscard]] bool stream_type() const noexcept { return stream_type_; }
    [[nodiscard]] const std::optional<Error>& error() const noexcept { return error_; }
    [[nodiscard]] std::string_view error_body() const noexcept { return error_body_; }
    [[nodiscard]] std::string_view retry_after() const noexcept { return retry_after_; }

  private:
    bool on_event(const SseEvent& event) override
    {
        // Every event moves the position, one the client ignores too
        state_.set_last_id(event.id);
        const auto kind = event_kind(event.event);
        if (!kind)
            return true; // L-18.1-5: an event it does not know
        const auto schema = peek_schema(event.data, client_.decode_.limits);
        if (!schema)
            return stop(schema.error());
        if (*schema > known_schema)
            return true; // L-18.1-5: a document of a newer schema
        if (*kind == EventKind::shutdown)
        {
            // The server stops: connect again after its retry at least
            const auto shutdown = read_shutdown_event(event.data, client_.decode_);
            if (shutdown && *shutdown && (*shutdown)->retry)
            {
                const std::uint64_t ms = std::min<std::uint64_t>(*(*shutdown)->retry, 3600) * 1000;
                state_.retry_ms = std::max<std::uint32_t>(state_.retry_ms, static_cast<std::uint32_t>(ms));
            }
        }
        StreamEvent out;
        out.kind = *kind;
        out.id   = event.id;
        out.data = event.data;
        return handler_.on_event(out);
    }

    bool on_comment(std::string_view /*text*/) override { return handler_.on_heartbeat(); }

    void on_retry(std::uint32_t milliseconds) override { state_.retry_ms = milliseconds; }

    bool stop(const Error& error)
    {
        error_ = error;
        return false;
    }

    Client& client_;
    EventStreamState& state_;
    EventHandler& handler_;
    SseParser parser_;
    String error_body_;
    String retry_after_;
    std::uint16_t status_ = 0;
    bool stream_type_     = false;
    std::optional<Error> error_;
};

Result<void> Client::events(EventStreamState& state, EventHandler& handler, const EventsQuery& query)
{
    if (auto ok = ready(Family::events); !ok)
        return ok;
    auto url   = api_url("/events");
    bool first = true;
    add_query(*url, first, "platform", query.platform);
    std::array<Header, 1> extra {};
    std::size_t extras = 0;
    if (state.last_id_size != 0)
    {
        if (!header_value(state.last_id_view()))
        {
            state.forget_position();
            return fail(Category::usage, "a last event id that is not a header value");
        }
        extra[extras++] = { "Last-Event-ID", state.last_id_view() };
    }
    Call call;
    call.url    = *url;
    call.accept = "text/event-stream";
    call.extra  = std::span(extra.data(), extras);
    EventReceiver receiver(*this, state, handler);
    const auto sent = exchange(call, receiver);
    if (receiver.status() == 200 && receiver.stream_type())
        state.failures = 0;
    else
        ++state.failures;
    if (receiver.error())
        return std::unexpected(*receiver.error());
    if (receiver.status() != 0 && receiver.status() != 200)
    {
        // § 18.1: a token too old, or never given: read again, without one
        if (receiver.status() == 410 || receiver.status() == 400)
            state.forget_position();
        return std::unexpected(problem(receiver.status(), receiver.error_body(), receiver.retry_after()));
    }
    if (!sent)
        return std::unexpected(sent.error());
    if (receiver.status() == 0)
        return fail(Category::transport, "no answer");
    return {};
}

Read<Changes> Client::wait_changes(std::string_view since, std::uint32_t wait, const EventsQuery& query)
{
    if (auto ok = ready(Family::changes); !ok)
        return std::unexpected(ok.error());
    if (auto ok = ready(Family::events); !ok)
        return std::unexpected(ok.error());
    if (since.empty())
        return fail(Category::usage, "a long poll waits after a since token (SPEC.md 18.3)");
    std::uint64_t longest = 300;
    if (handshake_ && handshake_->limits && handshake_->limits->wait)
        longest = *handshake_->limits->wait;
    const auto seconds = static_cast<std::uint32_t>(std::min<std::uint64_t>(wait, longest));
    auto url           = api_url("/changes");
    bool first         = true;
    add_query(*url, first, "since", since);
    add_query(*url, first, "wait", std::optional<std::uint32_t>(seconds));
    add_query(*url, first, "platform", query.platform);
    return read<Changes>(Method::get, *url, read_changes);
}

std::chrono::seconds Client::event_silence_limit() const noexcept
{
    std::uint64_t heartbeat = 60;
    if (handshake_ && handshake_->limits && handshake_->limits->heartbeat)
        heartbeat = std::clamp<std::uint64_t>(*handshake_->limits->heartbeat, 5, 60);
    return std::chrono::seconds(static_cast<std::chrono::seconds::rep>(2 * heartbeat));
}

} // namespace lantern
