// Events (§ 18): the stream through the app's callbacks, long polling, and
// each event's document.
#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <lantern/events.hpp>

#include "callbacks.hpp"

using namespace lantern_c;

// Where a stream resumes, and its last id as a NUL-terminated text
struct lantern_event_stream_state
{
    lantern::EventStreamState state;
    mutable std::array<char, 513> id {};
};

namespace
{

// The app's callbacks behind the C++ handler; each event's texts copied,
// so that every lantern_str is NUL-terminated.
class Handler final : public lantern::EventHandler
{
  public:
    Handler(const lantern_event_callbacks& callbacks, Resource* resource) noexcept
        : callbacks_(callbacks)
        , resource_(resource)
    {
    }

    [[nodiscard]] bool on_event(const lantern::StreamEvent& event) override
    {
        const lantern::Allocator allocator(resource_);
        const lantern::String id(event.id, allocator);
        const lantern::String data(event.data, allocator);
        lantern_stream_event out {};
        out.struct_size = sizeof(out);
        out.kind        = static_cast<lantern_event_kind>(event.kind);
        out.id          = view(id);
        out.data        = view(data);
        return callbacks_.on_event(callbacks_.user, &out);
    }

    [[nodiscard]] bool on_heartbeat() override
    {
        return callbacks_.on_heartbeat == nullptr || callbacks_.on_heartbeat(callbacks_.user);
    }

  private:
    lantern_event_callbacks callbacks_;
    Resource* resource_;
};

lantern::EventStreamState* as_state(lantern_event_stream_state* state) noexcept
{
    return &state->state;
}

const lantern::EventStreamState* as_state(const lantern_event_stream_state* state) noexcept
{
    return &state->state;
}

// An event's document, read with the schema rule, into its box.
template <class T, class Out, class Reader>
lantern_status read_event(const char* data, std::size_t size, const lantern_allocator* allocator, Out** out,
    lantern_error* error, Reader reader)
{
    if (out == nullptr || (data == nullptr && size != 0))
        return usage(error, "a NULL argument");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    auto read = reader(
        std::string_view(data == nullptr ? "" : data, size), decode_options(nullptr, resource.get()));
    if (!read)
        return fail(error, read.error());
    ok(error);
    if (!*read)
        return LANTERN_ABSENT;
    *out = reinterpret_cast<Out*>(box_new<T>(resource.get(), std::move(**read)));
    return LANTERN_OK;
}

template <class T, class C> const T* as_event(const C* event) noexcept
{
    return reinterpret_cast<const T*>(event);
}

lantern_str string_at(const lantern::Vector<lantern::String>& list, std::size_t index) noexcept
{
    return index < list.size() ? view(list[index]) : empty_str();
}

} // namespace

// NOLINTBEGIN(readability-identifier-naming,misc-use-internal-linkage)
extern "C" {

LANTERN_API const char* lantern_event_kind_name(lantern_event_kind kind)
{
    if (kind < LANTERN_EVENT_READY || kind > LANTERN_EVENT_SHUTDOWN)
        return "";
    // event_kind_name() gives views of literals: NUL-terminated
    return lantern::event_kind_name(static_cast<lantern::EventKind>(kind)).data();
}

LANTERN_API lantern_status lantern_event_stream_state_create(
    const lantern_allocator* allocator, lantern_event_stream_state** out, lantern_error* error)
{
    if (out == nullptr)
        return usage(error, "out is NULL");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    *out = box_new<lantern_event_stream_state>(resource.get());
    return ok(error);
}

LANTERN_API void lantern_event_stream_state_free(lantern_event_stream_state* state)
{
    unbox(state);
}

LANTERN_API lantern_str lantern_event_stream_state_last_id(const lantern_event_stream_state* state)
{
    if (state == nullptr)
        return empty_str();
    const std::string_view id = as_state(state)->last_id_view();
    copy_text(id, state->id.data(), state->id.size());
    return { state->id.data(), std::string_view(state->id.data()).size() };
}

LANTERN_API bool lantern_event_stream_state_set_last_id(lantern_event_stream_state* state, const char* id)
{
    if (state == nullptr)
        return false;
    const std::string_view value = text(id);
    lantern::EventStreamState& s = *as_state(state);
    if (value.size() >= s.last_id.size())
        return false;
    s.set_last_id(value);
    return s.last_id_view() == value;
}

LANTERN_API void lantern_event_stream_state_forget_position(lantern_event_stream_state* state)
{
    if (state != nullptr)
        as_state(state)->forget_position();
}

LANTERN_API uint32_t lantern_event_stream_state_retry_ms(const lantern_event_stream_state* state)
{
    return state == nullptr ? 0 : as_state(state)->retry_ms;
}

LANTERN_API uint32_t lantern_event_stream_state_failures(const lantern_event_stream_state* state)
{
    return state == nullptr ? 0 : as_state(state)->failures;
}

LANTERN_API uint32_t lantern_event_stream_state_reconnect_delay_ms(
    const lantern_event_stream_state* state, double jitter)
{
    if (state == nullptr)
        return 0;
    const auto delay = as_state(state)->reconnect_delay(jitter).count();
    return static_cast<std::uint32_t>(std::clamp<std::chrono::milliseconds::rep>(delay, 0, UINT32_MAX));
}

LANTERN_API lantern_status lantern_client_events(lantern_client* client, lantern_event_stream_state* state,
    const lantern_event_callbacks* callbacks, const char* platform, lantern_error* error)
{
    if (client == nullptr || state == nullptr || callbacks == nullptr)
        return usage(error, "a NULL argument");
    const lantern_event_callbacks c = copy_struct(callbacks);
    if (c.on_event == nullptr)
        return usage(error, "on_event is NULL");
    lantern::EventStreamState& s = *as_state(state);
    Handler handler(c, client->resource.get());
    lantern::EventsQuery query;
    query.platform   = text(platform);
    const auto ended = client->client.events(s, handler, query);
    if (!ended)
        return fail(error, ended.error());
    return ok(error);
}

LANTERN_API lantern_status lantern_client_wait_changes(lantern_client* client, const char* since,
    uint32_t wait, const char* platform, lantern_changes** out, lantern_error* error)
{
    if (client == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    lantern::EventsQuery query;
    query.platform              = text(platform);
    const lantern_status status = give_read<lantern::Changes>(
        client->resource.get(), client->client.wait_changes(text(since), wait, query), out, error);
    if (status >= 0)
        ok(error);
    return status;
}

LANTERN_API uint32_t lantern_client_event_silence_limit(const lantern_client* client)
{
    if (client == nullptr)
        return 0;
    const auto seconds = client->client.event_silence_limit().count();
    return static_cast<std::uint32_t>(std::clamp<std::chrono::seconds::rep>(seconds, 0, UINT32_MAX));
}

LANTERN_API lantern_status lantern_read_library_event(const char* data, size_t size,
    const lantern_allocator* allocator, lantern_library_event** out, lantern_error* error)
{
    return read_event<lantern::LibraryEvent>(
        data, size, allocator, out, error, [](std::string_view d, const lantern::DecodeOptions& o) {
            return lantern::read_library_event(d, o);
        });
}

LANTERN_API lantern_status lantern_read_request_event(const char* data, size_t size,
    const lantern_allocator* allocator, lantern_request_event** out, lantern_error* error)
{
    return read_event<lantern::RequestEvent>(
        data, size, allocator, out, error, [](std::string_view d, const lantern::DecodeOptions& o) {
            return lantern::read_request_event(d, o);
        });
}

LANTERN_API lantern_status lantern_read_pairing_event(const char* data, size_t size,
    const lantern_allocator* allocator, lantern_pairing_event** out, lantern_error* error)
{
    return read_event<lantern::PairingEvent>(
        data, size, allocator, out, error, [](std::string_view d, const lantern::DecodeOptions& o) {
            return lantern::read_pairing_event(d, o);
        });
}

LANTERN_API lantern_status lantern_read_save_event(const char* data, size_t size,
    const lantern_allocator* allocator, lantern_save_event** out, lantern_error* error)
{
    return read_event<lantern::SaveEvent>(data, size, allocator, out, error,
        [](std::string_view d, const lantern::DecodeOptions& o) { return lantern::read_save_event(d, o); });
}

LANTERN_API lantern_status lantern_read_sync_event(const char* data, size_t size,
    const lantern_allocator* allocator, lantern_sync_event** out, lantern_error* error)
{
    return read_event<lantern::SyncEvent>(data, size, allocator, out, error,
        [](std::string_view d, const lantern::DecodeOptions& o) { return lantern::read_sync_event(d, o); });
}

LANTERN_API lantern_status lantern_read_shutdown_event(const char* data, size_t size,
    const lantern_allocator* allocator, lantern_shutdown_event** out, lantern_error* error)
{
    return read_event<lantern::ShutdownEvent>(
        data, size, allocator, out, error, [](std::string_view d, const lantern::DecodeOptions& o) {
            return lantern::read_shutdown_event(d, o);
        });
}

LANTERN_API void lantern_library_event_free(lantern_library_event* event)
{
    unbox(reinterpret_cast<lantern::LibraryEvent*>(event));
}

LANTERN_API void lantern_request_event_free(lantern_request_event* event)
{
    unbox(reinterpret_cast<lantern::RequestEvent*>(event));
}

LANTERN_API void lantern_pairing_event_free(lantern_pairing_event* event)
{
    unbox(reinterpret_cast<lantern::PairingEvent*>(event));
}

LANTERN_API void lantern_save_event_free(lantern_save_event* event)
{
    unbox(reinterpret_cast<lantern::SaveEvent*>(event));
}

LANTERN_API void lantern_sync_event_free(lantern_sync_event* event)
{
    unbox(reinterpret_cast<lantern::SyncEvent*>(event));
}

LANTERN_API void lantern_shutdown_event_free(lantern_shutdown_event* event)
{
    unbox(reinterpret_cast<lantern::ShutdownEvent*>(event));
}

LANTERN_API size_t lantern_library_event_get_families_count(const lantern_library_event* event)
{
    return event == nullptr ? 0 : as_event<lantern::LibraryEvent>(event)->families.size();
}

LANTERN_API lantern_str lantern_library_event_get_families_at(
    const lantern_library_event* event, size_t index)
{
    return event == nullptr ? empty_str()
                            : string_at(as_event<lantern::LibraryEvent>(event)->families, index);
}

LANTERN_API size_t lantern_library_event_get_platforms_count(const lantern_library_event* event)
{
    return event == nullptr ? 0 : as_event<lantern::LibraryEvent>(event)->platforms.size();
}

LANTERN_API lantern_str lantern_library_event_get_platforms_at(
    const lantern_library_event* event, size_t index)
{
    return event == nullptr ? empty_str()
                            : string_at(as_event<lantern::LibraryEvent>(event)->platforms, index);
}

LANTERN_API lantern_str lantern_request_event_get_id(const lantern_request_event* event)
{
    return event == nullptr ? empty_str() : view(as_event<lantern::RequestEvent>(event)->id);
}

LANTERN_API lantern_str lantern_request_event_get_platform(const lantern_request_event* event)
{
    return event == nullptr ? empty_str() : view(as_event<lantern::RequestEvent>(event)->platform);
}

LANTERN_API lantern_str lantern_request_event_get_title_id(const lantern_request_event* event)
{
    return event == nullptr ? empty_str() : view(as_event<lantern::RequestEvent>(event)->title_id);
}

LANTERN_API lantern_str lantern_request_event_get_status(const lantern_request_event* event)
{
    return event == nullptr ? empty_str() : view(as_event<lantern::RequestEvent>(event)->status);
}

LANTERN_API bool lantern_request_event_get_deleted(const lantern_request_event* event)
{
    return event != nullptr && as_event<lantern::RequestEvent>(event)->deleted;
}

LANTERN_API lantern_str lantern_pairing_event_get_id(const lantern_pairing_event* event)
{
    return event == nullptr ? empty_str() : view(as_event<lantern::PairingEvent>(event)->id);
}

LANTERN_API lantern_str lantern_pairing_event_get_code(const lantern_pairing_event* event)
{
    return event == nullptr ? empty_str() : view(as_event<lantern::PairingEvent>(event)->code);
}

LANTERN_API lantern_str lantern_pairing_event_get_device(const lantern_pairing_event* event)
{
    return event == nullptr ? empty_str() : view(as_event<lantern::PairingEvent>(event)->device);
}

LANTERN_API lantern_str lantern_pairing_event_get_key(const lantern_pairing_event* event)
{
    return event == nullptr ? empty_str() : view(as_event<lantern::PairingEvent>(event)->key);
}

LANTERN_API lantern_str lantern_pairing_event_get_expires(const lantern_pairing_event* event)
{
    return event == nullptr ? empty_str() : view(as_event<lantern::PairingEvent>(event)->expires);
}

LANTERN_API lantern_str lantern_save_event_get_platform(const lantern_save_event* event)
{
    return event == nullptr ? empty_str() : view(as_event<lantern::SaveEvent>(event)->platform);
}

LANTERN_API lantern_str lantern_save_event_get_title_id(const lantern_save_event* event)
{
    return event == nullptr ? empty_str() : view(as_event<lantern::SaveEvent>(event)->title_id);
}

LANTERN_API lantern_str lantern_save_event_get_save_id(const lantern_save_event* event)
{
    return event == nullptr ? empty_str() : view(as_event<lantern::SaveEvent>(event)->save_id);
}

LANTERN_API lantern_str lantern_save_event_get_created(const lantern_save_event* event)
{
    return event == nullptr ? empty_str() : view(as_event<lantern::SaveEvent>(event)->created);
}

LANTERN_API lantern_str lantern_save_event_get_device(const lantern_save_event* event)
{
    return event == nullptr ? empty_str() : view(as_event<lantern::SaveEvent>(event)->device);
}

LANTERN_API lantern_str lantern_sync_event_get_collection(const lantern_sync_event* event)
{
    return event == nullptr ? empty_str() : view(as_event<lantern::SyncEvent>(event)->collection);
}

LANTERN_API uint64_t lantern_sync_event_get_rev(const lantern_sync_event* event)
{
    return event == nullptr ? 0 : as_event<lantern::SyncEvent>(event)->rev;
}

LANTERN_API bool lantern_shutdown_event_get_retry(const lantern_shutdown_event* event, uint64_t* out)
{
    if (event == nullptr || out == nullptr)
        return false;
    const std::optional<std::uint64_t>& retry = as_event<lantern::ShutdownEvent>(event)->retry;
    if (!retry)
        return false;
    *out = *retry;
    return true;
}

} // extern "C"
// NOLINTEND(readability-identifier-naming,misc-use-internal-linkage)
