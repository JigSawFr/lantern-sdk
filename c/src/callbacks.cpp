// The app's callbacks behind the C++ library's interfaces, and the objects
// made of them.
#include "callbacks.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>

using namespace lantern_c;

namespace
{

// A NUL-terminated copy, since every lantern_str the app gets is one.
lantern::String terminated(std::string_view value, Resource* resource)
{
    return lantern::String(value, lantern::Allocator(resource));
}

lantern_str str(const lantern::String& value) noexcept
{
    return view(value);
}

lantern::Error callback_error(
    lantern_status status, const lantern_error& reported, lantern::Category fallback, std::string_view detail)
{
    return from_callback(status, &reported, fallback, detail);
}

lantern_error fresh_error() noexcept
{
    lantern_error error {};
    error.struct_size = sizeof(lantern_error);
    return error;
}

} // namespace

lantern::Result<void> lantern_random::fill(std::span<std::uint8_t> out)
{
    const lantern_status status = callbacks().fill(callbacks().user, out.data(), out.size());
    if (status != LANTERN_OK)
        return std::unexpected(
            from_callback(status, nullptr, lantern::Category::storage, "the app's random source failed"));
    return {};
}

std::int64_t lantern_clock::unix_seconds()
{
    return callbacks().unix_seconds(callbacks().user);
}

lantern::Result<std::optional<lantern::Credentials>> lantern_credential_store::load(
    std::string_view uid, lantern::Allocator allocator)
{
    const lantern::String key = terminated(uid, resource());
    std::optional<lantern::Credentials> kept;
    lantern_credentials_sink sink { &kept, allocator };
    const lantern_status status = callbacks().load(callbacks().user, str(key), &sink);
    if (status != LANTERN_OK)
        return std::unexpected(from_callback(
            status, nullptr, lantern::Category::storage, "the app's credential store failed to load"));
    return kept;
}

lantern::Result<void> lantern_credential_store::store(
    std::string_view uid, const lantern::Credentials& credentials)
{
    const lantern::String key = terminated(uid, resource());
    lantern_credentials out {};
    out.struct_size = sizeof(out);
    out.token       = str(credentials.token);
    if (credentials.key)
    {
        out.has_key = true;
        std::memcpy(out.key_seed, credentials.key->data(), credentials.key->size());
    }
    if (credentials.spki)
    {
        out.has_spki = true;
        copy_digest(*credentials.spki, out.spki);
    }
    const lantern_status status = callbacks().store(callbacks().user, str(key), &out);
    // The seed was copied here: wipe it
    std::memset(out.key_seed, 0, sizeof(out.key_seed));
    if (status != LANTERN_OK)
        return std::unexpected(from_callback(
            status, nullptr, lantern::Category::storage, "the app's credential store failed to store"));
    return {};
}

lantern::Result<void> lantern_credential_store::erase(std::string_view uid)
{
    const lantern::String key   = terminated(uid, resource());
    const lantern_status status = callbacks().erase(callbacks().user, str(key));
    if (status != LANTERN_OK)
        return std::unexpected(from_callback(
            status, nullptr, lantern::Category::storage, "the app's credential store failed to erase"));
    return {};
}

lantern::Result<std::optional<lantern::PinnedKey>> lantern_pin_store::load(
    std::string_view platform, std::string_view id)
{
    const lantern::String p = terminated(platform, resource());
    const lantern::String i = terminated(id, resource());
    lantern_pin pin {};
    bool found                  = false;
    const lantern_status status = callbacks().load(callbacks().user, str(p), str(i), &pin, &found);
    if (status != LANTERN_OK)
        return std::unexpected(
            from_callback(status, nullptr, lantern::Category::storage, "the app's pin store failed to load"));
    if (!found)
        return std::optional<lantern::PinnedKey> {};
    lantern::PinnedKey out;
    out.is_signed = pin.is_signed;
    std::memcpy(out.public_key.data(), pin.public_key, out.public_key.size());
    return out;
}

lantern::Result<void> lantern_pin_store::store(
    std::string_view platform, std::string_view id, const lantern::PinnedKey& pin)
{
    const lantern::String p = terminated(platform, resource());
    const lantern::String i = terminated(id, resource());
    lantern_pin out {};
    out.is_signed = pin.is_signed;
    std::memcpy(out.public_key, pin.public_key.data(), pin.public_key.size());
    const lantern_status status = callbacks().store(callbacks().user, str(p), str(i), &out);
    if (status != LANTERN_OK)
        return std::unexpected(from_callback(
            status, nullptr, lantern::Category::storage, "the app's pin store failed to store"));
    return {};
}

void lantern_deprecation_log::deprecated(
    std::string_view url, std::string_view deprecation, std::string_view sunset)
{
    const lantern::String u = terminated(url, resource());
    const lantern::String d = terminated(deprecation, resource());
    const lantern::String s = terminated(sunset, resource());
    callbacks().deprecated(callbacks().user, str(u), str(d), str(s));
}

lantern::Result<void> CallbackDownloadSink::write(std::span<const std::byte> bytes)
{
    // Nothing to hand on: the app's write() never sees an empty chunk
    if (bytes.empty())
        return {};
    const lantern_status status = callbacks().write(
        callbacks().user, reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size());
    if (status != LANTERN_OK)
        return std::unexpected(from_callback(
            status, nullptr, lantern::Category::storage, "the app's download sink failed to write"));
    return {};
}

lantern::Result<void> CallbackDownloadSink::restart()
{
    const lantern_status status = callbacks().restart(callbacks().user);
    if (status != LANTERN_OK)
        return std::unexpected(from_callback(
            status, nullptr, lantern::Category::storage, "the app's download sink failed to restart"));
    return {};
}

lantern::Result<void> CallbackUploadSource::read(std::uint64_t offset, std::span<std::byte> out)
{
    const lantern_status status
        = callbacks().read(callbacks().user, offset, reinterpret_cast<std::uint8_t*>(out.data()), out.size());
    if (status != LANTERN_OK)
        return std::unexpected(from_callback(
            status, nullptr, lantern::Category::storage, "the app's upload source failed to read"));
    return {};
}

lantern::Result<std::optional<std::uint64_t>> lantern_data_probe::size(std::string_view path)
{
    const lantern::String p     = terminated(path, resource());
    std::uint64_t size          = 0;
    bool present                = false;
    const lantern_status status = callbacks().size(callbacks().user, str(p), &size, &present);
    if (status != LANTERN_OK)
        return std::unexpected(
            from_callback(status, nullptr, lantern::Category::storage, "the app's data probe failed"));
    if (!present)
        return std::optional<std::uint64_t> {};
    return size;
}

lantern::Result<lantern::Digest> lantern_data_probe::sha256(std::string_view path)
{
    const lantern::String p = terminated(path, resource());
    lantern::Digest digest {};
    const lantern_status status = callbacks().sha256(callbacks().user, str(p), digest.data());
    if (status != LANTERN_OK)
        return std::unexpected(
            from_callback(status, nullptr, lantern::Category::storage, "the app's data probe failed"));
    return digest;
}

lantern::Result<void> lantern_udp_socket::send_to(
    std::string_view address, std::uint16_t port, std::span<const std::byte> bytes)
{
    const lantern::String a     = terminated(address, resource());
    const lantern_status status = callbacks().send_to(
        callbacks().user, a.c_str(), port, reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size());
    if (status != LANTERN_OK)
        return std::unexpected(from_callback(
            status, nullptr, lantern::Category::transport, "the app's UDP socket failed to send"));
    return {};
}

lantern::Result<std::optional<lantern::Datagram>> lantern_udp_socket::receive(
    std::span<std::byte> buffer, std::chrono::milliseconds timeout)
{
    lantern_datagram datagram {};
    bool received           = false;
    const auto milliseconds = std::clamp<std::chrono::milliseconds::rep>(timeout.count(), 0, UINT32_MAX);
    const lantern_status status
        = callbacks().receive(callbacks().user, reinterpret_cast<std::uint8_t*>(buffer.data()), buffer.size(),
            static_cast<std::uint32_t>(milliseconds), &datagram, &received);
    if (status != LANTERN_OK)
        return std::unexpected(from_callback(
            status, nullptr, lantern::Category::transport, "the app's UDP socket failed to receive"));
    if (!received)
        return std::optional<lantern::Datagram> {};
    lantern::Datagram out;
    out.size                                       = std::min(datagram.size, buffer.size());
    datagram.address[sizeof(datagram.address) - 1] = '\0';
    const std::string_view address(datagram.address);
    out.address_size = std::min(address.size(), out.address.size());
    std::copy_n(address.begin(), out.address_size, out.address.begin());
    out.port = datagram.port;
    return out;
}

lantern::Result<void> CallbackTransport::send(
    const lantern::Request& request, lantern::ResponseHandler& handler)
{
    // Every lantern_str the app gets is NUL-terminated: the URL and each
    // header are copied for the call
    const lantern::Allocator allocator(resource());
    const lantern::String url     = terminated(request.url, resource());
    const std::string_view method = lantern::method_name(request.method);
    lantern::Vector<lantern::String> texts(allocator);
    texts.reserve(request.headers.size() * 2);
    lantern::Vector<lantern_header> headers(allocator);
    headers.reserve(request.headers.size());
    for (const lantern::Header& header : request.headers)
    {
        texts.emplace_back(header.name);
        const lantern::String& name = texts.back();
        texts.emplace_back(header.value);
        const lantern::String& value = texts.back();
        headers.push_back({ str(name), str(value) });
    }
    lantern_request out {};
    out.struct_size  = sizeof(out);
    out.method       = static_cast<lantern_method>(request.method);
    out.method_name  = { method.data(), method.size() };
    out.url          = str(url);
    out.headers      = headers.data();
    out.header_count = headers.size();
    out.body         = reinterpret_cast<const std::uint8_t*>(request.body.data());
    out.body_size    = request.body.size();
    lantern_response response { &handler };
    lantern_error error         = fresh_error();
    const lantern_status status = callbacks().send(callbacks().user, &out, &response, &error);
    if (status != LANTERN_OK)
        return std::unexpected(
            callback_error(status, error, lantern::Category::transport, "the app's transport failed"));
    return {};
}

// NOLINTBEGIN(readability-identifier-naming,misc-use-internal-linkage)
extern "C" {

LANTERN_API lantern_status lantern_random_create(const lantern_random_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_random** out, lantern_error* error)
{
    return make_callbacks(
        callbacks, allocator, [](const lantern_random_callbacks& c) { return c.fill != nullptr; }, out,
        error);
}

LANTERN_API void lantern_random_free(lantern_random* random)
{
    unbox(random);
}

LANTERN_API lantern_status lantern_clock_create(const lantern_clock_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_clock** out, lantern_error* error)
{
    return make_callbacks(
        callbacks, allocator, [](const lantern_clock_callbacks& c) { return c.unix_seconds != nullptr; }, out,
        error);
}

LANTERN_API void lantern_clock_free(lantern_clock* clock)
{
    unbox(clock);
}

LANTERN_API lantern_status lantern_credentials_sink_set(
    lantern_credentials_sink* sink, const lantern_credentials* credentials)
{
    if (sink == nullptr || credentials == nullptr)
        return LANTERN_ERROR_USAGE;
    const lantern_credentials copy = copy_struct(credentials);
    lantern::Credentials kept(sink->allocator);
    kept.token = to_string(copy.token, sink->allocator);
    if (copy.has_key)
    {
        lantern::KeySeed seed {};
        std::memcpy(seed.data(), copy.key_seed, seed.size());
        kept.key = seed;
    }
    if (copy.has_spki)
        kept.spki = digest_of(copy.spki);
    sink->out->emplace(std::move(kept));
    return LANTERN_OK;
}

LANTERN_API lantern_status lantern_credential_store_create(const lantern_credential_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_credential_store** out, lantern_error* error)
{
    return make_callbacks(
        callbacks, allocator,
        [](const lantern_credential_callbacks& c) {
            return c.load != nullptr && c.store != nullptr && c.erase != nullptr;
        },
        out, error);
}

LANTERN_API void lantern_credential_store_free(lantern_credential_store* store)
{
    unbox(store);
}

LANTERN_API lantern_status lantern_pin_store_create(const lantern_pin_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_pin_store** out, lantern_error* error)
{
    return make_callbacks(
        callbacks, allocator,
        [](const lantern_pin_callbacks& c) { return c.load != nullptr && c.store != nullptr; }, out, error);
}

LANTERN_API void lantern_pin_store_free(lantern_pin_store* store)
{
    unbox(store);
}

LANTERN_API lantern_status lantern_deprecation_log_create(const lantern_deprecation_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_deprecation_log** out, lantern_error* error)
{
    return make_callbacks(
        callbacks, allocator, [](const lantern_deprecation_callbacks& c) { return c.deprecated != nullptr; },
        out, error);
}

LANTERN_API void lantern_deprecation_log_free(lantern_deprecation_log* log)
{
    unbox(log);
}

LANTERN_API lantern_status lantern_download_sink_create(const lantern_download_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_download_sink** out, lantern_error* error)
{
    CallbackDownloadSink* made  = nullptr;
    const lantern_status status = make_callbacks(
        callbacks, allocator,
        [](const lantern_download_callbacks& c) { return c.write != nullptr && c.restart != nullptr; }, &made,
        error);
    if (status != LANTERN_OK || made == nullptr)
    {
        if (out != nullptr)
            *out = nullptr;
        return status;
    }
    *out = give_sink(made->resource(), made, nullptr);
    return LANTERN_OK;
}

LANTERN_API void lantern_download_sink_free(lantern_download_sink* sink)
{
    if (sink == nullptr)
        return;
    if (sink->destroy != nullptr)
        sink->destroy(sink->object);
    unbox(sink);
}

LANTERN_API lantern_status lantern_download_sink_write(
    lantern_download_sink* sink, const uint8_t* bytes, size_t size, lantern_error* error)
{
    if (sink == nullptr || (bytes == nullptr && size != 0))
        return usage(error, "a NULL argument");
    const auto written = sink->impl->write(std::as_bytes(std::span(bytes, bytes == nullptr ? 0 : size)));
    if (!written)
        return fail(error, written.error());
    return ok(error);
}

LANTERN_API lantern_status lantern_download_sink_restart(lantern_download_sink* sink, lantern_error* error)
{
    if (sink == nullptr)
        return usage(error, "sink is NULL");
    const auto restarted = sink->impl->restart();
    if (!restarted)
        return fail(error, restarted.error());
    return ok(error);
}

LANTERN_API lantern_status lantern_upload_source_create(const lantern_upload_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_upload_source** out, lantern_error* error)
{
    CallbackUploadSource* made  = nullptr;
    const lantern_status status = make_callbacks(
        callbacks, allocator, [](const lantern_upload_callbacks& c) { return c.read != nullptr; }, &made,
        error);
    if (status != LANTERN_OK || made == nullptr)
    {
        if (out != nullptr)
            *out = nullptr;
        return status;
    }
    *out = give_source(made->resource(), made, nullptr);
    return LANTERN_OK;
}

LANTERN_API void lantern_upload_source_free(lantern_upload_source* source)
{
    if (source == nullptr)
        return;
    if (source->destroy != nullptr)
        source->destroy(source->object);
    unbox(source);
}

LANTERN_API lantern_status lantern_data_probe_create(const lantern_data_probe_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_data_probe** out, lantern_error* error)
{
    return make_callbacks(
        callbacks, allocator,
        [](const lantern_data_probe_callbacks& c) { return c.size != nullptr && c.sha256 != nullptr; }, out,
        error);
}

LANTERN_API void lantern_data_probe_free(lantern_data_probe* probe)
{
    unbox(probe);
}

LANTERN_API lantern_status lantern_udp_socket_create(const lantern_udp_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_udp_socket** out, lantern_error* error)
{
    return make_callbacks(
        callbacks, allocator,
        [](const lantern_udp_callbacks& c) { return c.send_to != nullptr && c.receive != nullptr; }, out,
        error);
}

LANTERN_API void lantern_udp_socket_free(lantern_udp_socket* socket)
{
    unbox(socket);
}

LANTERN_API lantern_status lantern_transport_create(const lantern_transport_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_transport** out, lantern_error* error)
{
    CallbackTransport* made     = nullptr;
    const lantern_status status = make_callbacks(
        callbacks, allocator, [](const lantern_transport_callbacks& c) { return c.send != nullptr; }, &made,
        error);
    if (status != LANTERN_OK || made == nullptr)
    {
        if (out != nullptr)
            *out = nullptr;
        return status;
    }
    const ScopedResource resource(allocator);
    *out = box_new<lantern_transport>(resource.get(),
        lantern_transport {
            made, made, [](void* object) noexcept { unbox(static_cast<CallbackTransport*>(object)); } });
    return LANTERN_OK;
}

LANTERN_API void lantern_transport_free(lantern_transport* transport)
{
    if (transport == nullptr)
        return;
    transport->destroy(transport->object);
    unbox(transport);
}

LANTERN_API bool lantern_response_status(lantern_response* response, uint16_t status)
{
    return response != nullptr && response->handler->on_status(status);
}

LANTERN_API bool lantern_response_header(
    lantern_response* response, const char* name, size_t name_size, const char* value, size_t value_size)
{
    if (response == nullptr || (name == nullptr && name_size != 0) || (value == nullptr && value_size != 0))
        return false;
    return response->handler->on_header(std::string_view(name == nullptr ? "" : name, name_size),
        std::string_view(value == nullptr ? "" : value, value_size));
}

LANTERN_API bool lantern_response_body(lantern_response* response, const uint8_t* bytes, size_t size)
{
    if (response == nullptr || (bytes == nullptr && size != 0))
        return false;
    if (size == 0)
        return true;
    return response->handler->on_body(std::as_bytes(std::span(bytes, size)));
}

} // extern "C"
// NOLINTEND(readability-identifier-naming,misc-use-internal-linkage)
