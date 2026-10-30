// The app's callbacks, seen as the C++ library's interfaces: each opaque
// type of lantern.h made from a struct of function pointers is one of these.
#pragma once

#include <lantern/lantern.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/client.hpp>
#include <lantern/credentials.hpp>
#include <lantern/device_key.hpp>
#include <lantern/discovery.hpp>
#include <lantern/download.hpp>
#include <lantern/encrypted_save.hpp>
#include <lantern/homebrew.hpp>
#include <lantern/http_signature.hpp>
#include <lantern/pinning.hpp>
#include <lantern/tls.hpp>
#include <lantern/transport.hpp>

#include "internal.hpp"

// Each holds a reference to the resource it was made with, and calls the
// app's `release` when it goes.
template <class Callbacks> class CallbackHolder
{
  public:
    CallbackHolder(lantern_c::Resource* memory, const Callbacks& given) noexcept
        : resource_(memory)
        , callbacks_(given)
    {
    }
    CallbackHolder(const CallbackHolder&)            = delete;
    CallbackHolder& operator=(const CallbackHolder&) = delete;
    CallbackHolder(CallbackHolder&&)                 = delete;
    CallbackHolder& operator=(CallbackHolder&&)      = delete;
    ~CallbackHolder()
    {
        if (callbacks_.release != nullptr)
            callbacks_.release(callbacks_.user);
    }

    // The resource it was made with.
    [[nodiscard]] lantern_c::Resource* resource() const noexcept { return resource_.get(); }

  protected:
    [[nodiscard]] const Callbacks& callbacks() const noexcept { return callbacks_; }

  private:
    lantern_c::ResourceRef resource_;
    Callbacks callbacks_;
};

struct lantern_random final : lantern::RandomSource, CallbackHolder<lantern_random_callbacks>
{
    using CallbackHolder::CallbackHolder;
    [[nodiscard]] lantern::Result<void> fill(std::span<std::uint8_t> out) override;
};

struct lantern_clock final : lantern::Clock, CallbackHolder<lantern_clock_callbacks>
{
    using CallbackHolder::CallbackHolder;
    [[nodiscard]] std::int64_t unix_seconds() override;
};

struct lantern_credential_store final : lantern::CredentialStore, CallbackHolder<lantern_credential_callbacks>
{
    using CallbackHolder::CallbackHolder;
    [[nodiscard]] lantern::Result<std::optional<lantern::Credentials>> load(
        std::string_view uid, lantern::Allocator allocator) override;
    [[nodiscard]] lantern::Result<void> store(
        std::string_view uid, const lantern::Credentials& credentials) override;
    [[nodiscard]] lantern::Result<void> erase(std::string_view uid) override;
};

struct lantern_pin_store final : lantern::KeyPinStore, CallbackHolder<lantern_pin_callbacks>
{
    using CallbackHolder::CallbackHolder;
    [[nodiscard]] lantern::Result<std::optional<lantern::PinnedKey>> load(
        std::string_view platform, std::string_view id) override;
    [[nodiscard]] lantern::Result<void> store(
        std::string_view platform, std::string_view id, const lantern::PinnedKey& pin) override;
};

struct lantern_deprecation_log final : lantern::DeprecationLog, CallbackHolder<lantern_deprecation_callbacks>
{
    using CallbackHolder::CallbackHolder;
    void deprecated(std::string_view url, std::string_view deprecation, std::string_view sunset) override;
};

class CallbackDownloadSink final : public lantern::DownloadSink,
                                   public CallbackHolder<lantern_download_callbacks>
{
  public:
    using CallbackHolder::CallbackHolder;
    [[nodiscard]] lantern::Result<void> write(std::span<const std::byte> bytes) override;
    [[nodiscard]] lantern::Result<void> restart() override;
};

class CallbackUploadSource final : public lantern::UploadSource,
                                   public CallbackHolder<lantern_upload_callbacks>
{
  public:
    using CallbackHolder::CallbackHolder;
    [[nodiscard]] lantern::Result<void> read(std::uint64_t offset, std::span<std::byte> out) override;
};

struct lantern_data_probe final : lantern::DataProbe, CallbackHolder<lantern_data_probe_callbacks>
{
    using CallbackHolder::CallbackHolder;
    [[nodiscard]] lantern::Result<std::optional<std::uint64_t>> size(std::string_view path) override;
    [[nodiscard]] lantern::Result<lantern::Digest> sha256(std::string_view path) override;
};

struct lantern_udp_socket final : lantern::UdpSocket, CallbackHolder<lantern_udp_callbacks>
{
    using CallbackHolder::CallbackHolder;
    [[nodiscard]] lantern::Result<void> send_to(
        std::string_view address, std::uint16_t port, std::span<const std::byte> bytes) override;
    [[nodiscard]] lantern::Result<std::optional<lantern::Datagram>> receive(
        std::span<std::byte> buffer, std::chrono::milliseconds timeout) override;
};

// The app's transport, through its callbacks.
class CallbackTransport final : public lantern::Transport, public CallbackHolder<lantern_transport_callbacks>
{
  public:
    using CallbackHolder::CallbackHolder;
    [[nodiscard]] lantern::Result<void> send(
        const lantern::Request& request, lantern::ResponseHandler& handler) override;
};

// Any transport: the app's, or one of the library's. `destroy` frees
// `object`, the box `impl` lives in.
struct lantern_transport
{
    lantern::Transport* impl;
    void* object;
    void (*destroy)(void* object) noexcept;
};

// Any download sink: the app's, or one of the library's (a decrypting
// one, which `decrypting` names). `destroy` frees `object`, the box of
// `impl`; null for a sink the library lends a callback.
struct lantern_download_sink
{
    lantern::DownloadSink* impl;
    void* object;
    void (*destroy)(void* object) noexcept;
    lantern::DecryptingSink* decrypting;
};

// Any upload source: the app's, or an encrypting one, which `encrypting`
// names; `key_id` is the text describe() points the request to.
struct lantern_upload_source
{
    lantern::UploadSource* impl;
    void* object;
    void (*destroy)(void* object) noexcept;
    lantern::EncryptingSource* encrypting;
    std::array<char, 17> key_id;
};

struct lantern_response
{
    lantern::ResponseHandler* handler;
};

struct lantern_credentials_sink
{
    std::optional<lantern::Credentials>* out;
    lantern::Allocator allocator;
};

// A server's key: ServerTrust itself.
struct lantern_trust final
{
    lantern::ServerTrust trust;
};

namespace lantern_c
{

// The transport the app's NULL-checked handle stands for.
[[nodiscard]] inline lantern::Transport* impl(lantern_transport* transport) noexcept
{
    return transport == nullptr ? nullptr : transport->impl;
}

// Makes the opaque object of a callbacks struct, after checking that the
// functions it needs are there.
template <class Object, class Callbacks, class Complete>
lantern_status make_callbacks(const Callbacks* callbacks, const lantern_allocator* allocator,
    Complete complete, Object** out, lantern_error* error)
{
    if (out == nullptr)
        return usage(error, "out is NULL");
    *out = nullptr;
    if (callbacks == nullptr)
        return usage(error, "callbacks is NULL");
    const Callbacks copy = copy_struct(callbacks);
    if (!complete(copy))
        return usage(error, "a callback the object needs is NULL");
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    *out = box_new<Object>(resource.get(), resource.get(), copy);
    return ok(error);
}

} // namespace lantern_c

// A download in progress, and the text it was loaded from (its unknown
// members are kept when it is saved again).
struct lantern_download_state
{
    lantern_c::Resource* resource;
    lantern::DownloadState state;
    lantern::String loaded;
    // Loaded from a document of a newer schema: never saved over.
    bool newer = false;

    explicit lantern_download_state(lantern_c::Resource* memory)
        : resource(memory)
        , loaded(lantern::Allocator(memory))
    {
    }
};

struct lantern_upload_progress
{
    lantern_c::Resource* resource;
    lantern::UploadProgress progress;
    lantern::String loaded;
    bool newer = false;

    explicit lantern_upload_progress(lantern_c::Resource* memory)
        : resource(memory)
        , loaded(lantern::Allocator(memory))
    {
    }
};

// The client, and the resource every document it reads comes from.
struct lantern_client
{
    lantern_c::ResourceRef resource;
    lantern::Client client;

    lantern_client(lantern_c::Resource* memory, lantern::Client&& made)
        : resource(memory)
        , client(std::move(made))
    {
    }
};

// A pairing in progress, and its server key's short fingerprint as a
// NUL-terminated text.
struct lantern_pairing
{
    lantern::Pairing pairing;
    std::array<char, 20> fingerprint {};

    explicit lantern_pairing(lantern::Pairing&& made)
        : pairing(std::move(made))
    {
        const std::string_view view = pairing.fingerprint_view();
        std::copy_n(view.data(), std::min(view.size(), fingerprint.size() - 1), fingerprint.begin());
    }
};

namespace lantern_c
{

// The handle of a sink in its box, `impl` its own box (freed with it), or
// null for one lent to a callback.
template <class Impl>
lantern_download_sink* give_sink(Resource* resource, Impl* impl, lantern::DecryptingSink* decrypting)
{
    return box_new<lantern_download_sink>(resource,
        lantern_download_sink {
            impl, impl, [](void* object) noexcept { unbox(static_cast<Impl*>(object)); }, decrypting });
}

template <class Impl>
lantern_upload_source* give_source(Resource* resource, Impl* impl, lantern::EncryptingSource* encrypting)
{
    return box_new<lantern_upload_source>(resource,
        lantern_upload_source {
            impl, impl, [](void* object) noexcept { unbox(static_cast<Impl*>(object)); }, encrypting, {} });
}

} // namespace lantern_c
