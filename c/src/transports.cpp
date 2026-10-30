// The library's own transports, when the build has them (libcurl's,
// mbedTLS's), and the operating system's random source.
#include <algorithm>
#include <chrono>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <span>

#include <lantern/device_key.hpp>

#include "callbacks.hpp"

#ifdef LANTERN_C_HAS_CURL
#include <curl/curl.h>

#include "curl_transport.hpp"
#endif
#ifdef LANTERN_C_HAS_MBEDTLS
#include "mbedtls_transport.hpp"
#endif

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// clang-format off
#include <windows.h>
#include <bcrypt.h>
// clang-format on
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <stdlib.h>
#define LANTERN_C_ARC4RANDOM
#elif defined(__linux__) && !defined(__ANDROID__)
#include <sys/random.h>
#include <sys/types.h>
#define LANTERN_C_GETRANDOM
#elif defined(__ANDROID__) || defined(__ANDROID_API__)
#include <fcntl.h>
#include <unistd.h>
#define LANTERN_C_URANDOM
#endif

using namespace lantern_c;

namespace
{

// The operating system's cryptographic generator, one function per system
#ifdef _WIN32
#define LANTERN_C_SYSTEM_RANDOM
lantern::Result<void> system_bytes(std::span<std::uint8_t> out) noexcept
{
    for (std::size_t done = 0; done < out.size();)
    {
        const std::size_t step = std::min<std::size_t>(out.size() - done, ULONG_MAX);
        if (BCryptGenRandom(
                nullptr, out.data() + done, static_cast<ULONG>(step), BCRYPT_USE_SYSTEM_PREFERRED_RNG)
            != 0)
            return lantern::fail(lantern::Category::storage, "BCryptGenRandom failed");
        done += step;
    }
    return {};
}
#endif
#ifdef LANTERN_C_ARC4RANDOM
#define LANTERN_C_SYSTEM_RANDOM
lantern::Result<void> system_bytes(std::span<std::uint8_t> out) noexcept
{
    arc4random_buf(out.data(), out.size());
    return {};
}
#endif
#ifdef LANTERN_C_GETRANDOM
#define LANTERN_C_SYSTEM_RANDOM
lantern::Result<void> system_bytes(std::span<std::uint8_t> out) noexcept
{
    for (std::size_t done = 0; done < out.size();)
    {
        const ssize_t got = getrandom(out.data() + done, out.size() - done, 0);
        if (got < 0)
            return lantern::fail(lantern::Category::storage, "getrandom failed");
        done += static_cast<std::size_t>(got);
    }
    return {};
}
#endif
#ifdef LANTERN_C_URANDOM
#define LANTERN_C_SYSTEM_RANDOM
lantern::Result<void> system_bytes(std::span<std::uint8_t> out) noexcept
{
    const int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return lantern::fail(lantern::Category::storage, "no /dev/urandom");
    for (std::size_t done = 0; done < out.size();)
    {
        const ssize_t got = ::read(fd, out.data() + done, out.size() - done);
        if (got <= 0)
        {
            ::close(fd);
            return lantern::fail(lantern::Category::storage, "/dev/urandom gave nothing");
        }
        done += static_cast<std::size_t>(got);
    }
    ::close(fd);
    return {};
}
#endif

// lantern_random is the app's callbacks; the system's goes through them.
lantern_status system_fill(void* user, std::uint8_t* out, std::size_t size)
{
#ifdef LANTERN_C_SYSTEM_RANDOM
    static_cast<void>(user);
    return system_bytes(std::span(out, size)) ? LANTERN_OK : LANTERN_ERROR_STORAGE;
#else
    static_cast<void>(user);
    static_cast<void>(out);
    static_cast<void>(size);
    return LANTERN_ERROR_UNSUPPORTED;
#endif
}

// The transports this build has
#ifdef LANTERN_C_HAS_CURL
constexpr bool has_curl = true;
#else
constexpr bool has_curl = false;
#endif
#ifdef LANTERN_C_HAS_MBEDTLS
constexpr bool has_mbedtls = true;
#else
constexpr bool has_mbedtls = false;
#endif

template <class Impl> lantern_transport* give_transport(Resource* resource, Impl&& made)
{
    Impl* impl = box_new<Impl>(resource, std::forward<Impl>(made));
    return box_new<lantern_transport>(resource,
        lantern_transport { impl, impl, [](void* object) noexcept { unbox(static_cast<Impl*>(object)); } });
}

} // namespace

// NOLINTBEGIN(readability-identifier-naming,misc-use-internal-linkage)
extern "C" {

LANTERN_API lantern_status lantern_random_create_system(
    const lantern_allocator* allocator, lantern_random** out, lantern_error* error)
{
#ifdef LANTERN_C_SYSTEM_RANDOM
    // The system's generator holds no state
    lantern_random_callbacks callbacks {};
    callbacks.struct_size = sizeof(callbacks);
    callbacks.fill        = system_fill;
    return lantern_random_create(&callbacks, allocator, out, error);
#else
    static_cast<void>(allocator);
    if (out != nullptr)
        *out = nullptr;
    return fail(error, lantern::Category::unsupported, "no system random source on this platform: give one");
#endif
}

LANTERN_API bool lantern_has_transport(lantern_transport_kind kind)
{
    return (kind == LANTERN_TRANSPORT_CURL && has_curl) || (kind == LANTERN_TRANSPORT_MBEDTLS && has_mbedtls);
}

LANTERN_API lantern_status lantern_curl_global_init(lantern_error* error)
{
#ifdef LANTERN_C_HAS_CURL
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
        return fail(error, lantern::Category::transport, "curl_global_init failed");
    return ok(error);
#else
    return fail(error, lantern::Category::unsupported, "this build has no libcurl transport");
#endif
}

LANTERN_API lantern_status lantern_transport_create_curl(const lantern_curl_options* options,
    const lantern_allocator* allocator, lantern_transport** out, lantern_error* error)
{
    if (out == nullptr)
        return usage(error, "out is NULL");
    *out = nullptr;
#ifdef LANTERN_C_HAS_CURL
    const lantern_curl_options o = copy_struct(options);
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    lantern::curl::Options settings;
    settings.trust   = o.trust == nullptr ? nullptr : &o.trust->trust;
    settings.ca_file = text(o.ca_file);
    if (o.connect_timeout_ms != 0)
        settings.connect_timeout = std::chrono::milliseconds(o.connect_timeout_ms);
    if (o.stall_timeout_s != 0)
        settings.stall_timeout = std::chrono::seconds(o.stall_timeout_s);
    auto made = lantern::curl::CurlTransport::create(settings);
    if (!made)
        return fail(error, made.error());
    *out = give_transport(resource.get(), std::move(*made));
    return ok(error);
#else
    static_cast<void>(options);
    static_cast<void>(allocator);
    return fail(error, lantern::Category::unsupported, "this build has no libcurl transport");
#endif
}

LANTERN_API lantern_status lantern_transport_create_mbedtls(const lantern_mbedtls_options* options,
    const lantern_allocator* allocator, lantern_transport** out, lantern_error* error)
{
    if (out == nullptr)
        return usage(error, "out is NULL");
    *out = nullptr;
#ifdef LANTERN_C_HAS_MBEDTLS
    const lantern_mbedtls_options o = copy_struct(options);
    if (o.random == nullptr)
        return usage(error, "the mbedTLS transport needs a random source");
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    lantern::mbedtls::Options settings;
    settings.random = o.random;
    settings.trust  = o.trust == nullptr ? nullptr : &o.trust->trust;
    settings.ca_pem = text(o.ca_pem);
    if (o.timeout_ms != 0)
        settings.timeout = std::chrono::milliseconds(o.timeout_ms);
    auto made = lantern::mbedtls::MbedTlsTransport::create(settings);
    if (!made)
        return fail(error, made.error());
    *out = give_transport(resource.get(), std::move(*made));
    return ok(error);
#else
    static_cast<void>(options);
    static_cast<void>(allocator);
    return fail(error, lantern::Category::unsupported, "this build has no mbedTLS transport");
#endif
}

} // extern "C"
// NOLINTEND(readability-identifier-naming,misc-use-internal-linkage)
