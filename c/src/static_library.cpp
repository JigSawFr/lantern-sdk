// Static libraries (§ 21): a library of files over HTTP or the app's own
// file I/O, read as a server is, and what the device computes of it.
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <lantern/static_library.hpp>

#include "callbacks.hpp"

using namespace lantern_c;

namespace
{

// The app's files behind the C++ interface: each read lends it the sink.
class CallbackStaticFiles final : public lantern::StaticFiles,
                                  public CallbackHolder<lantern_static_files_callbacks>
{
  public:
    using CallbackHolder::CallbackHolder;

    [[nodiscard]] lantern::Result<void> read(
        std::string_view path, std::uint64_t offset, lantern::DownloadSink& sink) override
    {
        const lantern::String name(path, lantern::Allocator(resource()));
        lantern_download_sink lent { &sink, nullptr, nullptr, nullptr };
        bool found                  = true;
        const lantern_status status = callbacks().read(callbacks().user, view(name), offset, &lent, &found);
        if (status != LANTERN_OK)
            return std::unexpected(from_callback(
                status, nullptr, lantern::Category::transport, "the app's files failed to read"));
        if (!found)
            return std::unexpected(lantern::Error::from_status(404));
        return {};
    }
};

} // namespace

// A library, and the resource it was opened with, which its documents use
struct lantern_static_library
{
    Resource* memory; // the box's, which holds its reference
    lantern::StaticLibrary library;
};

namespace
{

const lantern::StaticLibrary* as_library(const lantern_static_library* library) noexcept
{
    return &library->library;
}

lantern::StaticLibrary* as_library(lantern_static_library* library) noexcept
{
    return &library->library;
}

Resource* resource_of(const lantern_static_library* library) noexcept
{
    return library->memory;
}

template <class T, class Out>
lantern_status give(lantern_static_library* library, lantern::Read<T>&& read, Out** out, lantern_error* error)
{
    const lantern_status status = give_read<T>(resource_of(library), std::move(read), out, error);
    if (status >= 0)
        ok(error);
    return status;
}

} // namespace

// Any source of files: the app's, or the library's over HTTP.
struct lantern_static_files
{
    lantern::StaticFiles* impl;
    void* object;
    void (*destroy)(void* object) noexcept;
};

// NOLINTBEGIN(readability-identifier-naming,misc-use-internal-linkage)
extern "C" {

LANTERN_API lantern_status lantern_static_files_create(const lantern_static_files_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_static_files** out, lantern_error* error)
{
    CallbackStaticFiles* made   = nullptr;
    const lantern_status status = make_callbacks(
        callbacks, allocator, [](const lantern_static_files_callbacks& c) { return c.read != nullptr; },
        &made, error);
    if (status != LANTERN_OK || made == nullptr)
    {
        if (out != nullptr)
            *out = nullptr;
        return status;
    }
    *out = box_new<lantern_static_files>(made->resource(),
        lantern_static_files {
            made, made, [](void* object) noexcept { unbox(static_cast<CallbackStaticFiles*>(object)); } });
    return LANTERN_OK;
}

LANTERN_API lantern_status lantern_static_files_create_http(lantern_transport* transport, const char* root,
    const char* user_agent, const lantern_allocator* allocator, lantern_static_files** out,
    lantern_error* error)
{
    if (transport == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    auto made = lantern::HttpStaticFiles::create(
        *transport->impl, text(root), text(user_agent), lantern::Allocator(resource.get()));
    if (!made)
        return fail(error, made.error());
    auto* files = box_new<lantern::HttpStaticFiles>(resource.get(), std::move(*made));
    *out        = box_new<lantern_static_files>(resource.get(),
               lantern_static_files { files, files,
            [](void* object) noexcept { unbox(static_cast<lantern::HttpStaticFiles*>(object)); } });
    return ok(error);
}

LANTERN_API void lantern_static_files_free(lantern_static_files* files)
{
    if (files == nullptr)
        return;
    files->destroy(files->object);
    unbox(files);
}

LANTERN_API bool lantern_is_static_path(const char* path)
{
    return lantern::is_static_path(text(path));
}

LANTERN_API lantern_status lantern_static_library_open(lantern_static_files* files,
    const lantern_limits* limits, const lantern_allocator* allocator, lantern_static_library** out,
    lantern_error* error)
{
    if (files == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    auto opened = lantern::StaticLibrary::open(*files->impl, decode_options(limits, resource.get()));
    if (!opened)
        return fail(error, opened.error());
    ok(error);
    if (!*opened)
        return LANTERN_ABSENT;
    *out = box_new<lantern_static_library>(
        resource.get(), lantern_static_library { resource.get(), std::move(**opened) });
    return LANTERN_OK;
}

LANTERN_API void lantern_static_library_free(lantern_static_library* library)
{
    unbox(library);
}

LANTERN_API const lantern_handshake* lantern_static_library_handshake(const lantern_static_library* library)
{
    return library == nullptr ? nullptr : wrap(&as_library(library)->handshake());
}

LANTERN_API lantern_status lantern_static_library_apps(lantern_static_library* library, const char* platform,
    const char* cursor, lantern_apps_page** out, lantern_error* error)
{
    if (library == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give(library, as_library(library)->apps(text(platform), text(cursor)), out, error);
}

LANTERN_API lantern_status lantern_static_library_titles(lantern_static_library* library,
    const char* platform, const char* cursor, lantern_titles** out, lantern_error* error)
{
    if (library == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give(library, as_library(library)->titles(text(platform), text(cursor)), out, error);
}

LANTERN_API lantern_status lantern_static_library_homebrew(lantern_static_library* library,
    const char* platform, const char* cursor, lantern_homebrew_page** out, lantern_error* error)
{
    if (library == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give(library, as_library(library)->homebrew(text(platform), text(cursor)), out, error);
}

LANTERN_API lantern_status lantern_static_library_title(lantern_static_library* library, const char* platform,
    const char* title_id, lantern_title** out, lantern_error* error)
{
    if (library == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give(library, as_library(library)->title(text(platform), text(title_id)), out, error);
}

LANTERN_API lantern_status lantern_static_library_homebrew_entry(lantern_static_library* library,
    const char* platform, const char* id, lantern_homebrew** out, lantern_error* error)
{
    if (library == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give(library, as_library(library)->homebrew_entry(text(platform), text(id)), out, error);
}

LANTERN_API lantern_status lantern_static_library_cheats(lantern_static_library* library,
    const char* platform, const char* title_id, lantern_cheat_sets** out, lantern_error* error)
{
    if (library == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give(library, as_library(library)->cheats(text(platform), text(title_id)), out, error);
}

LANTERN_API lantern_status lantern_static_library_cheat_text(
    lantern_static_library* library, const lantern_cheat_set* set, lantern_string** out, lantern_error* error)
{
    if (library == nullptr || set == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out      = nullptr;
    auto read = as_library(library)->cheat_text(*as(set));
    if (!read)
        return fail(error, read.error());
    *out = give_string(resource_of(library), std::move(*read));
    return ok(error);
}

LANTERN_API lantern_status lantern_static_library_download(lantern_static_library* library,
    const lantern_download_target* target, lantern_download_state* state, lantern_download_sink* sink,
    lantern_error* error)
{
    if (library == nullptr || target == nullptr || state == nullptr || sink == nullptr)
        return usage(error, "a NULL argument");
    const lantern_download_target t = copy_struct(target);
    lantern::DownloadTarget settings;
    settings.url    = text(t.url);
    settings.size   = t.size;
    settings.sha256 = digest_of(t.sha256);
    const auto done = as_library(library)->download(settings, state->state, *sink->impl);
    if (!done)
        return fail(error, done.error());
    return ok(error);
}

LANTERN_API size_t lantern_app_list_count(const lantern_app_list* list)
{
    return list == nullptr ? 0 : reinterpret_cast<const lantern::Vector<lantern::App>*>(list)->size();
}

LANTERN_API const lantern_app* lantern_app_list_at(const lantern_app_list* list, size_t index)
{
    if (list == nullptr)
        return nullptr;
    const auto& apps = *reinterpret_cast<const lantern::Vector<lantern::App>*>(list);
    return index < apps.size() ? wrap(&apps[index]) : nullptr;
}

LANTERN_API void lantern_app_list_free(lantern_app_list* list)
{
    unbox(reinterpret_cast<lantern::Vector<lantern::App>*>(list));
}

LANTERN_API size_t lantern_homebrew_list_count(const lantern_homebrew_list* list)
{
    return list == nullptr ? 0 : reinterpret_cast<const lantern::Vector<lantern::Homebrew>*>(list)->size();
}

LANTERN_API const lantern_homebrew* lantern_homebrew_list_at(const lantern_homebrew_list* list, size_t index)
{
    if (list == nullptr)
        return nullptr;
    const auto& entries = *reinterpret_cast<const lantern::Vector<lantern::Homebrew>*>(list);
    return index < entries.size() ? wrap(&entries[index]) : nullptr;
}

LANTERN_API void lantern_homebrew_list_free(lantern_homebrew_list* list)
{
    unbox(reinterpret_cast<lantern::Vector<lantern::Homebrew>*>(list));
}

LANTERN_API lantern_status lantern_static_library_missing(lantern_static_library* library,
    const char* platform, const lantern_missing_request* request, lantern_app_list** out,
    lantern_error* error)
{
    if (library == nullptr || request == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out                            = nullptr;
    const lantern_missing_request r = copy_struct(request);
    if ((r.installed == nullptr && r.installed_count != 0) || (r.want == nullptr && r.want_count != 0))
        return usage(error, "a NULL array with items");
    Resource* resource = resource_of(library);
    lantern::MissingRequest settings { lantern::Allocator(resource) };
    settings.installed.reserve(r.installed_count);
    for (std::size_t i = 0; i < r.installed_count; ++i)
    {
        settings.installed.emplace_back();
        settings.installed.back().app_id       = text(r.installed[i].app_id);
        settings.installed.back().version_code = r.installed[i].version_code;
    }
    for (std::size_t i = 0; i < r.want_count; ++i)
        settings.want.emplace_back(text(r.want[i]));
    auto apps = as_library(library)->missing(text(platform), settings);
    if (!apps)
        return fail(error, apps.error());
    *out = reinterpret_cast<lantern_app_list*>(
        box_new<lantern::Vector<lantern::App>>(resource, std::move(*apps)));
    return ok(error);
}

LANTERN_API lantern_status lantern_static_library_homebrew_updates(lantern_static_library* library,
    const char* platform, const lantern_homebrew_updates_request* request, lantern_homebrew_list** out,
    lantern_error* error)
{
    if (library == nullptr || request == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out                                     = nullptr;
    const lantern_homebrew_updates_request r = copy_struct(request);
    if (r.installed == nullptr && r.installed_count != 0)
        return usage(error, "a NULL array with items");
    Resource* resource = resource_of(library);
    lantern::HomebrewUpdatesRequest settings { lantern::Allocator(resource) };
    settings.installed.reserve(r.installed_count);
    for (std::size_t i = 0; i < r.installed_count; ++i)
    {
        settings.installed.emplace_back();
        settings.installed.back().id    = text(r.installed[i].id);
        settings.installed.back().build = r.installed[i].build;
    }
    auto entries = as_library(library)->homebrew_updates(text(platform), settings);
    if (!entries)
        return fail(error, entries.error());
    *out = reinterpret_cast<lantern_homebrew_list*>(
        box_new<lantern::Vector<lantern::Homebrew>>(resource, std::move(*entries)));
    return ok(error);
}

} // extern "C"
// NOLINTEND(readability-identifier-naming,misc-use-internal-linkage)
