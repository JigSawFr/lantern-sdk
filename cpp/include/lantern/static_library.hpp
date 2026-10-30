// Static libraries (SPEC.md § 21): a library served as files, on a web host
// or read from a USB key or an SD card, with no server at all.
//
// - StaticFiles is where the files come from: HttpStaticFiles reads them
//   over the app's Transport (HTTPS, or HTTP on loopback, § 2), any other
//   source is the app's own file I/O, behind the same small interface.
// - StaticLibrary reads lantern.json (a handshake with `static`, base
//   "."), then the pages, titles, homebrew entries and cheat sets where
//   § 21.1 puts them, as JSON whatever their Content-Type, each with the
//   `schema` rule and § 13's bounds, its pages chained by their cursors.
//   Every `file` a document gives must be a path relative to the root
//   (L-21.1-2), and every file is checked by its size and SHA-256 (§ 6.6).
// - What a static library cannot answer, the client computes from its
//   pages (L-21.3-2): what the device is missing, by § 6.3's rules over the
//   whole listing of its platform, and the updates of homebrew.
//
// A static library has no pairing, no token and no rating cap: nothing
// secret goes to it, and it is public to whoever reaches its files.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/document.hpp>
#include <lantern/download.hpp>
#include <lantern/error.hpp>
#include <lantern/memory.hpp>
#include <lantern/transport.hpp>
#include <lantern/types.hpp>

namespace lantern
{

// § 21.1: a path relative to the root, as a document's `file` or image
// `url` gives it: no scheme, no leading "/", no ".." part, no "\", no query
// or fragment, no control character.
[[nodiscard]] bool is_static_path(std::string_view path) noexcept;

class StaticFiles
{
  public:
    StaticFiles()                              = default;
    StaticFiles(const StaticFiles&)            = default;
    StaticFiles(StaticFiles&&)                 = default;
    StaticFiles& operator=(const StaticFiles&) = default;
    StaticFiles& operator=(StaticFiles&&)      = default;
    virtual ~StaticFiles()                     = default;

    // Streams the file at `path` (checked by is_static_path, relative to
    // the root) into `sink`, from `offset` on; a source that cannot start
    // there calls sink.restart() and gives it whole. A file that does not
    // exist is Error::from_status(404); a source cut is Category::transport.
    [[nodiscard]] virtual Result<void> read(std::string_view path, std::uint64_t offset, DownloadSink& sink)
        = 0;
};

// A static library at an address (its root, ending with "/"), read with
// the app's Transport: no token, no signature, Range to resume.
class HttpStaticFiles final : public StaticFiles
{
  public:
    // `root`: "https://lea.example.org/library/" (HTTP on loopback only).
    [[nodiscard]] static Result<HttpStaticFiles> create(
        Transport& transport, std::string_view root, std::string_view user_agent, Allocator allocator = {});

    [[nodiscard]] Result<void> read(std::string_view path, std::uint64_t offset, DownloadSink& sink) override;

  private:
    HttpStaticFiles(Transport& transport, Allocator allocator);
    Transport* transport_;
    String root_;
    String user_agent_;
};

class StaticLibrary
{
  public:
    // Reads lantern.json: absent for a handshake of a newer schema; an
    // error for one that is not a static library's (no `static`, a base
    // other than ".", a family a static library cannot offer, L-21.2-1).
    [[nodiscard]] static Read<StaticLibrary> open(StaticFiles& files, const DecodeOptions& options = {});

    [[nodiscard]] const Handshake& handshake() const noexcept { return handshake_; }

    // A page of a listing, from 1 (an empty cursor) or the previous page's
    // `next`; a platform of the handshake's.
    [[nodiscard]] Read<AppsPage> apps(std::string_view platform, std::string_view cursor = {});
    [[nodiscard]] Read<Titles> titles(std::string_view platform, std::string_view cursor = {});
    [[nodiscard]] Read<HomebrewPage> homebrew(std::string_view platform, std::string_view cursor = {});
    [[nodiscard]] Read<Title> title(std::string_view platform, std::string_view title_id);
    [[nodiscard]] Read<Homebrew> homebrew_entry(std::string_view platform, std::string_view id);
    // A title's cheat sets: none when it has no file of them (§ 21.1).
    [[nodiscard]] Read<CheatSets> cheats(std::string_view platform, std::string_view title_id);
    // A set's text, checked by its size and SHA-256.
    [[nodiscard]] Result<String> cheat_text(const CheatSet& set);

    // A file (`target.url` the document's relative `file`), checked as
    // Client::download checks one: success only when its SHA-256 matched.
    [[nodiscard]] Result<void> download(
        const DownloadTarget& target, DownloadState& state, DownloadSink& sink);

    // § 6.3 over the whole listing of `platform` (L-21.3-2): the apps
    // `request` says the device is missing, by the server's rules.
    [[nodiscard]] Result<Vector<App>> missing(std::string_view platform, const MissingRequest& request);
    // § 8.5: the entries of `platform` whose build is above the one installed.
    [[nodiscard]] Result<Vector<Homebrew>> homebrew_updates(
        std::string_view platform, const HomebrewUpdatesRequest& request);

  private:
    StaticLibrary(StaticFiles& files, const DecodeOptions& options);
    [[nodiscard]] Result<String> fetch(std::string_view path, bool missing_ok, bool& missing);
    [[nodiscard]] Result<void> platform_ok(std::string_view platform) const;
    [[nodiscard]] Result<String> page_path(
        std::string_view family, std::string_view platform, std::string_view cursor) const;

    StaticFiles* files_;
    DecodeOptions decode_;
    Allocator allocator_;
    Handshake handshake_;
};

} // namespace lantern
