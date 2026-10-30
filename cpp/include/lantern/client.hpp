// The client, read side of draft 0.3: the handshake, the apps' listing with
// its cursors, what the device is missing, changes, titles, homebrew (the
// listing, an entry, the updates), cheat sets and their text, and verified
// downloads. Everything goes through the app's Transport.
//
// Not in this version: pairing and tokens beyond a bearer token the app
// sets (draft 0.4 changes them: device-bound keys and signed requests, for
// which RequestSigner is the hook), and the routes that write (saves,
// cheats, requests).
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
#include <lantern/url.hpp>

namespace lantern
{

struct ClientConfig
{
    // The server's origin: "https://shelf.example.org" or
    // "https://192.0.2.10:8443"; plain HTTP only on loopback (SPEC.md § 2).
    std::string_view origin;
    // "Name/version" (§ 2, required).
    std::string_view user_agent;
    // Lantern-Platform (§ 4.3), sent on every call: the platform the client
    // runs on. Empty: none sent, and the server answers for every platform.
    std::string_view platform;
    // Accept-Language, as the app builds it ("fr, en;q=0.5"), or empty.
    std::string_view accept_language;
    // Limits and memory of every document read (§ 13).
    DecodeOptions decode {};
    // The most of a problem+json body read for an error.
    std::size_t max_error_body = 64 * 1024;
    // Draft 0.4's hook; null in this version.
    RequestSigner* signer = nullptr;
};

struct AppsQuery
{
    std::string_view platform; // overrides Lantern-Platform
    std::string_view type;
    std::string_view title_id;
    std::string_view q;
    std::string_view sort; // "name", "added" or "release"
    std::optional<std::uint32_t> page_size;
    std::string_view cursor; // a page's `next`
};

struct HomebrewQuery
{
    std::string_view platform;
    std::string_view q;
    std::string_view kind;
    std::string_view genre;
    std::optional<std::uint32_t> page_size;
    std::string_view cursor;
};

struct CheatsQuery
{
    std::string_view platform;
    std::string_view title_id;
    std::string_view build_id;
};

// The families of § 4.2, for Client::offers().
enum class Family : std::uint8_t
{
    library,
    titles,
    changes,
    sections,
    homebrew,
    saves,
    cheats,
    requests,
    pairing,
};

class Client
{
  public:
    // Checks the configuration: an origin of HTTPS (or HTTP on loopback)
    // with no path, a User-Agent of the form Name/version, a platform name.
    [[nodiscard]] static Result<Client> create(Transport& transport, const ClientConfig& config);

    // `Authorization: Bearer <token>` on every call to the server's origin,
    // and to no other (§ 2, § 5.1). How the app got it (pairing, § 5.2) is
    // its own business until draft 0.4.
    [[nodiscard]] Result<void> set_bearer_token(std::string_view token);
    void clear_bearer_token() noexcept;

    // GET /.well-known/lantern (§ 4.2). Every other call needs it first: it
    // gives the base path and the families offered to this caller. Absent
    // (an empty optional) for a handshake of a newer schema.
    [[nodiscard]] Read<Handshake> handshake();
    [[nodiscard]] const Handshake* server() const noexcept { return handshake_ ? &*handshake_ : nullptr; }
    // The schema the server writes for a family, 0 when it does not offer
    // it to this caller (or before the handshake).
    [[nodiscard]] std::uint64_t offers(Family family) const noexcept;

    // § 6.2: a page; pass its `next` as the next query's cursor. A 410
    // (Code::gone) means the cursor expired: read the list from its start.
    [[nodiscard]] Read<AppsPage> apps(const AppsQuery& query = {});
    // § 6.3: needs a platform (the configuration's, or `platform`).
    [[nodiscard]] Read<AppsPage> missing(
        const MissingRequest& request, std::string_view cursor = {}, std::string_view platform = {});
    // § 6.4: without `since`, no apps and the current token.
    [[nodiscard]] Read<Changes> changes(std::string_view since = {});
    [[nodiscard]] Read<Sections> sections();
    // § 7.1, § 7.2 (100 ids at most), § 7.3.
    [[nodiscard]] Read<Title> title(std::string_view title_id);
    [[nodiscard]] Read<Titles> titles(std::span<const std::string_view> ids);
    [[nodiscard]] Read<TitleChanges> title_changes(std::string_view since = {});
    // § 8.5.
    [[nodiscard]] Read<HomebrewPage> homebrew(const HomebrewQuery& query = {});
    [[nodiscard]] Read<Homebrew> homebrew_entry(std::string_view id);
    [[nodiscard]] Read<HomebrewPage> homebrew_updates(
        const HomebrewUpdatesRequest& request, std::string_view cursor = {}, std::string_view platform = {});
    // § 10.
    [[nodiscard]] Read<CheatSets> cheats(const CheatsQuery& query = {});
    // A set's text (1 MiB at most), checked against its size and SHA-256.
    [[nodiscard]] Result<String> cheat_text(const CheatSet& set);

    // § 6.6: downloads `target` into `sink`, from `state.received` on (a
    // Range request), hashing as it goes; success only when the whole file
    // is there and its SHA-256 is the target's. A transport error leaves
    // `state` at what was received: call again to resume. A digest or size
    // that does not match is Category::integrity: the sink holds nothing to
    // install, and `state` is reset.
    [[nodiscard]] Result<void> download(
        const DownloadTarget& target, DownloadState& state, DownloadSink& sink);

    [[nodiscard]] Allocator allocator() const noexcept { return allocator_; }

  private:
    Client(Transport& transport, const ClientConfig& config);

    struct Response;
    class Collector;

    [[nodiscard]] Result<void> ready(Family family) const;
    [[nodiscard]] Result<String> api_url(std::string_view path) const;
    [[nodiscard]] Result<void> exchange(Method method, std::string_view url, std::string_view body,
        std::string_view content_type, ResponseHandler& handler, std::span<const Header> extra = {});
    [[nodiscard]] Result<Response> fetch(Method method, std::string_view url, std::string_view body = {});
    template <class T, class Reader>
    [[nodiscard]] Read<T> read(
        Method method, std::string_view url, Reader reader, std::string_view body = {});
    [[nodiscard]] Error problem(
        std::uint16_t status, std::string_view body, std::string_view retry_after) const;
    void update_accept_schema();
    [[nodiscard]] UrlParts origin() const noexcept;

    Transport* transport_;
    Allocator allocator_;
    DecodeOptions decode_;
    std::size_t max_error_body_;
    RequestSigner* signer_;
    String origin_text_;
    String user_agent_;
    String platform_;
    String accept_language_;
    String token_;
    String base_;
    String accept_schema_;
    std::optional<Handshake> handshake_;
};

} // namespace lantern
