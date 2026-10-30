#include <lantern/client.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <system_error>

#include <lantern/encoding.hpp>
#include <lantern/json.hpp>
#include <lantern/profiles.hpp>

namespace lantern
{

namespace
{

constexpr std::size_t max_headers      = 64;
constexpr std::size_t max_header_bytes = std::size_t { 8 } * 1024;
constexpr std::size_t max_titles       = 100;

bool equal_ignoring_case(std::string_view a, std::string_view b) noexcept
{
    return a.size() == b.size()
        && std::equal(a.begin(), a.end(), b.begin(),
            [](char x, char y)
            {
                const auto lower
                    = [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; };
                return lower(x) == lower(y);
            });
}

// A header value the app gives: printable ASCII and spaces, nothing that
// could end the line.
bool header_value(std::string_view value) noexcept
{
    return std::ranges::all_of(value,
        [](char c)
        {
            const auto byte = static_cast<unsigned char>(c);
            return byte >= 0x20U && byte < 0x7FU;
        });
}

// RFC 6750's b64token: what a bearer token may hold.
bool bearer_token(std::string_view token) noexcept
{
    if (token.empty())
        return false;
    const std::size_t end = token.find_last_not_of('=') + 1;
    return std::all_of(token.begin(), token.begin() + static_cast<std::ptrdiff_t>(end),
        [](char c)
        {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
                || c == '.' || c == '_' || c == '~' || c == '+' || c == '/';
        });
}

bool json_media_type(std::string_view content_type) noexcept
{
    const std::string_view type    = content_type.substr(0, content_type.find(';'));
    const std::string_view trimmed = type.substr(
        0, type.find_last_not_of(' ') == std::string_view::npos ? 0 : type.find_last_not_of(' ') + 1);
    return equal_ignoring_case(trimmed, "application/json")
        || (trimmed.size() > 5 && equal_ignoring_case(trimmed.substr(trimmed.size() - 5), "+json"));
}

void add_query(String& url, bool& first, std::string_view name, std::string_view value)
{
    if (value.empty())
        return;
    url.push_back(first ? '?' : '&');
    first = false;
    url.append(name);
    url.push_back('=');
    percent_encode(value, url);
}

void add_query(String& url, bool& first, std::string_view name, std::optional<std::uint32_t> value)
{
    if (!value)
        return;
    std::array<char, 12> buffer {};
    const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), *value);
    add_query(url, first, name,
        std::string_view(buffer.data(), static_cast<std::size_t>(result.ptr - buffer.data())));
}

std::uint64_t feature(const Handshake& handshake, Family family) noexcept
{
    const HandshakeFeatures& f = handshake.features;
    std::optional<std::uint64_t> value;
    switch (family)
    {
        case Family::library:
            value = f.library;
            break;
        case Family::titles:
            value = f.titles;
            break;
        case Family::changes:
            value = f.changes;
            break;
        case Family::sections:
            value = f.sections;
            break;
        case Family::homebrew:
            value = f.homebrew;
            break;
        case Family::saves:
            value = f.saves;
            break;
        case Family::cheats:
            value = f.cheats;
            break;
        case Family::requests:
            value = f.requests;
            break;
        case Family::pairing:
            value = f.pairing;
            break;
    }
    return value.value_or(0);
}

std::string_view family_name(Family family) noexcept
{
    switch (family)
    {
        case Family::library:
            return "library";
        case Family::titles:
            return "titles";
        case Family::changes:
            return "changes";
        case Family::sections:
            return "sections";
        case Family::homebrew:
            return "homebrew";
        case Family::saves:
            return "saves";
        case Family::cheats:
            return "cheats";
        case Family::requests:
            return "requests";
        case Family::pairing:
            return "pairing";
    }
    return "";
}

// The headers the client adds for a request signer.
class SignedHeaders final : public HeaderSink
{
  public:
    explicit SignedHeaders(Allocator allocator)
        : headers_(allocator)
    {
    }

    Result<void> add(std::string_view name, std::string_view value) override
    {
        if (name.empty() || !header_value(name) || !header_value(value) || name.contains(':'))
            return fail(Category::usage, "a signer's header that is not a header");
        headers_.emplace_back();
        headers_.back().first.assign(name);
        headers_.back().second.assign(value);
        return {};
    }

    [[nodiscard]] const Vector<std::pair<String, String>>& headers() const noexcept { return headers_; }

  private:
    Vector<std::pair<String, String>> headers_;
};

} // namespace

// A whole answer, for the documents and the errors.
struct Client::Response
{
    std::uint16_t status = 0;
    String body;
    String content_type;
    String retry_after;
};

// Collects an answer, its body bounded by the limits.
class Client::Collector final : public ResponseHandler
{
  public:
    Collector(Response& response, std::size_t max_document, std::size_t max_error) noexcept
        : response_(response)
        , max_document_(max_document)
        , max_error_(max_error)
    {
    }

    bool on_status(std::uint16_t status) override
    {
        response_.status = status;
        cap_             = (status >= 200 && status < 300) ? max_document_ : max_error_;
        return true;
    }

    bool on_header(std::string_view name, std::string_view value) override
    {
        if (++headers_ > max_headers || value.size() > max_header_bytes)
            return stop(Error::make(Category::limit, "an answer with too many or too long headers"));
        if (equal_ignoring_case(name, "Content-Type"))
            response_.content_type.assign(value);
        else if (equal_ignoring_case(name, "Retry-After"))
            response_.retry_after.assign(value);
        return true;
    }

    bool on_body(std::span<const std::byte> chunk) override
    {
        if (chunk.size() > cap_ - std::min(cap_, response_.body.size()))
        {
            // An error's body is only read for its detail: cut, not refused
            if (response_.status >= 200 && response_.status < 300)
                return stop(Error::make(Category::limit, "a document larger than the limit (SPEC.md 13)"));
            truncated_ = true;
            return false;
        }
        response_.body.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        return true;
    }

    [[nodiscard]] const std::optional<Error>& error() const noexcept { return error_; }
    [[nodiscard]] bool truncated() const noexcept { return truncated_; }

  private:
    bool stop(const Error& error)
    {
        error_ = error;
        return false;
    }

    Response& response_;
    std::size_t max_document_;
    std::size_t max_error_;
    std::size_t cap_     = 0;
    std::size_t headers_ = 0;
    bool truncated_      = false;
    std::optional<Error> error_;
};

Client::Client(Transport& transport, const ClientConfig& config)
    : transport_(&transport)
    , allocator_(config.decode.memory)
    , decode_(config.decode)
    , max_error_body_(config.max_error_body)
    , signer_(config.signer)
    , origin_text_(config.origin, allocator_)
    , user_agent_(config.user_agent, allocator_)
    , platform_(config.platform, allocator_)
    , accept_language_(config.accept_language, allocator_)
    , token_(allocator_)
    , base_(allocator_)
    , accept_schema_(allocator_)
{
}

Result<Client> Client::create(Transport& transport, const ClientConfig& config)
{
    const auto origin = split_url(config.origin);
    if (!origin)
        return std::unexpected(origin.error());
    if (auto scheme = check_scheme(*origin); !scheme)
        return std::unexpected(scheme.error());
    if (origin->target != "/" || config.origin.ends_with('/'))
        return fail(Category::usage, "the origin is a scheme, a host and a port, without a path");
    const std::size_t slash = config.user_agent.find('/');
    if (slash == std::string_view::npos || slash == 0 || slash + 1 == config.user_agent.size()
        || !header_value(config.user_agent))
        return fail(Category::usage, "the User-Agent is Name/version (SPEC.md 2)");
    if (!config.platform.empty() && !is_platform_name(config.platform))
        return fail(Category::usage, "not a platform name (SPEC.md 4.3)");
    if (!header_value(config.accept_language))
        return fail(Category::usage, "an Accept-Language that is not a header value");
    if (config.decode.memory == nullptr)
        return fail(Category::usage, "no memory resource");
    return Client(transport, config);
}

UrlParts Client::origin() const noexcept
{
    // Checked by create(): it splits
    return split_url(origin_text_).value_or(UrlParts {});
}

Result<void> Client::set_bearer_token(std::string_view token)
{
    if (!bearer_token(token))
        return fail(Category::usage, "not a bearer token (RFC 6750)");
    token_.assign(token);
    return {};
}

void Client::clear_bearer_token() noexcept
{
    token_.clear();
}

std::uint64_t Client::offers(Family family) const noexcept
{
    return handshake_ ? feature(*handshake_, family) : 0;
}

void Client::update_accept_schema()
{
    // § 3.2: for a family the server writes in a newer schema, ask for the
    // one this library reads; a server that cannot gives the newer one,
    // which the reader then treats as absent
    accept_schema_.clear();
    if (!handshake_)
        return;
    for (const Family family : { Family::library, Family::titles, Family::changes, Family::sections,
             Family::homebrew, Family::saves, Family::cheats })
    {
        if (feature(*handshake_, family) > known_schema)
        {
            if (!accept_schema_.empty())
                accept_schema_.append(", ");
            accept_schema_.append(family_name(family));
            accept_schema_.append("=1");
        }
    }
}

Result<void> Client::ready(Family family) const
{
    if (!handshake_)
        return fail(Category::usage, "no handshake yet: call handshake() first");
    if (feature(*handshake_, family) == 0)
    {
        std::array<char, 96> buffer {};
        const std::string_view name = family_name(family);
        const std::string_view text = " is not offered to this caller (SPEC.md 4.2)";
        std::copy_n(name.data(), name.size(), buffer.data());
        std::copy_n(text.data(), text.size(), buffer.data() + name.size());
        return fail(Category::unsupported, std::string_view(buffer.data(), name.size() + text.size()));
    }
    return {};
}

Result<String> Client::api_url(std::string_view path) const
{
    String url(origin_text_, allocator_);
    url.append(base_);
    url.append("/v1");
    url.append(path);
    return url;
}

Result<void> Client::exchange(Method method, std::string_view url, std::string_view body,
    std::string_view content_type, ResponseHandler& handler, std::span<const Header> extra)
{
    const auto target = split_url(url);
    if (!target)
        return std::unexpected(target.error());
    if (auto scheme = check_scheme(*target); !scheme)
        return std::unexpected(scheme.error());
    Vector<Header> headers(allocator_);
    headers.reserve(16 + extra.size());
    headers.push_back({ "User-Agent", user_agent_ });
    headers.push_back({ "Accept", "application/json" });
    if (!platform_.empty())
        headers.push_back({ "Lantern-Platform", platform_ });
    if (!accept_language_.empty())
        headers.push_back({ "Accept-Language", accept_language_ });
    if (!accept_schema_.empty())
        headers.push_back({ "Accept-Schema", accept_schema_ });
    String authorization(allocator_);
    if (!token_.empty() && same_origin(*target, origin()))
    {
        authorization.append("Bearer ");
        authorization.append(token_);
        headers.push_back({ "Authorization", authorization });
    }
    if (!body.empty())
        headers.push_back({ "Content-Type", content_type });
    for (const Header& header : extra)
        headers.push_back(header);

    SignedHeaders signed_headers(allocator_);
    if (signer_ != nullptr)
    {
        SigningInput input;
        input.method    = method_name(method);
        input.target    = url;
        input.authority = target->authority;
        input.path      = target->target;
        input.headers   = headers;
        if (!body.empty())
            input.content_digest = Sha256::of(body);
        if (auto signed_ok = signer_->sign(input, signed_headers); !signed_ok)
            return signed_ok;
        for (const auto& [name, value] : signed_headers.headers())
            headers.push_back({ name, value });
    }

    Request request;
    request.method  = method;
    request.url     = url;
    request.headers = headers;
    request.body    = std::as_bytes(std::span(body.data(), body.size()));
    return transport_->send(request, handler);
}

Result<Client::Response> Client::fetch(Method method, std::string_view url, std::string_view body)
{
    Response response { 0, String(allocator_), String(allocator_), String(allocator_) };
    Collector collector(response, decode_.limits.max_document, max_error_body_);
    const auto sent = exchange(method, url, body, "application/json", collector);
    if (collector.error())
        return std::unexpected(*collector.error());
    if (!sent && !collector.truncated())
        return std::unexpected(sent.error());
    if (response.status == 0)
        return fail(Category::transport, "no answer");
    return response;
}

Error Client::problem(std::uint16_t status, std::string_view body, std::string_view retry_after) const
{
    Error error = Error::from_status(status);
    // § 12: a problem document says the code; one the library cannot read
    // (another schema, another form) leaves the status alone to act on
    if (!body.empty())
    {
        DecodeOptions options       = decode_;
        options.limits.max_document = std::min(options.limits.max_document, max_error_body_);
        const auto read             = read_problem(body, options);
        if (read && *read)
        {
            const Problem& p = **read;
            error.set_code(code_from_name(p.code), p.code);
            error.set_detail(p.detail);
            error.set_title(p.title);
        }
    }
    std::uint32_t seconds = 0;
    const auto result = std::from_chars(retry_after.data(), retry_after.data() + retry_after.size(), seconds);
    if (!retry_after.empty() && result.ec == std::errc {}
        && result.ptr == retry_after.data() + retry_after.size())
        error.set_retry_after(seconds);
    return error;
}

template <class T, class Reader>
Read<T> Client::read(Method method, std::string_view url, Reader reader, std::string_view body)
{
    const auto response = fetch(method, url, body);
    if (!response)
        return std::unexpected(response.error());
    if (response->status < 200 || response->status >= 300)
        return std::unexpected(problem(response->status, response->body, response->retry_after));
    if (!json_media_type(response->content_type))
        return fail(Category::invalid_response, "a document that is not application/json");
    return reader(response->body, decode_);
}

Read<Handshake> Client::handshake()
{
    String url(origin_text_, allocator_);
    url.append("/.well-known/lantern");
    auto read_one = read<Handshake>(Method::get, url,
        [](std::string_view text, const DecodeOptions& options) { return read_handshake(text, options); });
    if (!read_one || !*read_one)
        return read_one;
    const Handshake& document = **read_one;
    if (document.base.empty() || document.base.front() != '/' || document.base.back() == '/'
        || document.base.find_first_of("?#") != String::npos)
        return fail(Category::invalid_response, "the handshake's base is not a path (SPEC.md 2)");
    if (std::ranges::find(document.versions, std::uint64_t { 1 }) == document.versions.end())
        return fail(Category::unsupported, "the server does not serve version 1 of the protocol");
    handshake_.emplace(document, allocator_);
    base_.assign(document.base);
    update_accept_schema();
    return read_one;
}

Read<AppsPage> Client::apps(const AppsQuery& query)
{
    if (auto ok = ready(Family::library); !ok)
        return std::unexpected(ok.error());
    auto url   = api_url("/apps");
    bool first = true;
    add_query(*url, first, "platform", query.platform);
    add_query(*url, first, "type", query.type);
    add_query(*url, first, "title_id", query.title_id);
    add_query(*url, first, "q", query.q);
    add_query(*url, first, "sort", query.sort);
    add_query(*url, first, "page_size", query.page_size);
    add_query(*url, first, "cursor", query.cursor);
    return read<AppsPage>(Method::get, *url, read_apps_page);
}

Read<AppsPage> Client::missing(
    const MissingRequest& request, std::string_view cursor, std::string_view platform)
{
    if (auto ok = ready(Family::library); !ok)
        return std::unexpected(ok.error());
    if (platform.empty() && platform_.empty())
        return fail(Category::usage, "what is missing needs a platform (SPEC.md 6.3)");
    auto url   = api_url("/apps/missing");
    bool first = true;
    add_query(*url, first, "platform", platform);
    add_query(*url, first, "cursor", cursor);
    String body(allocator_);
    write_missing_request(request, body);
    return read<AppsPage>(Method::post, *url, read_apps_page, body);
}

Read<Changes> Client::changes(std::string_view since)
{
    if (auto ok = ready(Family::changes); !ok)
        return std::unexpected(ok.error());
    auto url   = api_url("/changes");
    bool first = true;
    add_query(*url, first, "since", since);
    return read<Changes>(Method::get, *url, read_changes);
}

Read<Sections> Client::sections()
{
    if (auto ok = ready(Family::sections); !ok)
        return std::unexpected(ok.error());
    auto url = api_url("/sections");
    return read<Sections>(Method::get, *url, read_sections);
}

Read<Title> Client::title(std::string_view title_id)
{
    if (auto ok = ready(Family::titles); !ok)
        return std::unexpected(ok.error());
    if (!is_core_id(title_id) || title_id == "changes")
        return fail(Category::usage, "not a title id (SPEC.md 6.1)");
    auto url = api_url("/titles/");
    percent_encode(title_id, *url);
    return read<Title>(Method::get, *url, read_title);
}

Read<Titles> Client::titles(std::span<const std::string_view> ids)
{
    if (auto ok = ready(Family::titles); !ok)
        return std::unexpected(ok.error());
    if (ids.empty() || ids.size() > max_titles)
        return fail(Category::usage, "1 to 100 title ids at once (SPEC.md 7.2)");
    auto url = api_url("/titles?ids=");
    for (std::size_t i = 0; i < ids.size(); ++i)
    {
        if (!is_core_id(ids[i]))
            return fail(Category::usage, "not a title id (SPEC.md 6.1)");
        if (i != 0)
            url->push_back(',');
        percent_encode(ids[i], *url);
    }
    return read<Titles>(Method::get, *url, read_titles);
}

Read<TitleChanges> Client::title_changes(std::string_view since)
{
    if (auto ok = ready(Family::titles); !ok)
        return std::unexpected(ok.error());
    auto url   = api_url("/titles/changes");
    bool first = true;
    add_query(*url, first, "since", since);
    return read<TitleChanges>(Method::get, *url, read_title_changes);
}

Read<HomebrewPage> Client::homebrew(const HomebrewQuery& query)
{
    if (auto ok = ready(Family::homebrew); !ok)
        return std::unexpected(ok.error());
    auto url   = api_url("/homebrew");
    bool first = true;
    add_query(*url, first, "platform", query.platform);
    add_query(*url, first, "q", query.q);
    add_query(*url, first, "kind", query.kind);
    add_query(*url, first, "genre", query.genre);
    add_query(*url, first, "page_size", query.page_size);
    add_query(*url, first, "cursor", query.cursor);
    return read<HomebrewPage>(Method::get, *url, read_homebrew_page);
}

Read<Homebrew> Client::homebrew_entry(std::string_view id)
{
    if (auto ok = ready(Family::homebrew); !ok)
        return std::unexpected(ok.error());
    if (!is_homebrew_id(id))
        return fail(Category::usage, "not a homebrew id (SPEC.md 8.1)");
    auto url = api_url("/homebrew/");
    percent_encode(id, *url);
    return read<Homebrew>(Method::get, *url, read_homebrew);
}

Read<HomebrewPage> Client::homebrew_updates(
    const HomebrewUpdatesRequest& request, std::string_view cursor, std::string_view platform)
{
    if (auto ok = ready(Family::homebrew); !ok)
        return std::unexpected(ok.error());
    if (platform.empty() && platform_.empty())
        return fail(Category::usage, "homebrew updates need a platform (SPEC.md 8.5)");
    auto url   = api_url("/homebrew/updates");
    bool first = true;
    add_query(*url, first, "platform", platform);
    add_query(*url, first, "cursor", cursor);
    String body(allocator_);
    write_homebrew_updates_request(request, body);
    return read<HomebrewPage>(Method::post, *url, read_homebrew_page, body);
}

Read<CheatSets> Client::cheats(const CheatsQuery& query)
{
    if (auto ok = ready(Family::cheats); !ok)
        return std::unexpected(ok.error());
    auto url   = api_url("/cheats");
    bool first = true;
    add_query(*url, first, "platform", query.platform);
    add_query(*url, first, "title_id", query.title_id);
    add_query(*url, first, "build_id", query.build_id);
    return read<CheatSets>(Method::get, *url, read_cheat_sets);
}

} // namespace lantern
