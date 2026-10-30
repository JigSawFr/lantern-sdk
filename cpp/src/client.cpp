#include <lantern/client.hpp>

#include "client_internal.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <system_error>
#include <utility>

#include <lantern/digest.hpp>
#include <lantern/encoding.hpp>
#include <lantern/json.hpp>
#include <lantern/profiles.hpp>

namespace lantern
{

using detail::add_query;
using detail::bearer_token;
using detail::bytes_of;
using detail::equal_ignoring_case;
using detail::header_value;
using detail::max_header_bytes;
using detail::max_headers;

namespace
{

constexpr std::size_t max_titles = 100;

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
        case Family::signatures:
            value = f.signatures;
            break;
        case Family::admin:
            value = f.admin;
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
        case Family::signatures:
            return "signatures";
        case Family::admin:
            return "admin";
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
        if (headers_.size() >= 8)
            return fail(Category::usage, "a signer adds a few headers, not more");
        headers_.emplace_back();
        headers_.back().first.assign(name);
        headers_.back().second.assign(value);
        return {};
    }

    [[nodiscard]] const Vector<std::pair<String, String>>& headers() const noexcept { return headers_; }

  private:
    Vector<std::pair<String, String>> headers_;
};

Clock& system_clock() noexcept
{
    static SystemClock clock;
    return clock;
}

} // namespace

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
        else if (equal_ignoring_case(name, "Upload-Offset"))
            response_.upload_offset.assign(value);
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

// Sits between the transport and a call's handler: notes the server's Date,
// Deprecation and Accept-Signature, and holds back a 401 to a signed
// request, so that the client can sign again with the server's clock when
// the signature was refused as expired (§ 5.4, L-5.4-8), once.
class Client::Retry final : public ResponseHandler
{
  public:
    Retry(Client& client, ResponseHandler& inner, bool hold_401, std::size_t max_body)
        : client_(client)
        , inner_(inner)
        , hold_401_(hold_401)
        , max_body_(max_body)
        , date_(client.allocator_)
        , deprecation_(client.allocator_)
        , sunset_(client.allocator_)
        , headers_(client.allocator_)
        , body_(client.allocator_)
    {
    }

    bool on_status(std::uint16_t status) override
    {
        status_  = status;
        holding_ = hold_401_ && status == 401;
        return holding_ || inner_.on_status(status);
    }

    bool on_header(std::string_view name, std::string_view value) override
    {
        if (value.size() <= max_header_bytes)
        {
            if (equal_ignoring_case(name, "Date"))
                date_.assign(value);
            else if (equal_ignoring_case(name, "Deprecation"))
                deprecation_.assign(value);
            else if (equal_ignoring_case(name, "Sunset"))
                sunset_.assign(value);
            else if (status_ == 401 && equal_ignoring_case(name, "Accept-Signature"))
                client_.accept_signature_.assign(value);
        }
        if (!holding_)
            return inner_.on_header(name, value);
        if (headers_.size() >= max_headers || value.size() > max_header_bytes)
            return false;
        headers_.emplace_back();
        headers_.back().first.assign(name);
        headers_.back().second.assign(value);
        return true;
    }

    bool on_body(std::span<const std::byte> chunk) override
    {
        if (!holding_)
            return inner_.on_body(chunk);
        if (chunk.size() > max_body_ - std::min(max_body_, body_.size()))
            return false;
        body_.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        return true;
    }

    [[nodiscard]] bool holding() const noexcept { return holding_; }
    [[nodiscard]] std::string_view date() const noexcept { return date_; }
    [[nodiscard]] std::string_view deprecation() const noexcept { return deprecation_; }
    [[nodiscard]] std::string_view sunset() const noexcept { return sunset_; }

    // A 401 held for a signature refused as expired, with the server's Date.
    [[nodiscard]] bool expired_signature() const
    {
        if (!holding_ || date_.empty())
            return false;
        DecodeOptions options       = client_.decode_;
        options.limits.max_document = std::min(options.limits.max_document, max_body_);
        const auto read             = read_problem(body_, options);
        return read && *read && (**read).code == "signature_expired";
    }

    // Gives the held 401 to the call's handler, as it came.
    void replay()
    {
        if (!inner_.on_status(status_))
            return;
        for (const auto& [name, value] : headers_)
        {
            if (!inner_.on_header(name, value))
                return;
        }
        if (!body_.empty())
            static_cast<void>(inner_.on_body(std::as_bytes(std::span(body_.data(), body_.size()))));
    }

  private:
    Client& client_;
    ResponseHandler& inner_;
    bool hold_401_;
    std::size_t max_body_;
    std::uint16_t status_ = 0;
    bool holding_         = false;
    String date_;
    String deprecation_;
    String sunset_;
    Vector<std::pair<String, String>> headers_;
    String body_;
};

Client::Client(Transport& transport, const ClientConfig& config)
    : transport_(&transport)
    , allocator_(config.decode.memory)
    , decode_(config.decode)
    , max_error_body_(config.max_error_body)
    , app_signer_(config.signer)
    , random_(config.random)
    , clock_(config.clock != nullptr ? config.clock : &system_clock())
    , trust_(config.trust)
    , deprecations_(config.deprecations)
    , accept_signature_(allocator_)
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
    signer_.reset();
    return {};
}

Result<void> Client::use_key(const DeviceKey& key)
{
    if (random_ == nullptr)
        return fail(Category::usage, "signing needs a RandomSource (ClientConfig::random) for its nonces");
    signer_.emplace(key, *random_, *clock_);
    signer_->set_clock_offset(clock_offset_);
    return {};
}

Result<void> Client::set_credentials(std::string_view token, const DeviceKey& key)
{
    if (auto set = set_bearer_token(token); !set)
        return set;
    if (auto used = use_key(key); !used)
    {
        token_.clear();
        return used;
    }
    return {};
}

void Client::clear_bearer_token() noexcept
{
    token_.clear();
    signer_.reset();
}

Result<bool> Client::sign_in(CredentialStore& store)
{
    if (!handshake_)
        return fail(Category::usage, "no handshake yet: the credentials are kept by the server's uid");
    auto kept = store.load(handshake_->uid, allocator_);
    if (!kept)
        return std::unexpected(kept.error());
    if (!*kept)
        return false;
    const Credentials& credentials = **kept;
    if (credentials.key)
    {
        if (auto set = set_credentials(credentials.token, DeviceKey::from_seed(*credentials.key)); !set)
            return std::unexpected(set.error());
    }
    else if (auto set = set_bearer_token(credentials.token); !set)
        return std::unexpected(set.error());
    if (credentials.spki && trust_ != nullptr)
        trust_->pin(*credentials.spki);
    return true;
}

Result<void> Client::forget(CredentialStore& store)
{
    clear_bearer_token();
    if (!handshake_)
        return fail(Category::usage, "no handshake yet: the credentials are kept by the server's uid");
    return store.erase(handshake_->uid);
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
             Family::homebrew, Family::saves, Family::cheats, Family::requests, Family::admin })
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

void Client::take_server_date(std::string_view date)
{
    const auto server = parse_http_date(date);
    if (!server)
        return;
    clock_offset_ = *server - clock_->unix_seconds();
    if (signer_)
        signer_->set_clock_offset(clock_offset_);
}

Result<void> Client::send_once(const Call& call, ResponseHandler& handler)
{
    const auto target = split_url(call.url);
    if (!target)
        return std::unexpected(target.error());
    if (auto scheme = check_scheme(*target); !scheme)
        return std::unexpected(scheme.error());
    const bool to_origin = same_origin(*target, origin());
    Vector<Header> headers(allocator_);
    headers.reserve(20 + call.extra.size());
    headers.push_back({ "User-Agent", user_agent_ });
    headers.push_back({ "Accept", "application/json" });
    if (!platform_.empty())
        headers.push_back({ "Lantern-Platform", platform_ });
    if (!accept_language_.empty())
        headers.push_back({ "Accept-Language", accept_language_ });
    if (!accept_schema_.empty())
        headers.push_back({ "Accept-Schema", accept_schema_ });
    // § 2: the token and the signatures go to the server's origin alone;
    // § 5.3: never over a connection whose key nobody verified
    const bool with_token = !token_.empty() && !call.anonymous && to_origin;
    if ((with_token || call.poll_signer != nullptr) && trust_ != nullptr
        && trust_->mode() == ServerTrust::Mode::unverified)
        return fail(Category::refused,
            "the server's key is not verified: pin it before sending a secret (SPEC.md 5.3)");
    String authorization(allocator_);
    if (with_token)
    {
        authorization.append("Bearer ");
        authorization.append(token_);
        headers.push_back({ "Authorization", authorization });
    }
    String digest_field(allocator_);
    std::optional<Digest> body_digest;
    if (!call.body.empty())
    {
        headers.push_back({ "Content-Type", call.content_type });
        // RFC 9530: every body carries its digest, which a signature covers
        body_digest = Sha256::of(call.body);
        format_digest_field(*body_digest, digest_field);
        headers.push_back({ "Content-Digest", digest_field });
    }
    for (const Header& header : call.extra)
        headers.push_back(header);

    SignedHeaders signed_headers(allocator_);
    std::array<RequestSigner*, 2> signers {};
    if (to_origin)
    {
        if (call.poll_signer != nullptr)
            signers[0] = call.poll_signer;
        else if (with_token && signer_)
            signers[0] = &*signer_;
        signers[1] = app_signer_;
    }
    for (RequestSigner* signer : signers)
    {
        if (signer == nullptr)
            continue;
        SigningInput input;
        input.method             = method_name(call.method);
        input.target             = call.url;
        input.authority          = target->authority;
        input.path               = target->target;
        input.headers            = headers;
        input.content_digest     = body_digest;
        input.keyed_poll         = call.poll_signer != nullptr && signer == call.poll_signer;
        const std::size_t before = signed_headers.headers().size();
        if (auto signed_ok = signer->sign(input, signed_headers); !signed_ok)
            return signed_ok;
        for (std::size_t i = before; i < signed_headers.headers().size(); ++i)
            headers.push_back({ signed_headers.headers()[i].first, signed_headers.headers()[i].second });
    }

    Request request;
    request.method  = call.method;
    request.url     = call.url;
    request.headers = headers;
    request.body    = call.body;
    return transport_->send(request, handler);
}

Result<void> Client::exchange(const Call& call, ResponseHandler& handler)
{
    const bool signed_request
        = call.poll_signer != nullptr || (signer_ && !token_.empty() && !call.anonymous);
    Retry first(*this, handler, signed_request, max_error_body_);
    auto sent                   = send_once(call, first);
    const std::string_view date = first.date();
    if (call.take_date && !date.empty())
        take_server_date(date);
    if (!first.deprecation().empty() && deprecations_ != nullptr)
        deprecations_->deprecated(call.url, first.deprecation(), first.sunset());
    if (!first.holding())
        return sent;
    if (!first.expired_signature())
    {
        first.replay();
        return {};
    }
    // § 5.4: the server's clock, then the request again, once, newly signed
    take_server_date(date);
    if (call.poll_signer != nullptr)
        call.poll_signer->set_clock_offset(clock_offset_);
    Retry second(*this, handler, false, max_error_body_);
    return send_once(call, second);
}

Result<Client::Response> Client::fetch(const Call& call)
{
    Response response(allocator_);
    Collector collector(response, decode_.limits.max_document, max_error_body_);
    const auto sent = exchange(call, collector);
    if (collector.error())
        return std::unexpected(*collector.error());
    if (!sent && !collector.truncated())
        return std::unexpected(sent.error());
    if (response.status == 0)
        return fail(Category::transport, "no answer");
    return response;
}

Result<Client::Response> Client::fetch(Method method, std::string_view url, std::string_view body)
{
    Call call;
    call.method = method;
    call.url    = url;
    call.body   = bytes_of(body);
    return fetch(call);
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
    refine_signature_error(error);
    return error;
}

Error Client::problem(const Response& response) const
{
    return problem(response.status, response.body, response.retry_after);
}

void Client::refine_signature_error(Error& error) const
{
    // § 5.4: a signature refused for a reason signing again cannot mend
    // says what to do instead (Accept-Signature, L-5.4-10)
    const Code code = error.code();
    if (error.status() != 401
        || (code != Code::signature_required && code != Code::signature_invalid
            && code != Code::signature_expired))
        return;
    if (!signer_)
    {
        error.set_detail(
            "this token is bound to a device key this client does not hold: pair again (SPEC.md 5.4)");
        return;
    }
    const auto wanted = parse_accept_signature(accept_signature_);
    if (!wanted)
        return;
    const auto keyid = signer_->key().keyid();
    if (!wanted->keyid.empty() && wanted->keyid != std::string_view(keyid.data(), keyid.size()))
        error.set_detail("the server binds this token to another device key: pair again (SPEC.md 5.4)");
    else if (!wanted->alg.empty() && wanted->alg != "ed25519")
        error.set_detail("the server asks for a signature algorithm other than ed25519 (SPEC.md 5.4)");
}

Result<Client::Response> Client::expect(const Call& call)
{
    // Any 2xx: what was asked was done, as far as the client can tell
    auto response = fetch(call);
    if (!response)
        return response;
    if (response->status < 200 || response->status >= 300)
        return std::unexpected(problem(*response));
    return response;
}

Read<Handshake> Client::handshake()
{
    String url(origin_text_, allocator_);
    url.append("/.well-known/lantern");
    Call call;
    call.url       = url;
    call.take_date = true;
    auto read_one  = read<Handshake>(call,
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
