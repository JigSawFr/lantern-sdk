#include <lantern/http_signature.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <memory_resource>
#include <system_error>
#include <utility>

#include <lantern/digest.hpp>
#include <lantern/encoding.hpp>
#include <lantern/url.hpp>

namespace lantern
{

namespace
{

constexpr std::string_view label_prefix = "lantern=";
constexpr std::size_t nonce_bytes       = 16;
constexpr std::size_t keyid_size        = 43;

char lower(char c) noexcept
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

bool equal_ignoring_case(std::string_view a, std::string_view b) noexcept
{
    return a.size() == b.size()
        && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) { return lower(x) == lower(y); });
}

std::string_view trim(std::string_view text) noexcept
{
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t'))
        text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t'))
        text.remove_suffix(1);
    return text;
}

void append_number(String& out, std::int64_t value)
{
    std::array<char, 24> buffer {};
    const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
    out.append(buffer.data(), result.ptr);
}

// The components a request covers, in § 5.4's order.
std::size_t expected_components(
    bool with_token, bool with_body, std::array<std::string_view, 4>& out) noexcept
{
    std::size_t count = 0;
    out[count++]      = "@method";
    out[count++]      = "@target-uri";
    if (with_token)
        out[count++] = "authorization";
    if (with_body)
        out[count++] = "content-digest";
    return count;
}

// Reads `"name"` at the front of `text`.
bool quoted(std::string_view& text, std::string_view& value) noexcept
{
    if (text.empty() || text.front() != '"')
        return false;
    const std::size_t close = text.find('"', 1);
    if (close == std::string_view::npos)
        return false;
    value = text.substr(1, close - 1);
    text.remove_prefix(close + 1);
    return true;
}

bool component_name(std::string_view name) noexcept
{
    return !name.empty()
        && std::ranges::all_of(name, [](char c) { return (c >= 'a' && c <= 'z') || c == '@' || c == '-'; });
}

// An inner list of quoted component names: ("a" "b"), at the front of `text`.
bool inner_list(std::string_view& text, std::span<std::string_view> out, std::size_t& count) noexcept
{
    count = 0;
    if (text.empty() || text.front() != '(')
        return false;
    text.remove_prefix(1);
    if (!text.empty() && text.front() == ')')
    {
        text.remove_prefix(1);
        return true;
    }
    for (;;)
    {
        std::string_view name;
        if (!quoted(text, name) || !component_name(name) || count == out.size())
            return false;
        out[count++] = name;
        if (!text.empty() && text.front() == ')')
        {
            text.remove_prefix(1);
            return true;
        }
        if (text.empty() || text.front() != ' ')
            return false;
        text.remove_prefix(1);
    }
}

bool digits(std::string_view text, std::size_t max) noexcept
{
    return !text.empty() && text.size() <= max
        && std::ranges::all_of(text, [](char c) { return c >= '0' && c <= '9'; });
}

// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
std::int64_t days_from_civil(std::int64_t year, unsigned month, unsigned day) noexcept
{
    year -= month <= 2 ? 1 : 0;
    const std::int64_t era = (year >= 0 ? year : year - 399) / 400;
    const auto yoe         = static_cast<unsigned>(year - era * 400);
    const unsigned doy     = (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1;
    const unsigned doe     = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

std::optional<unsigned> two_digits(std::string_view text) noexcept
{
    if (text.size() != 2 || !digits(text, 2))
        return std::nullopt;
    return static_cast<unsigned>((text[0] - '0') * 10 + (text[1] - '0'));
}

} // namespace

std::int64_t SystemClock::unix_seconds()
{
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch())
        .count();
}

Result<String> target_uri(std::string_view url, Allocator allocator)
{
    const auto parts = split_url(url);
    if (!parts)
        return std::unexpected(parts.error());
    String out(allocator);
    out.reserve(url.size());
    out.append(parts->scheme);
    out.append("://");
    const bool ipv6 = parts->host.contains(':');
    if (ipv6)
        out.push_back('[');
    for (const char c : parts->host)
        out.push_back(lower(c));
    if (ipv6)
        out.push_back(']');
    const std::uint16_t default_port = parts->scheme == "https" ? 443 : 80;
    if (parts->port != default_port)
    {
        out.push_back(':');
        append_number(out, parts->port);
    }
    out.append(parts->target);
    return out;
}

void signature_params(const SignedComponents& components, std::int64_t created, std::string_view nonce,
    std::string_view keyid, String& out)
{
    std::array<std::string_view, 4> names {};
    const std::size_t count
        = expected_components(!components.authorization.empty(), !components.content_digest.empty(), names);
    out.push_back('(');
    for (std::size_t i = 0; i < count; ++i)
    {
        if (i != 0)
            out.push_back(' ');
        out.push_back('"');
        out.append(names[i]);
        out.push_back('"');
    }
    out.append(");created=");
    append_number(out, created);
    out.append(";nonce=\"");
    out.append(nonce);
    out.append(R"(";keyid=")");
    out.append(keyid);
    out.append(R"(";alg="ed25519")");
}

void signature_base(const SignedComponents& components, std::string_view params, String& out)
{
    out.append("\"@method\": ");
    out.append(components.method);
    out.append("\n\"@target-uri\": ");
    out.append(components.target_uri);
    if (!components.authorization.empty())
    {
        out.append("\n\"authorization\": ");
        out.append(components.authorization);
    }
    if (!components.content_digest.empty())
    {
        out.append("\n\"content-digest\": ");
        out.append(components.content_digest);
    }
    out.append("\n\"@signature-params\": ");
    out.append(params);
}

Result<void> sign_components(const DeviceKey& key, const SignedComponents& components, std::int64_t created,
    std::string_view nonce, SignatureHeaders& out)
{
    if (!is_base64url(nonce, 22, 64))
        return fail(Category::usage, "a nonce is 22 to 64 characters of base64url (SPEC.md 5.4)");
    if (created < 0)
        return fail(Category::usage, "a signature's created is a time after 1970");
    const auto keyid = key.keyid();
    String params(out.signature_input.get_allocator());
    signature_params(components, created, nonce, std::string_view(keyid.data(), keyid.size()), params);
    String base(out.signature_input.get_allocator());
    signature_base(components, params, base);
    const SignatureBytes signature
        = key.sign(std::span(reinterpret_cast<const std::uint8_t*>(base.data()), base.size()));
    out.signature_input.assign(label_prefix);
    out.signature_input.append(params);
    out.signature.assign("lantern=:");
    base64_encode(signature, out.signature);
    out.signature.push_back(':');
    if (out.signature_input.size() > max_signature_header)
        return fail(Category::usage, "a Signature-Input above 1 KiB (SPEC.md 13)");
    return {};
}

Result<std::array<char, 22>> make_nonce(RandomSource& random)
{
    std::array<std::uint8_t, nonce_bytes> bytes {};
    if (auto filled = random.fill(bytes); !filled)
        return std::unexpected(filled.error());
    std::array<char, 32> buffer {};
    std::pmr::monotonic_buffer_resource arena(buffer.data(), buffer.size(), std::pmr::null_memory_resource());
    String text(&arena);
    text.reserve(24);
    base64url_encode(bytes, text);
    std::array<char, 22> out {};
    std::copy_n(text.begin(), std::min(text.size(), out.size()), out.begin());
    return out;
}

Result<void> DeviceSigner::sign(const SigningInput& request, HeaderSink& headers)
{
    std::string_view authorization;
    std::string_view content_digest;
    for (const Header& header : request.headers)
    {
        if (equal_ignoring_case(header.name, "Authorization"))
            authorization = header.value;
        else if (equal_ignoring_case(header.name, "Content-Digest"))
            content_digest = header.value;
    }
    if (authorization.empty() && !request.keyed_poll)
        return {};

    std::array<std::byte, 2048> buffer {};
    std::pmr::monotonic_buffer_resource arena(buffer.data(), buffer.size());
    String digest_field(&arena);
    if (request.content_digest && content_digest.empty())
    {
        format_digest_field(*request.content_digest, digest_field);
        if (auto added = headers.add("Content-Digest", digest_field); !added)
            return added;
        content_digest = digest_field;
    }
    if (!request.content_digest)
        content_digest = {};

    const auto uri = target_uri(request.target, &arena);
    if (!uri)
        return std::unexpected(uri.error());
    const auto nonce = make_nonce(*random_);
    if (!nonce)
        return std::unexpected(nonce.error());
    SignedComponents components;
    components.method         = request.method;
    components.target_uri     = *uri;
    components.authorization  = authorization;
    components.content_digest = content_digest;
    SignatureHeaders out(&arena);
    const std::int64_t created = clock_->unix_seconds() + offset_;
    if (auto signed_ok
        = sign_components(key_, components, created, std::string_view(nonce->data(), nonce->size()), out);
        !signed_ok)
        return signed_ok;
    if (auto added = headers.add("Signature-Input", out.signature_input); !added)
        return added;
    return headers.add("Signature", out.signature);
}

SignatureVerdict check_signature(const SignatureCheck& check) noexcept
{
    SignatureVerdict verdict;
    const std::string_view input = trim(check.signature_input);
    const std::string_view value = trim(check.signature);
    if (input.empty() || value.empty())
    {
        verdict.code = Code::signature_required;
        return verdict;
    }
    verdict.code = Code::signature_invalid;
    if (input.size() > max_signature_header || value.size() > max_signature_header
        || !input.starts_with(label_prefix))
        return verdict;

    // ("@method" …);created=<digits>;nonce="…";keyid="…";alg="ed25519", nothing else
    const std::string_view params = input.substr(label_prefix.size());
    std::string_view rest         = params;
    std::array<std::string_view, 8> covered {};
    std::size_t count = 0;
    if (!inner_list(rest, covered, count) || !rest.starts_with(";created="))
        return verdict;
    rest.remove_prefix(9);
    const std::size_t semicolon = rest.find(';');
    if (semicolon == std::string_view::npos)
        return verdict;
    const std::string_view created_text = rest.substr(0, semicolon);
    rest.remove_prefix(semicolon);
    std::string_view nonce;
    std::string_view keyid;
    if (!digits(created_text, 12) || !rest.starts_with(";nonce="))
        return verdict;
    rest.remove_prefix(7);
    if (!quoted(rest, nonce) || !is_base64url(nonce, 22, 64) || !rest.starts_with(";keyid="))
        return verdict;
    rest.remove_prefix(7);
    if (!quoted(rest, keyid) || !is_base64url(keyid, keyid_size, keyid_size) || rest != ";alg=\"ed25519\"")
        return verdict;
    verdict.nonce = nonce;
    verdict.keyid = keyid;

    std::array<std::string_view, 4> wanted {};
    const std::size_t wanted_count
        = expected_components(!check.authorization.empty(), check.has_body, wanted);
    if (count != wanted_count
        || !std::equal(wanted.begin(), wanted.begin() + static_cast<std::ptrdiff_t>(count), covered.begin()))
        return verdict;
    if (check.has_body && trim(check.content_digest).empty())
        return verdict;
    const auto expected_keyid = key_thumbprint(check.key);
    if (keyid != std::string_view(expected_keyid.data(), expected_keyid.size()))
        return verdict;

    // Signature: lantern=:<86 characters of base64 and ==>:
    if (!value.starts_with("lantern=:") || !value.ends_with(':') || value.size() != 9 + 88 + 1)
        return verdict;
    SignatureBytes signature {};
    if (!base64_decode(value.substr(9, 88), signature))
        return verdict;

    std::array<std::byte, 4096> buffer {};
    std::pmr::monotonic_buffer_resource arena(buffer.data(), buffer.size(), std::pmr::null_memory_resource());
    String base(&arena);
    SignedComponents components;
    components.method         = check.method;
    components.target_uri     = check.target_uri;
    components.authorization  = check.authorization;
    components.content_digest = check.has_body ? trim(check.content_digest) : std::string_view {};
    // The base holds the components and the params; a request whose base
    // does not fit (an absurd URL) is refused rather than allocated for
    const std::size_t needed = components.method.size() + components.target_uri.size()
        + components.authorization.size() + components.content_digest.size() + params.size() + 128;
    if (needed > buffer.size() / 2)
        return verdict;
    base.reserve(needed);
    signature_base(components, params, base);
    if (!ed25519_verify(
            signature, check.key, std::span(reinterpret_cast<const std::uint8_t*>(base.data()), base.size())))
        return verdict;

    std::int64_t created = 0;
    std::from_chars(created_text.data(), created_text.data() + created_text.size(), created);
    const std::int64_t difference = created > check.now ? created - check.now : check.now - created;
    if (std::cmp_greater(difference, check.skew))
    {
        verdict.code = Code::signature_expired;
        return verdict;
    }
    if (check.has_body && check.body_sha256)
    {
        const ParsedDigest declared = parse_digest_field(check.content_digest);
        if (declared.state != DigestField::sha256 || !same_digest(declared.sha256, *check.body_sha256))
        {
            verdict.code = Code::digest_mismatch;
            return verdict;
        }
    }
    verdict.code = Code::none;
    return verdict;
}

std::optional<AcceptSignature> parse_accept_signature(std::string_view value) noexcept
{
    if (value.size() > max_signature_header)
        return std::nullopt;
    // A dictionary: find the member `lantern` (members are split by commas
    // outside quotes and parentheses)
    std::size_t at = 0;
    while (at < value.size())
    {
        while (at < value.size() && (value[at] == ' ' || value[at] == '\t' || value[at] == ','))
            ++at;
        std::string_view rest = value.substr(at);
        if (rest.starts_with(label_prefix))
        {
            rest.remove_prefix(label_prefix.size());
            AcceptSignature out;
            if (!inner_list(rest, out.components, out.component_count))
                return std::nullopt;
            while (!rest.empty() && rest.front() == ';')
            {
                rest.remove_prefix(1);
                const std::size_t equals = rest.find('=');
                if (equals == std::string_view::npos)
                    return std::nullopt;
                const std::string_view key = rest.substr(0, equals);
                rest.remove_prefix(equals + 1);
                std::string_view parameter;
                if (!rest.empty() && rest.front() == '"')
                {
                    if (!quoted(rest, parameter))
                        return std::nullopt;
                }
                else
                {
                    const std::size_t end = std::min(rest.find_first_of(";, "), rest.size());
                    parameter             = rest.substr(0, end);
                    rest.remove_prefix(end);
                }
                if (key == "keyid")
                    out.keyid = parameter;
                else if (key == "alg")
                    out.alg = parameter;
            }
            return out;
        }
        // Skip this member: to the next comma outside quotes and parentheses
        bool in_quotes = false;
        int depth      = 0;
        for (; at < value.size(); ++at)
        {
            const char c = value[at];
            if (c == '"')
                in_quotes = !in_quotes;
            else if (!in_quotes && c == '(')
                ++depth;
            else if (!in_quotes && c == ')')
                --depth;
            else if (!in_quotes && depth == 0 && c == ',')
                break;
        }
    }
    return std::nullopt;
}

std::optional<std::int64_t> parse_http_date(std::string_view text) noexcept
{
    // "Sun, 06 Nov 1994 08:49:37 GMT"
    text = trim(text);
    if (text.size() != 29 || text[3] != ',' || text[4] != ' ' || text[7] != ' ' || text[11] != ' '
        || text[16] != ' ' || text[19] != ':' || text[22] != ':' || text.substr(25) != " GMT")
        return std::nullopt;
    static constexpr std::array<std::string_view, 12> months { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    const std::string_view month_text = text.substr(8, 3);
    unsigned month_number             = 0;
    for (std::size_t i = 0; i < months.size(); ++i)
    {
        if (months[i] == month_text)
            month_number = static_cast<unsigned>(i) + 1;
    }
    if (month_number == 0)
        return std::nullopt;
    const auto day    = two_digits(text.substr(5, 2));
    const auto hour   = two_digits(text.substr(17, 2));
    const auto minute = two_digits(text.substr(20, 2));
    const auto second = two_digits(text.substr(23, 2));
    if (!day || !hour || !minute || !second || !digits(text.substr(12, 4), 4) || *day == 0 || *day > 31
        || *hour > 23 || *minute > 59 || *second > 60)
        return std::nullopt;
    std::int64_t year = 0;
    std::from_chars(text.data() + 12, text.data() + 16, year);
    return days_from_civil(year, month_number, *day) * 86400 + std::int64_t { *hour } * 3600
        + std::int64_t { *minute } * 60 + std::int64_t { *second };
}

} // namespace lantern
