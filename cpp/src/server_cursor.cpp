// SPEC.md § 6.2: cursors a server can give without keeping them.
//
// A cursor holds the sort key of a page's last item, the listing it belongs
// to and when it was given, sealed with the server's secret (HMAC-SHA-256).
// The next page starts after that key, so reading while the library changes
// neither skips nor repeats an item. A cursor the server never gave, or gave
// for another listing, is a 400; an expired one, a 410.
#include <algorithm>
#include <array>
#include <charconv>
#include <limits>

#include <lantern/encoding.hpp>
#include <lantern/hkdf.hpp>
#include <lantern/json.hpp>
#include <lantern/sha256.hpp>

#include "server_internal.hpp"

namespace lantern::detail
{

namespace
{

constexpr std::string_view prefix        = "c_";
constexpr std::size_t mac_bytes          = 16;
constexpr std::size_t max_minor_in_token = 100;

// A listing's page_size (§ 6.2): a positive integer, lowered to the limit.
std::expected<std::uint32_t, ProblemError> page_size_param(
    const ServerState& state, const ServerRequest& request)
{
    const auto text = request.param("page_size");
    if (!text)
        return std::min(state.default_page_size, state.page_limit);
    std::uint64_t value = 0;
    for (const char c : *text)
    {
        if (c < '0' || c > '9')
            return std::unexpected(bad_request(state, "page_size is a positive integer."));
        value = std::min<std::uint64_t>(
            value * 10 + static_cast<std::uint64_t>(c - '0'), std::numeric_limits<std::uint32_t>::max());
    }
    if (value < 1)
        return std::unexpected(bad_request(state, "page_size is a positive integer."));
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(value, state.page_limit));
}

std::span<const std::uint8_t> bytes_of(std::string_view text) noexcept
{
    return { reinterpret_cast<const std::uint8_t*>(text.data()), text.size() };
}

// The MAC of a token of that kind ('c' a cursor, 's' and 't' a since token):
// a token of one kind is never taken for another's.
std::array<std::uint8_t, mac_bytes> mac_of(const ServerState& state, char kind, std::string_view raw)
{
    String message(1, kind, state.allocator);
    message.push_back('.');
    message.append(raw);
    const Digest full = HmacSha256::of(state.secret, bytes_of(message));
    std::array<std::uint8_t, mac_bytes> out {};
    std::copy_n(full.begin(), out.size(), out.begin());
    return out;
}

// RFC 4648 § 5 without padding, back to bytes; false for anything else.
bool decode_url(std::string_view text, Vector<std::uint8_t>& out)
{
    if (text.empty() || text.size() % 4 == 1)
        return false;
    String standard(text.size() + 3, '=', out.get_allocator());
    for (std::size_t i = 0; i < text.size(); ++i)
    {
        standard[i] = text[i];
        if (text[i] == '-')
            standard[i] = '+';
        else if (text[i] == '_')
            standard[i] = '/';
    }
    standard.resize((text.size() + 3) / 4 * 4, '=');
    const auto size = base64_decoded_size(standard);
    if (!size)
        return false;
    out.resize(*size);
    return base64_decode(standard, out);
}

} // namespace

int compare(const SortKey& a, const SortKey& b) noexcept
{
    if (a.major != b.major)
        return a.major < b.major ? -1 : 1;
    if (const int minor = a.minor.compare(b.minor); minor != 0)
        return minor < 0 ? -1 : 1;
    if (const int id = a.id.compare(b.id); id != 0)
        return id < 0 ? -1 : 1;
    return 0;
}

String scope_of(std::span<const std::string_view> parts, const Allocator& allocator)
{
    Sha256 hash;
    for (const std::string_view part : parts)
    {
        hash.update(part);
        hash.update(std::string_view("\x1f", 1));
    }
    const auto hex = to_hex(hash.finish());
    return { hex.data(), 16, allocator };
}

String seal_cursor(const ServerState& state, std::string_view scope, const SortKey& key)
{
    // When it was given, to a sixtieth of the cursors' lifetime: two identical
    // requests in a row give the same page, so the same ETag (§ 14), unless a
    // window ends between them
    const std::int64_t step = std::max<std::int64_t>(1, state.cursor_lifetime / 60);
    const std::int64_t now  = state.clock->unix_seconds();
    const std::int64_t when = now / step * step;
    // A sort key too long for `opaque` (512 characters) is found again by its id
    const bool by_id = key.minor.size() > max_minor_in_token;

    String raw(state.allocator);
    json::Writer w(raw);
    w.begin_object();
    w.key("s");
    w.string(scope);
    w.key("a");
    w.number(key.major);
    if (by_id)
    {
        w.key("l");
        w.boolean(true);
    }
    else
    {
        w.key("n");
        w.string(key.minor);
    }
    w.key("i");
    w.string(key.id);
    w.key("t");
    w.number(when);
    w.end_object();

    const auto mac = mac_of(state, 'c', raw);
    String token(prefix, state.allocator);
    base64url_encode(bytes_of(raw), token);
    token.push_back('.');
    base64url_encode(mac, token);
    return token;
}

std::expected<CursorPosition, ProblemError> open_cursor(
    const ServerState& state, std::string_view cursor, std::string_view scope)
{
    const auto never_given
        = [&] { return bad_request(state, "Unknown cursor: one this server never gave."); };
    if (cursor.size() > 1024 || !cursor.starts_with(prefix))
        return std::unexpected(never_given());
    cursor.remove_prefix(prefix.size());
    const std::size_t dot = cursor.find('.');
    if (dot == std::string_view::npos)
        return std::unexpected(never_given());
    Vector<std::uint8_t> raw(state.allocator);
    Vector<std::uint8_t> given(state.allocator);
    if (!decode_url(cursor.substr(0, dot), raw) || !decode_url(cursor.substr(dot + 1), given)
        || given.size() != mac_bytes)
        return std::unexpected(never_given());
    const std::string_view text(reinterpret_cast<const char*>(raw.data()), raw.size());
    const auto expected   = mac_of(state, 'c', text);
    std::uint32_t differs = 0;
    for (std::size_t i = 0; i < mac_bytes; ++i)
        differs |= static_cast<std::uint32_t>(expected[i]) ^ static_cast<std::uint32_t>(given[i]);
    if (differs != 0)
        return std::unexpected(never_given());

    json::Limits limits;
    limits.max_document = 4096;
    const auto document = json::parse(text, limits, state.allocator.resource());
    if (!document || !document->root().is_object())
        return std::unexpected(never_given());
    const json::Value& root = document->root();
    const json::Value* s    = root.find("s");
    const json::Value* a    = root.find("a");
    const json::Value* i    = root.find("i");
    const json::Value* t    = root.find("t");
    const json::Value* n    = root.find("n");
    const json::Value* l    = root.find("l");
    if (s == nullptr || !s->is_string() || a == nullptr || i == nullptr || !i->is_string() || t == nullptr
        || (n == nullptr) == (l == nullptr) || (n != nullptr && !n->is_string()))
        return std::unexpected(never_given());
    const auto major  = a->to_i64();
    const auto issued = t->to_i64();
    if (!major || !issued)
        return std::unexpected(never_given());
    if (s->text() != scope)
        return std::unexpected(bad_request(state, "This cursor belongs to another listing."));
    if (state.clock->unix_seconds() - *issued > static_cast<std::int64_t>(state.cursor_lifetime))
        return std::unexpected(gone(state, "Cursor expired: read the list again from its start."));
    CursorPosition position(state.allocator);
    position.key.major = *major;
    position.key.id.assign(i->text());
    if (n != nullptr)
        position.key.minor.assign(n->text());
    position.by_id = n == nullptr;
    return position;
}

std::expected<PageWindow, ProblemError> page_window(const ServerState& state, const ServerRequest& request,
    std::span<const SortKey> keys, std::string_view scope)
{
    const auto size = page_size_param(state, request);
    if (!size)
        return std::unexpected(size.error());
    PageWindow window(state.allocator);
    window.order.reserve(keys.size());
    for (std::size_t i = 0; i < keys.size(); ++i)
        window.order.push_back(i);
    std::ranges::sort(
        window.order, [&](std::size_t a, std::size_t b) { return compare(keys[a], keys[b]) < 0; });

    if (const auto cursor = request.param("cursor"))
    {
        auto position = open_cursor(state, *cursor, scope);
        if (!position)
            return std::unexpected(std::move(position.error()));
        if (position->by_id)
        {
            const auto found = std::ranges::find_if(
                window.order, [&](std::size_t i) { return keys[i].id == position->key.id; });
            if (found == window.order.end())
                return std::unexpected(gone(state, "Cursor expired: read the list again from its start."));
            window.from = static_cast<std::size_t>(found - window.order.begin()) + 1;
        }
        else
        {
            // After the item the last page ended with, whether or not it is still there
            const auto after = std::ranges::partition_point(
                window.order, [&](std::size_t i) { return compare(keys[i], position->key) <= 0; });
            window.from = static_cast<std::size_t>(after - window.order.begin());
        }
    }
    window.count = std::min<std::size_t>(*size, window.order.size() - window.from);
    if (window.from + window.count < window.order.size())
        window.next = seal_cursor(state, scope, keys[window.order[window.from + window.count - 1]]);
    return window;
}

String seal_since(const ServerState& state, char kind, std::string_view epoch, std::uint64_t position)
{
    String raw(state.allocator);
    json::Writer w(raw);
    w.begin_object();
    w.key("e");
    w.string(epoch);
    w.key("n");
    w.number(position);
    w.end_object();

    const auto mac = mac_of(state, kind, raw);
    String token(1, kind, state.allocator);
    token.push_back('_');
    base64url_encode(bytes_of(raw), token);
    token.push_back('.');
    base64url_encode(mac, token);
    return token;
}

std::expected<std::uint64_t, ProblemError> open_since(
    const ServerState& state, char kind, std::string_view token, const JournalPosition& journal)
{
    const auto never_given
        = [&] { return bad_request(state, "Unknown since token: one this server never gave."); };
    if (token.size() > 1024 || token.size() < 3 || token[0] != kind || token[1] != '_')
        return std::unexpected(never_given());
    token.remove_prefix(2);
    const std::size_t dot = token.find('.');
    if (dot == std::string_view::npos)
        return std::unexpected(never_given());
    Vector<std::uint8_t> raw(state.allocator);
    Vector<std::uint8_t> given(state.allocator);
    if (!decode_url(token.substr(0, dot), raw) || !decode_url(token.substr(dot + 1), given)
        || given.size() != mac_bytes)
        return std::unexpected(never_given());
    const std::string_view text(reinterpret_cast<const char*>(raw.data()), raw.size());
    const auto expected   = mac_of(state, kind, text);
    std::uint32_t differs = 0;
    for (std::size_t i = 0; i < mac_bytes; ++i)
        differs |= static_cast<std::uint32_t>(expected[i]) ^ static_cast<std::uint32_t>(given[i]);
    if (differs != 0)
        return std::unexpected(never_given());

    json::Limits limits;
    limits.max_document = 4096;
    const auto document = json::parse(text, limits, state.allocator.resource());
    if (!document || !document->root().is_object())
        return std::unexpected(never_given());
    const json::Value* e = document->root().find("e");
    const json::Value* n = document->root().find("n");
    const auto position  = n != nullptr && n->is_number() ? n->to_u64() : std::nullopt;
    if (e == nullptr || !e->is_string() || !position)
        return std::unexpected(never_given());
    if (e->text() != journal.epoch || *position < journal.oldest || *position > journal.position)
        return std::unexpected(gone(state, "Token too old for this server: read them all again."));
    return *position;
}

} // namespace lantern::detail
