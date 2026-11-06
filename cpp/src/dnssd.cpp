#include <lantern/dnssd.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <optional>
#include <span>

namespace lantern
{

namespace
{

constexpr std::string_view server_service = "_lantern._tcp.local";
constexpr std::string_view peer_service   = "_lantern-peer._tcp.local";

constexpr std::uint16_t type_a    = 1;
constexpr std::uint16_t type_ptr  = 12;
constexpr std::uint16_t type_txt  = 16;
constexpr std::uint16_t type_aaaa = 28;
constexpr std::uint16_t type_srv  = 33;
constexpr std::uint16_t type_any  = 255;

// What a message may hold, and what a browse keeps.
constexpr std::size_t max_message   = 9000;
constexpr std::size_t max_records   = 512;
constexpr std::size_t max_instances = 64;
constexpr std::size_t max_hosts     = 64;
constexpr std::size_t max_jumps     = 64;
constexpr std::size_t max_name      = 255;
constexpr std::size_t max_txt       = 1200;
constexpr std::size_t max_label     = 63;
constexpr std::size_t max_display   = 512;

using Bytes = std::span<const std::uint8_t>;

std::uint16_t u16(Bytes message, std::size_t at) noexcept
{
    return static_cast<std::uint16_t>((message[at] << 8) | message[at + 1]);
}

std::uint32_t u32(Bytes message, std::size_t at) noexcept
{
    return (static_cast<std::uint32_t>(u16(message, at)) << 16) | u16(message, at + 2);
}

char lower(char c) noexcept
{
    return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
}

// A name as the key of a map: lower case (DNS names are not case-sensitive), a
// dot inside a label written "\." so that labels cannot be confused.
void append_key(String& out, std::string_view label)
{
    for (const char c : label)
    {
        if (c == '.')
            out.push_back('\\');
        out.push_back(lower(c));
    }
}

struct ParsedName
{
    bool ok          = false;
    std::size_t next = 0;
    // The labels as a key; the first label as it was written; the key of the rest.
    String key;
    String first;
    String rest;
    std::size_t labels = 0;

    explicit ParsedName(const Allocator& allocator)
        : key(allocator)
        , first(allocator)
        , rest(allocator)
    {
    }
};

// A name at `at` of `message`, compressed or not (RFC 1035 § 4.1.4).
ParsedName read_name(Bytes message, std::size_t at, const Allocator& allocator)
{
    ParsedName out(allocator);
    std::size_t next  = 0;
    bool jumped       = false;
    std::size_t size  = 0;
    std::size_t jumps = 0;
    std::size_t pos   = at;
    for (;;)
    {
        if (pos >= message.size())
            return out;
        const std::size_t length = message[pos];
        if ((length & 0xc0U) == 0xc0U)
        {
            if (pos + 1 >= message.size())
                return out;
            const std::size_t target = ((length & 0x3fU) << 8) | message[pos + 1];
            if (!jumped)
                next = pos + 2;
            jumped = true;
            // A pointer goes back, and not for ever: a loop is a message to drop
            if (target >= pos || ++jumps > max_jumps)
                return out;
            pos = target;
        }
        else if ((length & 0xc0U) != 0)
            return out;
        else if (length == 0)
        {
            out.next = jumped ? next : pos + 1;
            out.ok   = true;
            return out;
        }
        else
        {
            if (pos + 1 + length > message.size())
                return out;
            size += length + 1;
            if (size > max_name || out.labels >= 127)
                return out;
            const std::string_view label(reinterpret_cast<const char*>(message.data() + pos + 1), length);
            if (out.labels == 0)
                out.first.assign(label);
            else
            {
                if (out.labels > 1)
                    out.rest.push_back('.');
                append_key(out.rest, label);
            }
            if (out.labels > 0)
                out.key.push_back('.');
            append_key(out.key, label);
            ++out.labels;
            pos += 1 + length;
        }
    }
}

void put16(String& out, std::uint16_t value)
{
    out.push_back(static_cast<char>(value >> 8));
    out.push_back(static_cast<char>(value & 0xffU));
}

// A question, class IN, ID 1: `labels` joined by dots, the first one being
// `first` when it is not empty (an instance's label may hold dots).
String question(
    std::string_view first, std::string_view service, std::uint16_t type, const Allocator& allocator)
{
    String out(allocator);
    put16(out, 1);
    put16(out, 0);
    put16(out, 1);
    put16(out, 0);
    put16(out, 0);
    put16(out, 0);
    const auto label = [&](std::string_view text)
    {
        const std::size_t length = std::min(text.size(), max_label);
        out.push_back(static_cast<char>(length));
        out.append(text.substr(0, length));
    };
    if (!first.empty())
        label(first);
    while (!service.empty())
    {
        const std::size_t dot = service.find('.');
        label(service.substr(0, dot));
        service = dot == std::string_view::npos ? std::string_view {} : service.substr(dot + 1);
    }
    out.push_back('\0');
    put16(out, type);
    put16(out, 1);
    return out;
}

String ipv4_text(Bytes rdata, const Allocator& allocator)
{
    String out(allocator);
    for (std::size_t i = 0; i < 4; ++i)
    {
        if (i != 0)
            out.push_back('.');
        std::array<char, 4> digits {};
        const auto result = std::to_chars(digits.data(), digits.data() + digits.size(), rdata[i]);
        out.append(digits.data(), result.ptr);
    }
    return out;
}

// An IPv6 address, its longest run of zero groups as `::` (RFC 5952).
String ipv6_text(Bytes rdata, const Allocator& allocator)
{
    std::array<std::uint16_t, 8> groups {};
    for (std::size_t i = 0; i < 8; ++i)
        groups[i] = static_cast<std::uint16_t>((rdata[2 * i] << 8) | rdata[2 * i + 1]);
    std::size_t best        = 8;
    std::size_t best_length = 0;
    for (std::size_t i = 0; i < 8;)
    {
        if (groups[i] != 0)
        {
            ++i;
            continue;
        }
        std::size_t j = i;
        while (j < 8 && groups[j] == 0)
            ++j;
        if (j - i > best_length)
        {
            best        = i;
            best_length = j - i;
        }
        i = j;
    }
    String out(allocator);
    const auto write = [&](std::size_t from, std::size_t to)
    {
        for (std::size_t i = from; i < to; ++i)
        {
            if (i != from)
                out.push_back(':');
            std::array<char, 5> digits {};
            const auto result = std::to_chars(digits.data(), digits.data() + digits.size(), groups[i], 16);
            out.append(digits.data(), result.ptr);
        }
    };
    if (best_length < 2)
    {
        write(0, 8);
        return out;
    }
    write(0, best);
    out.append("::");
    write(best + best_length, 8);
    return out;
}

struct Instance
{
    String key;
    String first;
    String from;
    String target;
    String txt;
    std::uint16_t port = 0;
    bool has_port      = false;
    bool has_txt       = false;

    explicit Instance(const Allocator& allocator)
        : key(allocator)
        , first(allocator)
        , from(allocator)
        , target(allocator)
        , txt(allocator)
    {
    }
};

struct Host
{
    String key;
    String v4;
    String v6;

    explicit Host(const Allocator& allocator)
        : key(allocator)
        , v4(allocator)
        , v6(allocator)
    {
    }
};

// What the answers of a browse say, gathered.
class Gathered
{
  public:
    Gathered(std::string_view service, const Allocator& allocator)
        : service_(service)
        , allocator_(allocator)
        , service_key_(allocator)
        , instances_(allocator)
        , hosts_(allocator)
    {
        std::size_t start = 0;
        while (start <= service.size())
        {
            const std::size_t dot = service.find('.', start);
            const auto label      = service.substr(start, dot == std::string_view::npos ? dot : dot - start);
            if (start != 0)
                service_key_.push_back('.');
            append_key(service_key_, label);
            if (dot == std::string_view::npos)
                break;
            start = dot + 1;
        }
    }

    void add(Bytes message, std::string_view from)
    {
        if (message.size() < 12 || message.size() > max_message)
            return;
        // A response, of the standard query's opcode, with no error
        const std::uint16_t flags = u16(message, 2);
        if ((flags & 0x8000U) == 0 || (flags & 0x7800U) != 0 || (flags & 0x000fU) != 0)
            return;
        const std::size_t questions = u16(message, 4);
        const std::size_t total     = std::size_t { u16(message, 6) } + u16(message, 8) + u16(message, 10);
        if (questions > 16 || total > max_records)
            return;
        std::size_t at = 12;
        for (std::size_t i = 0; i < questions; ++i)
        {
            const ParsedName name = read_name(message, at, allocator_);
            if (!name.ok || name.next + 4 > message.size())
                return;
            at = name.next + 4;
        }
        for (std::size_t i = 0; i < total; ++i)
        {
            const ParsedName owner = read_name(message, at, allocator_);
            if (!owner.ok || owner.next + 10 > message.size())
                return;
            const std::uint16_t type = u16(message, owner.next);
            const std::uint32_t ttl  = u32(message, owner.next + 4);
            const std::size_t length = u16(message, owner.next + 8);
            const std::size_t start  = owner.next + 10;
            if (start + length > message.size())
                return;
            record(message, owner, type, ttl, start, length, from);
            at = start + length;
        }
    }

    // The instances whose port or TXT has not come: the questions for them.
    [[nodiscard]] Vector<String> follow_ups() const
    {
        Vector<String> out(allocator_);
        for (const Instance& instance : instances_)
        {
            if (!instance.has_port || !instance.has_txt)
                out.push_back(question(instance.first, service_, type_any, allocator_));
        }
        return out;
    }

    [[nodiscard]] const Vector<Instance>& instances() const noexcept { return instances_; }

    // The address of an instance's host, or the one its answer came from.
    [[nodiscard]] String address_of(const Instance& instance) const
    {
        for (const Host& host : hosts_)
        {
            if (host.key == instance.target)
            {
                if (!host.v4.empty())
                    return host.v4;
                if (!host.v6.empty())
                    return host.v6;
            }
        }
        return instance.from;
    }

  private:
    Instance* find(std::string_view key)
    {
        for (Instance& instance : instances_)
        {
            if (instance.key == key)
                return &instance;
        }
        return nullptr;
    }

    void record(Bytes message, const ParsedName& owner, std::uint16_t type, std::uint32_t ttl,
        std::size_t start, std::size_t length, std::string_view from)
    {
        const Bytes rdata = message.subspan(start, length);
        if (type == type_ptr && owner.key == service_key_)
        {
            const ParsedName instance = read_name(message, start, allocator_);
            if (!instance.ok || instance.labels < 2 || instance.rest != service_key_)
                return;
            const Instance* known = find(instance.key);
            if (ttl == 0)
            {
                if (known != nullptr)
                    instances_.erase(instances_.begin() + (known - instances_.data()));
            }
            else if (known == nullptr && instances_.size() < max_instances)
            {
                Instance made(allocator_);
                made.key.assign(instance.key);
                made.first.assign(instance.first);
                made.from.assign(from);
                instances_.push_back(std::move(made));
            }
        }
        else if (type == type_srv && length >= 7)
        {
            Instance* known = find(owner.key);
            if (known == nullptr)
                return;
            const ParsedName target = read_name(message, start + 6, allocator_);
            if (!target.ok)
                return;
            known->port     = u16(rdata, 4);
            known->has_port = true;
            known->target.assign(target.key);
            known->from.assign(from);
        }
        else if (type == type_txt)
        {
            Instance* known = find(owner.key);
            if (known == nullptr || length > max_txt)
                return;
            known->txt.assign(reinterpret_cast<const char*>(rdata.data()), rdata.size());
            known->has_txt = true;
        }
        else if ((type == type_a && length == 4) || (type == type_aaaa && length == 16))
        {
            Host* host = nullptr;
            for (Host& each : hosts_)
            {
                if (each.key == owner.key)
                    host = &each;
            }
            if (host == nullptr)
            {
                if (hosts_.size() >= max_hosts)
                    return;
                hosts_.emplace_back(allocator_);
                host = &hosts_.back();
                host->key.assign(owner.key);
            }
            if (type == type_a)
                host->v4 = ipv4_text(rdata, allocator_);
            else
                host->v6 = ipv6_text(rdata, allocator_);
        }
    }

    std::string_view service_;
    Allocator allocator_;
    String service_key_;
    Vector<Instance> instances_;
    Vector<Host> hosts_;
};

// The first value of a TXT key (RFC 6763 § 6), the key compared without case.
std::optional<std::string_view> txt_value(std::string_view txt, std::string_view key)
{
    std::size_t at = 0;
    while (at < txt.size())
    {
        const std::size_t length = static_cast<unsigned char>(txt[at]);
        if (length == 0 || at + 1 + length > txt.size())
            return std::nullopt;
        const std::string_view entry = txt.substr(at + 1, length);
        at += 1 + length;
        const std::size_t eq = entry.find('=');
        const auto name      = entry.substr(0, eq);
        if (name.size() != key.size()
            || !std::ranges::equal(name, key, [](char a, char b) { return lower(a) == lower(b); }))
            continue;
        return eq == std::string_view::npos ? std::string_view {} : entry.substr(eq + 1);
    }
    return std::nullopt;
}

// A name a person reads: no control character, bounded.
String display(std::string_view text, const Allocator& allocator)
{
    String out(allocator);
    for (const char c : text.substr(0, max_display))
        out.push_back(static_cast<unsigned char>(c) < 0x20 || c == 0x7f ? ' ' : c);
    return out;
}

void json_string(String& out, std::string_view text)
{
    out.push_back('"');
    for (const char c : text)
    {
        if (c == '"' || c == '\\')
        {
            out.push_back('\\');
            out.push_back(c);
        }
        else if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f)
            out.push_back(' ');
        else
            out.push_back(c);
    }
    out.push_back('"');
}

// "1,2" as a JSON array, or nothing when it is not a list of versions.
std::optional<String> versions_json(std::string_view text, const Allocator& allocator)
{
    String out(allocator);
    out.push_back('[');
    std::size_t count = 0;
    while (!text.empty())
    {
        const std::size_t comma = text.find(',');
        const auto number       = text.substr(0, comma);
        std::uint32_t value     = 0;
        const auto parsed       = std::from_chars(number.data(), number.data() + number.size(), value);
        if (number.empty() || parsed.ec != std::errc {} || parsed.ptr != number.data() + number.size()
            || value < 1 || ++count > 16)
            return std::nullopt;
        if (count > 1)
            out.push_back(',');
        out.append(number);
        text = comma == std::string_view::npos ? std::string_view {} : text.substr(comma + 1);
    }
    if (count == 0)
        return std::nullopt;
    out.push_back(']');
    return out;
}

bool is_uuid(std::string_view text) noexcept
{
    const auto hex = [](std::string_view part)
    {
        return std::ranges::all_of(part, [](char c)
            { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); });
    };
    return text.size() == 36 && text[8] == '-' && text[13] == '-' && text[18] == '-' && text[23] == '-'
        && hex(text.substr(0, 8)) && hex(text.substr(9, 4)) && hex(text.substr(14, 4))
        && hex(text.substr(19, 4)) && hex(text.substr(24));
}

} // namespace

Result<void> browse_dnssd(UdpSocket& socket, const DnssdOptions& options, DiscoveryHandler& handler)
{
    if (options.address.empty())
        return fail(Category::usage, "a browse needs an address");
    const Allocator allocator(options.decode.memory);
    const std::string_view service = options.peers ? peer_service : server_service;
    Gathered gathered(service, allocator);
    const auto send = [&](const String& message)
    {
        return socket.send_to(
            options.address, options.port, std::as_bytes(std::span(message.data(), message.size())));
    };
    if (auto sent = send(question({}, service, type_ptr, allocator)); !sent)
        return sent;

    using steady      = std::chrono::steady_clock;
    const auto start  = steady::now();
    const auto end    = start + options.wait;
    const auto follow = start + options.wait / 3;
    bool followed     = false;
    std::array<std::byte, max_message + 1> buffer {};
    for (;;)
    {
        const auto now = steady::now();
        if (now >= end)
            break;
        if (!followed && now >= follow)
        {
            followed = true;
            // An answer that came without an instance's port or TXT: ask for them once
            for (const String& message : gathered.follow_ups())
            {
                if (auto sent = send(message); !sent)
                    return sent;
            }
        }
        const auto next    = followed ? end : follow;
        const auto timeout = std::max(
            std::chrono::milliseconds(1), std::chrono::duration_cast<std::chrono::milliseconds>(next - now));
        const auto got = socket.receive(buffer, timeout);
        if (!got)
            return std::unexpected(got.error());
        if (!*got || (*got)->size > max_message)
            continue;
        const Datagram& datagram = **got;
        const Bytes message(reinterpret_cast<const std::uint8_t*>(buffer.data()), datagram.size);
        gathered.add(message, datagram.address_view());
    }

    Vector<String> seen(allocator);
    for (const Instance& instance : gathered.instances())
    {
        if (!instance.has_port || !instance.has_txt || instance.port == 0)
            continue;
        const String address = gathered.address_of(instance);
        const auto origin    = discovered_origin(address, instance.port, allocator);
        if (!origin)
            continue;
        const auto path     = txt_value(instance.txt, "path");
        const auto versions = txt_value(instance.txt, "v");
        if (!path || !versions)
            continue;
        if (options.peers)
        {
            const auto servers = txt_value(instance.txt, "servers");
            const auto tls     = txt_value(instance.txt, "tls");
            if (!servers || !tls || (*tls != "0" && *tls != "1"))
                continue;
            // The versions hold 1, and the path is a base without its last slash
            std::string_view base = *path;
            while (base.size() > 1 && base.back() == '/')
                base.remove_suffix(1);
            bool has_one = false;
            for (std::string_view rest = *versions; !rest.empty();)
            {
                const std::size_t comma = rest.find(',');
                has_one                 = has_one || rest.substr(0, comma) == "1";
                rest = comma == std::string_view::npos ? std::string_view {} : rest.substr(comma + 1);
            }
            if (!has_one || base.empty() || base.front() != '/' || base.starts_with("//")
                || base.back() == '/' || base.size() > 256
                || base.find_first_of("?# \\") != std::string_view::npos)
                continue;
            PeerReply reply(allocator);
            reply.lantern = "peer";
            reply.name    = display(instance.first, allocator);
            reply.port    = instance.port;
            reply.base.assign(base);
            reply.tls   = *tls == "1";
            reply.slots = 1;
            bool valid  = true;
            for (std::string_view rest = *servers; !rest.empty();)
            {
                const std::size_t comma = rest.find(',');
                const auto uid          = rest.substr(0, comma);
                rest = comma == std::string_view::npos ? std::string_view {} : rest.substr(comma + 1);
                if (uid.empty())
                    continue;
                valid = valid && is_uuid(uid) && reply.servers.size() < 16;
                if (valid)
                    reply.servers.emplace_back(uid);
            }
            if (!valid || reply.servers.empty())
                continue;
            String key(reply.name, allocator);
            key.push_back(' ');
            key.append(address);
            if (std::ranges::find(seen, key) != seen.end() || seen.size() >= max_instances)
                continue;
            seen.push_back(std::move(key));
            DiscoveredPeer out;
            out.address       = address;
            out.reply         = &reply;
            out.endpoint.host = address;
            out.endpoint.port = instance.port;
            out.endpoint.base = reply.base;
            out.endpoint.tls  = reply.tls;
            if (!handler.on_peer(out))
                return {};
            continue;
        }
        // A server's: held to the rules of its datagram reply
        const auto uid  = txt_value(instance.txt, "uid");
        const auto list = versions_json(*versions, allocator);
        if (!uid || !list)
            continue;
        String json(allocator);
        json.append(R"({"schema":1,"lantern":"server","uid":)");
        json_string(json, *uid);
        json.append(R"(,"name":)");
        json_string(json, display(instance.first, allocator));
        json.append(R"(,"port":)");
        json.append(std::to_string(instance.port));
        json.append(R"(,"base":)");
        json_string(json, *path);
        json.append(R"(,"versions":)");
        json.append(*list);
        json.push_back('}');
        const auto read
            = read_discovery_datagram(std::as_bytes(std::span(json.data(), json.size())), options.decode);
        if (!read || !*read)
            continue;
        const DiscoveryReply& found = **read;
        if (std::ranges::find(seen, found.uid) != seen.end() || seen.size() >= max_instances)
            continue;
        seen.emplace_back(found.uid);
        DiscoveredServer server;
        server.address = address;
        server.reply   = &found;
        server.origin  = *origin;
        if (!handler.on_server(server))
            return {};
    }
    return {};
}

} // namespace lantern
