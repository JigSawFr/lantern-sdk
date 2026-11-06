// DNS-SD (SPEC.md § 4.1, § 19.5): the answers a client reads, hostile ones included.
#include <doctest.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <lantern/dnssd.hpp>
#include <lantern/lantern.hpp>

using namespace lantern;

namespace
{

using Raw = std::vector<std::uint8_t>;

constexpr std::string_view uid = "6f1c2a8e-0000-4000-8000-000000000001";

void add(Raw& out, std::string_view text)
{
    out.insert(out.end(), text.begin(), text.end());
}

void u16(Raw& out, std::uint16_t value)
{
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

// A name from its labels; `pointer`, when not zero, ends it with a compression pointer.
Raw name(const std::vector<std::string>& labels, std::size_t pointer = 0)
{
    Raw out;
    for (const std::string& label : labels)
    {
        out.push_back(static_cast<std::uint8_t>(label.size()));
        add(out, label);
    }
    if (pointer == 0)
        out.push_back(0);
    else
    {
        out.push_back(static_cast<std::uint8_t>(0xc0U | (pointer >> 8)));
        out.push_back(static_cast<std::uint8_t>(pointer & 0xffU));
    }
    return out;
}

Raw record(const Raw& owner, std::uint16_t type, const Raw& rdata, std::uint32_t ttl = 120)
{
    Raw out = owner;
    u16(out, type);
    u16(out, 1);
    u16(out, static_cast<std::uint16_t>(ttl >> 16));
    u16(out, static_cast<std::uint16_t>(ttl & 0xffffU));
    u16(out, static_cast<std::uint16_t>(rdata.size()));
    out.insert(out.end(), rdata.begin(), rdata.end());
    return out;
}

Raw txt(const std::vector<std::string>& pairs)
{
    Raw out;
    for (const std::string& pair : pairs)
    {
        out.push_back(static_cast<std::uint8_t>(pair.size()));
        add(out, pair);
    }
    return out;
}

Raw srv(std::uint16_t port, const Raw& host)
{
    Raw out;
    u16(out, 0);
    u16(out, 0);
    u16(out, port);
    out.insert(out.end(), host.begin(), host.end());
    return out;
}

Raw response(const std::vector<Raw>& records, std::uint16_t flags = 0x8400)
{
    Raw out;
    u16(out, 0);
    u16(out, flags);
    u16(out, 0);
    u16(out, static_cast<std::uint16_t>(records.size()));
    u16(out, 0);
    u16(out, 0);
    for (const Raw& each : records)
        out.insert(out.end(), each.begin(), each.end());
    return out;
}

const std::vector<std::string> service  = { "_lantern", "_tcp", "local" };
const std::vector<std::string> instance = { "Living room shelf", "_lantern", "_tcp", "local" };
const std::vector<std::string> host     = { "shelf", "local" };

Raw advertisement(std::optional<Raw> address = Raw { 192, 168, 1, 20 },
    std::vector<std::string> pairs           = { "uid=" + std::string(uid), "path=/api/lantern", "v=1" },
    std::uint16_t port                       = 8443)
{
    std::vector<Raw> records {
        record(name(service), 12, name(instance)),
        record(name(instance), 33, srv(port, name(host))),
        record(name(instance), 16, txt(pairs)),
    };
    if (address)
        records.push_back(record(name(host), 1, *address));
    return response(records);
}

// A socket that hears what it is given, and may answer a question with more.
struct Socket final : UdpSocket
{
    std::deque<std::pair<std::string, Raw>> heard;
    std::vector<Raw> asked;
    std::function<void(Socket&, const Raw&)> on_question;

    Result<void> send_to(
        std::string_view address, std::uint16_t port, std::span<const std::byte> bytes) override
    {
        CHECK(address == "224.0.0.251");
        CHECK(port == 5353);
        Raw question(bytes.size());
        std::transform(bytes.begin(), bytes.end(), question.begin(),
            [](std::byte b) { return std::to_integer<std::uint8_t>(b); });
        asked.push_back(question);
        if (on_question)
            on_question(*this, question);
        return {};
    }

    Result<std::optional<Datagram>> receive(
        std::span<std::byte> buffer, std::chrono::milliseconds timeout) override
    {
        if (heard.empty())
        {
            std::this_thread::sleep_for(std::min(timeout, std::chrono::milliseconds(10)));
            return std::optional<Datagram> {};
        }
        auto [address, bytes] = heard.front();
        heard.pop_front();
        Datagram d;
        d.size = std::min(bytes.size(), buffer.size());
        for (std::size_t i = 0; i < d.size; ++i)
            buffer[i] = static_cast<std::byte>(bytes[i]);
        std::copy(address.begin(), address.end(), d.address.begin());
        d.address_size = address.size();
        d.port         = 5353;
        return std::optional<Datagram>(d);
    }
};

struct Found final : DiscoveryHandler
{
    struct Server
    {
        std::string address;
        std::string origin;
        std::string uid;
        std::string name;
        std::string base;
        std::vector<std::uint64_t> versions;
        std::uint64_t port;
    };
    struct Peer
    {
        std::string address;
        std::string name;
        std::string base;
        bool tls;
        std::vector<std::string> servers;
        std::uint16_t port;
    };
    std::vector<Server> servers;
    std::vector<Peer> peers;

    bool on_server(const DiscoveredServer& server) override
    {
        servers.push_back({ std::string(server.address), std::string(server.origin),
            std::string(server.reply->uid), std::string(server.reply->name), std::string(server.reply->base),
            std::vector<std::uint64_t>(server.reply->versions.begin(), server.reply->versions.end()),
            server.reply->port });
        return true;
    }
    bool on_peer(const DiscoveredPeer& peer) override
    {
        std::vector<std::string> servers_of;
        for (const String& each : peer.reply->servers)
            servers_of.emplace_back(each);
        peers.push_back({ std::string(peer.address), std::string(peer.reply->name),
            std::string(peer.reply->base), peer.reply->tls, servers_of, peer.endpoint.port });
        return true;
    }
};

DnssdOptions quick(bool peers = false, int wait = 60)
{
    DnssdOptions options;
    options.wait  = std::chrono::milliseconds(wait);
    options.peers = peers;
    return options;
}

Found browse(Socket& socket, bool peers = false, int wait = 60)
{
    Found found;
    REQUIRE(browse_dnssd(socket, quick(peers, wait), found));
    return found;
}

std::vector<Found::Server> servers_of(const Raw& message, std::string_view from = "192.168.1.99")
{
    Socket socket;
    socket.heard.emplace_back(std::string(from), message);
    return browse(socket, false, 3).servers;
}

} // namespace

TEST_CASE("dnssd: the question is the service's PTR, in class IN")
{
    Socket socket;
    const Found found = browse(socket);
    CHECK(found.servers.empty());
    REQUIRE_FALSE(socket.asked.empty());
    const Raw expected = []
    {
        Raw out;
        u16(out, 1);
        u16(out, 0);
        u16(out, 1);
        u16(out, 0);
        u16(out, 0);
        u16(out, 0);
        const Raw labels = name(service);
        out.insert(out.end(), labels.begin(), labels.end());
        u16(out, 12);
        u16(out, 1);
        return out;
    }();
    CHECK(socket.asked.front() == expected);
}

TEST_CASE("dnssd: a server's advertisement is a server found, at the address its host says")
{
    const auto found = servers_of(advertisement());
    REQUIRE(found.size() == 1);
    CHECK(found[0].address == "192.168.1.20");
    CHECK(found[0].origin == "https://192.168.1.20:8443");
    CHECK(found[0].uid == uid);
    CHECK(found[0].name == "Living room shelf");
    CHECK(found[0].base == "/api/lantern");
    CHECK(found[0].versions == std::vector<std::uint64_t> { 1 });
    CHECK(found[0].port == 8443);
}

TEST_CASE("dnssd: with no address of its own, the one the answer came from stands for it")
{
    const auto found
        = servers_of(advertisement(std::nullopt, { "uid=" + std::string(uid), "path=/api/lantern", "v=1,2" }),
            "192.168.1.77");
    REQUIRE(found.size() == 1);
    CHECK(found[0].address == "192.168.1.77");
    CHECK(found[0].versions == std::vector<std::uint64_t> { 1, 2 });
}

TEST_CASE("dnssd: an IPv6 address is written short, and names are not case-sensitive")
{
    Raw address;
    for (const int group : { 0xfe80, 0, 0, 0, 0x1234, 0, 0, 1 })
        u16(address, static_cast<std::uint16_t>(group));
    const Raw message = response({
        record(name({ "_LANTERN", "_TCP", "LOCAL" }), 12, name({ "Shelf", "_Lantern", "_tcp", "local" })),
        record(name({ "shelf", "_lantern", "_tcp", "LOCAL" }), 33, srv(8443, name({ "Shelf", "Local" }))),
        record(name({ "SHELF", "_lantern", "_tcp", "local" }), 16,
            txt({ "UID=" + std::string(uid), "Path=/api/lantern", "V=1" })),
        record(name({ "shelf", "local" }), 28, address),
    });
    const auto found  = servers_of(message, "fe80::1");
    REQUIRE(found.size() == 1);
    CHECK(found[0].address == "fe80::1234:0:0:1");
    CHECK(found[0].origin == "https://[fe80::1234:0:0:1]:8443");
}

TEST_CASE("dnssd: names are compressed as responders write them")
{
    Raw head;
    u16(head, 0);
    u16(head, 0x8400);
    u16(head, 0);
    u16(head, 3);
    u16(head, 0);
    u16(head, 0);
    const Raw owner               = name(service);
    const Raw ptr                 = record(owner, 12, name({ "Shelf" }, 12));
    const std::size_t instance_at = 12 + owner.size() + 10;
    Raw message                   = head;
    for (const Raw& each : { ptr, record(name({}, instance_at), 33, srv(8443, name(host))),
             record(
                 name({}, instance_at), 16, txt({ "uid=" + std::string(uid), "path=/api/lantern", "v=1" })) })
        message.insert(message.end(), each.begin(), each.end());
    const auto found = servers_of(message);
    REQUIRE(found.size() == 1);
    CHECK(found[0].name == "Shelf");
    CHECK(found[0].port == 8443);
}

TEST_CASE("dnssd: a goodbye forgets the instance")
{
    Socket socket;
    socket.heard.emplace_back("192.168.1.99", advertisement());
    socket.heard.emplace_back("192.168.1.99", response({ record(name(service), 12, name(instance), 0) }));
    CHECK(browse(socket).servers.empty());
}

TEST_CASE("dnssd: an instance without its port or its TXT is asked for them, once")
{
    Socket socket;
    socket.heard.emplace_back("192.168.1.99", response({ record(name(service), 12, name(instance)) }));
    socket.on_question = [](Socket& self, const Raw& question)
    {
        // Only the instance's question gets the advertisement
        if (question.size() > 20 && question[12] == 17)
            self.heard.emplace_back("192.168.1.99", advertisement(Raw { 10, 1, 2, 3 }));
    };
    const Found found = browse(socket);
    REQUIRE(found.servers.size() == 1);
    CHECK(found.servers[0].address == "10.1.2.3");
    REQUIRE(socket.asked.size() == 2);
    // The instance's question: its label as written (it holds spaces), type ANY
    const Raw& second = socket.asked[1];
    CHECK(second[12] == 17);
    CHECK(std::string(second.begin() + 13, second.begin() + 30) == "Living room shelf");
    CHECK(second[second.size() - 4] == 0);
    CHECK(second[second.size() - 3] == 255);
}

TEST_CASE("dnssd: a TXT that is not a server's is left out")
{
    const std::string id = "uid=" + std::string(uid);
    const std::vector<std::vector<std::string>> bad {
        { id, "v=1" }, // no path
        { id, "path=//evil", "v=1" }, { id, "path=/a?b", "v=1" }, { id, "path=/api/lantern/", "v=1" },
        { "path=/api/lantern", "v=1" }, // no uid
        { "uid=not-a-uuid", "path=/api/lantern", "v=1" }, { id, "path=/api/lantern" }, // no versions
        { id, "path=/api/lantern", "v=one" }, { id, "path=/api/lantern", "v=0" },
        { id, "path=/api/lantern", "v=2" }, // no version 1
    };
    for (const auto& pairs : bad)
        CHECK(servers_of(advertisement(Raw { 192, 168, 1, 20 }, pairs)).empty());
    CHECK(servers_of(advertisement(Raw { 192, 168, 1, 20 }, { id, "path=/api/lantern", "v=1" }, 0)).empty());
}

TEST_CASE("dnssd: another service's instances are not this one's, and a server is found once")
{
    const std::vector<std::string> http    = { "_http", "_tcp", "local" };
    const std::vector<std::string> printer = { "Printer", "_http", "_tcp", "local" };
    CHECK(servers_of(
        response({ record(name(http), 12, name(printer)), record(name(printer), 33, srv(80, name(host))),
            record(name(printer), 16, txt({ "uid=" + std::string(uid), "path=/x", "v=1" })) }))
              .empty());
    Socket socket;
    socket.heard.emplace_back("192.168.1.99", advertisement());
    socket.heard.emplace_back("192.168.1.98", advertisement());
    CHECK(browse(socket).servers.size() == 1);
}

TEST_CASE("dnssd: a peer's advertisement")
{
    const std::vector<std::string> peer_service  = { "_lantern-peer", "_tcp", "local" };
    const std::vector<std::string> peer_instance = { "Den console", "_lantern-peer", "_tcp", "local" };
    const auto message = [&](const std::string& tls, const std::string& servers, const std::string& path)
    {
        return response({ record(name(peer_service), 12, name(peer_instance)),
            record(name(peer_instance), 33, srv(47116, name(host))),
            record(
                name(peer_instance), 16, txt({ "servers=" + servers, "path=" + path, "v=1", "tls=" + tls })),
            record(name(host), 1, Raw { 192, 168, 1, 30 }) });
    };
    Socket socket;
    socket.heard.emplace_back(
        "192.168.1.30", message("1", std::string(uid) + "," + std::string(uid), "/peer/"));
    const Found found = browse(socket, true);
    REQUIRE(found.peers.size() == 1);
    CHECK(found.peers[0].address == "192.168.1.30");
    CHECK(found.peers[0].name == "Den console");
    CHECK(found.peers[0].base == "/peer");
    CHECK(found.peers[0].tls);
    CHECK(found.peers[0].servers.size() == 2);
    CHECK(found.peers[0].port == 47116);
    CHECK(found.servers.empty());

    for (const Raw& bad : { message("2", std::string(uid), "/peer"), message("1", "not-a-uuid", "/peer"),
             message("1", "", "/peer"), message("1", std::string(uid), "peer") })
    {
        Socket other;
        other.heard.emplace_back("192.168.1.30", bad);
        CHECK(browse(other, true).peers.empty());
    }
}

TEST_CASE("dnssd: hostile answers are dropped, never an error")
{
    const Raw good = advertisement();
    CHECK(servers_of(response({ record(name(service), 12, name(instance)) }, 0x0400)).empty());
    Raw error = good;
    error[3]  = 0x03;
    CHECK(servers_of(error).empty());
    Raw opcode = good;
    opcode[2]  = 0xa4;
    CHECK(servers_of(opcode).empty());

    // A pointer that loops, one that goes forward
    Raw looping;
    u16(looping, 0);
    u16(looping, 0x8400);
    u16(looping, 0);
    u16(looping, 1);
    u16(looping, 0);
    u16(looping, 0);
    looping.push_back(0xc0);
    looping.push_back(12);
    for (const int value : { 12, 1, 0, 1, 0 })
        u16(looping, static_cast<std::uint16_t>(value));
    CHECK(servers_of(looping).empty());
    Raw forward = looping;
    forward[13] = 40;
    forward.resize(forward.size() + 40);
    CHECK(servers_of(forward).empty());

    // Counts the message cannot hold, a label that does not fit, noise, too much
    Raw counts = good;
    counts[6]  = 0xff;
    counts[7]  = 0xff;
    CHECK(servers_of(counts).empty());
    Raw label(good.begin(), good.begin() + 12);
    label.push_back(0x80);
    CHECK(servers_of(label).empty());
    CHECK(servers_of(Raw(9001, 0x80)).empty());
    CHECK(servers_of(Raw {}).empty());
    CHECK(servers_of(Raw { 1, 2, 3 }).empty());
}

TEST_CASE("dnssd: a message cut or flipped anywhere is never an error")
{
    const Raw good = advertisement();
    for (std::size_t n = 0; n < good.size(); ++n)
        (void)servers_of(Raw(good.begin(), good.begin() + static_cast<std::ptrdiff_t>(n)));
    for (std::size_t n = 0; n < good.size(); ++n)
    {
        for (const int x : { 0x01, 0x80, 0xff })
        {
            Raw flipped = good;
            flipped[n]  = static_cast<std::uint8_t>(flipped[n] ^ static_cast<std::uint8_t>(x));
            (void)servers_of(flipped);
        }
    }
}

TEST_CASE("dnssd: a network of instances is bounded")
{
    Socket socket;
    for (int i = 0; i < 200; ++i)
        socket.heard.emplace_back("192.168.1.99",
            response({ record(
                name(service), 12, name({ "n" + std::to_string(i), "_lantern", "_tcp", "local" })) }));
    const Found found = browse(socket);
    CHECK(found.servers.empty());
    // At most 64 are asked for, each once
    CHECK(socket.asked.size() <= 1 + 64);
}

TEST_CASE("dnssd: a browse needs an address")
{
    Socket socket;
    Found found;
    DnssdOptions options = quick();
    options.address      = {};
    CHECK_FALSE(browse_dnssd(socket, options, found));
}
