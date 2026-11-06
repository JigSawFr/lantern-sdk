#include <lantern/deflate.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <utility>

namespace lantern
{

namespace
{

constexpr std::size_t window_size   = 32768;
constexpr std::size_t window_mask   = window_size - 1;
constexpr std::size_t hash_bits     = 15;
constexpr std::size_t min_match     = 3;
constexpr std::size_t max_match     = 258;
constexpr std::size_t nice_match    = 128;
constexpr unsigned max_chain        = 48;
constexpr std::uint32_t hash_factor = 0x9e3779b1U;
constexpr unsigned hash_shift       = 32 - hash_bits;
constexpr std::size_t end_of_block  = 256;
constexpr std::size_t length_symbol = 257;
constexpr std::size_t literal_codes = 288;
constexpr std::size_t stored_max    = 65535;
// Positions are kept in 32 bits (plus one, 0 meaning none); a longer input is stored.
constexpr std::uint32_t position_limit = 0xfffffff0U;

constexpr std::array<std::uint16_t, 29> length_base { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
constexpr std::array<std::uint8_t, 29> length_extra { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3,
    3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
constexpr std::array<std::uint16_t, 30> distance_base { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129,
    193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };

constexpr std::array<std::uint32_t, 256> crc_table = []
{
    std::array<std::uint32_t, 256> table {};
    for (std::uint32_t n = 0; n < 256; ++n)
    {
        std::uint32_t c = n;
        for (int k = 0; k < 8; ++k)
            c = (c & 1U) != 0 ? 0xedb88320U ^ (c >> 1) : c >> 1;
        table[n] = c;
    }
    return table;
}();

constexpr std::uint32_t reversed(std::uint32_t code, unsigned bits) noexcept
{
    std::uint32_t out = 0;
    for (unsigned i = 0; i < bits; ++i)
    {
        out = (out << 1U) | (code & 1U);
        code >>= 1U;
    }
    return out;
}

struct Symbol
{
    std::uint16_t code; // in the order the bits are written (least significant first)
    std::uint8_t bits;
};

// The fixed literal and length code of RFC 1951 § 3.2.6.
constexpr std::array<Symbol, literal_codes> fixed_literals = []
{
    std::array<Symbol, literal_codes> table {};
    for (std::uint32_t s = 0; s < literal_codes; ++s)
    {
        std::uint32_t code = 0;
        unsigned bits      = 0;
        if (s < 144)
        {
            code = 0x30U + s;
            bits = 8;
        }
        else if (s < 256)
        {
            code = 0x190U + (s - 144);
            bits = 9;
        }
        else if (s < 280)
        {
            code = s - 256;
            bits = 7;
        }
        else
        {
            code = 0xc0U + (s - 280);
            bits = 8;
        }
        table[s] = { static_cast<std::uint16_t>(reversed(code, bits)), static_cast<std::uint8_t>(bits) };
    }
    return table;
}();

// For a length of 3 to 258, the index in length_base.
constexpr std::array<std::uint8_t, max_match + 1> length_index = []
{
    std::array<std::uint8_t, max_match + 1> table {};
    for (std::size_t i = 0; i < 28; ++i)
        for (std::size_t n = 0; n < (std::size_t { 1 } << length_extra[i]); ++n)
            table[length_base[i] + n] = static_cast<std::uint8_t>(i);
    table[max_match] = 28;
    return table;
}();

// The distance code of 1 to 32768: 0 to 29.
constexpr std::size_t distance_code(std::size_t distance) noexcept
{
    if (distance <= 4)
        return distance - 1;
    const std::size_t before = distance - 1;
    const std::size_t top    = static_cast<std::size_t>(std::bit_width(before)) - 1;
    return (2 * top) + ((before >> (top - 1)) & 1U);
}

class BitWriter
{
  public:
    explicit BitWriter(String& out) noexcept
        : out_(out)
    {
    }

    void put(std::uint32_t value, unsigned bits)
    {
        buffer_ |= static_cast<std::uint64_t>(value) << count_;
        count_ += bits;
        while (count_ >= 8)
        {
            out_.push_back(static_cast<char>(buffer_ & 0xffU));
            buffer_ >>= 8U;
            count_ -= 8;
        }
    }

    void put(Symbol symbol) { put(symbol.code, symbol.bits); }

    void align()
    {
        if (count_ > 0)
            put(0, 8 - count_);
    }

  private:
    String& out_;
    std::uint64_t buffer_ = 0;
    unsigned count_       = 0;
};

void le32(String& out, std::uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i)
        out.push_back(static_cast<char>((value >> (8 * i)) & 0xffU));
}

void header(String& out)
{
    // magic, deflate, no flags, no time, no extra flags, "unknown" system
    static constexpr std::array<unsigned char, 10> bytes { 0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff };
    for (const unsigned char byte : bytes)
        out.push_back(static_cast<char>(byte));
}

// Stored blocks, for an input whose positions would not fit in 32 bits.
void store(std::span<const std::byte> data, String& out)
{
    std::size_t at = 0;
    do
    {
        const std::size_t length = std::min(stored_max, data.size() - at);
        const bool last          = at + length == data.size();
        out.push_back(last ? '\x01' : '\x00');
        out.push_back(static_cast<char>(length & 0xffU));
        out.push_back(static_cast<char>((length >> 8U) & 0xffU));
        out.push_back(static_cast<char>(~length & 0xffU));
        out.push_back(static_cast<char>((~length >> 8U) & 0xffU));
        for (std::size_t i = 0; i < length; ++i)
            out.push_back(static_cast<char>(std::to_integer<unsigned>(data[at + i])));
        at += length;
    } while (at < data.size());
}

class Compressor
{
  public:
    Compressor(std::span<const std::byte> data, String& out)
        : data_(data)
        , writer_(out)
        , head_(std::size_t { 1 } << hash_bits, 0U, out.get_allocator())
        , prev_(window_size, 0U, out.get_allocator())
    {
    }

    void run()
    {
        const std::size_t size = data_.size();
        writer_.put(0x3U, 3); // the last block, fixed Huffman
        std::size_t pos = 0;
        while (pos < size)
        {
            std::size_t length   = 0;
            std::size_t distance = 0;
            find(pos, length, distance);
            if (length >= min_match)
            {
                const std::size_t code = length_index[length];
                writer_.put(fixed_literals[length_symbol + code]);
                writer_.put(static_cast<std::uint32_t>(length - length_base[code]), length_extra[code]);
                const std::size_t slot = distance_code(distance);
                writer_.put(reversed(static_cast<std::uint32_t>(slot), 5), 5);
                const unsigned extra = slot < 4 ? 0U : static_cast<unsigned>(slot / 2) - 1U;
                writer_.put(static_cast<std::uint32_t>(distance - distance_base[slot]), extra);
                for (std::size_t i = 0; i < length; ++i)
                    insert(pos + i);
                pos += length;
            }
            else
            {
                writer_.put(fixed_literals[at(pos)]);
                insert(pos);
                ++pos;
            }
        }
        writer_.put(fixed_literals[end_of_block]);
        writer_.align();
    }

  private:
    [[nodiscard]] std::uint32_t at(std::size_t i) const noexcept
    {
        return std::to_integer<std::uint32_t>(data_[i]);
    }

    [[nodiscard]] std::size_t hash(std::size_t i) const noexcept
    {
        const std::uint32_t three = at(i) | (at(i + 1) << 8U) | (at(i + 2) << 16U);
        return static_cast<std::size_t>((three * hash_factor) >> hash_shift);
    }

    void insert(std::size_t i) noexcept
    {
        if (i + min_match > data_.size())
            return;
        const std::size_t h    = hash(i);
        prev_[i & window_mask] = head_[h];
        head_[h]               = static_cast<std::uint32_t>(i + 1);
    }

    void find(std::size_t pos, std::size_t& best, std::size_t& best_distance) const noexcept
    {
        const std::size_t size = data_.size();
        if (pos + min_match > size)
            return;
        const std::size_t limit = std::min(max_match, size - pos);
        std::uint32_t entry     = head_[hash(pos)];
        unsigned chain          = max_chain;
        while (entry != 0 && chain-- > 0)
        {
            const std::size_t candidate = entry - 1U;
            const std::size_t distance  = pos - candidate;
            if (distance > window_size)
                break;
            if (best < limit && data_[candidate + best] == data_[pos + best])
            {
                std::size_t length = 0;
                while (length < limit && data_[candidate + length] == data_[pos + length])
                    ++length;
                if (length > best)
                {
                    best          = length;
                    best_distance = distance;
                    if (length >= nice_match || length == limit)
                        return;
                }
            }
            const std::uint32_t next = prev_[candidate & window_mask];
            if (next >= entry)
                break;
            entry = next;
        }
    }

    std::span<const std::byte> data_;
    BitWriter writer_;
    Vector<std::uint32_t> head_;
    Vector<std::uint32_t> prev_;
};

// A q-value as thousandths: "0", "0.5", "1.000"; -1 when it is not one.
int quality(std::string_view text) noexcept
{
    if (text.empty() || (text[0] != '0' && text[0] != '1'))
        return -1;
    const int whole = text[0] - '0';
    if (text.size() == 1)
        return whole * 1000;
    if (text[1] != '.' || text.size() > 5)
        return -1;
    int fraction = 0;
    int scale    = 100;
    for (std::size_t i = 2; i < text.size(); ++i)
    {
        if (text[i] < '0' || text[i] > '9')
            return -1;
        fraction += (text[i] - '0') * scale;
        scale /= 10;
    }
    if (whole == 1 && fraction != 0)
        return -1;
    return (whole * 1000) + fraction;
}

std::string_view trimmed(std::string_view text) noexcept
{
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t'))
        text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t'))
        text.remove_suffix(1);
    return text;
}

// `text` equals `lower` (written in lower case) apart from case.
bool same_name(std::string_view text, std::string_view lower) noexcept
{
    if (text.size() != lower.size())
        return false;
    for (std::size_t i = 0; i < text.size(); ++i)
    {
        const char c = text[i] >= 'A' && text[i] <= 'Z' ? static_cast<char>(text[i] - 'A' + 'a') : text[i];
        if (c != lower[i])
            return false;
    }
    return true;
}

// The q-value among the parameters of one coding (1000 when it has none).
int coding_quality(std::string_view params) noexcept
{
    int q = 1000;
    while (!params.empty())
    {
        const std::size_t next      = params.find(';');
        const std::string_view pair = trimmed(params.substr(0, next));
        params = next == std::string_view::npos ? std::string_view {} : params.substr(next + 1);
        const std::size_t equals = pair.find('=');
        if (equals != std::string_view::npos && same_name(trimmed(pair.substr(0, equals)), "q"))
            q = std::max(quality(trimmed(pair.substr(equals + 1))), 0);
    }
    return q;
}

} // namespace

std::uint32_t gzip_crc32(std::span<const std::byte> data) noexcept
{
    std::uint32_t crc = 0xffffffffU;
    for (const std::byte byte : data)
        crc = crc_table[(crc ^ std::to_integer<std::uint32_t>(byte)) & 0xffU] ^ (crc >> 8U);
    return crc ^ 0xffffffffU;
}

void gzip(std::span<const std::byte> data, String& output)
{
    header(output);
    if (std::cmp_greater(data.size(), position_limit))
        store(data, output);
    else
    {
        Compressor compressor(data, output);
        compressor.run();
    }
    le32(output, gzip_crc32(data));
    le32(output, static_cast<std::uint32_t>(data.size() & 0xffffffffU));
}

bool accepts_gzip(std::string_view accept_encoding) noexcept
{
    int named    = -1; // gzip or x-gzip
    int star     = -1;
    int identity = -1;
    while (!accept_encoding.empty())
    {
        const std::size_t comma     = accept_encoding.find(',');
        const std::string_view item = trimmed(accept_encoding.substr(0, comma));
        accept_encoding
            = comma == std::string_view::npos ? std::string_view {} : accept_encoding.substr(comma + 1);
        const std::size_t semi        = item.find(';');
        const std::string_view coding = trimmed(item.substr(0, semi));
        const int q = semi == std::string_view::npos ? 1000 : coding_quality(item.substr(semi + 1));
        if (same_name(coding, "gzip") || same_name(coding, "x-gzip"))
            named = std::max(named, q);
        else if (coding == "*")
            star = std::max(star, q);
        else if (same_name(coding, "identity"))
            identity = std::max(identity, q);
    }
    const int allowed = named >= 0 ? named : std::max(star, 0);
    return allowed > 0 && allowed >= std::max(identity, 0);
}

} // namespace lantern
