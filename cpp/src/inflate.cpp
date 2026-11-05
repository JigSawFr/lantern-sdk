#include <lantern/inflate.hpp>

#include <array>
#include <cstdint>
#include <utility>

namespace lantern
{

namespace
{

constexpr int max_bits     = 15;
constexpr int max_lcodes   = 286;
constexpr int max_dcodes   = 30;
constexpr int fixed_lcodes = 288;

constexpr std::array<std::uint16_t, 29> length_base { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
constexpr std::array<std::uint8_t, 29> length_extra { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3,
    3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
constexpr std::array<std::uint16_t, 30> distance_base { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129,
    193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
constexpr std::array<std::uint8_t, 30> distance_extra { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7,
    8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };
constexpr std::array<std::uint8_t, 19> code_order { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14,
    1, 15 };

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

// An index of the tables, which the arithmetic of the format does in int.
constexpr std::size_t u(int value) noexcept
{
    return static_cast<std::size_t>(value);
}

enum class Fail : std::uint8_t
{
    none,
    corrupt,
    cut,
    large
};

// A canonical Huffman code: how many symbols have each length, and the
// symbols in the order of their codes (Mark Adler's puff).
struct Code
{
    std::array<std::uint16_t, max_bits + 1> count {};
    std::array<std::uint16_t, fixed_lcodes> symbol {};
};

// 0 for a complete code, > 0 for an incomplete one, < 0 for an over-subscribed one.
int construct(Code& code, const std::uint8_t* length, int n) noexcept
{
    code.count.fill(0);
    for (int s = 0; s < n; ++s)
        ++code.count[length[u(s)]];
    if (std::cmp_equal(code.count[0], n))
        return 0;
    int left = 1;
    for (int len = 1; len <= max_bits; ++len)
    {
        left <<= 1;
        left -= code.count[u(len)];
        if (left < 0)
            return left;
    }
    std::array<std::uint16_t, max_bits + 1> offs {};
    for (int len = 1; len < max_bits; ++len)
        offs[u(len + 1)] = static_cast<std::uint16_t>(offs[u(len)] + code.count[u(len)]);
    for (int s = 0; s < n; ++s)
        if (length[u(s)] != 0)
            code.symbol[offs[length[u(s)]]++] = static_cast<std::uint16_t>(s);
    return left;
}

class Inflater
{
  public:
    Inflater(std::span<const std::byte> in, std::size_t max_output, String& out, std::size_t base) noexcept
        : in_(in)
        , max_(max_output)
        , out_(out)
        , base_(base)
    {
    }

    // One deflate stream; `used` is how much of the input it took.
    Fail run(std::size_t& used)
    {
        bool last = false;
        while (!last)
        {
            const int final_block = bits(1);
            const int type        = bits(2);
            if (failed_ != Fail::none)
                return failed_;
            last        = final_block == 1;
            Fail result = Fail::none;
            if (type == 0)
                result = stored();
            else if (type == 1)
                result = fixed();
            else if (type == 2)
                result = dynamic();
            else
                result = Fail::corrupt;
            if (result != Fail::none)
                return result;
        }
        used = pos_;
        return Fail::none;
    }

  private:
    int bits(int need) noexcept
    {
        std::uint32_t value = bit_buffer_;
        while (bit_count_ < need)
        {
            if (pos_ >= in_.size())
            {
                failed_ = Fail::cut;
                return 0;
            }
            value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in_[pos_++])) << bit_count_;
            bit_count_ += 8;
        }
        bit_buffer_ = value >> need;
        bit_count_ -= need;
        return static_cast<int>(value & ((1U << need) - 1U));
    }

    int decode(const Code& code) noexcept
    {
        int value = 0;
        int first = 0;
        int index = 0;
        for (int len = 1; len <= max_bits; ++len)
        {
            value |= bits(1);
            if (failed_ != Fail::none)
                return -1;
            const int count = code.count[u(len)];
            if (value - count < first)
                return code.symbol[u(index + (value - first))];
            index += count;
            first += count;
            first <<= 1;
            value <<= 1;
        }
        failed_ = Fail::corrupt;
        return -1;
    }

    Fail put(char c)
    {
        if (out_.size() - base_ >= max_)
            return Fail::large;
        out_.push_back(c);
        return Fail::none;
    }

    Fail stored()
    {
        bit_buffer_ = 0;
        bit_count_  = 0;
        if (in_.size() - pos_ < 4)
            return Fail::cut;
        const auto b        = [&](std::size_t i) { return std::to_integer<unsigned>(in_[pos_ + i]); };
        const unsigned len  = b(0) | (b(1) << 8);
        const unsigned nlen = b(2) | (b(3) << 8);
        if (len != (~nlen & 0xffffU))
            return Fail::corrupt;
        pos_ += 4;
        if (in_.size() - pos_ < len)
            return Fail::cut;
        if (out_.size() - base_ + len > max_)
            return Fail::large;
        out_.append(reinterpret_cast<const char*>(in_.data() + pos_), len);
        pos_ += len;
        return Fail::none;
    }

    Fail codes(const Code& lengths, const Code& distances)
    {
        for (;;)
        {
            int symbol = decode(lengths);
            if (failed_ != Fail::none)
                return failed_;
            if (symbol < 256)
            {
                if (const Fail f = put(static_cast<char>(symbol)); f != Fail::none)
                    return f;
            }
            else if (symbol == 256)
                return Fail::none;
            else
            {
                symbol -= 257;
                if (symbol >= 29)
                    return Fail::corrupt;
                const int len  = length_base[u(symbol)] + bits(length_extra[u(symbol)]);
                const int dsym = decode(distances);
                if (failed_ != Fail::none)
                    return failed_;
                if (dsym >= max_dcodes)
                    return Fail::corrupt;
                const std::size_t dist
                    = distance_base[u(dsym)] + static_cast<std::size_t>(bits(distance_extra[u(dsym)]));
                if (failed_ != Fail::none)
                    return failed_;
                if (dist > out_.size() - base_)
                    return Fail::corrupt;
                if (out_.size() - base_ + static_cast<std::size_t>(len) > max_)
                    return Fail::large;
                for (int i = 0; i < len; ++i)
                    out_.push_back(out_[out_.size() - dist]);
            }
        }
    }

    Fail fixed()
    {
        Code lengths;
        Code distances;
        std::array<std::uint8_t, fixed_lcodes> lengths_of {};
        int s = 0;
        for (; s < 144; ++s)
            lengths_of[u(s)] = 8;
        for (; s < 256; ++s)
            lengths_of[u(s)] = 9;
        for (; s < 280; ++s)
            lengths_of[u(s)] = 7;
        for (; s < fixed_lcodes; ++s)
            lengths_of[u(s)] = 8;
        construct(lengths, lengths_of.data(), fixed_lcodes);
        std::array<std::uint8_t, max_dcodes> distances_of {};
        distances_of.fill(5);
        construct(distances, distances_of.data(), max_dcodes);
        return codes(lengths, distances);
    }

    Fail dynamic()
    {
        const int nlen  = bits(5) + 257;
        const int ndist = bits(5) + 1;
        const int ncode = bits(4) + 4;
        if (failed_ != Fail::none)
            return failed_;
        if (nlen > max_lcodes || ndist > max_dcodes)
            return Fail::corrupt;
        std::array<std::uint8_t, max_lcodes + max_dcodes> lengths_of {};
        for (int i = 0; i < ncode; ++i)
            lengths_of[code_order[u(i)]] = static_cast<std::uint8_t>(bits(3));
        if (failed_ != Fail::none)
            return failed_;
        Code lengths;
        if (construct(lengths, lengths_of.data(), 19) != 0)
            return Fail::corrupt;
        std::array<std::uint8_t, max_lcodes + max_dcodes> all {};
        int index = 0;
        while (index < nlen + ndist)
        {
            const int symbol = decode(lengths);
            if (failed_ != Fail::none)
                return failed_;
            if (symbol < 16)
                all[u(index++)] = static_cast<std::uint8_t>(symbol);
            else
            {
                int previous = 0;
                int repeat   = 0;
                if (symbol == 16)
                {
                    if (index == 0)
                        return Fail::corrupt;
                    previous = all[u(index - 1)];
                    repeat   = 3 + bits(2);
                }
                else if (symbol == 17)
                    repeat = 3 + bits(3);
                else
                    repeat = 11 + bits(7);
                if (failed_ != Fail::none)
                    return failed_;
                if (index + repeat > nlen + ndist)
                    return Fail::corrupt;
                while (repeat-- > 0)
                    all[u(index++)] = static_cast<std::uint8_t>(previous);
            }
        }
        if (all[256] == 0)
            return Fail::corrupt;
        Code literals;
        int err = construct(literals, all.data(), nlen);
        if (err != 0 && (err < 0 || nlen != literals.count[0] + literals.count[1]))
            return Fail::corrupt;
        Code distances;
        err = construct(distances, all.data() + nlen, ndist);
        if (err != 0 && (err < 0 || ndist != distances.count[0] + distances.count[1]))
            return Fail::corrupt;
        return codes(literals, distances);
    }

    std::span<const std::byte> in_;
    std::size_t max_;
    String& out_;
    std::size_t base_;
    std::size_t pos_          = 0;
    std::uint32_t bit_buffer_ = 0;
    int bit_count_            = 0;
    Fail failed_              = Fail::none;
};

Result<void> refused(Fail failure)
{
    switch (failure)
    {
        case Fail::large:
            return fail(Category::limit, "a document larger than the limit once decompressed (SPEC.md 13)");
        case Fail::cut:
            return fail(Category::invalid_response, "a gzip body that ends early");
        default:
            return fail(Category::invalid_response, "a gzip body that does not decode");
    }
}

} // namespace

Result<void> gunzip(std::span<const std::byte> gzip, std::size_t max_output, String& output)
{
    const std::size_t start = output.size();
    std::size_t pos         = 0;
    if (gzip.empty())
        return fail(Category::invalid_response, "a gzip body that ends early");
    while (pos < gzip.size())
    {
        const auto in = gzip.subspan(pos);
        const auto at = [&](std::size_t i) { return std::to_integer<unsigned>(in[i]); };
        if (in.size() < 18)
            return fail(Category::invalid_response, "a gzip body that ends early");
        if (at(0) != 0x1f || at(1) != 0x8b || at(2) != 8)
            return fail(Category::invalid_response, "a gzip body that does not decode");
        const unsigned flags = at(3);
        if ((flags & 0xe0U) != 0)
            return fail(Category::invalid_response, "a gzip body that does not decode");
        std::size_t head = 10;
        if ((flags & 4U) != 0)
        {
            if (in.size() < head + 2)
                return fail(Category::invalid_response, "a gzip body that ends early");
            head += 2 + (at(head) | (at(head + 1) << 8));
        }
        for (const unsigned flag : { 8U, 16U })
        {
            if ((flags & flag) == 0)
                continue;
            while (head < in.size() && at(head) != 0)
                ++head;
            ++head;
        }
        if ((flags & 2U) != 0)
            head += 2;
        if (head + 8 > in.size())
            return fail(Category::invalid_response, "a gzip body that ends early");
        const std::size_t member = output.size();
        Inflater inflater(
            in.subspan(head), max_output - std::min(max_output, member - start), output, member);
        std::size_t used = 0;
        if (const Fail f = inflater.run(used); f != Fail::none)
            return refused(f);
        const std::size_t trailer = head + used;
        if (trailer + 8 > in.size())
            return fail(Category::invalid_response, "a gzip body that ends early");
        const auto word = [&](std::size_t i)
        {
            return static_cast<std::uint32_t>(at(trailer + i))
                | (static_cast<std::uint32_t>(at(trailer + i + 1)) << 8)
                | (static_cast<std::uint32_t>(at(trailer + i + 2)) << 16)
                | (static_cast<std::uint32_t>(at(trailer + i + 3)) << 24);
        };
        std::uint32_t crc = 0xffffffffU;
        for (std::size_t i = member; i < output.size(); ++i)
            crc = crc_table[(crc ^ static_cast<std::uint8_t>(output[i])) & 0xffU] ^ (crc >> 8);
        crc ^= 0xffffffffU;
        if (crc != word(0) || static_cast<std::uint32_t>(output.size() - member) != word(4))
            return fail(Category::invalid_response, "a gzip body that does not check (CRC-32 or size)");
        pos += trailer + 8;
    }
    return {};
}

} // namespace lantern
