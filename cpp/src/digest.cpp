#include <lantern/digest.hpp>

#include <lantern/encoding.hpp>

namespace lantern
{

namespace
{

void skip_space(std::string_view value, std::size_t& i) noexcept
{
    while (i < value.size() && (value[i] == ' ' || value[i] == '\t'))
        ++i;
}

bool key_char(char c) noexcept
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == '*';
}

// Skips a bare item (a token, an integer, a string, a byte sequence or a
// boolean) at `i`; false when there is none.
bool skip_bare_item(std::string_view value, std::size_t& i) noexcept
{
    if (i >= value.size())
        return false;
    const char c = value[i];
    if (c == ':')
    {
        const std::size_t end = value.find(':', i + 1);
        if (end == std::string_view::npos)
            return false;
        i = end + 1;
        return true;
    }
    if (c == '"')
    {
        for (++i; i < value.size(); ++i)
        {
            if (value[i] == '\\')
            {
                ++i;
                continue;
            }
            if (value[i] == '"')
            {
                ++i;
                return true;
            }
        }
        return false;
    }
    if (c == '?')
    {
        i += 2;
        return i <= value.size();
    }
    const std::size_t start = i;
    while (i < value.size() && value[i] != ',' && value[i] != ';' && value[i] != ' ' && value[i] != '\t')
        ++i;
    return i > start;
}

bool skip_parameters(std::string_view value, std::size_t& i) noexcept
{
    while (i < value.size() && value[i] == ';')
    {
        ++i;
        skip_space(value, i);
        const std::size_t start = i;
        while (i < value.size() && key_char(value[i]))
            ++i;
        if (i == start)
            return false;
        if (i < value.size() && value[i] == '=')
        {
            ++i;
            if (!skip_bare_item(value, i))
                return false;
        }
    }
    return true;
}

} // namespace

void format_digest_field(const Digest& digest, String& out)
{
    out.append("sha-256=:");
    base64_encode(digest, out);
    out.push_back(':');
}

ParsedDigest parse_digest_field(std::string_view value) noexcept
{
    ParsedDigest out;
    std::size_t i = 0;
    skip_space(value, i);
    while (i < value.size())
    {
        const std::size_t key_start = i;
        while (i < value.size() && key_char(value[i]))
            ++i;
        const std::string_view key = value.substr(key_start, i - key_start);
        if (key.empty())
            return { DigestField::malformed, {} };
        if (i < value.size() && value[i] == '=')
        {
            ++i;
            const std::size_t item = i;
            if (!skip_bare_item(value, i))
                return { DigestField::malformed, {} };
            if (key == "sha-256")
            {
                const std::string_view raw = value.substr(item, i - item);
                if (raw.size() < 2 || raw.front() != ':' || raw.back() != ':'
                    || !base64_decode(raw.substr(1, raw.size() - 2), out.sha256))
                    return { DigestField::malformed, {} };
                out.state = DigestField::sha256;
            }
        }
        if (!skip_parameters(value, i))
            return { DigestField::malformed, {} };
        skip_space(value, i);
        if (i == value.size())
            break;
        if (value[i] != ',')
            return { DigestField::malformed, {} };
        ++i;
        skip_space(value, i);
        if (i == value.size())
            return { DigestField::malformed, {} };
    }
    return out;
}

} // namespace lantern
