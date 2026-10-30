#include <lantern/tls.hpp>

#include <algorithm>

#include <lantern/encoding.hpp>

namespace lantern
{

namespace
{

constexpr std::size_t max_certificate = std::size_t { 64 } * 1024;

struct Tlv
{
    std::uint8_t tag = 0;
    std::span<const std::uint8_t> content;
    std::span<const std::uint8_t> whole;
};

// One DER element at the front of `in`, which moves past it.
bool read_tlv(std::span<const std::uint8_t>& in, Tlv& out) noexcept
{
    if (in.size() < 2)
        return false;
    const std::uint8_t tag = in[0];
    if ((tag & 0x1FU) == 0x1FU)
        return false; // a tag of several bytes: none in a certificate's structure
    std::size_t length = in[1];
    std::size_t header = 2;
    if (length == 0x80U)
        return false; // indefinite: not DER
    if (length > 0x80U)
    {
        const std::size_t bytes = length & 0x7FU;
        if (bytes > 3 || in.size() < 2 + bytes)
            return false;
        length = 0;
        for (std::size_t i = 0; i < bytes; ++i)
            length = (length << 8U) | in[2 + i];
        if (length < 0x80U)
            return false; // not the shortest form
        header += bytes;
    }
    if (length > in.size() - header)
        return false;
    out.tag     = tag;
    out.content = in.subspan(header, length);
    out.whole   = in.first(header + length);
    in          = in.subspan(header + length);
    return true;
}

constexpr std::uint8_t sequence_tag = 0x30;
constexpr std::uint8_t integer_tag  = 0x02;
constexpr std::uint8_t version_tag  = 0xA0; // [0] EXPLICIT

bool code_symbols(std::string_view group) noexcept
{
    return group.size() == 4
        && std::ranges::all_of(group,
            [](char c) { return (c >= '2' && c <= '9') || (c >= 'A' && c <= 'Z' && c != 'I' && c != 'O'); });
}

bool grouped_code(std::string_view code, std::size_t min_groups, std::size_t max_groups) noexcept
{
    std::size_t groups = 0;
    for (;;)
    {
        const std::size_t dash = std::min(code.find('-'), code.size());
        if (!code_symbols(code.substr(0, dash)))
            return false;
        ++groups;
        if (dash == code.size())
            break;
        code.remove_prefix(dash + 1);
    }
    return groups >= min_groups && groups <= max_groups;
}

} // namespace

void ServerTrust::require_ca() noexcept
{
    mode_ = Mode::ca;
    pin_.reset();
    ++generation_;
}

void ServerTrust::pin(const Digest& spki_sha256) noexcept
{
    mode_ = Mode::pinned;
    pin_  = spki_sha256;
    ++generation_;
}

void ServerTrust::allow_unverified() noexcept
{
    mode_ = Mode::unverified;
    pin_.reset();
    ++generation_;
}

bool ServerTrust::accept(std::span<const std::uint8_t> spki_der, bool ca_verified) noexcept
{
    seen_ = Sha256::of(std::as_bytes(spki_der));
    switch (mode_)
    {
        case Mode::ca:
            return ca_verified;
        case Mode::pinned:
            return pin_ && same_digest(*pin_, *seen_);
        case Mode::unverified:
            return true;
    }
    return false;
}

Result<std::span<const std::uint8_t>> certificate_spki(std::span<const std::uint8_t> der) noexcept
{
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    // TBSCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber,
    //     signature, issuer, validity, subject, subjectPublicKeyInfo, … }
    const auto refused = [] { return fail(Category::invalid_response, "not a DER X.509 certificate"); };
    if (der.size() > max_certificate)
        return refused();
    Tlv certificate;
    if (!read_tlv(der, certificate) || certificate.tag != sequence_tag)
        return refused();
    std::span<const std::uint8_t> inside = certificate.content;
    Tlv tbs;
    if (!read_tlv(inside, tbs) || tbs.tag != sequence_tag)
        return refused();
    std::span<const std::uint8_t> fields = tbs.content;
    Tlv field;
    if (!read_tlv(fields, field))
        return refused();
    if (field.tag == version_tag && !read_tlv(fields, field))
        return refused();
    if (field.tag != integer_tag) // serialNumber
        return refused();
    // signature, issuer, validity, subject
    for (int i = 0; i < 4; ++i)
    {
        if (!read_tlv(fields, field) || field.tag != sequence_tag)
            return refused();
    }
    Tlv spki;
    if (!read_tlv(fields, spki) || spki.tag != sequence_tag)
        return refused();
    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm SEQUENCE, subjectPublicKey BIT STRING }
    std::span<const std::uint8_t> parts = spki.content;
    Tlv algorithm;
    Tlv key;
    if (!read_tlv(parts, algorithm) || algorithm.tag != sequence_tag || !read_tlv(parts, key)
        || key.tag != 0x03U || !parts.empty())
        return refused();
    return spki.whole;
}

Result<Vector<std::uint8_t>> pem_certificate(std::string_view pem, Allocator allocator)
{
    constexpr std::string_view begin = "-----BEGIN CERTIFICATE-----";
    constexpr std::string_view end   = "-----END CERTIFICATE-----";
    const std::size_t from           = pem.find(begin);
    if (from == std::string_view::npos)
        return fail(Category::usage, "no certificate in this PEM text");
    const std::size_t to = pem.find(end, from);
    if (to == std::string_view::npos)
        return fail(Category::usage, "a PEM certificate without its end");
    const std::string_view body = pem.substr(from + begin.size(), to - from - begin.size());
    if (body.size() > max_certificate * 2)
        return fail(Category::limit, "a certificate above 64 KiB");
    String text(allocator);
    text.reserve(body.size());
    for (const char c : body)
    {
        if (c != '\r' && c != '\n' && c != ' ' && c != '\t')
            text.push_back(c);
    }
    const auto size = base64_decoded_size(text);
    if (!size)
        return fail(Category::usage, "a PEM certificate that is not base64");
    Vector<std::uint8_t> out(*size, allocator);
    if (!base64_decode(text, out))
        return fail(Category::usage, "a PEM certificate that is not base64");
    return out;
}

Result<Digest> spki_sha256(std::span<const std::uint8_t> certificate_der) noexcept
{
    const auto spki = certificate_spki(certificate_der);
    if (!spki)
        return std::unexpected(spki.error());
    return Sha256::of(std::as_bytes(*spki));
}

Result<Digest> spki_sha256_pem(std::string_view pem, Allocator allocator)
{
    const auto der = pem_certificate(pem, allocator);
    if (!der)
        return std::unexpected(der.error());
    return spki_sha256(*der);
}

std::array<char, 19> short_form(const Digest& fingerprint) noexcept
{
    static constexpr std::string_view hex = "0123456789ABCDEF";
    std::array<char, 19> out {};
    std::size_t at = 0;
    for (std::size_t i = 0; i < 8; ++i)
    {
        if (i != 0 && i % 2 == 0)
            out[at++] = ' ';
        out[at++] = hex[fingerprint[i] >> 4U];
        out[at++] = hex[fingerprint[i] & 0x0FU];
    }
    return out;
}

bool is_pairing_code(std::string_view code) noexcept
{
    return grouped_code(code, 2, 8);
}

bool is_invitation_code(std::string_view code) noexcept
{
    return grouped_code(code, 4, 8);
}

Result<InvitationLink> parse_invitation_link(std::string_view link) noexcept
{
    const std::size_t question = link.find('?');
    if (question == std::string_view::npos)
        return fail(Category::usage, "an invitation's link has its code in its query (SPEC.md 5.5)");
    std::string_view query = link.substr(question + 1);
    query                  = query.substr(0, query.find('#'));
    InvitationLink out;
    bool has_spki = false;
    while (!query.empty())
    {
        const std::size_t amp       = std::min(query.find('&'), query.size());
        const std::string_view pair = query.substr(0, amp);
        query                       = amp == query.size() ? std::string_view {} : query.substr(amp + 1);
        const std::size_t equals    = pair.find('=');
        const std::string_view name = pair.substr(0, equals);
        const std::string_view value
            = equals == std::string_view::npos ? std::string_view {} : pair.substr(equals + 1);
        if (name == "invitation")
            out.code = value;
        else if (name == "spki")
        {
            has_spki = true;
            out.spki = digest_from_hex(value);
        }
    }
    if (!is_invitation_code(out.code))
        return fail(Category::usage, "an invitation's link without a code of SPEC.md 5.5's form");
    if (has_spki && !out.spki)
        return fail(Category::usage, "an invitation's spki is 64 lower-case hex digits (SPEC.md 5.5)");
    return out;
}

} // namespace lantern
