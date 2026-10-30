// Signed requests (SPEC.md § 5.4), any Signature-Input, Signature and
// Accept-Signature: a server's check gives a code, never a crash, and
// accepts nothing a key of small order signed; an HTTP date is read or
// refused. The input is split at its first two newlines.
#include <cstddef>
#include <cstdint>
#include <string_view>

#include <lantern/http_signature.hpp>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    const std::size_t first      = text.find('\n');
    const std::string_view input = text.substr(0, first);
    const std::string_view rest
        = first == std::string_view::npos ? std::string_view {} : text.substr(first + 1);
    const std::size_t second     = rest.find('\n');
    const std::string_view value = rest.substr(0, second);
    const std::string_view tail
        = second == std::string_view::npos ? std::string_view {} : rest.substr(second + 1);

    lantern::SignatureCheck check;
    check.method          = "GET";
    check.target_uri      = "https://shelf.example.org/api/lantern/v1/apps?page_size=50";
    check.authorization   = "Bearer et_c8V1nQ0xYbExampleVectorToken0000000000";
    check.signature_input = input;
    check.signature       = value;
    check.content_digest  = tail;
    check.has_body        = !tail.empty();
    check.now             = 1793345400;
    // The identity, a key of small order: nothing it signs is ever taken
    check.key                               = {};
    check.key[0]                            = 1;
    const lantern::SignatureVerdict verdict = lantern::check_signature(check);
    if (verdict.code == lantern::Code::none || verdict.code == lantern::Code::signature_expired)
        __builtin_trap();
    if (verdict.code != lantern::Code::signature_required && verdict.code != lantern::Code::signature_invalid)
        __builtin_trap();

    const auto wanted = lantern::parse_accept_signature(text);
    if (wanted && wanted->component_count > lantern::AcceptSignature::max_components)
        __builtin_trap();
    static_cast<void>(lantern::parse_http_date(input));
    return 0;
}
