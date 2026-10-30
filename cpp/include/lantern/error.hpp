// Errors: what went wrong, as a value. Nothing in the library throws.
//
// An Error carries a category (where it went wrong), the problem+json fields
// a server sent (SPEC.md § 12) when it sent one, and a detail for people,
// bounded and without control characters. An error code the library does
// not know is read by its HTTP status alone (Error::effective_code).
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string_view>

namespace lantern
{

// Where an error comes from.
enum class Category : std::uint8_t
{
    protocol, // the server answered with an error status (problem+json)
    transport, // the request did not reach the server, or its answer was cut
    invalid_response, // a document or header the protocol does not allow
    limit, // beyond SPEC.md § 13's limits, or the app's own lower ones
    integrity, // a size or SHA-256 that does not match: the download is refused
    signature, // a homebrew signature that does not verify, or a changed key
    refused, // a manifest, path or package the client must refuse (§ 8.3, § 8.6)
    unsupported, // a family the server does not offer, a platform with no profile
    usage, // an argument the app gave that the protocol does not allow
    storage, // the app's sink or key store failed
    memory, // the memory budget the app gave is spent
};

// The codes of SPEC.md § 12, and `unknown` for a code this library does not
// know (a later version's), read by its status.
enum class Code : std::uint8_t
{
    none,
    bad_request,
    unauthorized,
    forbidden,
    account_frozen,
    not_found,
    conflict,
    gone,
    too_large,
    unsupported_schema,
    digest_mismatch,
    slow_down,
    internal,
    unavailable,
    unknown,
};

// The code a status implies (§ 12's table), for a code the library does not
// know: 422, which has two codes, gives `unknown`.
[[nodiscard]] Code code_for_status(std::uint16_t status) noexcept;
// The code's name as § 12 writes it ("account_frozen"), or "" for none.
[[nodiscard]] std::string_view code_name(Code code) noexcept;
// A code from its name; `unknown` for a name § 12 does not have.
[[nodiscard]] Code code_from_name(std::string_view name) noexcept;
[[nodiscard]] std::string_view category_name(Category category) noexcept;

// A short text kept inside the error: no allocation, cut at a UTF-8
// boundary, control characters replaced by spaces.
template <std::size_t N> class FixedText
{
  public:
    void assign(std::string_view text) noexcept;
    [[nodiscard]] std::string_view view() const noexcept { return { data_, size_ }; }

  private:
    char data_[N] {};
    std::size_t size_ = 0;
};

class Error
{
  public:
    // A local error, with its detail.
    [[nodiscard]] static Error make(Category category, std::string_view detail) noexcept;
    // An error status with no problem document the library could read.
    [[nodiscard]] static Error from_status(std::uint16_t status) noexcept;

    [[nodiscard]] Category category() const noexcept { return category_; }
    // The code as the server wrote it: `unknown` when it wrote one this
    // library does not know, `none` when it wrote none or the error is local.
    [[nodiscard]] Code code() const noexcept { return code_; }
    // The code to act on: the server's, or the one its status implies.
    [[nodiscard]] Code effective_code() const noexcept;
    // The HTTP status, or 0 for a local error.
    [[nodiscard]] std::uint16_t status() const noexcept { return status_; }
    // Retry-After, in seconds, on a 429 or a 503 (0: none given).
    [[nodiscard]] std::uint32_t retry_after() const noexcept { return retry_after_; }
    // For people: shown as is, already bounded and without control characters.
    [[nodiscard]] std::string_view detail() const noexcept { return detail_.view(); }
    [[nodiscard]] std::string_view title() const noexcept { return title_.view(); }
    // The code exactly as the server wrote it, unknown ones included.
    [[nodiscard]] std::string_view code_text() const noexcept { return code_text_.view(); }

    void set_code(Code code, std::string_view text) noexcept;
    void set_status(std::uint16_t status) noexcept { status_ = status; }
    void set_retry_after(std::uint32_t seconds) noexcept { retry_after_ = seconds; }
    void set_detail(std::string_view text) noexcept { detail_.assign(text); }
    void set_title(std::string_view text) noexcept { title_.assign(text); }

  private:
    Category category_         = Category::usage;
    Code code_                 = Code::none;
    std::uint16_t status_      = 0;
    std::uint32_t retry_after_ = 0;
    FixedText<200> detail_;
    FixedText<96> title_;
    FixedText<32> code_text_;
};

template <class T> using Result = std::expected<T, Error>;

// std::unexpected of a local error, for `return fail(…);`.
[[nodiscard]] inline std::unexpected<Error> fail(Category category, std::string_view detail) noexcept
{
    return std::unexpected(Error::make(category, detail));
}

} // namespace lantern
