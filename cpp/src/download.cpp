#include <lantern/download.hpp>

#include <algorithm>
#include <charconv>
#include <system_error>

#include <lantern/client.hpp>
#include <lantern/digest.hpp>
#include <lantern/encoding.hpp>

#include "client_internal.hpp"

namespace lantern
{

namespace
{

constexpr std::uint64_t max_cheat_set = std::uint64_t { 1024 } * 1024;

bool equal_ignoring_case(std::string_view a, std::string_view b) noexcept
{
    return a.size() == b.size()
        && std::equal(a.begin(), a.end(), b.begin(),
            [](char x, char y)
            {
                const auto lower
                    = [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; };
                return lower(x) == lower(y);
            });
}

std::optional<std::uint64_t> parse_u64(std::string_view text) noexcept
{
    std::uint64_t value = 0;
    const char* end     = text.data() + text.size();
    const auto result   = std::from_chars(text.data(), end, value);
    if (text.empty() || result.ec != std::errc {} || result.ptr != end)
        return std::nullopt;
    return value;
}

struct ContentRange
{
    std::uint64_t first = 0;
    std::uint64_t last  = 0;
    std::uint64_t total = 0;
};

// "bytes 100-199/200"
std::optional<ContentRange> parse_content_range(std::string_view value) noexcept
{
    if (!value.starts_with("bytes "))
        return std::nullopt;
    value.remove_prefix(6);
    const std::size_t dash  = value.find('-');
    const std::size_t slash = value.find('/');
    if (dash == std::string_view::npos || slash == std::string_view::npos || dash > slash)
        return std::nullopt;
    const auto first = parse_u64(value.substr(0, dash));
    const auto last  = parse_u64(value.substr(dash + 1, slash - dash - 1));
    const auto total = parse_u64(value.substr(slash + 1));
    if (!first || !last || !total || *first > *last || *last >= *total)
        return std::nullopt;
    return ContentRange { *first, *last, *total };
}

// Streams a file into the sink, hashing it, checking what the server says
// of it against what the listing said.
class DownloadHandler final : public ResponseHandler
{
  public:
    DownloadHandler(const DownloadTarget& target, DownloadState& state, DownloadSink& sink,
        std::size_t max_error, Allocator allocator)
        : target_(target)
        , state_(state)
        , sink_(sink)
        , from_(state.received)
        , hash_(state.hash)
        , max_error_(max_error)
        , error_body_(allocator)
        , retry_after_(allocator)
    {
    }

    bool on_status(std::uint16_t status) override
    {
        status_ = status;
        if (status == 200 && state_.received != 0)
        {
            // The whole file again: it changed, or the server ignored Range
            if (auto restarted = sink_.restart(); !restarted)
                return stop(restarted.error());
            state_.received = 0;
            hash_           = Sha256();
            state_.hash     = hash_.state();
            from_           = 0;
        }
        return true;
    }

    bool on_header(std::string_view name, std::string_view value) override
    {
        if (equal_ignoring_case(name, "Repr-Digest"))
        {
            repr_digest_ = parse_digest_field(value);
            if (repr_digest_.state == DigestField::malformed)
                return stop(
                    Error::make(Category::invalid_response, "a Repr-Digest that is not RFC 9530's form"));
        }
        else if (equal_ignoring_case(name, "Content-Range"))
            content_range_ = parse_content_range(value);
        else if (equal_ignoring_case(name, "Content-Length"))
            content_length_ = parse_u64(value);
        else if (equal_ignoring_case(name, "ETag"))
        {
            if (!value.starts_with("W/") && value.size() <= state_.etag.size())
            {
                std::ranges::copy(value, state_.etag.begin());
                state_.etag_size = value.size();
            }
        }
        else if (equal_ignoring_case(name, "Retry-After"))
            retry_after_.assign(value);
        return true;
    }

    bool on_body(std::span<const std::byte> chunk) override
    {
        if (!success())
        {
            if (chunk.size() > max_error_ - std::min(max_error_, error_body_.size()))
                return false;
            error_body_.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            return true;
        }
        if (!checked_ && !check_headers())
            return false;
        if (chunk.size() > target_.size - state_.received)
            return stop(Error::make(Category::integrity, "the server sends more bytes than the file has"));
        if (auto written = sink_.write(chunk); !written)
            return stop(written.error());
        hash_.update(chunk);
        state_.received += chunk.size();
        state_.hash = hash_.state();
        return true;
    }

    // What the server says of the file, against the listing: checked before
    // the first byte is kept.
    bool check_headers()
    {
        checked_ = true;
        if (repr_digest_.state == DigestField::sha256 && !same_digest(repr_digest_.sha256, target_.sha256))
            return stop(
                Error::make(Category::integrity, "the server's Repr-Digest is not the listing's sha256"));
        if (status_ == 206)
        {
            if (!content_range_ || content_range_->first != from_ || content_range_->total != target_.size)
                return stop(
                    Error::make(Category::invalid_response, "a Content-Range that is not the range asked"));
        }
        const std::uint64_t expected = target_.size - from_;
        if (content_length_ && *content_length_ != expected)
            return stop(Error::make(Category::integrity, "a Content-Length that is not the listing's size"));
        return true;
    }

    [[nodiscard]] bool success() const noexcept { return status_ == 200 || status_ == 206; }
    [[nodiscard]] std::uint16_t status() const noexcept { return status_; }
    [[nodiscard]] bool checked() const noexcept { return checked_; }
    [[nodiscard]] const std::optional<Error>& error() const noexcept { return error_; }
    [[nodiscard]] std::string_view error_body() const noexcept { return error_body_; }
    [[nodiscard]] std::string_view retry_after() const noexcept { return retry_after_; }
    [[nodiscard]] Sha256& hash() noexcept { return hash_; }

  private:
    bool stop(const Error& error)
    {
        error_ = error;
        return false;
    }

    const DownloadTarget& target_;
    DownloadState& state_;
    DownloadSink& sink_;
    std::uint64_t from_;
    Sha256 hash_;
    std::size_t max_error_;
    String error_body_;
    String retry_after_;
    std::uint16_t status_ = 0;
    bool checked_         = false;
    ParsedDigest repr_digest_;
    std::optional<ContentRange> content_range_;
    std::optional<std::uint64_t> content_length_;
    std::optional<Error> error_;
};

} // namespace

Result<void> MemorySink::write(std::span<const std::byte> bytes)
{
    if (bytes.size() > cap_ - std::min(cap_, bytes_.size()))
        return fail(Category::limit, "more bytes than the memory sink takes");
    bytes_.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    return {};
}

Result<void> MemorySink::restart()
{
    bytes_.clear();
    return {};
}

Result<void> Client::download(const DownloadTarget& target, DownloadState& state, DownloadSink& sink)
{
    if (state.received > target.size)
        return fail(Category::usage, "a download state past the file's size");
    const auto url = resolve_url(origin(), target.url, allocator_);
    if (!url)
        return std::unexpected(url.error());

    const auto finish = [&](Sha256& hash) -> Result<void>
    {
        if (!same_digest(hash.finish(), target.sha256))
        {
            state.reset();
            return fail(Category::integrity, "the file's SHA-256 is not the listing's: install nothing");
        }
        return {};
    };
    if (state.received == target.size && target.size != 0)
    {
        Sha256 hash(state.hash);
        return finish(hash);
    }

    // Range from what was received; If-Range so that a changed file comes whole
    std::array<char, 40> range {};
    std::array<Header, 2> extra {};
    std::size_t extras = 0;
    if (state.received != 0)
    {
        const std::string_view prefix = "bytes=";
        std::ranges::copy(prefix, range.begin());
        const auto result
            = std::to_chars(range.data() + prefix.size(), range.data() + range.size() - 1, state.received);
        *result.ptr     = '-';
        extra[extras++] = { "Range",
            std::string_view(range.data(), static_cast<std::size_t>(result.ptr + 1 - range.data())) };
        if (state.etag_size != 0)
            extra[extras++] = { "If-Range", state.etag_view() };
    }

    DownloadHandler handler(target, state, sink, max_error_body_, allocator_);
    Call call;
    call.url        = *url;
    call.extra      = std::span(extra.data(), extras);
    const auto sent = exchange(call, handler);
    if (handler.error())
    {
        if (handler.error()->category() == Category::integrity)
            state.reset();
        return std::unexpected(*handler.error());
    }
    if (handler.status() != 0 && !handler.success())
    {
        if (handler.status() == 416)
            state.reset();
        return std::unexpected(problem(handler.status(), handler.error_body(), handler.retry_after()));
    }
    if (!sent)
        return std::unexpected(sent.error());
    if (!handler.checked() && !handler.check_headers())
    {
        state.reset();
        return std::unexpected(
            handler.error().value_or(Error::make(Category::invalid_response, "a file refused")));
    }
    if (state.received != target.size)
        return fail(Category::transport, "the download was cut short: call again to resume");
    return finish(handler.hash());
}

Result<String> Client::cheat_text(const CheatSet& set)
{
    if (auto ok = ready(Family::cheats); !ok)
        return std::unexpected(ok.error());
    if (set.size > max_cheat_set)
        return fail(Category::limit, "a cheat set above 1 MiB (SPEC.md 13)");
    auto url = api_url("/cheats/");
    percent_encode(set.id, *url);
    MemorySink sink(static_cast<std::size_t>(set.size), allocator_);
    DownloadState state;
    const DownloadTarget target { *url, set.size, set.sha256 };
    if (auto done = download(target, state, sink); !done)
        return std::unexpected(done.error());
    return String(sink.text(), allocator_);
}

} // namespace lantern
