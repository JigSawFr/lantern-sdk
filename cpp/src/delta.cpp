// Differential updates (SPEC.md § 22), the client's side: a chunk index
// fetched and checked, and a file put together from the chunks of what the
// app holds and ranges read from the server, mirrors and peers.
#include <lantern/chunks.hpp>
#include <lantern/client.hpp>

#include "client_internal.hpp"

#include <algorithm>
#include <array>

namespace lantern
{

using detail::equal_ignoring_case;
using detail::header_value;
using detail::parse_content_range;
using detail::parse_u64;

namespace
{

constexpr std::size_t max_mirrors = 8;
constexpr std::size_t max_peers   = 8;

} // namespace

// Where a range may be read from.
struct Client::RangeSource
{
    using allocator_type = Allocator;

    String url;
    // A mirror or a peer: nothing of the server's goes to it (§ 19.1)
    bool untrusted = false;
    // A peer's grant, as the header carries it
    String grant;
    // Failed: not asked again for this file (L-19.1-3)
    bool dead = false;

    explicit RangeSource(const allocator_type& allocator = {})
        : url(allocator)
        , grant(allocator)
    {
    }
    RangeSource(const RangeSource& other, const allocator_type& allocator)
        : url(other.url, allocator)
        , untrusted(other.untrusted)
        , grant(other.grant, allocator)
        , dead(other.dead)
    {
    }
    RangeSource(RangeSource&& other, const allocator_type& allocator)
        : url(std::move(other.url), allocator)
        , untrusted(other.untrusted)
        , grant(std::move(other.grant), allocator)
        , dead(other.dead)
    {
    }
    RangeSource(const RangeSource&)            = default;
    RangeSource(RangeSource&&) noexcept        = default;
    RangeSource& operator=(const RangeSource&) = default;
    RangeSource& operator=(RangeSource&&)      = default;
    ~RangeSource()                             = default;
};

// Feeds the assembler with the body of a range, checking that the source
// answered the range asked, and no more (L-22.3-3).
class Client::RangeHandler final : public ResponseHandler
{
  public:
    RangeHandler(DeltaAssembler& assembler, const ByteRange& range, std::uint64_t file_size,
        std::size_t max_error, Allocator allocator)
        : assembler_(assembler)
        , range_(range)
        , file_size_(file_size)
        , max_error_(max_error)
        , error_body_(allocator)
        , retry_after_(allocator)
    {
    }

    bool on_status(std::uint16_t status) override
    {
        status_ = status;
        return true;
    }

    bool on_header(std::string_view name, std::string_view value) override
    {
        if (equal_ignoring_case(name, "Content-Range"))
            content_range_ = parse_content_range(value);
        else if (equal_ignoring_case(name, "Content-Length"))
            content_length_ = parse_u64(value);
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
        if (auto fed = assembler_.feed(chunk); !fed)
            return stop(fed.error());
        return true;
    }

    // What the source says of the answer, against the range asked.
    bool check_headers()
    {
        checked_ = true;
        if (status_ == 206)
        {
            if (!content_range_ || content_range_->first != range_.first
                || content_range_->last != range_.last || content_range_->total != file_size_)
                return stop(
                    Error::make(Category::invalid_response, "a Content-Range that is not the range asked"));
        }
        else if (range_.first != 0 || range_.last + 1 != file_size_)
        {
            // The whole file, sent for a part of it: not read (L-22.3-3)
            return stop(Error::make(Category::invalid_response, "a source that does not honour Range"));
        }
        if (content_length_ && *content_length_ != range_.length())
            return stop(Error::make(Category::invalid_response, "a Content-Length that is not the range's"));
        return true;
    }

    [[nodiscard]] bool success() const noexcept { return status_ == 200 || status_ == 206; }
    [[nodiscard]] std::uint16_t status() const noexcept { return status_; }
    [[nodiscard]] bool checked() const noexcept { return checked_; }
    [[nodiscard]] const std::optional<Error>& error() const noexcept { return error_; }
    [[nodiscard]] std::string_view error_body() const noexcept { return error_body_; }
    [[nodiscard]] std::string_view retry_after() const noexcept { return retry_after_; }

  private:
    bool stop(const Error& error)
    {
        error_ = error;
        return false;
    }

    DeltaAssembler& assembler_;
    ByteRange range_;
    std::uint64_t file_size_;
    std::size_t max_error_;
    String error_body_;
    String retry_after_;
    std::uint16_t status_ = 0;
    bool checked_         = false;
    std::optional<detail::ContentRange> content_range_;
    std::optional<std::uint64_t> content_length_;
    std::optional<Error> error_;
};

Read<ChunkIndex> Client::chunk_index(const AppChunks& chunks, const DownloadTarget& target)
{
    if (chunks.size == 0 || chunks.size > chunk_index_limit)
        return fail(Category::limit, "a chunk index of 0 bytes or above 8 MiB (SPEC.md 13)");
    const auto url = resolve_url(origin(), chunks.url, allocator_);
    if (!url)
        return std::unexpected(url.error());
    Call call;
    call.url = *url;
    // Never more than `chunks` says (L-22.3-1)
    call.max_body       = static_cast<std::size_t>(chunks.size);
    const auto response = fetch(call);
    if (!response)
        return std::unexpected(response.error());
    if (response->status < 200 || response->status >= 300)
        return std::unexpected(problem(*response));
    // A static library's file is JSON whatever its Content-Type (L-21.3-1)
    return read_chunk_index(response->body, &chunks, target.sha256, target.size, allocator_);
}

Read<ChunkIndex> Client::chunk_index_of(const Digest& sha256, std::uint64_t size)
{
    if (auto ok = ready(Family::deltas); !ok)
        return std::unexpected(ok.error());
    auto url       = api_url("/chunks/sha256/");
    const auto hex = to_hex(sha256);
    url->append(hex.data(), hex.size());
    Call call;
    call.url            = *url;
    call.max_body       = chunk_index_limit;
    const auto response = fetch(call);
    if (!response)
        return std::unexpected(response.error());
    if (response->status < 200 || response->status >= 300)
        return std::unexpected(problem(*response));
    return read_chunk_index(response->body, nullptr, sha256, size, allocator_);
}

Result<void> Client::fetch_range(DeltaAssembler& assembler, const ByteRange& range,
    const DownloadTarget& target, const RangeSource& source)
{
    if (auto begun = assembler.begin_range(range); !begun)
        return begun;
    const std::string text = "bytes=" + std::to_string(range.first) + '-' + std::to_string(range.last);
    std::array<Header, 2> extra {};
    std::size_t extras = 0;
    extra[extras++]    = { "Range", std::string_view(text) };
    if (!source.grant.empty())
        extra[extras++] = { "Lantern-Grant", source.grant };

    RangeHandler handler(assembler, range, target.size, max_error_body_, allocator_);
    Call call;
    call.method     = Method::get;
    call.url        = source.url;
    call.untrusted  = source.untrusted;
    call.accept     = "*/*";
    call.extra      = std::span(extra.data(), extras);
    const auto sent = exchange(call, handler);
    if (handler.error())
        return std::unexpected(*handler.error());
    if (handler.status() != 0 && !handler.success())
        return std::unexpected(problem(handler.status(), handler.error_body(), handler.retry_after()));
    if (!sent)
        return std::unexpected(sent.error());
    if (!handler.checked() && !handler.check_headers())
        return std::unexpected(
            handler.error().value_or(Error::make(Category::invalid_response, "a range refused")));
    return assembler.end_range();
}

Result<void> Client::read_range(DeltaAssembler& assembler, const ByteRange& range,
    const DownloadTarget& target, Vector<RangeSource>& sources, DeltaReport& report)
{
    ByteRange asking = range;
    std::optional<Error> last;
    for (RangeSource& source : sources)
    {
        if (source.dead)
            continue;
        ++report.requests;
        const auto done = fetch_range(assembler, asking, target, source);
        // The chunks verified before a failure are kept: the next source
        // reads from the first that is not
        const auto rest = assembler.remaining(range);
        if (!rest)
            return {};
        // L-19.1-3: what failed is dropped
        source.dead = true;
        if (!done)
            last = done.error();
        asking = *rest;
    }
    return std::unexpected(
        last.value_or(Error::make(Category::transport, "no source left to read a range from")));
}

Result<void> Client::download_whole(
    const DownloadTarget& target, DownloadSink& sink, const DeltaOptions& options)
{
    DownloadState state;
    std::size_t tried = 0;
    for (const DeltaPeer& peer : options.peers)
    {
        if (++tried > max_peers)
            break;
        if (peer.grant == nullptr)
            continue;
        state.reset();
        if (auto done = download_from_peer(peer.endpoint, *peer.grant, target, state, sink); done)
            return done;
        state.reset();
        if (auto dropped = sink.restart(); !dropped)
            return dropped;
    }
    state.reset();
    return download_with_mirrors(options.mirrors, target, state, sink);
}

Result<DeltaReport> Client::download_with_index(const DownloadTarget& target, const ChunkIndex& index,
    std::span<const Seed> seeds, DownloadSink& sink, const DeltaOptions& options)
{
    // L-22.3-4: whatever goes wrong, the file is read whole
    const auto whole = [&]() -> Result<DeltaReport>
    {
        if (auto dropped = sink.restart(); !dropped)
            return std::unexpected(dropped.error());
        if (auto done = download_whole(target, sink, options); !done)
            return std::unexpected(done.error());
        DeltaReport report;
        report.whole_file = true;
        return report;
    };
    if (index.size != target.size || !same_digest(index.sha256, target.sha256))
        return whole();
    const auto plan = plan_delta(index, seeds, allocator_);
    // Nothing found in the seeds: nothing to gain from ranges
    if (!plan || plan->seeded == 0)
        return whole();
    DeltaAssembler assembler(index, *plan, seeds, sink, allocator_);
    if (auto started = assembler.start(); !started)
        return whole();

    // Peers, then mirrors, then the server
    Vector<RangeSource> sources(allocator_);
    std::size_t tried = 0;
    for (const DeltaPeer& peer : options.peers)
    {
        if (++tried > max_peers)
            break;
        if (peer.grant == nullptr || !same_digest(peer.grant->sha256, target.sha256)
            || peer.grant->size != target.size || !header_value(peer.grant->grant))
            continue;
        const auto url = peer_blob_url(peer.endpoint, target.sha256, allocator_);
        if (!url)
            continue;
        RangeSource& source = sources.emplace_back();
        source.url          = *url;
        source.untrusted    = true;
        source.grant        = peer.grant->grant;
    }
    tried = 0;
    for (const Mirror& mirror : options.mirrors)
    {
        if (++tried > max_mirrors)
            break;
        const auto parts = split_url(mirror.url);
        if (!parts || !check_untrusted_scheme(*parts))
            continue;
        RangeSource& source = sources.emplace_back();
        source.url          = mirror.url;
        source.untrusted    = true;
    }
    if (const auto url = resolve_url(origin(), target.url, allocator_); url)
    {
        RangeSource& source = sources.emplace_back();
        source.url          = *url;
    }

    DeltaReport report;
    for (const ByteRange& range : delta_ranges(*plan, options.gap, allocator_))
    {
        if (auto read = read_range(assembler, range, target, sources, report); !read)
            return whole();
    }
    if (auto finished = assembler.finish(); !finished)
        return whole();
    report.from_seeds  = assembler.from_seeds();
    report.from_ranges = assembler.from_ranges();
    return report;
}

Result<DeltaReport> Client::download_with_seeds(const DownloadTarget& target, const AppChunks& chunks,
    std::span<const Seed> seeds, DownloadSink& sink, const DeltaOptions& options)
{
    const auto index = chunk_index(chunks, target);
    if (!index || !*index)
    {
        // No usable index: the file whole, as without this family
        if (auto dropped = sink.restart(); !dropped)
            return std::unexpected(dropped.error());
        if (auto done = download_whole(target, sink, options); !done)
            return std::unexpected(done.error());
        DeltaReport report;
        report.whole_file = true;
        return report;
    }
    return download_with_index(target, **index, seeds, sink, options);
}

} // namespace lantern
