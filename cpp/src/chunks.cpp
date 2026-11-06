// SPEC.md § 22: the chunker lantern-cdc-1, chunk indexes, and putting a file
// together from seeds and ranges.
#include <lantern/chunks.hpp>

#include <algorithm>
#include <charconv>
#include <cstring>
#include <system_error>

namespace lantern
{

namespace
{

constexpr unsigned cdc_size_bits_least = 16;
constexpr unsigned cdc_size_bits_most  = 22;
constexpr std::size_t json_scratch     = 4096;

std::array<std::uint64_t, 256> make_gear() noexcept
{
    std::array<std::uint64_t, 256> gear {};
    std::array<char, 14> input {};
    std::memcpy(input.data(), cdc_algorithm.data(), cdc_algorithm.size());
    for (std::size_t i = 0; i < gear.size(); ++i)
    {
        input[cdc_algorithm.size()] = static_cast<char>(i);
        const Digest digest         = Sha256::of(std::string_view(input.data(), input.size()));
        std::uint64_t value         = 0;
        for (std::size_t k = 0; k < 8; ++k)
            value = (value << 8U) | digest[k];
        gear[i] = value;
    }
    return gear;
}

std::optional<std::uint64_t> whole_number(std::string_view text) noexcept
{
    std::uint64_t value = 0;
    const char* end     = text.data() + text.size();
    const auto result   = std::from_chars(text.data(), end, value);
    if (text.empty() || result.ec != std::errc {} || result.ptr != end)
        return std::nullopt;
    return value;
}

int compare_digests(const Digest& a, const Digest& b) noexcept
{
    return std::memcmp(a.data(), b.data(), a.size());
}

// The members of an index, as read.
struct ReadIndex
{
    explicit ReadIndex(const Allocator& allocator)
        : chunks(allocator)
    {
    }

    std::optional<std::uint64_t> schema;
    std::optional<std::uint64_t> size;
    std::optional<Digest> sha256;
    bool has_chunker = false;
    bool known_alg   = false;
    std::optional<std::uint64_t> chunker_size;
    bool has_chunks = false;
    // A chunk not of the form, or too many of them
    bool bad_chunks = false;
    Vector<IndexedChunk> chunks;
};

Error reader_error(const json::Reader& reader)
{
    return reader.failed() ? reader.error() : Error::make(Category::invalid_response, "not a chunk index");
}

// Moves past a chunk's array whatever it holds, from inside it (depth `depth`).
bool drain(json::Reader& reader, std::size_t depth) noexcept
{
    while (reader.depth() >= depth)
    {
        if (reader.next() == json::Event::error)
            return false;
    }
    return true;
}

// One entry of `chunks`, [size, "sha256"], read whole whatever its form,
// from its first event `event`. False when the reader failed; `ok` says
// whether the entry is of the form.
bool read_entry(json::Reader& reader, json::Event event, IndexedChunk& out, bool& ok) noexcept
{
    ok = false;
    if (event != json::Event::array_begin)
        return reader.skip();
    const std::size_t depth = reader.depth();
    event                   = reader.next();
    if (event == json::Event::error)
        return false;
    if (event != json::Event::number)
        return event == json::Event::array_end || drain(reader, depth);
    const auto length = whole_number(reader.text());
    event             = reader.next();
    if (event == json::Event::error)
        return false;
    if (event != json::Event::string)
        return event == json::Event::array_end || drain(reader, depth);
    const auto digest = digest_from_hex(reader.text());
    event             = reader.next();
    if (event == json::Event::error)
        return false;
    if (event != json::Event::array_end)
        return drain(reader, depth);
    if (length && digest && *length >= 1 && *length <= UINT32_MAX)
    {
        out.length = static_cast<std::uint32_t>(*length);
        out.sha256 = *digest;
        ok         = true;
    }
    return true;
}

bool read_chunks(json::Reader& reader, ReadIndex& out) noexcept
{
    const json::Event begin = reader.next();
    if (begin == json::Event::error)
        return false;
    if (begin != json::Event::array_begin)
    {
        out.bad_chunks = true;
        return reader.skip();
    }
    for (;;)
    {
        const json::Event event = reader.next();
        if (event == json::Event::array_end)
            return true;
        if (event == json::Event::error)
            return false;
        if (out.bad_chunks)
        {
            if (!reader.skip())
                return false;
            continue;
        }
        IndexedChunk entry;
        bool ok = false;
        if (!read_entry(reader, event, entry, ok))
            return false;
        if (!ok || out.chunks.size() >= chunks_limit)
            out.bad_chunks = true;
        else
            out.chunks.push_back(entry);
    }
}

bool read_chunker(json::Reader& reader, ReadIndex& out) noexcept
{
    const json::Event begin = reader.next();
    if (begin == json::Event::error)
        return false;
    out.has_chunker = true;
    if (begin != json::Event::object_begin)
        return reader.skip();
    bool has_alg  = false;
    bool has_size = false;
    while (reader.next() == json::Event::key)
    {
        const std::string_view key = reader.text();
        if (key == "alg" && !has_alg)
        {
            has_alg                 = true;
            const json::Event event = reader.next();
            if (event == json::Event::error)
                return false;
            out.known_alg = event == json::Event::string && reader.text() == cdc_algorithm;
            if (event != json::Event::string && !reader.skip())
                return false;
        }
        else if (key == "size" && !has_size)
        {
            has_size                = true;
            const json::Event event = reader.next();
            if (event == json::Event::error)
                return false;
            if (event == json::Event::number)
                out.chunker_size = whole_number(reader.text());
            else if (!reader.skip())
                return false;
        }
        else
        {
            if (reader.next() == json::Event::error || !reader.skip())
                return false;
        }
    }
    return !reader.failed();
}

} // namespace

bool is_cdc_size(std::uint64_t size) noexcept
{
    return size >= cdc_size_least && size <= cdc_size_most && (size & (size - 1)) == 0;
}

std::optional<CdcBounds> cdc_bounds(std::uint64_t size) noexcept
{
    if (!is_cdc_size(size))
        return std::nullopt;
    unsigned bits = 0;
    while ((std::uint64_t { 1 } << bits) < size)
        ++bits;
    CdcBounds bounds;
    bounds.min  = static_cast<std::size_t>(size >> 2U);
    bounds.max  = static_cast<std::size_t>(size << 2U);
    bounds.mask = ((std::uint64_t { 1 } << bits) - 1) << (64U - bits);
    return bounds;
}

const std::array<std::uint64_t, 256>& cdc_gear() noexcept
{
    static const std::array<std::uint64_t, 256> table = make_gear();
    return table;
}

std::size_t cdc_next(std::span<const std::byte> rest, const CdcBounds& bounds) noexcept
{
    if (rest.size() <= bounds.min)
        return rest.size();
    const std::size_t end = std::min(rest.size(), bounds.max);
    const auto& gear      = cdc_gear();
    std::uint64_t hash    = 0;
    for (std::size_t i = bounds.min; i < end; ++i)
    {
        hash = (hash << 1U) + gear[std::to_integer<unsigned>(rest[i])];
        if ((hash & bounds.mask) == 0)
            return i + 1;
    }
    return end;
}

Result<Vector<Cut>> cdc_cut(std::span<const std::byte> data, std::uint64_t size, Allocator allocator)
{
    const auto bounds = cdc_bounds(size);
    if (!bounds)
        return fail(Category::usage, "a chunker's size is a power of two from 65536 to 4194304");
    Vector<Cut> cuts(allocator);
    cuts.reserve(data.size() / (bounds->min + 1) + 1);
    std::size_t at = 0;
    while (at < data.size())
    {
        const std::size_t length = cdc_next(data.subspan(at), *bounds);
        cuts.push_back({ at, static_cast<std::uint32_t>(length) });
        at += length;
    }
    return cuts;
}

std::optional<std::uint64_t> cdc_size_for(std::uint64_t length) noexcept
{
    for (unsigned bits = cdc_size_bits_least; bits <= cdc_size_bits_most; ++bits)
    {
        const std::uint64_t size = std::uint64_t { 1 } << bits;
        const std::uint64_t low  = size >> 2U;
        if (length / (low + 1) + 1 <= chunks_limit && length / size <= 16384)
            return size;
    }
    const std::uint64_t size = cdc_size_most;
    if (length / ((size >> 2U) + 1) + 1 <= chunks_limit)
        return size;
    return std::nullopt;
}

Read<ChunkIndex> read_chunk_index(
    std::string_view raw, const AppChunks* ref, const Digest& sha256, std::uint64_t size, Allocator allocator)
{
    if (raw.size() > chunk_index_limit)
        return fail(Category::limit, "a chunk index above 8 MiB (SPEC.md 13)");
    if (ref != nullptr)
    {
        if (raw.size() != ref->size)
            return fail(Category::integrity, "a chunk index of other bytes than `chunks` gives");
        if (!same_digest(Sha256::of(raw), ref->sha256))
            return fail(Category::integrity, "a chunk index whose SHA-256 is not the one `chunks` gives");
    }
    const json::Limits limits;
    std::array<char, json_scratch> scratch {};
    ReadIndex found(allocator);
    found.chunks.reserve(std::min(raw.size() / 70 + 1, chunks_limit));

    json::Reader reader(raw, limits, scratch);
    if (reader.next() != json::Event::object_begin)
        return std::unexpected(reader_error(reader));
    // Which members were seen, to refuse one twice
    unsigned seen = 0;
    while (reader.next() == json::Event::key)
    {
        const std::string_view key = reader.text();
        unsigned bit               = 0;
        if (key == "schema")
            bit = 1;
        else if (key == "sha256")
            bit = 2;
        else if (key == "size")
            bit = 4;
        else if (key == "chunker")
            bit = 8;
        else if (key == "chunks")
            bit = 16;
        if ((seen & bit) != 0)
            return fail(Category::invalid_response, "a chunk index with a member twice");
        seen |= bit;
        bool ok = true;
        switch (bit)
        {
            case 1:
            case 4:
            {
                const json::Event event = reader.next();
                ok                      = event != json::Event::error;
                if (ok && event == json::Event::number)
                    (bit == 1 ? found.schema : found.size) = whole_number(reader.text());
                else if (ok)
                    ok = reader.skip();
                break;
            }
            case 2:
            {
                const json::Event event = reader.next();
                ok                      = event != json::Event::error;
                if (ok && event == json::Event::string)
                    found.sha256 = digest_from_hex(reader.text());
                else if (ok)
                    ok = reader.skip();
                break;
            }
            case 8:
                ok = read_chunker(reader, found);
                break;
            case 16:
                found.has_chunks = true;
                ok               = read_chunks(reader, found);
                break;
            default:
                ok = reader.next() != json::Event::error && reader.skip();
                break;
        }
        if (!ok)
            return std::unexpected(reader_error(reader));
    }
    if (reader.failed() || reader.next() != json::Event::end)
        return std::unexpected(reader_error(reader));

    // § 3.2: a schema above the one this library reads is absent
    if (!found.schema)
        return fail(Category::invalid_response, "a chunk index without an integer schema");
    if (*found.schema > 1)
        return std::optional<ChunkIndex> {};
    if (*found.schema != 1)
        return fail(Category::invalid_response, "a chunk index of schema 0");
    // A chunker this library does not know: the file is read whole
    if (!found.has_chunker || !found.known_alg || !found.chunker_size || !is_cdc_size(*found.chunker_size))
        return std::optional<ChunkIndex> {};
    if (!found.sha256 || !found.size || !same_digest(*found.sha256, sha256) || *found.size != size)
        return fail(Category::integrity, "the chunk index of another file");
    if (!found.has_chunks || found.bad_chunks)
        return fail(Category::invalid_response, "chunks of another form than SPEC.md 22.1's");
    const auto bounds = cdc_bounds(*found.chunker_size);
    if (!bounds)
        return fail(Category::invalid_response, "a chunker this client does not know");
    std::uint64_t total = 0;
    for (const IndexedChunk& chunk : found.chunks)
    {
        if (chunk.length > bounds->max)
            return fail(Category::invalid_response, "a chunk above the chunker's most (SPEC.md 22.3)");
        total += chunk.length;
    }
    if (total != size)
        return fail(Category::integrity, "a chunk index whose chunks do not add up to the file's size");

    ChunkIndex index(allocator);
    index.size         = size;
    index.sha256       = sha256;
    index.chunker_size = *found.chunker_size;
    index.chunks       = std::move(found.chunks);
    return index;
}

namespace
{

struct SeedChunk
{
    Digest sha256 {};
    std::uint32_t length = 0;
    std::int32_t seed    = 0;
    std::uint64_t offset = 0;
};

bool seed_chunk_less(const SeedChunk& a, const SeedChunk& b) noexcept
{
    if (const int c = compare_digests(a.sha256, b.sha256); c != 0)
        return c < 0;
    if (a.seed != b.seed)
        return a.seed < b.seed;
    return a.offset < b.offset;
}

} // namespace

Result<DeltaPlan> plan_delta(const ChunkIndex& index, std::span<const Seed> seeds, Allocator allocator)
{
    const auto bounds = cdc_bounds(index.chunker_size);
    if (!bounds)
        return fail(Category::usage, "an index of a chunker this library does not know");
    if (seeds.size() > static_cast<std::size_t>(INT32_MAX))
        return fail(Category::usage, "too many seeds");
    Vector<SeedChunk> found(allocator);
    for (std::size_t n = 0; n < seeds.size(); ++n)
    {
        const Seed seed = seeds[n];
        std::size_t at  = 0;
        while (at < seed.size())
        {
            const std::size_t length = cdc_next(seed.subspan(at), *bounds);
            SeedChunk chunk;
            chunk.sha256 = Sha256::of(seed.subspan(at, length));
            chunk.length = static_cast<std::uint32_t>(length);
            chunk.seed   = static_cast<std::int32_t>(n);
            chunk.offset = at;
            found.push_back(chunk);
            at += length;
        }
    }
    std::ranges::sort(found, seed_chunk_less);

    DeltaPlan plan(allocator);
    plan.steps.reserve(index.chunks.size());
    std::uint64_t offset = 0;
    for (const IndexedChunk& chunk : index.chunks)
    {
        DeltaStep step;
        step.offset = offset;
        step.length = chunk.length;
        step.sha256 = chunk.sha256;
        // The first seed's, and its first, among those of the same SHA-256 and size
        auto it = std::ranges::lower_bound(
            found, chunk.sha256, [](const Digest& a, const Digest& d) { return compare_digests(a, d) < 0; },
            &SeedChunk::sha256);
        for (; it != found.end() && compare_digests(it->sha256, chunk.sha256) == 0; ++it)
        {
            if (it->length == chunk.length)
            {
                step.seed        = it->seed;
                step.seed_offset = it->offset;
                break;
            }
        }
        (step.from_seed() ? plan.seeded : plan.to_read) += chunk.length;
        plan.steps.push_back(step);
        offset += chunk.length;
    }
    return plan;
}

Vector<ByteRange> delta_ranges(const DeltaPlan& plan, std::uint64_t gap, Allocator allocator)
{
    Vector<ByteRange> out(allocator);
    for (const DeltaStep& step : plan.steps)
    {
        if (step.from_seed())
            continue;
        const std::uint64_t last = step.offset + step.length - 1;
        if (!out.empty() && step.offset - out.back().last - 1 <= gap)
            out.back().last = last;
        else
            out.push_back({ step.offset, last });
    }
    return out;
}

DeltaAssembler::DeltaAssembler(const ChunkIndex& index, const DeltaPlan& plan, std::span<const Seed> seeds,
    DownloadSink& sink, Allocator allocator)
    : index_(&index)
    , plan_(&plan)
    , seeds_(seeds)
    , sink_(&sink)
    , chunk_(allocator)
{
    std::uint32_t most = 0;
    for (const DeltaStep& step : plan.steps)
    {
        if (!step.from_seed())
            most = std::max(most, step.length);
    }
    chunk_.resize(most);
}

Result<void> DeltaAssembler::keep(std::span<const std::byte> bytes)
{
    // L-22.3-3: never more than the file's size
    if (bytes.size() > index_->size - written_)
        return fail(Category::integrity, "more bytes than the file has");
    if (auto done = sink_->write(bytes); !done)
        return done;
    file_hash_.update(bytes);
    written_ += bytes.size();
    return {};
}

Result<void> DeltaAssembler::flush_seeds()
{
    const auto& steps = plan_->steps;
    while (next_ < steps.size() && steps[next_].from_seed())
    {
        const DeltaStep& step = steps[next_];
        const auto n          = static_cast<std::size_t>(step.seed);
        if (n >= seeds_.size() || step.seed_offset > seeds_[n].size()
            || step.length > seeds_[n].size() - step.seed_offset)
            return fail(Category::usage, "a plan that does not match its seeds");
        if (auto done = keep(seeds_[n].subspan(static_cast<std::size_t>(step.seed_offset), step.length));
            !done)
            return done;
        from_seeds_ += step.length;
        ++next_;
    }
    return {};
}

Result<void> DeltaAssembler::start()
{
    if (started_)
        return fail(Category::usage, "an assembler started twice");
    started_ = true;
    return flush_seeds();
}

Result<void> DeltaAssembler::begin_range(const ByteRange& range)
{
    if (!started_)
        return fail(Category::usage, "an assembler not started");
    if (next_ >= plan_->steps.size() || range.last < range.first || range.first != plan_->steps[next_].offset
        || range.last >= index_->size)
        return fail(Category::usage, "a range that does not begin at the next chunk to read");
    position_   = range.first;
    range_end_  = range.last + 1;
    held_       = 0;
    chunk_hash_ = Sha256();
    return {};
}

Result<void> DeltaAssembler::feed(std::span<const std::byte> bytes)
{
    if (bytes.size() > range_end_ - position_)
        return fail(Category::integrity, "a source sends more than the range asked for (SPEC.md 22.3)");
    const auto& steps = plan_->steps;
    while (!bytes.empty())
    {
        if (next_ >= steps.size())
        {
            // Past the last chunk to read: nothing is kept
            position_ += bytes.size();
            return {};
        }
        const DeltaStep& step = steps[next_];
        if (position_ < step.offset)
        {
            // Chunks found in a seed, between two to read: not kept
            const auto skip
                = static_cast<std::size_t>(std::min<std::uint64_t>(bytes.size(), step.offset - position_));
            position_ += skip;
            bytes = bytes.subspan(skip);
            continue;
        }
        const std::size_t take = std::min<std::size_t>(bytes.size(), step.length - held_);
        std::ranges::copy(bytes.first(take), chunk_.begin() + static_cast<std::ptrdiff_t>(held_));
        chunk_hash_.update(bytes.first(take));
        held_ += take;
        position_ += take;
        bytes = bytes.subspan(take);
        if (held_ < step.length)
            continue;
        // L-22.3-2: a chunk is kept only once its SHA-256 matches the index's
        held_ = 0;
        if (!same_digest(chunk_hash_.finish(), step.sha256))
            return fail(Category::integrity, "a chunk that does not match its SHA-256 (SPEC.md 22.3)");
        if (auto done = keep(std::span<const std::byte>(chunk_.data(), step.length)); !done)
            return done;
        from_ranges_ += step.length;
        ++next_;
        if (auto done = flush_seeds(); !done)
            return done;
    }
    return {};
}

Result<void> DeltaAssembler::end_range() const
{
    if (position_ != range_end_)
        return fail(Category::transport, "a range cut short");
    return {};
}

std::optional<ByteRange> DeltaAssembler::remaining(const ByteRange& asked) const noexcept
{
    const auto& steps = plan_->steps;
    if (next_ >= steps.size())
        return std::nullopt;
    const DeltaStep& step = steps[next_];
    if (step.offset > asked.last || step.offset + step.length - 1 > asked.last)
        return std::nullopt;
    return ByteRange { step.offset, asked.last };
}

Result<void> DeltaAssembler::finish()
{
    if (next_ != plan_->steps.size() || written_ != index_->size)
        return fail(Category::integrity, "the file is not whole: read it whole (SPEC.md 22.3)");
    Sha256 hash = file_hash_;
    if (!same_digest(hash.finish(), index_->sha256))
        return fail(Category::integrity, "the file put together does not match its SHA-256: read it whole");
    return {};
}

} // namespace lantern
