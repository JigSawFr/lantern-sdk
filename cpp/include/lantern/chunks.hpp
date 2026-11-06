// Differential updates (SPEC.md § 22, feature `deltas`): a file is cut into
// chunks by a rule that depends on its bytes alone (`lantern-cdc-1`), its
// index lists them by size and SHA-256, and a client that holds bytes of an
// older version (its seeds) puts the newer file together from the chunks it
// finds there and ranges of the file it reads, each chunk checked by its
// SHA-256 and the whole file by its own, before anything is installed.
//
// Nothing here talks to a server: the chunker, the index's reader and its
// checks (L-22.3-1), the plan and the assembler (L-22.3-2, L-22.3-3). The
// client (client.hpp) fetches an index and reads the ranges.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/document.hpp>
#include <lantern/download.hpp>
#include <lantern/error.hpp>
#include <lantern/memory.hpp>
#include <lantern/sha256.hpp>
#include <lantern/types.hpp>

namespace lantern
{

inline constexpr std::string_view cdc_algorithm = "lantern-cdc-1";
// A chunker's size: a power of two from 64 KiB to 4 MiB (§ 22.1).
inline constexpr std::uint64_t cdc_size_least = std::uint64_t { 1 } << 16U;
inline constexpr std::uint64_t cdc_size_most  = std::uint64_t { 1 } << 22U;
// § 13: the chunks of an index, and an index's bytes.
inline constexpr std::size_t chunks_limit      = 100000;
inline constexpr std::size_t chunk_index_limit = std::size_t { 8 } << 20U;

[[nodiscard]] bool is_cdc_size(std::uint64_t size) noexcept;

// A chunker's bounds for a `size` S (§ 22.2): at least S / 4 bytes, at most
// 4 S, the mask whose top b bits are set (S = 2^b).
struct CdcBounds
{
    std::size_t min    = 0;
    std::size_t max    = 0;
    std::uint64_t mask = 0;
};

// Nothing for a size that is not a power of two from 64 KiB to 4 MiB.
[[nodiscard]] std::optional<CdcBounds> cdc_bounds(std::uint64_t size) noexcept;

// The gear table: for each byte value, the first 8 bytes, as a big-endian
// integer, of the SHA-256 of `lantern-cdc-1` followed by that byte.
[[nodiscard]] const std::array<std::uint64_t, 256>& cdc_gear() noexcept;

// The length of the chunk that begins `rest`, which is not empty: the end
// of `rest` when `bounds.min` bytes or fewer are left, else after the first
// byte from the `min`-th on that leaves the gear hash's masked bits clear,
// or after the `max`-th, or at the end.
[[nodiscard]] std::size_t cdc_next(std::span<const std::byte> rest, const CdcBounds& bounds) noexcept;

// A chunk of a file: where it begins and how long it is.
struct Cut
{
    std::uint64_t offset = 0;
    std::uint32_t length = 0;
};

// Every chunk of `data` for a chunker of `size`; an error for a size that is
// not one. No allocation but the result.
[[nodiscard]] Result<Vector<Cut>> cdc_cut(
    std::span<const std::byte> data, std::uint64_t size, Allocator allocator = {});

// The chunker's size a server may choose for a file of `length` bytes: the
// smallest whose chunks stay about 16,384 and, whatever the bytes, within
// the limit of 100,000; nothing for a file too large for any.
[[nodiscard]] std::optional<std::uint64_t> cdc_size_for(std::uint64_t length) noexcept;

// A chunk as an index lists it.
struct IndexedChunk
{
    std::uint32_t length = 0;
    Digest sha256 {};
};

// A chunk index (§ 22.1), read and checked.
struct ChunkIndex
{
    using allocator_type = Allocator;

    // The whole file's, as its app or package gives them.
    std::uint64_t size = 0;
    Digest sha256 {};
    // The chunker's size (its algorithm is `lantern-cdc-1`).
    std::uint64_t chunker_size = 0;
    Vector<IndexedChunk> chunks;

    ChunkIndex()
        : ChunkIndex(allocator_type {})
    {
    }
    explicit ChunkIndex(const allocator_type& allocator)
        : chunks(allocator)
    {
    }
    ChunkIndex(const ChunkIndex& other, const allocator_type& allocator)
        : size(other.size)
        , sha256(other.sha256)
        , chunker_size(other.chunker_size)
        , chunks(other.chunks, allocator)
    {
    }
    ChunkIndex(ChunkIndex&& other, const allocator_type& allocator)
        : size(other.size)
        , sha256(other.sha256)
        , chunker_size(other.chunker_size)
        , chunks(std::move(other.chunks), allocator)
    {
    }
    ChunkIndex(const ChunkIndex&)            = default;
    ChunkIndex(ChunkIndex&&) noexcept        = default;
    ChunkIndex& operator=(const ChunkIndex&) = default;
    ChunkIndex& operator=(ChunkIndex&&)      = default;
    ~ChunkIndex()                            = default;
};

// The index a client may use for the file of `sha256` and `size`, from the
// bytes `raw` it read where `ref` (the app's or package's `chunks`) says it
// is (L-22.3-1). With `ref`, `raw` must be of its size and SHA-256 (an index
// asked for by the file's SHA-256 has no `ref`: leave it null).
//
// Absent (an empty optional) for an index of a `schema` above 1 or a chunker
// this library does not know (§ 3.2): read the file whole. An error for one
// that is not usable: other bytes than `ref` gives, not an index of that
// file, chunks of another form (each 1 byte to the chunker's most, a digest
// in lower case, 100,000 at most, their sizes adding up to the file's), a
// member twice. Read the file whole then too.
[[nodiscard]] Read<ChunkIndex> read_chunk_index(std::string_view raw, const AppChunks* ref,
    const Digest& sha256, std::uint64_t size, Allocator allocator = {});

// Bytes the client holds of an older version of the file.
using Seed = std::span<const std::byte>;

// One chunk of the file to put together.
struct DeltaStep
{
    std::uint64_t offset = 0;
    std::uint32_t length = 0;
    Digest sha256 {};
    // The seed holding this chunk, and where; -1 for a chunk to read.
    std::int32_t seed         = -1;
    std::uint64_t seed_offset = 0;

    [[nodiscard]] bool from_seed() const noexcept { return seed >= 0; }
};

// What is taken from where (§ 22.3), in the file's order.
struct DeltaPlan
{
    Vector<DeltaStep> steps;
    // Bytes found in the seeds, and bytes to read.
    std::uint64_t seeded  = 0;
    std::uint64_t to_read = 0;

    explicit DeltaPlan(const Allocator& allocator = {})
        : steps(allocator)
    {
    }
};

// Cuts each seed by the index's chunker and takes, for each chunk of the
// index, the first seed's chunk of the same size and SHA-256 (the chunks of
// a seed are held by their hashes: nothing is allocated per byte).
[[nodiscard]] Result<DeltaPlan> plan_delta(
    const ChunkIndex& index, std::span<const Seed> seeds, Allocator allocator = {});

// A range of the file, `first` to `last` inclusive (RFC 9110's range).
struct ByteRange
{
    std::uint64_t first = 0;
    std::uint64_t last  = 0;

    [[nodiscard]] std::uint64_t length() const noexcept { return last - first + 1; }
    friend bool operator==(const ByteRange&, const ByteRange&) = default;
};

// The ranges to ask for: the chunks to read, neighbours joined when at most
// `gap` bytes of chunks found in a seed lie between them (Annex B.13).
[[nodiscard]] Vector<ByteRange> delta_ranges(
    const DeltaPlan& plan, std::uint64_t gap = 0, Allocator allocator = {});

// What a differential download did.
struct DeltaReport
{
    // Bytes taken from the seeds, and bytes read as ranges and verified.
    std::uint64_t from_seeds  = 0;
    std::uint64_t from_ranges = 0;
    // Requests for ranges sent.
    std::uint32_t requests = 0;
    // The index could not be used, or a source failed: the file was read
    // whole (L-22.3-4).
    bool whole_file = false;
};

// Puts the file together into `sink`, in its order: the chunks found in the
// seeds are written as they come up, and the others are fed from the ranges
// read (feed()), each held until its SHA-256 matches the index's and only
// then written (L-22.3-2). Never more than the file's size is written
// (L-22.3-3: the sizes of the chunks add up to it), nor a byte read that was
// not asked for. finish() checks the whole file.
//
// A failure leaves the sink with what was verified; the caller then calls
// `sink.restart()` and reads the whole file (L-22.3-4).
class DeltaAssembler
{
  public:
    // `index`, `plan` and `seeds` must outlive the assembler; `plan` was made
    // by plan_delta() from this index and these seeds.
    DeltaAssembler(const ChunkIndex& index, const DeltaPlan& plan, std::span<const Seed> seeds,
        DownloadSink& sink, Allocator allocator = {});

    // Writes the chunks found in the seeds before the first chunk to read.
    [[nodiscard]] Result<void> start();

    // The next range is `range`, which begins at the first chunk not yet
    // verified (a partial chunk of an earlier attempt is dropped).
    [[nodiscard]] Result<void> begin_range(const ByteRange& range);
    // The next bytes of the range. More than the range asked for is an error.
    [[nodiscard]] Result<void> feed(std::span<const std::byte> bytes);
    // The range is over: an error when it gave fewer bytes than asked.
    [[nodiscard]] Result<void> end_range() const;
    // What of `asked` is still to read after an attempt (a range cut short
    // keeps the chunks verified so far): the same range without them.
    [[nodiscard]] std::optional<ByteRange> remaining(const ByteRange& asked) const noexcept;

    // The file is whole and its size and SHA-256 are the index's; an error
    // (Category::integrity) otherwise.
    [[nodiscard]] Result<void> finish();

    [[nodiscard]] std::uint64_t written() const noexcept { return written_; }
    // Bytes taken from the seeds, and bytes read and verified.
    [[nodiscard]] std::uint64_t from_seeds() const noexcept { return from_seeds_; }
    [[nodiscard]] std::uint64_t from_ranges() const noexcept { return from_ranges_; }

  private:
    [[nodiscard]] Result<void> flush_seeds();
    [[nodiscard]] Result<void> keep(std::span<const std::byte> bytes);

    const ChunkIndex* index_;
    const DeltaPlan* plan_;
    std::span<const Seed> seeds_;
    DownloadSink* sink_;
    Vector<std::byte> chunk_;
    Sha256 chunk_hash_;
    Sha256 file_hash_;
    std::size_t next_          = 0;
    std::size_t held_          = 0;
    std::uint64_t position_    = 0;
    std::uint64_t range_end_   = 0;
    std::uint64_t written_     = 0;
    std::uint64_t from_seeds_  = 0;
    std::uint64_t from_ranges_ = 0;
    bool started_              = false;
};

} // namespace lantern
