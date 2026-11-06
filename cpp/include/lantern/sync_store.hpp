// What a server keeps of the sync data (SPEC.md § 20): the interface the
// server core asks, and a complete store held in memory for tests, demos and
// as a reference to read.
//
// The server does the protocol's work: the collections and the form of their
// items, the merge rule item by item (sync.hpp), the revisions, `If-Match`,
// the generation checked, the limit of items, the events. A store keeps
// each account's collections of items, deletions included, a revision per
// collection, and a `generation` that changes only when the data is erased
// (§ 20.5). A deletion is kept at least 30 days (L-20.5-2); a store that
// drops the older ones remembers up to which revision, so that a read after
// an older one is a 410 (L-20.3-1). Every method is atomic; the server makes
// a check and the change it leads to one step itself. Several threads call
// them.
#pragma once

#include <cstdint>
#include <mutex>
#include <span>
#include <string_view>
#include <unordered_map>
#include <utility>

#include <lantern/device_key.hpp>
#include <lantern/error.hpp>
#include <lantern/memory.hpp>
#include <lantern/types.hpp>

namespace lantern
{

// How many days a deletion is kept at least (L-20.5-2).
inline constexpr std::int64_t sync_tombstone_days = 30;

// A collection's revision and its live items, in the account's overview.
struct SyncCollectionInfo
{
    using allocator_type = Allocator;

    String name;
    std::uint64_t rev   = 0;
    std::uint64_t items = 0;

    explicit SyncCollectionInfo(const allocator_type& allocator = {})
        : name(allocator)
    {
    }
    SyncCollectionInfo(const SyncCollectionInfo& other, const allocator_type& allocator)
        : name(other.name, allocator)
        , rev(other.rev)
        , items(other.items)
    {
    }
    SyncCollectionInfo(SyncCollectionInfo&& other, const allocator_type& allocator)
        : name(std::move(other.name), allocator)
        , rev(other.rev)
        , items(other.items)
    {
    }
    SyncCollectionInfo(const SyncCollectionInfo&)            = default;
    SyncCollectionInfo(SyncCollectionInfo&&)                 = default;
    SyncCollectionInfo& operator=(const SyncCollectionInfo&) = default;
    SyncCollectionInfo& operator=(SyncCollectionInfo&&)      = default;
    ~SyncCollectionInfo()                                    = default;
};

// What an account keeps: its generation and the collections it holds items
// in (the others are empty, at revision 0).
struct SyncOverview
{
    using allocator_type = Allocator;

    String generation;
    Vector<SyncCollectionInfo> collections;

    explicit SyncOverview(const allocator_type& allocator = {})
        : generation(allocator)
        , collections(allocator)
    {
    }
};

// A collection as kept: every item, deletions included, each with its `rev`.
struct SyncSnapshot
{
    using allocator_type = Allocator;

    String generation;
    std::uint64_t rev = 0;
    // The deletions up to this revision are gone: a read after an older one
    // cannot be answered (410).
    std::uint64_t floor = 0;
    Vector<SyncItem> items;

    explicit SyncSnapshot(const allocator_type& allocator = {})
        : generation(allocator)
        , items(allocator)
    {
    }
};

// Where a server keeps sync data. A method that fails (Category::storage)
// makes the request a 500. `user` is the account's name, `now` Unix seconds.
class SyncStore
{
  public:
    SyncStore()                            = default;
    SyncStore(const SyncStore&)            = default;
    SyncStore(SyncStore&&)                 = default;
    SyncStore& operator=(const SyncStore&) = default;
    SyncStore& operator=(SyncStore&&)      = default;
    virtual ~SyncStore()                   = default;

    // How many items a collection holds at most (`limits.sync_items`, L-20.5-4), 1 to 100000.
    [[nodiscard]] virtual std::uint32_t item_limit() const noexcept = 0;

    // The account's generation, and the revision and live items of the collections it holds.
    [[nodiscard]] virtual Result<SyncOverview> overview(
        std::string_view user, std::int64_t now, const Allocator& allocator)
        = 0;
    // A collection whole (empty at revision 0 when the account has none).
    [[nodiscard]] virtual Result<SyncSnapshot> read(
        std::string_view user, std::string_view collection, std::int64_t now, const Allocator& allocator)
        = 0;
    // Keeps `items` (each with its `rev`: the item replaces the one of its key) and sets the collection's
    // revision to `rev`.
    [[nodiscard]] virtual Result<void> write(std::string_view user, std::string_view collection,
        std::span<const SyncItem> items, std::uint64_t rev, std::int64_t now)
        = 0;
    // Erases a collection, or every one when `collection` is empty, deletions included, and gives the
    // account a new generation (L-20.5-1), which it returns.
    [[nodiscard]] virtual Result<String> erase(
        std::string_view user, std::string_view collection, const Allocator& allocator)
        = 0;
    // Erases an account's data, the account being deleted (L-20.5-3).
    [[nodiscard]] virtual Result<void> forget(std::string_view user) = 0;
};

// Sync data held in memory, behind a mutex. The generations are drawn from
// `random`, which must outlive the store; deletions are dropped after
// `retention` seconds (30 days by default, the least the protocol allows).
class MemorySyncStore final : public SyncStore
{
  public:
    explicit MemorySyncStore(RandomSource& random, std::uint32_t item_limit = 10000,
        std::int64_t retention = sync_tombstone_days * 86400, const Allocator& allocator = {});

    [[nodiscard]] std::uint32_t item_limit() const noexcept override { return limit_; }
    [[nodiscard]] Result<SyncOverview> overview(
        std::string_view user, std::int64_t now, const Allocator& allocator) override;
    [[nodiscard]] Result<SyncSnapshot> read(std::string_view user, std::string_view collection,
        std::int64_t now, const Allocator& allocator) override;
    [[nodiscard]] Result<void> write(std::string_view user, std::string_view collection,
        std::span<const SyncItem> items, std::uint64_t rev, std::int64_t now) override;
    [[nodiscard]] Result<String> erase(
        std::string_view user, std::string_view collection, const Allocator& allocator) override;
    [[nodiscard]] Result<void> forget(std::string_view user) override;

  private:
    struct Kept
    {
        using allocator_type = Allocator;

        SyncItem item;
        std::int64_t at = 0; // when it was kept

        explicit Kept(const allocator_type& allocator)
            : item(allocator)
        {
        }
        Kept(const Kept& other, const allocator_type& allocator)
            : item(other.item, allocator)
            , at(other.at)
        {
        }
        Kept(Kept&& other, const allocator_type& allocator)
            : item(std::move(other.item), allocator)
            , at(other.at)
        {
        }
        Kept(const Kept&)            = default;
        Kept(Kept&&)                 = default;
        Kept& operator=(const Kept&) = default;
        Kept& operator=(Kept&&)      = default;
        ~Kept()                      = default;
    };

    struct Collection
    {
        using allocator_type = Allocator;

        std::uint64_t rev   = 0;
        std::uint64_t floor = 0;
        std::pmr::unordered_map<String, Kept> items;

        explicit Collection(const allocator_type& allocator)
            : items(allocator)
        {
        }
        Collection(const Collection& other, const allocator_type& allocator)
            : rev(other.rev)
            , floor(other.floor)
            , items(other.items, allocator)
        {
        }
        Collection(Collection&& other, const allocator_type& allocator)
            : rev(other.rev)
            , floor(other.floor)
            , items(std::move(other.items), allocator)
        {
        }
        Collection(const Collection&)            = default;
        Collection(Collection&&)                 = default;
        Collection& operator=(const Collection&) = default;
        Collection& operator=(Collection&&)      = default;
        ~Collection()                            = default;
    };

    struct Account
    {
        using allocator_type = Allocator;

        String generation;
        std::pmr::unordered_map<String, Collection> collections;

        explicit Account(const allocator_type& allocator)
            : generation(allocator)
            , collections(allocator)
        {
        }
        Account(const Account& other, const allocator_type& allocator)
            : generation(other.generation, allocator)
            , collections(other.collections, allocator)
        {
        }
        Account(Account&& other, const allocator_type& allocator)
            : generation(std::move(other.generation), allocator)
            , collections(std::move(other.collections), allocator)
        {
        }
        Account(const Account&)            = default;
        Account(Account&&)                 = default;
        Account& operator=(const Account&) = default;
        Account& operator=(Account&&)      = default;
        ~Account()                         = default;
    };

    // The account's entry, with a first generation when it is new; under the lock.
    [[nodiscard]] Result<Account*> account(std::string_view user);
    [[nodiscard]] Result<String> fresh_generation();
    // Drops the deletions kept longer than the retention, noting up to which revision.
    void purge(Collection& collection, std::int64_t now) const;

    Allocator allocator_;
    RandomSource* random_;
    std::uint32_t limit_;
    std::int64_t retention_;
    std::mutex mutex_;
    std::pmr::unordered_map<String, Account> accounts_;
};

} // namespace lantern
