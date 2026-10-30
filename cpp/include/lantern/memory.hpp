// Memory: every allocation of the library goes through a
// std::pmr::memory_resource the app chooses, and every decode stays within a
// budget the app sets.
//
// Why std::pmr: it is in every standard library Aurore's toolchains ship
// (libstdc++ of devkitA64, devkitARM and VitaSDK; libc++ of the NDK, Xcode,
// Emscripten and the PS4's LLVM; MSVC's STL), it needs neither exceptions
// nor RTTI, and it keeps allocators out of the types' signatures: a
// Vector<App> is the same type whatever the app gives. A console app passes
// a std::pmr::monotonic_buffer_resource over a static buffer, or its own
// resource; a desktop app passes nothing and gets the default one.
//
// Why a budget besides the resource: a resource cannot fail without an
// exception, so the library counts what it asks for before it asks, and
// stops with Category::memory when the budget is spent. Every allocation of
// a decode is charged once, regrowth included, so a monotonic resource of
// `budget` bytes (plus its alignment) never runs out first.
#pragma once

#include <cstddef>
#include <memory_resource>
#include <string>
#include <vector>

namespace lantern
{

using Allocator                 = std::pmr::polymorphic_allocator<>;
using String                    = std::pmr::string;
template <class T> using Vector = std::pmr::vector<T>;

// What one decode may allocate, at most.
class Budget
{
  public:
    explicit Budget(std::size_t limit) noexcept
        : limit_(limit)
    {
    }

    // Charges `bytes`; false, and nothing charged, when it would go over.
    [[nodiscard]] bool charge(std::size_t bytes) noexcept;
    [[nodiscard]] std::size_t used() const noexcept { return used_; }
    [[nodiscard]] std::size_t limit() const noexcept { return limit_; }

  private:
    std::size_t limit_;
    std::size_t used_ = 0;
};

// A resource that counts what goes through it, for an app that wants to
// see its peak, and for the tests that check the budget holds.
class CountingResource final : public std::pmr::memory_resource
{
  public:
    explicit CountingResource(std::pmr::memory_resource* upstream = std::pmr::get_default_resource()) noexcept
        : upstream_(upstream)
    {
    }

    [[nodiscard]] std::size_t current() const noexcept { return current_; }
    [[nodiscard]] std::size_t peak() const noexcept { return peak_; }
    [[nodiscard]] std::size_t allocations() const noexcept { return allocations_; }

  private:
    void* do_allocate(std::size_t bytes, std::size_t alignment) override;
    void do_deallocate(void* pointer, std::size_t bytes, std::size_t alignment) override;
    [[nodiscard]] bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override
    {
        return this == &other;
    }

    std::pmr::memory_resource* upstream_;
    std::size_t current_     = 0;
    std::size_t peak_        = 0;
    std::size_t allocations_ = 0;
};

// Blocks taken from a resource and given back all at once: a parsed
// document's nodes and strings live in one.
class Arena
{
  public:
    explicit Arena(std::pmr::memory_resource* upstream) noexcept
        : upstream_(upstream)
    {
    }
    Arena(const Arena&)            = delete;
    Arena& operator=(const Arena&) = delete;
    Arena(Arena&& other) noexcept;
    Arena& operator=(Arena&& other) noexcept;
    ~Arena();

    // `bytes` aligned on `alignment`; never null (the resource's own failure
    // ends the program, as a pmr container's would).
    [[nodiscard]] void* allocate(std::size_t bytes, std::size_t alignment);
    [[nodiscard]] std::pmr::memory_resource* upstream() const noexcept { return upstream_; }

  private:
    struct Block
    {
        Block* next;
        std::size_t size;
    };
    void release() noexcept;

    std::pmr::memory_resource* upstream_;
    Block* blocks_     = nullptr;
    std::byte* cursor_ = nullptr;
    std::size_t left_  = 0;
};

} // namespace lantern
