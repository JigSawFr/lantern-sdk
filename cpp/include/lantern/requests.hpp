// What a server keeps of the requests for games (SPEC.md § 11): the interface
// the server core asks, and a complete store held in memory for tests, demos
// and as a reference to read.
//
// The server does the protocol's work: the platform and its title ids, a
// request per open title (the same title asked again gives the open one),
// withdrawing, the states of § 11's table (`done` and `declined` are final),
// the limit of open requests per account, and erasing an account's requests
// when it is deleted (§ 5.7). A store keeps documents, per account. Every
// method is atomic; the server makes a check and the change it leads to one
// step itself. Several threads call them.
#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <string_view>
#include <utility>

#include <lantern/error.hpp>
#include <lantern/memory.hpp>

namespace lantern
{

// A request, as kept: the account that made it beside what clients read.
struct StoredRequest
{
    using allocator_type = Allocator;

    String id; // `r_` and letters, digits, `_` and `-`
    String user;
    String platform;
    String title_id;
    String name; // the title's name, when the library knows it
    String status; // `open`, `done` or `declined`
    std::int64_t created = 0; // Unix seconds
    std::int64_t updated = 0; // when the status last changed
    String reason; // the admin's words, on a declined request

    StoredRequest()
        : StoredRequest(allocator_type {})
    {
    }
    explicit StoredRequest(const allocator_type& allocator)
        : id(allocator)
        , user(allocator)
        , platform(allocator)
        , title_id(allocator)
        , name(allocator)
        , status(allocator)
        , reason(allocator)
    {
    }
    StoredRequest(const StoredRequest& other, const allocator_type& allocator)
        : id(other.id, allocator)
        , user(other.user, allocator)
        , platform(other.platform, allocator)
        , title_id(other.title_id, allocator)
        , name(other.name, allocator)
        , status(other.status, allocator)
        , created(other.created)
        , updated(other.updated)
        , reason(other.reason, allocator)
    {
    }
    StoredRequest(StoredRequest&& other, const allocator_type& allocator)
        : id(std::move(other.id), allocator)
        , user(std::move(other.user), allocator)
        , platform(std::move(other.platform), allocator)
        , title_id(std::move(other.title_id), allocator)
        , name(std::move(other.name), allocator)
        , status(std::move(other.status), allocator)
        , created(other.created)
        , updated(other.updated)
        , reason(std::move(other.reason), allocator)
    {
    }
    StoredRequest(const StoredRequest&)            = default;
    StoredRequest(StoredRequest&&)                 = default;
    StoredRequest& operator=(const StoredRequest&) = default;
    StoredRequest& operator=(StoredRequest&&)      = default;
    ~StoredRequest()                               = default;
};

// Where a server keeps requests. A method that fails (Category::storage)
// makes the request a 500.
class RequestStore
{
  public:
    RequestStore()                               = default;
    RequestStore(const RequestStore&)            = default;
    RequestStore(RequestStore&&)                 = default;
    RequestStore& operator=(const RequestStore&) = default;
    RequestStore& operator=(RequestStore&&)      = default;
    virtual ~RequestStore()                      = default;

    // An account's requests, or everyone's when `user` is empty, in the order they were made.
    [[nodiscard]] virtual Result<Vector<StoredRequest>> requests(
        std::string_view user, const Allocator& allocator)
        = 0;
    // The request of that id, whoever made it.
    [[nodiscard]] virtual Result<std::optional<StoredRequest>> request(
        std::string_view id, const Allocator& allocator)
        = 0;
    [[nodiscard]] virtual Result<void> add(const StoredRequest& request) = 0;
    // Sets the status, the reason and the time of the request of that id; false when there is none.
    [[nodiscard]] virtual Result<bool> set_status(
        std::string_view id, std::string_view status, std::string_view reason, std::int64_t updated)
        = 0;
    // Removes the account's own request, as it was; nothing when the account has none of that id.
    [[nodiscard]] virtual Result<std::optional<StoredRequest>> remove(
        std::string_view user, std::string_view id, const Allocator& allocator)
        = 0;
    // Erases an account's requests (§ 5.7).
    [[nodiscard]] virtual Result<void> forget(std::string_view user) = 0;
};

// Requests held in memory, behind a mutex.
class MemoryRequestStore final : public RequestStore
{
  public:
    explicit MemoryRequestStore(const Allocator& allocator = {});

    [[nodiscard]] Result<Vector<StoredRequest>> requests(
        std::string_view user, const Allocator& allocator) override;
    [[nodiscard]] Result<std::optional<StoredRequest>> request(
        std::string_view id, const Allocator& allocator) override;
    [[nodiscard]] Result<void> add(const StoredRequest& request) override;
    [[nodiscard]] Result<bool> set_status(
        std::string_view id, std::string_view status, std::string_view reason, std::int64_t updated) override;
    [[nodiscard]] Result<std::optional<StoredRequest>> remove(
        std::string_view user, std::string_view id, const Allocator& allocator) override;
    [[nodiscard]] Result<void> forget(std::string_view user) override;

  private:
    Allocator allocator_;
    std::mutex mutex_;
    Vector<StoredRequest> kept_;
};

} // namespace lantern
