// What a server keeps of its accounts, tokens and pairings (SPEC.md § 5.1,
// § 5.2, § 5.4): the interface the server core asks, and a complete store
// held in memory for tests, demos and as a reference to read.
//
// What is kept follows § 5: a token's SHA-256 only (never the token), the
// device's public key when it paired with one, the scopes approved (never
// more than the account's, which the server checks again at every request),
// and the pairings that wait for their user, with the secret address of
// their poll. Every method is called per request, from as many threads as
// the app's HTTP server uses: a store must be safe for that, and each of
// its methods atomic.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

#include <lantern/ed25519.hpp>
#include <lantern/error.hpp>
#include <lantern/memory.hpp>
#include <lantern/sha256.hpp>

namespace lantern
{

// The scopes of § 4.2, in the order the handshake and the stores list them.
inline constexpr std::array<std::string_view, 8> known_scopes { "library", "saves", "cheats", "cheats.write",
    "requests", "admin", "sync.read", "sync.write" };

[[nodiscard]] bool is_known_scope(std::string_view scope) noexcept;
// The known scopes among `scopes`, in their order, each once.
[[nodiscard]] Vector<String> ordered_scopes(
    std::span<const std::string_view> scopes, const Allocator& allocator);
// A pairing code as a user types it (§ 5.2, L-5.2-14), without case, spaces
// or dashes: `kq4m 7txd` is `KQ4M7TXD`.
[[nodiscard]] String typed_code(std::string_view text, const Allocator& allocator);
// An account's name (§ 5.7): 1 to 64 letters, digits, '.', '_' and '-'.
[[nodiscard]] bool is_account_name(std::string_view name) noexcept;
// Two secrets compared without stopping at the first difference. The
// lengths are not secret.
[[nodiscard]] bool constant_time_equal(std::string_view a, std::string_view b) noexcept;

// An account (§ 5.7): its name, its scopes, and whether it may do nothing.
// Signing in belongs to the app: an account has no password here.
struct StoredAccount
{
    using allocator_type = Allocator;

    String name;
    Vector<String> scopes;
    bool frozen = false;

    StoredAccount()
        : StoredAccount(allocator_type {})
    {
    }
    explicit StoredAccount(const allocator_type& allocator)
        : name(allocator)
        , scopes(allocator)
    {
    }
    StoredAccount(const StoredAccount& other, const allocator_type& allocator)
        : name(other.name, allocator)
        , scopes(other.scopes, allocator)
        , frozen(other.frozen)
    {
    }
    StoredAccount(StoredAccount&& other, const allocator_type& allocator)
        : name(std::move(other.name), allocator)
        , scopes(std::move(other.scopes), allocator)
        , frozen(other.frozen)
    {
    }
    StoredAccount(const StoredAccount&)            = default;
    StoredAccount(StoredAccount&&)                 = default;
    StoredAccount& operator=(const StoredAccount&) = default;
    StoredAccount& operator=(StoredAccount&&)      = default;
    ~StoredAccount()                               = default;
};

// A paired device and its token (§ 5.1), as kept: the token itself is not.
struct PairedDevice
{
    using allocator_type = Allocator;

    String id; // `d_` and 16 hex digits
    String user; // the account's name
    String name; // what the user calls the device
    Vector<String> scopes;
    std::optional<PublicKey> key; // the token is bound to it (§ 5.4)
    std::int64_t created = 0; // Unix seconds
    std::optional<std::int64_t> expires; // Unix seconds; none: until revoked

    PairedDevice()
        : PairedDevice(allocator_type {})
    {
    }
    explicit PairedDevice(const allocator_type& allocator)
        : id(allocator)
        , user(allocator)
        , name(allocator)
        , scopes(allocator)
    {
    }
    PairedDevice(const PairedDevice& other, const allocator_type& allocator)
        : id(other.id, allocator)
        , user(other.user, allocator)
        , name(other.name, allocator)
        , scopes(other.scopes, allocator)
        , key(other.key)
        , created(other.created)
        , expires(other.expires)
    {
    }
    PairedDevice(PairedDevice&& other, const allocator_type& allocator)
        : id(std::move(other.id), allocator)
        , user(std::move(other.user), allocator)
        , name(std::move(other.name), allocator)
        , scopes(std::move(other.scopes), allocator)
        , key(other.key)
        , created(other.created)
        , expires(other.expires)
    {
    }
    PairedDevice(const PairedDevice&)            = default;
    PairedDevice(PairedDevice&&)                 = default;
    PairedDevice& operator=(const PairedDevice&) = default;
    PairedDevice& operator=(PairedDevice&&)      = default;
    ~PairedDevice()                              = default;
};

// A pairing waiting for its user, or decided and not yet collected (§ 5.2).
struct PendingPairing
{
    using allocator_type = Allocator;

    enum class State : std::uint8_t
    {
        waiting,
        approved,
        refused,
    };

    String poll; // the secret address's last part: whoever has it collects the token
    String id; // names the pairing for an administrator; not a secret
    String code; // "KQ4M-7TXD"
    String device;
    Vector<String> scopes; // the ones asked for, known ones only
    std::optional<PublicKey> key;
    std::int64_t created   = 0; // Unix seconds
    std::int64_t expires   = 0; // Unix seconds: the code is good until then
    std::uint32_t interval = 5; // seconds between two polls
    State state            = State::waiting;
    // Once approved: the account, the scopes granted and the token, which
    // only waits here for its one collection (at most the code's lifetime).
    String user;
    Vector<String> granted;
    String token;
    std::optional<std::int64_t> token_lifetime; // seconds
    // Unix seconds of the last poll answered 202 or 200 (L-5.2-15).
    std::optional<std::int64_t> polled;

    PendingPairing()
        : PendingPairing(allocator_type {})
    {
    }
    explicit PendingPairing(const allocator_type& allocator)
        : poll(allocator)
        , id(allocator)
        , code(allocator)
        , device(allocator)
        , scopes(allocator)
        , user(allocator)
        , granted(allocator)
        , token(allocator)
    {
    }
    PendingPairing(const PendingPairing& other, const allocator_type& allocator)
        : poll(other.poll, allocator)
        , id(other.id, allocator)
        , code(other.code, allocator)
        , device(other.device, allocator)
        , scopes(other.scopes, allocator)
        , key(other.key)
        , created(other.created)
        , expires(other.expires)
        , interval(other.interval)
        , state(other.state)
        , user(other.user, allocator)
        , granted(other.granted, allocator)
        , token(other.token, allocator)
        , token_lifetime(other.token_lifetime)
        , polled(other.polled)
    {
    }
    PendingPairing(PendingPairing&& other, const allocator_type& allocator)
        : poll(std::move(other.poll), allocator)
        , id(std::move(other.id), allocator)
        , code(std::move(other.code), allocator)
        , device(std::move(other.device), allocator)
        , scopes(std::move(other.scopes), allocator)
        , key(other.key)
        , created(other.created)
        , expires(other.expires)
        , interval(other.interval)
        , state(other.state)
        , user(std::move(other.user), allocator)
        , granted(std::move(other.granted), allocator)
        , token(std::move(other.token), allocator)
        , token_lifetime(other.token_lifetime)
        , polled(other.polled)
    {
    }
    PendingPairing(const PendingPairing&)            = default;
    PendingPairing(PendingPairing&&)                 = default;
    PendingPairing& operator=(const PendingPairing&) = default;
    PendingPairing& operator=(PendingPairing&&)      = default;
    // Wipes the token it may hold.
    ~PendingPairing();
};

// What a poll of a pairing finds (§ 5.2).
struct PairingPoll
{
    using allocator_type = Allocator;

    enum class Kind : std::uint8_t
    {
        unknown, // refused, expired, already collected or never given: 410
        refused, // the user said no (the pairing is forgotten): 410
        too_soon, // polled before `interval` passed since the last answered poll: 429
        waiting, // 202
        approved, // 200, once: the pairing is forgotten
    };

    Kind kind                = Kind::unknown;
    std::int64_t retry_after = 0; // too_soon: seconds until the poll is answered
    String token;
    Vector<String> scopes;
    bool bound = false;
    std::optional<std::int64_t> token_lifetime;

    PairingPoll()
        : PairingPoll(allocator_type {})
    {
    }
    explicit PairingPoll(const allocator_type& allocator)
        : token(allocator)
        , scopes(allocator)
    {
    }
    PairingPoll(const PairingPoll&)            = default;
    PairingPoll(PairingPoll&&)                 = default;
    PairingPoll& operator=(const PairingPoll&) = default;
    PairingPoll& operator=(PairingPoll&&)      = default;
    // Wipes the token.
    ~PairingPoll();
};

// How add_pairing() answered.
enum class PairingAdded : std::uint8_t
{
    added,
    full, // too many are waiting: the server answers 429
    code_taken, // another waiting pairing has this code (typed alike): the server draws another
};

// Where a server keeps its accounts, devices and pairings. A method that
// fails (Category::storage) makes the request a 500.
class AccountStore
{
  public:
    AccountStore()                               = default;
    AccountStore(const AccountStore&)            = default;
    AccountStore(AccountStore&&)                 = default;
    AccountStore& operator=(const AccountStore&) = default;
    AccountStore& operator=(AccountStore&&)      = default;
    virtual ~AccountStore()                      = default;

    // The account of that name, if there is one.
    [[nodiscard]] virtual Result<std::optional<StoredAccount>> account(
        std::string_view name, const Allocator& allocator)
        = 0;

    // The device whose token has this SHA-256, unless it is unknown, revoked
    // or expired at `now` (Unix seconds). The server hashes the token it is
    // sent; the store never sees one.
    [[nodiscard]] virtual Result<std::optional<PairedDevice>> device_of(
        const Digest& token_hash, std::int64_t now, const Allocator& allocator)
        = 0;
    // Keeps a device and the SHA-256 of its token.
    [[nodiscard]] virtual Result<void> add_device(const PairedDevice& device, const Digest& token_hash) = 0;
    // The live devices of an account, oldest first.
    [[nodiscard]] virtual Result<Vector<PairedDevice>> devices(
        std::string_view user, std::int64_t now, const Allocator& allocator)
        = 0;
    // Revokes a device's token at once (§ 5.1); false when there is none.
    [[nodiscard]] virtual Result<bool> revoke_device(std::string_view id) = 0;

    // Keeps a pairing that waits. The store also forgets those past `expires`.
    [[nodiscard]] virtual Result<PairingAdded> add_pairing(const PendingPairing& entry, std::int64_t now) = 0;
    // The pairing at this poll address (a secret: compare it in constant time).
    [[nodiscard]] virtual Result<std::optional<PendingPairing>> pairing(
        std::string_view poll, std::int64_t now, const Allocator& allocator)
        = 0;
    // The pairing waiting with this code, as the user typed it.
    [[nodiscard]] virtual Result<std::optional<PendingPairing>> pairing_by_code(
        std::string_view code, std::int64_t now, const Allocator& allocator)
        = 0;
    // Marks the pairing at `poll` approved: the account, the scopes granted
    // and the token to give once. False when it is no longer waiting.
    [[nodiscard]] virtual Result<bool> approve_pairing(std::string_view poll, std::string_view user,
        std::span<const std::string_view> granted, std::string_view token,
        std::optional<std::int64_t> token_lifetime, std::int64_t now)
        = 0;
    // Marks the pairing at `poll` refused. False when it is no longer waiting.
    [[nodiscard]] virtual Result<bool> refuse_pairing(std::string_view poll, std::int64_t now) = 0;
    // A poll (§ 5.2): counts `interval` from the last poll it answered,
    // never from one it refused (L-5.2-15), and gives the token once.
    [[nodiscard]] virtual Result<PairingPoll> poll_pairing(
        std::string_view poll, std::int64_t now, const Allocator& allocator)
        = 0;
    // Forgets the pairings approved for an account that was deleted, before they were collected.
    [[nodiscard]] virtual Result<void> forget_user(std::string_view user) = 0;
};

// Accounts, devices and pairings held in memory, behind a mutex. The
// accounts are the app's to set up (add_account, add_token); the server
// adds the devices and the pairings. Tokens are looked up by their hash
// with a comparison that does not stop at the first differing byte.
class MemoryAccountStore final : public AccountStore
{
  public:
    explicit MemoryAccountStore(const Allocator& allocator = {}, std::size_t max_pairings = 1000);

    // A new account; Category::usage for a name that is not § 5.7's, for a
    // scope that is not § 4.2's, and for a name already taken.
    [[nodiscard]] Result<void> add_account(
        std::string_view name, std::span<const std::string_view> scopes, bool frozen = false);
    // false: no such account.
    [[nodiscard]] Result<bool> set_frozen(std::string_view name, bool frozen);
    // Replaces the account's scopes; the scopes of its devices are cut back at every request.
    [[nodiscard]] Result<bool> set_scopes(std::string_view name, std::span<const std::string_view> scopes);
    // A token this store did not issue (a demo's, or one moved from another
    // store): kept as its hash. The device's id comes from the hash.
    [[nodiscard]] Result<PairedDevice> add_token(std::string_view token, std::string_view user,
        std::string_view name, std::span<const std::string_view> scopes,
        const std::optional<PublicKey>& key = std::nullopt, std::int64_t created = 0,
        std::optional<std::int64_t> expires = std::nullopt);
    // Forgets an account, its devices and its pairings at once (§ 5.7).
    [[nodiscard]] Result<bool> delete_account(std::string_view name);

    [[nodiscard]] Result<std::optional<StoredAccount>> account(
        std::string_view name, const Allocator& allocator) override;
    [[nodiscard]] Result<std::optional<PairedDevice>> device_of(
        const Digest& token_hash, std::int64_t now, const Allocator& allocator) override;
    [[nodiscard]] Result<void> add_device(const PairedDevice& device, const Digest& token_hash) override;
    [[nodiscard]] Result<Vector<PairedDevice>> devices(
        std::string_view user, std::int64_t now, const Allocator& allocator) override;
    [[nodiscard]] Result<bool> revoke_device(std::string_view id) override;
    [[nodiscard]] Result<PairingAdded> add_pairing(const PendingPairing& entry, std::int64_t now) override;
    [[nodiscard]] Result<std::optional<PendingPairing>> pairing(
        std::string_view poll, std::int64_t now, const Allocator& allocator) override;
    [[nodiscard]] Result<std::optional<PendingPairing>> pairing_by_code(
        std::string_view code, std::int64_t now, const Allocator& allocator) override;
    [[nodiscard]] Result<bool> approve_pairing(std::string_view poll, std::string_view user,
        std::span<const std::string_view> granted, std::string_view token,
        std::optional<std::int64_t> token_lifetime, std::int64_t now) override;
    [[nodiscard]] Result<bool> refuse_pairing(std::string_view poll, std::int64_t now) override;
    [[nodiscard]] Result<PairingPoll> poll_pairing(
        std::string_view poll, std::int64_t now, const Allocator& allocator) override;
    [[nodiscard]] Result<void> forget_user(std::string_view user) override;

  private:
    struct StoredDevice
    {
        PairedDevice device;
        Digest token_hash {};
    };

    void purge(std::int64_t now);
    PendingPairing* find_poll(std::string_view poll);

    Allocator allocator_;
    std::size_t max_pairings_;
    std::mutex mutex_;
    Vector<StoredAccount> accounts_;
    Vector<StoredDevice> devices_;
    Vector<PendingPairing> pairings_;
};

} // namespace lantern
