#include <lantern/accounts.hpp>

#include <algorithm>
#include <cstddef>

#include <lantern/hkdf.hpp>

namespace lantern
{

namespace
{

constexpr std::string_view hex_digits = "0123456789abcdef";

void wipe(String& secret) noexcept
{
    secure_wipe(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(secret.data()), secret.size()));
}

} // namespace

bool is_known_scope(std::string_view scope) noexcept
{
    return std::ranges::any_of(known_scopes, [&](std::string_view known) { return known == scope; });
}

Vector<String> ordered_scopes(std::span<const std::string_view> scopes, const Allocator& allocator)
{
    Vector<String> out(allocator);
    for (const std::string_view known : known_scopes)
    {
        if (std::ranges::any_of(scopes, [&](std::string_view item) { return item == known; }))
            out.emplace_back(known);
    }
    return out;
}

String typed_code(std::string_view text, const Allocator& allocator)
{
    String out(allocator);
    for (const char c : text)
    {
        if (c == ' ' || c == '\t' || c == '-')
            continue;
        out.push_back((c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c);
    }
    return out;
}

bool is_account_name(std::string_view name) noexcept
{
    return !name.empty() && name.size() <= 64
        && std::ranges::all_of(name,
            [](char c)
            {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.'
                    || c == '_' || c == '-';
            });
}

bool constant_time_equal(std::string_view a, std::string_view b) noexcept
{
    if (a.size() != b.size())
        return false;
    std::uint8_t difference = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        difference = static_cast<std::uint8_t>(
            difference | (static_cast<std::uint8_t>(a[i]) ^ static_cast<std::uint8_t>(b[i])));
    return difference == 0;
}

PendingPairing::~PendingPairing()
{
    wipe(token);
}

PairingPoll::~PairingPoll()
{
    wipe(token);
}

MemoryAccountStore::MemoryAccountStore(const Allocator& allocator, std::size_t max_pairings)
    : allocator_(allocator)
    , max_pairings_(max_pairings)
    , accounts_(allocator)
    , devices_(allocator)
    , pairings_(allocator)
{
}

Result<void> MemoryAccountStore::add_account(
    std::string_view name, std::span<const std::string_view> scopes, bool frozen)
{
    if (!is_account_name(name))
        return fail(Category::usage, "an account's name is 1 to 64 letters, digits, '.', '_' and '-'");
    if (!std::ranges::all_of(scopes, [](std::string_view scope) { return is_known_scope(scope); }))
        return fail(Category::usage, "a scope the specification does not define (SPEC.md 4.2)");
    const std::scoped_lock lock(mutex_);
    if (std::ranges::any_of(accounts_, [&](const StoredAccount& item) { return item.name == name; }))
        return fail(Category::usage, "an account of that name exists");
    StoredAccount account(allocator_);
    account.name.assign(name);
    account.scopes = ordered_scopes(scopes, allocator_);
    account.frozen = frozen;
    accounts_.push_back(std::move(account));
    return {};
}

Result<bool> MemoryAccountStore::set_frozen(std::string_view name, bool frozen)
{
    const std::scoped_lock lock(mutex_);
    const auto found
        = std::ranges::find_if(accounts_, [&](const StoredAccount& item) { return item.name == name; });
    if (found == accounts_.end())
        return false;
    found->frozen = frozen;
    return true;
}

Result<bool> MemoryAccountStore::set_scopes(std::string_view name, std::span<const std::string_view> scopes)
{
    if (!std::ranges::all_of(scopes, [](std::string_view scope) { return is_known_scope(scope); }))
        return fail(Category::usage, "a scope the specification does not define (SPEC.md 4.2)");
    const std::scoped_lock lock(mutex_);
    const auto found
        = std::ranges::find_if(accounts_, [&](const StoredAccount& item) { return item.name == name; });
    if (found == accounts_.end())
        return false;
    found->scopes = ordered_scopes(scopes, allocator_);
    return true;
}

Result<PairedDevice> MemoryAccountStore::add_token(std::string_view token, std::string_view user,
    std::string_view name, std::span<const std::string_view> scopes, const std::optional<PublicKey>& key,
    std::int64_t created, std::optional<std::int64_t> expires)
{
    if (token.empty())
        return fail(Category::usage, "a token is not empty");
    const Digest hash = Sha256::of(token);
    PairedDevice device(allocator_);
    device.id = "d_";
    for (std::size_t i = 0; i < 8; ++i)
    {
        device.id.push_back(hex_digits[hash[i] >> 4U]);
        device.id.push_back(hex_digits[hash[i] & 0x0FU]);
    }
    device.user.assign(user);
    device.name.assign(name);
    device.scopes  = ordered_scopes(scopes, allocator_);
    device.key     = key;
    device.created = created;
    device.expires = expires;
    if (auto added = add_device(device, hash); !added)
        return std::unexpected(added.error());
    return device;
}

Result<bool> MemoryAccountStore::delete_account(std::string_view name)
{
    const std::scoped_lock lock(mutex_);
    const auto found
        = std::ranges::find_if(accounts_, [&](const StoredAccount& item) { return item.name == name; });
    if (found == accounts_.end())
        return false;
    accounts_.erase(found);
    std::erase_if(devices_, [&](const StoredDevice& item) { return item.device.user == name; });
    std::erase_if(pairings_, [&](const PendingPairing& item) { return item.user == name; });
    return true;
}

Result<std::optional<StoredAccount>> MemoryAccountStore::account(
    std::string_view name, const Allocator& allocator)
{
    const std::scoped_lock lock(mutex_);
    const auto found
        = std::ranges::find_if(accounts_, [&](const StoredAccount& item) { return item.name == name; });
    if (found == accounts_.end())
        return std::optional<StoredAccount> {};
    return std::optional<StoredAccount>(std::in_place, *found, allocator);
}

Result<std::optional<PairedDevice>> MemoryAccountStore::device_of(
    const Digest& token_hash, std::int64_t now, const Allocator& allocator)
{
    const std::scoped_lock lock(mutex_);
    const StoredDevice* found = nullptr;
    // Every hash is compared, so that the time taken does not say where a match is
    for (const StoredDevice& item : devices_)
    {
        if (same_digest(item.token_hash, token_hash))
            found = &item;
    }
    if (found == nullptr || (found->device.expires && *found->device.expires <= now))
        return std::optional<PairedDevice> {};
    return std::optional<PairedDevice>(std::in_place, found->device, allocator);
}

Result<void> MemoryAccountStore::add_device(const PairedDevice& device, const Digest& token_hash)
{
    const std::scoped_lock lock(mutex_);
    StoredDevice stored { PairedDevice(device, allocator_), token_hash };
    devices_.push_back(std::move(stored));
    return {};
}

Result<Vector<PairedDevice>> MemoryAccountStore::devices(
    std::string_view user, std::int64_t now, const Allocator& allocator)
{
    Vector<PairedDevice> out(allocator);
    const std::scoped_lock lock(mutex_);
    for (const StoredDevice& item : devices_)
    {
        if (item.device.user == user && (!item.device.expires || *item.device.expires > now))
            out.emplace_back(item.device);
    }
    std::ranges::stable_sort(
        out, [](const PairedDevice& a, const PairedDevice& b) { return a.created < b.created; });
    return out;
}

Result<bool> MemoryAccountStore::revoke_device(std::string_view id)
{
    const std::scoped_lock lock(mutex_);
    return std::erase_if(devices_, [&](const StoredDevice& item) { return item.device.id == id; }) != 0;
}

void MemoryAccountStore::purge(std::int64_t now)
{
    std::erase_if(pairings_, [&](const PendingPairing& item) { return item.expires <= now; });
}

PendingPairing* MemoryAccountStore::find_poll(std::string_view poll)
{
    PendingPairing* found = nullptr;
    for (PendingPairing& item : pairings_)
    {
        if (constant_time_equal(item.poll, poll))
            found = &item;
    }
    return found;
}

Result<PairingAdded> MemoryAccountStore::add_pairing(const PendingPairing& entry, std::int64_t now)
{
    const std::scoped_lock lock(mutex_);
    purge(now);
    if (pairings_.size() >= max_pairings_)
        return PairingAdded::full;
    const String code = typed_code(entry.code, allocator_);
    if (std::ranges::any_of(
            pairings_, [&](const PendingPairing& item) { return typed_code(item.code, allocator_) == code; }))
        return PairingAdded::code_taken;
    pairings_.emplace_back(entry);
    return PairingAdded::added;
}

Result<std::optional<PendingPairing>> MemoryAccountStore::pairing(
    std::string_view poll, std::int64_t now, const Allocator& allocator)
{
    const std::scoped_lock lock(mutex_);
    purge(now);
    const PendingPairing* found = find_poll(poll);
    if (found == nullptr)
        return std::optional<PendingPairing> {};
    return std::optional<PendingPairing>(std::in_place, *found, allocator);
}

Result<std::optional<PendingPairing>> MemoryAccountStore::pairing_by_code(
    std::string_view code, std::int64_t now, const Allocator& allocator)
{
    const String typed = typed_code(code, allocator_);
    const std::scoped_lock lock(mutex_);
    purge(now);
    const PendingPairing* found = nullptr;
    for (const PendingPairing& item : pairings_)
    {
        if (item.state == PendingPairing::State::waiting
            && constant_time_equal(typed_code(item.code, allocator_), typed))
            found = &item;
    }
    if (found == nullptr)
        return std::optional<PendingPairing> {};
    return std::optional<PendingPairing>(std::in_place, *found, allocator);
}

Result<bool> MemoryAccountStore::approve_pairing(std::string_view poll, std::string_view user,
    std::span<const std::string_view> granted, std::string_view token,
    std::optional<std::int64_t> token_lifetime, std::int64_t now)
{
    const std::scoped_lock lock(mutex_);
    purge(now);
    PendingPairing* found = find_poll(poll);
    if (found == nullptr || found->state != PendingPairing::State::waiting)
        return false;
    found->state = PendingPairing::State::approved;
    found->user.assign(user);
    found->granted = ordered_scopes(granted, allocator_);
    found->token.assign(token);
    found->token_lifetime = token_lifetime;
    return true;
}

Result<bool> MemoryAccountStore::refuse_pairing(std::string_view poll, std::int64_t now)
{
    const std::scoped_lock lock(mutex_);
    purge(now);
    PendingPairing* found = find_poll(poll);
    if (found == nullptr || found->state != PendingPairing::State::waiting)
        return false;
    found->state = PendingPairing::State::refused;
    return true;
}

Result<PairingPoll> MemoryAccountStore::poll_pairing(
    std::string_view poll, std::int64_t now, const Allocator& allocator)
{
    PairingPoll out(allocator);
    const std::scoped_lock lock(mutex_);
    purge(now);
    PendingPairing* found = find_poll(poll);
    if (found == nullptr)
        return out;
    // The interval counts from the last poll answered, never from one refused (L-5.2-15)
    if (found->polled && now - *found->polled < static_cast<std::int64_t>(found->interval))
    {
        out.kind        = PairingPoll::Kind::too_soon;
        out.retry_after = *found->polled + static_cast<std::int64_t>(found->interval) - now;
        return out;
    }
    found->polled = now;
    if (found->state == PendingPairing::State::refused)
    {
        out.kind = PairingPoll::Kind::refused;
        pairings_.erase(pairings_.begin() + (found - pairings_.data()));
        return out;
    }
    if (found->state == PendingPairing::State::waiting)
    {
        out.kind = PairingPoll::Kind::waiting;
        return out;
    }
    out.kind           = PairingPoll::Kind::approved;
    out.token          = std::move(found->token);
    out.scopes         = Vector<String>(found->granted, allocator);
    out.bound          = found->key.has_value();
    out.token_lifetime = found->token_lifetime;
    pairings_.erase(pairings_.begin() + (found - pairings_.data()));
    return out;
}

Result<void> MemoryAccountStore::forget_user(std::string_view user)
{
    const std::scoped_lock lock(mutex_);
    std::erase_if(pairings_, [&](const PendingPairing& item) { return item.user == user; });
    return {};
}

} // namespace lantern
