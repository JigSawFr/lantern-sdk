// Sync (SPEC.md § 20): a user's wishes, and what each of their consoles has
// installed, kept by their server, read and written with the scopes
// sync.read and sync.write, and only with the user's consent (§ 20.1).
//
// The client (client.hpp) reads and writes nothing of <base>/v1/sync before
// the app sets a SyncConsent (L-20.1-1), and sends `installed` only with a
// consent given for it by name (L-20.1-2). It keeps the account's
// `generation`: one that changed means the user deleted their data, and the
// client then turns sync off rather than write its items back (L-20.3-2).
//
// The merge rule of § 20.4 is here too, the same on every server and in
// every client that keeps a copy: the later `updated` wins; on the same
// one, a deletion; between two values, the greater canonical JSON.
#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

#include <lantern/document.hpp>
#include <lantern/error.hpp>
#include <lantern/json.hpp>
#include <lantern/memory.hpp>
#include <lantern/types.hpp>

namespace lantern
{

// What the user agreed to, per console profile and per server (§ 20.1).
// The app asks, keeps the answer (with the generation the client reports),
// and gives it back to the client at start.
struct SyncConsent
{
    // Sync on: wishes, and reading the collections.
    bool sync = false;
    // What this console has installed may leave it: asked by name.
    bool installed = false;
};

inline constexpr std::string_view sync_wishes    = "wishes";
inline constexpr std::string_view sync_installed = "installed";

// A collection's name (§ 20.2): 1 to 32 of a-z, 0-9 and _, a letter first.
[[nodiscard]] bool is_sync_collection(std::string_view name) noexcept;

// A sync time (§ 20.2), "2026-10-30T09:12:03.250Z" or without its
// milliseconds, as milliseconds since the Unix epoch; nothing for another
// form or a date that does not exist.
[[nodiscard]] std::optional<std::int64_t> parse_sync_time(std::string_view text) noexcept;
// Written to the millisecond, as § 20.2 writes it.
void format_sync_time(std::int64_t milliseconds, String& out);

// The canonical JSON of § 20.4: keys sorted (by their UTF-8 bytes), no
// space, characters other than ASCII as they are; numbers as written.
[[nodiscard]] Result<String> canonical_json(
    std::string_view json, Allocator allocator = {}, const json::Limits& limits = {});

// What the merge decides of an item sent against the one kept.
struct SyncMerge
{
    // The item sent is the one kept (it takes the collection's next rev).
    bool replaced = false;
    // Its `updated`, as kept: one more than `skew` seconds ahead of the
    // server's clock is the server's time (L-20.4-2).
    std::int64_t updated = 0;
};

// § 20.4's rule, item by item: `have` the item kept (null: none), `sent` the
// item sent, `now` the server's time in milliseconds, `skew` its
// auth.skew in seconds. An error for an item whose `updated` is not a
// sync time, or whose value is not JSON.
[[nodiscard]] Result<SyncMerge> sync_merge(const SyncItem* have, const SyncItem& sent, std::int64_t now,
    std::int64_t skew, Allocator allocator = {});

// A wish's value, and a device's `installed` value, as JSON for an item.
void write_wish(const Wish& wish, String& out);
void write_installed(const Installed& installed, String& out);
// The same, read from an item's value; an error for a value not of the
// collection's form.
[[nodiscard]] Result<Wish> read_wish(std::string_view value, const DecodeOptions& options = {});
[[nodiscard]] Result<Installed> read_installed(std::string_view value, const DecodeOptions& options = {});
// A wish's key, "<platform>/<title_id>".
[[nodiscard]] Result<String> wish_key(
    std::string_view platform, std::string_view title_id, Allocator allocator = {});

} // namespace lantern
