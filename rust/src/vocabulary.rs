//! The open vocabularies SPEC.md lists in its text rather than in its
//! schemas. A reader takes a value it does not know as the specification says
//! (an unknown kind is an app, an unknown `assets` is `user_owned`, an unknown
//! architecture is never its own); a later version may add values.

use std::sync::LazyLock;

use regex::Regex;

/// A homebrew's kinds (SPEC.md § 8.1).
pub const KINDS: &[&str] = &[
    "app",
    "game",
    "port",
    "emulator",
    "tool",
    "overlay",
    "sysmodule",
    "theme",
];
/// Where a port's assets come from (SPEC.md § 8.6).
pub const ASSETS: &[&str] = &["included", "demo_included", "free_external", "user_owned"];
/// The architectures a package may name (SPEC.md § 8.2).
pub const ARCH_NAMES: &[&str] = &["aarch64", "armhf", "x86", "x86_64", "riscv64"];
/// The families of the handshake's `features` (SPEC.md § 4.2).
pub const FAMILIES: &[&str] = &[
    "library",
    "titles",
    "changes",
    "sections",
    "homebrew",
    "saves",
    "cheats",
    "requests",
    "pairing",
    "signatures",
    "admin",
    "events",
    "peers",
    "sync",
    "encrypted_saves",
    "deltas",
];
/// The pairing alphabet (SPEC.md § 5.2), also a save key's (§ 9.4): 5 bits a
/// symbol, no 0, O, 1 or I.
pub const CODE_ALPHABET: &str = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

/// A pattern of the specification, compiled once.
pub(crate) fn pattern(source: &str) -> Regex {
    // The patterns are literals of this crate, checked by its tests.
    #[allow(clippy::expect_used)]
    Regex::new(source).expect("a pattern of the specification")
}

macro_rules! patterns {
    ($($(#[$doc:meta])* $name:ident = $source:expr;)*) => {
        $(
            $(#[$doc])*
            pub static $name: LazyLock<Regex> = LazyLock::new(|| pattern($source));
        )*
    };
}

patterns! {
    /// The form of an architecture's name, this version's or a later one's (SPEC.md § 8.2).
    ARCH = r"^[a-z0-9_]{1,32}$";
    /// A platform's name (SPEC.md § 4.3).
    PLATFORM = r"^[a-z0-9][a-z0-9-]{0,31}$";
    /// A title or an app id, the core's form (SPEC.md § 6.1).
    CORE_ID = r"^[A-Za-z0-9._-]{1,128}$";
    /// A lower-case word: a filter's kind or genre, an app's type (SPEC.md § 6.1, § 8.5).
    WORD = r"^[a-z][a-z0-9_]{0,31}$";
    /// A cheat set's build id, the core's form (SPEC.md § 10).
    BUILD_ID = r"^[A-Za-z0-9._-]{1,64}$";
    /// A SHA-256, lower-case hex.
    SHA256_HEX = r"^[0-9a-f]{64}$";
}

/// Whether `id` is a homebrew's id (SPEC.md § 8.1): 1 to 128 bytes, a
/// lower-case letter first, dot-separated parts (at least two).
#[must_use]
pub fn is_homebrew_id(id: &str) -> bool {
    static PARTS: LazyLock<Regex> =
        LazyLock::new(|| pattern(r"^[a-z][a-z0-9_-]*(?:\.[a-z0-9][a-z0-9_-]*)+$"));
    (1..=128).contains(&id.len()) && PARTS.is_match(id)
}

/// Whether `name` is a platform's name (SPEC.md § 4.3).
#[must_use]
pub fn is_platform(name: &str) -> bool {
    PLATFORM.is_match(name)
}

/// Whether `text` is a SHA-256 in lower-case hex.
#[must_use]
pub fn is_sha256_hex(text: &str) -> bool {
    SHA256_HEX.is_match(text)
}
