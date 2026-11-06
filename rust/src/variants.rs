//! Packages a device cannot use, and variants of one game (SPEC.md § 6.1,
//! Annex A.1 and B.15): whether a client installs an app, the update an
//! installed app already includes, which variant it prefers by default, and
//! the `requires` of a Switch `.nsp` stored with the firmware's compression layer.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::generated::models::App;
use crate::vocabulary::pattern;

/// At most this many tokens in an app's `requires` (§ 6.1).
pub const REQUIRES_MAX: usize = 8;
/// At most this many entries in an app's `includes` (§ 6.1).
pub const INCLUDES_MAX: usize = 16;
/// At most this many words in a missing request's `formats` or `satisfies` (§ 6.3).
pub const WORDS_MAX: usize = 16;
/// What a Switch `.nsp` stored with the firmware's compression layer takes (Annex A.1).
pub const SWITCH_LZ4_REQUIRES: &[&str] = &["fs-compression", "sigpatch"];

/// A package format (SPEC.md § 6.1): the words of `formats`, and of the listing's `format` filter.
pub static FORMAT_WORD: LazyLock<Regex> = LazyLock::new(|| pattern(r"^[a-z0-9]{1,16}$"));
/// A token of an app's `requires` (SPEC.md § 6.1), and of a request's `satisfies`.
pub static REQUIRES_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| pattern(r"^[a-z0-9][a-z0-9-]{0,31}$"));

/// Whether a client installs an app, and if not why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallDecision {
    /// The client installs it.
    Install,
    /// The client cannot: the reasons are those of the reference client.
    Unavailable(Vec<String>),
}

/// Whether an update that an installed app `includes`, at its version or
/// above, is `app` (L-6.1-5): only an app of type `update` is ever one.
#[must_use]
pub fn included(app: &App, installed: &[App]) -> bool {
    app.r#type == "update"
        && installed.iter().any(|other| {
            other
                .includes
                .iter()
                .flatten()
                .any(|i| i.app_id == app.app_id && i.version_code >= app.version_code)
        })
}

/// Whether a client installs `app` (SPEC.md § 6.1). `formats`: the package
/// formats the client knows; `satisfies`: the `requires` tokens it knows and
/// the device provides; `installed`: the apps the device has installed. A
/// format or a token the client does not know is refused as one it cannot
/// satisfy (L-6.1-3, L-6.1-4), and so is an update that an installed app
/// includes (L-6.1-5).
#[must_use]
pub fn install_decision(
    app: &App,
    formats: &[&str],
    satisfies: &[&str],
    installed: &[App],
) -> InstallDecision {
    let known: HashSet<&str> = formats.iter().copied().collect();
    let provided: HashSet<&str> = satisfies.iter().copied().collect();
    let mut reasons = Vec::new();
    if !known.contains(app.format.as_str()) {
        reasons.push(format!("format '{}'", app.format));
    }
    for token in app.requires.iter().flatten() {
        if !provided.contains(token.as_str()) {
            reasons.push(format!("requires '{token}'"));
        }
    }
    if included(app, installed) {
        reasons.push("already included by an installed app".to_owned());
    }
    if reasons.is_empty() {
        InstallDecision::Install
    } else {
        InstallDecision::Unavailable(reasons)
    }
}

/// The variant a client installs by default among apps that share an
/// `app_id` and a `version_code` (Annex B.15): the fewest `requires`, then the
/// smallest `size`, then the smaller `id`, so that two clients agree. `None`
/// for no variant.
#[must_use]
pub fn prefer_variant(variants: &[App]) -> Option<&App> {
    variants.iter().min_by(|a, b| {
        let key = |app: &App| (app.requires.as_ref().map_or(0, Vec::len), app.size);
        key(a).cmp(&key(b)).then_with(|| a.id.cmp(&b.id))
    })
}

/// The `requires` of a package a toolkit finds by its file name (Annex A.1):
/// a Switch `.nsp` whose name holds `[LZ4]` (any case) is stored with the
/// firmware's compression layer and takes fs-compression and sigpatch; `None`
/// for any other file.
#[must_use]
pub fn requires_of_name(platform: &str, file_name: &str) -> Option<Vec<String>> {
    let name = file_name
        .rsplit('/')
        .next()
        .unwrap_or(file_name)
        .to_ascii_lowercase();
    (platform == "switch"
        && std::path::Path::new(&name)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("nsp"))
        && name.contains("[lz4]"))
    .then(|| {
        SWITCH_LZ4_REQUIRES
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    })
}

/// `requires` without duplicates, in order (§ 6.1).
#[must_use]
pub fn unique_tokens(tokens: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    tokens
        .iter()
        .filter(|t| seen.insert(t.as_str()))
        .cloned()
        .collect()
}
