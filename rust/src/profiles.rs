//! Platform profiles (SPEC.md Annex A): what the core leaves open, per
//! platform. The Switch's is complete; the 3DS's, the Vita's, the PS4's,
//! Android's and Linux's are drafts (`draft` is true), still to be reviewed
//! by someone who knows the platform. The other platforms have no profile
//! yet: [`profile`] gives `None`, and a client installs nothing of them
//! (§ 4.3). The same tables as the other languages.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::error::{Error, Result};
use crate::vocabulary::{ARCH_NAMES, CORE_ID, pattern};

/// A homebrew format the platform's own installer installs: no path, an empty manifest (SPEC.md § 8.2).
pub const SYSTEM: &str = "system";
/// A homebrew format that is an archive with a manifest (SPEC.md § 8.2).
pub const ARCHIVE: &str = "archive";

/// Where a client writes a cheat set (Annex A): `path` with `{title_id}`, `{build_id}` and `{format}`.
#[derive(Debug, Clone)]
pub struct Cheats {
    /// The cheat format.
    pub format: &'static str,
    /// The path, with its placeholders.
    pub path: &'static str,
    /// The form of a build id, when the platform has one.
    pub build_id: Option<Regex>,
}

/// One platform's profile (Annex A).
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct Profile {
    /// The platform's name.
    pub platform: &'static str,
    /// Still to be reviewed by someone who knows the platform.
    pub draft: bool,
    /// A title id's form; `None` where the core's is all there is (Linux).
    pub title_id: Option<Regex>,
    /// An app's id, by its type (`""`: any type).
    pub app_ids: HashMap<&'static str, Regex>,
    /// The app types; `None` where the profile has no apps (Linux).
    pub types: Option<&'static [&'static str]>,
    /// The package formats; `None` where the profile has no apps (Linux).
    pub formats: Option<&'static [&'static str]>,
    /// A newer package of the same `app_id` replaces the base: it is the update (Android, SPEC.md § 6.3).
    pub newer_base_replaces: bool,
    /// Each homebrew format: a single file's path (`{id}`, `{file}`), [`ARCHIVE`] or [`SYSTEM`].
    pub homebrew_formats: HashMap<&'static str, &'static str>,
    /// The roots a homebrew writes to without asking (`{id}`: its id).
    pub free_roots: &'static [&'static str],
    /// The roots that need consent.
    pub consent_roots: &'static [&'static str],
    /// Where a port's `data_root` may lie; `None` where the user picks a folder (Android).
    pub data_areas: Option<&'static [&'static str]>,
    /// The architectures of `arch`; `None` on a platform of one architecture, where a package has none.
    pub arches: Option<&'static [&'static str]>,
    /// The platform's own keys of `requires.min` (SPEC.md § 8.7).
    pub requires_min: &'static [&'static str],
    /// The platform's own id of installed software (SPEC.md § 8.1).
    pub system_id: bool,
    /// The save kinds (SPEC.md § 9.1).
    pub save_kinds: &'static [&'static str],
    /// Where cheats go, when the platform has them.
    pub cheats: Option<Cheats>,
    /// Whether a client may install apps of it (Linux: homebrew only, Annex A.6).
    pub installs_apps: bool,
}

const BASE_TYPES: &[&str] = &["base", "update", "dlc"];

fn re(source: &'static str) -> Regex {
    pattern(source)
}

fn either(a: &str, b: &str) -> Regex {
    // Both are anchored patterns of this file; the alternation keeps each whole.
    pattern(&format!("(?:{a})|(?:{b})"))
}

const SWITCH_ID: &str = r"^[0-9A-F]{16}$";
const SWITCH_TITLE: &str = r"^[0-9A-F]{12}[02468ACE]000$";
const N3DS_TITLE: &str = r"^0004000[02][0-9A-F]{8}$";
const VITA_TITLE: &str = r"^[A-Z0-9]{9}$";
const VITA_CONTENT: &str = r"^[A-Z]{2}[0-9]{4}-[A-Z0-9]{9}_[0-9]{2}-[A-Z0-9]{16}$";
const PS4_TITLE: &str = r"^[A-Z]{4}[0-9]{5}$";
const PS4_CONTENT: &str = r"^[A-Z]{2}[0-9]{4}-[A-Z]{4}[0-9]{5}_[0-9]{2}-[A-Z0-9]{16}$";
const ANDROID_ID: &str = r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$";

fn base(platform: &'static str, draft: bool) -> Profile {
    Profile {
        platform,
        draft,
        title_id: None,
        app_ids: HashMap::new(),
        types: Some(BASE_TYPES),
        formats: None,
        newer_base_replaces: false,
        homebrew_formats: HashMap::new(),
        free_roots: &[],
        consent_roots: &[],
        data_areas: Some(&[]),
        arches: None,
        requires_min: &[],
        system_id: false,
        save_kinds: &[],
        cheats: None,
        installs_apps: true,
    }
}

fn switch() -> Profile {
    Profile {
        title_id: Some(re(SWITCH_TITLE)),
        app_ids: HashMap::from([
            ("", re(SWITCH_ID)),
            ("base", re(SWITCH_TITLE)),
            ("update", re(r"^[0-9A-F]{12}[02468ACE]800$")),
        ]),
        formats: Some(&["nsp", "nsz", "xci", "xcz"]),
        homebrew_formats: HashMap::from([
            ("nro", "/switch/{id}/{id}.nro"),
            ("ovl", "/switch/.overlays/{file}"),
            ("zip", ARCHIVE),
        ]),
        free_roots: &["/switch/{id}/", "/config/{id}/"],
        consent_roots: &["/atmosphere/", "/switch/.overlays/"],
        data_areas: Some(&["/switch/", "/config/"]),
        requires_min: &["firmware", "atmosphere"],
        save_kinds: &["account", "device", "bcat", "cache", "other"],
        cheats: Some(Cheats {
            format: "atmosphere",
            path: "/atmosphere/contents/{title_id}/cheats/{build_id}.txt",
            build_id: Some(re(r"^[0-9A-F]{1,64}$")),
        }),
        ..base("switch", false)
    }
}

fn n3ds() -> Profile {
    Profile {
        title_id: Some(re(N3DS_TITLE)),
        app_ids: HashMap::from([
            ("", re(r"^0004(0000|0002|000E|008C)[0-9A-F]{8}$")),
            ("base", re(N3DS_TITLE)),
            ("update", re(r"^0004000E[0-9A-F]{8}$")),
            ("dlc", re(r"^0004008C[0-9A-F]{8}$")),
        ]),
        formats: Some(&["cia"]),
        homebrew_formats: HashMap::from([
            ("3dsx", "/3ds/{id}/{id}.3dsx"),
            ("zip", ARCHIVE),
            ("cia", SYSTEM),
        ]),
        free_roots: &["/3ds/{id}/"],
        consent_roots: &["/luma/", "/boot.firm", "/boot.3dsx", "/gm9/"],
        data_areas: Some(&["/3ds/"]),
        requires_min: &["firmware", "luma"],
        system_id: true,
        save_kinds: &["device", "other"],
        cheats: Some(Cheats {
            format: "gateshark",
            path: "/cheats/{title_id}.txt",
            build_id: None,
        }),
        ..base("3ds", true)
    }
}

fn vita() -> Profile {
    Profile {
        title_id: Some(re(VITA_TITLE)),
        app_ids: HashMap::from([
            ("", either(VITA_TITLE, VITA_CONTENT)),
            ("base", re(VITA_TITLE)),
            ("update", re(VITA_TITLE)),
            ("dlc", re(VITA_CONTENT)),
        ]),
        formats: Some(&["vpk", "pkg"]),
        homebrew_formats: HashMap::from([("vpk", SYSTEM)]),
        free_roots: &["/ux0/data/{id}/"],
        consent_roots: &["/ux0/tai/", "/ur0/tai/"],
        data_areas: Some(&["/ux0/data/"]),
        system_id: true,
        save_kinds: &["device"],
        cheats: Some(Cheats {
            format: "psv",
            path: "/ux0/vitacheat/db/{title_id}.psv",
            build_id: None,
        }),
        ..base("vita", true)
    }
}

fn ps4() -> Profile {
    Profile {
        title_id: Some(re(PS4_TITLE)),
        app_ids: HashMap::from([
            ("", either(PS4_TITLE, PS4_CONTENT)),
            ("base", re(PS4_TITLE)),
            ("update", re(PS4_TITLE)),
            ("dlc", re(PS4_CONTENT)),
        ]),
        formats: Some(&["pkg"]),
        homebrew_formats: HashMap::from([("pkg", SYSTEM)]),
        free_roots: &["/data/{id}/"],
        consent_roots: &["/data/GoldHEN/"],
        data_areas: Some(&["/data/"]),
        requires_min: &["firmware", "goldhen"],
        system_id: true,
        save_kinds: &["account"],
        cheats: Some(Cheats {
            format: "json",
            path: "/data/GoldHEN/cheats/{format}/{title_id}_{build_id}.{format}",
            build_id: Some(re(r"^[0-9]{2}\.[0-9]{2}(_.+)?$")),
        }),
        ..base("ps4", true)
    }
}

fn android() -> Profile {
    Profile {
        title_id: Some(re(ANDROID_ID)),
        app_ids: HashMap::from([("", re(ANDROID_ID))]),
        types: Some(&["base"]),
        formats: Some(&["apk", "apks"]),
        newer_base_replaces: true,
        homebrew_formats: HashMap::from([("apk", SYSTEM), ("apks", SYSTEM)]),
        data_areas: None,
        arches: Some(&["aarch64", "armhf", "x86", "x86_64"]),
        requires_min: &["sdk"],
        system_id: true,
        ..base("android", true)
    }
}

fn linux() -> Profile {
    Profile {
        types: None,
        homebrew_formats: HashMap::from([("zip", ARCHIVE)]),
        free_roots: &["/{id}/"],
        consent_roots: &["/"],
        data_areas: Some(&["/"]),
        arches: Some(ARCH_NAMES),
        requires_min: &["glibc", "ram_mb", "screen"],
        installs_apps: false,
        ..base("linux", true)
    }
}

static PROFILES: LazyLock<Vec<Profile>> =
    LazyLock::new(|| vec![switch(), n3ds(), vita(), ps4(), android(), linux()]);

/// Platforms named by SPEC.md § 4.3 that have no profile yet (Annex A.7).
pub const OPEN_PLATFORMS: &[&str] = &["ios", "windows", "macos", "web", "steam", "gog", "xbox"];

/// The platform's profile, or `None` when it has none (a client installs nothing of it).
#[must_use]
pub fn profile(platform: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.platform == platform)
}

/// A title id of the core's form, and of the platform's profile when it has one.
#[must_use]
pub fn title_id_ok(platform: &str, title_id: &str) -> bool {
    CORE_ID.is_match(title_id)
        && profile(platform)
            .and_then(|p| p.title_id.as_ref())
            .is_none_or(|pattern| pattern.is_match(title_id))
}

/// An app id of the core's form, and of the platform's profile (for its type, when given).
#[must_use]
pub fn app_id_ok(platform: &str, app_id: &str, app_type: Option<&str>) -> bool {
    if !CORE_ID.is_match(app_id) {
        return false;
    }
    let Some(p) = profile(platform) else {
        return true;
    };
    let pattern = app_type
        .and_then(|t| p.app_ids.get(t))
        .or_else(|| p.app_ids.get(""));
    pattern.is_none_or(|pattern| pattern.is_match(app_id))
}

/// Where a single-file package of `format` goes (Annex A), or `None` for an
/// archive or the system's installer.
#[must_use]
pub fn single_file_path(
    p: &Profile,
    format: &str,
    homebrew_id: &str,
    file_name: &str,
) -> Option<String> {
    let place = p.homebrew_formats.get(format).copied()?;
    (place != SYSTEM && place != ARCHIVE).then(|| {
        place
            .replace("{id}", homebrew_id)
            .replace("{file}", file_name)
    })
}

/// The free and the consent roots of a homebrew's manifest, its id put in.
#[must_use]
pub fn roots(p: &Profile, homebrew_id: &str) -> (Vec<String>, Vec<String>) {
    let put = |roots: &[&str]| {
        roots
            .iter()
            .map(|r| r.replace("{id}", homebrew_id))
            .collect()
    };
    (put(p.free_roots), put(p.consent_roots))
}

/// What a Switch app id is, by its lowest 13 bits (Annex A.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchKind {
    /// The base game: its id ends in 000.
    Base,
    /// Its update: 800.
    Update,
    /// An add-on.
    Dlc,
}

/// The title id and the kind of a Switch app id (Annex A.1).
///
/// # Errors
///
/// [`Error::Document`] when `app_id` is not 16 upper-case hex digits.
pub fn switch_ids(app_id: &str) -> Result<(String, SwitchKind)> {
    let n = switch_number(app_id, SWITCH_ID, "a Switch id")?;
    let kind = match n & 0x1fff {
        0 => SwitchKind::Base,
        0x800 => SwitchKind::Update,
        _ => SwitchKind::Dlc,
    };
    Ok((format!("{:016X}", n & !0x1fff), kind))
}

fn switch_number(text: &str, form: &str, what: &str) -> Result<u64> {
    if !pattern(form).is_match(text) {
        return Err(Error::document(format!("{text} is not {what}")));
    }
    u64::from_str_radix(text, 16).map_err(|_| Error::document(format!("{text} is not {what}")))
}

/// The app id of a Switch game's update: its title id plus 800 (hex).
///
/// # Errors
///
/// [`Error::Document`] when `title_id` is not a Switch game's.
pub fn switch_update_id(title_id: &str) -> Result<String> {
    let n = switch_number(title_id, SWITCH_TITLE, "a Switch game's title id")?;
    Ok(format!("{:016X}", n + 0x800))
}

/// A Switch title version as the system reads it, from `v196608` or `196608` (Annex A.1).
///
/// # Errors
///
/// [`Error::Document`] when it is neither, or is above 32 bits.
pub fn switch_version_code(text: &str) -> Result<u32> {
    let trimmed = text.trim();
    let digits = trimmed.strip_prefix('v').unwrap_or(trimmed);
    let ok = !digits.is_empty() && digits.len() <= 10 && digits.bytes().all(|b| b.is_ascii_digit());
    ok.then(|| digits.parse::<u32>().ok())
        .flatten()
        .ok_or_else(|| Error::document(format!("{text} is not a Switch title version")))
}

/// `APP_VER` `XX.YY` as XX*100+YY: a Vita's or a PS4's `version_code` (Annex A.3, A.4).
///
/// # Errors
///
/// [`Error::Document`] when it is not `XX.YY`.
pub fn app_ver_code(app_ver: &str) -> Result<u32> {
    let bad = || Error::document(format!("{app_ver} is not an APP_VER (XX.YY)"));
    let (major, minor) = app_ver.trim().split_once('.').ok_or_else(bad)?;
    let two = |s: &str| {
        (s.len() == 2 && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<u32>().ok())
            .flatten()
    };
    Ok(two(major).ok_or_else(bad)? * 100 + two(minor).ok_or_else(bad)?)
}

/// A 3DS title version's name (Annex A.2): its top 6 bits, next 6 and low 4, `2069` being `2.1.5`.
///
/// # Errors
///
/// [`Error::Document`] when it is above 16 bits.
pub fn n3ds_version_name(version_code: u32) -> Result<String> {
    if version_code > 0xffff {
        return Err(Error::document(format!(
            "{version_code} is not a 16-bit title version"
        )));
    }
    Ok(format!(
        "{}.{}.{}",
        version_code >> 10,
        (version_code >> 4) & 0x3f,
        version_code & 0xf
    ))
}

/// Where a client writes a cheat set (Annex A). On a Switch, Atmosphère names
/// the file with the first 16 digits of the build id.
///
/// # Errors
///
/// [`Error::Document`] when the platform has no cheats, or an id is not of its form.
pub fn cheat_path(
    platform: &str,
    title_id: &str,
    build_id: Option<&str>,
    format: Option<&str>,
) -> Result<String> {
    let cheats = profile(platform)
        .and_then(|p| p.cheats.as_ref())
        .ok_or_else(|| Error::document(format!("no cheats on {platform}")))?;
    if let Some(form) = &cheats.build_id
        && !build_id.is_some_and(|b| form.is_match(b))
    {
        return Err(Error::document(format!(
            "{} is not a {platform} build id",
            build_id.unwrap_or("")
        )));
    }
    if !title_id_ok(platform, title_id) {
        return Err(Error::document(format!(
            "{title_id} is not a {platform} title id"
        )));
    }
    let build = build_id.unwrap_or("");
    let build = if platform == "switch" {
        build.get(..16).unwrap_or(build)
    } else {
        build
    };
    Ok(cheats
        .path
        .replace("{title_id}", title_id)
        .replace("{build_id}", build)
        .replace("{format}", format.unwrap_or(cheats.format)))
}
