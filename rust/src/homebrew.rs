//! Homebrew (SPEC.md § 8): the paths and manifests a package installs, the
//! digest of a manifest, the bytes an author signs, and the key a client
//! pins at the first install of an `id`.
//!
//! Nothing here reads a file or the network: the client downloads the package
//! (see [`crate::client::Client::download`]) and these functions say whether
//! what it holds is what the entry promised.

use std::collections::HashSet;
use std::fmt::Write as _;

use unicode_normalization::UnicodeNormalization;

use crate::bytes::{from_base64, from_hex};
use crate::digest::sha256_hex;
use crate::error::{Error, Result};
use crate::generated::models::{Homebrew, ManifestEntry, Package, Signature};
use crate::limits::{PATH, PATH_PART};
use crate::signatures::{ed25519_verify, short_fingerprint};

/// What an author signs with (SPEC.md § 8.4).
pub const PURPOSE: &str = "lantern-homebrew-1";

/// Whether `path` is a device path (SPEC.md § 8.2).
///
/// # Errors
///
/// [`Error::Document`] saying which rule it breaks.
pub fn check_path(path: &str) -> Result<()> {
    let bad = |why: &str| Err(Error::field(why, "path"));
    if path.len() > PATH {
        return bad("a path is 1024 bytes at most");
    }
    let Some(rest) = path.strip_prefix('/') else {
        return bad("a path starts with /");
    };
    if path
        .chars()
        .any(|c| c.is_control() || matches!(c, '\\' | ':' | '"'))
    {
        return bad("a path has no \\, :, \" or control character");
    }
    for part in rest.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return bad("a path has no empty, . or .. part");
        }
        if part.len() > PATH_PART {
            return bad("a part of a path is 255 bytes at most");
        }
    }
    Ok(())
}

/// The key two paths are compared by: canonical caseless match (NFD, default
/// case folding, NFD; SPEC.md § 2.3).
#[must_use]
pub fn caseless_key(text: &str) -> String {
    let decomposed: String = text.nfd().collect();
    caseless::default_case_fold_str(&decomposed).nfd().collect()
}

/// Whether a manifest breaks § 8.2: a path that is not one, a digest that is
/// not 64 lower-case hex digits, a negative size, or two paths the same when
/// case is ignored.
///
/// # Errors
///
/// [`Error::Document`] naming the entry.
pub fn check_manifest(manifest: &[ManifestEntry]) -> Result<()> {
    let mut seen = HashSet::new();
    for entry in manifest {
        check_path(&entry.path)?;
        if entry.size < 0 {
            return Err(Error::field("a size is not negative", "size"));
        }
        if entry.sha256.len() != 64
            || !entry
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::field(
                "a sha256 is 64 lower-case hex digits",
                "sha256",
            ));
        }
        if !seen.insert(caseless_key(&entry.path)) {
            return Err(Error::field(
                "two paths are the same when case is ignored",
                "path",
            ));
        }
    }
    Ok(())
}

/// The canonical form of a manifest (SPEC.md § 8.2): the entries sorted by
/// path as UTF-8 bytes, each `{"path","sha256","size"}` in that order, no
/// space.
#[must_use]
pub fn manifest_canonical(manifest: &[ManifestEntry]) -> String {
    let mut sorted: Vec<&ManifestEntry> = manifest.iter().collect();
    sorted.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let mut out = String::from("[");
    for (n, e) in sorted.iter().enumerate() {
        if n > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"path\":{},\"sha256\":{},\"size\":{}}}",
            json_string(&e.path),
            json_string(&e.sha256),
            e.size
        );
    }
    out.push(']');
    out
}

fn json_string(text: &str) -> String {
    // A path holds no control character, \ or ": nothing to escape but what
    // serde_json would write the same way.
    serde_json::Value::String(text.to_owned()).to_string()
}

/// `manifest_sha256`: the SHA-256, lower-case hex, of the canonical form.
#[must_use]
pub fn manifest_digest(manifest: &[ManifestEntry]) -> String {
    sha256_hex(manifest_canonical(manifest).as_bytes())
}

/// The bytes an author signs for a package (SPEC.md § 8.4).
#[must_use]
pub fn signed_bytes(entry: &Homebrew, package: &Package) -> String {
    format!(
        "{{\"build\":{},\"id\":{},\"manifest_sha256\":{},\"platform\":{},\"purpose\":\"{PURPOSE}\",\"sha256\":{}}}",
        entry.build,
        json_string(&entry.id),
        json_string(&package.manifest_sha256),
        json_string(&entry.platform),
        json_string(&package.sha256),
    )
}

/// Whether `signature` is the author's over `package` of `entry`: the key and
/// the signature decode, the key is not of small order, `S` is reduced, and
/// the equation holds (SPEC.md § 8.4, `vectors/ed25519-refused.json`).
#[must_use]
pub fn signature_ok(entry: &Homebrew, package: &Package, signature: &Signature) -> bool {
    if signature.alg != "ed25519" {
        return false;
    }
    let (Some(key), Some(value)) = (
        from_base64(&signature.public_key),
        from_base64(&signature.value),
    ) else {
        return false;
    };
    ed25519_verify(&key, signed_bytes(entry, package).as_bytes(), &value)
}

/// What a client checks before it downloads `package` of `entry` (SPEC.md
/// §§ 8.2, 8.3, 8.4): the manifest follows the rules and has the digest the
/// package says (an archive or a single file; a package the platform
/// installs itself has an empty manifest), and the signature, where there is
/// one, verifies. The signature is `package.signature`, else the entry's
/// when `package` is the entry's own.
///
/// # Errors
///
/// [`Error::Document`] for a manifest that breaks the rules,
/// [`Error::Integrity`] for a digest or a signature that does not verify.
pub fn check_package(entry: &Homebrew, package: &Package) -> Result<()> {
    if from_hex(&package.sha256).is_none_or(|b| b.len() != 32) {
        return Err(Error::field("a sha256 is 64 hex digits", "sha256"));
    }
    if let Some(manifest) = &package.manifest {
        check_manifest(manifest)?;
        if manifest_digest(manifest) != package.manifest_sha256 {
            return Err(Error::Integrity(
                "the manifest is not the one manifest_sha256 names".to_owned(),
            ));
        }
    }
    let own = std::ptr::eq(package, &raw const entry.package);
    let signature =
        package
            .signature
            .as_ref()
            .or(if own { entry.signature.as_ref() } else { None });
    if let Some(signature) = signature
        && !signature_ok(entry, package, signature)
    {
        return Err(Error::Integrity(
            "the author's signature does not verify".to_owned(),
        ));
    }
    Ok(())
}

/// The packages of `entry` a device of `arch` may take (SPEC.md § 8.2): the
/// ones whose `arch` lists it, else the ones with no `arch`; none when none
/// fits.
#[must_use]
pub fn packages_for<'a>(entry: &'a Homebrew, arch: &str) -> Vec<&'a Package> {
    std::iter::once(&entry.package)
        .chain(entry.packages.iter().flatten())
        .filter(|p| p.arch.as_ref().is_none_or(|a| a.iter().any(|x| x == arch)))
        .collect()
}

/// What pinning says about the key an entry offers (SPEC.md § 8.4).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PinCheck {
    /// The first install of this `id`: pin the key (or that it had none).
    First,
    /// The same key, or still none.
    Same,
    /// Another key, or none after a key, or a key after none: refused unless
    /// the user accepts, after both short fingerprints are shown.
    Changed {
        /// The pinned key's short fingerprint, `None` when it was unsigned.
        pinned: Option<String>,
        /// The offered key's short fingerprint, `None` when unsigned.
        offered: Option<String>,
    },
}

/// Compares the pinned key of an installed `id` (`None`: not installed; `Some(None)`:
/// installed unsigned) with the key `offered` (base64) by a new version.
#[must_use]
pub fn check_pin(pinned: Option<Option<&str>>, offered: Option<&str>) -> PinCheck {
    let Some(pinned) = pinned else {
        return PinCheck::First;
    };
    if pinned == offered {
        return PinCheck::Same;
    }
    let print = |key: Option<&str>| key.and_then(from_base64).map(|k| short_fingerprint(&k));
    PinCheck::Changed {
        pinned: print(pinned),
        offered: print(offered),
    }
}
