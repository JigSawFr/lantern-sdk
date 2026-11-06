// SPDX-License-Identifier: MIT

package lantern

import "regexp"

// The open vocabularies SPEC.md lists in its text rather than in its schemas.
// A reader takes a value it does not know as the specification says (an unknown
// kind is an app, an unknown assets is user_owned); a later version may add values.
var (
	// Kinds are a homebrew's kinds (SPEC.md § 8.1).
	Kinds = []string{"app", "game", "port", "emulator", "tool", "overlay", "sysmodule", "theme"}
	// Assets say where a port's assets come from (SPEC.md § 8.6).
	Assets = []string{"included", "demo_included", "free_external", "user_owned"}
	// ArchNames are the architectures a package may name (SPEC.md § 8.2).
	ArchNames = []string{"aarch64", "armhf", "x86", "x86_64", "riscv64"}
	// Families are the families of the handshake's features (SPEC.md § 4.2).
	Families = []string{
		"library", "titles", "changes", "sections", "homebrew", "saves", "cheats", "requests",
		"pairing", "signatures", "admin", "events", "peers", "sync", "encrypted_saves", "deltas",
	}
)

// Forms of identifiers and words, this version's or a later one's.
var (
	// ArchPattern is the form of an architecture's name (SPEC.md § 8.2).
	ArchPattern = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	// PlatformPattern is a platform's name (SPEC.md § 4.3).
	PlatformPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	// CoreIDPattern is a title or an app id, the core's form (SPEC.md § 6.1).
	CoreIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	// HomebrewIDPattern is a homebrew's id (SPEC.md § 8.1).
	HomebrewIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*(?:\.[a-z0-9][a-z0-9_-]*)+$`)
	// WordPattern is a lower-case word: a filter's kind or genre, an app's type (SPEC.md § 6.1, § 8.5).
	WordPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	// FormatWordPattern is a package format (SPEC.md § 6.1).
	FormatWordPattern = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
	// RequiresTokenPattern is a token of an app's requires, and of a missing request's satisfies (SPEC.md § 6.1, § 6.3).
	RequiresTokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	// BuildIDPattern is a cheat set's build id, the core's form (SPEC.md § 10).
	BuildIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	// SHA256Pattern is a SHA-256, lower-case hex.
	SHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// IsPlatform reports whether name is a platform's name (SPEC.md § 4.3).
func IsPlatform(name string) bool { return PlatformPattern.MatchString(name) }

// IsHomebrewID reports whether id is a homebrew's id: at most 128 bytes (SPEC.md § 8.1).
func IsHomebrewID(id string) bool { return len(id) <= 128 && HomebrewIDPattern.MatchString(id) }
