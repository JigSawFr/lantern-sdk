// SPDX-License-Identifier: MIT

package lantern

import (
	"regexp"
	"strings"
)

// A homebrew format the platform's own installer installs has no path and an empty manifest;
// an archive has a manifest (SPEC.md § 8.2). Any other value of Profile.HomebrewFormats is the
// path of a single file.
const (
	FormatSystem  = "system"
	FormatArchive = "archive"
)

// CheatPlace says where a client writes a cheat set (Annex A): Path holds {title_id}, {build_id}
// and {format}.
type CheatPlace struct {
	Format  string
	Path    string
	BuildID *regexp.Regexp // nil where the platform has no build id
}

// Profile is what the core leaves open for one platform (SPEC.md Annex A). The Switch's is
// complete; the others are drafts (Draft). A platform without a profile has none: a client
// installs nothing of it.
type Profile struct {
	Platform string
	Draft    bool
	TitleID  *regexp.Regexp // nil where the platform has no title id form
	// HomebrewFormats maps each format to a single file's path ({id}, {file}), FormatArchive or
	// FormatSystem.
	HomebrewFormats map[string]string
	// FreeRoots are the roots a homebrew writes to without asking ({id}: its id); ConsentRoots
	// those that need the user's consent.
	FreeRoots, ConsentRoots []string
	// DataAreas are where a port's data_root may lie; nil where the user picks a folder.
	DataAreas []string
	// Arches are the architectures of `arch`; nil on a platform of one architecture.
	Arches []string
	// RequiresMin are the platform's own keys of requires.min (SPEC.md § 8.7).
	RequiresMin []string
	SystemID    bool
	SaveKinds   []string
	Cheats      *CheatPlace
	// InstallsApps is false where a client installs homebrew only (Linux).
	InstallsApps bool
}

var (
	switchTitle = regexp.MustCompile(`^[0-9A-F]{12}[02468ACE]000$`)
	n3dsTitle   = regexp.MustCompile(`^0004000[02][0-9A-F]{8}$`)
	vitaTitle   = regexp.MustCompile(`^[A-Z0-9]{9}$`)
	ps4Title    = regexp.MustCompile(`^[A-Z]{4}[0-9]{5}$`)
	androidID   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$`)
)

// Profiles are the platforms that have one, by name (Annex A).
var Profiles = map[string]*Profile{
	"switch": {
		Platform: "switch", TitleID: switchTitle, InstallsApps: true,
		HomebrewFormats: map[string]string{"nro": "/switch/{id}/{id}.nro", "ovl": "/switch/.overlays/{file}", "zip": FormatArchive},
		FreeRoots:       []string{"/switch/{id}/", "/config/{id}/"},
		ConsentRoots:    []string{"/atmosphere/", "/switch/.overlays/"},
		DataAreas:       []string{"/switch/", "/config/"},
		RequiresMin:     []string{"firmware", "atmosphere"},
		SaveKinds:       []string{"account", "device", "bcat", "cache", "other"},
		Cheats: &CheatPlace{Format: "atmosphere", Path: "/atmosphere/contents/{title_id}/cheats/{build_id}.txt",
			BuildID: regexp.MustCompile(`^[0-9A-F]{1,64}$`)},
	},
	"3ds": {
		Platform: "3ds", Draft: true, TitleID: n3dsTitle, InstallsApps: true, SystemID: true,
		HomebrewFormats: map[string]string{"3dsx": "/3ds/{id}/{id}.3dsx", "zip": FormatArchive, "cia": FormatSystem},
		FreeRoots:       []string{"/3ds/{id}/"},
		ConsentRoots:    []string{"/luma/", "/boot.firm", "/boot.3dsx", "/gm9/"},
		DataAreas:       []string{"/3ds/"},
		RequiresMin:     []string{"firmware", "luma"},
		SaveKinds:       []string{"device", "other"},
		Cheats:          &CheatPlace{Format: "gateshark", Path: "/cheats/{title_id}.txt"},
	},
	"vita": {
		Platform: "vita", Draft: true, TitleID: vitaTitle, InstallsApps: true, SystemID: true,
		HomebrewFormats: map[string]string{"vpk": FormatSystem},
		FreeRoots:       []string{"/ux0/data/{id}/"},
		ConsentRoots:    []string{"/ux0/tai/", "/ur0/tai/"},
		DataAreas:       []string{"/ux0/data/"},
		SaveKinds:       []string{"device"},
		Cheats:          &CheatPlace{Format: "psv", Path: "/ux0/vitacheat/db/{title_id}.psv"},
	},
	"ps4": {
		Platform: "ps4", Draft: true, TitleID: ps4Title, InstallsApps: true, SystemID: true,
		HomebrewFormats: map[string]string{"pkg": FormatSystem},
		FreeRoots:       []string{"/data/{id}/"},
		ConsentRoots:    []string{"/data/GoldHEN/"},
		DataAreas:       []string{"/data/"},
		RequiresMin:     []string{"firmware", "goldhen"},
		SaveKinds:       []string{"account"},
		Cheats: &CheatPlace{Format: "json", Path: "/data/GoldHEN/cheats/{format}/{title_id}_{build_id}.{format}",
			BuildID: regexp.MustCompile(`^[0-9]{2}\.[0-9]{2}(_.+)?$`)},
	},
	"android": {
		Platform: "android", Draft: true, TitleID: androidID, InstallsApps: true, SystemID: true,
		HomebrewFormats: map[string]string{"apk": FormatSystem, "apks": FormatSystem},
		Arches:          []string{"aarch64", "armhf", "x86", "x86_64"},
		RequiresMin:     []string{"sdk"},
	},
	"linux": {
		Platform: "linux", Draft: true,
		HomebrewFormats: map[string]string{"zip": FormatArchive},
		FreeRoots:       []string{"/{id}/"},
		ConsentRoots:    []string{"/"},
		DataAreas:       []string{"/"},
		Arches:          ArchNames,
		RequiresMin:     []string{"glibc", "ram_mb", "screen"},
	},
}

// ProfileOf is the profile of a platform, or nil when it has none (a client installs nothing of it).
func ProfileOf(platform string) *Profile { return Profiles[platform] }

// Roots are the roots of a homebrew's manifest, its id put in: the ones it writes to without
// asking, and the ones that need consent.
func (p *Profile) Roots(homebrewID string) (free, consent []string) {
	put := func(in []string) []string {
		var out []string
		for _, r := range in {
			out = append(out, strings.ReplaceAll(r, "{id}", homebrewID))
		}
		return out
	}
	return put(p.FreeRoots), put(p.ConsentRoots)
}
