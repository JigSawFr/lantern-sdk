// SPDX-License-Identifier: MIT

package lantern

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// What a client checks of a homebrew before it installs or starts it (SPEC.md § 8), and what a
// server checks before it serves one: paths and manifests (§ 8.2), signatures (§ 8.4), where a
// manifest writes (§ 8.3, Annex A), the package of the device's architecture, a port's data
// (§ 8.6) and the requirements (§ 8.7). The same rules as the other libraries.

// HomebrewPurpose is the purpose a homebrew's signature covers (SPEC.md § 8.4).
const HomebrewPurpose = "lantern-homebrew-1"

// DottedKeys are the keys of requires.min that are dotted versions (SPEC.md § 8.7, Annex A).
var DottedKeys = []string{"glibc", "firmware", "atmosphere", "luma", "goldhen", "sdk"}

var (
	dottedPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,3}$`)
	screenPattern = regexp.MustCompile(`^([1-9][0-9]{0,5})x([1-9][0-9]{0,5})$`)
	hashForms     = map[string]*regexp.Regexp{
		"sha256": regexp.MustCompile(`^[0-9a-f]{64}$`),
		"sha1":   regexp.MustCompile(`^[0-9a-f]{40}$`),
		"md5":    regexp.MustCompile(`^[0-9a-f]{32}$`),
	}
)

// ErrRefused is a homebrew a client must not install; the error says why.
var ErrRefused = errors.New("lantern: homebrew refused")

func refused(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, args...))
}

// EffectiveAssets is a port's assets as a reader reads it (SPEC.md § 8.6): a value it does not
// know is user_owned.
func EffectiveAssets(assets string) string {
	if contains(Assets, assets) {
		return assets
	}
	return "user_owned"
}

// PathProblem says why path breaks SPEC.md § 8.2, or "" when it does not.
func PathProblem(path string) string {
	shown := strconv.Quote(Clip(path, 80))
	if !strings.HasPrefix(path, "/") {
		return shown + " is not absolute"
	}
	if len(path) > MaxPath {
		return fmt.Sprintf("%s…: above %d bytes", shown, MaxPath)
	}
	if !utf8.ValidString(path) {
		return shown + " is not UTF-8"
	}
	for _, part := range strings.Split(path[1:], "/") {
		if part == "" || part == "." || part == ".." {
			return shown + " has an empty, . or .. part"
		}
		if len(part) > MaxPathPart {
			return fmt.Sprintf("%s has a part above %d bytes", shown, MaxPathPart)
		}
		for _, c := range part {
			if c == '\\' || c == ':' || c == '"' || c < 32 || c == 127 {
				return shown + ` has a \, :, " or control character`
			}
		}
	}
	return ""
}

// ManifestProblems says every way a manifest breaks SPEC.md § 8.2 (none when it does not).
func ManifestProblems(manifest []ManifestEntry) []string {
	var out []string
	if len(manifest) > MaxManifestFiles {
		out = append(out, fmt.Sprintf("%d files, above %d", len(manifest), MaxManifestFiles))
	}
	seen := map[string]bool{}
	for _, e := range manifest {
		if p := PathProblem(e.Path); p != "" {
			out = append(out, p)
			continue
		}
		folded := strings.ToLower(e.Path)
		if seen[folded] {
			out = append(out, strconv.Quote(e.Path)+" twice, when case is ignored")
		}
		seen[folded] = true
		if e.Size < 0 || !SHA256Pattern.MatchString(e.SHA256) {
			out = append(out, strconv.Quote(e.Path)+": its size or sha256 is not of its form")
		}
	}
	return out
}

// ManifestOf is a package's manifest: its own, a single file's (its path), or none (the
// platform's installer installs it).
func ManifestOf(p Package) []ManifestEntry {
	if p.Manifest != nil {
		return append([]ManifestEntry(nil), p.Manifest...)
	}
	if p.Path != nil {
		return []ManifestEntry{{Path: *p.Path, Size: p.Size, SHA256: p.SHA256}}
	}
	return nil
}

// jsString writes s as a JSON string the way JavaScript's JSON.stringify does: only the quote,
// the backslash and the control characters are escaped.
func jsString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range s {
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\b':
			b.WriteString(`\b`)
		case c == '\f':
			b.WriteString(`\f`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c < 0x20:
			fmt.Fprintf(&b, `\u%04x`, c)
		default:
			b.WriteRune(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ManifestCanonical is the canonical form of a manifest (SPEC.md § 8.2): its entries sorted by
// path as UTF-8 bytes, each {"path","sha256","size"}, no space, characters other than ASCII as
// they are.
func ManifestCanonical(manifest []ManifestEntry) string {
	entries := append([]ManifestEntry(nil), manifest...)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	parts := make([]string, len(entries))
	for i, e := range entries {
		parts[i] = fmt.Sprintf(`{"path":%s,"sha256":"%s","size":%d}`, jsString(e.Path), e.SHA256, e.Size)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// ManifestSHA256 is the SHA-256, lower-case hex, of a manifest's canonical form (SPEC.md § 8.2).
func ManifestSHA256(manifest []ManifestEntry) string {
	return SHA256Hex([]byte(ManifestCanonical(manifest)))
}

// SignedMessage is the bytes an author signs for p (SPEC.md § 8.4): the entry's own package, or
// one of its packages.
func SignedMessage(entry *Homebrew, p Package) []byte {
	return []byte(fmt.Sprintf(`{"build":%d,"id":"%s","manifest_sha256":"%s","platform":"%s","purpose":"%s","sha256":"%s"}`,
		entry.Build, entry.ID, p.ManifestSHA256, entry.Platform, HomebrewPurpose, p.SHA256))
}

// VerifySignature says whether p's signature (the entry's, for its own package; the package's,
// for one of Packages) verifies; signed is false when it is unsigned. A package of Packages
// must be signed by the entry's key.
func VerifySignature(entry *Homebrew, p Package) (valid, signed bool) {
	own := entry.Package.File == p.File && entry.Package.SHA256 == p.SHA256 && entry.Package.ManifestSHA256 == p.ManifestSHA256
	sig := p.Signature
	if own {
		sig = entry.Signature
	}
	if sig == nil {
		return false, entry.Signature != nil // unsigned; a package unsigned under a signed entry does not verify
	}
	if entry.Signature != nil && sig.PublicKey != entry.Signature.PublicKey {
		return false, true
	}
	public, err1 := base64.StdEncoding.DecodeString(sig.PublicKey)
	value, err2 := base64.StdEncoding.DecodeString(sig.Value)
	if sig.Alg != "ed25519" || err1 != nil || err2 != nil {
		return false, true
	}
	return VerifyEd25519(public, SignedMessage(entry, p), value), true
}

// KeyFingerprint is a key's short fingerprint, for people (SPEC.md § 8.4, in the form of § 5.3).
func KeyFingerprint(publicKey string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return "", errors.New("lantern: not a base64 key")
	}
	sum := sha256.Sum256(raw)
	head := strings.ToUpper(hex.EncodeToString(sum[:]))[:16]
	return head[0:4] + " " + head[4:8] + " " + head[8:12] + " " + head[12:16], nil
}

// KeyChange is what SPEC.md § 8.4 says of an entry's key against the one pinned for its id.
type KeyChange string

// The three outcomes of KeyChanged.
const (
	KeyPin     KeyChange = "pin"     // a first install: pin the key (or that it had none)
	KeySame    KeyChange = "same"    // the same key
	KeyDiffers KeyChange = "changed" // another key, none after one, or one after none: the user must accept
)

// KeyChanged compares the key an entry offers with the one pinned for its id; pinned is nil on a
// first install and "" for an id first installed unsigned.
func KeyChanged(pinned *string, entry *Homebrew) KeyChange {
	offered := ""
	if entry.Signature != nil {
		offered = entry.Signature.PublicKey
	}
	switch {
	case pinned == nil:
		return KeyPin
	case offered == *pinned:
		return KeySame
	}
	return KeyDiffers
}

// InstallPlan is the paths a client writes without asking, and those it shows the user and writes
// only once they agree.
type InstallPlan struct {
	Free, Consent []string
}

func under(path, root string) bool {
	if strings.HasSuffix(root, "/") {
		return strings.HasPrefix(path, root)
	}
	return path == root
}

// PlanInstall says where p writes, by the profile's roots (SPEC.md § 8.3, Annex A). It refuses
// (ErrRefused) a platform without a profile, a manifest that breaks § 8.2 or whose digest is not
// manifest_sha256, and a path outside every root.
func PlanInstall(entry *Homebrew, p Package) (*InstallPlan, error) {
	prof := ProfileOf(entry.Platform)
	if prof == nil || len(prof.HomebrewFormats) == 0 {
		return nil, refused("no profile for %s homebrew: nothing of it is installed", entry.Platform)
	}
	place, ok := prof.HomebrewFormats[p.Format]
	if !ok {
		return nil, refused("%s is not a homebrew format of %s", p.Format, entry.Platform)
	}
	switch {
	case place == FormatArchive && p.Manifest == nil:
		return nil, refused("an archive without its manifest")
	case place == FormatSystem && (p.Path != nil || len(p.Manifest) > 0):
		return nil, refused("%s is installed by the platform's installer: no path, an empty manifest", p.Format)
	case place != FormatArchive && place != FormatSystem && p.Path == nil:
		return nil, refused("a single %s file without its path", p.Format)
	}
	if p.Path != nil && p.Manifest != nil {
		if len(p.Manifest) != 1 || p.Manifest[0].Path != *p.Path || p.Manifest[0].Size != p.Size || p.Manifest[0].SHA256 != p.SHA256 {
			return nil, refused("a path, and a manifest that is not that one file")
		}
	}
	manifest := ManifestOf(p)
	if problems := ManifestProblems(manifest); len(problems) > 0 {
		if len(problems) > 3 {
			problems = problems[:3]
		}
		return nil, refused("%s", strings.Join(problems, "; "))
	}
	if ManifestSHA256(manifest) != p.ManifestSHA256 {
		return nil, refused("manifest_sha256 is not the digest of the manifest")
	}
	free, consent := prof.Roots(entry.ID)
	plan := &InstallPlan{}
	for _, e := range manifest {
		switch {
		case anyUnder(e.Path, free):
			plan.Free = append(plan.Free, e.Path)
		case anyUnder(e.Path, consent):
			plan.Consent = append(plan.Consent, e.Path)
		default:
			return nil, refused("%s is outside %s's roots", strconv.Quote(e.Path), entry.Platform)
		}
	}
	return plan, nil
}

func anyUnder(path string, roots []string) bool {
	for _, r := range roots {
		if under(path, r) {
			return true
		}
	}
	return false
}

// ArchOK says whether a package's arch is well formed for its platform (none on a platform of
// one architecture, a list otherwise); with mine (the device's architecture) whether it may run
// there. A name a reader does not know is never its own (SPEC.md § 8.2).
func ArchOK(p Package, platform, mine string) bool {
	if p.Arch == nil {
		return true
	}
	prof := ProfileOf(platform)
	if (prof != nil && prof.Arches == nil) || len(p.Arch) == 0 {
		return false
	}
	for _, a := range p.Arch {
		if !ArchPattern.MatchString(a) {
			return false
		}
	}
	if mine == "" {
		return true
	}
	return contains(ArchNames, mine) && contains(p.Arch, mine)
}

// PickPackage is the package a device of architecture mine installs (SPEC.md § 8.2): one whose
// arch lists it, else one without arch. ok is false when none fits.
func PickPackage(entry *Homebrew, mine string) (p Package, ok bool) {
	packages := append([]Package{entry.Package}, entry.Packages...)
	if mine != "" {
		for _, c := range packages {
			if c.Arch != nil && ArchOK(c, entry.Platform, mine) {
				return c, true
			}
		}
	}
	for _, c := range packages {
		if c.Arch == nil {
			return c, true
		}
	}
	return Package{}, false
}

// DataFiles are every file a requires_data names, those of each alternative included.
func DataFiles(items []RequiredData) []RequiredFile {
	var out []RequiredFile
	for _, d := range items {
		switch {
		case d.Group != nil:
			for _, option := range d.Group.OneOf {
				out = append(out, option...)
			}
		case d.File != nil:
			out = append(out, *d.File)
		}
	}
	return out
}

// PortProblems says every way an entry's port object breaks SPEC.md § 8.6 (none when it does not).
func PortProblems(entry *Homebrew) []string {
	port := entry.Port
	if port == nil {
		if entry.EffectiveKind() == "port" {
			return []string{"no port object"}
		}
		return nil
	}
	var out []string
	if port.Original.Name == "" {
		out = append(out, "original has no name")
	}
	if port.Engine.Name == "" {
		out = append(out, "engine has no name")
	}
	root := port.DataRoot
	if !(strings.HasSuffix(root, "/") && len(root) > 1 && PathProblem(strings.TrimSuffix(root, "/")) == "") {
		return append(out, fmt.Sprintf("data_root %s is not a folder's path", strconv.Quote(Clip(root, 80))))
	}
	if prof := ProfileOf(entry.Platform); prof != nil && prof.DataAreas != nil {
		inside := false
		for _, a := range prof.DataAreas {
			inside = inside || (strings.HasPrefix(root, a) && root != a)
		}
		if !inside {
			out = append(out, fmt.Sprintf("data_root %s is not under %s", strconv.Quote(root), strings.Join(prof.DataAreas, ", ")))
		}
	}
	for _, d := range port.RequiresData {
		if d.Group != nil {
			ok := len(d.Group.OneOf) >= 2
			for _, o := range d.Group.OneOf {
				ok = ok && len(o) > 0
			}
			if !ok {
				out = append(out, "one_of has fewer than two alternatives, or an empty one")
			}
		}
	}
	files := DataFiles(port.RequiresData)
	if len(files) > MaxRequiredData {
		out = append(out, fmt.Sprintf("more than %d data files", MaxRequiredData))
	}
	var single []string
	for _, d := range port.RequiresData {
		if d.File != nil {
			single = append(single, d.File.Path)
		}
	}
	sets := [][]string{single}
	for _, d := range port.RequiresData {
		if d.Group != nil {
			for _, option := range d.Group.OneOf {
				set := append([]string(nil), single...)
				for _, f := range option {
					set = append(set, f.Path)
				}
				sets = append(sets, set)
			}
		}
	}
	for _, set := range sets {
		seen := map[string]bool{}
		for _, p := range set {
			if seen[p] {
				out = append(out, "a data path twice")
				break
			}
			seen[p] = true
		}
	}
	served := append([]Package{entry.Package}, entry.Packages...)
	shipped, hashes := map[string]bool{}, map[string]bool{}
	for _, p := range served {
		hashes[p.SHA256] = true
		for _, m := range ManifestOf(p) {
			shipped[m.Path] = true
			hashes[m.SHA256] = true
		}
	}
	for _, f := range files {
		if strings.HasPrefix(f.Path, "/") {
			out = append(out, fmt.Sprintf("data path %s is not relative to data_root", strconv.Quote(Clip(f.Path, 80))))
			continue
		}
		if p := PathProblem(root + f.Path); p != "" {
			out = append(out, fmt.Sprintf("data path %s: %s", strconv.Quote(Clip(f.Path, 80)), p))
			continue
		}
		if shipped[root+f.Path] {
			out = append(out, fmt.Sprintf("data %s is in the package: Lantern never serves a port's data", strconv.Quote(root+f.Path)))
		}
		if f.Hint == "" {
			out = append(out, fmt.Sprintf("data %s: no hint saying where the user finds it", strconv.Quote(f.Path)))
		}
		if len(f.Accept) > MaxAccept {
			out = append(out, fmt.Sprintf("data %s: more than %d accepted versions", strconv.Quote(f.Path), MaxAccept))
		}
		for _, a := range f.Accept {
			given := map[string]string{}
			for k, v := range map[string]*string{"sha256": a.SHA256, "sha1": a.SHA1, "md5": a.Md5} {
				if v != nil {
					given[k] = *v
				}
			}
			wellFormed := len(given) > 0
			for k, v := range given {
				wellFormed = wellFormed && hashForms[k].MatchString(v)
			}
			switch {
			case !wellFormed:
				out = append(out, fmt.Sprintf("data %s: an accepted version without a hash of a known form", strconv.Quote(f.Path)))
			case a.SHA256 != nil && hashes[*a.SHA256]:
				out = append(out, fmt.Sprintf("data %s: the package serves a file of an accepted hash", strconv.Quote(f.Path)))
			}
		}
	}
	return out
}

// FileHashes are the hashes of a data file a client has, by algorithm ("sha256", and "sha1" or
// "md5" where it can compute them).
type FileHashes map[string]string

func accepted(f RequiredFile, hashes FileHashes) bool {
	if len(f.Accept) == 0 {
		return true
	}
	for _, a := range f.Accept {
		given := map[string]*string{"sha256": a.SHA256, "sha1": a.SHA1, "md5": a.Md5}
		n, ok := 0, true
		for k, v := range given {
			if v != nil {
				n++
				ok = ok && hashes[k] == *v
			}
		}
		if n > 0 && ok {
			return true
		}
	}
	return false
}

// LaunchCheck is what CheckLaunch found: the port starts only when OK.
type LaunchCheck struct {
	Missing, Wrong, AbsentOptional []string
	// Choices are, for each group none of whose alternatives is complete, every alternative's paths.
	Choices [][][]string
	OK      bool
}

// CheckLaunch is what a client checks before it starts a port (SPEC.md § 8.6). present maps a
// path relative to data_root (exact, case included) to the hashes of the file there.
func CheckLaunch(entry *Homebrew, present map[string]FileHashes) LaunchCheck {
	var out LaunchCheck
	check := func(files []RequiredFile, missing, wrong, absent *[]string) {
		for _, f := range files {
			hashes, ok := present[f.Path]
			switch {
			case !ok && f.Optional != nil && *f.Optional:
				*absent = append(*absent, f.Path)
			case !ok:
				*missing = append(*missing, f.Path)
			case !accepted(f, hashes):
				*wrong = append(*wrong, f.Path)
			}
		}
	}
	if entry.Port != nil {
		for _, d := range entry.Port.RequiresData {
			if d.File != nil {
				check([]RequiredFile{*d.File}, &out.Missing, &out.Wrong, &out.AbsentOptional)
				continue
			}
			if d.Group == nil {
				continue
			}
			type tried struct{ missing, wrong, absent []string }
			tries := make([]tried, len(d.Group.OneOf))
			complete, anyWrong := false, false
			for i, option := range d.Group.OneOf {
				check(option, &tries[i].missing, &tries[i].wrong, &tries[i].absent)
				complete = complete || (len(tries[i].missing) == 0 && len(tries[i].wrong) == 0)
				anyWrong = anyWrong || len(tries[i].wrong) > 0
			}
			if complete {
				continue
			}
			var first []string
			if len(d.Group.OneOf) > 0 {
				for _, f := range d.Group.OneOf[0] {
					first = append(first, f.Path)
				}
			}
			if d.Group.Optional != nil && *d.Group.Optional && !anyWrong {
				out.AbsentOptional = append(out.AbsentOptional, first...)
				continue
			}
			if len(tries) > 0 && len(tries[0].missing) > 0 {
				out.Missing = append(out.Missing, tries[0].missing...)
			} else {
				out.Missing = append(out.Missing, first...)
			}
			var choice [][]string
			for i, option := range d.Group.OneOf {
				out.Wrong = append(out.Wrong, tries[i].wrong...)
				var paths []string
				for _, f := range option {
					paths = append(paths, f.Path)
				}
				choice = append(choice, paths)
			}
			out.Choices = append(out.Choices, choice)
		}
	}
	out.OK = len(out.Missing) == 0 && len(out.Wrong) == 0
	return out
}

var knownRequires = map[string]bool{"text": true, "min": true, "gpu": true, "homebrew": true}

// asInt reads a JSON number of the values a decoded document holds, as an integer.
func asInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), n == float64(int64(n))
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

// RequiresProblems says every way an entry's requires breaks SPEC.md § 8.7's shapes, for the keys
// this library knows.
func RequiresProblems(entry *Homebrew) []string {
	r := entry.Requires
	if r == nil {
		return nil
	}
	var out []string
	if r.Text == "" {
		out = append(out, "requires has no text")
	}
	for _, k := range sortedKeys(r.Min) {
		v := r.Min[k]
		s, isString := v.(string)
		switch {
		case k == "ram_mb":
			if n, ok := asInt(v); !ok || n < 1 {
				out = append(out, fmt.Sprintf("requires.min.ram_mb %v is not a positive integer", v))
			}
		case k == "screen":
			if !isString || !screenPattern.MatchString(s) {
				out = append(out, fmt.Sprintf("requires.min.screen %v is not <width>x<height>", v))
			}
		case contains(DottedKeys, k):
			if !isString || !dottedPattern.MatchString(s) {
				out = append(out, fmt.Sprintf("requires.min.%s %v is not a dotted version", k, v))
			}
		}
	}
	if r.GPU != nil && len(r.GPU) == 0 {
		out = append(out, "requires.gpu is empty")
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// CompareDotted is -1, 0 or 1: two dotted versions compared part by part, as numbers, a missing
// part being 0.
func CompareDotted(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int64
		if i < len(pa) {
			x, _ = strconv.ParseInt(pa[i], 10, 64)
		}
		if i < len(pb) {
			y, _ = strconv.ParseInt(pb[i], 10, 64)
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	return 0
}

// Decision is whether a client offers a package (SPEC.md § 8.7).
type Decision string

// The three decisions of Offer.
const (
	DecisionOffer  Decision = "offer"
	DecisionWarn   Decision = "warn"   // a condition it cannot read: it still offers, naming it, and shows text
	DecisionRefuse Decision = "refuse" // a condition the device fails
)

// DeviceFacts is what a device knows of itself, each key absent when it does not know it:
// "glibc": "2.31", "ram_mb": 1024, "screen": "1280x720", "gpu": []string{"gles2"}, and the
// profile's keys ("firmware": "18.0.0").
type DeviceFacts map[string]any

// Offer says whether a client offers entry's package on device, and why not or what it could not
// read. A refusal wins over a warning.
func Offer(entry *Homebrew, device DeviceFacts) (Decision, []string) {
	r := entry.Requires
	if r == nil {
		return DecisionOffer, nil
	}
	var fails, unknown []string
	for _, k := range sortedKeys(r.Min) {
		v := r.Min[k]
		mine := device[k]
		want, isString := v.(string)
		switch {
		case k == "ram_mb" && isInt(v):
			want, _ := asInt(v)
			have, ok := asInt(mine)
			if !ok {
				unknown = append(unknown, fmt.Sprintf("ram_mb %d (this device's memory is unknown)", want))
			} else if have < want {
				fails = append(fails, fmt.Sprintf("ram_mb: %d MiB or more; this device has %d", want, have))
			}
		case k == "screen" && isString && screenPattern.MatchString(want):
			w := screenPattern.FindStringSubmatch(want)
			ms, _ := mine.(string)
			h := screenPattern.FindStringSubmatch(ms)
			if h == nil {
				unknown = append(unknown, fmt.Sprintf("screen %s (this device's screen is unknown)", want))
			} else if atoi(h[1]) < atoi(w[1]) || atoi(h[2]) < atoi(w[2]) {
				fails = append(fails, fmt.Sprintf("screen: %s or larger; this device's is %s", want, ms))
			}
		case contains(DottedKeys, k) && isString && dottedPattern.MatchString(want):
			ms, _ := mine.(string)
			if !dottedPattern.MatchString(ms) {
				unknown = append(unknown, fmt.Sprintf("%s %s (this device's is unknown)", k, want))
			} else if CompareDotted(ms, want) < 0 {
				fails = append(fails, fmt.Sprintf("%s: %s or later; this device has %s", k, want, ms))
			}
		default:
			b, _ := json.Marshal(v)
			unknown = append(unknown, fmt.Sprintf("min.%s %s", k, b))
		}
	}
	if r.GPU != nil {
		var known, other []string
		for _, g := range r.GPU {
			if contains(GPUNames, g) {
				known = append(known, g)
			} else {
				other = append(other, g)
			}
		}
		mine, isList := stringList(device["gpu"])
		matched := false
		for _, g := range known {
			matched = matched || contains(mine, g)
		}
		switch {
		case !isList:
			unknown = append(unknown, fmt.Sprintf("gpu %s (this device's graphics are unknown)", strings.Join(r.GPU, ", ")))
		case !matched && len(known) > 0 && len(known) == len(r.GPU):
			have := strings.Join(mine, ", ")
			if have == "" {
				have = "none"
			}
			fails = append(fails, fmt.Sprintf("gpu: one of %s; this device has %s", strings.Join(r.GPU, ", "), have))
		case !matched:
			unknown = append(unknown, "gpu "+strings.Join(other, ", "))
		}
	}
	var extra []string
	for k := range r.Extra {
		if !knownRequires[k] && !strings.HasPrefix(k, "x-") {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	unknown = append(unknown, extra...)
	switch {
	case len(fails) > 0:
		return DecisionRefuse, fails
	case len(unknown) > 0:
		return DecisionWarn, unknown
	}
	return DecisionOffer, nil
}

func isInt(v any) bool { _, ok := asInt(v); return ok }

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

func stringList(v any) ([]string, bool) {
	switch l := v.(type) {
	case []string:
		return l, true
	case []any:
		out := make([]string, 0, len(l))
		for _, e := range l {
			s, _ := e.(string)
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}
