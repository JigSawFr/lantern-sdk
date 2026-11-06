// SPDX-License-Identifier: MIT

// Command gen generates the library's models from the specification's JSON
// Schemas, as tools/generate.py does for Python.
//
//	go run ./internal/gen           # writes models_gen.go and schema/v1/
//	go run ./internal/gen -check    # exits 1 when what is committed is stale
//
// It reads spec/schemas/v1/*.json (the submodule at the repository's root) and
// writes models_gen.go (a struct per object of the schemas, which reads and
// writes through internal/model and keeps the fields it does not know) and a
// copy of the schemas, which package schema embeds and validates against.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

// names are the types' names, by where the object is in the schemas: "<file>"
// for a document, "common#<def>" for a definition, then "/<property>" and "[]"
// for an array's items.
var names = map[string]string{
	"common#page":                          "AppsPage",
	"common#title/players":                 "Players",
	"common#ratings[]":                     "Rating",
	"common#title/video":                   "Video",
	"common#request":                       "TitleRequest",
	"common#required_file/accept[]":        "AcceptedVersion",
	"common#port/original":                 "PortOriginal",
	"common#port/original/stores[]":        "PortStore",
	"common#port/original/title":           "PortTitle",
	"common#port/engine":                   "PortEngine",
	"common#requires/homebrew[]":           "RequiredHomebrew",
	"common#required_data":                 "RequiredDataGroup",
	"handshake/software":                   "Software",
	"handshake/account":                    "Account",
	"handshake/limits":                     "Limits",
	"sections/sections[]":                  "Section",
	"title-changes/removed[]":              "RemovedTitle",
	"missing-request/installed[]":          "InstalledApp",
	"homebrew-updates-request/installed[]": "InstalledHomebrew",
	"cheats":                               "CheatSets",
	"requests":                             "TitleRequests",
	"sync/collections{}":                   "SyncSummary",
	"handshake/peers":                      "HandshakePeers",
	"handshake/static":                     "HandshakeStatic",
}

// lenient fields are taken by a reader even when a writer must give them.
var lenient = map[[2]string]bool{{"Homebrew", "kind"}: true}

type effective struct{ method, vocab, def, section, why string }

// effectives are the fields of an open vocabulary, read through a method that
// maps what the reader does not know to the value the specification says.
var effectives = map[[2]string]effective{
	{"Homebrew", "kind"}: {"EffectiveKind", "Kinds", `"app"`, "8.1", "a kind it does not know, or none, is an app"},
	{"Port", "assets"}:   {"EffectiveAssets", "Assets", `"user_owned"`, "8.6", "a value it does not know is user_owned"},
}

var genreFields = map[[2]string]bool{{"Homebrew", "genres"}: true, {"Title", "genres"}: true}

type vocabulary struct {
	name, schema, doc string
	path              []string
}

var vocabularies = []vocabulary{
	{"Genres", "common", "Genres of a title or a homebrew (SPEC.md § 7.1).", []string{"$defs", "genre", "enum"}},
	{"Scopes", "common", "What a token may do (SPEC.md § 4.2).", []string{"$defs", "scope", "enum"}},
	{"SaveKinds", "common", "A save's kinds (SPEC.md § 9.1).", []string{"$defs", "save_kind", "enum"}},
	{"GPUNames", "common", "Graphics interfaces of requires.gpu (SPEC.md § 8.7).", []string{"$defs", "requires", "properties", "gpu", "items", "enum"}},
	{"ErrorCodes", "problem", "The error codes of SPEC.md § 12.", []string{"properties", "code", "enum"}},
	{"AccountStates", "handshake", "An account's states (SPEC.md § 4.2).", []string{"properties", "account", "properties", "state", "enum"}},
	{"RequestStatuses", "common", "A request's statuses (SPEC.md § 11).", []string{"$defs", "request", "properties", "status", "enum"}},
}

var initialisms = map[string]string{
	"id": "ID", "uid": "UID", "url": "URL", "uri": "URI", "uuid": "UUID", "gpu": "GPU", "cpu": "CPU",
	"api": "API", "ip": "IP", "json": "JSON", "qr": "QR", "ssid": "SSID", "tls": "TLS", "spki": "SPKI",
}

var shaWord = regexp.MustCompile(`^sha\d+$`)

func pascal(text string) string {
	var out strings.Builder
	for _, part := range regexp.MustCompile(`[^A-Za-z0-9]+`).Split(text, -1) {
		switch {
		case part == "":
		case initialisms[strings.ToLower(part)] != "":
			out.WriteString(initialisms[strings.ToLower(part)])
		case shaWord.MatchString(part):
			out.WriteString(strings.ToUpper(part))
		default:
			out.WriteString(strings.ToUpper(part[:1]) + part[1:])
		}
	}
	return out.String()
}

type kind int

const (
	kScalar kind = iota
	kModel
	kUnion
	kSlice
	kMap
	kAny
)

type typ struct {
	goType   string
	kind     kind
	nullable bool
}

type fld struct {
	key, name string
	t         typ
	required  bool
}

type mdl struct {
	name, where, doc string
	fields           []fld
}

type object = map[string]any

type generator struct {
	schemas   map[string]object
	common    object
	models    map[string]*mdl
	order     []string
	byWhere   map[string]string
	documents map[string]string
	docOrder  []string
}

// keyOrder remembers the order a schema writes an object's keys in, by the object's address:
// Go's maps forget it, and a model's fields follow the schema.
var keyOrder = map[uintptr][]string{}

func decode(raw []byte) (object, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	o, ok := v.(object)
	if !ok {
		return nil, fmt.Errorf("not an object")
	}
	return o, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	if d == '[' {
		list := []any{}
		for dec.More() {
			v, err := parseValue(dec)
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
		_, err := dec.Token()
		return list, err
	}
	o := object{}
	var order []string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return nil, err
		}
		v, err := parseValue(dec)
		if err != nil {
			return nil, err
		}
		o[k.(string)] = v
		order = append(order, k.(string))
	}
	_, err = dec.Token()
	keyOrder[reflect.ValueOf(o).Pointer()] = order
	return o, err
}

func newGenerator(folder string) (*generator, error) {
	g := &generator{schemas: map[string]object{}, models: map[string]*mdl{}, byWhere: map[string]string{}, documents: map[string]string{}}
	files, _ := filepath.Glob(filepath.Join(folder, "*.json"))
	sort.Strings(files)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		o, err := decode(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		g.schemas[strings.TrimSuffix(filepath.Base(f), ".json")] = o
	}
	if g.schemas["common"] == nil {
		return nil, fmt.Errorf("no schemas in %s (git submodule update --init)", folder)
	}
	g.common = g.schemas["common"]["$defs"].(object)
	return g, nil
}

var refPattern = regexp.MustCompile(`^(?:common\.json)?#/\$defs/([A-Za-z0-9_]+)$`)

func (g *generator) ref(ref string) (string, object) {
	m := refPattern.FindStringSubmatch(ref)
	if m == nil {
		panic("gen: unknown $ref " + ref)
	}
	return "common#" + m[1], g.common[m[1]].(object)
}

func isModel(n any) bool {
	o, ok := n.(object)
	if !ok {
		return false
	}
	_, props := o["properties"]
	_, additional := o["additionalProperties"].(object)
	return props && !additional
}

func scalar(name string) typ { return typ{goType: name, kind: kScalar} }

func (g *generator) typeOf(node any, where string) typ {
	o, ok := node.(object)
	if !ok {
		return typ{goType: "any", kind: kAny}
	}
	if r, ok := o["$ref"].(string); ok {
		target, schema := g.ref(r)
		if target == "common#required_data" {
			return g.requiredData()
		}
		if isModel(schema) {
			return g.modelType(g.model(target, schema))
		}
		return g.typeOf(schema, target)
	}
	if all, ok := o["allOf"].([]any); ok {
		for _, part := range all {
			if p, ok := part.(object); ok {
				if _, has := p["$ref"]; has {
					return g.typeOf(p, where)
				}
			}
		}
	}
	if one, ok := o["oneOf"].([]any); ok {
		var rest []any
		nulls := 0
		for _, alt := range one {
			if a, ok := alt.(object); ok && len(a) == 1 && a["type"] == "null" {
				nulls++
			} else {
				rest = append(rest, alt)
			}
		}
		if nulls > 0 && len(rest) == 1 {
			inner := g.typeOf(rest[0], where)
			inner.nullable = true
			return inner
		}
		return typ{goType: "any", kind: kAny}
	}
	if c, ok := o["const"]; ok {
		if n, ok := c.(json.Number); ok {
			if _, err := n.Int64(); err == nil {
				return scalar("int64")
			}
			return scalar("float64")
		}
		if _, ok := c.(string); ok {
			return scalar("string")
		}
		return scalar("bool")
	}
	if e, ok := o["enum"].([]any); ok {
		allStrings := true
		for _, v := range e {
			if _, ok := v.(string); !ok {
				allStrings = false
			}
		}
		if allStrings {
			return scalar("string")
		}
	}
	switch o["type"] {
	case "string":
		return scalar("string")
	case "integer":
		return scalar("int64")
	case "boolean":
		return scalar("bool")
	case "array":
		item := g.typeOf(o["items"], where+"[]")
		return typ{goType: "[]" + g.valueType(item), kind: kSlice}
	}
	if _, ok := o["additionalProperties"].(object); ok && o["type"] == "object" {
		v := g.typeOf(o["additionalProperties"], where+"{}")
		return typ{goType: "map[string]" + g.valueType(v), kind: kMap}
	}
	if isModel(node) {
		return g.modelType(g.model(where, o))
	}
	if o["type"] == "object" {
		return typ{goType: "map[string]any", kind: kMap}
	}
	return typ{goType: "any", kind: kAny}
}

// valueType is a type as an element of a list or a map: a pointer where it may be null.
func (g *generator) valueType(t typ) string {
	if t.nullable && (t.kind == kScalar || t.kind == kModel || t.kind == kUnion) {
		return "*" + t.goType
	}
	return t.goType
}

func (g *generator) modelType(name string) typ { return typ{goType: name, kind: kModel} }

func (g *generator) requiredData() typ {
	nodes := g.common["required_data"].(object)["oneOf"].([]any)
	g.typeOf(nodes[0], "common#required_data")
	g.model("common#required_data", nodes[1].(object))
	return typ{goType: "RequiredData", kind: kUnion}
}

func (g *generator) model(where string, node object) string {
	if n, ok := g.byWhere[where]; ok {
		return n
	}
	name := names[where]
	if name == "" {
		tail := where[strings.LastIndex(where, "#")+1:]
		name = pascal(strings.ReplaceAll(tail, "[]", ""))
	}
	if other, ok := g.models[name]; ok {
		panic(fmt.Sprintf("gen: two models named %s (%s, %s)", name, where, other.where))
	}
	doc, _ := node["description"].(string)
	if doc == "" {
		doc, _ = node["title"].(string)
	}
	m := &mdl{name: name, where: where, doc: strings.TrimSpace(doc)}
	g.byWhere[where] = name
	g.models[name] = m
	g.order = append(g.order, name)
	required := map[string]bool{}
	for _, r := range anyList(node["required"]) {
		required[r.(string)] = true
	}
	props, _ := node["properties"].(object)
	for _, key := range orderedKeys(props) {
		prop := props[key]
		if p, ok := prop.(object); ok {
			if not, ok := p["not"].(object); ok && len(not) == 0 {
				continue // a field that must not be there
			}
		}
		t := g.typeOf(prop, where+"/"+key)
		m.fields = append(m.fields, fld{key: key, name: pascal(key), t: t, required: required[key] && !lenient[[2]string{name, key}]})
	}
	return name
}

func anyList(v any) []any {
	l, _ := v.([]any)
	return l
}

// orderedKeys gives an object's keys in the order the schema writes them.
func orderedKeys(props object) []string {
	if props == nil {
		return nil
	}
	return keyOrder[reflect.ValueOf(props).Pointer()]
}

func (g *generator) run() {
	var docs []string
	for name := range g.schemas {
		if name != "common" {
			docs = append(docs, name)
		}
	}
	sort.Strings(docs)
	for _, name := range docs {
		node := g.schemas[name]
		var model string
		switch {
		case node["$ref"] != nil:
			where, target := g.ref(node["$ref"].(string))
			model = g.model(where, target)
		case node["allOf"] != nil && node["properties"] == nil:
			var parts []object
			for _, p := range anyList(node["allOf"]) {
				if o, ok := p.(object); ok {
					parts = append(parts, o)
				}
			}
			var ref string
			for _, p := range parts {
				if r, ok := p["$ref"].(string); ok {
					ref = r
					break
				}
			}
			if ref != "" {
				where, target := g.ref(ref)
				model = g.model(where, target)
			} else {
				var own object
				for _, p := range parts {
					props, _ := p["properties"].(object)
					if _, has := props["schema"]; !has {
						own = p
						break
					}
				}
				merged := object{"description": node["description"]}
				for k, v := range own {
					merged[k] = v
				}
				model = g.model(name, merged)
			}
			m := g.models[model]
			has := false
			for _, f := range m.fields {
				has = has || f.key == "schema"
			}
			if !has {
				m.fields = append([]fld{{key: "schema", name: "Schema", t: scalar("int64")}}, m.fields...)
			}
		default:
			model = g.model(name, node)
		}
		g.documents[name] = model
		g.docOrder = append(g.docOrder, name)
	}
}

func firstSentence(doc, fallback string) string {
	if doc == "" {
		return fallback
	}
	s, _, _ := strings.Cut(doc, ". ")
	return strings.TrimRight(strings.ReplaceAll(s, "\n", " "), ".")
}

func (g *generator) source() string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	w("// Code generated by internal/gen from spec/schemas/v1; DO NOT EDIT.\n\n")
	w("package lantern\n\nimport (\n\t\"encoding/json\"\n\n\t\"github.com/JigSawFr/lantern-sdk/go/internal/model\"\n)\n\n")
	for _, v := range vocabularies {
		var node any = g.schemas[v.schema]
		for _, k := range v.path {
			if o, ok := node.(object); ok {
				node = o[k]
			}
		}
		w("// %s %s\nvar %s = []string{\n", v.name, v.doc[:1]+v.doc[1:], v.name)
		for _, e := range anyList(node) {
			w("\t%q,\n", e.(string))
		}
		w("}\n\n")
	}
	for _, name := range g.order {
		m := g.models[name]
		w("// %s is %s.\n//\n// From %s.\ntype %s struct {\n", m.name, lowerFirst(firstSentence(m.doc, m.name)), strings.Replace(m.where, "common#", "common.json#/$defs/", 1), m.name)
		hasNulls := false
		for _, f := range m.fields {
			t := f.t.goType
			pointer := (f.t.kind == kScalar || f.t.kind == kModel || f.t.kind == kUnion) && (!f.required || f.t.nullable)
			if pointer {
				t = "*" + t
			}
			tag := fmt.Sprintf("json:%q", f.key)
			var flags []string
			if f.required {
				flags = append(flags, "required")
			}
			if f.t.nullable {
				flags = append(flags, "nullable")
				hasNulls = hasNulls || !f.required
			}
			if len(flags) > 0 {
				tag += fmt.Sprintf(" lantern:%q", strings.Join(flags, ","))
			}
			w("\t%s %s `%s`\n", f.name, t, tag)
		}
		w("\t// Extra holds the fields this version does not know, as they were read (SPEC.md § 3.2).\n\tExtra map[string]json.RawMessage `json:\"-\"`\n")
		if hasNulls {
			w("\t// Nulls holds the optional fields that were given as null, so that they are written back as null.\n\tNulls map[string]bool `json:\"-\"`\n")
		}
		w("}\n\n")
		w("// UnmarshalJSON reads %s, keeping the fields it does not know.\nfunc (m *%s) UnmarshalJSON(data []byte) error { return model.Decode(data, m) }\n\n", m.name, m.name)
		w("// MarshalJSON writes %s with the fields it kept.\nfunc (m %s) MarshalJSON() ([]byte, error) { return model.Encode(m) }\n\n", m.name, m.name)
		for _, f := range m.fields {
			e, ok := effectives[[2]string{m.name, f.key}]
			if !ok {
				continue
			}
			w("// %s is %s as a reader reads it (SPEC.md § %s): %s.\nfunc (m %s) %s() string {\n", e.method, f.name, e.section, e.why, m.name, e.method)
			if f.required && !f.t.nullable {
				w("\tfor _, v := range %s {\n\t\tif v == m.%s {\n\t\t\treturn v\n\t\t}\n\t}\n\treturn %s\n}\n\n", e.vocab, f.name, e.def)
			} else {
				w("\tif m.%s != nil {\n\t\tfor _, v := range %s {\n\t\t\tif v == *m.%s {\n\t\t\t\treturn v\n\t\t\t}\n\t\t}\n\t}\n\treturn %s\n}\n\n", f.name, e.vocab, f.name, e.def)
			}
		}
		for _, f := range m.fields {
			if genreFields[[2]string{m.name, f.key}] {
				w("// EffectiveGenres is Genres as a reader reads them (SPEC.md § 7.1): one it does not know is other.\nfunc (m %s) EffectiveGenres() []string {\n", m.name)
				w("\tvar out []string\n\tseen := map[string]bool{}\n\tfor _, g := range m.Genres {\n\t\tif !contains(Genres, g) {\n\t\t\tg = \"other\"\n\t\t}\n\t\tif !seen[g] {\n\t\t\tseen[g] = true\n\t\t\tout = append(out, g)\n\t\t}\n\t}\n\treturn out\n}\n\n")
			}
		}
	}
	w(`// RequiredData is a file the user supplies, or a group of alternatives (one_of) (SPEC.md § 8.6): one of File and Group is set.
type RequiredData struct {
	File  *RequiredFile
	Group *RequiredDataGroup
}

// UnmarshalJSON reads a group when the object has one_of, a file otherwise.
func (d *RequiredData) UnmarshalJSON(data []byte) error {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil || probe == nil {
		return &model.Error{Where: "RequiredData", Reason: "not an object"}
	}
	*d = RequiredData{}
	if _, ok := probe["one_of"]; ok {
		d.Group = new(RequiredDataGroup)
		return d.Group.UnmarshalJSON(data)
	}
	d.File = new(RequiredFile)
	return d.File.UnmarshalJSON(data)
}

// MarshalJSON writes whichever of File and Group is set.
func (d RequiredData) MarshalJSON() ([]byte, error) {
	if d.Group != nil {
		return d.Group.MarshalJSON()
	}
	if d.File != nil {
		return d.File.MarshalJSON()
	}
	return []byte("null"), nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// DocumentNames are the documents of spec/schemas/v1 (common.json aside), sorted.
var DocumentNames = []string{
`)
	for _, d := range g.docOrder {
		w("\t%q,\n", d)
	}
	w("}\n\n// NewDocument is a pointer to a new, empty model of the document spec/schemas/v1/<name>.json, or nil.\nfunc NewDocument(name string) any {\n\tswitch name {\n")
	for _, d := range g.docOrder {
		w("\tcase %q:\n\t\treturn new(%s)\n", d, g.documents[d])
	}
	w("\t}\n\treturn nil\n}\n")
	return b.String()
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	// Keep an acronym or a name as it is: only a capital followed by a lower-case letter is lowered.
	if len(s) > 1 && s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'a' && s[1] <= 'z' {
		return strings.ToLower(s[:1]) + s[1:]
	}
	return s
}

func generated(folder string) (map[string][]byte, error) {
	g, err := newGenerator(folder)
	if err != nil {
		return nil, err
	}
	g.run()
	src, err := format.Source([]byte(g.source()))
	if err != nil {
		return nil, fmt.Errorf("gen: %w\n%s", err, g.source())
	}
	files := map[string][]byte{"models_gen.go": src}
	schemas, _ := filepath.Glob(filepath.Join(folder, "*.json"))
	for _, p := range schemas {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		files["schema/v1/"+filepath.Base(p)] = raw
	}
	return files, nil
}

func main() {
	check := flag.Bool("check", false, "exit 1 when the committed files are stale")
	schemas := flag.String("schemas", "../spec/schemas/v1", "the specification's schemas")
	out := flag.String("out", ".", "the module's folder")
	flag.Parse()
	files, err := generated(*schemas)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(2)
	}
	var stale []string
	for rel, content := range files {
		path := filepath.Join(*out, rel)
		if current, err := os.ReadFile(path); err != nil || !bytes.Equal(current, content) {
			stale = append(stale, rel)
			if !*check {
				_ = os.MkdirAll(filepath.Dir(path), 0o755)
				if err := os.WriteFile(path, content, 0o644); err != nil {
					fmt.Fprintln(os.Stderr, "gen:", err)
					os.Exit(2)
				}
			}
		}
	}
	existing, _ := filepath.Glob(filepath.Join(*out, "schema", "v1", "*.json"))
	for _, p := range existing {
		rel, _ := filepath.Rel(*out, p)
		rel = filepath.ToSlash(rel)
		if _, ok := files[rel]; !ok {
			stale = append(stale, rel)
			if !*check {
				_ = os.Remove(p)
			}
		}
	}
	sort.Strings(stale)
	if *check {
		for _, rel := range stale {
			fmt.Fprintf(os.Stderr, "gen: %s is stale: run go generate ./...\n", rel)
		}
		if len(stale) > 0 {
			os.Exit(1)
		}
		return
	}
	fmt.Printf("gen: %d files, %d written or removed\n", len(files), len(stale))
}
