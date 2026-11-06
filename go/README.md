# Lantern for Go

[Lantern](https://lantern.boreale.dev/?utm_source=github&utm_medium=readme) in Go: the documents of the protocol as typed values, and (being built, a family at a time) a client and a server that mounts on any `http.Handler` router.

> [!NOTE]
> **Not usable as a client or a server yet.** This is the first slice: the documents, their checks and the shared building blocks. The client and the server follow, in the order of [the plan](https://github.com/JigSawFr/lantern-sdk#-families-by-language); the README's table says which family each language has.

```sh
go get github.com/JigSawFr/lantern-sdk/go
```

Go 1.24 or later, and nothing but the standard library.

## What is there

| Package | What it does |
|---|---|
| `lantern` | The specification's documents (`Handshake`, `Homebrew`, `AppsPage`…) generated from its JSON Schemas, with every field they do not know kept and written back; the vocabularies; the errors (`ProblemError`, tested with `errors.Is`); the `schema` rule; canonical JSON (RFC 8785); digests (`Repr-Digest`); the limits of SPEC.md § 13 and a JSON reader that keeps to them |
| `lantern/schema` | The specification's JSON Schemas, embedded, and a validator for them |

```go
raw := []byte(`{"schema": 1, "uid": "…", …}`)

h, err := lantern.Parse[lantern.Handshake](raw)
switch {
case errors.Is(err, lantern.ErrNewerSchema):
    // a document of a newer schema is absent, not an error (SPEC.md § 3.2)
case err != nil:
    // not a Handshake, or beyond SPEC.md § 13
default:
    fmt.Println(h.Name, h.Features["library"])
}

v, _ := lantern.LoadJSON(raw, lantern.LoadOptions{})
problems, _ := schema.Validate("handshake", v) // none when the document is valid
```

An optional field is a pointer (`nil` when absent), a required one a value. The fields a version does not know are in `Extra`, and `json.Marshal` writes them back.

## Developing

```sh
git submodule update --init   # the specification
go generate ./...             # the documents, after the schemas change
go test ./...
```

`go run ./internal/gen -check` fails when the generated files are not those of the pinned specification (CI runs it). The module's tags are `go/vX.Y.Z`, the SDK's version ([RELEASING.md](../RELEASING.md)).

MIT, like the rest of the SDK.
