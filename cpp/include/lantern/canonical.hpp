// Canonical JSON (SPEC.md § 2.3): RFC 8785's JSON Canonicalization Scheme.
// No space; the members of each object sorted by their names as UTF-16
// code units; in strings, only `"`, `\` and the control characters escaped
// (`\b`, `\t`, `\n`, `\f`, `\r`, the others as `\u00xx` in lower case);
// numbers as ECMAScript writes them: an integer without a fraction or an
// exponent (`1.0` and `1` are both `1`, `-0` is `0`), any other in the
// shortest form that reads back the same number (`0.5`, `1e+21`, `1e-7`,
// but `100000000000000000000` and `0.000001`). Sync's merge rule (§ 20.4)
// compares values by these bytes, and a chunk index (§ 22.1) is written in
// them.
#pragma once

#include <string_view>

#include <lantern/error.hpp>
#include <lantern/json.hpp>
#include <lantern/memory.hpp>

namespace lantern
{

// A JSON number, as the document wrote it, written as ECMAScript writes
// numbers and appended to `out`. An error (Category::invalid_response) for
// a text that is not a JSON number, or a number beyond a double's range
// (which I-JSON does not allow).
[[nodiscard]] Result<void> canonical_number(std::string_view number, String& out);

// A parsed value, appended to `out` in canonical form. An error for an
// object with a member name twice, or a number as above.
[[nodiscard]] Result<void> write_canonical_json(
    const json::Value& value, String& out, Allocator allocator = {});

// The canonical JSON of a document, as UTF-8 bytes in a string. An error
// for a document that does not parse within `limits`, an object with a key
// twice, or a number beyond a double's range.
[[nodiscard]] Result<String> canonical_json(
    std::string_view json, Allocator allocator = {}, const json::Limits& limits = {});

} // namespace lantern
