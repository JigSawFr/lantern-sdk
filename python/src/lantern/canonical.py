"""Canonical JSON (SPEC.md § 2.3): RFC 8785's JSON Canonicalization Scheme.
What sync's merge rule compares (§ 20.4) and what a chunk index is written
in (§ 22.1) are canonical bytes.

    canonical({"b": 1.0, "a": [1, 2]})        # b'{"a":[1,2],"b":1}'

No space; an object's members sorted by their names as UTF-16 code units
(not code points: U+FFFF comes after U+1F3AE, whose first unit is 0xD83C);
strings with only what JSON must escape escaped, the rest as it is; numbers
as ECMAScript writes them (`1.0` is `1`, `-0.0` is `0`, `1e21` is `1e+21`).
Test vectors: vectors/canonical-json.json.
"""

from __future__ import annotations

import json
import math
from decimal import Decimal

from lantern._base import JSONValue

#: The largest integer a double holds exactly (I-JSON, SPEC.md § 2.3).
INT_LIMIT = (1 << 53) - 1


def number(x: int | float) -> str:
    """A JSON number as ECMAScript writes it (RFC 8785 § 3.2.2.3): an integer without a fraction or an
    exponent, the others in their shortest form that reads back the same. ValueError for NaN, an infinity and
    a number beyond a double's range, which I-JSON does not have."""
    if isinstance(x, bool):
        raise TypeError("not a number")
    if isinstance(x, int) and abs(x) <= INT_LIMIT:
        return str(x)
    try:
        x = float(x)
    except OverflowError:
        raise ValueError("a number beyond a double's range is not I-JSON") from None
    if math.isnan(x) or math.isinf(x):
        raise ValueError("JSON has no NaN nor infinity")
    if x == 0:
        return "0"
    t = Decimal(repr(abs(x))).as_tuple()  # repr: the shortest digits that read back the same
    whole = "".join(map(str, t.digits))
    digits = whole.rstrip("0") or "0"
    n, k = len(whole) + int(t.exponent), len(digits)  # the value is 0.<digits> x 10^n
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * -n + digits
    else:
        body = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if n > 0 else "-") + str(abs(n - 1))
    return ("-" if x < 0 else "") + body


class _Raw(str):
    """A piece of punctuation already written."""


def text(value: JSONValue) -> str:
    """`value`'s canonical JSON as text, written without recursion: a value nested deep does not overflow the
    stack. TypeError for what JSON does not have."""
    out: list[str] = []
    stack: list[object] = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, _Raw):
            out.append(v)
        elif v is None or isinstance(v, bool):
            out.append({None: "null", True: "true", False: "false"}[v])
        elif isinstance(v, str):
            out.append(json.dumps(v, ensure_ascii=False))
        elif isinstance(v, int | float):
            out.append(number(v))
        elif isinstance(v, list):
            parts: list[object] = [_Raw("[")]
            for i, item in enumerate(v):
                if i:
                    parts.append(_Raw(","))
                parts.append(item)
            stack.extend(reversed([*parts, _Raw("]")]))
        elif isinstance(v, dict):
            keys = sorted(v, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
            parts = [_Raw("{")]
            for i, k in enumerate(keys):
                parts += [_Raw(("," if i else "") + json.dumps(k, ensure_ascii=False) + ":"), v[k]]
            stack.extend(reversed([*parts, _Raw("}")]))
        else:
            raise TypeError(f"not JSON: {type(v).__name__}")
    return "".join(out)


def canonical(value: JSONValue) -> bytes:
    """`value`'s canonical JSON, in UTF-8 (SPEC.md § 2.3)."""
    return text(value).encode("utf-8")


__all__ = ["INT_LIMIT", "canonical", "number", "text"]
