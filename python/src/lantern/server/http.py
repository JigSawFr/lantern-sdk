"""The server toolkit's HTTP layer, independent of any framework: a request
as an adapter hands it over, a response as it hands it back, problem+json
errors (SPEC.md § 12), JSON documents with their ETag and caching headers
(SPEC.md § 14), the platform a client names (SPEC.md § 4.3), and request
documents read by the `schema` rule (SPEC.md § 3.2)."""

from __future__ import annotations

import gzip
import hashlib
import json
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from urllib.parse import quote, urlencode

from lantern._base import SCHEMA, DocumentError, JSONObject
from lantern.http import JSON, PLATFORM_HEADER, PROBLEM_JSON, Headers, accept_languages, media_type
from lantern.limits import load_json
from lantern.signatures import received_uri
from lantern.vocabulary import is_platform

#: A request document's largest body here, well within SPEC.md § 13's 32 MiB.
BODY_LIMIT = 1 << 20
CHALLENGE = 'Bearer realm="lantern"'
TITLES = {
    400: "Bad request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not found",
    405: "Method not allowed",
    409: "Conflict",
    410: "Gone",
    413: "Too large",
    416: "Range not satisfiable",
    422: "Unprocessable",
    429: "Slow down",
    500: "Internal error",
    503: "Unavailable",
}
PROBLEM_TYPE = "https://lantern.boreale.dev/errors/"
#: The language of the toolkit's own texts (titles and details of errors): English (SPEC.md § 2.2).
LANGUAGE = "en"


@dataclass
class ServerRequest:
    """A request, as a framework adapter hands it to the toolkit: the path
    (decoded, without the query), the query's parameters (the last value of
    each), the headers and the body (read only for the routes that take one);
    then the scheme it came by, its request target as sent (path and query,
    their percent-encoding unchanged: a signature covers it, SPEC.md § 5.4),
    and the caller's address (for the limits of pairing, § 5.2)."""

    method: str
    path: str
    query: Mapping[str, str] = field(default_factory=dict)
    headers: Headers = field(default_factory=Headers)
    body: bytes = b""
    scheme: str = "https"
    target: str = ""
    remote: str = ""

    def header(self, name: str) -> str | None:
        return self.headers.get(name)

    @property
    def raw_target(self) -> str:
        """The request target as sent; rebuilt from path and query when the adapter gave none."""
        if self.target:
            return self.target
        query = urlencode(list(self.query.items()), quote_via=quote)
        return quote(self.path, safe="/:@!$&'()*+,;=-._~") + (f"?{query}" if query else "")

    def target_uri(self, scheme: str | None = None) -> str:
        """`@target-uri` (SPEC.md § 5.4): the scheme, the Host header, the target as sent."""
        return received_uri(scheme or self.scheme, self.header("Host") or "", self.raw_target)

    def origin(self, scheme: str | None = None) -> str:
        """`<scheme>://<Host>`: where the server's own pages are, for the documents it writes."""
        uri = self.target_uri(scheme)
        return uri[: uri.index("/", uri.index("//") + 2)]

    @property
    def languages(self) -> list[str]:
        """Accept-Language, best first."""
        return accept_languages(self.header("Accept-Language"))


@dataclass
class FileBody:
    """A response's body read from a file: `length` bytes from `start`."""

    path: str
    start: int
    length: int
    chunk: int = 1 << 20

    def __iter__(self) -> Iterator[bytes]:
        left = self.length
        with open(self.path, "rb") as f:
            f.seek(self.start)
            while left > 0:
                data = f.read(min(self.chunk, left))
                if not data:  # the file shrank under us: stop rather than lie about the length
                    return
                left -= len(data)
                yield data


@dataclass
class ServerResponse:
    """A response for an adapter to send. `body` is bytes, or a FileBody to
    stream; Content-Length is always among the headers, HEAD included (whose
    body is empty)."""

    status: int
    headers: Headers = field(default_factory=Headers)
    body: bytes | FileBody = b""

    def iter_body(self) -> Iterator[bytes]:
        if isinstance(self.body, bytes):
            if self.body:
                yield self.body
        else:
            yield from self.body


class ProblemError(Exception):
    """Raise it in a handler: answered as application/problem+json (SPEC.md § 12)."""

    def __init__(
        self,
        status: int,
        code: str,
        detail: str | None = None,
        *,
        title: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(f"{status} {code}: {detail or ''}")
        self.status, self.code, self.detail = status, code, detail
        self.title = title or TITLES.get(status, "Error")
        self.headers = dict(headers or {})

    def document(self) -> JSONObject:
        doc: JSONObject = {
            "schema": SCHEMA,
            "type": PROBLEM_TYPE + self.code.replace("_", "-"),
            "title": self.title,
            "status": self.status,
            "code": self.code,
        }
        if self.detail:
            doc["detail"] = self.detail
        doc["language"] = LANGUAGE
        return doc


def bad_request(detail: str) -> ProblemError:
    return ProblemError(400, "bad_request", detail)


def not_found(detail: str = "Not on this server.") -> ProblemError:
    return ProblemError(404, "not_found", detail)


def gone(detail: str) -> ProblemError:
    return ProblemError(410, "gone", detail)


def unauthorized(detail: str, *, invalid_token: bool = False) -> ProblemError:
    challenge = CHALLENGE + (', error="invalid_token"' if invalid_token else "")
    return ProblemError(401, "unauthorized", detail, headers={"WWW-Authenticate": challenge})


def method_not_allowed(allowed: list[str]) -> ProblemError:
    return ProblemError(
        405,
        "bad_request",
        "This route does not take that method.",
        title="Method not allowed",
        headers={"Allow": ", ".join(allowed)},
    )


def caching_headers(request: ServerRequest) -> Headers:
    """Vary and Cache-Control for an answer to `request` (SPEC.md § 14)."""
    h = Headers({"Vary": f"Authorization, {PLATFORM_HEADER}, Accept-Language"})
    h["Cache-Control"] = "private" if request.header("Authorization") else "no-cache"
    return h


def problem_response(request: ServerRequest, error: ProblemError) -> ServerResponse:
    body = json.dumps(error.document(), ensure_ascii=False, separators=(",", ":")).encode()
    headers = caching_headers(request)
    headers.update(error.headers)
    headers["Content-Type"] = PROBLEM_JSON
    headers["Content-Language"] = LANGUAGE
    headers["Content-Length"] = str(len(body))
    return ServerResponse(error.status, headers, b"" if request.method == "HEAD" else body)


def _zstd() -> Callable[[bytes], bytes] | None:
    try:
        from compression import zstd  # type: ignore[import-not-found, unused-ignore]  # Python 3.14
    except ImportError:
        return None
    compress: Callable[[bytes], bytes] = zstd.compress
    return compress


def _gzip(data: bytes) -> bytes:
    return gzip.compress(data, compresslevel=6, mtime=0)


def content_coding(accept_encoding: str | None) -> str | None:
    """The coding a JSON answer takes for an Accept-Encoding (SPEC.md § 2.1):
    zstd when this Python has it, else gzip; None when the client asks for neither."""
    accepted: dict[str, float] = {}
    for part in (accept_encoding or "").split(","):
        name, _, params = part.strip().partition(";")
        q = 1.0
        for param in params.split(";"):
            key, _, value = param.strip().partition("=")
            if key.strip().lower() == "q":
                try:
                    q = float(value)
                except ValueError:
                    q = 0.0
        if name.strip():
            accepted[name.strip().lower()] = q
    for coding in ("zstd", "gzip"):
        if accepted.get(coding, accepted.get("*", 0.0)) > 0 and (coding != "zstd" or _zstd() is not None):
            return coding
    return None


#: JSON smaller than this goes as it is: compressing it would gain nothing.
COMPRESS_FROM = 512


def json_response(request: ServerRequest, document: JSONObject, status: int = 200) -> ServerResponse:
    """A JSON document, with a strong ETag on a 200 to GET or HEAD, honouring
    If-None-Match with 304 (SPEC.md § 14), and the caching headers: private
    to an authenticated caller, varying on Authorization, Lantern-Platform,
    Accept-Language and Accept-Encoding. It is compressed as Accept-Encoding
    asks (zstd on Python 3.14, gzip), with an ETag of its own (SPEC.md § 2.1)."""
    body = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()
    headers = caching_headers(request)
    headers["Vary"] += ", Accept-Encoding"
    headers["Content-Type"] = JSON
    coding = content_coding(request.header("Accept-Encoding")) if len(body) >= COMPRESS_FROM else None
    tag = hashlib.sha256(body).hexdigest()[:32]
    if coding is not None:
        compress = _zstd() if coding == "zstd" else _gzip
        assert compress is not None
        body = compress(body)
        headers["Content-Encoding"] = coding
        tag += "-" + coding
    if status == 200 and request.method in ("GET", "HEAD"):
        etag = f'"{tag}"'
        headers["ETag"] = etag
        if etag in [t.strip() for t in (request.header("If-None-Match") or "").split(",")]:
            del headers["Content-Type"]
            headers.pop("Content-Encoding", None)
            headers["Content-Length"] = "0"
            return ServerResponse(304, headers)
    headers["Content-Length"] = str(len(body))
    return ServerResponse(status, headers, b"" if request.method == "HEAD" else body)


def html_response(request: ServerRequest, page: str, status: int = 200) -> ServerResponse:
    """An HTML page of the server's own (its approval page), never cached, never framed."""
    body = page.encode()
    headers = Headers(
        {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "Content-Language": LANGUAGE,
            "Referrer-Policy": "no-referrer",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'",
            "Content-Length": str(len(body)),
        }
    )
    return ServerResponse(status, headers, b"" if request.method == "HEAD" else body)


def platform_of(request: ServerRequest, *, required: bool = False) -> str | None:
    """The platform the client named (SPEC.md § 4.3): ?platform=, else the
    Lantern-Platform header; None for every platform. 400 for a name that is
    not a platform's, or for none where `required`."""
    name = request.query.get("platform") or (request.header(PLATFORM_HEADER) or "").strip()
    if not name:
        if required:
            raise bad_request("Name a platform: Lantern-Platform or ?platform= (SPEC.md § 4.3).")
        return None
    if not is_platform(name):
        raise bad_request(f"{name[:40]!r} is not a platform's name.")
    return name


def read_document(request: ServerRequest, *, limit: int = BODY_LIMIT) -> JSONObject:
    """A client's JSON document (SPEC.md § 3.2, § 12): 413 above `limit`,
    400 when it is not JSON or has no integer `schema`, 422
    `unsupported_schema` for a schema this server cannot read."""
    if len(request.body) > limit:
        raise ProblemError(413, "too_large", f"At most {limit} bytes here.")
    if media_type(request.header("Content-Type")) != JSON:
        raise bad_request("The body is application/json.")
    try:
        doc = load_json(request.body, where="the body")
    except DocumentError as e:
        raise bad_request(f"The body is not a document this server can read: {e.reason}") from None
    schema = doc.get("schema") if isinstance(doc, dict) else None
    if not isinstance(doc, dict) or not isinstance(schema, int) or isinstance(schema, bool) or schema < 1:
        raise bad_request("The body is an object with an integer schema.")
    if schema > SCHEMA:
        raise ProblemError(
            422,
            "unsupported_schema",
            f"This server reads schema {SCHEMA} here, not {schema}.",
            title="Unsupported schema",
        )
    return doc
