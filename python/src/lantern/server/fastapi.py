"""Lantern in a FastAPI (or Starlette) app (the `fastapi` extra).

    from fastapi import FastAPI
    from lantern.server.app import LanternApp
    from lantern.server.fastapi import include

    app = FastAPI()
    include(app, LanternApp(library, uid=SERVER_UID, name="Living room shelf"))

The toolkit's handlers are synchronous (a Library may read a database or a
disk): they run in Starlette's thread pool, and files are streamed from it.
"""

from __future__ import annotations

from fastapi import FastAPI
from starlette.concurrency import iterate_in_threadpool, run_in_threadpool
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse

from lantern.http import Headers
from lantern.server.app import LanternApp
from lantern.server.http import BODY_LIMIT, ProblemError, ServerRequest, ServerResponse, problem_response

METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
_WITH_BODY = ("POST", "PUT", "PATCH")
#: A body above the limit is still read, and dropped, up to this: the client then gets its 413.
DRAIN = 4 << 20


async def to_request(req: Request, body_limit: int = BODY_LIMIT) -> ServerRequest | ServerResponse:
    """The toolkit's request from Starlette's, its body read up to `body_limit`
    (a response, 413, when it is larger)."""
    query = {k: req.query_params.getlist(k)[-1] for k in req.query_params}
    raw_path = req.scope.get("raw_path") or req.url.path.encode()
    raw_query = req.scope.get("query_string") or b""
    target = raw_path.decode("latin-1") + (f"?{raw_query.decode('latin-1')}" if raw_query else "")
    out = ServerRequest(
        req.method,
        req.url.path,
        query,
        Headers(req.headers.items()),
        scheme=req.url.scheme,
        target=target,
        remote=req.client.host if req.client else "",
    )
    if req.method in _WITH_BODY:
        too_large = problem_response(out, ProblemError(413, "too_large", f"At most {body_limit} bytes here."))
        length = req.headers.get("content-length")
        if length is not None and length.isdigit() and int(length) > max(body_limit, DRAIN):
            return too_large  # too much to read: the connection is closed
        data = bytearray()
        seen = 0
        async for chunk in req.stream():
            seen += len(chunk)
            if seen <= body_limit:
                data += chunk
            elif seen > max(body_limit, DRAIN):
                return too_large
        if seen > body_limit:
            return too_large  # read to its end, so that the client gets the answer rather than a reset
        out.body = bytes(data)
    return out


def to_response(resp: ServerResponse) -> Response:
    headers = dict(resp.headers.items())
    if isinstance(resp.body, bytes):
        return Response(resp.body, status_code=resp.status, headers=headers)
    return StreamingResponse(iterate_in_threadpool(iter(resp.body)), status_code=resp.status, headers=headers)


def include(app: FastAPI, lantern: LanternApp, *, body_limit: int = BODY_LIMIT) -> None:
    """Serve `lantern`'s routes from `app` (left out of its OpenAPI schema)."""

    async def endpoint(request: Request) -> Response:
        converted = await to_request(request, body_limit)
        if isinstance(converted, ServerResponse):
            return to_response(converted)
        return to_response(await run_in_threadpool(lantern.handle, converted))

    paths = ["/.well-known/lantern", lantern.base + "/v1", lantern.base + "/v1/{rest:path}"]
    if lantern.verify_path is not None and lantern.pair_page is None:
        paths.append(lantern.verify_path)
    for path in paths:
        app.add_api_route(path, endpoint, methods=METHODS, include_in_schema=False)
