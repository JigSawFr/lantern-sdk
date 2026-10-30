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


async def to_request(req: Request, body_limit: int = BODY_LIMIT) -> ServerRequest | ServerResponse:
    """The toolkit's request from Starlette's, its body read up to `body_limit`
    (a response, 413, when it is larger)."""
    query = {k: req.query_params.getlist(k)[-1] for k in req.query_params}
    out = ServerRequest(req.method, req.url.path, query, Headers(req.headers.items()))
    if req.method in _WITH_BODY:
        too_large = problem_response(out, ProblemError(413, "too_large", f"At most {body_limit} bytes here."))
        length = req.headers.get("content-length")
        if length is not None and length.isdigit() and int(length) > body_limit:
            return too_large
        data = bytearray()
        async for chunk in req.stream():
            data += chunk
            if len(data) > body_limit:
                return too_large
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

    for path in ("/.well-known/lantern", lantern.base + "/v1", lantern.base + "/v1/{rest:path}"):
        app.add_api_route(path, endpoint, methods=METHODS, include_in_schema=False)
