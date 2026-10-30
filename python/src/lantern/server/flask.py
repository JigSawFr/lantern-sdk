"""Lantern in a Flask app (the `flask` extra).

    from flask import Flask
    from lantern.server.app import LanternApp
    from lantern.server.flask import init_app

    app = Flask(__name__)
    init_app(app, LanternApp(library, uid=SERVER_UID, name="Living room shelf"))

It adds the routes /.well-known/lantern, <base>/v1 and <base>/v1/<path>, for
every method (the toolkit answers 405 where a route does not take one).
"""

from __future__ import annotations

from urllib.parse import quote

import flask

from lantern.http import Headers
from lantern.server.app import LanternApp
from lantern.server.http import BODY_LIMIT, ProblemError, ServerRequest, ServerResponse, problem_response

METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
_WITH_BODY = ("POST", "PUT", "PATCH")


def to_request(req: flask.Request, body_limit: int = BODY_LIMIT) -> ServerRequest | ServerResponse:
    """The toolkit's request from Flask's, its body read up to `body_limit`
    (a response, 413, when it is larger)."""
    query = {k: req.args.getlist(k)[-1] for k in req.args}
    env = req.environ
    target = env.get("RAW_URI") or env.get("REQUEST_URI") or ""
    if not isinstance(target, str) or not target.startswith("/"):
        raw_query = env.get("QUERY_STRING") or ""
        target = quote(req.path, safe="/:@!$&'()*+,;=-._~") + (f"?{raw_query}" if raw_query else "")
    out = ServerRequest(
        req.method,
        req.path,
        query,
        Headers(list(req.headers.items())),
        scheme=req.scheme,
        target=target,
        remote=req.remote_addr or "",
    )
    if req.method in _WITH_BODY:
        if req.content_length is not None and req.content_length > body_limit:
            return problem_response(out, ProblemError(413, "too_large", f"At most {body_limit} bytes here."))
        data = req.stream.read(body_limit + 1)
        if len(data) > body_limit:
            return problem_response(out, ProblemError(413, "too_large", f"At most {body_limit} bytes here."))
        out.body = data
    return out


def to_response(resp: ServerResponse) -> flask.Response:
    out = flask.Response(resp.iter_body(), status=resp.status, direct_passthrough=True)
    out.headers.clear()
    for name, value in resp.headers.items():
        out.headers[name] = value
    return out


def init_app(app: flask.Flask, lantern: LanternApp, *, body_limit: int = BODY_LIMIT, endpoint: str = "lantern") -> None:
    """Serve `lantern`'s routes from `app`."""

    def view(rest: str = "") -> flask.Response:
        request = to_request(flask.request, body_limit)
        if isinstance(request, ServerResponse):
            return to_response(request)
        return to_response(lantern.handle(request))

    app.add_url_rule("/.well-known/lantern", f"{endpoint}_well_known", view, methods=METHODS)
    app.add_url_rule(lantern.base + "/v1", f"{endpoint}_v1", view, methods=METHODS, strict_slashes=True)
    app.add_url_rule(lantern.base + "/v1/", f"{endpoint}_v1_slash", view, methods=METHODS)
    app.add_url_rule(lantern.base + "/v1/<path:rest>", f"{endpoint}_routes", view, methods=METHODS)
    if lantern.verify_path is not None and lantern.pair_page is None:
        app.add_url_rule(lantern.verify_path, f"{endpoint}_pair", view, methods=METHODS)
