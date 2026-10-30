"""Lantern: client and server library for the Lantern protocol, between
console homebrews and the game library servers people run at home.

    import lantern

    with lantern.LanternClient("https://shelf.example.org/", platform="switch") as client:
        for app in client.iter_apps():
            print(app.name, app.version_code)

- lantern.LanternClient, lantern.AsyncLanternClient: the client (read side);
- lantern.models: the documents, generated from the specification's schemas;
- lantern.homebrew, lantern.profiles, lantern.digest, lantern.pinning: what a
  client checks before it installs anything;
- lantern.server: the toolkit a server is built with (Flask and FastAPI
  adapters in lantern.server.flask and lantern.server.fastapi);
- lantern.schema, lantern.limits, lantern.store: validation, SPEC.md § 13's
  limits, and files kept by the `schema` rule.

Follows the specification's draft 0.3 (SPEC_DRAFT).
"""

from lantern._base import SCHEMA, DocumentError, JSONObject, JSONValue, LanternError
from lantern._version import SPEC_DRAFT, __version__
from lantern.client import AsyncLanternClient, BearerToken, LanternClient
from lantern.errors import (
    AccountFrozen,
    BadRequest,
    Conflict,
    Forbidden,
    Gone,
    InsecureTransport,
    IntegrityError,
    NewerSchema,
    NotFound,
    ProblemError,
    ServerError,
    SlowDown,
    TooLarge,
    TransportError,
    Unauthorized,
    Unavailable,
    UnexpectedResponse,
    Unprocessable,
)

__all__ = [
    "SCHEMA",
    "SPEC_DRAFT",
    "AccountFrozen",
    "AsyncLanternClient",
    "BadRequest",
    "BearerToken",
    "Conflict",
    "DocumentError",
    "Forbidden",
    "Gone",
    "InsecureTransport",
    "IntegrityError",
    "JSONObject",
    "JSONValue",
    "LanternClient",
    "LanternError",
    "NewerSchema",
    "NotFound",
    "ProblemError",
    "ServerError",
    "SlowDown",
    "TooLarge",
    "TransportError",
    "Unauthorized",
    "Unavailable",
    "UnexpectedResponse",
    "Unprocessable",
    "__version__",
]
