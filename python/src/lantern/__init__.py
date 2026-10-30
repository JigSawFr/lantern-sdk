"""Lantern: client and server library for the Lantern protocol, between
console homebrews and the game library servers people run at home.

    import lantern

    with lantern.LanternClient("https://shelf.example.org/", platform="switch") as client:
        for app in client.iter_apps():
            print(app.name, app.version_code)

- lantern.LanternClient, lantern.AsyncLanternClient: the client: pairing with
  a device key, signed requests, every route of the protocol;
- lantern.models: the documents, generated from the specification's schemas;
- lantern.homebrew, lantern.profiles, lantern.digest, lantern.pinning: what a
  client checks before it installs anything, and what it keeps of a server;
- lantern.signatures, lantern.spki, lantern.ratings, lantern.discovery: signed
  requests (RFC 9421), key fingerprints, rating caps, LAN discovery;
- lantern.events, lantern.grants, lantern.sync, lantern.e2e, lantern.static:
  event streams, grants and mirrors, sync's merge rule and consent,
  encrypted saves, and static libraries (read, and generated);
- lantern.peer: a minimal peer, which serves the files a console holds to
  the holders of a grant;
- lantern.server: the toolkit a server is built with (Flask and FastAPI
  adapters in lantern.server.flask and lantern.server.fastapi);
- lantern.schema, lantern.limits, lantern.store: validation, SPEC.md § 13's
  limits, and files kept by the `schema` rule.

Follows the specification's draft 0.5 (SPEC_DRAFT).
"""

from lantern._base import SCHEMA, DocumentError, JSONObject, JSONValue, LanternError
from lantern._version import SPEC_DRAFT, __version__
from lantern.client import AsyncLanternClient, BearerToken, LanternClient
from lantern.e2e import BadPhrase, RefusedBackup
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
    PinMismatch,
    PreconditionFailed,
    ProblemError,
    ServerError,
    SignatureExpired,
    SignatureInvalid,
    SignatureRefused,
    SignatureReplayed,
    SignatureRequired,
    SlowDown,
    TooLarge,
    TransportError,
    Unauthorized,
    Unavailable,
    UnexpectedResponse,
    Unprocessable,
)
from lantern.sync import ConsentRequired, SyncReset

__all__ = [
    "SCHEMA",
    "SPEC_DRAFT",
    "AccountFrozen",
    "AsyncLanternClient",
    "BadPhrase",
    "BadRequest",
    "BearerToken",
    "Conflict",
    "ConsentRequired",
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
    "PinMismatch",
    "PreconditionFailed",
    "ProblemError",
    "RefusedBackup",
    "ServerError",
    "SignatureExpired",
    "SignatureInvalid",
    "SignatureRefused",
    "SignatureReplayed",
    "SignatureRequired",
    "SlowDown",
    "SyncReset",
    "TooLarge",
    "TransportError",
    "Unauthorized",
    "Unavailable",
    "UnexpectedResponse",
    "Unprocessable",
    "__version__",
]
