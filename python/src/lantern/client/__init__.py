"""The client side: LanternClient (sync, standard library by default) and
AsyncLanternClient (async, over httpx), their request pipeline, and what
pairing and signing need (DeviceSigner, Pairing, invitation links)."""

from lantern.client.aio import AsyncLanternClient
from lantern.client.auth import DeviceSigner, InvitationLink, Pairing, invitation_link
from lantern.client.core import Deprecation, what_fits
from lantern.client.stdlib import StdlibTransport
from lantern.client.streams import AsyncEventStream, EventStream
from lantern.client.sync import LanternClient
from lantern.client.transport import (
    AsyncResponse,
    AsyncTransport,
    BearerToken,
    Credentials,
    Request,
    RequestSigner,
    Response,
    Transport,
)

__all__ = [
    "AsyncEventStream",
    "AsyncLanternClient",
    "AsyncResponse",
    "AsyncTransport",
    "BearerToken",
    "Credentials",
    "Deprecation",
    "DeviceSigner",
    "EventStream",
    "InvitationLink",
    "LanternClient",
    "Pairing",
    "Request",
    "RequestSigner",
    "Response",
    "StdlibTransport",
    "Transport",
    "invitation_link",
    "what_fits",
]
