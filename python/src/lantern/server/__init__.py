"""The server toolkit: what a server author needs to add Lantern to an
existing app. LanternApp answers the routes over a Library the app
implements (MemoryLibrary is one) and, with an Accounts store (MemoryAccounts
is one), pairs devices, checks signed requests, redeems invitations, applies
rating caps and answers the administration API. The pieces it is made of
(problem+json, cursors, files with ranges and digests, the platform filter,
the handshake, the pairing desk, LAN discovery) are usable on their own.
Flask and FastAPI adapters are in lantern.server.flask and
lantern.server.fastapi (their extras)."""

from lantern.server.accounts import AccountError, Accounts, Device, Invitation, MemoryAccounts, User
from lantern.server.app import LanternApp, check_content_digest, missing
from lantern.server.discovery import DiscoveryResponder, advertise_dnssd, discovery_reply
from lantern.server.files import FileRef, file_response, parse_range
from lantern.server.http import (
    ProblemError,
    ServerRequest,
    ServerResponse,
    json_response,
    platform_of,
    problem_response,
    read_document,
)
from lantern.server.library import (
    Account,
    Authenticate,
    Journal,
    Library,
    MemoryLibrary,
    check_homebrew,
    make_package,
    zip_manifest,
)
from lantern.server.paging import Cursors, Sealer, SinceTokens, page_size
from lantern.server.pairing import Limiter, PairingDesk, Pending, approval_page

__all__ = [
    "Account",
    "AccountError",
    "Accounts",
    "Authenticate",
    "Cursors",
    "Device",
    "DiscoveryResponder",
    "FileRef",
    "Invitation",
    "Journal",
    "LanternApp",
    "Library",
    "Limiter",
    "MemoryAccounts",
    "MemoryLibrary",
    "PairingDesk",
    "Pending",
    "ProblemError",
    "Sealer",
    "ServerRequest",
    "ServerResponse",
    "SinceTokens",
    "User",
    "advertise_dnssd",
    "approval_page",
    "check_content_digest",
    "check_homebrew",
    "discovery_reply",
    "file_response",
    "json_response",
    "make_package",
    "missing",
    "page_size",
    "parse_range",
    "platform_of",
    "problem_response",
    "read_document",
    "zip_manifest",
]
