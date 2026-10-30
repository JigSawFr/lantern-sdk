"""The server toolkit: what a server author needs to add Lantern to an
existing app. LanternApp answers the read routes over a Library the app
implements (MemoryLibrary is one); the pieces it is made of (problem+json,
cursors, files with ranges and digests, the platform filter, the handshake)
are usable on their own. Flask and FastAPI adapters are in
lantern.server.flask and lantern.server.fastapi (their extras)."""

from lantern.server.app import LanternApp, missing
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

__all__ = [
    "Account",
    "Authenticate",
    "Cursors",
    "FileRef",
    "Journal",
    "LanternApp",
    "Library",
    "MemoryLibrary",
    "ProblemError",
    "Sealer",
    "ServerRequest",
    "ServerResponse",
    "SinceTokens",
    "check_homebrew",
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
