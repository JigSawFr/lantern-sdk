"""The server toolkit: what a server author needs to add Lantern to an
existing app. LanternApp answers the routes over a Library the app
implements (MemoryLibrary is one) and, with an Accounts store (MemoryAccounts
is one; SqliteAccounts keeps its pairings across a restart), pairs devices,
checks signed requests, redeems invitations, applies rating caps and answers the administration API; with a SaveStore
(MemorySaveStore, FileSaveStore) it keeps save backups, encrypted ones
among them, and with a RequestStore (MemoryRequests) requests for games. The pieces it is made of
(problem+json, cursors, files with ranges and digests, the platform filter,
the handshake, the pairing desk, LAN discovery) are usable on their own.
Flask and FastAPI adapters are in lantern.server.flask and
lantern.server.fastapi (their extras)."""

from lantern.missing import missing
from lantern.server.accounts import UNSET, AccountError, Accounts, Device, Invitation, MemoryAccounts, User
from lantern.server.app import LanternApp, check_content_digest
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
    DELTAS_MAX,
    DELTAS_MIN,
    Account,
    Authenticate,
    ChangeLog,
    CheatWriter,
    ChunkSource,
    Journal,
    Library,
    MediaSource,
    MemoryLibrary,
    SectionSource,
    check_homebrew,
    make_package,
    zip_manifest,
)
from lantern.server.paging import Cursors, Sealer, SinceTokens, page_size
from lantern.server.pairing import Limiter, PairingDesk, Pending, approval_page
from lantern.server.saves import FileSaveStore, MemorySaveStore, SaveLimits, SaveStore, UploadSession
from lantern.server.secrets_file import SecretsFile, SecretsSchemaError
from lantern.server.sqlite_accounts import AccountsSchemaError, SqliteAccounts
from lantern.server.sqlite_journal import SqliteJournal
from lantern.server.sqlite_requests import SqliteRequests
from lantern.server.sqlite_sync import SqliteSync
from lantern.server.title_requests import MemoryRequests, RequestStore, StoredRequest

__all__ = [
    "DELTAS_MAX",
    "DELTAS_MIN",
    "UNSET",
    "Account",
    "AccountError",
    "Accounts",
    "AccountsSchemaError",
    "Authenticate",
    "ChangeLog",
    "CheatWriter",
    "ChunkSource",
    "Cursors",
    "Device",
    "DiscoveryResponder",
    "FileRef",
    "FileSaveStore",
    "Invitation",
    "Journal",
    "LanternApp",
    "Library",
    "Limiter",
    "MediaSource",
    "MemoryAccounts",
    "MemoryLibrary",
    "MemoryRequests",
    "MemorySaveStore",
    "PairingDesk",
    "Pending",
    "ProblemError",
    "RequestStore",
    "SaveLimits",
    "SaveStore",
    "Sealer",
    "SecretsFile",
    "SecretsSchemaError",
    "SectionSource",
    "ServerRequest",
    "ServerResponse",
    "SinceTokens",
    "SqliteAccounts",
    "SqliteJournal",
    "SqliteRequests",
    "SqliteSync",
    "StoredRequest",
    "UploadSession",
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
