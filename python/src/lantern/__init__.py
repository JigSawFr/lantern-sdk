"""Lantern: client and server library for the Lantern protocol, between
console homebrews and the game library servers people run at home.

Follows the specification's draft 0.3 (SPEC_DRAFT).
"""

from lantern._base import SCHEMA, DocumentError, JSONObject, JSONValue, LanternError
from lantern._version import SPEC_DRAFT, __version__

__all__ = ["SCHEMA", "SPEC_DRAFT", "DocumentError", "JSONObject", "JSONValue", "LanternError", "__version__"]
