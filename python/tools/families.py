"""The families the Python toolkit's demo offers a caller who holds every scope, as JSON: what the SDK's table
of families (README.md) is checked against (tools/check_matrix.py). Run from python/."""

from __future__ import annotations

import json
import sys

sys.path.insert(0, "tests")

from demo import EVERY_SCOPE, demo_accounts, make_lantern
from lantern.server.library import Account
from lantern.vocabulary import FAMILIES

offered = make_lantern(accounts=demo_accounts()).features(Account(scopes=frozenset(EVERY_SCOPE)))
print(json.dumps({"families": list(FAMILIES), "server": [f for f in FAMILIES if offered.get(f)]}))
