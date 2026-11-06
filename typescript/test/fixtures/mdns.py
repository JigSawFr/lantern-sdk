"""The reference server's DNS-SD responders (spec/server/mdns.py) on loopback, for the client's browse:
one for a server and one for a peer, each on a port of its own. Prints one JSON line when ready."""

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "spec", "server"))
import mdns  # noqa: E402

UID = "6f1c2a8e-0000-4000-8000-000000000001"
server_port, peer_port = int(sys.argv[1]), int(sys.argv[2])
server = mdns.Responder(
    "_lantern._tcp", "Living room shelf", 8443, {"uid": UID, "path": "/api/lantern", "v": "1"},
    "lantern-6f1c2a8e", "192.168.1.20", server_port, "127.0.0.1",
).serve()
peer = mdns.Responder(
    "_lantern-peer._tcp", "Den console", 47116, {"servers": UID, "path": "/peer", "v": "1", "tls": "1"},
    "peer-den", "192.168.1.30", peer_port, "127.0.0.1",
).serve()
print(json.dumps({"uid": UID}), flush=True)
try:
    while True:
        time.sleep(1)
finally:
    server.close()
    peer.close()
