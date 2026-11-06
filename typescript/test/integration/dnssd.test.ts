/**
 * DNS-SD against the specification's reference responders (spec/server/mdns.py,
 * started by test/fixtures/mdns.py on loopback): the single question a client
 * asks from a port of its own is answered straight back (RFC 6762 § 6.7), for a
 * server (`_lantern._tcp`) and for a peer (`_lantern-peer._tcp`).
 */

import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { browseDnssd, browseDnssdPeers } from "../../src/node/index.ts";
import { PACKAGE, type Served, servePython } from "../helpers.ts";

const SERVER_PORT = 25353;
const PEER_PORT = 25354;
let responders: Served<{ uid: string }>;

before(async () => {
  responders = await servePython(["test/fixtures/mdns.py", String(SERVER_PORT), String(PEER_PORT)], { cwd: PACKAGE });
});
after(async () => {
  await responders.stop();
});

describe("DNS-SD against the reference responders", () => {
  test("the server is found, with what its advertisement says", async () => {
    const found = await browseDnssd({ address: "127.0.0.1", port: SERVER_PORT, timeout: 0.6 });
    assert.deepEqual(found, [
      {
        address: "192.168.1.20",
        port: 8443,
        uid: responders.info.uid,
        name: "Living room shelf",
        base: "/api/lantern",
        versions: [1],
        url: "https://192.168.1.20:8443/",
      },
    ]);
  });

  test("the peer is found, and it takes the server's grants", async () => {
    const options = { address: "127.0.0.1", port: PEER_PORT, timeout: 0.6 };
    const peers = await browseDnssdPeers({ ...options, server: responders.info.uid });
    assert.equal(peers.length, 1);
    assert.equal(peers[0]?.url, "https://192.168.1.30:47116/peer");
    assert.deepEqual(peers[0]?.servers, [responders.info.uid]);
    assert.equal((await browseDnssdPeers({ ...options, server: "another" })).length, 0);
  });

  test("a responder is not another's: a server is not asked of peers", async () => {
    assert.deepEqual(await browseDnssd({ address: "127.0.0.1", port: PEER_PORT, timeout: 0.4 }), []);
  });
});
