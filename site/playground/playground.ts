// The SDK's page runs the SDK: LanternClient (the library's client) talks to LanternApp (its server) over a made-up
// library, both in this page. Nothing goes over the network: an in-page Transport hands each request to the server's
// fetchHandler(). The bundle is built by tools/build_playground.mjs (site/assets/sdk-playground.js).
import {
  type App,
  LanternClient,
  MemorySink,
  type Transport,
  type TransportRequest,
  type TransportResponse,
} from "../../typescript/src/index.ts";
import { fetchHandler, LanternApp, MemoryLibrary } from "../../typescript/src/server/index.ts";

const GAMES: [name: string, number: number, version: string, update: [number, string] | null][] = [
  ["Frostline Tales", 1, "1.0.0", [196608, "1.3.0"]],
  ["Moss & Ember", 2, "1.0.0", [65536, "1.1.0"]],
  ["Cinder Harbor", 3, "1.2.0", null],
  ["Paper Comet", 4, "1.0.1", null],
  ["Tidepool Racers", 5, "1.0.0", [131072, "1.2.0"]],
];

function makeApp(): LanternApp {
  const library = new MemoryLibrary({ base: "/api/lantern" });
  const text = new TextEncoder();
  for (const [name, number, version, update] of GAMES) {
    const title = `0100ABCD${number.toString(16).toUpperCase().padStart(4, "0")}0000`;
    library.addAppFile({
      data: text.encode(`${name} ${version}: a made-up game`.repeat(40)),
      platform: "switch",
      title_id: title,
      app_id: title,
      type: "base",
      version_code: 0,
      version_name: version,
      name,
      format: "nsp",
    });
    if (update !== null) {
      library.addAppFile({
        data: text.encode(`${name} ${update[1]}: a made-up update`.repeat(30)),
        platform: "switch",
        title_id: title,
        app_id: `${title.slice(0, 13)}800`,
        type: "update",
        version_code: update[0],
        version_name: update[1],
        name,
        format: "nsp",
      });
    }
  }
  return new LanternApp(library, { uid: "3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f", name: "Living room shelf" });
}

/** What a step did on the wire: the method, the path and the status of each request. */
export interface Request1 {
  method: string;
  path: string;
  status: number;
}

/** A Transport that gives each request to the server in this page, and notes it. */
class InPage implements Transport {
  readonly seen: Request1[] = [];
  readonly #handler: (request: Request) => Promise<Response>;
  constructor(handler: (request: Request) => Promise<Response>) {
    this.#handler = handler;
  }
  async send(request: TransportRequest): Promise<TransportResponse> {
    const init: RequestInit = { method: request.method, headers: request.headers };
    if (request.body !== undefined) init.body = request.body as BodyInit;
    const response = await this.#handler(new Request(request.url, init));
    const url = new URL(request.url);
    // a cursor is sealed and long: its first and last signs say enough
    this.seen.push({ method: request.method, path: (url.pathname + url.search).replace(/cursor=[^&]+/, "cursor=…"), status: response.status });
    const bytes = new Uint8Array(await response.arrayBuffer());
    return {
      status: response.status,
      headers: response.headers,
      async *body() {
        if (bytes.length > 0) yield bytes;
      },
      async cancel() {},
    };
  }
}

export interface Step {
  /** The code the step runs, as the reader would write it. */
  code: string;
  requests: Request1[];
  result: unknown;
}

/** Runs the four steps in turn on a fresh server; each one's requests are those it made. */
export async function run(): Promise<Step[]> {
  const transport = new InPage(fetchHandler(makeApp()));
  const client = new LanternClient("https://shelf.example.org/", { platform: "switch", transport });
  const steps: Step[] = [];
  const step = async (code: string, body: () => Promise<unknown>): Promise<unknown> => {
    transport.seen.length = 0;
    const result = await body();
    steps.push({ code, requests: [...transport.seen], result });
    return result;
  };

  await step(`const hello = await client.handshake();`, async () => {
    const hello = await client.handshake();
    return { name: hello.name, draft: hello.draft, families: Object.keys(hello.features).sort() };
  });

  const apps: App[] = [];
  await step(
    `for await (const app of client.iterApps({ pageSize: 3 })) apps.push(app);`,
    async () => {
      for await (const app of client.iterApps({ pageSize: 3 })) apps.push(app);
      return apps.map((a) => ({ name: a.name, type: a.type, version: a.version_name, size: a.size }));
    },
  );

  const base = apps.find((a) => a.type === "base" && a.name === "Frostline Tales");
  await step(`// a console that holds Frostline Tales 1.0.0\nconst page = await client.missing([[base.app_id, 0]]);`, async () => {
    if (base === undefined) return [];
    const page = await client.missing([[base.app_id, 0]]);
    return page.items.map((a) => ({ name: a.name, type: a.type, version: a.version_name }));
  });

  const smallest = [...apps].sort((a, b) => a.size - b.size)[0];
  await step(`const saved = await client.downloadApp(smallest, new MemorySink());`, async () => {
    if (smallest === undefined) return null;
    const sink = new MemorySink();
    await client.downloadApp(smallest, sink);
    return { name: smallest.name, bytes: smallest.size, sha256: `${smallest.sha256.slice(0, 16)}… matched` };
  });

  await client.close();
  return steps;
}
