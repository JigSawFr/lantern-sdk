/**
 * Events on the server's side (SPEC.md § 18): a journal of events kept in
 * memory, whose ids are tokens of /v1/changes (the stream and `changes?since=`
 * share them), the streams it feeds (Server-Sent Events, never compressed,
 * a heartbeat at least every `limits.heartbeat` seconds) and long polls.
 *
 * LanternApp writes the events of what it does (a pairing waiting, a sync
 * collection changed, a library that changed when its Library tells it) and
 * `app.emit()` those of the server's own families; each caller gets only what
 * its token may read (§ 18.2): of its scopes and account, of its platform, and
 * within its rating cap.
 */

import { randomBytes } from "node:crypto";
import { toBase64Url } from "../bytes.ts";

/** Who may see an event, beside the scope its type needs. */
export interface Audience {
  /** The scope a caller needs, when not its type's (an event of the server's own). */
  scope?: string;
  /** The account it is for (a request's, a save's, sync's). */
  user?: string;
  /** The platform it is of, when one. */
  platform?: string;
  /** A title it is of: hidden from a caller whose rating cap hides it (§ 5.6). */
  titleId?: string;
}

/** What changed in a library, for the event `library` (§ 18.2): a family, a platform, the title or ratings it reads by. */
export interface LibraryChange {
  family: "apps" | "titles" | "homebrew" | "cheats";
  platform: string;
  /** The title a rating cap reads it by (apps, titles, cheat sets). */
  titleId?: string;
  /** Its own ratings (homebrew), when a cap reads them. */
  ratings?: readonly { system: string; rating: string }[];
}

/** An event kept: its place in the journal, its type, its data, and who may see it. */
export interface HubEvent {
  seq: number;
  event: string;
  data: Record<string, unknown>;
  audience: Audience;
  changes: LibraryChange[];
  /** The library journal's position when it was written: its id resumes /v1/changes from there. */
  position: number;
}

/** The scope each event needs (§ 18.2); `ready` and `shutdown` go to every stream. */
export const EVENT_SCOPES: Readonly<Record<string, string>> = {
  library: "library",
  request: "requests",
  save: "saves",
  pairing: "admin",
  sync: "sync.read",
};

/** The journal of events, and what streams and long polls wait on. */
export class EventHub {
  /** Changes when the process starts again: an id of another epoch is too old (410). */
  readonly epoch = toBase64Url(randomBytes(6));
  readonly limit: number;
  #seq = 0;
  #floor = 0;
  #events: HubEvent[] = [];
  #waiters = new Set<() => void>();
  #stopping = false;

  constructor(limit = 10000) {
    this.limit = limit;
  }

  get seq(): number {
    return this.#seq;
  }

  /** The oldest event an id may resume after. */
  get floor(): number {
    return this.#floor;
  }

  get stopping(): boolean {
    return this.#stopping;
  }

  /** Records an event; its place in the journal. */
  emit(
    event: string,
    data: Record<string, unknown>,
    audience: Audience = {},
    changes: LibraryChange[] = [],
    position = 0,
  ): number {
    const seq = ++this.#seq;
    this.#events.push({ seq, event, data: { schema: 1, ...data }, audience, changes, position });
    if (this.#events.length > this.limit) {
      const dropped = this.#events.splice(0, this.#events.length - this.limit);
      this.#floor = Math.max(this.#floor, dropped.at(-1)?.seq ?? 0);
    }
    this.wake();
    return seq;
  }

  /** The events after `seq`, in order. */
  after(seq: number): HubEvent[] {
    return this.#events.filter((e) => e.seq > seq);
  }

  /** Wakes every stream and long poll: an event came, or an account changed (a stream checks its token again). */
  wake(): void {
    const waiters = [...this.#waiters];
    this.#waiters.clear();
    for (const w of waiters) w();
  }

  /** Waits until the next wake, `ms` at most, or `signal`. */
  wait(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve) => {
      if (signal?.aborted || this.#stopping) return resolve();
      const done = (): void => {
        clearTimeout(timer);
        this.#waiters.delete(done);
        signal?.removeEventListener("abort", done);
        resolve();
      };
      const timer = setTimeout(done, Math.max(0, ms));
      this.#waiters.add(done);
      signal?.addEventListener("abort", done);
    });
  }

  /** The server stops: every stream gets `shutdown`, then ends (§ 18.2, L-18.2-2). */
  shutdown(retry = 30): void {
    if (this.#stopping) return;
    this.emit("shutdown", { retry });
    this.#stopping = true;
    this.wake();
  }
}

/** An event as the stream writes it: its id, its type and its data on one line. */
export function sseEvent(id: string, event: string, data: unknown): string {
  return `id: ${id}\nevent: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}
