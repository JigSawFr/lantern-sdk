/**
 * An event stream (SPEC.md § 18.1) a client holds: read over fetch() (or the
 * client's transport), parsed by a bounded SseParser, and opened again as the
 * text says when it ends or fails: after `retry` at least (L-18.1-9), with
 * `Last-Event-ID` set to the last id read, backing off as Annex B.2 says while
 * connecting fails, and when nothing came for twice `limits.heartbeat`.
 *
 * What it gives up on, it throws to the loop that reads it: a stream that
 * breaks the limits of § 13 (DocumentError), a token the server no longer
 * takes, an id too old (Gone: read the library again, then open a stream
 * without a token), or five failures in a row.
 */

import { DocumentError } from "../base.ts";
import { ServerError, SlowDown, TransportError } from "../errors.ts";
import { backoff, readEvent, type ServerEvent, type SseBlock, SseParser } from "../events.ts";
import type { TransportResponse } from "./transport.ts";

/** What opens the stream: given the last id read (or the one to resume from), the open response. */
export type Connect = (lastId: string | undefined) => Promise<TransportResponse>;

export interface EventStreamOptions {
  /** The token to resume from (an id read before, kept across a restart: Annex B.10). */
  since?: string;
  /** Connections that fail in a row before giving up (Annex B.2: 5). */
  tries?: number;
  /** Called each time the stream is opened again, with the error that ended the last one (if any). */
  onReconnect?: (error: unknown, waitSeconds: number) => void;
}

/** Waits `ms`, or less when `abort` fires. */
function sleep(ms: number, abort: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (abort.aborted) return resolve();
    const timer = setTimeout(done, ms);
    function done(): void {
      clearTimeout(timer);
      abort.removeEventListener("abort", done);
      resolve();
    }
    abort.addEventListener("abort", done);
  });
}

/** Whether an error ends the stream for a while only. */
function transient(e: unknown): boolean {
  return e instanceof TransportError || e instanceof SlowDown || e instanceof ServerError;
}

/** Events, as they come, for as long as the stream is read (see the module's comment). */
export class EventStream implements AsyncIterable<ServerEvent> {
  /** The last event id read: where the stream goes on from, and what to keep across a restart. */
  lastId: string | undefined;
  /** The milliseconds to wait before connecting again, as the server last said (`retry`). */
  retry = 5000;
  /** Whether the server said it is stopping (`shutdown`), until the stream is open again. */
  serverStopping = false;
  readonly #connect: Connect;
  readonly #tries: number;
  readonly #onReconnect: EventStreamOptions["onReconnect"];
  readonly #abort = new AbortController();
  #response: TransportResponse | undefined;
  #iterator: AsyncGenerator<ServerEvent> | undefined;

  constructor(connect: Connect, options: EventStreamOptions = {}) {
    this.#connect = connect;
    this.lastId = options.since;
    this.#tries = options.tries ?? 5;
    this.#onReconnect = options.onReconnect;
  }

  /** Ends the stream: the loop reading it ends. */
  async close(): Promise<void> {
    this.#abort.abort();
    await this.#response?.cancel();
  }

  get closed(): boolean {
    return this.#abort.signal.aborted;
  }

  /** The stream's events: the same iterator each time it is asked for (one loop reads a stream). */
  [Symbol.asyncIterator](): AsyncGenerator<ServerEvent> {
    this.#iterator ??= this.#run();
    return this.#iterator;
  }

  async *#run(): AsyncGenerator<ServerEvent> {
    let failures = 0;
    let wait = 0;
    try {
      while (!this.closed) {
        if (wait > 0) await sleep(wait, this.#abort.signal);
        if (this.closed) return;
        let ended: unknown;
        try {
          this.#response = await this.#connect(this.lastId);
          failures = 0;
          this.serverStopping = false;
          const parser = new SseParser();
          for await (const chunk of this.#response.body()) {
            let blocks: SseBlock[];
            let refused: unknown;
            try {
              blocks = parser.push(chunk);
            } catch (e) {
              // What came before a bound passed is given; then the stream is refused.
              blocks = parser.completed();
              refused = e;
            }
            for (const block of blocks) {
              if (block.retry !== undefined) this.retry = block.retry;
              const event = readEvent(block);
              if (parser.lastEventId) this.lastId = parser.lastEventId;
              if (event === undefined) continue;
              if (event.event === "shutdown") {
                this.serverStopping = true;
                const seconds = Number(event.data["retry"]);
                if (Number.isFinite(seconds) && seconds > 0) this.retry = Math.max(this.retry, seconds * 1000);
              }
              yield event;
              if (this.closed) return;
              if (this.serverStopping) break;
            }
            if (refused !== undefined) throw refused;
            if (this.serverStopping) break;
          }
        } catch (e) {
          if (this.closed) return;
          if (e instanceof DocumentError || !transient(e)) throw e;
          ended = e;
          failures++;
          if (failures >= this.#tries) throw e;
        } finally {
          await this.#response?.cancel();
          this.#response = undefined;
        }
        // The stream ended (or failed): wait `retry` at least, and back off while connecting fails.
        const floor = ended instanceof SlowDown && ended.retryAfter !== undefined ? ended.retryAfter * 1000 : 0;
        wait = Math.max(this.retry, floor, failures > 0 ? backoff(failures) * 1000 : 0);
        this.#onReconnect?.(ended, wait / 1000);
      }
    } finally {
      this.#abort.abort();
    }
  }
}
