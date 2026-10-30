/**
 * Events (SPEC.md § 18): a reader of Server-Sent Events over a stream of
 * bytes, bounded, and what each event says. A browser's EventSource cannot
 * send `Authorization` nor sign a request (§ 5.4), so the client reads the
 * stream over fetch(), with this reader.
 *
 * The reader follows the WHATWG HTML standard's parsing (lines ended by CR,
 * LF or CRLF; `field: value`; `data` lines joined by LF; a comment begins with
 * `:`; an empty line dispatches the event), within bounds: a line longer than
 * `lineLimit` bytes, or an event whose data is above § 13's 4 KiB, throws
 * DocumentError as soon as the bound is passed, without holding the rest.
 */

import { DocumentError, type JSONObject, SCHEMA } from "./base.ts";
import { fromUtf8, utf8Length } from "./bytes.ts";
import { loadJson } from "./limits.ts";

/** An event's `data` at most (SPEC.md § 13). */
export const EVENT_DATA = 4096;
/** A line of the stream at most: an event's data and its field's name, with room. */
export const EVENT_LINE = EVENT_DATA + 1024;
/** The events of this version (SPEC.md § 18.2); a reader ignores the others. */
export const EVENT_TYPES = ["ready", "library", "request", "pairing", "save", "sync", "shutdown"] as const;
export type EventType = (typeof EVENT_TYPES)[number];

/** What the stream gave between two empty lines: an event's fields, or `retry` alone. */
export interface SseBlock {
  id?: string;
  event?: string;
  data?: string;
  retry?: number;
}

/** An event the client reads (SPEC.md § 18.2): its id (a token of /v1/changes), its type and its document. */
export interface ServerEvent {
  id: string;
  event: string;
  data: JSONObject;
}

const LF = 0x0a;
const CR = 0x0d;

/**
 * A bounded Server-Sent Events parser. Feed it the stream's chunks with
 * push(); each gives the blocks it completed. A comment counts as life (a
 * heartbeat) but gives no block.
 */
export class SseParser {
  readonly lineLimit: number;
  readonly dataLimit: number;
  #lineBytes = new Uint8Array(256);
  #lineLength = 0;
  #afterCr = false;
  #first = true;
  #block: { id?: string; event?: string; data: string[]; dataBytes: number; retry?: number; any: boolean } = {
    data: [],
    dataBytes: 0,
    any: false,
  };
  /** The last event id the stream set (an `id` field), as the standard keeps it. */
  lastEventId = "";
  /** Comments read (heartbeats). */
  comments = 0;

  constructor(options: { lineLimit?: number; dataLimit?: number } = {}) {
    this.lineLimit = options.lineLimit ?? EVENT_LINE;
    this.dataLimit = options.dataLimit ?? EVENT_DATA;
  }

  push(chunk: Uint8Array): SseBlock[] {
    const out: SseBlock[] = [];
    for (let i = 0; i < chunk.length; i++) {
      const byte = chunk[i] as number;
      if (this.#afterCr) {
        this.#afterCr = false;
        if (byte === LF) continue;
      }
      if (byte === LF || byte === CR) {
        if (byte === CR) this.#afterCr = true;
        const block = this.#endLine();
        if (block !== undefined) out.push(block);
        continue;
      }
      if (this.#lineLength >= this.lineLimit) {
        throw new DocumentError(`an event stream's line above ${this.lineLimit} bytes`, "events");
      }
      if (this.#lineLength === this.#lineBytes.length) {
        const bigger = new Uint8Array(Math.min(this.lineLimit, this.#lineBytes.length * 2));
        bigger.set(this.#lineBytes);
        this.#lineBytes = bigger;
      }
      this.#lineBytes[this.#lineLength++] = byte;
    }
    return out;
  }

  #endLine(): SseBlock | undefined {
    let text = fromUtf8(this.#lineBytes.subarray(0, this.#lineLength));
    this.#lineLength = 0;
    if (this.#first) {
      this.#first = false;
      if (text.startsWith("﻿")) text = text.slice(1);
    }
    if (text === "") return this.#dispatch();
    if (text.startsWith(":")) {
      this.comments++;
      return undefined;
    }
    const colon = text.indexOf(":");
    const field = colon < 0 ? text : text.slice(0, colon);
    let value = colon < 0 ? "" : text.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    const b = this.#block;
    switch (field) {
      case "data": {
        b.dataBytes += utf8Length(value) + (b.data.length > 0 ? 1 : 0);
        if (b.dataBytes > this.dataLimit) {
          throw new DocumentError(`an event's data above ${this.dataLimit} bytes (SPEC.md § 13)`, "events");
        }
        b.data.push(value);
        b.any = true;
        break;
      }
      case "event":
        b.event = value;
        b.any = true;
        break;
      case "id":
        if (!value.includes("\0")) {
          b.id = value;
          this.lastEventId = value;
        }
        b.any = true;
        break;
      case "retry":
        if (/^\d{1,9}$/.test(value)) {
          b.retry = Number(value);
          b.any = true;
        }
        break;
      default:
        break; // a field the standard does not know is ignored
    }
    return undefined;
  }

  #dispatch(): SseBlock | undefined {
    const b = this.#block;
    this.#block = { data: [], dataBytes: 0, any: false };
    if (!b.any) return undefined;
    const out: SseBlock = {};
    if (b.id !== undefined) out.id = b.id;
    if (b.event !== undefined) out.event = b.event;
    if (b.data.length > 0) out.data = b.data.join("\n");
    if (b.retry !== undefined) out.retry = b.retry;
    return out;
  }
}

/**
 * The event a block carries, or undefined when a reader ignores it (SPEC.md
 * § 18.1): no data, no id, a type this version does not know, a document of a
 * newer schema. A data that is not a JSON document throws DocumentError.
 */
export function readEvent(block: SseBlock): ServerEvent | undefined {
  if (block.data === undefined || block.event === undefined) return undefined;
  if (!(EVENT_TYPES as readonly string[]).includes(block.event)) return undefined;
  const doc = loadJson(block.data, { where: `event ${block.event}` });
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    throw new DocumentError("an event's data is a JSON object", `event ${block.event}`);
  }
  const schema = (doc as JSONObject)["schema"];
  if (typeof schema !== "number" || !Number.isInteger(schema) || schema < 1) {
    throw new DocumentError("no integer schema", `event ${block.event}`);
  }
  if (schema > SCHEMA) return undefined;
  if (block.id === undefined || block.id === "") return undefined;
  return { id: block.id, event: block.event, data: doc as JSONObject };
}

/** The text of an event on the stream (a server's), its data one line of JSON. */
export function formatEvent(id: string, event: string, data: unknown): string {
  const json = JSON.stringify(data);
  if (/[\r\n]/.test(id) || /[\r\n]/.test(event)) throw new RangeError("an event's id and type are one line");
  return `id: ${id}\nevent: ${event}\ndata: ${json}\n\n`;
}

/** A backoff with full jitter (Annex B.2): a random time between 0 and min(60, 2^n) seconds, at least `floor`. */
export function backoff(attempt: number, floor = 0): number {
  const ceiling = Math.min(60, 2 ** Math.min(attempt, 6));
  return Math.max(floor, Math.random() * ceiling);
}
