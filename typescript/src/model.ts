/**
 * The checks the generated readers (generated/models.ts) are made of. A
 * reader checks the type of every field it knows, recursively, and gives
 * back the very object it was given: the fields it does not know stay on
 * it, so that a document written back loses none of them (SPEC.md § 3.2).
 */

import { DocumentError, isObject } from "./base.ts";

/** Reads one value at `where`, or throws DocumentError. */
export type Check<T> = (value: unknown, where: string) => T;

export function obj(value: unknown, where: string): Record<string, unknown> {
  if (!isObject(value)) throw new DocumentError("not an object", where);
  return value;
}

export function req(o: Record<string, unknown>, key: string, where: string, check: Check<unknown>): void {
  if (!Object.hasOwn(o, key)) throw new DocumentError(`no ${key}`, where);
  check(o[key], `${where}.${key}`);
}

export function opt(o: Record<string, unknown>, key: string, where: string, check: Check<unknown>): void {
  if (!Object.hasOwn(o, key) || o[key] === undefined) return;
  check(o[key], `${where}.${key}`);
}

export const str: Check<string> = (v, where) => {
  if (typeof v !== "string") throw new DocumentError("not a string", where);
  return v;
};

export const int: Check<number> = (v, where) => {
  if (typeof v !== "number" || !Number.isInteger(v)) throw new DocumentError("not an integer", where);
  return v;
};

export const num: Check<number> = (v, where) => {
  if (typeof v !== "number" || !Number.isFinite(v)) throw new DocumentError("not a number", where);
  return v;
};

export const bool: Check<boolean> = (v, where) => {
  if (typeof v !== "boolean") throw new DocumentError("not true or false", where);
  return v;
};

export const any: Check<unknown> = (v) => v;

export function list<T>(item: Check<T>): Check<T[]> {
  return (v, where) => {
    if (!Array.isArray(v)) throw new DocumentError("not a list", where);
    v.forEach((x, i) => {
      item(x, `${where}[${i}]`);
    });
    return v as T[];
  };
}

export function map<T>(item: Check<T>): Check<Record<string, T>> {
  return (v, where) => {
    const o = obj(v, where);
    for (const [k, x] of Object.entries(o)) item(x, `${where}.${k}`);
    return o as Record<string, T>;
  };
}

export function nullable<T>(item: Check<T>): Check<T | null> {
  return (v, where) => (v === null ? null : item(v, where));
}
