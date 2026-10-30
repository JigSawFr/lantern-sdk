/** What the tests share: the repository's paths, the specification's vectors, and Python servers started for a test. */

import { type ChildProcess, spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

export const PACKAGE = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const REPOSITORY = resolve(PACKAGE, "..");
export const SPEC = join(REPOSITORY, "spec");
export const PYTHON = process.env["PYTHON"] ?? "python3";
export const AGENT = "LanternTypeScriptTest/1.0";

export function vectors<T = Record<string, unknown>>(name: string): T {
  return JSON.parse(readFileSync(join(SPEC, "vectors", `${name}.json`), "utf8")) as T;
}

export function example<T = Record<string, unknown>>(name: string): T {
  return JSON.parse(readFileSync(join(SPEC, "examples", "v1", `${name}.json`), "utf8")) as T;
}

/** A Python process that prints one JSON line when it is ready, then serves until it is stopped. */
export interface Served<T> {
  info: T;
  process: ChildProcess;
  /** The lines it wrote on standard error (a hostile server's request log). */
  log: string[];
  stop(): Promise<void>;
}

export async function servePython<T>(
  args: string[],
  options: { cwd?: string; timeout?: number } = {},
): Promise<Served<T>> {
  const child = spawn(PYTHON, args, { cwd: options.cwd ?? PACKAGE, stdio: ["pipe", "pipe", "pipe"] });
  const log: string[] = [];
  createInterface({ input: child.stderr }).on("line", (line) => log.push(line));
  const lines = createInterface({ input: child.stdout });
  const info = await new Promise<T>((resolvePromise, reject) => {
    const timer = setTimeout(
      () => {
        child.kill("SIGKILL");
        reject(new Error(`${args.join(" ")}: not ready within ${options.timeout ?? 30} s\n${log.join("\n")}`));
      },
      (options.timeout ?? 30) * 1000,
    );
    lines.once("line", (line) => {
      clearTimeout(timer);
      try {
        resolvePromise(JSON.parse(line) as T);
      } catch (e) {
        reject(e);
      }
    });
    child.once("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`${args.join(" ")} exited (${code})\n${log.join("\n")}`));
    });
  });
  return {
    info,
    process: child,
    log,
    stop: () =>
      new Promise<void>((resolveStop) => {
        if (child.exitCode !== null || child.signalCode !== null) {
          resolveStop();
          return;
        }
        const timer = setTimeout(() => child.kill("SIGKILL"), 5000);
        child.once("exit", () => {
          clearTimeout(timer);
          resolveStop();
        });
        child.stdin?.end();
        child.kill("SIGTERM");
      }),
  };
}

/** The requests a hostile server logged ({method, path, authorization}). */
export function requestsOf(log: readonly string[]): { method: string; path: string; authorization: string | null }[] {
  return log
    .filter((l) => l.startsWith("{"))
    .map((l) => JSON.parse(l) as { method: string; path: string; authorization: string | null });
}

/** Waits until `check` holds, or `seconds` pass. */
export async function until(check: () => boolean, seconds = 2): Promise<void> {
  const end = Date.now() + seconds * 1000;
  while (!check() && Date.now() < end) await new Promise((r) => setTimeout(r, 20));
}
