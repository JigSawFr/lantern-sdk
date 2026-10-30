/**
 * The open vocabularies SPEC.md lists in its text rather than in its schemas.
 * A reader takes a value it does not know as the specification says (an
 * unknown kind is an app, an unknown `assets` is `user_owned`, an unknown
 * architecture is never its own); a later version may add values.
 */

/** A homebrew's kinds (SPEC.md § 8.1). */
export const KINDS = ["app", "game", "port", "emulator", "tool", "overlay", "sysmodule", "theme"] as const;
/** Where a port's assets come from (SPEC.md § 8.6). */
export const ASSETS = ["included", "demo_included", "free_external", "user_owned"] as const;
/** The architectures a package may name (SPEC.md § 8.2). */
export const ARCH_NAMES = ["aarch64", "armhf", "x86", "x86_64", "riscv64"] as const;
/** The form of an architecture's name, this version's or a later one's (SPEC.md § 8.2). */
export const ARCH = /^[a-z0-9_]{1,32}$/;
/** The families of the handshake's `features` (SPEC.md § 4.2). */
export const FAMILIES = [
  "library",
  "titles",
  "changes",
  "sections",
  "homebrew",
  "saves",
  "cheats",
  "requests",
  "pairing",
  "signatures",
  "admin",
] as const;
export type Family = (typeof FAMILIES)[number];
/** A platform's name (SPEC.md § 4.3). */
export const PLATFORM = /^[a-z0-9][a-z0-9-]{0,31}$/;
/** A title or an app id, the core's form (SPEC.md § 6.1). */
export const CORE_ID = /^[A-Za-z0-9._-]{1,128}$/;
/** A homebrew's id (SPEC.md § 8.1). */
export const HOMEBREW_ID = /^(?=.{1,128}$)[a-z][a-z0-9_-]*(?:\.[a-z0-9][a-z0-9_-]*)+$/;
/** A lower-case word: a filter's kind or genre, an app's type (SPEC.md § 6.1, § 8.5). */
export const WORD = /^[a-z][a-z0-9_]{0,31}$/;
/** A cheat set's build id, the core's form (SPEC.md § 10). */
export const BUILD_ID = /^[A-Za-z0-9._-]{1,64}$/;
/** A SHA-256, lower-case hex. */
export const SHA256_HEX = /^[0-9a-f]{64}$/;

/** Whether `name` is a platform's name (SPEC.md § 4.3). */
export function isPlatform(name: string): boolean {
  return PLATFORM.test(name);
}
