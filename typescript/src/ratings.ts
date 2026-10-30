/**
 * Rating caps (SPEC.md § 5.6): the age a rating is read as, the age of a title
 * or a homebrew for a cap, and whether a cap hides it. A server hides what is
 * above a token's cap everywhere; a client shows the cap its token carries
 * (the handshake's `account.rating_cap`). Test vectors: `vectors/rating-caps.json`.
 */

import type { Rating, RatingCap } from "./generated/models.ts";
import { readRatingCap } from "./generated/models.ts";

/** The age each rating of each system is read as (SPEC.md § 5.6). */
export const AGES: Readonly<Record<string, Readonly<Record<string, number>>>> = {
  PEGI: { "3": 3, "7": 7, "12": 12, "16": 16, "18": 18 },
  ESRB: { EC: 3, E: 6, "E10+": 10, T: 13, M: 17, AO: 18 },
  CERO: { A: 0, B: 12, C: 15, D: 17, Z: 18 },
  USK: { "0": 0, "6": 6, "12": 12, "16": 16, "18": 18 },
  ACB: { G: 0, PG: 8, M: 15, "MA15+": 15, "R18+": 18, "X18+": 18 },
  CLASSIND: { L: 0, "10": 10, "12": 12, "14": 14, "16": 16, "18": 18 },
  GRAC: { ALL: 0, "12": 12, "15": 15, "18": 18 },
};

/** The age of one rating; undefined for a system or a rating the table does not list. */
export function ratingAge(system: string, rating: string): number | undefined {
  const row = Object.hasOwn(AGES, system) ? AGES[system] : undefined;
  return row !== undefined && Object.hasOwn(row, rating) ? row[rating] : undefined;
}

/** The age a cap allows: its `age`, or its rating's; undefined when the table cannot read it. */
export function capAge(cap: RatingCap): number | undefined {
  if (cap.age !== undefined) return cap.age;
  if (cap.system !== undefined && cap.rating !== undefined) return ratingAge(cap.system, cap.rating);
  return undefined;
}

function highest(ages: (number | undefined)[]): number | undefined {
  const known = ages.filter((a): a is number => a !== undefined);
  return known.length > 0 ? Math.max(...known) : undefined;
}

/**
 * The age of a title (or a homebrew) of `ratings`, for `cap`: its rating of the
 * cap's system when it has one the table reads, otherwise the highest age of
 * its ratings the table reads; undefined when unrated.
 */
export function ageOf(ratings: readonly Rating[], cap: RatingCap): number | undefined {
  if (cap.system !== undefined) {
    const own = highest(ratings.filter((r) => r.system === cap.system).map((r) => ratingAge(r.system, r.rating)));
    if (own !== undefined) return own;
  }
  return highest(ratings.map((r) => ratingAge(r.system, r.rating)));
}

/**
 * Whether a token of `cap` must not see what has `ratings` (SPEC.md § 5.6):
 * above the cap's age, or unrated with `unrated` `hide`. A cap the table
 * cannot read hides everything rated, so that it never loosens.
 */
export function hidden(ratings: readonly Rating[] | undefined, cap: RatingCap | undefined): boolean {
  if (cap === undefined) return false;
  const age = ageOf(ratings ?? [], cap);
  if (age === undefined) return cap.unrated === "hide";
  const limit = capAge(cap);
  return limit === undefined || age > limit;
}

/** Why `cap` is not a rating cap of SPEC.md § 5.6, or undefined. */
export function capProblem(cap: RatingCap): string | undefined {
  if (cap.age !== undefined) {
    if (cap.system !== undefined || cap.rating !== undefined) {
      return "a rating cap is an age, or a rating of one system, not both";
    }
    if (cap.age < 0 || cap.age > 99) return "a rating cap's age is 0 to 99";
  } else if (cap.system === undefined || cap.rating === undefined) {
    return "a rating cap is an age, or a system and its rating";
  }
  if (cap.unrated !== undefined && cap.unrated !== "show" && cap.unrated !== "hide") return "unrated is show or hide";
  return undefined;
}

/** A rating cap of a document, or undefined for none; a RangeError for one not of SPEC.md § 5.6's form. */
export function readCap(value: unknown): RatingCap | undefined {
  if (value === undefined || value === null) return undefined;
  const cap = readRatingCap(value, "rating_cap");
  const problem = capProblem(cap);
  if (problem !== undefined) throw new RangeError(problem);
  return cap;
}
