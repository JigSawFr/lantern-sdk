"""Rating caps (SPEC.md § 5.6): the age a rating is read as, the age of a
title or a homebrew for a cap, and whether a cap hides it. A server hides
what is above a token's cap everywhere; a client shows the cap its token
carries (the handshake's `account.rating_cap`). Test vectors:
`vectors/rating-caps.json`."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from lantern._base import JSONValue
from lantern._generated.models import Rating, RatingCap

#: The age each rating of each system is read as (SPEC.md § 5.6).
AGES: Mapping[str, Mapping[str, int]] = {
    "PEGI": {"3": 3, "7": 7, "12": 12, "16": 16, "18": 18},
    "ESRB": {"EC": 3, "E": 6, "E10+": 10, "T": 13, "M": 17, "AO": 18},
    "CERO": {"A": 0, "B": 12, "C": 15, "D": 17, "Z": 18},
    "USK": {"0": 0, "6": 6, "12": 12, "16": 16, "18": 18},
    "ACB": {"G": 0, "PG": 8, "M": 15, "MA15+": 15, "R18+": 18, "X18+": 18},
    "CLASSIND": {"L": 0, "10": 10, "12": 12, "14": 14, "16": 16, "18": 18},
    "GRAC": {"ALL": 0, "12": 12, "15": 15, "18": 18},
}


def rating_age(system: str, rating: str) -> int | None:
    """The age of one rating; None for a system or a rating the table does not list."""
    return AGES.get(system, {}).get(rating)


def cap_age(cap: RatingCap) -> int | None:
    """The age a cap allows: its `age`, or its rating's; None when the table cannot read it."""
    if cap.age is not None:
        return cap.age
    if cap.system is not None and cap.rating is not None:
        return rating_age(cap.system, cap.rating)
    return None


def age_of(ratings: Iterable[Rating], cap: RatingCap) -> int | None:
    """The age of a title (or a homebrew) of `ratings`, for `cap`: its rating
    of the cap's system when it has one the table reads, otherwise the highest
    age of its ratings the table reads; None when unrated."""
    items = list(ratings)
    if cap.system is not None:
        own = [rating_age(r.system, r.rating) for r in items if r.system == cap.system]
        own_ages = [a for a in own if a is not None]
        if own_ages:
            return max(own_ages)
    ages = [a for a in (rating_age(r.system, r.rating) for r in items) if a is not None]
    return max(ages) if ages else None


def hidden(ratings: Iterable[Rating] | None, cap: RatingCap | None) -> bool:
    """Whether a token of `cap` must not see what has `ratings` (SPEC.md § 5.6):
    above the cap's age, or unrated with `unrated` `hide`. A cap the table
    cannot read hides everything rated, so that it never loosens."""
    if cap is None:
        return False
    age = age_of(ratings or (), cap)
    if age is None:
        return cap.unrated == "hide"
    limit = cap_age(cap)
    return limit is None or age > limit


def read_cap(value: JSONValue) -> RatingCap | None:
    """A rating cap of a document, or None for none; ValueError for one that is
    not of SPEC.md § 5.6's form."""
    if value is None:
        return None
    cap = RatingCap.from_json(value, "rating_cap")
    problem = cap_problem(cap)
    if problem:
        raise ValueError(problem)
    return cap


def cap_problem(cap: RatingCap) -> str | None:
    """Why `cap` is not a rating cap of SPEC.md § 5.6, or None."""
    if cap.age is not None:
        if cap.system is not None or cap.rating is not None:
            return "a rating cap is an age, or a rating of one system, not both"
        if not 0 <= cap.age <= 99:
            return "a rating cap's age is 0 to 99"
    elif cap.system is None or cap.rating is None:
        return "a rating cap is an age, or a system and its rating"
    if cap.unrated is not None and cap.unrated not in ("show", "hide"):
        return "unrated is show or hide"
    return None
