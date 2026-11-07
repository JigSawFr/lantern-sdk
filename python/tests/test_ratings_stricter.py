"""`ratings.stricter`: the one cap that holds a token's and its account's."""

from __future__ import annotations

from lantern.models import RatingCap
from lantern.ratings import hidden, stricter


def test_no_cap_is_the_other() -> None:
    cap = RatingCap(age=12)
    assert stricter(None, None) is None
    assert stricter(cap, None) is cap and stricter(None, cap) is cap


def test_the_lower_age_wins_whichever_way_it_is_written() -> None:
    assert stricter(RatingCap(age=12), RatingCap(age=7)) == RatingCap(age=7)
    assert stricter(RatingCap(age=7), RatingCap(age=12)) == RatingCap(age=7)
    assert stricter(RatingCap(system="PEGI", rating="12"), RatingCap(age=16)) == RatingCap(system="PEGI", rating="12")
    assert stricter(RatingCap(system="ESRB", rating="E"), RatingCap(age=10)) == RatingCap(system="ESRB", rating="E")


def test_a_cap_the_table_cannot_read_is_never_loosened() -> None:
    unreadable = RatingCap(system="NOPE", rating="X")
    assert stricter(unreadable, RatingCap(age=3)) == unreadable
    assert stricter(RatingCap(age=3), unreadable) == unreadable


def test_hiding_the_unrated_wins() -> None:
    both = stricter(RatingCap(age=7), RatingCap(age=12, unrated="hide"))
    assert both == RatingCap(age=7, unrated="hide")
    assert hidden(None, both) and not hidden(None, RatingCap(age=7))
    assert stricter(RatingCap(age=12, unrated="hide"), RatingCap(age=7)) == RatingCap(age=7, unrated="hide")
