"""A title's images on the server's own origin (SPEC.md § 7.1, L-7.1-2): content-addressed, served for a year,
immutable, and hidden with the titles that show them."""

from __future__ import annotations

from demo import BASE as ORIGIN
from demo import DEMO_TOKEN, build_library, make_lantern
from lantern._generated.models import Image, Rating, RatingCap, Title
from lantern.digest import sha256_hex
from lantern.server import Account, FileRef, MemoryLibrary
from lantern.server.http import ServerRequest
from test_server import BASE, call

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


def _library() -> tuple[MemoryLibrary, str]:
    lib = build_library()
    name = lib.add_media(FileRef.of_bytes(PNG, "image/png"), "png")
    lib.add_title(
        Title(
            platform="switch",
            title_id="0100FF0000010000",
            name="Pictured",
            ratings=[Rating(system="PEGI", rating="18")],
            icon=Image(url=f"{ORIGIN}/v1/media/{name}", sha256=sha256_hex(PNG), width=8, height=8),
        )
    )
    return lib, name


def test_l_7_1_2_an_image_is_served_immutable_and_by_its_hash() -> None:
    lib, name = _library()
    app = make_lantern(lib)
    r = call(app, "GET", f"{BASE}/media/{name}")
    assert r.status == 200 and r.body == PNG and name.startswith(sha256_hex(PNG))
    assert r.headers["Content-Type"] == "image/png"
    assert r.headers["Cache-Control"] == "public, max-age=31536000, immutable"
    assert call(app, "HEAD", f"{BASE}/media/{name}").status == 200
    assert call(app, "GET", f"{BASE}/media/{name}", Range="bytes=0-3").status == 206


def test_an_unknown_or_unshown_image_is_404() -> None:
    lib, _ = _library()
    stray = lib.add_media(FileRef.of_bytes(PNG + b"1", "image/png"), "png")  # no title shows it
    app = make_lantern(lib)
    assert call(app, "GET", f"{BASE}/media/{'0' * 64}.png").status == 404
    assert call(app, "GET", f"{BASE}/media/{stray}").status == 404


def test_an_image_is_private_with_a_token_and_hidden_by_the_rating_cap() -> None:
    lib, name = _library()
    bearer = f"Bearer {DEMO_TOKEN}"
    free = make_lantern(lib)
    r = call(free, "GET", f"{BASE}/media/{name}", Authorization=bearer)
    assert r.status == 200 and r.headers["Cache-Control"] == "private, max-age=31536000, immutable"

    def capped(request: ServerRequest) -> Account | None:
        return Account(scopes=frozenset({"library"}), rating_cap=RatingCap(age=12))

    app = make_lantern(lib)
    app.authenticate = capped
    assert (
        call(app, "GET", f"{BASE}/media/{name}", Authorization=bearer).status == 404
    )  # PEGI 18 hides the title and its icon
