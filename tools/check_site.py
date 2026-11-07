#!/usr/bin/env python3
"""Checks the Lantern SDK's built website (tools/build_site.py) and its sources.

    python3 tools/check_site.py <site-dir>

- what every one of Boréale's sites passes (library/boreale-site,
  boreale_site.check): the page chrome, no {{key}} left, links and #anchors
  that lead somewhere, links out by the rule "liens sortants anonymes" and
  their UTM tags (utm_source=sdk, only to Boréale's other sites), nothing
  the Content-Security-Policy blocks, Umami's tracker, no e-mail address in a
  page;
- the catalogs of site/i18n/ and boreale-site's: the same keys as
  en-US.json, none empty, the same {placeholders} and <em> as English's, no
  common text repeated here;
- the sitemap is well formed, and every page carries the SDK's data (the
  language cards read from sdk.json), not the note that it is missing;
- no e-mail address and no mailto: link in any file of the site (contact
  goes through the issues).
"""
import os
import re
import sys
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "library" / "boreale-site"))
import boreale_site as boreale  # noqa: E402
from boreale_site import check  # noqa: E402

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    site = Path(sys.argv[1])
    errors = boreale.check_catalogs(ROOT / "site" / "i18n")
    found, pages = check.pages(site, boreale.Site("sdk", os.environ.get("SITE_URL")), chrome=True)
    errors += found
    try:
        ElementTree.parse(site / "sitemap.xml")
    except (OSError, ElementTree.ParseError) as error:
        errors.append(f"sitemap.xml: {error}")
    for page in sorted(site.rglob("index.html")):
        text = page.read_text(encoding="utf-8")
        if 'class="cards' not in text:
            errors.append(f"{page.relative_to(site)}: no SDK data (sdk.json unread)")
        elif 'class="hero-code"' not in text:
            errors.append(f"{page.relative_to(site)}: no code beside the title")
    for path in sorted(site.rglob("*")):
        if path.is_file() and path.suffix in (".html", ".xml", ".txt", ".js", ".css", ".json"):
            text = path.read_text(encoding="utf-8", errors="replace")
            if "mailto:" in text or EMAIL.search(text):
                errors.append(f"{path.relative_to(site)}: an e-mail address (contact goes through the issues)")
    for e in errors:
        print(f"check_site: {e}")
    if errors:
        sys.exit(1)
    print(f"check_site: {pages} pages, {len(boreale.CODES)} catalogs, nothing wrong")


if __name__ == "__main__":
    main()
