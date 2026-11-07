# The SDK's website

`sdk.lantern.boreale.dev`: one page, in the fifteen languages of Boréale's
sites (English at the root, each other language in its folder), on GitHub
Pages (Settings › Pages › Source: GitHub Actions, custom domain
`sdk.lantern.boreale.dev`).

It says what `sdk.json` says (written by `tools/site_data.py`, checked by CI):
the libraries and their state, the families each one covers, the same call in
every language, the examples CI runs, what makes them trustworthy, and the
versions. The page is built from the repository it describes, so it never
lags behind it. Where it names a section of the specification, the link goes
to the protocol's site (`lantern.boreale.dev`).

| Path | What it is |
| --- | --- |
| `site/template.html`, `site/home.html` | The page around the SDK page, and the page. `{{key}}` is the key's text in the language's catalog. |
| `site/i18n/<language>.json` | The page's texts, in the fifteen languages. What Boréale's sites share (the menus, the footer) is `library/boreale-site`'s. |
| `site/assets/` | `site.css`, `sdk.js` (the language picker), `code.js` (the copy buttons), `lang-key.js`. The fonts, marks and the chrome come from `library/boreale-site`. |
| `tools/build_site.py` | `python3 tools/build_site.py build`; `SITE_OFFLINE=1` skips boreale.dev's `versions.json`. Standard library only. |
| `tools/check_site.py` | `python3 tools/check_site.py build`: the checks every Boréale site passes (links, catalogs, Content-Security-Policy, UTM, no e-mail address) and that the page carries the data. |

A text added goes in all fifteen catalogs, translated. The site's marks and
social preview are the brand kit's (`boreale/branding/sdk/`).

## The playground

The "Run it, here" section runs the SDK's own TypeScript client and server in the page: `site/playground/playground.ts`
builds a made-up library (`MemoryLibrary`), serves it with `LanternApp` through `fetchHandler()` and reads it with
`LanternClient` over an in-page `Transport`. `site/assets/sdk-playground.js` is that bundle (built by
`node tools/build_playground.mjs` with esbuild 0.25.5, loaded when the button is first pressed); `node-crypto.ts` stands
in for `node:crypto` (the SDK's SHA-256 and the browser's randomness). Its first line carries the SHA-256 of the
sources it was built from, and `tools/check_site.py` fails when `typescript/src/` or `site/playground/` changed
without the bundle built again, so CI needs no esbuild.

