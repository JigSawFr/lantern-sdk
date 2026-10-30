# Contributing

The libraries follow the [Lantern specification](https://github.com/JigSawFr/lantern):
a change to the protocol is proposed there first, then implemented here in
every language at once.

## Questions and problems

Open an issue, saying the language, the library's version and the
specification's draft. A security flaw is not an issue: see
[SECURITY.md](SECURITY.md).

## Pull requests

- Titles and commits in [Conventional Commits](https://www.conventionalcommits.org/),
  with the language or area as scope: `feat(cpp): …`, `fix(python): …`,
  `ci(typescript): …`.
- Each language's own checks pass before pushing; its README lists them.
- A change of behaviour comes with its test, in every language it
  concerns; a client fix also teaches the malicious test server its case.
- Examples and tests use made-up games and names, and only reserved
  addresses (`example.org`, `192.0.2.0/24`): never a real person, game,
  server or e-mail address.
- Every file says its licence ([REUSE](https://reuse.software/)).

Pull requests are merged as one squashed commit.

## Code of conduct

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).
