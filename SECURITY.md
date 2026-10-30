# Security

These libraries download files onto consoles and check them, so a flaw in
them matters. Thank you for reporting one.

## Reporting a flaw

Report it privately, through GitHub's private vulnerability reporting:
the **Security** tab of this repository, then **Report a vulnerability**.
Please don't open a public issue or pull request for it.

Say which library and version, what you found, how to reproduce it, and
what an attacker gains (a server that lies, a hostile network, a malformed
document).

## What happens next

- The report is acknowledged, then confirmed or answered with why it is
  not a flaw.
- A confirmed flaw is fixed in every language it touches, with a test, and
  in the malicious test server when it is a client flaw, so no library can
  bring it back.
- The advisory is published with the fixed release, crediting you if you
  wish.

## Verifying a release

Every file of a release is built by this repository's release workflow
(`.github/workflows/release.yml`) from the tag's commit, and attested by
GitHub through Sigstore: SLSA build provenance for each file, and each
package's SBOM (CycloneDX) linked to it. [RELEASING.md](RELEASING.md) says
how a release is made.

The files of the GitHub release, with the [GitHub CLI](https://cli.github.com/):

```sh
gh release download v0.5.0 -R JigSawFr/lantern-sdk
sha256sum -c SHA256SUMS
# Built by release.yml of this repository, from the tag
gh attestation verify lantern-cpp-0.5.0-linux-x86_64.tar.gz -R JigSawFr/lantern-sdk \
    --signer-workflow JigSawFr/lantern-sdk/.github/workflows/release.yml --source-ref refs/tags/v0.5.0
# Its SBOM, and what it lists
gh attestation verify lantern-cpp-0.5.0-linux-x86_64.tar.gz -R JigSawFr/lantern-sdk \
    --predicate-type https://cyclonedx.org/bom --format json --jq '.[0].verificationResult.statement.predicate'
```

The Python package on PyPI carries its own attestations (PEP 740), made by
the same workflow when it published it; its page shows them under
*Verified details*. They can be checked, and the files are the ones
attested on GitHub:

```sh
pip download lantern-protocol==0.5.0 --no-deps --only-binary :all: -d lantern
python -m pip install pypi-attestations
pypi-attestations verify pypi --repository https://github.com/JigSawFr/lantern-sdk \
    pypi:lantern_protocol-0.5.0-py3-none-any.whl
gh attestation verify lantern/lantern_protocol-0.5.0-py3-none-any.whl -R JigSawFr/lantern-sdk
```

The npm package is published with its provenance, which npm checks along
with the registry's signatures, in a project that depends on it:

```sh
npm install lantern-protocol@0.5.0
npm audit signatures
```

The Python package, the npm tarball and the source archive can also be
built again, byte for byte, and compared with the release:
`tools/reproduce.sh release v0.5.0`.

A file that fails any of these checks is not ours: please report it as a
flaw, as above.

## The specification

A flaw in the protocol itself belongs to
[the specification's repository](https://github.com/JigSawFr/lantern/security).
