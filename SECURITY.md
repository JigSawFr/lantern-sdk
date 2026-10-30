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

A flaw in the protocol itself belongs to
[the specification's repository](https://github.com/JigSawFr/lantern/security).
