# Known Limitations

## SSH fingerprints are evidence-only

Live validation on 2026-08-11 showed that Shodan's documented
`ssh.fingerprint` query did not return a seed whose host response contained the
same canonical fingerprint. Quoted, compact, and colon-separated forms did not
self-match reliably.

SSH fingerprints remain normalized and stored as evidence, but they are
excluded from discovery queries. Do not enable SSH discovery until a
Shodan-supported representation can reliably self-match a seed. Do not add
undocumented query fallbacks.

## Shodan version filtering is not exact

Live validation showed that Shodan's `version` filter can match broad package
version families rather than an exact package string. The
`port_product_and_version` rule therefore remains disabled by default. Local
candidate validation still requires exact port, transport, product, and version
equality when the rule is explicitly enabled.
