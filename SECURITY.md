# Security Policy

## Supported Versions

Only the latest release on the default branch (`main`) is supported with security updates.

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

**Email:** [security@sanna.dev](mailto:security@sanna.dev)

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

**Do not** open a public GitHub issue for security vulnerabilities.

## Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgement | Within 48 hours |
| Triage | Within 7 days |
| Fix timeline communicated | Within 14 days |

## Safe Harbor

Good-faith security researchers acting within this policy will not face legal action from Sanna AI. We consider security research conducted consistent with this policy to be authorized and will not pursue civil or criminal action.

## Scope

The following repositories are in scope:

- [sanna](https://github.com/sanna-ai/sanna)
- [sanna-ts](https://github.com/sanna-ai/sanna-ts)
- [sanna-openclaw](https://github.com/sanna-ai/sanna-openclaw)
- [sanna-protocol](https://github.com/sanna-ai/sanna-protocol)

The Sanna Cloud service ([api.sanna.cloud](https://api.sanna.cloud)) is also in scope.

## Out of Scope

- Social engineering (e.g., phishing)
- Denial of service (DoS/DDoS) attacks
- Third-party services and dependencies

## security.txt

Our `security.txt` file is available at:
[https://sanna.dev/.well-known/security.txt](https://sanna.dev/.well-known/security.txt)

## Credit

Researchers who report valid vulnerabilities will be credited (with their permission) in release notes.

## Test Key Rotation (SAN-404)

The committed Ed25519 PEM private key formerly under
`tests/.test_keys/` (key_id
`c7065a8b70d9ad93611125691c762cedbef6c15e8f4fc25a86cabb4ceecbd3d8`)
has been rotated and is now REVOKED. The corresponding private key
was committed to a public repository and must be assumed compromised.

Constitution YAMLs under `tests/constitutions/` whose
`provenance.signature.key_id` matches the value above were valid
under the old key but MUST NOT be trusted as cryptographic evidence
in any external context. They are re-signed with the new key in this
release; if a downstream consumer holds an older copy of these
fixtures, those copies should be discarded.

Forward-only removal: the old .key file has been deleted from the
working tree but remains reachable in git history at the commit at
which it was originally introduced. Sanna does not rewrite git
history; the trust signal is the REVOKED note above plus the rotated
.pub and re-signed YAMLs at HEAD.

Going forward, `.pre-commit-config.yaml`'s `detect-private-key` hook
blocks PEM private keys from entering the repo. CI runs the same hook
on every pull request. The `.gitignore` line that previously
un-ignored `tests/.test_keys/*.key` has been removed.

See also: the "Intentionally Public Test Cryptographic Material (SAN-489)"
section below for fixed-seed test fixtures that are intentionally public
by design and are NOT subject to this rotation. The two cases are
distinct: SAN-404 covers a previously-committed PEM private key that
was inadvertently exposed and has been REVOKED; SAN-489 covers test
material that was always intentionally public and remains so.


## Intentionally Public Test Cryptographic Material (SAN-489)

The Ed25519 seed at `tests/generate_vectors.py`
(`INTENTIONALLY_PUBLIC_TEST_VECTOR_SEED = b"\x01" * 32`, also referenced
at `tests/test_vectors.py`) is intentionally public. The corresponding
deterministic keypair (key_id
`34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e`,
public_key_hex
`8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c`)
signs the cross-language test vectors at
`tests/vectors/constitution_signature.json` and
`tests/vectors/receipt_signature.json`.

This is NOT a leaked secret. It is a fixed-seed test fixture that
enables third-party Sanna SDK implementations to reproduce signatures
byte-for-byte for canonicalization + signing conformance. The pattern
matches RFC 8032 test vectors and reference Ed25519 implementations.

This material MUST NOT be added to any production trust anchor. The
key_id above is published only as a test artifact; any system that
trusts it as a real publisher is misconfigured.

This SAN-489 section is distinct from the SAN-404 "Test Key Rotation"
section above: SAN-404 covered a previously-committed PEM private key
that was inadvertently exposed and has been ROTATED + REVOKED. SAN-489
covers a fixed-seed test fixture that is and remains intentionally
public by design.
