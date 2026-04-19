# Golden Receipt Archive

This directory contains archived golden receipt test vectors from prior SDK versions.

## Purpose

- **Regression testing**: Historical receipts let us verify that `sanna-verify` can still
  validate receipts emitted by older SDK versions (backward-compatibility guarantee).
- **SOC 2 audit trail**: Archived receipts document the exact receipt format at each
  release boundary, providing evidence for auditors that format changes were intentional
  and versioned.
- **Customer reference**: Customers who received receipts from prior SDK versions can
  verify those receipts remain authentic using these vectors.

## Version Directories

### `pre-v1.3/`

Golden receipts from the v0.13.x / v1.0.x / v1.1.x era (CHECKS_VERSION "5"–"7",
14-field fingerprint formula). These were the live golden vectors before the SAN-213
v1.3 release upgraded to CHECKS_VERSION "8" (16-field fingerprint).

The `v13_*` filenames in this directory used CHECKS_VERSION "6" despite the "v13" naming
(they predate the version renaming in v1.0.0). They are preserved here as regression
fixtures.

The `verify.py` auto-detects the fingerprint formula by `checks_version` integer value:
- `>= 8` → 16-field (v1.3+)
- `6`–`7` → 14-field (v1.0–v1.1)
- `<= 5` → 12-field (legacy)

So all archived receipts remain verifiable under the current SDK.

## Live Goldens

The `golden/receipts/*.json` files at the top level are the current golden vectors.
Pre-v1.0 numbered receipts (001–011, 999_tampered) are still referenced by tests and
remain at the top level.
