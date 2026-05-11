# Sanna Test Vectors

Deterministic test vectors for third-party Sanna SDK verifier implementations.

The Ed25519 seed used to generate these vectors is **INTENTIONALLY PUBLIC**.
The corresponding private key is NOT secret and MUST NOT be added to any
production trust anchor. The vectors exist so third-party SDK implementations
can reproduce signatures byte-for-byte and verify their canonicalization +
signing pipelines match Sanna's specification.

This is the same pattern as RFC 8032 test vectors and reference Ed25519
implementations: a fixed seed enables reproducibility for cross-language
conformance testing.

All vectors use the seed `0x01` repeated 32 times. The derived public key
and key_id are committed alongside the signed output for verifier convenience.

## Files

| File | Description |
|------|-------------|
| `canonicalization.json` | RFC 8785-style canonical JSON test cases |
| `constitution_signature.json` | Constitution Ed25519 signature vector (protocol conformance; seed `0x01`*32) |
| `receipt_signature.json` | Receipt Ed25519 signature vector (protocol conformance; seed `0x01`*32) |
| `ed25519_rfc8032.json` | IETF RFC 8032 Section 7.1 Ed25519 algorithm-conformance vectors (SAN-496) |

## Canonicalization Rules

Sanna uses RFC 8785 (JSON Canonicalization Scheme) with a restricted type set:

1. **Sorted keys** — lexicographic at every nesting level
2. **Compact separators** — `","` and `":"` with no spaces
3. **UTF-8 encoding** — `ensure_ascii=False`, non-ASCII preserved
4. **Integers only** — floats are rejected at the signing boundary
5. **JSON primitives** — `null`, `true`, `false` (lowercase)

## Signing Schemes

### `constitution_sig_v1`

- **Signed material**: full constitution as canonical JSON
- **Excluded field**: `provenance.signature.value` (set to `""`)
- **Algorithm**: Ed25519 over canonical bytes
- **Output**: base64-encoded signature

### `receipt_sig_v1`

- **Signed material**: full receipt as canonical JSON
- **Excluded field**: `receipt_signature.signature` (set to `""`)
- **Algorithm**: Ed25519 over canonical bytes
- **Output**: base64-encoded signature

## Key ID Derivation

```
key_id = SHA-256(raw_public_key_bytes)  # 64-char hex string
```

Where `raw_public_key_bytes` is the 32-byte raw Ed25519 public key
(not PEM-encoded, not DER — just the raw key material).

## Regenerating Vectors

```bash
python tests/generate_vectors.py
```

The generator uses `Ed25519PrivateKey.from_private_bytes(seed)` with
the fixed seed, so output is always identical.

## RFC 8032 Algorithm Conformance (SAN-496)

`ed25519_rfc8032.json` covers a **different test surface** than the protocol-conformance vectors above. The protocol vectors (`constitution_signature.json`, `receipt_signature.json`) verify that this SDK canonicalizes + signs in Sanna's specified style. The RFC 8032 vectors verify that this SDK's underlying Ed25519 implementation produces byte-correct outputs against the IETF authoritative reference -- catching the failure mode where a buggy Ed25519 implementation could pass protocol-conformance (correct flow, wrong crypto output).

Source: [IETF RFC 8032 Section 7.1](https://datatracker.ietf.org/doc/html/rfc8032#section-7.1).

The 5 vectors covered are TEST 1 (empty message), TEST 2 (1 byte), TEST 3 (2 bytes), TEST 1024 (1023 bytes), and TEST SHA(abc) (64-byte SHA-512 of "abc"). For each: the SDK derives the public key from the RFC seed, signs the RFC message, and asserts both outputs match the RFC byte-for-byte. A round-trip verify is also asserted.

These vectors are **hard-coded from the RFC text**, not generated. The authoritative-source link is therefore unambiguous: if `ed25519_rfc8032.json` ever drifts from RFC 8032 Section 7.1, that's a regression worth investigating.
