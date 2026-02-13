# Sanna Test Vectors

Deterministic test vectors for third-party verifier implementations.
All vectors use a fixed Ed25519 seed (`0x01` repeated 32 times) for reproducibility.

## Files

| File | Description |
|------|-------------|
| `canonicalization.json` | RFC 8785-style canonical JSON test cases |
| `constitution_signature.json` | Constitution Ed25519 signature vector |
| `receipt_signature.json` | Receipt Ed25519 signature vector |

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
