#!/usr/bin/env python3
"""Generate deterministic test vectors for Sanna.

Uses a fixed 32-byte seed for Ed25519 to produce reproducible keypairs,
signatures, and canonical JSON. Run from the repo root:

    python tests/generate_vectors.py

Writes JSON files to tests/vectors/.
"""

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# Fixed seed for deterministic keypair
SEED = b"\x01" * 32  # 32 bytes of 0x01

VECTORS_DIR = Path(__file__).parent / "vectors"
VECTORS_DIR.mkdir(exist_ok=True)


def make_keypair():
    """Deterministic Ed25519 keypair from fixed seed."""
    private_key = Ed25519PrivateKey.from_private_bytes(SEED)
    public_key = private_key.public_key()
    return private_key, public_key


def public_key_hex(pub):
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


def compute_key_id(pub):
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def canonical_json_bytes(obj):
    """RFC 8785 canonical JSON (restricted to Sanna's type set)."""
    canon = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return canon.encode("utf-8")


def sha256_full(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ============================================================================
# 1. Canonicalization vectors
# ============================================================================

def generate_canonicalization_vectors():
    cases = []

    # Case 1: simple sorted keys
    obj1 = {"b": 2, "a": 1}
    canon1 = canonical_json_bytes(obj1)
    cases.append({
        "name": "simple_sorted_keys",
        "description": "Object keys must be sorted lexicographically",
        "input": obj1,
        "expected_canonical_hex": canon1.hex(),
        "expected_sha256": sha256_full(canon1),
    })

    # Case 2: nested objects
    obj2 = {"z": {"b": 2, "a": 1}, "a": [3, 1, 2]}
    canon2 = canonical_json_bytes(obj2)
    cases.append({
        "name": "nested_objects",
        "description": "Nested dicts must also have sorted keys; arrays preserve order",
        "input": obj2,
        "expected_canonical_hex": canon2.hex(),
        "expected_sha256": sha256_full(canon2),
    })

    # Case 3: null and booleans
    obj3 = {"flag": True, "empty": None, "off": False}
    canon3 = canonical_json_bytes(obj3)
    cases.append({
        "name": "null_and_booleans",
        "description": "null, true, false serialized as JSON primitives",
        "input": obj3,
        "expected_canonical_hex": canon3.hex(),
        "expected_sha256": sha256_full(canon3),
    })

    # Case 4: unicode string
    obj4 = {"name": "Sanna \u2014 Truth"}
    canon4 = canonical_json_bytes(obj4)
    cases.append({
        "name": "unicode_string",
        "description": "Non-ASCII characters preserved with ensure_ascii=False",
        "input": obj4,
        "expected_canonical_hex": canon4.hex(),
        "expected_sha256": sha256_full(canon4),
    })

    # Case 5: empty structures
    obj5 = {"arr": [], "obj": {}}
    canon5 = canonical_json_bytes(obj5)
    cases.append({
        "name": "empty_structures",
        "description": "Empty array and object have compact representation",
        "input": obj5,
        "expected_canonical_hex": canon5.hex(),
        "expected_sha256": sha256_full(canon5),
    })

    # Case 6: integer types
    obj6 = {"neg": -42, "pos": 100, "zero": 0}
    canon6 = canonical_json_bytes(obj6)
    cases.append({
        "name": "integer_types",
        "description": "Integers including negative and zero; no floats allowed",
        "input": obj6,
        "expected_canonical_hex": canon6.hex(),
        "expected_sha256": sha256_full(canon6),
    })

    # Case 7: deeply nested
    obj7 = {"level1": {"level2": {"level3": {"value": 42}}}}
    canon7 = canonical_json_bytes(obj7)
    cases.append({
        "name": "deeply_nested",
        "description": "Multiple nesting levels with sorted keys at each level",
        "input": obj7,
        "expected_canonical_hex": canon7.hex(),
        "expected_sha256": sha256_full(canon7),
    })

    return {
        "description": "Canonicalization test vectors for RFC 8785-style canonical JSON (integers only, no floats)",
        "rules": [
            "Keys sorted lexicographically at every nesting level",
            "Compact separators: comma and colon with no spaces",
            "ensure_ascii=False: non-ASCII characters preserved as UTF-8",
            "Floats are rejected — all numeric values must be integers",
            "JSON primitives: null, true, false (lowercase)",
        ],
        "cases": cases,
    }


# ============================================================================
# 2. Constitution signature vectors
# ============================================================================

def generate_constitution_signature_vectors():
    private_key, public_key = make_keypair()
    key_id = compute_key_id(public_key)

    # Minimal signable dict matching constitution_to_signable_dict() output
    signable_dict = {
        "schema_version": "0.1.0",
        "identity": {
            "agent_name": "vector-test-agent",
            "domain": "testing",
            "description": "Test vector agent",
        },
        "provenance": {
            "authored_by": "test-author",
            "approved_by": ["test-approver"],
            "approval_date": "2025-01-01",
            "approval_method": "test",
            "change_history": [],
            "signature": {
                "value": "",
                "key_id": key_id,
                "signed_by": "vector-signer",
                "signed_at": "2025-01-01T00:00:00+00:00",
                "scheme": "constitution_sig_v1",
            },
        },
        "boundaries": [
            {
                "id": "B001",
                "description": "Test boundary",
                "category": "scope",
                "severity": "high",
            }
        ],
        "trust_tiers": {
            "autonomous": ["read"],
            "requires_approval": ["write"],
            "prohibited": ["delete"],
        },
        "halt_conditions": [],
        "invariants": [
            {
                "id": "INV_NO_FABRICATION",
                "rule": "Never fabricate information",
                "enforcement": "halt",
                "check": None,
            }
        ],
        "policy_hash": "abc123",
    }

    canonical = canonical_json_bytes(signable_dict)
    signature = private_key.sign(canonical)
    signature_b64 = base64.b64encode(signature).decode("ascii")

    return {
        "description": "Constitution Ed25519 signature test vector",
        "scheme": "constitution_sig_v1",
        "signing_rules": [
            "provenance.signature.value is set to empty string before signing",
            "Full document is canonicalized via RFC 8785-style JSON",
            "Ed25519 signature over canonical bytes",
            "Signature is base64-encoded",
        ],
        "seed_hex": SEED.hex(),
        "public_key_hex": public_key_hex(public_key),
        "key_id": key_id,
        "signable_dict": signable_dict,
        "expected_canonical_hex": canonical.hex(),
        "expected_signature_base64": signature_b64,
    }


# ============================================================================
# 3. Receipt signature vectors
# ============================================================================

def generate_receipt_signature_vectors():
    private_key, public_key = make_keypair()
    key_id = compute_key_id(public_key)

    # Minimal receipt dict
    receipt_dict = {
        "sanna_version": "0.6.4",
        "schema_version": "0.6.1",
        "correlation_id": "vector-trace-001",
        "timestamp": "2025-01-01T00:00:00+00:00",
        "query_hash": "abc123",
        "context_hash": "def456",
        "output_hash": "ghi789",
        "checks_version": "0.6.1",
        "checks_passed": 1,
        "checks_run": 1,
        "checks": [
            {
                "check_id": "sanna.context_contradiction",
                "passed": True,
                "severity": "critical",
                "evidence": "No contradiction found",
                "triggered_by": "INV_NO_FABRICATION",
                "enforcement_level": "halt",
                "check_impl": "sanna.context_contradiction",
                "replayable": True,
            }
        ],
        "status": "PASS",
        "receipt_fingerprint": "placeholder",
        "receipt_signature": {
            "signature": "",
            "key_id": key_id,
            "signed_by": "vector-signer",
            "signed_at": "2025-01-01T00:00:00+00:00",
            "scheme": "receipt_sig_v1",
        },
    }

    canonical = canonical_json_bytes(receipt_dict)
    signature = private_key.sign(canonical)
    signature_b64 = base64.b64encode(signature).decode("ascii")

    return {
        "description": "Receipt Ed25519 signature test vector",
        "scheme": "receipt_sig_v1",
        "signing_rules": [
            "receipt_signature.signature is set to empty string before signing",
            "Full receipt is canonicalized via RFC 8785-style JSON",
            "Ed25519 signature over canonical bytes",
            "Signature is base64-encoded",
        ],
        "seed_hex": SEED.hex(),
        "public_key_hex": public_key_hex(public_key),
        "key_id": key_id,
        "receipt_dict": receipt_dict,
        "expected_canonical_hex": canonical.hex(),
        "expected_signature_base64": signature_b64,
    }


# ============================================================================
# Main
# ============================================================================

def main():
    vectors = {
        "canonicalization.json": generate_canonicalization_vectors(),
        "constitution_signature.json": generate_constitution_signature_vectors(),
        "receipt_signature.json": generate_receipt_signature_vectors(),
    }

    for filename, data in vectors.items():
        path = VECTORS_DIR / filename
        path.write_text(json.dumps(data, indent=2) + "\n")
        print(f"  Written: {path}")

    print(f"\n  {len(vectors)} vector files generated in {VECTORS_DIR}")


if __name__ == "__main__":
    main()
