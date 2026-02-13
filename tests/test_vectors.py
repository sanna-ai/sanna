"""Tests for deterministic test vectors.

Validates that committed vector files match regeneration and that
Sanna's crypto/hashing internals produce the expected outputs.
"""

import base64
import hashlib
import json
from pathlib import Path

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from sanna.hashing import canonical_json_bytes, sha256_hex
from sanna.crypto import sanitize_for_signing

VECTORS_DIR = Path(__file__).parent / "vectors"
SEED = b"\x01" * 32


def _load_vector(name: str) -> dict:
    return json.loads((VECTORS_DIR / name).read_text())


def _make_keypair():
    private_key = Ed25519PrivateKey.from_private_bytes(SEED)
    return private_key, private_key.public_key()


def _raw_public_hex(pub) -> str:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def _compute_key_id(pub) -> str:
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


# =============================================================================
# CANONICALIZATION VECTORS
# =============================================================================

class TestCanonicalization:
    @pytest.fixture
    def vectors(self):
        return _load_vector("canonicalization.json")

    def test_simple_sorted_keys(self, vectors):
        case = next(c for c in vectors["cases"] if c["name"] == "simple_sorted_keys")
        canon = canonical_json_bytes(case["input"])
        assert canon.hex() == case["expected_canonical_hex"]
        assert hashlib.sha256(canon).hexdigest() == case["expected_sha256"]

    def test_nested_objects(self, vectors):
        case = next(c for c in vectors["cases"] if c["name"] == "nested_objects")
        canon = canonical_json_bytes(case["input"])
        assert canon.hex() == case["expected_canonical_hex"]
        assert hashlib.sha256(canon).hexdigest() == case["expected_sha256"]

    def test_null_and_booleans(self, vectors):
        case = next(c for c in vectors["cases"] if c["name"] == "null_and_booleans")
        canon = canonical_json_bytes(case["input"])
        assert canon.hex() == case["expected_canonical_hex"]
        assert hashlib.sha256(canon).hexdigest() == case["expected_sha256"]

    def test_unicode_string(self, vectors):
        case = next(c for c in vectors["cases"] if c["name"] == "unicode_string")
        canon = canonical_json_bytes(case["input"])
        assert canon.hex() == case["expected_canonical_hex"]
        assert hashlib.sha256(canon).hexdigest() == case["expected_sha256"]

    def test_empty_structures(self, vectors):
        case = next(c for c in vectors["cases"] if c["name"] == "empty_structures")
        canon = canonical_json_bytes(case["input"])
        assert canon.hex() == case["expected_canonical_hex"]
        assert hashlib.sha256(canon).hexdigest() == case["expected_sha256"]

    def test_integer_types(self, vectors):
        case = next(c for c in vectors["cases"] if c["name"] == "integer_types")
        canon = canonical_json_bytes(case["input"])
        assert canon.hex() == case["expected_canonical_hex"]
        assert hashlib.sha256(canon).hexdigest() == case["expected_sha256"]

    def test_deeply_nested(self, vectors):
        case = next(c for c in vectors["cases"] if c["name"] == "deeply_nested")
        canon = canonical_json_bytes(case["input"])
        assert canon.hex() == case["expected_canonical_hex"]
        assert hashlib.sha256(canon).hexdigest() == case["expected_sha256"]

    def test_all_cases_covered(self, vectors):
        """Every case in the vector file is tested."""
        names = {c["name"] for c in vectors["cases"]}
        expected = {
            "simple_sorted_keys", "nested_objects", "null_and_booleans",
            "unicode_string", "empty_structures", "integer_types", "deeply_nested",
        }
        assert names == expected


# =============================================================================
# CONSTITUTION SIGNATURE VECTORS
# =============================================================================

class TestConstitutionSignature:
    @pytest.fixture
    def vector(self):
        return _load_vector("constitution_signature.json")

    def test_canonical_bytes_match(self, vector):
        signable = vector["signable_dict"]
        signable = sanitize_for_signing(signable)
        canon = canonical_json_bytes(signable)
        assert canon.hex() == vector["expected_canonical_hex"]

    def test_signature_verifies(self, vector):
        _, pub = _make_keypair()
        canon = bytes.fromhex(vector["expected_canonical_hex"])
        sig = base64.b64decode(vector["expected_signature_base64"])
        # Ed25519 verify raises on failure
        pub.verify(sig, canon)

    def test_key_id_matches(self, vector):
        _, pub = _make_keypair()
        assert _compute_key_id(pub) == vector["key_id"]

    def test_public_key_hex_matches(self, vector):
        _, pub = _make_keypair()
        assert _raw_public_hex(pub) == vector["public_key_hex"]


# =============================================================================
# RECEIPT SIGNATURE VECTORS
# =============================================================================

class TestReceiptSignature:
    @pytest.fixture
    def vector(self):
        return _load_vector("receipt_signature.json")

    def test_canonical_bytes_match(self, vector):
        receipt = vector["receipt_dict"]
        receipt = sanitize_for_signing(receipt)
        canon = canonical_json_bytes(receipt)
        assert canon.hex() == vector["expected_canonical_hex"]

    def test_signature_verifies(self, vector):
        _, pub = _make_keypair()
        canon = bytes.fromhex(vector["expected_canonical_hex"])
        sig = base64.b64decode(vector["expected_signature_base64"])
        pub.verify(sig, canon)

    def test_key_id_matches(self, vector):
        _, pub = _make_keypair()
        assert _compute_key_id(pub) == vector["key_id"]

    def test_public_key_hex_matches(self, vector):
        _, pub = _make_keypair()
        assert _raw_public_hex(pub) == vector["public_key_hex"]


# =============================================================================
# DETERMINISM AND SELF-CONSISTENCY
# =============================================================================

class TestDeterminism:
    def test_keypair_is_deterministic(self):
        """Same seed always produces the same keypair."""
        _, pub1 = _make_keypair()
        _, pub2 = _make_keypair()
        assert _raw_public_hex(pub1) == _raw_public_hex(pub2)

    def test_vectors_regenerate_identically(self):
        """Running the generator twice produces identical output."""
        from tests.generate_vectors import (
            generate_canonicalization_vectors,
            generate_constitution_signature_vectors,
            generate_receipt_signature_vectors,
        )

        canon = generate_canonicalization_vectors()
        committed = _load_vector("canonicalization.json")
        assert canon == committed

        const_sig = generate_constitution_signature_vectors()
        committed_const = _load_vector("constitution_signature.json")
        assert const_sig == committed_const

        receipt_sig = generate_receipt_signature_vectors()
        committed_receipt = _load_vector("receipt_signature.json")
        assert receipt_sig == committed_receipt

    def test_raw_crypto_verification(self):
        """Verify signature using only raw crypto, no sanna imports."""
        private_key = Ed25519PrivateKey.from_private_bytes(SEED)
        pub = private_key.public_key()

        # Sign arbitrary data
        data = b'{"test":true}'
        sig = private_key.sign(data)

        # Verify
        pub.verify(sig, data)  # raises on failure

        # Verify key_id derivation
        raw_bytes = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        key_id = hashlib.sha256(raw_bytes).hexdigest()
        assert len(key_id) == 64
