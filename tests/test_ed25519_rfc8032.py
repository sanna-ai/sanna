"""SAN-496: RFC 8032 Section 7.1 Ed25519 algorithm-conformance tests.

Verifies the SDK's Ed25519 implementation (via the `cryptography` library
imported at src/sanna/crypto.py:27) produces byte-correct outputs against
the IETF RFC 8032 reference vectors. This is the ALGORITHM-conformance
test surface; the PROTOCOL-conformance surface lives in the existing
constitution_signature.json + receipt_signature.json vectors using the
SAN-489-relabeled fixed seed.

Source: https://datatracker.ietf.org/doc/html/rfc8032#section-7.1

For each RFC 8032 vector:
  1. Derive raw public key from secret seed; assert byte-exact match with RFC pubkey
  2. Sign the message; assert byte-exact match with RFC signature
  3. Verify the signature against the public key (round-trip)

A sanity test asserts the JSON file contains exactly the 5 RFC 8032
Section 7.1 vectors -- no more, no less.

Runs on Python 3.10, 3.11, 3.12 (CI matrix).
"""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

VECTORS_FILE = Path(__file__).parent / "vectors" / "ed25519_rfc8032.json"


def _load_vectors():
    with VECTORS_FILE.open(encoding="utf-8") as f:
        data = json.load(f)
    return data["vectors"]


@pytest.mark.parametrize(
    "vector", _load_vectors(), ids=lambda v: v["name"]
)
def test_ed25519_rfc8032_public_key_derivation(vector):
    """Derived public key matches the RFC 8032 expected pubkey byte-for-byte."""
    seed = bytes.fromhex(vector["secret_key_hex"])
    expected_pubkey = bytes.fromhex(vector["public_key_hex"])

    sk = Ed25519PrivateKey.from_private_bytes(seed)
    derived_pubkey = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    assert derived_pubkey == expected_pubkey, (
        f"Public key derivation mismatch for {vector['name']}: "
        f"expected {expected_pubkey.hex()}, got {derived_pubkey.hex()}. "
        f"See RFC 8032 Section 7.1."
    )


@pytest.mark.parametrize(
    "vector", _load_vectors(), ids=lambda v: v["name"]
)
def test_ed25519_rfc8032_signature_matches(vector):
    """Signing the RFC message with the RFC seed produces the RFC signature byte-for-byte."""
    seed = bytes.fromhex(vector["secret_key_hex"])
    message = bytes.fromhex(vector["message_hex"])
    expected_signature = bytes.fromhex(vector["signature_hex"])

    sk = Ed25519PrivateKey.from_private_bytes(seed)
    signature = sk.sign(message)

    assert signature == expected_signature, (
        f"Signature mismatch for {vector['name']}: "
        f"expected {expected_signature.hex()}, got {signature.hex()}. "
        f"See RFC 8032 Section 7.1."
    )


@pytest.mark.parametrize(
    "vector", _load_vectors(), ids=lambda v: v["name"]
)
def test_ed25519_rfc8032_signature_verifies(vector):
    """The RFC signature verifies against the RFC public key + message (round-trip)."""
    pubkey_raw = bytes.fromhex(vector["public_key_hex"])
    message = bytes.fromhex(vector["message_hex"])
    signature = bytes.fromhex(vector["signature_hex"])

    pk = Ed25519PublicKey.from_public_bytes(pubkey_raw)
    pk.verify(signature, message)  # raises InvalidSignature on mismatch


def test_ed25519_rfc8032_vectors_file_has_all_five():
    """Sanity-check: tests/vectors/ed25519_rfc8032.json contains exactly the 5 RFC 8032 Section 7.1 vectors."""
    vectors = _load_vectors()
    names = {v["name"] for v in vectors}
    expected = {"TEST 1", "TEST 2", "TEST 3", "TEST 1024", "TEST SHA(abc)"}
    assert names == expected, (
        f"Expected exactly the 5 RFC 8032 Section 7.1 vectors {sorted(expected)}; "
        f"got {sorted(names)}."
    )
