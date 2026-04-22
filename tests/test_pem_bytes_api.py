"""Tests for PEM-bytes key API: verify_receipt(public_key_pem=...) and sign_receipt_from_pem().

SAN-223: Additive parameters for server-side callers that hold keys in memory
(e.g. from a database column) rather than on the filesystem.
"""

import pytest
from dataclasses import asdict
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as rsa_generate

from sanna.crypto import sign_receipt_from_pem
from sanna.verify import verify_receipt, load_schema
from sanna.receipt import generate_receipt

SCHEMA = load_schema()


# =============================================================================
# Shared helpers
# =============================================================================

def _make_keypair():
    """Generate an in-memory Ed25519 keypair; return (private_pem, public_pem)."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    public_pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return private_pem, public_pem


def _make_receipt_dict():
    """Build a minimal v1.4 receipt dict (checks_version=9, tool_name set)."""
    trace_data = {
        "correlation_id": "test-pem-api-001",
        "name": "pem-api-test",
        "timestamp": "2026-01-01T00:00:00Z",
        "input": {"query": "Is this grounded?"},
        "output": {"final_answer": "Yes, this answer is grounded in the provided context."},
        "metadata": {},
        "observations": [
            {
                "id": "obs-1",
                "name": "retrieval",
                "type": "SPAN",
                "input": {"query": "grounding check"},
                "output": {"context": "This answer is grounded in the provided context."},
                "metadata": {},
                "start_time": "2026-01-01T00:00:01Z",
                "end_time": "2026-01-01T00:00:02Z",
            }
        ],
    }
    receipt = generate_receipt(trace_data)
    return asdict(receipt)


# =============================================================================
# Tests
# =============================================================================

def test_verify_with_public_key_pem_bytes():
    """verify_receipt accepts public_key_pem as bytes and validates a signed receipt."""
    private_pem, public_pem = _make_keypair()
    receipt = _make_receipt_dict()
    sign_receipt_from_pem(receipt, private_pem)
    result = verify_receipt(receipt, SCHEMA, public_key_pem=public_pem)
    assert result.valid, f"Expected valid=True, got errors: {result.errors}"


def test_verify_with_public_key_pem_str():
    """verify_receipt accepts public_key_pem as a UTF-8 string."""
    private_pem, public_pem = _make_keypair()
    receipt = _make_receipt_dict()
    sign_receipt_from_pem(receipt, private_pem)
    result = verify_receipt(receipt, SCHEMA, public_key_pem=public_pem.decode("utf-8"))
    assert result.valid, f"Expected valid=True, got errors: {result.errors}"


def test_verify_both_params_raises():
    """Specifying both public_key_path and public_key_pem raises ValueError."""
    receipt = _make_receipt_dict()
    with pytest.raises(ValueError, match="Cannot specify both"):
        verify_receipt(receipt, SCHEMA, public_key_path="x.pub", public_key_pem=b"y")


def test_verify_invalid_pem_raises():
    """Passing invalid PEM bytes as public_key_pem raises ValueError.

    The receipt must be signed so that the signature block is present and the
    code path reaches load_public_key_from_pem before returning False.
    """
    private_pem, _ = _make_keypair()
    receipt = _make_receipt_dict()
    sign_receipt_from_pem(receipt, private_pem)
    with pytest.raises(ValueError):
        verify_receipt(receipt, SCHEMA, public_key_pem=b"not valid pem")


def test_verify_wrong_algorithm_pem_raises():
    """Passing an RSA public key PEM raises ValueError (wrong algorithm).

    The receipt must be signed so that the signature block is present and the
    code path reaches load_public_key_from_pem before returning False.
    """
    private_pem, _ = _make_keypair()
    receipt = _make_receipt_dict()
    sign_receipt_from_pem(receipt, private_pem)
    rsa_priv = rsa_generate(public_exponent=65537, key_size=2048)
    rsa_pub_pem = rsa_priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(ValueError):
        verify_receipt(receipt, SCHEMA, public_key_pem=rsa_pub_pem)


def test_verify_backward_compat_path(tmp_path):
    """Existing public_key_path parameter still works after the additive change."""
    private_pem, public_pem = _make_keypair()
    pub_key_file = tmp_path / "key.pub"
    pub_key_file.write_bytes(public_pem)
    receipt = _make_receipt_dict()
    sign_receipt_from_pem(receipt, private_pem)
    result = verify_receipt(receipt, SCHEMA, public_key_path=str(pub_key_file))
    assert result.valid, f"Expected valid=True, got errors: {result.errors}"


def test_sign_with_private_key_pem_bytes():
    """sign_receipt_from_pem adds a valid receipt_signature block."""
    private_pem, _ = _make_keypair()
    receipt = _make_receipt_dict()
    result = sign_receipt_from_pem(receipt, private_pem)
    assert "receipt_signature" in result
    assert result["receipt_signature"]["scheme"] == "receipt_sig_v1"
    key_id = result["receipt_signature"]["key_id"]
    assert isinstance(key_id, str) and len(key_id) == 64
    assert result["receipt_signature"]["signature"] != ""


def test_round_trip_pem():
    """sign_receipt_from_pem → verify_receipt(public_key_pem=...) round-trip is valid."""
    private_pem, public_pem = _make_keypair()
    receipt = _make_receipt_dict()
    sign_receipt_from_pem(receipt, private_pem)
    result = verify_receipt(receipt, SCHEMA, public_key_pem=public_pem)
    assert result.valid, f"Round-trip failed: {result.errors}"


def test_sign_with_invalid_pem_raises():
    """sign_receipt_from_pem raises ValueError on invalid PEM input."""
    receipt = _make_receipt_dict()
    with pytest.raises(ValueError):
        sign_receipt_from_pem(receipt, b"not pem")


def test_sign_with_wrong_algorithm_raises():
    """sign_receipt_from_pem raises ValueError when given an RSA private key."""
    rsa_priv = rsa_generate(public_exponent=65537, key_size=2048)
    rsa_priv_pem = rsa_priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    receipt = _make_receipt_dict()
    with pytest.raises(ValueError):
        sign_receipt_from_pem(receipt, rsa_priv_pem)
