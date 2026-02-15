"""
Sanna cryptographic operations — Ed25519 signing and verification.

Provides key generation, signing, and verification for constitutions
and receipts using Ed25519 asymmetric signatures.

v0.6.3: Constitution signature covers full document (not just the hash).
Receipt signature includes the receipt_signature metadata block (with
``signature`` set to ``""``).  Both carry a ``scheme`` field for
forward compatibility.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from .hashing import canonical_json_bytes


# =============================================================================
# SANITIZATION
# =============================================================================

def sanitize_for_signing(obj, path: str = "$"):
    """Sanitize a dict/list tree for canonical JSON signing.

    Walks *obj* recursively.  Floats that are exact integer values
    (e.g. ``71.0``) are silently converted to ``int``.  Lossy floats
    (e.g. ``71.43``) raise ``TypeError`` with the JSON-path so the caller
    can fix the data (use integer basis-points or a string representation).

    Returns a new object tree — the original is not mutated.
    """
    if isinstance(obj, float):
        if obj == int(obj) and not (obj != obj):  # exclude NaN
            return int(obj)
        raise TypeError(
            f"Float value {obj!r} at path {path} cannot be signed. "
            f"Use integer basis points or string representation."
        )
    if isinstance(obj, dict):
        return {k: sanitize_for_signing(v, f"{path}.{k}") for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize_for_signing(v, f"{path}[{i}]") for i, v in enumerate(obj)]
    return obj


# =============================================================================
# KEY MANAGEMENT
# =============================================================================

def generate_keypair(
    output_dir: str | Path = ".",
    signed_by: Optional[str] = None,
    write_metadata: bool = False,
    label: Optional[str] = None,
) -> tuple[Path, Path]:
    """Generate an Ed25519 keypair and write to PEM files.

    Key files are named by their key_id (SHA-256 of the public key):
    ``<key_id>.key``, ``<key_id>.pub``, and ``<key_id>.meta.json``.

    A metadata sidecar ``<key_id>.meta.json`` is always created,
    containing ``key_id``, ``created_at``, ``algorithm``, and optionally
    ``label`` and ``signed_by``.

    Args:
        output_dir: Directory for key files.
        signed_by: Human-readable signer identity (stored in meta.json).
        write_metadata: Legacy parameter, ignored. Meta.json is always written.
        label: Human-friendly label for the keypair (e.g. "author", "approver").

    Returns (private_key_path, public_key_path).
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    key_id = compute_key_id(public_key)

    private_path = output_dir / f"{key_id}.key"
    public_path = output_dir / f"{key_id}.pub"

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_bytes)
    public_path.write_bytes(public_bytes)

    # Restrict private key permissions (POSIX only)
    try:
        import os
        os.chmod(private_path, 0o600)
    except OSError:
        pass  # Windows or restricted filesystem

    # Always write metadata sidecar (atomic via temp + rename)
    import os
    meta: dict = {
        "key_id": key_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "Ed25519",
    }
    if label:
        meta["label"] = label
    if signed_by:
        meta["signed_by"] = signed_by
    meta_path = output_dir / f"{key_id}.meta.json"
    tmp_meta = meta_path.with_suffix(".meta.json.tmp")
    tmp_meta.write_text(json.dumps(meta, indent=2))
    os.replace(tmp_meta, meta_path)

    return private_path, public_path


def load_key_metadata(key_path: str | Path) -> dict | None:
    """Read the .meta.json sidecar for a key file, if it exists.

    Args:
        key_path: Path to a ``.key`` or ``.pub`` file.

    Returns the parsed metadata dict, or None if the sidecar is missing.
    """
    key_path = Path(key_path)
    # Derive meta path: replace .key/.pub extension with .meta.json
    stem = key_path.stem
    meta_path = key_path.parent / f"{stem}.meta.json"
    if meta_path.exists():
        return json.loads(meta_path.read_text())
    return None


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM file."""
    path = Path(path)
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"Expected Ed25519 private key, got {type(key).__name__}")
    return key


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM file."""
    path = Path(path)
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"Expected Ed25519 public key, got {type(key).__name__}")
    return key


def compute_key_id(public_key: Ed25519PublicKey) -> str:
    """Compute the full SHA-256 hex fingerprint of a public key (64 chars)."""
    raw_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw_bytes).hexdigest()


# =============================================================================
# SIGNING
# =============================================================================

def sign_bytes(data: bytes, private_key: Ed25519PrivateKey) -> str:
    """Sign data with Ed25519 and return base64-encoded signature."""
    signature = private_key.sign(data)
    return base64.b64encode(signature).decode("ascii")


def verify_signature(data: bytes, signature_b64: str, public_key: Ed25519PublicKey) -> bool:
    """Verify an Ed25519 signature. Returns True if valid.

    Uses strict base64 decoding (validate=True) with whitespace
    stripping for predictable cross-language behavior.
    """
    try:
        sig_clean = re.sub(r"\s+", "", signature_b64)
        signature = base64.b64decode(sig_clean, validate=True)
        public_key.verify(signature, data)
        return True
    except (binascii.Error, ValueError, Exception):
        return False


# =============================================================================
# CONSTITUTION SIGNING (v0.6.3: full-document)
# =============================================================================

def sign_constitution_full(
    constitution,
    private_key_path: str | Path,
    signed_by: Optional[str] = None,
):
    """Sign a constitution's full document with Ed25519.

    Returns a ConstitutionSignature dataclass with value, key_id,
    signed_by, signed_at, and scheme populated.

    The signed material is the canonical JSON of the full constitution
    (via constitution_to_signable_dict), which includes provenance and
    signer metadata.  Only provenance.signature.value is excluded
    (set to "").
    """
    from .constitution import ConstitutionSignature, constitution_to_signable_dict, Provenance

    private_key = load_private_key(private_key_path)
    public_key = private_key.public_key()
    key_id = compute_key_id(public_key)
    signed_at = datetime.now(timezone.utc).isoformat()

    # Build a ConstitutionSignature with all metadata but no value yet
    placeholder_sig = ConstitutionSignature(
        value="",  # placeholder — excluded from signing
        key_id=key_id,
        signed_by=signed_by or "",
        signed_at=signed_at,
        scheme="constitution_sig_v1",
    )

    # Attach placeholder to constitution's provenance for signable dict
    from .constitution import Constitution
    signing_constitution = Constitution(
        schema_version=constitution.schema_version,
        identity=constitution.identity,
        provenance=Provenance(
            authored_by=constitution.provenance.authored_by,
            approved_by=constitution.provenance.approved_by,
            approval_date=constitution.provenance.approval_date,
            approval_method=constitution.provenance.approval_method,
            change_history=constitution.provenance.change_history,
            signature=placeholder_sig,
        ),
        boundaries=constitution.boundaries,
        trust_tiers=constitution.trust_tiers,
        halt_conditions=constitution.halt_conditions,
        invariants=constitution.invariants,
        policy_hash=constitution.policy_hash,
        authority_boundaries=constitution.authority_boundaries,
        trusted_sources=constitution.trusted_sources,
        version=getattr(constitution, "version", "1.0"),
        reasoning=getattr(constitution, "reasoning", None),
    )

    signable_dict = constitution_to_signable_dict(signing_constitution)
    signable_dict = sanitize_for_signing(signable_dict)
    data = canonical_json_bytes(signable_dict)
    signature_b64 = sign_bytes(data, private_key)

    return ConstitutionSignature(
        value=signature_b64,
        key_id=key_id,
        signed_by=signed_by or "",
        signed_at=signed_at,
        scheme="constitution_sig_v1",
    )


def verify_constitution_full(
    constitution,
    public_key_path: str | Path,
) -> bool:
    """Verify a constitution's Ed25519 signature (full-document scheme).

    Reconstructs the signable dict (with provenance.signature.value=""),
    canonicalizes it, and verifies against the stored signature.
    Also checks that the key_id matches the public key.
    """
    from .constitution import constitution_to_signable_dict

    sig = constitution.provenance.signature
    if sig is None or not sig.value:
        return False

    public_key = load_public_key(public_key_path)

    # Check key_id matches
    expected_key_id = compute_key_id(public_key)
    if sig.key_id != expected_key_id:
        return False

    signable_dict = constitution_to_signable_dict(constitution)
    signable_dict = sanitize_for_signing(signable_dict)
    data = canonical_json_bytes(signable_dict)
    return verify_signature(data, sig.value, public_key)


# =============================================================================
# RECEIPT SIGNING (v0.6.3: metadata-binding)
# =============================================================================

def sign_receipt(
    receipt_dict: dict,
    private_key_path: str | Path,
    signed_by: Optional[str] = None,
) -> dict:
    """Sign a receipt and add receipt_signature block.

    v0.6.3: The receipt_signature block is included in the signed material
    with ``signature`` set to ``""`` (placeholder).  This binds the signer
    metadata (key_id, signed_by, signed_at) into the signature.
    """
    import copy

    private_key = load_private_key(private_key_path)
    public_key = private_key.public_key()
    key_id = compute_key_id(public_key)

    # Build the receipt_signature block with placeholder
    sig_block = {
        "signature": "",  # placeholder — excluded from signing
        "key_id": key_id,
        "signed_by": signed_by or "",
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "scheme": "receipt_sig_v1",
    }

    # Create signable copy with placeholder signature
    signable = copy.deepcopy(receipt_dict)
    signable["receipt_signature"] = sig_block
    signable = sanitize_for_signing(signable)
    data = canonical_json_bytes(signable)

    # Sign and replace placeholder
    signature_b64 = sign_bytes(data, private_key)
    sig_block["signature"] = signature_b64

    receipt_dict["receipt_signature"] = sig_block
    return receipt_dict


def verify_receipt_signature(
    receipt_dict: dict,
    public_key_path: str | Path,
) -> bool:
    """Verify a receipt's Ed25519 signature.

    v0.6.3: Reconstructs the signed material by setting
    receipt_signature.signature to "" (the placeholder used during signing).
    Also checks that receipt_signature.key_id matches the public key.
    """
    import copy

    sig_block = receipt_dict.get("receipt_signature")
    if not sig_block:
        return False

    signature_b64 = sig_block.get("signature", "")
    if not signature_b64:
        return False

    public_key = load_public_key(public_key_path)

    # Check key_id matches
    expected_key_id = compute_key_id(public_key)
    if sig_block.get("key_id") != expected_key_id:
        return False

    # Reconstruct signable form
    signable = copy.deepcopy(receipt_dict)
    signable["receipt_signature"]["signature"] = ""
    signable = sanitize_for_signing(signable)
    data = canonical_json_bytes(signable)

    return verify_signature(data, signature_b64, public_key)
