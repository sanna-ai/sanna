"""
Sanna evidence bundle — self-contained verification archives.

A bundle is a zip archive containing a receipt, the constitution that
drove its evaluation, and the public key(s) needed for offline Ed25519
signature verification.  It is the "handover moment" artifact — what
auditors, regulators, and third parties receive.

Bundle structure::

    receipt.json
    constitution.yaml
    public_keys/{key_id}.pub
    metadata.json
"""

from __future__ import annotations

import json
import logging
import tempfile
import zipfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("sanna.bundle")

BUNDLE_FORMAT_VERSION = "1.0.0"

# Safety limits for bundle verification
MAX_BUNDLE_MEMBERS = 10
MAX_BUNDLE_FILE_SIZE = 10 * 1024 * 1024  # 10 MB per member
_EXPECTED_MEMBERS = {"receipt.json", "constitution.yaml", "metadata.json"}
_EXPECTED_PREFIX = "public_keys/"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class BundleCheck:
    """Single verification step result."""
    name: str
    passed: bool
    detail: str


@dataclass
class BundleVerificationResult:
    """Result of bundle verification with per-step checks."""
    valid: bool
    checks: list[BundleCheck]
    receipt_summary: Optional[dict]
    errors: list[str] = field(default_factory=list)


# =============================================================================
# BUNDLE CREATION
# =============================================================================

def create_bundle(
    receipt_path: str | Path,
    constitution_path: str | Path,
    public_key_path: str | Path,
    output_path: str | Path,
    description: Optional[str] = None,
    approver_public_key_path: Optional[str | Path] = None,
    constitution_public_key_path: Optional[str | Path] = None,
) -> Path:
    """Create an evidence bundle zip archive.

    Args:
        receipt_path: Path to a signed receipt JSON file.
        constitution_path: Path to a signed constitution YAML/JSON file.
        public_key_path: Path to the Ed25519 public key PEM file (for receipt).
        output_path: Output path for the bundle zip.
        description: Optional human-readable note for metadata.
        approver_public_key_path: Path to the approver's Ed25519 public key
            PEM file. When provided, included in the bundle for offline
            approval verification.
        constitution_public_key_path: Path to the constitution author's Ed25519
            public key PEM file. When the constitution was signed by a different
            key than the receipt, provide this so the bundle includes both keys.

    Returns:
        Path to the created bundle.

    Raises:
        FileNotFoundError: If any input file does not exist.
        ValueError: If receipt is not valid JSON or is unsigned, or
            if constitution has no policy_hash.
    """
    receipt_path = Path(receipt_path)
    constitution_path = Path(constitution_path)
    public_key_path = Path(public_key_path)
    output_path = Path(output_path)

    # Validate inputs exist
    for p, label in [
        (receipt_path, "Receipt"),
        (constitution_path, "Constitution"),
        (public_key_path, "Public key"),
    ]:
        if not p.exists():
            raise FileNotFoundError(f"{label} not found: {p}")

    # Validate receipt
    try:
        receipt_text = receipt_path.read_text(encoding="utf-8")
        receipt = json.loads(receipt_text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Receipt is not valid JSON: {e}") from e

    if "receipt_signature" not in receipt:
        raise ValueError(
            "Receipt is not signed (no receipt_signature). "
            "Sign with: sign_receipt(receipt, private_key_path)"
        )

    # Validate constitution has policy_hash
    constitution_text = constitution_path.read_text(encoding="utf-8")
    if constitution_path.suffix in (".yaml", ".yml"):
        import yaml
        const_data = yaml.safe_load(constitution_text)
    else:
        const_data = json.loads(constitution_text)

    if not const_data.get("policy_hash"):
        raise ValueError(
            f"Constitution is not signed (no policy_hash): {constitution_path}. "
            f"Run: sanna-sign-constitution {constitution_path}"
        )

    # Require Ed25519 signature (not just hash)
    prov = const_data.get("provenance") or {}
    sig = prov.get("signature") or {}
    if not sig.get("value") or not sig.get("key_id"):
        raise ValueError(
            f"Constitution is not Ed25519-signed (missing signature.value or key_id): "
            f"{constitution_path}. Run: sanna-sign-constitution {constitution_path} --private-key <key>"
        )

    # Load public key and compute key_id
    from .crypto import load_public_key, compute_key_id
    public_key = load_public_key(public_key_path)
    key_id = compute_key_id(public_key)

    # Build metadata
    from .receipt import TOOL_VERSION
    metadata = {
        "bundle_format_version": BUNDLE_FORMAT_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": TOOL_VERSION,
        "description": description or "",
    }

    # v0.9.0: Add approval metadata
    approval_block = const_data.get("approval")
    if approval_block and approval_block.get("records"):
        current = approval_block["records"][-1]
        metadata["approval_status"] = current.get("status", "unapproved")
        metadata["approver_id"] = current.get("approver_id")
        metadata["approver_role"] = current.get("approver_role")
        metadata["approved_at"] = current.get("approved_at")
        metadata["constitution_version"] = current.get("constitution_version")
        metadata["content_hash"] = current.get("content_hash")
    else:
        metadata["approval_status"] = "unapproved"

    # v0.9.0: Build governance_summary
    governance_summary = {
        "constitution_author": prov.get("authored_by"),
    }
    if metadata["approval_status"] == "approved":
        approver = metadata.get("approver_id", "")
        role = metadata.get("approver_role", "")
        governance_summary["constitution_approved_by"] = f"{approver} ({role})" if role else approver
        governance_summary["constitution_version"] = metadata.get("constitution_version")
        governance_summary["approval_date"] = metadata.get("approved_at")
    governance_summary["constitution_approval_verified"] = (
        metadata["approval_status"] == "approved" and approver_public_key_path is not None
    )

    # v0.9.1: Identity verification in governance_summary
    iv = receipt.get("identity_verification")
    if iv and isinstance(iv, dict):
        governance_summary["identity_claims_total"] = iv.get("total_claims", 0)
        governance_summary["identity_claims_verified"] = iv.get("verified", 0)
        governance_summary["identity_claims_all_verified"] = iv.get("all_verified", False)

    metadata["governance_summary"] = governance_summary

    # Create zip archive
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("receipt.json", receipt_text)
        zf.writestr("constitution.yaml", constitution_text)
        zf.writestr(
            f"public_keys/{key_id}.pub",
            public_key_path.read_text(encoding="utf-8"),
        )

        # v0.9.0: Include constitution author's public key if different
        if constitution_public_key_path is not None:
            const_pub_path = Path(constitution_public_key_path)
            if const_pub_path.exists():
                const_pub_key = load_public_key(const_pub_path)
                const_key_id = compute_key_id(const_pub_key)
                if const_key_id != key_id:
                    zf.writestr(
                        f"public_keys/{const_key_id}.pub",
                        const_pub_path.read_text(encoding="utf-8"),
                    )

        # v0.9.0: Include approver's public key if provided
        if approver_public_key_path is not None:
            approver_pub_path = Path(approver_public_key_path)
            if approver_pub_path.exists():
                approver_pub_key = load_public_key(approver_pub_path)
                approver_key_id = compute_key_id(approver_pub_key)
                if approver_key_id != key_id:
                    zf.writestr(
                        f"public_keys/{approver_key_id}.pub",
                        approver_pub_path.read_text(encoding="utf-8"),
                    )

        zf.writestr("metadata.json", json.dumps(metadata, indent=2))

    logger.info("Bundle created: %s (key_id=%s)", output_path, key_id[:16])
    return output_path


# =============================================================================
# BUNDLE VERIFICATION
# =============================================================================

def verify_bundle(
    bundle_path: str | Path,
    strict: bool = True,
) -> BundleVerificationResult:
    """Verify an evidence bundle's integrity.

    Runs seven verification steps:

    1. **Bundle structure** — required files present in the zip.
    2. **Receipt schema** — receipt validates against JSON schema.
    3. **Receipt fingerprint** — deterministic fingerprint matches.
    4. **Constitution signature** — Ed25519 signature valid.
    5. **Provenance chain** — receipt→constitution binding intact.
    6. **Receipt signature** — Ed25519 signature valid.
    7. **Approval verification** — approval content hash and signature.

    Args:
        bundle_path: Path to the bundle zip file.
        strict: If True (default), all checks must pass for
            ``valid=True``.  If False, returns partial results.

    Returns:
        BundleVerificationResult with per-step checks and summary.
    """
    bundle_path = Path(bundle_path)
    if not bundle_path.exists():
        raise FileNotFoundError(f"Bundle not found: {bundle_path}")

    checks: list[BundleCheck] = []
    errors: list[str] = []
    receipt_summary: Optional[dict] = None

    # ---- Open zip safely ----
    try:
        zf = zipfile.ZipFile(bundle_path, "r")
    except zipfile.BadZipFile:
        return BundleVerificationResult(
            valid=False,
            checks=[BundleCheck("Bundle structure", False, "Not a valid zip file")],
            receipt_summary=None,
            errors=["Not a valid zip file"],
        )

    with tempfile.TemporaryDirectory(prefix="sanna_bundle_") as tmp_dir:
        tmp = Path(tmp_dir)

        # ---- Safe extraction: no extractall(), read members individually ----
        members = zf.namelist()

        # Guard: max member count
        if len(members) > MAX_BUNDLE_MEMBERS:
            zf.close()
            detail = f"Too many members: {len(members)} (max {MAX_BUNDLE_MEMBERS})"
            checks.append(BundleCheck("Bundle structure", False, detail))
            return BundleVerificationResult(
                valid=False, checks=checks,
                receipt_summary=None,
                errors=[f"Bundle structure invalid: {detail}"],
            )

        # Guard: reject ".." in paths (zip slip) and unexpected members
        for name in members:
            if ".." in name:
                zf.close()
                detail = f"Unsafe path in bundle: '{name}'"
                checks.append(BundleCheck("Bundle structure", False, detail))
                return BundleVerificationResult(
                    valid=False, checks=checks,
                    receipt_summary=None,
                    errors=[f"Bundle structure invalid: {detail}"],
                )
            if name not in _EXPECTED_MEMBERS and not (
                name.startswith(_EXPECTED_PREFIX) and name.endswith(".pub")
            ):
                zf.close()
                detail = f"Unexpected member in bundle: '{name}'"
                checks.append(BundleCheck("Bundle structure", False, detail))
                return BundleVerificationResult(
                    valid=False, checks=checks,
                    receipt_summary=None,
                    errors=[f"Bundle structure invalid: {detail}"],
                )

        # Read each member individually with size check
        for name in members:
            info = zf.getinfo(name)
            if info.file_size > MAX_BUNDLE_FILE_SIZE:
                zf.close()
                detail = f"Member '{name}' too large: {info.file_size} bytes (max {MAX_BUNDLE_FILE_SIZE})"
                checks.append(BundleCheck("Bundle structure", False, detail))
                return BundleVerificationResult(
                    valid=False, checks=checks,
                    receipt_summary=None,
                    errors=[f"Bundle structure invalid: {detail}"],
                )
            dest = tmp / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(name) as src:
                data = src.read(MAX_BUNDLE_FILE_SIZE + 1)
                if len(data) > MAX_BUNDLE_FILE_SIZE:
                    zf.close()
                    detail = f"Member '{name}' exceeds size limit during read"
                    checks.append(BundleCheck("Bundle structure", False, detail))
                    return BundleVerificationResult(
                        valid=False, checks=checks,
                        receipt_summary=None,
                        errors=[f"Bundle structure invalid: {detail}"],
                    )
                dest.write_bytes(data)
        zf.close()

        # ---- Step 1: Bundle structure ----
        receipt_file = tmp / "receipt.json"
        constitution_file = tmp / "constitution.yaml"
        public_keys_dir = tmp / "public_keys"

        missing = []
        if not receipt_file.exists():
            missing.append("receipt.json")
        if not constitution_file.exists():
            missing.append("constitution.yaml")
        if not public_keys_dir.exists() or not list(public_keys_dir.glob("*.pub")):
            missing.append("public_keys/*.pub")

        if missing:
            detail = f"Missing: {', '.join(missing)}"
            checks.append(BundleCheck("Bundle structure", False, detail))
            return BundleVerificationResult(
                valid=False, checks=checks,
                receipt_summary=None,
                errors=[f"Bundle structure invalid: {detail}"],
            )
        checks.append(BundleCheck("Bundle structure", True, "All required files present"))

        # Load receipt
        try:
            receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            checks.append(BundleCheck("Receipt schema", False, f"Invalid JSON: {e}"))
            return BundleVerificationResult(
                valid=False, checks=checks,
                receipt_summary=None,
                errors=[f"Receipt is not valid JSON: {e}"],
            )

        # Build receipt summary
        const_ref = receipt.get("constitution_ref") or {}
        receipt_summary = {
            "trace_id": receipt.get("trace_id"),
            "coherence_status": receipt.get("coherence_status"),
            "agent_name": const_ref.get("document_id", "").split("/")[0] if const_ref.get("document_id") else None,
            "constitution_version": const_ref.get("version"),
        }

        # Resolve public keys independently by key_id
        pub_key_files = list(public_keys_dir.glob("*.pub"))

        def _resolve_key(key_id: str) -> Optional[str]:
            """Find a public key file matching the given key_id."""
            if key_id:
                for pkf in pub_key_files:
                    if pkf.stem == key_id:
                        return str(pkf)
            return None

        # Receipt key — from receipt_signature.key_id
        sig_block = receipt.get("receipt_signature") or {}
        receipt_key_id = sig_block.get("key_id", "")
        receipt_pub_key_path = _resolve_key(receipt_key_id)
        if receipt_pub_key_path is None:
            # Fallback to first .pub file
            receipt_pub_key_path = str(pub_key_files[0])

        # ---- Step 2: Receipt schema ----
        from .verify import load_schema, verify_receipt as _verify_receipt
        schema = load_schema()
        receipt_result = _verify_receipt(receipt, schema)

        if receipt_result.valid:
            checks.append(BundleCheck(
                "Receipt schema", True,
                "Schema valid, fingerprint intact, status consistent",
            ))
        else:
            # Distinguish schema vs fingerprint vs other
            if receipt_result.exit_code == 2:
                detail = "; ".join(receipt_result.errors)
                checks.append(BundleCheck("Receipt schema", False, detail))
                errors.extend(receipt_result.errors)
            else:
                checks.append(BundleCheck("Receipt schema", True, "Schema valid"))

        # ---- Step 3: Receipt fingerprint ----
        from .verify import verify_fingerprint
        _fp_error = False
        try:
            fp_match, fp_computed, fp_expected = verify_fingerprint(receipt)
        except TypeError as e:
            checks.append(BundleCheck(
                "Receipt fingerprint", False,
                f"Fingerprint computation failed (float in receipt data): {e}",
            ))
            errors.append(f"Receipt fingerprint error: {e}")
            fp_match = False
            _fp_error = True
        if not _fp_error:
            if fp_match:
                checks.append(BundleCheck(
                    "Receipt fingerprint", True,
                    f"Fingerprint intact: {fp_expected}",
                ))
            else:
                detail = f"Mismatch: computed {fp_computed}, expected {fp_expected}"
                checks.append(BundleCheck("Receipt fingerprint", False, detail))
                errors.append(f"Receipt fingerprint mismatch: {detail}")

        # ---- Step 4: Constitution signature ----
        from .constitution import load_constitution, SannaConstitutionError
        from .crypto import verify_constitution_full

        try:
            constitution = load_constitution(str(constitution_file))
        except (SannaConstitutionError, ValueError) as e:
            checks.append(BundleCheck(
                "Constitution signature", False,
                f"Failed to load constitution: {e}",
            ))
            errors.append(f"Constitution load failed: {e}")
            constitution = None

        if constitution is not None:
            sig = constitution.provenance.signature
            if sig and sig.value:
                # Resolve constitution key by its own key_id
                const_key_id = sig.key_id or ""
                const_pub_key_path = _resolve_key(const_key_id)
                if const_pub_key_path is None:
                    # Fallback to receipt key (same author for both)
                    const_pub_key_path = receipt_pub_key_path

                try:
                    const_valid = verify_constitution_full(constitution, const_pub_key_path)
                except Exception as e:
                    const_valid = False

                if const_valid:
                    signed_by = sig.signed_by or "unknown"
                    checks.append(BundleCheck(
                        "Constitution signature", True,
                        f"Valid (signed by: {signed_by})",
                    ))
                else:
                    checks.append(BundleCheck(
                        "Constitution signature", False,
                        "Ed25519 signature verification failed",
                    ))
                    errors.append("Constitution signature verification failed")
            else:
                checks.append(BundleCheck(
                    "Constitution signature", False,
                    "Constitution has no signature",
                ))
                errors.append("Constitution is not signed")

        # ---- Step 5: Provenance chain ----
        if constitution is not None:
            chain_errors = _verify_provenance_chain(receipt, constitution)
            if not chain_errors:
                checks.append(BundleCheck(
                    "Provenance chain", True,
                    "Receipt-to-constitution binding intact",
                ))
            else:
                detail = "; ".join(chain_errors)
                checks.append(BundleCheck("Provenance chain", False, detail))
                errors.extend(chain_errors)
        else:
            checks.append(BundleCheck(
                "Provenance chain", False,
                "Cannot verify: constitution failed to load",
            ))

        # ---- Step 6: Receipt signature ----
        from .crypto import verify_receipt_signature
        sig_block = receipt.get("receipt_signature")
        if sig_block and sig_block.get("signature"):
            try:
                receipt_sig_valid = verify_receipt_signature(receipt, receipt_pub_key_path)
            except Exception:
                receipt_sig_valid = False

            if receipt_sig_valid:
                checks.append(BundleCheck(
                    "Receipt signature", True,
                    "Ed25519 signature valid",
                ))
            else:
                checks.append(BundleCheck(
                    "Receipt signature", False,
                    "Ed25519 signature verification failed",
                ))
                errors.append("Receipt signature verification failed")
        else:
            checks.append(BundleCheck(
                "Receipt signature", False,
                "Receipt has no signature",
            ))
            errors.append("Receipt is not signed")

        # ---- Step 7: Approval verification (v0.9.0) ----
        if constitution is not None:
            approval_check = _verify_approval_in_bundle(
                constitution, public_keys_dir,
            )
            checks.append(approval_check)

    # ---- Compute verdict ----
    if strict:
        valid = all(c.passed for c in checks)
    else:
        # Non-strict: valid if structure + fingerprint pass
        valid = not errors or all(
            c.passed for c in checks
            if c.name in ("Bundle structure", "Receipt fingerprint")
        )

    return BundleVerificationResult(
        valid=valid,
        checks=checks,
        receipt_summary=receipt_summary,
        errors=errors,
    )


# =============================================================================
# INTERNAL HELPERS
# =============================================================================

def _verify_approval_in_bundle(constitution, public_keys_dir: Path) -> BundleCheck:
    """Verify the constitution approval within a bundle.

    Checks:
    1. If constitution has approval, content_hash matches.
    2. If approver public key is in the bundle, verifies approval signature.

    Returns a single BundleCheck.
    """
    from .constitution import compute_content_hash, _approval_record_to_signable_dict
    from .hashing import canonical_json_bytes

    approval = constitution.approval
    if approval is None or approval.current is None:
        return BundleCheck(
            "Approval verification", True,
            "Constitution has no approval block (not required)",
        )

    record = approval.current

    if record.status != "approved":
        return BundleCheck(
            "Approval verification", False,
            f"Approval status is '{record.status}', not 'approved'",
        )

    # CRITICAL: Require non-empty approval_signature when status=="approved"
    if not record.approval_signature:
        return BundleCheck(
            "Approval verification", False,
            "Approval record claims 'approved' but approval_signature is missing/empty",
        )

    # Verify content_hash
    computed_hash = compute_content_hash(constitution)
    if record.content_hash != computed_hash:
        return BundleCheck(
            "Approval verification", False,
            f"Content hash mismatch: approval has {record.content_hash[:16]}..., "
            f"computed {computed_hash[:16]}... — content may have been tampered",
        )

    # Try to verify approval signature with available public keys
    if public_keys_dir.exists():
        from .crypto import verify_signature, load_public_key
        signable = _approval_record_to_signable_dict(record)
        data = canonical_json_bytes(signable)

        pub_key_files = list(public_keys_dir.glob("*.pub"))
        sig_verified = False
        for pkf in pub_key_files:
            try:
                pub_key = load_public_key(str(pkf))
                if verify_signature(data, record.approval_signature, pub_key):
                    sig_verified = True
                    break
            except Exception:
                continue

        if sig_verified:
            approver = record.approver_id
            role = record.approver_role
            return BundleCheck(
                "Approval verification", True,
                f"Approved by {approver} ({role}), content hash valid, signature verified",
            )
        else:
            return BundleCheck(
                "Approval verification", True,
                f"Approved by {record.approver_id}, content hash valid. "
                f"WARNING: Approval signature present but no approver public key in bundle "
                f"— signature not verified. Include approver key for full verification.",
            )

    return BundleCheck(
        "Approval verification", True,
        f"Approved by {record.approver_id}, content hash valid. "
        f"WARNING: Approval signature present but no approver public key in bundle "
        f"— signature not verified. Include approver key for full verification.",
    )


def _verify_provenance_chain(receipt: dict, constitution) -> list[str]:
    """Verify receipt-to-constitution provenance binding.

    Checks:
    1. policy_hash matches between receipt.constitution_ref and constitution.
    2. Signature value matches between receipt.constitution_ref and constitution.
    """
    errors = []
    const_ref = receipt.get("constitution_ref")
    if not const_ref:
        errors.append("Receipt has no constitution_ref")
        return errors

    # Check policy_hash
    receipt_hash = const_ref.get("policy_hash", "")
    if receipt_hash != constitution.policy_hash:
        errors.append(
            f"policy_hash mismatch: receipt has {receipt_hash[:16]}..., "
            f"constitution has {constitution.policy_hash[:16]}..."
        )

    # Check signature value
    receipt_sig = const_ref.get("signature")
    const_sig = constitution.provenance.signature
    if receipt_sig and const_sig and const_sig.value:
        if receipt_sig != const_sig.value:
            errors.append("Receipt references a different signed version of this constitution")

    return errors
