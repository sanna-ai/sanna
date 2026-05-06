"""SAN-358: Verifier assertions for session_manifest + invocation_anomaly receipts.

Verifier-side enforcement is non-negotiable per CLAUDE.md governance principle.
These checks are downstream of schema validation (which jsonschema covers via
the conditional allOf rules from SAN-204) and complement them with semantic
guarantees the schema cannot express (cross-receipt parent resolution,
delivered/suppressed disjointness, sorted-list determinism, etc.).

This module is per-receipt + cross-receipt verifier logic. AARM Core (R1-R6)
checks remain in src/sanna/aarm.py; do NOT mix concerns.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .manifest import VALID_SUPPRESSION_REASONS, SUPPRESSION_REASON_UNKNOWN

# Field name where the attempted capability is recorded in the com.sanna.anomaly
# extension, keyed by event_type.
# Confirmed from SAN-206 emission code:
#   invocation_anomaly (gateway/mcp): server.py:2581 -- extensions['com.sanna.anomaly']['attempted_tool']
#   cli_invocation_anomaly (cli): no Python emission code yet; inferred from mcp pattern
#   api_invocation_anomaly (http): no Python emission code yet; inferred from mcp pattern
_ANOMALY_CAPABILITY_FIELD = {
    "invocation_anomaly": "attempted_tool",
    "cli_invocation_anomaly": "attempted_command",
    "api_invocation_anomaly": "attempted_endpoint",
}

_ANOMALY_SURFACE_NAME = {
    "invocation_anomaly": "mcp",
    "cli_invocation_anomaly": "cli",
    "api_invocation_anomaly": "http",
}

_VALID_MANIFEST_ENFORCEMENT_SURFACES = frozenset({
    "gateway", "cli_interceptor", "http_interceptor", "mixed",
})

_VALID_ANOMALY_EVENT_TYPES = frozenset({
    "invocation_anomaly", "cli_invocation_anomaly", "api_invocation_anomaly",
})

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

_CROSS_RECEIPT_SKIP_MSG = (
    "Cross-receipt parent resolution requires receipt set; use verify_receipt_set"
)


@dataclass
class Check:
    name: str
    status: str  # "PASS", "FAIL", "WARN"
    message: str


def verify_session_manifest_receipt(receipt: dict) -> list[Check]:
    """9 semantic checks for session_manifest receipts (SAN-358).

    Checks are downstream of schema validation. Call after verify_schema()
    confirms structural validity.

    Args:
        receipt: Parsed receipt dict with event_type='session_manifest'.

    Returns:
        List of Check objects. FAIL => governance violation; WARN => soft issue.
    """
    checks: list[Check] = []
    ext = receipt.get("extensions") or {}
    manifest = ext.get("com.sanna.manifest")
    content_mode = receipt.get("content_mode")

    # ------------------------------------------------------------------
    # Check 1: manifest_extension_present
    # ------------------------------------------------------------------
    if not isinstance(manifest, dict):
        checks.append(Check(
            name="manifest_extension_present",
            status="FAIL",
            message="session_manifest receipt missing required extension 'com.sanna.manifest'",
        ))
        # Cannot proceed with surface-level checks; run remaining top-level ones.
        checks.extend(_check_constitution_ref(receipt))
        checks.extend(_check_enforcement_surface(receipt, {}))
        return checks

    checks.append(Check(
        name="manifest_extension_present",
        status="PASS",
        message="extension 'com.sanna.manifest' present",
    ))

    # ------------------------------------------------------------------
    # Check 2: manifest_version_supported
    # ------------------------------------------------------------------
    actual_version = manifest.get("version")
    if actual_version not in {"0.1"}:
        checks.append(Check(
            name="manifest_version_supported",
            status="FAIL",
            message=f"manifest version '{actual_version}' not in supported set {{'0.1'}}",
        ))
    else:
        checks.append(Check(
            name="manifest_version_supported",
            status="PASS",
            message=f"manifest version '{actual_version}' is supported",
        ))

    # ------------------------------------------------------------------
    # Check 3: manifest_has_at_least_one_surface
    # ------------------------------------------------------------------
    surfaces = manifest.get("surfaces")
    if not isinstance(surfaces, dict) or len(surfaces) < 1:
        checks.append(Check(
            name="manifest_has_at_least_one_surface",
            status="FAIL",
            message="manifest 'surfaces' must contain at least one of {'mcp', 'cli', 'http'}",
        ))
        checks.extend(_check_constitution_ref(receipt))
        checks.extend(_check_enforcement_surface(receipt, {}))
        return checks

    checks.append(Check(
        name="manifest_has_at_least_one_surface",
        status="PASS",
        message=f"manifest surfaces present: {sorted(surfaces.keys())}",
    ))

    # ------------------------------------------------------------------
    # Per-surface checks (4, 5, 6, 7)
    # Accumulate violations; emit one PASS per check when no violations.
    # ------------------------------------------------------------------
    sort_fails: list[Check] = []
    reason_issues: list[Check] = []
    overlap_fails: list[Check] = []
    key_mismatch_fails: list[Check] = []

    for surface_name, surface_data in surfaces.items():
        if not isinstance(surface_data, dict):
            continue

        is_mcp = surface_name == "mcp"
        delivered_field = "tools_delivered" if is_mcp else "patterns_delivered"
        suppressed_field = "tools_suppressed" if is_mcp else "patterns_suppressed"

        delivered = surface_data.get(delivered_field) or []
        suppressed = surface_data.get(suppressed_field) or []
        suppression_reasons = surface_data.get("suppression_reasons")

        # Check 4: manifest_lists_sorted
        for field_name, lst in [(delivered_field, delivered), (suppressed_field, suppressed)]:
            if isinstance(lst, list) and lst != sorted(lst):
                sort_fails.append(Check(
                    name="manifest_lists_sorted",
                    status="FAIL",
                    message=(
                        f"manifest surface '{surface_name}' field '{field_name}' "
                        "is not sorted alphabetically (determinism violated)"
                    ),
                ))

        # Check 5: manifest_suppression_reasons_in_enum
        # Skip when suppression_reasons is absent (redacted mode drops the field).
        if isinstance(suppression_reasons, dict):
            for _key, value in suppression_reasons.items():
                if value not in VALID_SUPPRESSION_REASONS:
                    reason_issues.append(Check(
                        name="manifest_suppression_reasons_in_enum",
                        status="FAIL",
                        message=(
                            f"manifest surface '{surface_name}' suppression_reason "
                            f"'{value}' not in stable enum (Section 2.21)"
                        ),
                    ))
                elif value == SUPPRESSION_REASON_UNKNOWN:
                    reason_issues.append(Check(
                        name="manifest_suppression_reasons_in_enum",
                        status="WARN",
                        message=(
                            f"manifest surface '{surface_name}' uses 'unknown' "
                            "suppression_reason (documented fallback per Section 2.21)"
                        ),
                    ))

        # Check 6: manifest_no_overlap_delivered_suppressed
        # Skip for content_mode=redacted: all names collapse to '<redacted>',
        # making overlap spurious by construction.
        if content_mode != "redacted" and isinstance(delivered, list) and isinstance(suppressed, list):
            overlap = sorted(set(delivered) & set(suppressed))
            for name in overlap:
                overlap_fails.append(Check(
                    name="manifest_no_overlap_delivered_suppressed",
                    status="FAIL",
                    message=(
                        f"manifest surface '{surface_name}' has '{name}' in BOTH "
                        "delivered and suppressed (anti-enumeration integrity violated)"
                    ),
                ))

        # Check 7: manifest_suppression_reasons_keys_match
        # Skip when suppression_reasons is absent (redacted mode).
        if isinstance(suppression_reasons, dict) and isinstance(suppressed, list):
            reason_keys = set(suppression_reasons.keys())
            suppressed_names = set(suppressed)
            if reason_keys != suppressed_names:
                key_mismatch_fails.append(Check(
                    name="manifest_suppression_reasons_keys_match",
                    status="FAIL",
                    message=(
                        f"manifest surface '{surface_name}' suppression_reasons keys "
                        f"{sorted(reason_keys)} do not match suppressed names "
                        f"{sorted(suppressed_names)}"
                    ),
                ))

    checks.extend(sort_fails or [Check(
        name="manifest_lists_sorted",
        status="PASS",
        message="all surface lists are sorted alphabetically",
    )])

    checks.extend(reason_issues or [Check(
        name="manifest_suppression_reasons_in_enum",
        status="PASS",
        message="all suppression_reasons are in the stable enum",
    )])

    checks.extend(overlap_fails or [Check(
        name="manifest_no_overlap_delivered_suppressed",
        status="PASS",
        message="no overlap between delivered and suppressed",
    )])

    checks.extend(key_mismatch_fails or [Check(
        name="manifest_suppression_reasons_keys_match",
        status="PASS",
        message="suppression_reasons keys match suppressed names",
    )])

    # ------------------------------------------------------------------
    # Check 8: manifest_constitution_ref_present
    # ------------------------------------------------------------------
    checks.extend(_check_constitution_ref(receipt))

    # ------------------------------------------------------------------
    # Check 9: manifest_enforcement_surface_consistent
    # ------------------------------------------------------------------
    checks.extend(_check_enforcement_surface(receipt, surfaces))

    # ------------------------------------------------------------------
    # SAN-406: redaction_markers_correct
    # ------------------------------------------------------------------
    checks.extend(_check_redaction_markers_correct(receipt))

    return checks


def _check_constitution_ref(receipt: dict) -> list[Check]:
    """Check 8: manifest_constitution_ref_present."""
    constitution_ref = receipt.get("constitution_ref")
    if isinstance(constitution_ref, dict):
        policy_hash = constitution_ref.get("policy_hash")
        if policy_hash and isinstance(policy_hash, str):
            return [Check(
                name="manifest_constitution_ref_present",
                status="PASS",
                message="constitution_ref.policy_hash present",
            )]
    return [Check(
        name="manifest_constitution_ref_present",
        status="FAIL",
        message=(
            "session_manifest receipt requires constitution_ref.policy_hash "
            "(manifest is meaningless without constitution binding)"
        ),
    )]


def _check_enforcement_surface(receipt: dict, surfaces: dict) -> list[Check]:
    """Check 9: manifest_enforcement_surface_consistent."""
    enforcement_surface = receipt.get("enforcement_surface")
    if enforcement_surface is None:
        # Already caught by existing verify_receipt() cv>=8 check; skip here.
        return []

    if enforcement_surface not in _VALID_MANIFEST_ENFORCEMENT_SURFACES:
        return [Check(
            name="manifest_enforcement_surface_consistent",
            status="FAIL",
            message=(
                f"session_manifest enforcement_surface '{enforcement_surface}' "
                "not in valid set {gateway, cli_interceptor, http_interceptor, mixed}"
            ),
        )]

    surface_count = len(surfaces) if isinstance(surfaces, dict) else 0

    if enforcement_surface == "mixed":
        if surface_count < 2:
            return [Check(
                name="manifest_enforcement_surface_consistent",
                status="FAIL",
                message=(
                    f"session_manifest with enforcement_surface='mixed' requires "
                    f"surfaces dict with at least 2 entries; got {surface_count}"
                ),
            )]

    elif enforcement_surface == "gateway":
        if isinstance(surfaces, dict) and "mcp" not in surfaces:
            return [Check(
                name="manifest_enforcement_surface_consistent",
                status="FAIL",
                message="session_manifest with enforcement_surface='gateway' missing 'mcp' surface",
            )]

    elif enforcement_surface == "cli_interceptor":
        if isinstance(surfaces, dict) and "cli" not in surfaces:
            return [Check(
                name="manifest_enforcement_surface_consistent",
                status="FAIL",
                message="session_manifest with enforcement_surface='cli_interceptor' missing 'cli' surface",
            )]

    elif enforcement_surface == "http_interceptor":
        if isinstance(surfaces, dict) and "http" not in surfaces:
            return [Check(
                name="manifest_enforcement_surface_consistent",
                status="FAIL",
                message="session_manifest with enforcement_surface='http_interceptor' missing 'http' surface",
            )]

    return [Check(
        name="manifest_enforcement_surface_consistent",
        status="PASS",
        message=f"enforcement_surface='{enforcement_surface}' is consistent with surfaces",
    )]


def _check_redaction_markers_correct(receipt: dict) -> list[Check]:
    """SAN-406: verify content_mode redaction markers are correct.

    Covers BOTH com.sanna.manifest list fields (Section 2.14, SAN-439 scope)
    AND com.sanna.anomaly attempted_* fields (Section 2.22.5, SAN-406 scope).

    Under content_mode=redacted, every value MUST equal the literal
    "<redacted>". Under content_mode=hashes_only, every value MUST match
    64-hex-lowercase. Under "full" or None, no constraint (returns []).
    """
    checks: list[Check] = []
    content_mode = receipt.get("content_mode")
    if content_mode in (None, "full"):
        return checks  # No constraint to enforce.

    extensions = receipt.get("extensions") or {}

    # com.sanna.manifest: list fields collapse to all-redacted markers.
    manifest_ext = extensions.get("com.sanna.manifest")
    if isinstance(manifest_ext, dict):
        surfaces = manifest_ext.get("surfaces") or {}
        for surface_name, surface in surfaces.items():
            if not isinstance(surface, dict):
                continue
            for list_field in (
                "tools_delivered", "tools_suppressed",
                "patterns_delivered", "patterns_suppressed",
            ):
                values = surface.get(list_field)
                if not isinstance(values, list):
                    continue
                for v in values:
                    if not _is_valid_redaction_marker(v, content_mode):
                        checks.append(Check(
                            name="redaction_markers_correct",
                            status="FAIL",
                            message=(
                                f"manifest surface '{surface_name}' "
                                f"{list_field} contains {v!r} which is "
                                f"not a valid {content_mode} marker"
                            ),
                        ))

    # com.sanna.anomaly: single attempted_* field per surface variant.
    anomaly_ext = extensions.get("com.sanna.anomaly")
    if isinstance(anomaly_ext, dict):
        event_type = receipt.get("event_type", "")
        field_name = _ANOMALY_CAPABILITY_FIELD.get(event_type)
        if field_name and field_name in anomaly_ext:
            v = anomaly_ext[field_name]
            if isinstance(v, str) and not _is_valid_redaction_marker(v, content_mode):
                checks.append(Check(
                    name="redaction_markers_correct",
                    status="FAIL",
                    message=(
                        f"anomaly extension {field_name} value {v!r} is "
                        f"not a valid {content_mode} marker"
                    ),
                ))

    if not checks:
        checks.append(Check(
            name="redaction_markers_correct",
            status="PASS",
            message=f"all redaction markers conform to content_mode={content_mode}",
        ))
    return checks


def _is_valid_redaction_marker(value: object, content_mode: str) -> bool:
    """Helper: does `value` conform to the expected marker format for `content_mode`?"""
    if not isinstance(value, str):
        return False
    if content_mode == "redacted":
        return value == "<redacted>"
    if content_mode == "hashes_only":
        return bool(_SHA256_HEX_RE.match(value))
    return True  # "full" / None: any value passes (defensive).


def verify_invocation_anomaly_receipt(
    receipt: dict,
    receipt_set: Optional[list[dict]] = None,
) -> list[Check]:
    """3 semantic checks for invocation_anomaly receipts (SAN-358).

    Handles all 3 surface variants: invocation_anomaly, cli_invocation_anomaly,
    api_invocation_anomaly.

    Args:
        receipt: Parsed anomaly receipt dict.
        receipt_set: Full set of receipts for cross-receipt parent resolution.
            Pass None (or omit) to skip cross-receipt checks 11 and 12 -- they
            will be emitted as WARN with a message directing callers to
            verify_receipt_set().

    Returns:
        List of Check objects.
    """
    checks: list[Check] = []
    event_type = receipt.get("event_type", "")

    # ------------------------------------------------------------------
    # Check 10: anomaly_event_type_in_valid_set
    # ------------------------------------------------------------------
    if event_type not in _VALID_ANOMALY_EVENT_TYPES:
        checks.append(Check(
            name="anomaly_event_type_in_valid_set",
            status="FAIL",
            message=f"anomaly receipt event_type '{event_type}' not in valid set",
        ))
        return checks

    checks.append(Check(
        name="anomaly_event_type_in_valid_set",
        status="PASS",
        message=f"event_type '{event_type}' is in valid set",
    ))

    # SAN-406: redaction markers check (independent of receipt_set; runs early).
    checks.extend(_check_redaction_markers_correct(receipt))

    # ------------------------------------------------------------------
    # Checks 11 and 12 require a receipt set for cross-receipt resolution.
    # ------------------------------------------------------------------
    if receipt_set is None:
        checks.append(Check(
            name="anomaly_parent_receipts_resolves_to_session_manifest",
            status="WARN",
            message=_CROSS_RECEIPT_SKIP_MSG,
        ))
        checks.append(Check(
            name="anomaly_attempted_capability_in_parent_suppressed_or_absent",
            status="WARN",
            message=_CROSS_RECEIPT_SKIP_MSG,
        ))
        return checks

    # ------------------------------------------------------------------
    # Check 11: anomaly_parent_receipts_resolves_to_session_manifest
    # ------------------------------------------------------------------
    parent_receipts = receipt.get("parent_receipts") or []

    if not parent_receipts:
        checks.append(Check(
            name="anomaly_parent_receipts_resolves_to_session_manifest",
            status="FAIL",
            message=(
                "anomaly receipt requires non-empty parent_receipts containing "
                "the active session_manifest's full_fingerprint (spec Section 2.12)"
            ),
        ))
        checks.append(Check(
            name="anomaly_attempted_capability_in_parent_suppressed_or_absent",
            status="WARN",
            message=_CROSS_RECEIPT_SKIP_MSG,
        ))
        return checks

    fp_index: dict[str, dict] = {
        r.get("full_fingerprint"): r
        for r in receipt_set
        if r.get("full_fingerprint")
    }

    parent_manifest: Optional[dict] = None
    for fp in parent_receipts:
        candidate = fp_index.get(fp)
        if candidate and candidate.get("event_type") == "session_manifest":
            parent_manifest = candidate
            break

    if parent_manifest is None:
        checks.append(Check(
            name="anomaly_parent_receipts_resolves_to_session_manifest",
            status="FAIL",
            message=(
                f"anomaly receipt parent_receipts {parent_receipts} do not resolve "
                "to a session_manifest in the provided receipt set"
            ),
        ))
        checks.append(Check(
            name="anomaly_attempted_capability_in_parent_suppressed_or_absent",
            status="WARN",
            message=_CROSS_RECEIPT_SKIP_MSG,
        ))
        return checks

    checks.append(Check(
        name="anomaly_parent_receipts_resolves_to_session_manifest",
        status="PASS",
        message="anomaly receipt parent_receipts resolves to a session_manifest in the receipt set",
    ))

    # ------------------------------------------------------------------
    # Check 12: anomaly_attempted_capability_in_parent_suppressed_or_absent
    # ------------------------------------------------------------------
    capability_field = _ANOMALY_CAPABILITY_FIELD[event_type]
    surface_name = _ANOMALY_SURFACE_NAME[event_type]

    anomaly_ext = (receipt.get("extensions") or {}).get("com.sanna.anomaly") or {}
    capability_name = anomaly_ext.get(capability_field)

    if capability_name is None:
        checks.append(Check(
            name="anomaly_attempted_capability_in_parent_suppressed_or_absent",
            status="WARN",
            message=(
                f"anomaly receipt missing '{capability_field}' in "
                "extensions['com.sanna.anomaly']; cannot verify capability "
                "against parent manifest"
            ),
        ))
        return checks

    parent_manifest_ext = (
        (parent_manifest.get("extensions") or {}).get("com.sanna.manifest") or {}
    )
    parent_surfaces = parent_manifest_ext.get("surfaces") or {}
    parent_surface = parent_surfaces.get(surface_name) or {}

    is_mcp = surface_name == "mcp"
    suppressed_field = "tools_suppressed" if is_mcp else "patterns_suppressed"
    delivered_field = "tools_delivered" if is_mcp else "patterns_delivered"

    suppressed = set(parent_surface.get(suppressed_field) or [])
    delivered = set(parent_surface.get(delivered_field) or [])

    if capability_name in suppressed:
        checks.append(Check(
            name="anomaly_attempted_capability_in_parent_suppressed_or_absent",
            status="PASS",
            message=(
                f"anomaly capability '{capability_name}' was suppressed in parent "
                "session_manifest (spec-conformant anti-enumeration signal)"
            ),
        ))
    elif capability_name in delivered:
        checks.append(Check(
            name="anomaly_attempted_capability_in_parent_suppressed_or_absent",
            status="FAIL",
            message=(
                f"anomaly receipt for capability '{capability_name}' that parent "
                "session_manifest declares as DELIVERED -- inconsistent receipt set"
            ),
        ))
    else:
        checks.append(Check(
            name="anomaly_attempted_capability_in_parent_suppressed_or_absent",
            status="PASS",
            message=(
                f"anomaly capability '{capability_name}' was not declared in "
                "constitution at all (verifier cannot disambiguate from "
                "policy-suppression on the wire; this is an informational note, "
                "not a violation)"
            ),
        ))

    return checks
