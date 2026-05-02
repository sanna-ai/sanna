"""SAN-368: AARM Core (R1-R6) conformance verifier.

Mechanically verifies the public claim from spec Section 14:
"Sanna Protocol v1.5 implements AARM Core (R1-R6) conformance,
mechanically verifiable via `sanna-verify aarm`."

Per-requirement check functions, decision-enum mapping table, aggregate
report. See spec Section 14 for the normative mapping.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

from .verify import verify_fingerprint
from .crypto import verify_receipt_signature

# Decision-enum mapping table (code primitive per SAN-356 G2).
# Sanna receipts use the LEFT keys; AARM names are RIGHT values.
SANNA_TO_AARM: dict[str, str] = {
    # authority_decisions.boundary_type values
    "can_execute": "ALLOW",
    "cannot_execute": "DENY",
    "must_escalate": "STEP_UP",
    "modify_with_constraints": "MODIFY",
    "defer_pending_context": "DEFER",
    # authority_decisions.decision values (action-form)
    "allow": "ALLOW",
    "halt": "DENY",
    "escalate": "STEP_UP",
    "modify": "MODIFY",
    "defer": "DEFER",
}


@dataclass
class CheckResult:
    """Result of one AARM requirement check."""

    requirement: str  # e.g., "R1", "R2", ..., "R6"
    name: str         # e.g., "Pre-Execution Interception"
    status: str       # "PASS" | "FAIL" | "PARTIAL" | "N/A"
    message: str
    evidence: list[dict] = field(default_factory=list)


@dataclass
class AarmReport:
    """Aggregate AARM Core (R1-R6) conformance report."""

    aggregate_status: str  # "PASS" | "FAIL" | "PARTIAL"
    checks: list[CheckResult]
    receipt_count: int
    generated_at: str

    def to_dict(self) -> dict:
        return {
            "aggregate_status": self.aggregate_status,
            "receipt_count": self.receipt_count,
            "generated_at": self.generated_at,
            "checks": [asdict(c) for c in self.checks],
        }


def check_r1_pre_execution_interception(receipts: list[dict]) -> CheckResult:
    """R1: every invocation_* receipt has enforcement_surface in the valid set."""
    valid_surfaces = {"middleware", "gateway", "cli_interceptor", "http_interceptor", "mixed"}
    failing = []
    invocation_count = 0
    for r in receipts:
        et = r.get("event_type", "") or ""
        if et.startswith("invocation_"):
            invocation_count += 1
            surface = r.get("enforcement_surface")
            if surface not in valid_surfaces:
                failing.append({
                    "receipt_fingerprint": r.get("receipt_fingerprint"),
                    "event_type": et,
                    "enforcement_surface": surface,
                })
    if not invocation_count:
        # Receipts without event_type still need enforcement_surface
        missing_surface = [
            r for r in receipts
            if r.get("enforcement_surface") not in valid_surfaces
        ]
        if missing_surface:
            return CheckResult(
                requirement="R1",
                name="Pre-Execution Interception",
                status="FAIL",
                message=f"{len(missing_surface)} receipt(s) lack a valid enforcement_surface",
                evidence=[
                    {
                        "receipt_fingerprint": r.get("receipt_fingerprint"),
                        "enforcement_surface": r.get("enforcement_surface"),
                    }
                    for r in missing_surface
                ],
            )
        return CheckResult(
            requirement="R1",
            name="Pre-Execution Interception",
            status="PASS",
            message=f"All {len(receipts)} receipt(s) have a valid enforcement_surface",
        )
    if failing:
        return CheckResult(
            requirement="R1",
            name="Pre-Execution Interception",
            status="FAIL",
            message=f"{len(failing)} invocation receipt(s) lack a valid enforcement_surface",
            evidence=failing,
        )
    return CheckResult(
        requirement="R1",
        name="Pre-Execution Interception",
        status="PASS",
        message=f"All {invocation_count} invocation receipt(s) have a valid enforcement_surface",
    )


def check_r2_context_accumulation(receipts: list[dict]) -> CheckResult:
    """R2: parent_receipts chain resolves end-to-end within the set."""
    fingerprints: set[str] = set()
    for r in receipts:
        if r.get("full_fingerprint"):
            fingerprints.add(r["full_fingerprint"])
        if r.get("receipt_fingerprint"):
            fingerprints.add(r["receipt_fingerprint"])

    broken = []
    for r in receipts:
        parents = r.get("parent_receipts") or []
        for p in parents:
            if p and p not in fingerprints:
                broken.append({
                    "receipt_fingerprint": r.get("receipt_fingerprint"),
                    "missing_parent": p,
                })
    if broken:
        return CheckResult(
            requirement="R2",
            name="Context Accumulation (parent_receipts chain)",
            status="FAIL",
            message=f"{len(broken)} parent_receipts reference(s) do not resolve within the receipt set",
            evidence=broken,
        )
    return CheckResult(
        requirement="R2",
        name="Context Accumulation (parent_receipts chain)",
        status="PASS",
        message="All parent_receipts references resolve within the receipt set",
    )


def check_r3_policy_evaluation(receipts: list[dict]) -> CheckResult:
    """R3: every governance receipt has constitution_ref.policy_hash."""
    governance = [r for r in receipts if r.get("constitution_ref") is not None]
    if not governance:
        return CheckResult(
            requirement="R3",
            name="Policy Evaluation with Intent Alignment",
            status="N/A",
            message="No governance receipts in set (constitution_ref absent on all receipts)",
        )
    failing = [
        r for r in governance
        if not (r.get("constitution_ref") or {}).get("policy_hash")
    ]
    if failing:
        return CheckResult(
            requirement="R3",
            name="Policy Evaluation with Intent Alignment",
            status="FAIL",
            message=f"{len(failing)} governance receipt(s) lack constitution_ref.policy_hash",
            evidence=[{"receipt_fingerprint": r.get("receipt_fingerprint")} for r in failing],
        )
    return CheckResult(
        requirement="R3",
        name="Policy Evaluation with Intent Alignment",
        status="PASS",
        message=f"All {len(governance)} governance receipt(s) have constitution_ref.policy_hash",
    )


def check_r4_decisions(receipts: list[dict]) -> CheckResult:
    """R4: decision values subset of SANNA_TO_AARM keys; STEP_UP receipts chain to resolution."""
    valid_decisions = set(SANNA_TO_AARM.keys())
    invalid: list[dict] = []
    step_up_unresolved: list[dict] = []

    for r in receipts:
        # Check authority_decisions.decision and boundary_type values
        for ad in (r.get("authority_decisions") or []):
            d = ad.get("decision")
            if d and d not in valid_decisions:
                invalid.append({
                    "receipt_fingerprint": r.get("receipt_fingerprint"),
                    "field": "authority_decisions.decision",
                    "value": d,
                })
            bt = ad.get("boundary_type")
            if bt and bt not in valid_decisions:
                invalid.append({
                    "receipt_fingerprint": r.get("receipt_fingerprint"),
                    "field": "authority_decisions.boundary_type",
                    "value": bt,
                })

        # STEP_UP chain check: escalated enforcement must resolve downstream
        ea = (r.get("enforcement") or {}).get("action")
        if ea in ("escalate", "escalated"):
            this_fp = r.get("full_fingerprint") or r.get("receipt_fingerprint")
            if this_fp:
                resolution = next(
                    (
                        other for other in receipts
                        if this_fp in (other.get("parent_receipts") or [])
                    ),
                    None,
                )
                if resolution is None:
                    step_up_unresolved.append({
                        "receipt_fingerprint": r.get("receipt_fingerprint"),
                        "issue": "STEP_UP receipt has no downstream receipt chaining to it",
                    })

    if invalid or step_up_unresolved:
        return CheckResult(
            requirement="R4",
            name="Five Authorization Decisions (with STEP_UP chain check)",
            status="FAIL",
            message=(
                f"{len(invalid)} invalid decision value(s); "
                f"{len(step_up_unresolved)} unresolved STEP_UP receipt(s)"
            ),
            evidence=invalid + step_up_unresolved,
        )
    return CheckResult(
        requirement="R4",
        name="Five Authorization Decisions (with STEP_UP chain check)",
        status="PASS",
        message=(
            "All decisions are in the valid AARM-mapped enum; "
            "all STEP_UP receipts chain to a resolution"
        ),
    )


def check_r5_tamper_evident(receipts: list[dict], public_key_path: str | None = None) -> CheckResult:
    """R5: every receipt's fingerprint validates; signature validates when public_key_path provided.

    Redacted-receipt acceptance: content_mode=redacted receipts pass when fingerprint is valid;
    visible-content presence is NOT required (cryptographic integrity is the conformance test).
    """
    failing = []
    for r in receipts:
        fp_ok, computed, expected = verify_fingerprint(r)
        if not fp_ok:
            failing.append({
                "receipt_fingerprint": r.get("receipt_fingerprint"),
                "issue": f"fingerprint mismatch (computed {computed[:16]}, expected {expected[:16]})",
            })
            continue
        if public_key_path is not None:
            sig_block = r.get("receipt_signature") or {}
            if sig_block.get("value"):
                if not verify_receipt_signature(r, public_key_path):
                    failing.append({
                        "receipt_fingerprint": r.get("receipt_fingerprint"),
                        "issue": "signature verification failed",
                    })

    if failing:
        return CheckResult(
            requirement="R5",
            name="Tamper-Evident Receipts",
            status="FAIL",
            message=f"{len(failing)} receipt(s) failed cryptographic integrity check",
            evidence=failing,
        )
    return CheckResult(
        requirement="R5",
        name="Tamper-Evident Receipts",
        status="PASS",
        message=(
            f"All {len(receipts)} receipt(s) have valid fingerprints"
            + (" and signatures" if public_key_path is not None else "")
        ),
    )


def check_r6_identity_binding(receipts: list[dict]) -> CheckResult:
    """R6: cv=10 receipts with agent_identity.agent_session_id pass; cv=9 partial; cv=10 missing fails.

    Per spec Section 2.19 and SAN-371 CV9_LEGACY pattern:
    - cv>=10 with agent_identity.agent_session_id -> PASS contribution
    - cv=10 missing agent_identity -> FAIL (hard error)
    - cv<=9 (legacy) -> PARTIAL contribution
    """
    pass_count = 0
    partial_count = 0
    fail: list[dict] = []

    for r in receipts:
        cv_str = r.get("checks_version", "") or ""
        try:
            cv = int(cv_str)
        except (ValueError, TypeError):
            cv = 0

        if cv >= 10:
            ai = r.get("agent_identity")
            if not ai or not ai.get("agent_session_id"):
                fail.append({
                    "receipt_fingerprint": r.get("receipt_fingerprint"),
                    "checks_version": cv_str,
                    "issue": "cv=10 receipt missing agent_identity.agent_session_id",
                })
            else:
                pass_count += 1
        else:
            partial_count += 1

    if fail:
        return CheckResult(
            requirement="R6",
            name="Identity Binding",
            status="FAIL",
            message=f"{len(fail)} cv=10 receipt(s) missing agent_identity",
            evidence=fail,
        )
    if partial_count > 0 and pass_count == 0:
        return CheckResult(
            requirement="R6",
            name="Identity Binding",
            status="PARTIAL",
            message=(
                f"All {partial_count} receipt(s) at cv<=9 (partial R6); "
                "upgrade to cv=10 with agent_identity for full R6 conformance"
            ),
        )
    if partial_count > 0:
        return CheckResult(
            requirement="R6",
            name="Identity Binding",
            status="PARTIAL",
            message=(
                f"{pass_count} receipt(s) at cv=10 with agent_identity (full R6); "
                f"{partial_count} receipt(s) at cv<=9 (partial R6)"
            ),
        )
    return CheckResult(
        requirement="R6",
        name="Identity Binding",
        status="PASS",
        message=f"All {pass_count} receipt(s) at cv=10 with agent_identity (full R6)",
    )


def aggregate_aarm_report(receipts: list[dict], public_key_path: str | None = None) -> AarmReport:
    """Run all R1-R6 checks and return an aggregate report."""
    checks = [
        check_r1_pre_execution_interception(receipts),
        check_r2_context_accumulation(receipts),
        check_r3_policy_evaluation(receipts),
        check_r4_decisions(receipts),
        check_r5_tamper_evident(receipts, public_key_path=public_key_path),
        check_r6_identity_binding(receipts),
    ]
    statuses = {c.status for c in checks}
    if "FAIL" in statuses:
        aggregate = "FAIL"
    elif "PARTIAL" in statuses:
        aggregate = "PARTIAL"
    else:
        aggregate = "PASS"
    return AarmReport(
        aggregate_status=aggregate,
        checks=checks,
        receipt_count=len(receipts),
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def format_aarm_report(report: AarmReport, fmt: str = "json") -> str:
    """Format an AarmReport as JSON or human-readable string."""
    if fmt == "json":
        return json.dumps(report.to_dict(), indent=2)
    if fmt == "human":
        lines = [
            "AARM Core (R1-R6) Conformance Report",
            "=" * 40,
            f"Receipt count: {report.receipt_count}",
            f"Generated at:  {report.generated_at}",
            f"Aggregate:     {report.aggregate_status}",
            "",
        ]
        for c in report.checks:
            lines.append(f"  [{c.status:7s}] {c.requirement} -- {c.name}")
            lines.append(f"            {c.message}")
            if c.evidence and c.status in ("FAIL", "PARTIAL"):
                for e in c.evidence[:3]:
                    lines.append(f"            evidence: {e}")
                if len(c.evidence) > 3:
                    lines.append(f"            ... ({len(c.evidence) - 3} more)")
            lines.append("")
        return "\n".join(lines)
    raise ValueError(f"Unknown format: {fmt!r} (supported: json, human)")
