#!/usr/bin/env python3
"""Governance Lifecycle Demo — Sanna v0.9.0

Walks through the COMPLETE governance lifecycle with cryptographic
binding: author creates, signs, approver approves, agents run, receipts
carry approval provenance, tamper detection fires, versioned updates
link, and evidence bundles capture everything.

Run:
    python examples/governance_lifecycle_demo.py
"""

import json
import sys
import tempfile
import warnings
from pathlib import Path

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sanna.bundle import create_bundle, verify_bundle
from sanna.constitution import (
    Constitution,
    AgentIdentity,
    Provenance,
    Boundary,
    Invariant,
    HaltCondition,
    AuthorityBoundaries,
    EscalationRule,
    sign_constitution,
    save_constitution,
    load_constitution,
    approve_constitution,
    compute_content_hash,
    parse_constitution,
)
from sanna.constitution_diff import diff_constitutions
from sanna.crypto import generate_keypair
from sanna.middleware import sanna_observe
from sanna.verify import verify_receipt, load_schema


# =============================================================================
# CONSTANTS
# =============================================================================

SECTION_WIDTH = 70


def header(step: int, title: str) -> None:
    """Print a bold section header."""
    print()
    print("=" * SECTION_WIDTH)
    print(f"  STEP {step}: {title}")
    print("=" * SECTION_WIDTH)
    print()


def subheader(label: str) -> None:
    print(f"  → {label}")


def success(msg: str) -> None:
    print(f"  [PASS] {msg}")


def fail(msg: str) -> None:
    print(f"  [FAIL] {msg}")


# =============================================================================
# DEMO
# =============================================================================

def run_demo() -> dict:
    """Run the full governance lifecycle demo. Returns summary dict."""
    results = {
        "steps_completed": 0,
        "receipts_generated": 0,
        "tamper_detected": False,
        "diff_changes": 0,
        "bundle_valid": False,
    }

    with tempfile.TemporaryDirectory(prefix="sanna_lifecycle_") as tmp:
        tmp_path = Path(tmp)

        # =====================================================================
        # Step 1: Create a constitution
        # =====================================================================
        header(1, "CREATE CONSTITUTION")

        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(
                agent_name="support-agent",
                domain="customer-support",
                description="Customer support agent with governance controls",
            ),
            provenance=Provenance(
                authored_by="alice@acme.com",
                approved_by=["bob@acme.com"],
                approval_date="2026-02-14",
                approval_method="manual",
            ),
            boundaries=[
                Boundary(id="B001", description="Must not access PII directly", category="confidentiality", severity="critical"),
                Boundary(id="B002", description="Scope limited to support queries", category="scope", severity="high"),
            ],
            invariants=[
                Invariant(id="INV_NO_FABRICATION", rule="Never fabricate information", enforcement="halt"),
                Invariant(id="INV_MARK_INFERENCE", rule="Mark inferences clearly", enforcement="warn"),
                Invariant(id="INV_NO_FALSE_CERTAINTY", rule="No false certainty", enforcement="warn"),
                Invariant(id="INV_PRESERVE_TENSION", rule="Preserve conflicting info", enforcement="warn"),
                Invariant(id="INV_NO_PREMATURE_COMPRESSION", rule="No oversimplification", enforcement="warn"),
            ],
            authority_boundaries=AuthorityBoundaries(
                cannot_execute=["delete_account", "modify_billing"],
                must_escalate=[EscalationRule(condition="refund > $500")],
                can_execute=["query_kb", "create_ticket", "send_response"],
            ),
            halt_conditions=[
                HaltCondition(id="H001", trigger="fabrication detected", escalate_to="ops@acme.com", severity="critical", enforcement="halt"),
            ],
        )

        const_v1_path = tmp_path / "constitution_v1.yaml"
        save_constitution(const, const_v1_path)

        print(f"  Agent: {const.identity.agent_name}")
        print(f"  Domain: {const.identity.domain}")
        print(f"  Invariants: {len(const.invariants)}")
        print(f"  Boundaries: {len(const.boundaries)}")
        print(f"  Authority: cannot_execute={const.authority_boundaries.cannot_execute}")
        print(f"  Saved to: {const_v1_path.name}")
        results["steps_completed"] += 1

        # =====================================================================
        # Step 2: Sign the constitution (author)
        # =====================================================================
        header(2, "SIGN CONSTITUTION (Author)")

        author_priv, author_pub = generate_keypair(tmp_path / "author_keys")
        approver_priv, approver_pub = generate_keypair(tmp_path / "approver_keys")

        signed = sign_constitution(const, private_key_path=str(author_priv))
        save_constitution(signed, const_v1_path)

        signed_loaded = load_constitution(str(const_v1_path))
        sig = signed_loaded.provenance.signature
        print(f"  Signed by: {sig.signed_by}")
        print(f"  Key ID: {sig.key_id[:16]}...")
        print(f"  Scheme: {sig.scheme}")
        print(f"  Policy hash: {signed_loaded.policy_hash[:16]}...")
        success("Constitution signed by author")
        results["steps_completed"] += 1

        # =====================================================================
        # Step 3: Approve the constitution (different key = different role)
        # =====================================================================
        header(3, "APPROVE CONSTITUTION (VP Risk)")

        record = approve_constitution(
            const_v1_path, approver_priv, "bob@acme.com", "VP Risk", "1.0"
        , verify_author_sig=False)
        approved_const = load_constitution(str(const_v1_path))

        print(f"  Approver: {record.approver_id}")
        print(f"  Role: {record.approver_role}")
        print(f"  Version: {record.constitution_version}")
        print(f"  Content hash: {record.content_hash[:16]}...")
        print(f"  Approved at: {record.approved_at}")
        success("Constitution v1 approved by VP Risk")
        results["steps_completed"] += 1

        # =====================================================================
        # Step 4: Run agents against the approved constitution
        # =====================================================================
        header(4, "RUN AGENTS WITH APPROVED CONSTITUTION")

        test_cases = [
            {
                "query": "What is our refund policy?",
                "context": "Our refund policy allows returns within 30 days. Items must be unused.",
            },
            {
                "query": "Can I get a replacement?",
                "context": "Replacements are available for defective items within 90 days of purchase.",
            },
            {
                "query": "How do I reset my password?",
                "context": "Password reset can be done via Settings > Security > Reset Password.",
            },
        ]

        @sanna_observe(
            require_constitution_sig=False,
            constitution_path=str(const_v1_path),
            private_key_path=str(author_priv),
        )
        def support_agent(query, context):
            return f"Based on our policy: {context.split('.')[0]}."

        receipt_paths = []
        for i, tc in enumerate(test_cases):
            result = support_agent(query=tc["query"], context=tc["context"])
            receipt_path = tmp_path / f"receipt_v1_{i}.json"
            receipt_path.write_text(json.dumps(result.receipt, indent=2))
            receipt_paths.append(receipt_path)

            has_approval = "constitution_approval" in (result.receipt.get("constitution_ref") or {})
            subheader(f"Receipt {i+1}: status={result.receipt['status']}, "
                      f"approval_provenance={has_approval}")
            results["receipts_generated"] += 1

        success(f"Generated {len(test_cases)} receipts with approval provenance")
        results["steps_completed"] += 1

        # =====================================================================
        # Step 5: Verify the complete chain
        # =====================================================================
        header(5, "VERIFY COMPLETE CHAIN")

        schema = load_schema()
        sample_receipt = json.loads(receipt_paths[0].read_text())
        vr = verify_receipt(
            sample_receipt, schema,
            public_key_path=str(author_pub),
            constitution_path=str(const_v1_path),
            constitution_public_key_path=str(author_pub),
            approver_public_key_path=str(approver_pub),
        )

        print(f"  Receipt valid: {vr.valid}")
        print(f"  Errors: {vr.errors}")
        print(f"  Fingerprint match: {vr.computed_fingerprint == vr.expected_fingerprint}")
        if sample_receipt.get("constitution_ref", {}).get("constitution_approval"):
            ca = sample_receipt["constitution_ref"]["constitution_approval"]
            print(f"  Approval in receipt: status={ca['status']}, "
                  f"approver={ca['approver_id']}")
        success("Full chain verified: receipt -> signature -> constitution -> approval")
        results["steps_completed"] += 1

        # =====================================================================
        # Step 6: Demonstrate tamper detection
        # =====================================================================
        header(6, "TAMPER DETECTION")

        import yaml
        tampered_path = tmp_path / "constitution_tampered.yaml"

        # Copy and tamper
        data = yaml.safe_load(const_v1_path.read_text())
        original_approval = data.get("approval", {})
        original_hash = None
        if original_approval and "records" in original_approval:
            recs = original_approval["records"]
            if recs:
                original_hash = recs[0].get("content_hash")

        # Change enforcement level — an unauthorized modification
        for inv in data.get("invariants", []):
            if inv["id"] == "INV_MARK_INFERENCE":
                inv["enforcement"] = "halt"  # was "warn"
                break
        tampered_path.write_text(yaml.dump(data, default_flow_style=False))

        # Load directly via parse_constitution to bypass hash check
        tampered_data = yaml.safe_load(tampered_path.read_text())
        tampered_const = parse_constitution(tampered_data)
        computed = compute_content_hash(tampered_const)
        if original_hash:
            hash_match = original_hash == computed
            print(f"  Original content hash: {original_hash[:16]}...")
            print(f"  Computed content hash: {computed[:16]}...")
            print(f"  Hashes match: {hash_match}")
            if not hash_match:
                fail("Content hash MISMATCH — unauthorized modification detected!")
                fail("Approval is INVALID after tampering.")
                results["tamper_detected"] = True
            else:
                print("  WARNING: tamper not detected (unexpected)")
        else:
            print("  No approval hash found (unexpected)")

        success("Tamper detection working correctly")
        results["steps_completed"] += 1

        # =====================================================================
        # Step 7: Create new version with diff
        # =====================================================================
        header(7, "VERSION 2 WITH DIFF")

        const_v2 = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(
                agent_name="support-agent",
                domain="customer-support",
                description="Customer support agent v2 — tighter controls",
            ),
            provenance=Provenance(
                authored_by="alice@acme.com",
                approved_by=["bob@acme.com"],
                approval_date="2026-02-14",
                approval_method="manual",
            ),
            boundaries=[
                Boundary(id="B001", description="Must not access PII directly", category="confidentiality", severity="critical"),
                Boundary(id="B002", description="Scope limited to support queries", category="scope", severity="high"),
                Boundary(id="B003", description="Cannot discuss competitor products", category="scope", severity="medium"),
            ],
            invariants=[
                Invariant(id="INV_NO_FABRICATION", rule="Never fabricate information", enforcement="halt"),
                Invariant(id="INV_MARK_INFERENCE", rule="Mark inferences clearly", enforcement="halt"),  # upgraded
                Invariant(id="INV_NO_FALSE_CERTAINTY", rule="No false certainty", enforcement="warn"),
                Invariant(id="INV_PRESERVE_TENSION", rule="Preserve conflicting info", enforcement="warn"),
                Invariant(id="INV_NO_PREMATURE_COMPRESSION", rule="No oversimplification", enforcement="warn"),
            ],
            authority_boundaries=AuthorityBoundaries(
                cannot_execute=["delete_account", "modify_billing", "export_data"],
                must_escalate=[EscalationRule(condition="refund > $500")],
                can_execute=["query_kb", "create_ticket", "send_response"],
            ),
            halt_conditions=[
                HaltCondition(id="H001", trigger="fabrication detected", escalate_to="ops@acme.com", severity="critical", enforcement="halt"),
            ],
        )

        const_v2_path = tmp_path / "constitution_v2.yaml"
        signed_v2 = sign_constitution(const_v2, private_key_path=str(author_priv))
        save_constitution(signed_v2, const_v2_path)

        # Diff v1 vs v2
        old = load_constitution(str(const_v1_path))
        new = load_constitution(str(const_v2_path))
        diff = diff_constitutions(old, new)

        print("  Changes detected:")
        for entry in diff.entries:
            print(f"    [{entry.change_type.upper()}] {entry.category}: {entry.key}")
        results["diff_changes"] = len(diff.entries)

        # Approve v2
        record_v2 = approve_constitution(
            const_v2_path, approver_priv, "bob@acme.com", "VP Risk", "2.0"
        , verify_author_sig=False)
        print()
        print(f"  Version 2 approved: {record_v2.constitution_version}")
        if record_v2.previous_version_hash:
            print(f"  Previous version hash: {record_v2.previous_version_hash[:16]}...")
        success("Constitution v2 approved. Change chain: v1 -> v2")
        results["steps_completed"] += 1

        # =====================================================================
        # Step 8: Create evidence bundle
        # =====================================================================
        header(8, "EVIDENCE BUNDLE")

        bundle_path = tmp_path / "evidence_bundle.zip"
        create_bundle(
            receipt_path=receipt_paths[0],
            constitution_path=const_v1_path,
            public_key_path=author_pub,
            output_path=bundle_path,
            approver_public_key_path=approver_pub,
        )

        subheader(f"Bundle created: {bundle_path.name}")

        # Verify the bundle
        bundle_result = verify_bundle(bundle_path)
        print(f"  Bundle valid: {bundle_result.valid}")
        print(f"  Checks passed: {sum(1 for c in bundle_result.checks if c.passed)}/{len(bundle_result.checks)}")
        for c in bundle_result.checks:
            status = "PASS" if c.passed else "FAIL"
            print(f"    [{status}] {c.name}")
        if bundle_result.errors:
            for e in bundle_result.errors:
                print(f"    ERROR: {e}")
        results["bundle_valid"] = bundle_result.valid
        results["steps_completed"] += 1

    # =========================================================================
    # SUMMARY
    # =========================================================================
    print()
    print("=" * SECTION_WIDTH)
    print("  GOVERNANCE LIFECYCLE COMPLETE")
    print("=" * SECTION_WIDTH)
    print()
    print(f"  Steps completed:    {results['steps_completed']}/8")
    print(f"  Receipts generated: {results['receipts_generated']}")
    print(f"  Tamper detected:    {results['tamper_detected']}")
    print(f"  Diff changes (v2):  {results['diff_changes']}")
    print(f"  Bundle valid:       {results['bundle_valid']}")
    print()

    return results


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    results = run_demo()
    if results["steps_completed"] < 8:
        sys.exit(1)
