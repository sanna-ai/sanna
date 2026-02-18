#!/usr/bin/env python3
"""Generate all golden receipt test vectors in v0.13.0 format.

Usage:
    python golden/generate_golden.py

Outputs JSON files to golden/receipts/.  Each receipt is generated
via ``sanna.receipt.generate_receipt()`` with deterministic inputs
and a fixed timestamp, then serialised with a stable receipt_id so
that fingerprints are reproducible across runs.
"""

import json
import sys
from dataclasses import asdict
from pathlib import Path

# Ensure the source tree is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sanna.receipt import generate_receipt, SPEC_VERSION, CHECKS_VERSION, TOOL_VERSION
from sanna.hashing import hash_text, hash_obj, EMPTY_HASH

OUT = Path(__file__).resolve().parent / "receipts"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_trace(correlation_id, query, context, response):
    """Build a minimal trace_data dict for generate_receipt()."""
    return {
        "correlation_id": correlation_id,
        "name": "golden",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "input": {"query": query},
        "output": {"final_answer": response},
        "metadata": {},
        "observations": [
            {
                "id": "obs-ret",
                "name": "retrieval",
                "type": "SPAN",
                "input": {"query": query},
                "output": {"context": context},
                "metadata": {},
                "start_time": "2026-01-01T00:00:01+00:00",
                "end_time": "2026-01-01T00:00:02+00:00",
            }
        ],
    }


def stabilise(receipt, receipt_id, timestamp="2026-01-01T00:00:00+00:00"):
    """Replace volatile fields (receipt_id, timestamp) so fingerprints
    are stable across regeneration runs.  receipt_id is NOT part of
    the fingerprint, so replacing it is safe.  Timestamp IS NOT part
    of the fingerprint either (only hashes are)."""
    d = asdict(receipt)
    d["receipt_id"] = receipt_id
    d["timestamp"] = timestamp
    return d


def add_extensions(receipt_dict, extensions):
    """Add extensions to a receipt dict and recompute fingerprint."""
    receipt_dict["extensions"] = extensions
    # Recompute fingerprint with extensions_hash
    correlation_id = receipt_dict["correlation_id"]
    context_hash = receipt_dict["context_hash"]
    output_hash = receipt_dict["output_hash"]
    checks_data = [
        {"check_id": c["check_id"], "passed": c["passed"],
         "severity": c["severity"], "evidence": c.get("evidence")}
        for c in receipt_dict["checks"]
    ]
    checks_hash = hash_obj(checks_data)
    constitution_hash = EMPTY_HASH
    enforcement_hash = EMPTY_HASH
    coverage_hash = EMPTY_HASH
    authority_hash = EMPTY_HASH
    escalation_hash = EMPTY_HASH
    trust_hash = EMPTY_HASH
    extensions_hash = hash_obj(extensions)

    fp_input = f"{correlation_id}|{context_hash}|{output_hash}|{CHECKS_VERSION}|{checks_hash}|{constitution_hash}|{enforcement_hash}|{coverage_hash}|{authority_hash}|{escalation_hash}|{trust_hash}|{extensions_hash}"
    receipt_dict["full_fingerprint"] = hash_text(fp_input)
    receipt_dict["receipt_fingerprint"] = hash_text(fp_input, truncate=16)
    return receipt_dict


def write(filename, receipt_dict):
    path = OUT / filename
    with open(path, "w") as f:
        json.dump(receipt_dict, f, indent=2)
        f.write("\n")
    print(f"  {filename}: status={receipt_dict['status']}")


# ---------------------------------------------------------------------------
# Test scenarios
# ---------------------------------------------------------------------------

SCENARIOS = [
    # 001: C1 FAIL — output contradicts context (refund)
    {
        "file": "001_fail_c1_refund.json",
        "id": "a0000001-0000-4000-8000-000000000001",
        "correlation_id": "golden-001-fail-c1-refund",
        "query": "refund policy software",
        "context": "Our refund policy: Physical products can be returned within 30 days. Digital products are non-refundable once downloaded. Subscriptions can be cancelled anytime.",
        "response": "Based on your purchase history, you are eligible to request a refund. However, since the software was downloaded, processing may take 5-7 business days.",
        "expected_status": "FAIL",
    },
    # 002: PASS — simple Q&A, no issues
    {
        "file": "002_pass_simple_qa.json",
        "id": "a0000002-0000-4000-8000-000000000002",
        "correlation_id": "golden-002-pass-simple-qa",
        "query": "What is the capital of France?",
        "context": "France is a country in Western Europe. Its capital is Paris, which is also the most populous city.",
        "response": "The capital of France is Paris.",
        "expected_status": "PASS",
    },
    # 003: PASS — technical answer with hedging
    {
        "file": "003_pass_technical_hedged.json",
        "id": "a0000003-0000-4000-8000-000000000003",
        "correlation_id": "golden-003-pass-technical-hedged",
        "query": "Is Python good for web development?",
        "context": "Python is used for web development with frameworks like Django and Flask. Performance may be lower than compiled languages. Python excels in rapid prototyping.",
        "response": "Python can be used for web development, particularly with Django or Flask. It may be slower than compiled alternatives, but it's generally good for rapid prototyping.",
        "expected_status": "PASS",
    },
    # 004: PASS — policy answer with conditionals
    {
        "file": "004_pass_policy_conditional.json",
        "id": "a0000004-0000-4000-8000-000000000004",
        "correlation_id": "golden-004-pass-policy-conditional",
        "query": "Can I upgrade my subscription?",
        "context": "Upgrades are available for annual subscribers. Monthly subscribers must wait until renewal. Enterprise plans have custom upgrade paths.",
        "response": "You may be able to upgrade, depending on your plan type. Annual subscribers can upgrade immediately, while monthly subscribers typically need to wait until renewal. Enterprise plans have separate upgrade paths.",
        "expected_status": "PASS",
    },
    # 005: WARN — C2 unmarked inference (definitive without hedging)
    {
        "file": "005_warn_c2_unmarked_inference.json",
        "id": "a0000005-0000-4000-8000-000000000005",
        "correlation_id": "golden-005-warn-c2-unmarked",
        "query": "Will the product launch succeed?",
        "context": "Market research shows mixed signals. Some segments show strong demand, others show saturation.",
        "response": "The product launch will definitely succeed and is guaranteed to exceed all targets.",
        "expected_status": "WARN",
    },
    # 006: WARN — C3 false certainty (ignores conditions)
    {
        "file": "006_warn_c3_false_certainty.json",
        "id": "a0000006-0000-4000-8000-000000000006",
        "correlation_id": "golden-006-warn-c3-certainty",
        "query": "Can I use the API?",
        "context": "Available if usage is under 1000 requests. Requires registration. Rate limits apply during peak hours.",
        "response": "You can use the API. Go ahead and start making requests.",
        "expected_status": "WARN",
    },
    # 007: WARN — C5 premature compression (oversimplified)
    {
        "file": "007_warn_c5_compression.json",
        "id": "a0000007-0000-4000-8000-000000000007",
        "correlation_id": "golden-007-warn-c5-compression",
        "query": "Deployment options?",
        "context": "Deployment options include:\n- AWS with auto-scaling\n- GCP with managed Kubernetes\n- Azure with serverless functions\n- On-premise with Docker\nEach has different cost and performance implications.",
        "response": "Deploy to cloud.",
        "expected_status": "WARN",
    },
    # 008: FAIL — C1 digital refund contradiction (distinct from 001)
    {
        "file": "008_fail_c1_digital.json",
        "id": "a0000008-0000-4000-8000-000000000008",
        "correlation_id": "golden-008-fail-c1-digital",
        "query": "Can I get a refund on my software purchase?",
        "context": "All digital products are non-refundable once the download link has been activated. Physical items may be returned within 14 days.",
        "response": "You are eligible for a refund on the software. Please contact support to initiate the process.",
        "expected_status": "FAIL",
    },
    # 009: WARN — C4 conflict collapse
    {
        "file": "009_warn_c4_conflict.json",
        "id": "a0000009-0000-4000-8000-000000000009",
        "correlation_id": "golden-009-warn-c4-conflict",
        "query": "Can I transfer my license?",
        "context": "License transfers are permitted for enterprise customers. Individual licenses cannot be transferred. Some exceptions may apply with manager approval.",
        "response": "Yes, you can transfer your license.",
        "expected_status": "WARN",
    },
    # 010: FAIL — multiple checks fail (C1 + C3 + C4)
    {
        "file": "010_fail_multiple.json",
        "id": "a0000010-0000-4000-8000-000000000010",
        "correlation_id": "golden-010-fail-multiple",
        "query": "refund eligibility",
        "context": "Refund policy: Physical products are eligible for return within 30 days. Digital products are non-refundable. Exceptions require manager approval and must meet specific criteria.",
        "response": "You are eligible for a full refund on this digital product. You can request it immediately.",
        "expected_status": "FAIL",
    },
]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    print(f"Generating golden receipts → {OUT}/")

    # --- Basic scenarios (001-010) ---
    for s in SCENARIOS:
        trace = make_trace(s["correlation_id"], s["query"], s["context"], s["response"])
        receipt = generate_receipt(trace)
        d = stabilise(receipt, s["id"])
        assert d["status"] == s["expected_status"], (
            f"{s['file']}: expected {s['expected_status']}, got {d['status']}"
        )
        write(s["file"], d)

    # --- 011: PASS with extensions ---
    trace = make_trace(
        "golden-011-pass-extensions",
        "store hours",
        "Store hours: Monday-Friday 9 AM to 9 PM. Saturday-Sunday 10 AM to 6 PM. Holiday hours may vary.",
        "The store is open weekdays 9 AM to 9 PM and weekends 10 AM to 6 PM. Note that holiday hours may differ.",
    )
    receipt = generate_receipt(trace)
    d = stabilise(receipt, "a0000011-0000-4000-8000-000000000011")
    extensions = {
        "vendor": "test-vendor",
        "pipeline_id": "pipe-123",
        "environment": "staging",
        "custom_score": 95,
        "tags": ["golden", "test"],
    }
    d = add_extensions(d, extensions)
    write("011_pass_with_extensions.json", d)

    # --- 999: Tampered receipt ---
    trace = make_trace(
        "golden-001-fail-c1-refund",
        "refund policy software",
        "Our refund policy: Physical products can be returned within 30 days. Digital products are non-refundable once downloaded. Subscriptions can be cancelled anytime.",
        "Based on your purchase history, you are eligible to request a refund. However, since the software was downloaded, processing may take 5-7 business days.",
    )
    receipt = generate_receipt(trace)
    d = stabilise(receipt, "a0000999-0000-4000-8000-000000000999")
    # Tamper: change the output AFTER hashing
    d["outputs"]["response"] = "TAMPERED: This was changed after generation"
    write("999_tampered.json", d)

    print(f"\nDone. {len(list(OUT.glob('*.json')))} golden receipts generated.")


if __name__ == "__main__":
    main()
