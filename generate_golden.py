#!/usr/bin/env python3
"""
Generate golden test receipts using the actual Sanna check implementations.

Run this whenever check logic changes to regenerate golden receipts.
Golden receipts are used by the test suite for regression testing.

Usage:  python generate_golden.py
"""

import json
import sys
from dataclasses import asdict
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from sanna.receipt import (
    generate_receipt, CheckResult, SannaReceipt,
    SPEC_VERSION, TOOL_VERSION, CHECKS_VERSION,
)
from sanna.hashing import hash_text, hash_obj


# =============================================================================
# SYNTHETIC TRACE DATA FOR GOLDEN RECEIPTS
# =============================================================================

TRACES = [
    {
        "id": "001_fail_c1_refund",
        "description": "C1 FAIL: Output contradicts non-refundable policy in context",
        "trace_data": {
            "correlation_id": "golden-001-fail-c1-refund",
            "name": "refund-check",
            "timestamp": "2026-01-03T00:00:00Z",
            "input": {"query": "Can I get a refund on my software purchase?"},
            "output": {"final_answer": "Based on your purchase history, you are eligible to request a refund. However, since the software was downloaded, processing may take 5-7 business days."},
            "metadata": {},
            "observations": [
                {
                    "id": "obs-001-ret",
                    "name": "retrieval",
                    "type": "SPAN",
                    "input": {"query": "refund policy software"},
                    "output": {"context": "Our refund policy: Physical products can be returned within 30 days. Digital products are non-refundable once downloaded. Subscriptions can be cancelled anytime."},
                    "metadata": {},
                    "start_time": "2026-01-03T00:00:01Z",
                    "end_time": "2026-01-03T00:00:02Z",
                }
            ],
        },
    },
    {
        "id": "002_pass_simple_qa",
        "description": "PASS: Simple Q&A with no violations",
        "trace_data": {
            "correlation_id": "golden-002-pass-simple-qa",
            "name": "simple-qa",
            "timestamp": "2026-01-03T00:00:00Z",
            "input": {"query": "What is the capital of France?"},
            "output": {"final_answer": "The capital of France is Paris. It has been the capital since the late 10th century and serves as the country's political, economic, and cultural center."},
            "metadata": {},
            "observations": [
                {
                    "id": "obs-002-ret",
                    "name": "retrieval",
                    "type": "SPAN",
                    "input": {"query": "capital of France"},
                    "output": {"context": "France is a country in Western Europe. Its capital city is Paris, which has served as the capital since the reign of the Capetian dynasty."},
                    "metadata": {},
                    "start_time": "2026-01-03T00:00:01Z",
                    "end_time": "2026-01-03T00:00:02Z",
                }
            ],
        },
    },
    {
        "id": "003_pass_technical_hedged",
        "description": "PASS: Technical answer with proper hedging",
        "trace_data": {
            "correlation_id": "golden-003-pass-technical-hedged",
            "name": "tech-qa",
            "timestamp": "2026-01-03T00:00:00Z",
            "input": {"query": "Will this migration break my database?"},
            "output": {"final_answer": "The migration may cause temporary downtime. It's possible that some indexes could need rebuilding, but this likely won't exceed 15 minutes based on similar migrations."},
            "metadata": {},
            "observations": [
                {
                    "id": "obs-003-ret",
                    "name": "retrieval",
                    "type": "SPAN",
                    "input": {"query": "database migration impact"},
                    "output": {"context": "Database migrations can cause downtime. Index rebuilds may be required. Estimated time depends on table size and index count."},
                    "metadata": {},
                    "start_time": "2026-01-03T00:00:01Z",
                    "end_time": "2026-01-03T00:00:02Z",
                }
            ],
        },
    },
    {
        "id": "004_pass_policy_conditional",
        "description": "PASS: Policy answer that acknowledges conditions",
        "trace_data": {
            "correlation_id": "golden-004-pass-policy-conditional",
            "name": "policy-check",
            "timestamp": "2026-01-03T00:00:00Z",
            "input": {"query": "Am I eligible for the premium plan discount?"},
            "output": {"final_answer": "You may be eligible for the premium plan discount, however this requires an annual commitment. Note that the discount only applies to new subscriptions and requires a minimum of 5 seats."},
            "metadata": {},
            "observations": [
                {
                    "id": "obs-004-ret",
                    "name": "retrieval",
                    "type": "SPAN",
                    "input": {"query": "premium plan discount eligibility"},
                    "output": {"context": "Premium plan discount: Available for annual commitments only. Requires minimum 5 seats. Not applicable to existing subscriptions. Cannot be combined with other offers."},
                    "metadata": {},
                    "start_time": "2026-01-03T00:00:01Z",
                    "end_time": "2026-01-03T00:00:02Z",
                }
            ],
        },
    },
    {
        "id": "005_warn_c2_unmarked_inference",
        "description": "WARN: C2 fires — definitive language without hedging",
        "trace_data": {
            "correlation_id": "golden-005-warn-c2-inference",
            "name": "inference-check",
            "timestamp": "2026-01-03T00:00:00Z",
            "input": {"query": "Will this investment pay off?"},
            "output": {"final_answer": "This investment will definitely pay off. The returns are guaranteed to exceed 20% annually, and you will certainly see profits within the first quarter."},
            "metadata": {},
            "observations": [
                {
                    "id": "obs-005-ret",
                    "name": "retrieval",
                    "type": "SPAN",
                    "input": {"query": "investment returns forecast"},
                    "output": {"context": "Historical returns have averaged 12-18% annually. Market conditions vary. Past performance does not guarantee future results."},
                    "metadata": {},
                    "start_time": "2026-01-03T00:00:01Z",
                    "end_time": "2026-01-03T00:00:02Z",
                }
            ],
        },
    },
    {
        "id": "006_warn_c3_false_certainty",
        "description": "WARN: C3 fires — confident claim ignoring conditions",
        "trace_data": {
            "correlation_id": "golden-006-warn-c3-certainty",
            "name": "certainty-check",
            "timestamp": "2026-01-03T00:00:00Z",
            "input": {"query": "Can I use the API for free?"},
            "output": {"final_answer": "You can use the API for free. Go ahead and start making requests immediately."},
            "metadata": {},
            "observations": [
                {
                    "id": "obs-006-ret",
                    "name": "retrieval",
                    "type": "SPAN",
                    "input": {"query": "API free tier"},
                    "output": {"context": "Free tier available if usage is under 1000 requests/month. Requires API key registration. Rate limits apply. Exceeding limits requires paid plan upgrade."},
                    "metadata": {},
                    "start_time": "2026-01-03T00:00:01Z",
                    "end_time": "2026-01-03T00:00:02Z",
                }
            ],
        },
    },
    {
        "id": "007_warn_c5_compression",
        "description": "WARN: C5 fires — complex context compressed to single sentence",
        "trace_data": {
            "correlation_id": "golden-007-warn-c5-compression",
            "name": "compression-check",
            "timestamp": "2026-01-03T00:00:00Z",
            "input": {"query": "What are the deployment options?"},
            "output": {"final_answer": "Deploy to cloud."},
            "metadata": {},
            "observations": [
                {
                    "id": "obs-007-ret",
                    "name": "retrieval",
                    "type": "SPAN",
                    "input": {"query": "deployment options"},
                    "output": {"context": "Deployment options include:\n- AWS with auto-scaling groups\n- GCP with Kubernetes Engine\n- Azure with App Service\n- On-premise with Docker Compose\n- Hybrid cloud with VPN tunneling\nEach option has different cost, latency, and compliance implications."},
                    "metadata": {},
                    "start_time": "2026-01-03T00:00:01Z",
                    "end_time": "2026-01-03T00:00:02Z",
                }
            ],
        },
    },
    {
        "id": "008_fail_c1_factual",
        "description": "FAIL: C1 fires — factual contradiction of non-refundable context",
        "trace_data": {
            "correlation_id": "golden-008-fail-c1-factual",
            "name": "factual-check",
            "timestamp": "2026-01-03T00:00:00Z",
            "input": {"query": "I bought a digital game, can I get my money back?"},
            "output": {"final_answer": "Since you purchased within the eligible timeframe, you are eligible to request a refund for your digital game purchase."},
            "metadata": {},
            "observations": [
                {
                    "id": "obs-008-ret",
                    "name": "retrieval",
                    "type": "SPAN",
                    "input": {"query": "digital game refund policy"},
                    "output": {"context": "All digital products are non-refundable once the download has started. Physical products can be returned within 14 days. Gift cards are non-refundable."},
                    "metadata": {},
                    "start_time": "2026-01-03T00:00:01Z",
                    "end_time": "2026-01-03T00:00:02Z",
                }
            ],
        },
    },
    {
        "id": "009_warn_c4_conflict",
        "description": "WARN: C4 fires — conflicting rules collapsed without acknowledgment",
        "trace_data": {
            "correlation_id": "golden-009-warn-c4-conflict",
            "name": "conflict-check",
            "timestamp": "2026-01-03T00:00:00Z",
            "input": {"query": "Can I transfer my license to another person?"},
            "output": {"final_answer": "Yes, you can transfer your license to another person. Contact support with the new user's details."},
            "metadata": {},
            "observations": [
                {
                    "id": "obs-009-ret",
                    "name": "retrieval",
                    "type": "SPAN",
                    "input": {"query": "license transfer policy"},
                    "output": {"context": "License transfers are permitted for enterprise accounts. Individual licenses cannot be transferred. Enterprise transfer requires manager approval. All transfers are non-refundable."},
                    "metadata": {},
                    "start_time": "2026-01-03T00:00:01Z",
                    "end_time": "2026-01-03T00:00:02Z",
                }
            ],
        },
    },
    {
        "id": "010_fail_multiple",
        "description": "FAIL: Multiple checks fire — C1 contradiction + C3 false certainty",
        "trace_data": {
            "correlation_id": "golden-010-fail-multiple",
            "name": "multi-fail",
            "timestamp": "2026-01-03T00:00:00Z",
            "input": {"query": "Is this product eligible for a refund?"},
            "output": {"final_answer": "You are eligible for a full refund on this digital product. You can request it immediately."},
            "metadata": {},
            "observations": [
                {
                    "id": "obs-010-ret",
                    "name": "retrieval",
                    "type": "SPAN",
                    "input": {"query": "refund eligibility"},
                    "output": {"context": "Refund policy: Physical products are eligible for return within 30 days. Digital products are non-refundable. Exceptions require manager approval and must meet specific criteria."},
                    "metadata": {},
                    "start_time": "2026-01-03T00:00:01Z",
                    "end_time": "2026-01-03T00:00:02Z",
                }
            ],
        },
    },
    {
        "id": "011_pass_span_provenance",
        "description": "PASS: Multi-step trace with span.output provenance",
        "trace_data": {
            "correlation_id": "golden-011-pass-span-provenance",
            "name": "multistep",
            "timestamp": "2026-01-03T00:00:00Z",
            "input": {"query": "Summarize the document"},
            "output": None,
            "metadata": {},
            "observations": [
                {
                    "id": "obs-011-ret",
                    "name": "retrieval",
                    "type": "SPAN",
                    "input": {"query": "document summary"},
                    "output": {"context": "The document discusses quarterly revenue growth of 15%, new product launches in Q3, and expansion into European markets."},
                    "metadata": {},
                    "start_time": "2026-01-03T00:00:01Z",
                    "end_time": "2026-01-03T00:00:02Z",
                },
                {
                    "id": "obs-011-gen",
                    "name": "llm-generation",
                    "type": "GENERATION",
                    "input": {"prompt": "Summarize..."},
                    "output": {"response": "The quarterly report shows 15% revenue growth, with new products launching in Q3 and European expansion underway. These appear to be positive indicators for the company."},
                    "metadata": {"model": "gpt-4"},
                    "start_time": "2026-01-03T00:00:03Z",
                    "end_time": "2026-01-03T00:00:05Z",
                }
            ],
        },
    },
    {
        "id": "012_pass_with_extensions",
        "description": "PASS: Receipt with vendor extensions (extensions not in trace_data, added post-generation)",
        "trace_data": {
            "correlation_id": "golden-012-pass-extensions",
            "name": "ext-test",
            "timestamp": "2026-01-03T00:00:00Z",
            "input": {"query": "What time does the store close?"},
            "output": {"final_answer": "Based on the information provided, the store closes at 9 PM on weekdays and 6 PM on weekends."},
            "metadata": {},
            "observations": [
                {
                    "id": "obs-012-ret",
                    "name": "retrieval",
                    "type": "SPAN",
                    "input": {"query": "store hours"},
                    "output": {"context": "Store hours: Monday-Friday 9 AM to 9 PM. Saturday-Sunday 10 AM to 6 PM. Holiday hours may vary."},
                    "metadata": {},
                    "start_time": "2026-01-03T00:00:01Z",
                    "end_time": "2026-01-03T00:00:02Z",
                }
            ],
        },
        "extensions": {
            "vendor": "test-vendor",
            "pipeline_id": "pipe-123",
            "environment": "staging",
            "custom_score": 0.95,
            "tags": ["golden", "test"]
        },
    },
]


def generate_golden_receipts():
    """Generate all golden receipts."""
    output_dir = Path(__file__).parent / "golden" / "receipts"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating golden receipts (checks_version={CHECKS_VERSION})...")
    print(f"Output: {output_dir}")
    print()

    for trace_def in TRACES:
        receipt = generate_receipt(trace_def["trace_data"])
        receipt_dict = asdict(receipt)

        # Add extensions if defined
        if "extensions" in trace_def:
            receipt_dict["extensions"] = trace_def["extensions"]

        # Override receipt_id with deterministic value for golden tests
        receipt_dict["receipt_id"] = hash_text(f"golden-{trace_def['id']}")

        filename = f"{trace_def['id']}.json"
        filepath = output_dir / filename

        with open(filepath, "w") as f:
            json.dump(receipt_dict, f, indent=2)

        status = receipt_dict.get("status") or receipt_dict.get("coherence_status", "UNKNOWN")
        icon = {"PASS": "✓", "WARN": "⚠", "FAIL": "✗"}[status]
        print(f"  [{icon}] {filename}: {status} — {trace_def['description']}")

    # Generate tampered receipt
    print()
    print("  Generating tampered receipt...")
    tampered = generate_receipt(TRACES[0]["trace_data"])
    tampered_dict = asdict(tampered)
    tampered_dict["receipt_id"] = hash_text("golden-999-tampered")
    # Tamper: change the output response
    tampered_dict["outputs"]["response"] = "TAMPERED: This was changed after generation"
    filepath = output_dir / "999_tampered.json"
    with open(filepath, "w") as f:
        json.dump(tampered_dict, f, indent=2)
    print(f"  [!] 999_tampered.json: Tampered (fingerprint should fail)")

    print()
    print(f"Done. {len(TRACES) + 1} receipts generated.")


if __name__ == "__main__":
    generate_golden_receipts()
