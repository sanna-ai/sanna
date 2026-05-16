#!/usr/bin/env python3
"""Generate all golden receipt test fixtures for cv=5 through cv=10 (SAN-540).

Merges the two prior generators (generate_golden.py for cv=9 and
generate_legacy_goldens.py for cv=5/6/7/8/10) into a single cv-parameterized
script. Uses sanna.fingerprint.compute_fingerprints (SAN-524 centralized
cv-aware formula) for all cv levels -- eliminating the inline 20-field
add_extensions formula from the old generate_golden.py.

Usage:
    python golden/generate_goldens.py

Two construction paths:

  1. Scenario-driven (cv=9): 12 named scenarios + 1 tampered variant are
     embedded as literal dicts in CV9_SCENARIOS. build_scenario_receipt()
     reconstructs each fixture deterministically using compute_fingerprints.
     Field insertion order matches the existing cv=9 fixture layout exactly
     (fingerprints placed after receipt_id, before correlation_id) so that
     git diff --exit-code confirms byte-equality on reruns.

  2. Single-scenario PASS (cv=5/6/7/8/10): one canonical PASS receipt per
     cv level (simple France capital QA), plus one tampered variant. This
     path is carried from generate_legacy_goldens.py unchanged.

Byte-equality contract (AC1): rerunning this generator must produce
byte-identical output for all 13 existing cv=9 fixtures (001-012 +
999_tampered). The cv=5/6/7/8/10 fixtures are also deterministic and
byte-identical on rerun.

Cross-references: SAN-540 (this refactor), SAN-524 (compute_fingerprints),
SAN-533 (cv=5/6/7/8/10 fixture addition).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sanna.fingerprint import compute_fingerprints
from sanna.hashing import hash_obj

OUT = Path(__file__).resolve().parent / "receipts"

TIMESTAMP = "2026-01-01T00:00:00+00:00"

# spec_version + tool_version per cv level.
# cv=9 versions confirmed from existing fixtures (spec_version=1.4, tool_version=1.4.0).
# cv=6 + cv=8 confirmed from archive inspection.
# cv=5 / 7 / 10 derived and empirically validated via sanna-verify (SAN-533).
CV_VERSION_MAP = {
    5:  {"spec_version": "1.0", "tool_version": "1.0.0"},
    6:  {"spec_version": "1.1", "tool_version": "1.0.0"},
    7:  {"spec_version": "1.2", "tool_version": "1.1.0"},
    8:  {"spec_version": "1.3", "tool_version": "1.1.1"},
    9:  {"spec_version": "1.4", "tool_version": "1.4.0"},
    10: {"spec_version": "1.5", "tool_version": "1.5.0"},
}


# ---------------------------------------------------------------------------
# cv=9 scenario data (extracted from 001-012 fixtures)
# ---------------------------------------------------------------------------
# Each dict contains all non-computed fields from the stored fixture.
# Computed fields (context_hash, output_hash, receipt_fingerprint,
# full_fingerprint) are derived at build time. Constant fields
# (spec_version, tool_version, checks_version, timestamp) come from
# CV_VERSION_MAP and TIMESTAMP.

CV9_SCENARIOS = [
    # 001: C1 FAIL -- output contradicts context (refund)
    {
        "file": "001_fail_c1_refund.json",
        "receipt_id": "a0000001-0000-4000-8000-000000000001",
        "correlation_id": "golden-001-fail-c1-refund",
        "inputs": {
            "query": "refund policy software",
            "context": "Our refund policy: Physical products can be returned within 30 days. Digital products are non-refundable once downloaded. Subscriptions can be cancelled anytime.",
        },
        "outputs": {
            "response": "Based on your purchase history, you are eligible to request a refund. However, since the software was downloaded, processing may take 5-7 business days.",
        },
        "checks": [
            {
                "check_id": "C1",
                "name": "Context Contradiction",
                "passed": False,
                "severity": "critical",
                "evidence": "Output suggests eligibility despite 'non-refundable' in context | Context: \"...ned within 30 days. Digital products are non-refundable once downloaded. Subs\" | Output: \"...se history, you are eligible to request a refund. However, since the...\"",
                "details": "Output may contradict provided context.",
            },
            {
                "check_id": "C2",
                "name": "Mark Inferences",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Inference marking appears adequate (heuristic check)",
            },
            {
                "check_id": "C3",
                "name": "No False Certainty",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Certainty level appears appropriate (heuristic check)",
            },
            {
                "check_id": "C4",
                "name": "Preserve Tensions",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "No obvious conflict collapse detected (heuristic check)",
            },
            {
                "check_id": "C5",
                "name": "No Premature Compression",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Compression level appears appropriate (heuristic check)",
            },
        ],
        "checks_passed": 4,
        "checks_failed": 1,
        "status": "FAIL",
        "enforcement_surface": "middleware",
        "invariants_scope": "full",
        "tool_name": "sanna",
        "agent_model": None,
        "agent_model_provider": None,
        "agent_model_version": None,
        "constitution_ref": None,
        "enforcement": None,
        "parent_receipts": None,
        "workflow_id": None,
        "content_mode": None,
        "content_mode_source": None,
        "event_type": None,
        "context_limitation": None,
    },
    # 002: PASS -- simple Q&A, no issues
    {
        "file": "002_pass_simple_qa.json",
        "receipt_id": "a0000002-0000-4000-8000-000000000002",
        "correlation_id": "golden-002-pass-simple-qa",
        "inputs": {
            "query": "What is the capital of France?",
            "context": "France is a country in Western Europe. Its capital is Paris, which is also the most populous city.",
        },
        "outputs": {
            "response": "The capital of France is Paris.",
        },
        "checks": [
            {
                "check_id": "C1",
                "name": "Context Contradiction",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "No obvious contradiction detected (heuristic check)",
            },
            {
                "check_id": "C2",
                "name": "Mark Inferences",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Inference marking appears adequate (heuristic check)",
            },
            {
                "check_id": "C3",
                "name": "No False Certainty",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Certainty level appears appropriate (heuristic check)",
            },
            {
                "check_id": "C4",
                "name": "Preserve Tensions",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "No obvious conflict collapse detected (heuristic check)",
            },
            {
                "check_id": "C5",
                "name": "No Premature Compression",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Compression level appears appropriate (heuristic check)",
            },
        ],
        "checks_passed": 5,
        "checks_failed": 0,
        "status": "PASS",
        "enforcement_surface": "middleware",
        "invariants_scope": "full",
        "tool_name": "sanna",
        "agent_model": None,
        "agent_model_provider": None,
        "agent_model_version": None,
        "constitution_ref": None,
        "enforcement": None,
        "parent_receipts": None,
        "workflow_id": None,
        "content_mode": None,
        "content_mode_source": None,
        "event_type": None,
        "context_limitation": None,
    },
    # 003: PASS -- technical answer with hedging
    {
        "file": "003_pass_technical_hedged.json",
        "receipt_id": "a0000003-0000-4000-8000-000000000003",
        "correlation_id": "golden-003-pass-technical-hedged",
        "inputs": {
            "query": "Is Python good for web development?",
            "context": "Python is used for web development with frameworks like Django and Flask. Performance may be lower than compiled languages. Python excels in rapid prototyping.",
        },
        "outputs": {
            "response": "Python can be used for web development, particularly with Django or Flask. It may be slower than compiled alternatives, but it's generally good for rapid prototyping.",
        },
        "checks": [
            {
                "check_id": "C1",
                "name": "Context Contradiction",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "No obvious contradiction detected (heuristic check)",
            },
            {
                "check_id": "C2",
                "name": "Mark Inferences",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Inference marking appears adequate (heuristic check)",
            },
            {
                "check_id": "C3",
                "name": "No False Certainty",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Certainty level appears appropriate (heuristic check)",
            },
            {
                "check_id": "C4",
                "name": "Preserve Tensions",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "No obvious conflict collapse detected (heuristic check)",
            },
            {
                "check_id": "C5",
                "name": "No Premature Compression",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Compression level appears appropriate (heuristic check)",
            },
        ],
        "checks_passed": 5,
        "checks_failed": 0,
        "status": "PASS",
        "enforcement_surface": "middleware",
        "invariants_scope": "full",
        "tool_name": "sanna",
        "agent_model": None,
        "agent_model_provider": None,
        "agent_model_version": None,
        "constitution_ref": None,
        "enforcement": None,
        "parent_receipts": None,
        "workflow_id": None,
        "content_mode": None,
        "content_mode_source": None,
        "event_type": None,
        "context_limitation": None,
    },
    # 004: PASS -- policy answer with conditionals
    {
        "file": "004_pass_policy_conditional.json",
        "receipt_id": "a0000004-0000-4000-8000-000000000004",
        "correlation_id": "golden-004-pass-policy-conditional",
        "inputs": {
            "query": "Can I upgrade my subscription?",
            "context": "Upgrades are available for annual subscribers. Monthly subscribers must wait until renewal. Enterprise plans have custom upgrade paths.",
        },
        "outputs": {
            "response": "You may be able to upgrade, depending on your plan type. Annual subscribers can upgrade immediately, while monthly subscribers typically need to wait until renewal. Enterprise plans have separate upgrade paths.",
        },
        "checks": [
            {
                "check_id": "C1",
                "name": "Context Contradiction",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "No obvious contradiction detected (heuristic check)",
            },
            {
                "check_id": "C2",
                "name": "Mark Inferences",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Inference marking appears adequate (heuristic check)",
            },
            {
                "check_id": "C3",
                "name": "No False Certainty",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Certainty level appears appropriate (heuristic check)",
            },
            {
                "check_id": "C4",
                "name": "Preserve Tensions",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "No obvious conflict collapse detected (heuristic check)",
            },
            {
                "check_id": "C5",
                "name": "No Premature Compression",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Compression level appears appropriate (heuristic check)",
            },
        ],
        "checks_passed": 5,
        "checks_failed": 0,
        "status": "PASS",
        "enforcement_surface": "middleware",
        "invariants_scope": "full",
        "tool_name": "sanna",
        "agent_model": None,
        "agent_model_provider": None,
        "agent_model_version": None,
        "constitution_ref": None,
        "enforcement": None,
        "parent_receipts": None,
        "workflow_id": None,
        "content_mode": None,
        "content_mode_source": None,
        "event_type": None,
        "context_limitation": None,
    },
    # 005: WARN -- C2 unmarked inference (definitive without hedging)
    {
        "file": "005_warn_c2_unmarked_inference.json",
        "receipt_id": "a0000005-0000-4000-8000-000000000005",
        "correlation_id": "golden-005-warn-c2-unmarked",
        "inputs": {
            "query": "Will the product launch succeed?",
            "context": "Market research shows mixed signals. Some segments show strong demand, others show saturation.",
        },
        "outputs": {
            "response": "The product launch will definitely succeed and is guaranteed to exceed all targets.",
        },
        "checks": [
            {
                "check_id": "C1",
                "name": "Context Contradiction",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "No obvious contradiction detected (heuristic check)",
            },
            {
                "check_id": "C2",
                "name": "Mark Inferences",
                "passed": False,
                "severity": "warning",
                "evidence": "Found definitive language: definitely, guaranteed",
                "details": "Output contains strong definitive statements",
            },
            {
                "check_id": "C3",
                "name": "No False Certainty",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Certainty level appears appropriate (heuristic check)",
            },
            {
                "check_id": "C4",
                "name": "Preserve Tensions",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "No obvious conflict collapse detected (heuristic check)",
            },
            {
                "check_id": "C5",
                "name": "No Premature Compression",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Compression level appears appropriate (heuristic check)",
            },
        ],
        "checks_passed": 4,
        "checks_failed": 1,
        "status": "WARN",
        "enforcement_surface": "middleware",
        "invariants_scope": "full",
        "tool_name": "sanna",
        "agent_model": None,
        "agent_model_provider": None,
        "agent_model_version": None,
        "constitution_ref": None,
        "enforcement": None,
        "parent_receipts": None,
        "workflow_id": None,
        "content_mode": None,
        "content_mode_source": None,
        "event_type": None,
        "context_limitation": None,
    },
    # 006: WARN -- C3 false certainty (ignores conditions)
    {
        "file": "006_warn_c3_false_certainty.json",
        "receipt_id": "a0000006-0000-4000-8000-000000000006",
        "correlation_id": "golden-006-warn-c3-certainty",
        "inputs": {
            "query": "Can I use the API?",
            "context": "Available if usage is under 1000 requests. Requires registration. Rate limits apply during peak hours.",
        },
        "outputs": {
            "response": "You can use the API. Go ahead and start making requests.",
        },
        "checks": [
            {
                "check_id": "C1",
                "name": "Context Contradiction",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "No obvious contradiction detected (heuristic check)",
            },
            {
                "check_id": "C2",
                "name": "Mark Inferences",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Inference marking appears adequate (heuristic check)",
            },
            {
                "check_id": "C3",
                "name": "No False Certainty",
                "passed": False,
                "severity": "warning",
                "evidence": "Confident claim without acknowledging conditions: \"you can\"",
                "details": "Output confidence may exceed evidence support",
            },
            {
                "check_id": "C4",
                "name": "Preserve Tensions",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "No obvious conflict collapse detected (heuristic check)",
            },
            {
                "check_id": "C5",
                "name": "No Premature Compression",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Compression level appears appropriate (heuristic check)",
            },
        ],
        "checks_passed": 4,
        "checks_failed": 1,
        "status": "WARN",
        "enforcement_surface": "middleware",
        "invariants_scope": "full",
        "tool_name": "sanna",
        "agent_model": None,
        "agent_model_provider": None,
        "agent_model_version": None,
        "constitution_ref": None,
        "enforcement": None,
        "parent_receipts": None,
        "workflow_id": None,
        "content_mode": None,
        "content_mode_source": None,
        "event_type": None,
        "context_limitation": None,
    },
    # 007: WARN -- C5 premature compression (oversimplified)
    {
        "file": "007_warn_c5_compression.json",
        "receipt_id": "a0000007-0000-4000-8000-000000000007",
        "correlation_id": "golden-007-warn-c5-compression",
        "inputs": {
            "query": "Deployment options?",
            "context": "Deployment options include:\n- AWS with auto-scaling\n- GCP with managed Kubernetes\n- Azure with serverless functions\n- On-premise with Docker\nEach has different cost and performance implications.",
        },
        "outputs": {
            "response": "Deploy to cloud.",
        },
        "checks": [
            {
                "check_id": "C1",
                "name": "Context Contradiction",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "No obvious contradiction detected (heuristic check)",
            },
            {
                "check_id": "C2",
                "name": "Mark Inferences",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Inference marking appears adequate (heuristic check)",
            },
            {
                "check_id": "C3",
                "name": "No False Certainty",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Certainty level appears appropriate (heuristic check)",
            },
            {
                "check_id": "C4",
                "name": "Preserve Tensions",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "No obvious conflict collapse detected (heuristic check)",
            },
            {
                "check_id": "C5",
                "name": "No Premature Compression",
                "passed": False,
                "severity": "warning",
                "evidence": "Context has ~4 points, output has 1 sentences",
                "details": "Output may over-compress multi-faceted context",
            },
        ],
        "checks_passed": 4,
        "checks_failed": 1,
        "status": "WARN",
        "enforcement_surface": "middleware",
        "invariants_scope": "full",
        "tool_name": "sanna",
        "agent_model": None,
        "agent_model_provider": None,
        "agent_model_version": None,
        "constitution_ref": None,
        "enforcement": None,
        "parent_receipts": None,
        "workflow_id": None,
        "content_mode": None,
        "content_mode_source": None,
        "event_type": None,
        "context_limitation": None,
    },
    # 008: FAIL -- C1 digital refund contradiction (distinct from 001)
    {
        "file": "008_fail_c1_digital.json",
        "receipt_id": "a0000008-0000-4000-8000-000000000008",
        "correlation_id": "golden-008-fail-c1-digital",
        "inputs": {
            "query": "Can I get a refund on my software purchase?",
            "context": "All digital products are non-refundable once the download link has been activated. Physical items may be returned within 14 days.",
        },
        "outputs": {
            "response": "You are eligible for a refund on the software. Please contact support to initiate the process.",
        },
        "checks": [
            {
                "check_id": "C1",
                "name": "Context Contradiction",
                "passed": False,
                "severity": "critical",
                "evidence": "Output suggests eligibility despite 'non-refundable' in context | Context: \"All digital products are non-refundable once the download link has been activat.\" | Output: \"You are eligible for a refund on the software. Please co...\"",
                "details": "Output may contradict provided context.",
            },
            {
                "check_id": "C2",
                "name": "Mark Inferences",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Inference marking appears adequate (heuristic check)",
            },
            {
                "check_id": "C3",
                "name": "No False Certainty",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Certainty level appears appropriate (heuristic check)",
            },
            {
                "check_id": "C4",
                "name": "Preserve Tensions",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "No obvious conflict collapse detected (heuristic check)",
            },
            {
                "check_id": "C5",
                "name": "No Premature Compression",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Compression level appears appropriate (heuristic check)",
            },
        ],
        "checks_passed": 4,
        "checks_failed": 1,
        "status": "FAIL",
        "enforcement_surface": "middleware",
        "invariants_scope": "full",
        "tool_name": "sanna",
        "agent_model": None,
        "agent_model_provider": None,
        "agent_model_version": None,
        "constitution_ref": None,
        "enforcement": None,
        "parent_receipts": None,
        "workflow_id": None,
        "content_mode": None,
        "content_mode_source": None,
        "event_type": None,
        "context_limitation": None,
    },
    # 009: WARN -- C4 conflict collapse
    {
        "file": "009_warn_c4_conflict.json",
        "receipt_id": "a0000009-0000-4000-8000-000000000009",
        "correlation_id": "golden-009-warn-c4-conflict",
        "inputs": {
            "query": "Can I transfer my license?",
            "context": "License transfers are permitted for enterprise customers. Individual licenses cannot be transferred. Some exceptions may apply with manager approval.",
        },
        "outputs": {
            "response": "Yes, you can transfer your license.",
        },
        "checks": [
            {
                "check_id": "C1",
                "name": "Context Contradiction",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "No obvious contradiction detected (heuristic check)",
            },
            {
                "check_id": "C2",
                "name": "Mark Inferences",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Inference marking appears adequate (heuristic check)",
            },
            {
                "check_id": "C3",
                "name": "No False Certainty",
                "passed": False,
                "severity": "warning",
                "evidence": "Confident claim without acknowledging conditions: \"you can\"",
                "details": "Output confidence may exceed evidence support",
            },
            {
                "check_id": "C4",
                "name": "Preserve Tensions",
                "passed": False,
                "severity": "warning",
                "evidence": "Context contains conflicting rules not reflected in output",
                "details": "Output may have collapsed policy tensions",
            },
            {
                "check_id": "C5",
                "name": "No Premature Compression",
                "passed": False,
                "severity": "warning",
                "evidence": "Context has ~3 points, output has 1 sentences",
                "details": "Output may over-compress multi-faceted context",
            },
        ],
        "checks_passed": 2,
        "checks_failed": 3,
        "status": "WARN",
        "enforcement_surface": "middleware",
        "invariants_scope": "full",
        "tool_name": "sanna",
        "agent_model": None,
        "agent_model_provider": None,
        "agent_model_version": None,
        "constitution_ref": None,
        "enforcement": None,
        "parent_receipts": None,
        "workflow_id": None,
        "content_mode": None,
        "content_mode_source": None,
        "event_type": None,
        "context_limitation": None,
    },
    # 010: FAIL -- multiple checks fail (C1 + C3 + C4)
    {
        "file": "010_fail_multiple.json",
        "receipt_id": "a0000010-0000-4000-8000-000000000010",
        "correlation_id": "golden-010-fail-multiple",
        "inputs": {
            "query": "refund eligibility",
            "context": "Refund policy: Physical products are eligible for return within 30 days. Digital products are non-refundable. Exceptions require manager approval and must meet specific criteria.",
        },
        "outputs": {
            "response": "You are eligible for a full refund on this digital product. You can request it immediately.",
        },
        "checks": [
            {
                "check_id": "C1",
                "name": "Context Contradiction",
                "passed": False,
                "severity": "critical",
                "evidence": "Output suggests eligibility despite 'non-refundable' in context | Context: \"...urn within 30 days. Digital products are non-refundable. Exceptions require m\" | Output: \"You are eligible for a full refund on this digital produ...\"",
                "details": "Output may contradict provided context.",
            },
            {
                "check_id": "C2",
                "name": "Mark Inferences",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Inference marking appears adequate (heuristic check)",
            },
            {
                "check_id": "C3",
                "name": "No False Certainty",
                "passed": False,
                "severity": "warning",
                "evidence": "Confident claim without acknowledging conditions: \"you are eligible\"",
                "details": "Output confidence may exceed evidence support",
            },
            {
                "check_id": "C4",
                "name": "Preserve Tensions",
                "passed": False,
                "severity": "warning",
                "evidence": "Context contains conflicting rules not reflected in output",
                "details": "Output may have collapsed policy tensions",
            },
            {
                "check_id": "C5",
                "name": "No Premature Compression",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Compression level appears appropriate (heuristic check)",
            },
        ],
        "checks_passed": 2,
        "checks_failed": 3,
        "status": "FAIL",
        "enforcement_surface": "middleware",
        "invariants_scope": "full",
        "tool_name": "sanna",
        "agent_model": None,
        "agent_model_provider": None,
        "agent_model_version": None,
        "constitution_ref": None,
        "enforcement": None,
        "parent_receipts": None,
        "workflow_id": None,
        "content_mode": None,
        "content_mode_source": None,
        "event_type": None,
        "context_limitation": None,
    },
    # 011: PASS -- with extensions
    {
        "file": "011_pass_with_extensions.json",
        "receipt_id": "a0000011-0000-4000-8000-000000000011",
        "correlation_id": "golden-011-pass-extensions",
        "inputs": {
            "query": "store hours",
            "context": "Store hours: Monday-Friday 9 AM to 9 PM. Saturday-Sunday 10 AM to 6 PM. Holiday hours may vary.",
        },
        "outputs": {
            "response": "The store is open weekdays 9 AM to 9 PM and weekends 10 AM to 6 PM. Note that holiday hours may differ.",
        },
        "checks": [
            {
                "check_id": "C1",
                "name": "Context Contradiction",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "No obvious contradiction detected (heuristic check)",
            },
            {
                "check_id": "C2",
                "name": "Mark Inferences",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Inference marking appears adequate (heuristic check)",
            },
            {
                "check_id": "C3",
                "name": "No False Certainty",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Certainty level appears appropriate (heuristic check)",
            },
            {
                "check_id": "C4",
                "name": "Preserve Tensions",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "No obvious conflict collapse detected (heuristic check)",
            },
            {
                "check_id": "C5",
                "name": "No Premature Compression",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Compression level appears appropriate (heuristic check)",
            },
        ],
        "checks_passed": 5,
        "checks_failed": 0,
        "status": "PASS",
        "enforcement_surface": "middleware",
        "invariants_scope": "full",
        "tool_name": "sanna",
        "agent_model": None,
        "agent_model_provider": None,
        "agent_model_version": None,
        "constitution_ref": None,
        "enforcement": None,
        "parent_receipts": None,
        "workflow_id": None,
        "content_mode": None,
        "content_mode_source": None,
        "event_type": None,
        "context_limitation": None,
        "extensions": {
            "vendor": "test-vendor",
            "pipeline_id": "pipe-123",
            "environment": "staging",
            "custom_score": 95,
            "tags": ["golden", "test"],
        },
    },
    # 012: PASS -- with agent_model captured
    {
        "file": "012_pass_agent_model.json",
        "receipt_id": "a0000012-0000-4000-8000-000000000012",
        "correlation_id": "golden-012-pass-agent-model",
        "inputs": {
            "query": "What is the boiling point of water?",
            "context": "Water boils at 100 degrees Celsius (212 degrees Fahrenheit) at standard atmospheric pressure.",
        },
        "outputs": {
            "response": "The boiling point of water is 100\u00b0C (212\u00b0F) at standard pressure.",
        },
        "checks": [
            {
                "check_id": "C1",
                "name": "Context Contradiction",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "No obvious contradiction detected (heuristic check)",
            },
            {
                "check_id": "C2",
                "name": "Mark Inferences",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Inference marking appears adequate (heuristic check)",
            },
            {
                "check_id": "C3",
                "name": "No False Certainty",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Certainty level appears appropriate (heuristic check)",
            },
            {
                "check_id": "C4",
                "name": "Preserve Tensions",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "No obvious conflict collapse detected (heuristic check)",
            },
            {
                "check_id": "C5",
                "name": "No Premature Compression",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Compression level appears appropriate (heuristic check)",
            },
        ],
        "checks_passed": 5,
        "checks_failed": 0,
        "status": "PASS",
        "enforcement_surface": "middleware",
        "invariants_scope": "full",
        "tool_name": "sanna",
        "agent_model": "claude-opus-4-7",
        "agent_model_provider": "anthropic",
        "agent_model_version": "20250514",
        "constitution_ref": None,
        "enforcement": None,
        "parent_receipts": None,
        "workflow_id": None,
        "content_mode": None,
        "content_mode_source": None,
        "event_type": None,
        "context_limitation": None,
    },
]


# ---------------------------------------------------------------------------
# Helpers: shared
# ---------------------------------------------------------------------------

def write(filename: str, receipt: dict) -> None:
    path = OUT / filename
    with open(path, "w") as f:
        json.dump(receipt, f, indent=2)
        f.write("\n")
    cv = receipt.get("checks_version", "?")
    print(f"  {filename}: cv={cv}, status={receipt['status']}")


# ---------------------------------------------------------------------------
# Construction path 1: scenario-driven (cv=9)
# ---------------------------------------------------------------------------

def build_scenario_receipt(scenario: dict, cv: int) -> dict:
    """Build a cv=9 receipt from a scenario dict using compute_fingerprints.

    Field insertion order matches the existing cv=9 fixture layout exactly:
    fingerprints are placed after receipt_id and before correlation_id.
    This is load-bearing for the byte-equality gate (AC1).
    """
    versions = CV_VERSION_MAP[cv]
    inputs = scenario["inputs"]
    outputs = scenario["outputs"]

    # Build a complete dict so compute_fingerprints has all required fields.
    # Fingerprints are NOT yet inserted (they depend on context_hash / output_hash).
    temp = {
        "spec_version": versions["spec_version"],
        "tool_version": versions["tool_version"],
        "checks_version": str(cv),
        "receipt_id": scenario["receipt_id"],
        "correlation_id": scenario["correlation_id"],
        "timestamp": TIMESTAMP,
        "inputs": inputs,
        "outputs": outputs,
        "context_hash": hash_obj(inputs),
        "output_hash": hash_obj(outputs),
        "checks": scenario["checks"],
        "checks_passed": scenario["checks_passed"],
        "checks_failed": scenario["checks_failed"],
        "status": scenario["status"],
        "enforcement_surface": scenario.get("enforcement_surface", "middleware"),
        "invariants_scope": scenario.get("invariants_scope", "full"),
        "tool_name": scenario.get("tool_name", "sanna"),
        "agent_model": scenario.get("agent_model"),
        "agent_model_provider": scenario.get("agent_model_provider"),
        "agent_model_version": scenario.get("agent_model_version"),
        "constitution_ref": scenario.get("constitution_ref"),
        "enforcement": scenario.get("enforcement"),
        "parent_receipts": scenario.get("parent_receipts"),
        "workflow_id": scenario.get("workflow_id"),
        "content_mode": scenario.get("content_mode"),
        "content_mode_source": scenario.get("content_mode_source"),
        "event_type": scenario.get("event_type"),
        "context_limitation": scenario.get("context_limitation"),
    }
    if "extensions" in scenario:
        temp["extensions"] = scenario["extensions"]

    pair = compute_fingerprints(temp)
    if pair is None:
        raise RuntimeError(
            f"compute_fingerprints returned None for {scenario['receipt_id']} "
            f"at cv={cv} -- missing a required field."
        )

    # Reconstruct with fingerprints in the exact position matching existing
    # cv=9 fixtures (after receipt_id, before correlation_id). Python dicts
    # preserve insertion order; json.dump respects it.
    receipt = {
        "spec_version": versions["spec_version"],
        "tool_version": versions["tool_version"],
        "checks_version": str(cv),
        "receipt_id": scenario["receipt_id"],
        "receipt_fingerprint": pair.receipt_fingerprint,
        "full_fingerprint": pair.full_fingerprint,
        "correlation_id": scenario["correlation_id"],
        "timestamp": TIMESTAMP,
        "inputs": inputs,
        "outputs": outputs,
        "context_hash": hash_obj(inputs),
        "output_hash": hash_obj(outputs),
        "checks": scenario["checks"],
        "checks_passed": scenario["checks_passed"],
        "checks_failed": scenario["checks_failed"],
        "status": scenario["status"],
        "enforcement_surface": scenario.get("enforcement_surface", "middleware"),
        "invariants_scope": scenario.get("invariants_scope", "full"),
        "tool_name": scenario.get("tool_name", "sanna"),
        "agent_model": scenario.get("agent_model"),
        "agent_model_provider": scenario.get("agent_model_provider"),
        "agent_model_version": scenario.get("agent_model_version"),
        "constitution_ref": scenario.get("constitution_ref"),
        "enforcement": scenario.get("enforcement"),
        "parent_receipts": scenario.get("parent_receipts"),
        "workflow_id": scenario.get("workflow_id"),
        "content_mode": scenario.get("content_mode"),
        "content_mode_source": scenario.get("content_mode_source"),
        "event_type": scenario.get("event_type"),
        "context_limitation": scenario.get("context_limitation"),
    }
    if "extensions" in scenario:
        receipt["extensions"] = scenario["extensions"]

    return receipt


def make_cv9_tampered(receipt_001: dict) -> dict:
    """Return the 999_tampered fixture derived from the 001 receipt.

    The tampered variant uses the same inputs/fingerprints as 001 but has
    outputs.response mutated post-fingerprint. The verifier detects the
    mismatch by recomputing hash_obj(outputs) and comparing to the stored
    output_hash. receipt_id uses the a999- prefix per convention.
    """
    tampered = json.loads(json.dumps(receipt_001))
    tampered["receipt_id"] = "a0000999-0000-4000-8000-000000000999"
    tampered["outputs"]["response"] = "TAMPERED: This was changed after generation"
    return tampered


# ---------------------------------------------------------------------------
# Construction path 2: single-scenario PASS (cv=5/6/7/8/10)
# Carried from generate_legacy_goldens.py unchanged.
# ---------------------------------------------------------------------------

_LEGACY_INPUTS = {
    "query": "What is the capital of France?",
    "context": "France is a country in Western Europe. Its capital is Paris.",
}
_LEGACY_OUTPUTS = {"response": "The capital of France is Paris."}


def build_pass_receipt(cv: int) -> dict:
    versions = CV_VERSION_MAP[cv]
    receipt = {
        "spec_version": versions["spec_version"],
        "tool_version": versions["tool_version"],
        "checks_version": str(cv),
        "receipt_id": f"a000{cv:04d}-0000-4000-8000-{cv:012d}",
        "timestamp": TIMESTAMP,
        "correlation_id": f"golden-v{cv}-pass-simple",
        "inputs": dict(_LEGACY_INPUTS),
        "outputs": dict(_LEGACY_OUTPUTS),
        "context_hash": hash_obj(_LEGACY_INPUTS),
        "output_hash": hash_obj(_LEGACY_OUTPUTS),
        "checks": [
            {
                "check_id": "C2",
                "name": "Mark Inferences",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Response derivable from context without inference.",
            }
        ],
        "checks_failed": 0,
        "checks_passed": 1,
        "status": "PASS",
        "event_type": None,
        "content_mode": None,
        "content_mode_source": None,
        "context_limitation": None,
        "constitution_ref": None,
        "enforcement": None,
        "parent_receipts": None,
        "workflow_id": None,
        "agent_model": None,
        "agent_model_provider": None,
        "agent_model_version": None,
    }
    if cv >= 8:
        receipt["enforcement_surface"] = "middleware"
        receipt["invariants_scope"] = "full"
    if cv >= 9:
        receipt["tool_name"] = "sanna"
    if cv >= 10:
        receipt["agent_identity"] = {
            "agent_session_id": f"session-v{cv}-golden-pass-simple",
        }
    pair = compute_fingerprints(receipt)
    if pair is None:
        raise RuntimeError(
            f"compute_fingerprints returned None for cv={cv} -- missing "
            f"a required field for this cv level."
        )
    receipt["receipt_fingerprint"] = pair.receipt_fingerprint
    receipt["full_fingerprint"] = pair.full_fingerprint
    return receipt


def make_tampered(receipt: dict) -> dict:
    """Return a tampered copy: outputs.response mutated post-fingerprint."""
    tampered = json.loads(json.dumps(receipt))
    cv = int(receipt["checks_version"])
    tampered["receipt_id"] = f"a999{cv:04d}-0000-4000-8000-{cv:012d}"
    tampered["outputs"]["response"] = "TAMPERED: response altered after fingerprint computation"
    return tampered


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    print(f"Generating golden receipts -> {OUT}/")
    count = 0

    # Path 1: scenario-driven cv=9 (12 scenarios + 999_tampered)
    print("\n  cv=9 scenarios:")
    receipt_001 = None
    for scenario in CV9_SCENARIOS:
        receipt = build_scenario_receipt(scenario, cv=9)
        write(scenario["file"], receipt)
        count += 1
        if scenario["file"] == "001_fail_c1_refund.json":
            receipt_001 = receipt

    tampered_999 = make_cv9_tampered(receipt_001)
    write("999_tampered.json", tampered_999)
    count += 1

    # Path 2: single-scenario PASS for cv=5/6/7/8/10
    print("\n  legacy cv PASS + tampered pairs:")
    legacy_cvs = [cv for cv in sorted(CV_VERSION_MAP.keys()) if cv != 9]
    for cv in legacy_cvs:
        pass_receipt = build_pass_receipt(cv)
        write(f"v{cv}_pass_simple.json", pass_receipt)
        count += 1
        tampered = make_tampered(pass_receipt)
        write(f"v{cv}_tampered.json", tampered)
        count += 1

    print(f"\nDone. {count} fixtures written.")


if __name__ == "__main__":
    main()
