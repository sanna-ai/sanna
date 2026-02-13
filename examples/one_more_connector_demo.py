#!/usr/bin/env python3
"""One More Connector — Sanna v0.7.0 Governance Demo

An agent uses 3-4 MCP tools. Sanna is the governance connector.
Four scenarios show the full governance lifecycle:

  1. Query a database (allowed) → receipt shows ALLOW
  2. Attempt to send an email (blocked) → receipt shows HALT
  3. Encounter PII data (triggers escalation) → receipt shows ESCALATE
  4. Generate a report (allowed) → receipt shows full audit trail

Each scenario produces a receipt JSON in examples/demo_receipts/.

Run: python examples/one_more_connector_demo.py
"""

import json
import sys
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sanna.constitution import (
    load_constitution,
    sign_constitution,
    save_constitution,
    constitution_to_receipt_ref,
)
from sanna.crypto import generate_keypair
from sanna.enforcement import configure_checks
from sanna.enforcement.authority import evaluate_authority, AuthorityDecision
from sanna.enforcement.escalation import execute_escalation, EscalationTarget
from sanna.middleware import (
    _build_trace_data,
    _generate_constitution_receipt,
    _resolve_source_tiers,
    _build_source_trust_evaluations,
)

# =============================================================================
# PATHS
# =============================================================================

CONSTITUTION_PATH = Path(__file__).parent / "constitutions" / "governance_connector.yaml"
OUTPUT_DIR = Path(__file__).parent / "demo_receipts"
OUTPUT_DIR.mkdir(exist_ok=True)


# =============================================================================
# SCENARIOS
# =============================================================================

SCENARIOS = [
    {
        "name": "01_query_database_allow",
        "title": "Query Database — ALLOWED",
        "description": "Agent queries the internal database. Constitution explicitly allows this action.",
        "action": "query_database",
        "params": {"table": "customers", "filter": "region=EMEA"},
        "query": "Show me all EMEA customers from Q4.",
        "context": [
            {
                "text": "Customer table contains 2,847 EMEA records for Q4 2025. "
                        "Top accounts: Acme Corp (€1.2M), Beta Ltd (€890K), Gamma GmbH (€750K).",
                "source": "internal_database",
            },
        ],
        "output": (
            "Based on the internal database, there are 2,847 EMEA customers for Q4 2025. "
            "The top three accounts by revenue are Acme Corp (€1.2M), Beta Ltd (€890K), "
            "and Gamma GmbH (€750K)."
        ),
    },
    {
        "name": "02_send_email_halt",
        "title": "Send Email — HALTED",
        "description": "Agent attempts to send an email. Constitution forbids outbound communication.",
        "action": "send_email",
        "params": {"to": "customer@example.com", "subject": "Q4 Report"},
        "query": "Email the Q4 report to the customer.",
        "context": [
            {
                "text": "The Q4 EMEA report has been generated and is ready for distribution.",
                "source": "internal_database",
            },
        ],
        "output": (
            "I will send the Q4 EMEA report to customer@example.com now."
        ),
    },
    {
        "name": "03_pii_access_escalate",
        "title": "PII Data Access — ESCALATED",
        "description": "Agent requests SSN field. Constitution requires escalation for PII.",
        "action": "access_customer_record",
        "params": {"customer_id": "C-9182", "fields": ["name", "email", "phone", "SSN"]},
        "query": "Look up full details for customer C-9182.",
        "context": [
            {
                "text": "Customer C-9182: Jane Doe, jane.doe@example.com, +1-555-0142. "
                        "Account tier: Premium. Region: NA.",
                "source": "partner_api",
            },
        ],
        "output": (
            "Customer C-9182 is Jane Doe, a Premium-tier customer in the NA region. "
            "Contact: jane.doe@example.com, +1-555-0142. "
            "Note: SSN field requires additional authorization."
        ),
    },
    {
        "name": "04_generate_report_audit",
        "title": "Generate Report — FULL AUDIT TRAIL",
        "description": "Agent generates a report from multiple sources. Receipt shows source-aware evaluation.",
        "action": "generate_report",
        "params": {"report_type": "quarterly_summary", "quarter": "Q4-2025"},
        "query": "Generate the Q4 2025 quarterly summary report.",
        "context": [
            {
                "text": "Q4 revenue: €4.7M (+12% YoY). EMEA led growth at 18%. "
                        "NA flat at 2%. APAC down 3%.",
                "source": "internal_database",
            },
            {
                "text": "Partner channel contributed €1.1M in Q4, up from €850K in Q3. "
                        "Three new partners onboarded.",
                "source": "partner_api",
            },
            {
                "text": "Industry analysts project 8-10% market growth for 2026. "
                        "Key risk: supply chain disruptions in APAC.",
                "source": "web_search",
            },
        ],
        "output": (
            "Q4 2025 Quarterly Summary:\n\n"
            "Revenue reached €4.7M, up 12% year-over-year. EMEA was the strongest "
            "region at 18% growth, while NA was flat at 2% and APAC declined 3%. "
            "The partner channel contributed €1.1M (up from €850K in Q3) with three "
            "new partners onboarded.\n\n"
            "Industry analysts project 8-10% market growth for 2026, though APAC "
            "supply chain risks remain a concern."
        ),
    },
]


# =============================================================================
# DEMO RUNNER
# =============================================================================

def run_demo():
    """Run the One More Connector demo."""
    print("=" * 72)
    print("  One More Connector — Sanna v0.7.0 Governance Demo")
    print("=" * 72)
    print()
    print("  Scenario: An agent uses multiple MCP tools.")
    print("  Sanna is the governance connector — one more tool in the chain.")
    print("  Every action evaluated. Every response checked. Every receipt portable.")
    print()

    with tempfile.TemporaryDirectory(prefix="sanna_demo_") as tmp_dir:
        tmp = Path(tmp_dir)

        # 1. Generate Ed25519 keypair
        priv_path, pub_path = generate_keypair(
            tmp / "keys", signed_by="governance-demo", write_metadata=True
        )
        print(f"  Keypair generated: {priv_path.name}")
        print()

        # 2. Load and sign constitution
        constitution = load_constitution(str(CONSTITUTION_PATH), validate=True)
        signed = sign_constitution(
            constitution,
            private_key_path=str(priv_path),
            signed_by="governance-demo",
        )
        signed_path = tmp / "governance_connector.yaml"
        save_constitution(signed, signed_path)

        print(f"  Constitution: {signed.identity.agent_name}")
        print(f"  policy_hash:  {signed.policy_hash[:32]}...")
        print(f"  Authority boundaries:")
        ab = signed.authority_boundaries
        print(f"    cannot_execute:  {ab.cannot_execute}")
        print(f"    must_escalate:   {[r.condition for r in ab.must_escalate]}")
        print(f"    can_execute:     {ab.can_execute}")
        ts = signed.trusted_sources
        print(f"  Trusted sources:")
        print(f"    tier_1:    {ts.tier_1}")
        print(f"    tier_2:    {ts.tier_2}")
        print(f"    tier_3:    {ts.tier_3}")
        print(f"    untrusted: {ts.untrusted}")
        print()

        # Prepare check configs
        constitution_ref = constitution_to_receipt_ref(signed)
        check_configs, custom_records = configure_checks(signed)

        # 3. Run each scenario
        for scenario in SCENARIOS:
            print("-" * 72)
            print(f"  {scenario['title']}")
            print(f"  {scenario['description']}")
            print("-" * 72)

            receipt = run_scenario(
                scenario=scenario,
                constitution=signed,
                constitution_ref=constitution_ref,
                check_configs=check_configs,
                custom_records=custom_records,
            )

            # Sign the receipt
            from sanna.crypto import sign_receipt
            receipt = sign_receipt(receipt, str(priv_path))

            # Print summary
            print_receipt_summary(receipt, scenario)

            # Write receipt
            output_path = OUTPUT_DIR / f"{scenario['name']}.json"
            with open(output_path, "w") as f:
                json.dump(receipt, f, indent=2)
            print(f"\n  Receipt saved: {output_path.name}")
            print()

        # 4. Summary
        print("=" * 72)
        print("  GOVERNANCE LIFECYCLE SUMMARY")
        print("=" * 72)
        print()
        print("  01_query_database_allow   — Action ALLOWED (can_execute)")
        print("                              C1 PASS, sources: tier_1")
        print("  02_send_email_halt        — Action HALTED (cannot_execute)")
        print("                              Forbidden by authority boundary")
        print("  03_pii_access_escalate    — Action ESCALATED (must_escalate)")
        print("                              PII detected, logged for review")
        print("  04_generate_report_audit  — Action ALLOWED (can_execute)")
        print("                              Mixed sources: tier_1 + tier_2 + tier_3")
        print()
        print("  Four receipts, four governance outcomes, one connector.")
        print(f"  All receipts in: {OUTPUT_DIR}/")
        print()


def run_scenario(
    *,
    scenario: dict,
    constitution,
    constitution_ref: dict,
    check_configs: list,
    custom_records: list,
) -> dict:
    """Run a single scenario: evaluate authority + generate receipt."""

    # --- Authority evaluation ---
    decision = evaluate_authority(
        scenario["action"],
        scenario["params"],
        constitution,
    )
    authority_decisions = [
        {
            "action": scenario["action"],
            "params": scenario["params"],
            "decision": decision.decision,
            "reason": decision.reason,
            "boundary_type": decision.boundary_type,
            "escalation_target": (
                {"type": decision.escalation_target.type}
                if decision.escalation_target
                else None
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    ]

    # --- Escalation (if triggered) ---
    escalation_events = []
    if decision.decision == "escalate" and decision.escalation_target:
        esc_result = execute_escalation(
            decision.escalation_target,
            {
                "action": scenario["action"],
                "params": scenario["params"],
                "reason": decision.reason,
            },
        )
        escalation_events.append({
            "action": scenario["action"],
            "condition": decision.reason,
            "target_type": decision.escalation_target.type,
            "success": esc_result.success,
            "details": esc_result.details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    # --- Resolve structured context + source tiers ---
    raw_context = scenario["context"]
    resolved_context = _resolve_source_tiers(raw_context, constitution.trusted_sources)
    source_trust_evals = _build_source_trust_evaluations(resolved_context)

    # --- Build trace data ---
    context_str = "\n".join(item["text"] for item in raw_context)
    trace_data = _build_trace_data(
        trace_id=f"demo-{scenario['name']}",
        query=scenario["query"],
        context=context_str,
        output=scenario["output"],
    )

    # --- Generate receipt ---
    receipt = _generate_constitution_receipt(
        trace_data,
        check_configs=check_configs,
        custom_records=custom_records,
        constitution_ref=constitution_ref,
        constitution_version=constitution.schema_version,
        authority_decisions=authority_decisions,
        escalation_events=escalation_events if escalation_events else None,
        source_trust_evaluations=source_trust_evals,
        structured_context=resolved_context,
    )

    return receipt


def print_receipt_summary(receipt: dict, scenario: dict):
    """Print a concise summary of a receipt."""

    # Authority
    auth = receipt.get("authority_decisions", [])
    if auth:
        d = auth[0]
        icon = {"allow": "ALLOW", "halt": "HALT", "escalate": "ESCALATE"}[d["decision"]]
        print(f"\n  Authority: [{icon}] {d['reason']}")
        if d.get("escalation_target"):
            print(f"  Escalation: target={d['escalation_target']['type']}")

    # Escalation events
    esc = receipt.get("escalation_events", [])
    if esc:
        for e in esc:
            status = "success" if e["success"] else "failed"
            print(f"  Escalation event: {e['target_type']} — {status}")

    # Source trust
    src = receipt.get("source_trust_evaluations", [])
    if src:
        tiers = ", ".join(f"{s['source_name']}={s['trust_tier']}" for s in src)
        print(f"  Sources: {tiers}")

    # Coherence checks
    checks = receipt.get("checks", [])
    print(f"\n  Coherence: {receipt['coherence_status']} "
          f"({receipt['checks_passed']} passed, {receipt['checks_failed']} failed)")
    for c in checks:
        icon = "PASS" if c["passed"] else "FAIL"
        print(f"    [{icon}] {c['check_id']:35s} enforcement={c['enforcement_level']}")

    # Fingerprint
    print(f"\n  Fingerprint: {receipt['receipt_fingerprint']}")


if __name__ == "__main__":
    run_demo()
