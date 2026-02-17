#!/usr/bin/env python3
"""Fleet Governance Demo — Sanna v0.8.0

Simulates three agents over 90 days, detects governance drift,
and exports evidence.  Demonstrates ReceiptStore, DriftAnalyzer,
custom evaluators, multi-window analysis, CSV/JSON export, and
offline receipt verification — all in one script.

Run:
    python examples/fleet_governance_demo.py
"""

import json
import random
import sys
import tempfile
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sanna.constitution import load_constitution, compute_constitution_hash, sign_constitution
from sanna.crypto import generate_keypair
from sanna.drift import DriftAnalyzer, export_drift_report_to_file, format_drift_report
from sanna.evaluators import register_invariant_evaluator, clear_evaluators
from sanna.init_constitution import load_template, render_template
from sanna.middleware import sanna_observe, SannaHaltError
from sanna.receipt import CheckResult
from sanna.store import ReceiptStore
from sanna.verify import verify_receipt, load_schema


# =============================================================================
# CONSTANTS
# =============================================================================

SEED = 42
TOTAL_DAYS = 90

# Agent definitions
# weekly_fail_pct controls the probability of choosing a C1-failing output.
# receipts_per_week controls volume — higher = more statistically stable.
AGENTS = [
    {
        "name": "snow-agent",
        "template": "enterprise-it",
        "enforcement": "strict",
        "description": "Enterprise IT / ServiceNow agent",
        # Stable low failure rate (~2%)
        "weekly_fail_pct": [2] * 13,
        "receipts_per_week": 14,
    },
    {
        "name": "sfdc-agent",
        "template": "customer-facing",
        "enforcement": "standard",
        "description": "Customer-facing CRM agent",
        # DRIFTING: starts good, degrades steadily over 12 weeks
        "weekly_fail_pct": [2, 3, 4, 5, 7, 9, 12, 15, 18, 22, 26, 30, 35],
        "receipts_per_week": 14,
    },
    {
        "name": "custom-agent",
        "template": "general-purpose",
        "enforcement": "advisory",
        "description": "General-purpose helper agent",
        # Stable moderate failure rate (~3%)
        "weekly_fail_pct": [3] * 13,
        "receipts_per_week": 14,
    },
]


# =============================================================================
# CONTEXT / OUTPUT PAIRS — crafted to trigger or pass C1
# =============================================================================

# Context contains "non-refundable" — the key C1 trigger word
CONTEXT = (
    "Our refund policy: Physical products can be returned within 30 days. "
    "Digital products are non-refundable once downloaded. "
    "Subscriptions can be cancelled anytime. "
    "If the product is defective, exceptions may apply. "
    "However, all exceptions require manager approval."
)

# Outputs that PASS C1 (no "eligible" + "refund" alongside "non-refundable" context)
GOOD_OUTPUTS = [
    "Physical products may be returned within 30 days of purchase. However, digital products are non-refundable once downloaded.",
    "I'd be happy to help. Note that subscriptions can be cancelled anytime, but digital downloads are non-refundable.",
    "Let me check your order. Physical items can be returned, however digital purchases cannot be refunded after download.",
    "According to our policy, physical products are returnable within 30 days. However, downloaded items are non-refundable.",
    "Thank you for reaching out. I can help with physical product returns, but note that digital downloads are final.",
    "Our records show this is a physical product, so it may be returnable within the 30-day window. However, digital items are excluded.",
    "For subscription cancellations, you can cancel anytime. However, please note that digital products are non-refundable.",
    "I understand your concern. Note that all exceptions to our refund policy require manager approval.",
]

# Outputs that FAIL C1 (say "eligible" + "refund" which contradicts "non-refundable")
BAD_OUTPUTS = [
    "Based on your purchase history, you are eligible for a refund on the software.",
    "You are eligible for a full refund on this digital product.",
    "Good news — your software purchase is eligible for a refund within 30 days.",
    "I can process your digital product refund. You are eligible for a full return.",
]

QUERIES = [
    "Can I get a refund?",
    "What is the refund policy?",
    "I want to return my purchase.",
    "Is this product refundable?",
    "Help with refund request.",
]


# =============================================================================
# CUSTOM EVALUATOR — demonstrates v0.8.0 evaluator registry
# =============================================================================

def _register_custom_evaluator():
    """Register a custom invariant evaluator for response length."""
    @register_invariant_evaluator("INV_RESPONSE_LENGTH")
    def check_response_length(
        context: str, output: str, constitution: dict, check_config: dict
    ) -> CheckResult:
        """Ensure response is at least 20 characters."""
        if len(output.strip()) < 20:
            return CheckResult(
                check_id="INV_RESPONSE_LENGTH",
                name="Response Length",
                passed=False,
                severity="warning",
                evidence=f"Response is only {len(output.strip())} chars (min 20)",
                details="Response is too short to be useful.",
            )
        return CheckResult(
            check_id="INV_RESPONSE_LENGTH",
            name="Response Length",
            passed=True,
            severity="info",
            details=f"Response length OK ({len(output.strip())} chars)",
        )


# =============================================================================
# CONSTITUTION SETUP
# =============================================================================

def setup_constitutions(tmp_dir: Path):
    """Load templates, customise, sign with Ed25519, and return paths by agent name.

    Uses YAML-patching to set policy_hash and inject the Ed25519 signature
    without round-tripping through save_constitution (which serialises null
    fields that fail schema validation).
    """
    # Generate a single keypair for all demo constitutions
    priv_path, _ = generate_keypair(tmp_dir / "keys")

    paths = {}
    for agent in AGENTS:
        template_content = load_template(agent["template"])
        rendered = render_template(
            template_content,
            agent_name=agent["name"],
            description=agent["description"],
            enforcement=agent["enforcement"],
        )

        # For custom-agent, inject a custom invariant
        if agent["name"] == "custom-agent":
            rendered = _inject_custom_invariant(rendered)

        # Write unsigned, compute hash, patch YAML with policy_hash
        unsigned_path = tmp_dir / f"{agent['name']}_unsigned.yaml"
        unsigned_path.write_text(rendered, encoding="utf-8")

        constitution = load_constitution(str(unsigned_path))
        policy_hash = compute_constitution_hash(constitution)
        hashed_yaml = rendered.replace("policy_hash: null", f"policy_hash: {policy_hash}")

        # Sign the constitution with Ed25519 and inject signature into YAML
        signed_const = sign_constitution(
            constitution, private_key_path=str(priv_path), signed_by="demo-signer"
        )
        sig = signed_const.provenance.signature
        sig_block = (
            f"  signature:\n"
            f"    value: {sig.value}\n"
            f"    key_id: {sig.key_id}\n"
            f"    signed_by: {sig.signed_by}\n"
            f"    signed_at: '{sig.signed_at}'\n"
            f"    scheme: {sig.scheme}\n"
        )
        signed_yaml = hashed_yaml.replace(
            "  change_history: []\n", f"  change_history: []\n{sig_block}"
        )

        signed_path = tmp_dir / f"{agent['name']}.yaml"
        signed_path.write_text(signed_yaml, encoding="utf-8")
        paths[agent["name"]] = str(signed_path)

    return paths


def _inject_custom_invariant(yaml_content: str) -> str:
    """Inject INV_RESPONSE_LENGTH invariant into the invariants list."""
    injection = (
        "  - id: \"INV_RESPONSE_LENGTH\"\n"
        "    rule: \"Response must be at least 20 characters.\"\n"
        "    enforcement: \"warn\"\n\n"
    )
    return yaml_content.replace(
        "# --- Authority Boundaries ---",
        injection + "# --- Authority Boundaries ---",
    )


# =============================================================================
# RECEIPT SIMULATION
# =============================================================================

def simulate_receipts(store, constitution_paths, rng):
    """Generate receipts for all agents across 90 days.

    Uses @sanna_observe with real constitutions to produce genuine
    receipts.  The failure rate is controlled by choosing good vs. bad
    outputs at the rates defined per-week in each agent config.
    """
    now = datetime.now(timezone.utc)
    total_generated = 0
    agent_counts = {}

    for agent_cfg in AGENTS:
        name = agent_cfg["name"]
        const_path = constitution_paths[name]
        count = 0

        for week in range(13):
            fail_pct = agent_cfg["weekly_fail_pct"][week]
            n_per_week = agent_cfg["receipts_per_week"]

            for i in range(n_per_week):
                # Spread receipts evenly across the week
                day_offset = week * 7 + int(i * 7 / n_per_week)
                if day_offset >= TOTAL_DAYS:
                    break

                should_fail = rng.random() * 100 < fail_pct
                query = rng.choice(QUERIES)
                output = rng.choice(BAD_OUTPUTS) if should_fail else rng.choice(GOOD_OUTPUTS)

                receipt = _generate_one_receipt(const_path, query, CONTEXT, output)
                if receipt is None:
                    continue

                # Backdate the receipt
                receipt_ts = now - timedelta(days=TOTAL_DAYS - day_offset)
                receipt["timestamp"] = receipt_ts.isoformat()

                store.save(receipt)
                count += 1

        agent_counts[name] = count
        total_generated += count

    return total_generated, agent_counts


def _generate_one_receipt(const_path, query, context, output):
    """Generate a single receipt using @sanna_observe."""
    @sanna_observe(constitution_path=const_path)
    def agent_fn(query: str, context: str) -> str:
        return output

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = agent_fn(query=query, context=context)
            return result.receipt
    except SannaHaltError as e:
        return e.receipt
    except Exception:
        return None


# =============================================================================
# DEMO RUNNER
# =============================================================================

def run_demo(output_dir=None):
    """Run the full fleet governance demo.

    Args:
        output_dir: Directory for export files. If None, uses a temp dir.

    Returns:
        A dict with demo results for testing.
    """
    rng = random.Random(SEED)

    print()
    print("\u2550" * 60)
    print("  Sanna Fleet Governance Demo \u2014 v0.8.0")
    print("\u2550" * 60)
    print()

    with tempfile.TemporaryDirectory(prefix="sanna_fleet_demo_") as tmp_dir:
        tmp = Path(tmp_dir)
        export_dir = Path(output_dir) if output_dir else tmp / "export"
        export_dir.mkdir(parents=True, exist_ok=True)

        # ------------------------------------------------------------------
        # 1. SETUP
        # ------------------------------------------------------------------
        print("1. SETUP \u2014 Creating constitutions from templates")
        print("-" * 60)

        _register_custom_evaluator()
        print("   Custom evaluator: INV_RESPONSE_LENGTH registered")

        constitution_paths = setup_constitutions(tmp)
        for name, path in constitution_paths.items():
            const = load_constitution(path)
            print(f"   {name:<14} | {const.identity.domain:<18} | hash={const.policy_hash[:16]}...")
        print()

        # ------------------------------------------------------------------
        # 2. SIMULATE 90 DAYS
        # ------------------------------------------------------------------
        print("2. SIMULATE \u2014 Generating receipts across 90 days")
        print("-" * 60)

        db_path = str(tmp / "fleet.db")
        store = ReceiptStore(db_path)

        total, agent_counts = simulate_receipts(store, constitution_paths, rng)
        for name, count in agent_counts.items():
            print(f"   {name:<14} | {count} receipts")
        print(f"   Total: {total} receipts")
        print()

        # ------------------------------------------------------------------
        # 3. DRIFT ANALYSIS
        # ------------------------------------------------------------------
        print("3. DRIFT ANALYSIS \u2014 Multi-window fleet report")
        print("-" * 60)

        analyzer = DriftAnalyzer(store)
        reports = analyzer.analyze_multi(
            windows=[30, 90],
            threshold=0.15,
            projection_days=90,
        )

        for report in reports:
            print(format_drift_report(report))

        # ------------------------------------------------------------------
        # 4. EXPORT
        # ------------------------------------------------------------------
        print("4. EXPORT \u2014 Enterprise reporting")
        print("-" * 60)

        csv_path = str(export_dir / "fleet_report.csv")
        json_path = str(export_dir / "fleet_report.json")

        report_90d = reports[1]  # 90-day window
        csv_abs = export_drift_report_to_file(report_90d, csv_path, fmt="csv")
        json_abs = export_drift_report_to_file(report_90d, json_path, fmt="json")

        print(f"   CSV:  {csv_abs}")
        print(f"   JSON: {json_abs}")
        print()

        # ------------------------------------------------------------------
        # 5. OFFLINE VERIFICATION
        # ------------------------------------------------------------------
        print("5. VERIFY \u2014 Offline receipt verification")
        print("-" * 60)

        schema = load_schema()
        sample_receipts = {}
        verification_results = {}

        for agent_cfg in AGENTS:
            name = agent_cfg["name"]
            receipts = store.query(agent_id=name)
            if receipts:
                sample_receipts[name] = receipts[0]

        for name, receipt in sample_receipts.items():
            vr = verify_receipt(receipt, schema)
            verification_results[name] = vr
            status = "VALID" if vr.valid else "INVALID"
            rid = receipt.get("receipt_id", "?")[:12]
            print(f"   {name:<14} | receipt {rid}... | {status}")
            if not vr.valid and vr.errors:
                for e in vr.errors[:1]:
                    print(f"   {'':<14}   error: {e[:70]}")

        print()

        # ------------------------------------------------------------------
        # 6. SUMMARY
        # ------------------------------------------------------------------
        fleet_statuses = {r.window_days: r.fleet_status for r in reports}
        agent_statuses_30d = {}
        agent_statuses_90d = {}
        if reports:
            for a in reports[0].agents:
                agent_statuses_30d[a.agent_id] = a.status
            for a in reports[1].agents:
                agent_statuses_90d[a.agent_id] = a.status

        print("\u2550" * 60)
        print()
        print("  Three agents, three platforms, one governance view.")
        print("  See which agent is drifting before it fails an audit.")
        print("  Export the proof trail. Verify every receipt offline.")
        print()
        print("\u2550" * 60)

        store.close()
        clear_evaluators()

        return {
            "total_receipts": total,
            "agent_counts": agent_counts,
            "reports": reports,
            "fleet_statuses": fleet_statuses,
            "agent_statuses_30d": agent_statuses_30d,
            "agent_statuses_90d": agent_statuses_90d,
            "csv_path": csv_abs,
            "json_path": json_abs,
            "sample_receipts": sample_receipts,
            "verification_results": verification_results,
        }


def main():
    """Entry point."""
    run_demo()


if __name__ == "__main__":
    main()
