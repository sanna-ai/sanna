"""
Tests for authority boundary enforcement integration with receipts.

Covers:
- Receipt generation with authority_decisions, escalation_events, source_trust_evaluations
- Fingerprint integrity (new sections change fingerprint, tampering detected)
- Verifier backward compatibility (old receipts without new sections still verify)
- Schema validation of new receipt sections
- Golden receipt with authority data verifies correctly
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sanna.middleware import (
    _build_trace_data,
    _generate_constitution_receipt,
    _generate_no_invariants_receipt,
)
from sanna.verify import verify_receipt, verify_fingerprint, load_schema
from sanna.enforcement import configure_checks
from sanna.constitution import load_constitution, constitution_to_receipt_ref

# =============================================================================
# PATHS
# =============================================================================

CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"
ALL_WARN_CONST = str(CONSTITUTIONS_DIR / "all_warn.yaml")
WITH_AUTHORITY_CONST = str(CONSTITUTIONS_DIR / "with_authority.yaml")
GOLDEN_DIR = Path(__file__).parent.parent / "golden" / "receipts"


# =============================================================================
# HELPERS
# =============================================================================

def _make_trace_data(correlation_id: str = "test-trace-001") -> dict:
    return _build_trace_data(
        correlation_id=correlation_id,
        query="What is the capital of France?",
        context="France is a country in Europe. Its capital is Paris.",
        output="The capital of France is Paris.",
    )


def _make_authority_decisions() -> list:
    return [
        {
            "action": "query_database",
            "params": {"table": "users"},
            "decision": "allow",
            "reason": "Action matches can_execute rule: 'query_database'",
            "boundary_type": "can_execute",
            "escalation_target": None,
            "timestamp": "2026-01-15T10:00:00+00:00",
        }
    ]


def _make_escalation_events() -> list:
    return [
        {
            "action": "refund_customer",
            "condition": "refund amount exceeds threshold",
            "target_type": "log",
            "success": True,
            "details": {"timestamp": "2026-01-15T10:00:00+00:00", "type": "escalation"},
            "timestamp": "2026-01-15T10:00:01+00:00",
        }
    ]


def _make_source_trust_evaluations() -> list:
    return [
        {
            "source_name": "customer_db",
            "trust_tier": "tier_1",
            "evaluated_at": "2026-01-15T10:00:00+00:00",
        }
    ]


def _generate_receipt_with_authority(
    authority_decisions=None,
    escalation_events=None,
    source_trust_evaluations=None,
) -> dict:
    """Generate a constitution-driven receipt with authority sections."""
    constitution = load_constitution(WITH_AUTHORITY_CONST, validate=True)
    constitution_ref = constitution_to_receipt_ref(constitution)
    check_configs, custom_records = configure_checks(constitution)
    trace_data = _make_trace_data()

    return _generate_constitution_receipt(
        trace_data,
        check_configs=check_configs,
        custom_records=custom_records,
        constitution_ref=constitution_ref,
        constitution_version=constitution.schema_version,
        authority_decisions=authority_decisions,
        escalation_events=escalation_events,
        source_trust_evaluations=source_trust_evaluations,
    )


# =============================================================================
# 1. Receipt generation with authority sections
# =============================================================================

class TestReceiptWithAuthoritySections:
    def test_receipt_includes_authority_decisions(self):
        decisions = _make_authority_decisions()
        receipt = _generate_receipt_with_authority(authority_decisions=decisions)

        assert "authority_decisions" in receipt
        assert receipt["authority_decisions"] == decisions
        assert len(receipt["authority_decisions"]) == 1

    def test_receipt_includes_escalation_events(self):
        events = _make_escalation_events()
        receipt = _generate_receipt_with_authority(escalation_events=events)

        assert "escalation_events" in receipt
        assert receipt["escalation_events"] == events

    def test_receipt_includes_source_trust_evaluations(self):
        evals = _make_source_trust_evaluations()
        receipt = _generate_receipt_with_authority(source_trust_evaluations=evals)

        assert "source_trust_evaluations" in receipt
        assert receipt["source_trust_evaluations"] == evals

    def test_receipt_includes_all_three_sections(self):
        receipt = _generate_receipt_with_authority(
            authority_decisions=_make_authority_decisions(),
            escalation_events=_make_escalation_events(),
            source_trust_evaluations=_make_source_trust_evaluations(),
        )

        assert "authority_decisions" in receipt
        assert "escalation_events" in receipt
        assert "source_trust_evaluations" in receipt

    def test_receipt_omits_sections_when_none(self):
        receipt = _generate_receipt_with_authority()

        assert "authority_decisions" not in receipt
        assert "escalation_events" not in receipt
        assert "source_trust_evaluations" not in receipt

    def test_receipt_omits_sections_when_empty_list(self):
        receipt = _generate_receipt_with_authority(
            authority_decisions=[],
            escalation_events=[],
            source_trust_evaluations=[],
        )

        # Empty lists are falsy — sections should be omitted
        assert "authority_decisions" not in receipt
        assert "escalation_events" not in receipt
        assert "source_trust_evaluations" not in receipt

    def test_receipt_with_halt_authority_decision(self):
        decisions = [
            {
                "action": "delete_database",
                "params": {},
                "decision": "halt",
                "reason": "Action matches cannot_execute rule: 'delete_database'",
                "boundary_type": "cannot_execute",
                "escalation_target": None,
                "timestamp": "2026-01-15T10:00:00+00:00",
            }
        ]
        receipt = _generate_receipt_with_authority(authority_decisions=decisions)

        assert receipt["authority_decisions"][0]["decision"] == "halt"
        assert receipt["authority_decisions"][0]["boundary_type"] == "cannot_execute"

    def test_receipt_with_escalate_decision_and_target(self):
        decisions = [
            {
                "action": "refund_customer",
                "params": {"amount": 5000},
                "decision": "escalate",
                "reason": "Action matches escalation condition",
                "boundary_type": "must_escalate",
                "escalation_target": {"type": "log"},
                "timestamp": "2026-01-15T10:00:00+00:00",
            }
        ]
        receipt = _generate_receipt_with_authority(authority_decisions=decisions)

        assert receipt["authority_decisions"][0]["escalation_target"]["type"] == "log"


# =============================================================================
# 2. Schema validation of new sections
# =============================================================================

class TestSchemaValidation:
    def test_receipt_with_authority_decisions_validates(self):
        decisions = _make_authority_decisions()
        receipt = _generate_receipt_with_authority(authority_decisions=decisions)
        schema = load_schema()
        result = verify_receipt(receipt, schema)

        assert result.valid, f"Schema validation failed: {result.errors}"

    def test_receipt_with_all_sections_validates(self):
        receipt = _generate_receipt_with_authority(
            authority_decisions=_make_authority_decisions(),
            escalation_events=_make_escalation_events(),
            source_trust_evaluations=_make_source_trust_evaluations(),
        )
        schema = load_schema()
        result = verify_receipt(receipt, schema)

        assert result.valid, f"Schema validation failed: {result.errors}"

    def test_receipt_without_new_sections_validates(self):
        receipt = _generate_receipt_with_authority()
        schema = load_schema()
        result = verify_receipt(receipt, schema)

        assert result.valid, f"Schema validation failed: {result.errors}"

    def test_authority_decision_with_invalid_decision_fails_schema(self):
        decisions = [{
            "action": "test",
            "params": {},
            "decision": "invalid_decision",
            "reason": "test",
            "boundary_type": "cannot_execute",
            "escalation_target": None,
            "timestamp": "2026-01-15T10:00:00+00:00",
        }]
        receipt = _generate_receipt_with_authority(authority_decisions=decisions)
        schema = load_schema()
        result = verify_receipt(receipt, schema)

        assert not result.valid
        assert result.exit_code == 2

    def test_escalation_event_with_invalid_target_type_fails_schema(self):
        events = [{
            "action": "test",
            "condition": "test condition",
            "target_type": "invalid_type",
            "success": True,
            "details": None,
            "timestamp": "2026-01-15T10:00:00+00:00",
        }]
        receipt = _generate_receipt_with_authority(escalation_events=events)
        schema = load_schema()
        result = verify_receipt(receipt, schema)

        assert not result.valid
        assert result.exit_code == 2

    def test_source_trust_with_invalid_tier_fails_schema(self):
        evals = [{
            "source_name": "test",
            "trust_tier": "invalid_tier",
            "evaluated_at": "2026-01-15T10:00:00+00:00",
        }]
        receipt = _generate_receipt_with_authority(source_trust_evaluations=evals)
        schema = load_schema()
        result = verify_receipt(receipt, schema)

        assert not result.valid
        assert result.exit_code == 2


# =============================================================================
# 3. Fingerprint integrity
# =============================================================================

class TestFingerprintIntegrity:
    def test_authority_decisions_change_fingerprint(self):
        receipt_without = _generate_receipt_with_authority()
        receipt_with = _generate_receipt_with_authority(
            authority_decisions=_make_authority_decisions(),
        )

        assert receipt_without["receipt_fingerprint"] != receipt_with["receipt_fingerprint"]

    def test_escalation_events_change_fingerprint(self):
        receipt_without = _generate_receipt_with_authority()
        receipt_with = _generate_receipt_with_authority(
            escalation_events=_make_escalation_events(),
        )

        assert receipt_without["receipt_fingerprint"] != receipt_with["receipt_fingerprint"]

    def test_source_trust_evals_change_fingerprint(self):
        receipt_without = _generate_receipt_with_authority()
        receipt_with = _generate_receipt_with_authority(
            source_trust_evaluations=_make_source_trust_evaluations(),
        )

        assert receipt_without["receipt_fingerprint"] != receipt_with["receipt_fingerprint"]

    def test_tampered_authority_decisions_detected(self):
        receipt = _generate_receipt_with_authority(
            authority_decisions=_make_authority_decisions(),
        )

        # Tamper with authority decisions
        receipt["authority_decisions"][0]["decision"] = "halt"

        match, computed, expected = verify_fingerprint(receipt)
        assert not match

    def test_tampered_escalation_events_detected(self):
        receipt = _generate_receipt_with_authority(
            escalation_events=_make_escalation_events(),
        )

        receipt["escalation_events"][0]["success"] = False

        match, computed, expected = verify_fingerprint(receipt)
        assert not match

    def test_tampered_source_trust_detected(self):
        receipt = _generate_receipt_with_authority(
            source_trust_evaluations=_make_source_trust_evaluations(),
        )

        receipt["source_trust_evaluations"][0]["trust_tier"] = "prohibited"

        match, computed, expected = verify_fingerprint(receipt)
        assert not match

    def test_untampered_receipt_with_authority_verifies(self):
        receipt = _generate_receipt_with_authority(
            authority_decisions=_make_authority_decisions(),
            escalation_events=_make_escalation_events(),
            source_trust_evaluations=_make_source_trust_evaluations(),
        )

        match, computed, expected = verify_fingerprint(receipt)
        assert match

    def test_different_authority_data_produces_different_fingerprint(self):
        decisions_a = [{
            "action": "query_database",
            "params": {},
            "decision": "allow",
            "reason": "Allowed",
            "boundary_type": "can_execute",
            "escalation_target": None,
            "timestamp": "2026-01-15T10:00:00+00:00",
        }]
        decisions_b = [{
            "action": "delete_database",
            "params": {},
            "decision": "halt",
            "reason": "Forbidden",
            "boundary_type": "cannot_execute",
            "escalation_target": None,
            "timestamp": "2026-01-15T10:00:00+00:00",
        }]

        receipt_a = _generate_receipt_with_authority(authority_decisions=decisions_a)
        receipt_b = _generate_receipt_with_authority(authority_decisions=decisions_b)

        assert receipt_a["receipt_fingerprint"] != receipt_b["receipt_fingerprint"]


# =============================================================================
# 4. Verifier backward compatibility
# =============================================================================

class TestVerifierBackwardCompat:
    def test_golden_receipt_verifies(self):
        """Golden receipt passes full schema validation."""
        path = GOLDEN_DIR / "002_pass_simple_qa.json"
        receipt = json.loads(path.read_text())
        schema = load_schema()
        result = verify_receipt(receipt, schema)

        assert result.valid, f"Golden receipt failed: {result.errors}"

    def test_receipt_without_new_sections_verifies(self):
        """A receipt generated without authority sections should verify."""
        receipt = _generate_receipt_with_authority()
        schema = load_schema()
        result = verify_receipt(receipt, schema)

        assert result.valid, f"Receipt without new sections failed: {result.errors}"

    def test_all_golden_receipts_verify(self):
        """All golden receipts must pass full schema validation."""
        schema = load_schema()
        for path in sorted(GOLDEN_DIR.glob("*.json")):
            if "tampered" in path.name:
                continue
            receipt = json.loads(path.read_text())
            result = verify_receipt(receipt, schema)
            assert result.valid, f"Golden receipt {path.name} failed: {result.errors}"


# =============================================================================
# 5. Full verification pipeline with authority sections
# =============================================================================

class TestFullVerificationWithAuthority:
    def test_receipt_with_authority_passes_full_verification(self):
        receipt = _generate_receipt_with_authority(
            authority_decisions=_make_authority_decisions(),
            escalation_events=_make_escalation_events(),
            source_trust_evaluations=_make_source_trust_evaluations(),
        )
        schema = load_schema()
        result = verify_receipt(receipt, schema)

        assert result.valid, f"Full verification failed: {result.errors}"
        assert result.exit_code == 0

    def test_receipt_with_only_authority_decisions_passes(self):
        receipt = _generate_receipt_with_authority(
            authority_decisions=_make_authority_decisions(),
        )
        schema = load_schema()
        result = verify_receipt(receipt, schema)

        assert result.valid, f"Verification failed: {result.errors}"

    def test_receipt_with_only_escalation_events_passes(self):
        receipt = _generate_receipt_with_authority(
            escalation_events=_make_escalation_events(),
        )
        schema = load_schema()
        result = verify_receipt(receipt, schema)

        assert result.valid, f"Verification failed: {result.errors}"

    def test_receipt_with_only_source_trust_passes(self):
        receipt = _generate_receipt_with_authority(
            source_trust_evaluations=_make_source_trust_evaluations(),
        )
        schema = load_schema()
        result = verify_receipt(receipt, schema)

        assert result.valid, f"Verification failed: {result.errors}"

    def test_tampered_authority_decision_fails_verification(self):
        receipt = _generate_receipt_with_authority(
            authority_decisions=_make_authority_decisions(),
        )
        receipt["authority_decisions"][0]["decision"] = "halt"

        schema = load_schema()
        result = verify_receipt(receipt, schema)

        assert not result.valid
        assert result.exit_code == 3  # fingerprint mismatch

    def test_added_authority_section_to_existing_receipt_fails(self):
        """Adding authority sections to a receipt that had none should fail."""
        receipt = _generate_receipt_with_authority()
        # Inject new section after generation — fingerprint won't match
        receipt["authority_decisions"] = _make_authority_decisions()

        schema = load_schema()
        result = verify_receipt(receipt, schema)

        assert not result.valid
        assert result.exit_code == 3

    def test_removed_authority_section_fails_verification(self):
        """Removing authority sections that were in the fingerprint should fail."""
        receipt = _generate_receipt_with_authority(
            authority_decisions=_make_authority_decisions(),
        )
        del receipt["authority_decisions"]

        schema = load_schema()
        result = verify_receipt(receipt, schema)

        assert not result.valid
        assert result.exit_code == 3


# =============================================================================
# 6. Multiple authority decisions in one receipt
# =============================================================================

class TestMultipleDecisions:
    def test_receipt_with_multiple_authority_decisions(self):
        decisions = [
            {
                "action": "query_database",
                "params": {"table": "users"},
                "decision": "allow",
                "reason": "Explicitly allowed",
                "boundary_type": "can_execute",
                "escalation_target": None,
                "timestamp": "2026-01-15T10:00:00+00:00",
            },
            {
                "action": "delete_database",
                "params": {},
                "decision": "halt",
                "reason": "Forbidden by authority boundary",
                "boundary_type": "cannot_execute",
                "escalation_target": None,
                "timestamp": "2026-01-15T10:00:01+00:00",
            },
        ]
        receipt = _generate_receipt_with_authority(authority_decisions=decisions)
        schema = load_schema()
        result = verify_receipt(receipt, schema)

        assert result.valid, f"Multi-decision receipt failed: {result.errors}"
        assert len(receipt["authority_decisions"]) == 2

    def test_receipt_with_multiple_escalation_events(self):
        events = [
            {
                "action": "refund_customer",
                "condition": "refund amount exceeds threshold",
                "target_type": "log",
                "success": True,
                "details": None,
                "timestamp": "2026-01-15T10:00:00+00:00",
            },
            {
                "action": "complaint_review",
                "condition": "customer complaint escalation",
                "target_type": "callback",
                "success": True,
                "details": {"callback_result": "approved"},
                "timestamp": "2026-01-15T10:00:01+00:00",
            },
        ]
        receipt = _generate_receipt_with_authority(escalation_events=events)
        schema = load_schema()
        result = verify_receipt(receipt, schema)

        assert result.valid, f"Multi-event receipt failed: {result.errors}"
        assert len(receipt["escalation_events"]) == 2
