"""Tests for Block I: Receipt Triad verification and vertical templates.

9 tests total:
1-3: Triad hash verification (match, mismatch variants)
4:   CLI output format
5:   Gateway boundary note in CLI output
6:   v1 receipt without triad still verifies
7-8: Vertical template validation (financial, healthcare)
"""

import hashlib
import json

import pytest

from sanna.verify import (
    TriadVerification,
    verify_receipt_triad,
)


# =============================================================================
# HELPERS
# =============================================================================

def _make_receipt_with_triad(
    tool_name: str = "notion_update-page",
    args: dict | None = None,
    justification: str | None = None,
    tamper_input: bool = False,
    tamper_reasoning: bool = False,
    tamper_action: bool = False,
) -> dict:
    """Build a minimal receipt dict with a v2 Receipt Triad."""
    from sanna.gateway.receipt_v2 import (
        compute_receipt_triad,
        receipt_triad_to_dict,
    )

    if args is None:
        args = {"page_id": "abc123", "title": "Test Page"}

    triad = compute_receipt_triad(tool_name, args, justification)
    triad_dict = receipt_triad_to_dict(triad)

    if tamper_input:
        triad_dict["input_hash"] = "0" * 64
    if tamper_reasoning:
        triad_dict["reasoning_hash"] = "0" * 64
    if tamper_action:
        triad_dict["action_hash"] = "0" * 64

    # Build the args JSON for inputs.context (what the gateway stores)
    args_json = json.dumps(args, sort_keys=True)

    receipt = {
        "spec_version": "1.0",
        "tool_version": "0.13.0",
        "checks_version": "5",
        "receipt_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "receipt_fingerprint": "b" * 16,
        "full_fingerprint": "b" * 64,
        "correlation_id": "gw-test123",
        "timestamp": "2026-02-14T18:00:00+00:00",
        "inputs": {"context": args_json, "query": tool_name},
        "outputs": {"output": "OK"},
        "context_hash": "c" * 64,
        "output_hash": "d" * 64,
        "status": "PASS",
        "checks_passed": 0,
        "checks_failed": 0,
        "checks": [],
        "extensions": {
            "com.sanna.gateway": {
                "receipt_version": "2.0",
                "receipt_triad": triad_dict,
                "action": {
                    "tool": tool_name,
                    "args_hash": "e" * 16,
                    "justification_stripped": justification is not None,
                },
                "enforcement": {
                    "level": "can_execute",
                    "constitution_version": "0.1.0",
                    "constitution_hash": "",
                },
            },
        },
    }
    return receipt


# =============================================================================
# 1-3: TRIAD HASH VERIFICATION
# =============================================================================

class TestTriadVerification:
    """Receipt Triad hash re-computation and comparison."""

    def test_verify_triad_all_match(self):
        """Valid receipt with all hashes matching passes verification."""
        receipt = _make_receipt_with_triad(
            tool_name="notion_update-page",
            args={"page_id": "abc123", "title": "Test"},
        )

        result = verify_receipt_triad(receipt)

        assert result.present is True
        assert result.input_hash_valid is True
        assert result.reasoning_hash_valid is True
        assert result.action_hash_valid is True
        assert result.gateway_boundary_consistent is True
        assert result.input_hash_match is True
        assert len(result.errors) == 0

    def test_verify_triad_input_mismatch(self):
        """Tampered inputs cause input_hash mismatch."""
        receipt = _make_receipt_with_triad(tamper_input=True)

        result = verify_receipt_triad(receipt)

        assert result.present is True
        # input_hash format is still valid (it's a proper 64-hex string)
        assert result.input_hash_valid is True
        # But it doesn't match re-computed
        assert result.input_hash_match is False
        # And gateway boundary is broken (input != action)
        assert result.gateway_boundary_consistent is False
        assert len(result.errors) >= 1

    def test_verify_triad_reasoning_mismatch(self):
        """Tampered reasoning hash is detected as format-valid but
        breaks gateway boundary constraint when action is also tampered."""
        receipt = _make_receipt_with_triad(tamper_reasoning=True)

        result = verify_receipt_triad(receipt)

        assert result.present is True
        # Reasoning hash has valid format (bare 64-hex 000...)
        assert result.reasoning_hash_valid is True
        # Gateway boundary still holds (input == action, both untampered)
        assert result.gateway_boundary_consistent is True
        # No format errors — reasoning can't be re-computed (justification stripped)
        # so only format validation applies
        assert all("reasoning" not in e for e in result.errors)

    def test_verify_triad_action_mismatch(self):
        """Tampered action hash breaks gateway boundary constraint."""
        receipt = _make_receipt_with_triad(tamper_action=True)

        result = verify_receipt_triad(receipt)

        assert result.present is True
        assert result.action_hash_valid is True
        # Gateway boundary broken: input != action
        assert result.gateway_boundary_consistent is False
        assert any("gateway boundary" in e.lower() for e in result.errors)


# =============================================================================
# 4-5: CLI OUTPUT FORMAT
# =============================================================================

class TestCLIOutput:
    """Verify CLI output includes Receipt Triad section."""

    def test_verify_output_format(self):
        """CLI summary output contains 'RECEIPT TRIAD' section."""
        from sanna.cli import format_verify_summary
        from sanna.verify import VerificationResult

        receipt = _make_receipt_with_triad()
        result = VerificationResult(
            valid=True,
            exit_code=0,
            errors=[],
            warnings=[],
            computed_fingerprint="b" * 16,
            expected_fingerprint="b" * 16,
            computed_status="PASS",
            expected_status="PASS",
        )

        output = format_verify_summary(result, receipt)

        assert "RECEIPT TRIAD" in output
        assert "Input" in output
        assert "Reasoning" in output
        assert "Action" in output

    def test_verify_gateway_boundary_note(self):
        """CLI output shows gateway_boundary context note."""
        from sanna.cli import format_verify_summary
        from sanna.verify import VerificationResult

        receipt = _make_receipt_with_triad()
        result = VerificationResult(
            valid=True,
            exit_code=0,
            errors=[],
            warnings=[],
            computed_fingerprint="b" * 16,
            expected_fingerprint="b" * 16,
            computed_status="PASS",
            expected_status="PASS",
        )

        output = format_verify_summary(result, receipt)

        assert "gateway_boundary" in output
        assert "forwarded" in output.lower()


# =============================================================================
# 6: V1 RECEIPT FALLBACK
# =============================================================================

class TestV1ReceiptFallback:
    """v1 receipts without triad still verify normally."""

    def test_verify_v1_receipt_no_triad(self):
        """v1 receipt without triad hashes returns present=False, no errors."""
        receipt = {
            "spec_version": "1.0",
            "receipt_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "extensions": {
                "gateway": {
                    "server_name": "notion",
                    "tool_name": "search",
                },
            },
        }

        result = verify_receipt_triad(receipt)

        assert result.present is False
        assert len(result.errors) == 0
        assert len(result.warnings) == 0


# =============================================================================
# 7-8: VERTICAL TEMPLATE VALIDATION
# =============================================================================

class TestVerticalTemplates:
    """Financial and healthcare templates are valid constitutions."""

    def test_financial_template_valid(self, tmp_path):
        """financial_analyst.yaml is a valid constitution."""
        from sanna.constitution import load_constitution
        import importlib.resources

        # Load template from package
        ref = importlib.resources.files("sanna.templates").joinpath(
            "financial_analyst.yaml",
        )
        template_text = ref.read_text()

        # Write to temp path and load
        template_path = tmp_path / "financial_analyst.yaml"
        template_path.write_text(template_text)

        constitution = load_constitution(str(template_path))

        assert constitution.identity.agent_name == "financial-analyst-agent"
        assert constitution.identity.domain == "financial-services"
        assert len(constitution.boundaries) >= 4
        assert len(constitution.invariants) >= 5
        assert constitution.authority_boundaries is not None
        assert "execute_trade" in constitution.authority_boundaries.cannot_execute

    def test_healthcare_template_valid(self, tmp_path):
        """healthcare_triage.yaml is a valid constitution."""
        from sanna.constitution import load_constitution
        import importlib.resources

        ref = importlib.resources.files("sanna.templates").joinpath(
            "healthcare_triage.yaml",
        )
        template_text = ref.read_text()

        template_path = tmp_path / "healthcare_triage.yaml"
        template_path.write_text(template_text)

        constitution = load_constitution(str(template_path))

        assert constitution.identity.agent_name == "healthcare-triage-agent"
        assert constitution.identity.domain == "healthcare"
        assert len(constitution.boundaries) >= 4
        assert len(constitution.invariants) >= 5
        assert constitution.authority_boundaries is not None
        assert "prescribe_medication" in constitution.authority_boundaries.cannot_execute
