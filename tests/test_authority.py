"""
Sanna authority boundary enforcement test suite.

Tests cover: cannot_execute matching, must_escalate condition matching,
can_execute allowlisting, evaluation order, backward compatibility,
escalation execution (log/webhook/callback), and callback registry.
"""

import importlib.util
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sanna.constitution import (
    Constitution,
    AgentIdentity,
    Provenance,
    Boundary,
    TrustTiers,
    AuthorityBoundaries,
    EscalationRule,
    EscalationTargetConfig,
    load_constitution,
)
from sanna.enforcement.authority import (
    AuthorityDecision,
    evaluate_authority,
    _matches_action,
    _matches_condition,
    _build_action_context,
)
from sanna.enforcement.escalation import (
    EscalationTarget,
    EscalationResult,
    execute_escalation,
    register_escalation_callback,
    clear_escalation_callbacks,
    get_escalation_callback,
)


# =============================================================================
# HELPERS
# =============================================================================

CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"


def _make_constitution(
    authority_boundaries: AuthorityBoundaries | None = None,
) -> Constitution:
    """Build a minimal Constitution with optional authority boundaries."""
    return Constitution(
        schema_version="1.0.0",
        identity=AgentIdentity(agent_name="test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="tester@test.com",
            approved_by=["approver@test.com"],
            approval_date="2026-01-01",
            approval_method="test",
        ),
        boundaries=[Boundary(id="B001", description="Test", category="scope", severity="medium")],
        authority_boundaries=authority_boundaries,
    )


def _make_ab(
    cannot_execute: list[str] | None = None,
    must_escalate: list[EscalationRule] | None = None,
    can_execute: list[str] | None = None,
    default_escalation: str = "log",
) -> AuthorityBoundaries:
    """Build AuthorityBoundaries with defaults."""
    return AuthorityBoundaries(
        cannot_execute=cannot_execute or [],
        must_escalate=must_escalate or [],
        can_execute=can_execute or [],
        default_escalation=default_escalation,
    )


# =============================================================================
# 1. cannot_execute — halt decisions
# =============================================================================

class TestCannotExecute:
    def test_exact_match_halts(self):
        ab = _make_ab(cannot_execute=["send external communications"])
        const = _make_constitution(ab)
        decision = evaluate_authority("send external communications", {}, const)

        assert decision.decision == "halt"
        assert decision.boundary_type == "cannot_execute"

    def test_substring_match_action_contains_pattern(self):
        """Action is a longer string containing the forbidden pattern."""
        ab = _make_ab(cannot_execute=["modify billing"])
        const = _make_constitution(ab)
        decision = evaluate_authority("modify billing data for customer", {}, const)

        assert decision.decision == "halt"
        assert decision.boundary_type == "cannot_execute"

    def test_substring_match_pattern_contains_action(self):
        """Forbidden pattern is a longer string containing the action."""
        ab = _make_ab(cannot_execute=["send external communications to partners"])
        const = _make_constitution(ab)
        decision = evaluate_authority("send external communications", {}, const)

        assert decision.decision == "halt"
        assert decision.boundary_type == "cannot_execute"

    def test_case_insensitive(self):
        ab = _make_ab(cannot_execute=["Delete User Accounts"])
        const = _make_constitution(ab)
        decision = evaluate_authority("delete user accounts", {}, const)

        assert decision.decision == "halt"

    def test_case_insensitive_reverse(self):
        ab = _make_ab(cannot_execute=["delete user accounts"])
        const = _make_constitution(ab)
        decision = evaluate_authority("DELETE USER ACCOUNTS", {}, const)

        assert decision.decision == "halt"

    def test_multiple_entries_first_match_used(self):
        ab = _make_ab(cannot_execute=[
            "send external communications",
            "modify billing data",
            "delete user accounts",
        ])
        const = _make_constitution(ab)
        decision = evaluate_authority("send external communications", {}, const)

        assert decision.decision == "halt"
        assert "send external communications" in decision.reason

    def test_no_match_does_not_halt(self):
        ab = _make_ab(cannot_execute=["delete records"])
        const = _make_constitution(ab)
        decision = evaluate_authority("query database", {}, const)

        assert decision.decision != "halt"

    def test_whitespace_tolerance(self):
        ab = _make_ab(cannot_execute=["  send external  "])
        const = _make_constitution(ab)
        decision = evaluate_authority("send external communications", {}, const)

        assert decision.decision == "halt"

    def test_partial_word_substring(self):
        """'billing' appears as substring in 'modify billing data'."""
        ab = _make_ab(cannot_execute=["billing"])
        const = _make_constitution(ab)
        decision = evaluate_authority("modify billing data", {}, const)

        assert decision.decision == "halt"


# =============================================================================
# 2. must_escalate — escalation decisions
# =============================================================================

class TestMustEscalate:
    def test_condition_matches_action_name(self):
        ab = _make_ab(must_escalate=[
            EscalationRule(condition="pii data"),
        ])
        const = _make_constitution(ab)
        decision = evaluate_authority("process_pii_data", {}, const)

        assert decision.decision == "escalate"
        assert decision.boundary_type == "must_escalate"

    def test_condition_matches_param_value(self):
        ab = _make_ab(must_escalate=[
            EscalationRule(condition="pii records"),
        ])
        const = _make_constitution(ab)
        decision = evaluate_authority("process_data", {"data_type": "PII records"}, const)

        assert decision.decision == "escalate"

    def test_condition_matches_param_key(self):
        ab = _make_ab(must_escalate=[
            EscalationRule(condition="confidence threshold"),
        ])
        const = _make_constitution(ab)
        decision = evaluate_authority("generate_response", {"confidence": 0.3, "threshold": 0.5}, const)

        assert decision.decision == "escalate"

    def test_webhook_target_returned(self):
        ab = _make_ab(must_escalate=[
            EscalationRule(
                condition="pii",
                target=EscalationTargetConfig(type="webhook", url="https://hooks.example.com/alert"),
            ),
        ])
        const = _make_constitution(ab)
        decision = evaluate_authority("handle_pii_request", {}, const)

        assert decision.decision == "escalate"
        assert decision.escalation_target is not None
        assert decision.escalation_target.type == "webhook"
        assert decision.escalation_target.url == "https://hooks.example.com/alert"

    def test_callback_target_returned(self):
        handler_fn = MagicMock()
        register_escalation_callback("my_handler", handler_fn)
        try:
            ab = _make_ab(must_escalate=[
                EscalationRule(
                    condition="pii",
                    target=EscalationTargetConfig(type="callback", handler="my_handler"),
                ),
            ])
            const = _make_constitution(ab)
            decision = evaluate_authority("handle_pii_request", {}, const)

            assert decision.escalation_target is not None
            assert decision.escalation_target.type == "callback"
            assert decision.escalation_target.handler is handler_fn
        finally:
            clear_escalation_callbacks()

    def test_log_target_returned(self):
        ab = _make_ab(must_escalate=[
            EscalationRule(
                condition="pii",
                target=EscalationTargetConfig(type="log"),
            ),
        ])
        const = _make_constitution(ab)
        decision = evaluate_authority("handle_pii_request", {}, const)

        assert decision.escalation_target.type == "log"

    def test_missing_target_uses_default(self):
        ab = _make_ab(
            must_escalate=[EscalationRule(condition="pii")],
            default_escalation="log",
        )
        const = _make_constitution(ab)
        decision = evaluate_authority("handle_pii_request", {}, const)

        assert decision.decision == "escalate"
        assert decision.escalation_target.type == "log"

    def test_missing_target_uses_custom_default(self):
        ab = _make_ab(
            must_escalate=[EscalationRule(condition="pii")],
            default_escalation="webhook",
        )
        const = _make_constitution(ab)
        decision = evaluate_authority("handle_pii_request", {}, const)

        assert decision.escalation_target.type == "webhook"

    def test_first_matching_condition_wins(self):
        ab = _make_ab(must_escalate=[
            EscalationRule(
                condition="pii",
                target=EscalationTargetConfig(type="webhook", url="https://first.example.com"),
            ),
            EscalationRule(
                condition="pii data",
                target=EscalationTargetConfig(type="log"),
            ),
        ])
        const = _make_constitution(ab)
        decision = evaluate_authority("process_pii_data", {}, const)

        assert decision.escalation_target.type == "webhook"
        assert "pii" in decision.reason

    def test_no_condition_match(self):
        ab = _make_ab(must_escalate=[
            EscalationRule(condition="pii"),
        ])
        const = _make_constitution(ab)
        decision = evaluate_authority("query_public_database", {}, const)

        assert decision.decision != "escalate"


# =============================================================================
# 3. can_execute — explicit allow
# =============================================================================

class TestCanExecute:
    def test_explicit_allow(self):
        ab = _make_ab(can_execute=["query knowledge base"])
        const = _make_constitution(ab)
        decision = evaluate_authority("query knowledge base", {}, const)

        assert decision.decision == "allow"
        assert decision.boundary_type == "can_execute"

    def test_substring_allow(self):
        ab = _make_ab(can_execute=["create support tickets"])
        const = _make_constitution(ab)
        decision = evaluate_authority("create support tickets for customer", {}, const)

        assert decision.decision == "allow"
        assert decision.boundary_type == "can_execute"

    def test_case_insensitive_allow(self):
        ab = _make_ab(can_execute=["Query Knowledge Base"])
        const = _make_constitution(ab)
        decision = evaluate_authority("query knowledge base", {}, const)

        assert decision.decision == "allow"
        assert decision.boundary_type == "can_execute"

    def test_not_in_can_execute_goes_to_default(self):
        ab = _make_ab(can_execute=["query knowledge base"])
        const = _make_constitution(ab)
        decision = evaluate_authority("send email", {}, const)

        assert decision.decision == "allow"
        assert decision.boundary_type == "uncategorized"


# =============================================================================
# 4. Evaluation order
# =============================================================================

class TestEvaluationOrder:
    def test_cannot_execute_before_must_escalate(self):
        """If action matches both cannot_execute and must_escalate, halt wins."""
        ab = _make_ab(
            cannot_execute=["send external communications"],
            must_escalate=[EscalationRule(condition="send external")],
        )
        const = _make_constitution(ab)
        decision = evaluate_authority("send external communications", {}, const)

        assert decision.decision == "halt"
        assert decision.boundary_type == "cannot_execute"

    def test_must_escalate_before_can_execute(self):
        """If action matches both must_escalate and can_execute, escalate wins."""
        ab = _make_ab(
            must_escalate=[EscalationRule(condition="query sensitive")],
            can_execute=["query sensitive database"],
        )
        const = _make_constitution(ab)
        decision = evaluate_authority("query sensitive database", {}, const)

        assert decision.decision == "escalate"
        assert decision.boundary_type == "must_escalate"

    def test_cannot_execute_before_can_execute(self):
        """If action matches both cannot_execute and can_execute, halt wins."""
        ab = _make_ab(
            cannot_execute=["delete records"],
            can_execute=["delete records"],
        )
        const = _make_constitution(ab)
        decision = evaluate_authority("delete records", {}, const)

        assert decision.decision == "halt"
        assert decision.boundary_type == "cannot_execute"

    def test_full_chain_priority(self):
        """Action matches all three tiers — cannot_execute wins."""
        ab = _make_ab(
            cannot_execute=["dangerous action"],
            must_escalate=[EscalationRule(condition="dangerous")],
            can_execute=["dangerous action"],
        )
        const = _make_constitution(ab)
        decision = evaluate_authority("dangerous action", {}, const)

        assert decision.decision == "halt"


# =============================================================================
# 5. Backward compatibility
# =============================================================================

class TestBackwardCompatibility:
    def test_no_authority_boundaries_allows_all(self):
        const = _make_constitution(authority_boundaries=None)
        decision = evaluate_authority("any action", {"key": "value"}, const)

        assert decision.decision == "allow"
        assert decision.boundary_type == "uncategorized"

    def test_none_authority_boundaries_allows_all(self):
        const = _make_constitution()
        assert const.authority_boundaries is None

        decision = evaluate_authority("delete everything", {}, const)
        assert decision.decision == "allow"

    def test_empty_authority_boundaries_allows_all(self):
        ab = _make_ab()  # all lists empty
        const = _make_constitution(ab)
        decision = evaluate_authority("any action", {}, const)

        assert decision.decision == "allow"
        assert decision.boundary_type == "uncategorized"

    def test_old_constitution_loads_without_authority_boundaries(self):
        """Existing constitutions without authority_boundaries still load."""
        const = load_constitution(str(CONSTITUTIONS_DIR / "all_warn.yaml"))
        assert const.authority_boundaries is None

        decision = evaluate_authority("any action", {}, const)
        assert decision.decision == "allow"

    def test_old_constitution_hash_unchanged(self):
        """Adding authority_boundaries field doesn't change hash of old constitutions."""
        from sanna.constitution import compute_constitution_hash

        const = load_constitution(str(CONSTITUTIONS_DIR / "all_warn.yaml"))
        computed = compute_constitution_hash(const)
        assert computed == const.policy_hash


# =============================================================================
# 6. Escalation execution — log
# =============================================================================

class TestEscalationLog:
    def test_log_escalation_succeeds(self):
        target = EscalationTarget(type="log")
        result = execute_escalation(target, {"action": "test", "reason": "test reason"})

        assert result.success is True
        assert result.target_type == "log"

    def test_log_escalation_returns_structured_entry(self):
        target = EscalationTarget(type="log")
        result = execute_escalation(target, {"action": "send_email", "reason": "PII detected"})

        assert "timestamp" in result.details
        assert result.details["type"] == "escalation"
        assert result.details["action"] == "send_email"
        assert result.details["reason"] == "PII detected"

    def test_unknown_type_falls_back_to_log(self):
        target = EscalationTarget(type="unknown_type")
        result = execute_escalation(target, {"action": "test"})

        assert result.success is True
        assert result.target_type == "log"


# =============================================================================
# 7. Escalation execution — webhook
# =============================================================================

@pytest.mark.skipif(
    not importlib.util.find_spec("httpx"),
    reason="httpx not installed",
)
class TestEscalationWebhook:
    def test_webhook_success(self):
        target = EscalationTarget(type="webhook", url="https://hooks.example.com/alert")

        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            result = execute_escalation(target, {"action": "test"})

        assert result.success is True
        assert result.target_type == "webhook"
        assert result.details["url"] == "https://hooks.example.com/alert"
        assert result.details["status_code"] == 200

    def test_webhook_no_url_falls_back_to_log(self):
        target = EscalationTarget(type="webhook", url=None)
        result = execute_escalation(target, {"action": "test"})

        assert result.success is True
        assert result.target_type == "log"

    def test_webhook_empty_url_falls_back_to_log(self):
        target = EscalationTarget(type="webhook", url="")
        result = execute_escalation(target, {"action": "test"})

        assert result.success is True
        assert result.target_type == "log"

    def test_webhook_failure_returns_error(self):
        target = EscalationTarget(type="webhook", url="https://hooks.example.com/alert")

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = ConnectionError("Connection refused")
            mock_client_cls.return_value = mock_client

            result = execute_escalation(target, {"action": "test"})

        assert result.success is False
        assert result.target_type == "webhook"
        assert "error" in result.details


# =============================================================================
# 8. Escalation execution — callback
# =============================================================================

class TestEscalationCallback:
    def test_callback_calls_handler(self):
        handler = MagicMock(return_value={"handled": True})
        target = EscalationTarget(type="callback", handler=handler)
        event = {"action": "test_action", "reason": "test reason"}

        result = execute_escalation(target, event)

        assert result.success is True
        assert result.target_type == "callback"
        handler.assert_called_once_with(event)
        assert result.details["callback_result"] == {"handled": True}

    def test_callback_no_handler_falls_back_to_log(self):
        target = EscalationTarget(type="callback", handler=None)
        result = execute_escalation(target, {"action": "test"})

        assert result.success is True
        assert result.target_type == "log"

    def test_callback_exception_returns_error(self):
        handler = MagicMock(side_effect=RuntimeError("handler crashed"))
        target = EscalationTarget(type="callback", handler=handler)

        result = execute_escalation(target, {"action": "test"})

        assert result.success is False
        assert result.target_type == "callback"
        assert "error" in result.details


# =============================================================================
# 9. Callback registry
# =============================================================================

class TestCallbackRegistry:
    def setup_method(self):
        clear_escalation_callbacks()

    def teardown_method(self):
        clear_escalation_callbacks()

    def test_register_and_retrieve(self):
        handler = lambda event: event
        register_escalation_callback("my_handler", handler)

        retrieved = get_escalation_callback("my_handler")
        assert retrieved is handler

    def test_clear_callbacks(self):
        register_escalation_callback("handler1", lambda e: e)
        register_escalation_callback("handler2", lambda e: e)
        clear_escalation_callbacks()

        assert get_escalation_callback("handler1") is None
        assert get_escalation_callback("handler2") is None

    def test_get_nonexistent_returns_none(self):
        result = get_escalation_callback("nonexistent")
        assert result is None

    def test_overwrite_callback(self):
        handler1 = lambda e: "first"
        handler2 = lambda e: "second"
        register_escalation_callback("my_handler", handler1)
        register_escalation_callback("my_handler", handler2)

        assert get_escalation_callback("my_handler") is handler2


# =============================================================================
# 10. AuthorityDecision dataclass
# =============================================================================

class TestAuthorityDecisionDataclass:
    def test_halt_decision_fields(self):
        d = AuthorityDecision(
            decision="halt",
            reason="Forbidden",
            boundary_type="cannot_execute",
        )
        assert d.decision == "halt"
        assert d.reason == "Forbidden"
        assert d.boundary_type == "cannot_execute"
        assert d.escalation_target is None

    def test_escalate_decision_has_target(self):
        target = EscalationTarget(type="webhook", url="https://example.com")
        d = AuthorityDecision(
            decision="escalate",
            reason="Needs review",
            boundary_type="must_escalate",
            escalation_target=target,
        )
        assert d.escalation_target is target
        assert d.escalation_target.url == "https://example.com"

    def test_allow_decision_no_target(self):
        d = AuthorityDecision(
            decision="allow",
            reason="Explicitly allowed",
            boundary_type="can_execute",
        )
        assert d.escalation_target is None


# =============================================================================
# 11. Matching helpers
# =============================================================================

class TestMatchingHelpers:
    def test_matches_action_exact(self):
        assert _matches_action("send email", "send email") is True

    def test_matches_action_pattern_in_action(self):
        assert _matches_action("billing", "modify billing data") is True

    def test_matches_action_action_in_pattern(self):
        assert _matches_action("modify billing data records", "modify billing data") is True

    def test_matches_action_no_match(self):
        assert _matches_action("delete records", "query database") is False

    def test_matches_condition_keyword_in_context(self):
        assert _matches_condition("pii data", "process_pii_data data_type PII") is True

    def test_matches_condition_no_match(self):
        assert _matches_condition("pii data", "query public database") is False

    def test_build_action_context_includes_keys_and_values(self):
        ctx = _build_action_context("process_data", {"type": "user", "count": 5})
        assert "process_data" in ctx
        assert "type" in ctx
        assert "user" in ctx
        assert "count" in ctx
        assert "5" in ctx


# =============================================================================
# 12. Edge cases
# =============================================================================

class TestEdgeCases:
    def test_empty_action_name_with_no_rules(self):
        ab = _make_ab()
        const = _make_constitution(ab)
        decision = evaluate_authority("", {}, const)

        assert decision.decision == "allow"
        assert decision.boundary_type == "uncategorized"

    def test_empty_action_name_matches_cannot_execute(self):
        """Empty string is a substring of any pattern, so it matches."""
        ab = _make_ab(cannot_execute=["delete records"])
        const = _make_constitution(ab)
        decision = evaluate_authority("", {}, const)

        assert decision.decision == "halt"

    def test_empty_params(self):
        ab = _make_ab(must_escalate=[EscalationRule(condition="pii")])
        const = _make_constitution(ab)
        decision = evaluate_authority("process_pii_data", {}, const)

        assert decision.decision == "escalate"

    def test_special_characters_in_action(self):
        ab = _make_ab(cannot_execute=["delete (all) records!"])
        const = _make_constitution(ab)
        decision = evaluate_authority("delete (all) records!", {}, const)

        assert decision.decision == "halt"

    def test_numeric_param_values_in_condition_matching(self):
        ab = _make_ab(must_escalate=[
            EscalationRule(condition="confidence threshold"),
        ])
        const = _make_constitution(ab)
        decision = evaluate_authority(
            "generate_response",
            {"confidence_score": 0.2, "threshold_value": 0.5},
            const,
        )

        assert decision.decision == "escalate"

    def test_very_long_cannot_execute_list(self):
        ab = _make_ab(cannot_execute=[f"action_{i}" for i in range(100)])
        const = _make_constitution(ab)
        decision = evaluate_authority("action_99", {}, const)

        assert decision.decision == "halt"

    def test_constitution_with_only_can_execute(self):
        ab = _make_ab(can_execute=["read database"])
        const = _make_constitution(ab)

        allowed = evaluate_authority("read database", {}, const)
        assert allowed.decision == "allow"
        assert allowed.boundary_type == "can_execute"

        unknown = evaluate_authority("write database", {}, const)
        assert unknown.decision == "allow"
        assert unknown.boundary_type == "uncategorized"


# =============================================================================
# 13. Constitution parsing with authority_boundaries
# =============================================================================

class TestConstitutionParsing:
    def test_parse_constitution_with_authority_boundaries(self):
        from sanna.constitution import parse_constitution

        data = {
            "sanna_constitution": "1.0.0",
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "test@test.com",
                "approved_by": ["approver@test.com"],
                "approval_date": "2026-01-01",
                "approval_method": "test",
            },
            "boundaries": [{"id": "B001", "description": "Test", "category": "scope", "severity": "medium"}],
            "authority_boundaries": {
                "cannot_execute": ["send external communications"],
                "must_escalate": [
                    {
                        "condition": "decisions involving PII",
                        "target": {"type": "webhook", "url": "https://hooks.example.com"},
                    },
                ],
                "can_execute": ["query knowledge base"],
            },
            "escalation_targets": {"default": "webhook"},
        }
        const = parse_constitution(data)

        assert const.authority_boundaries is not None
        assert const.authority_boundaries.cannot_execute == ["send external communications"]
        assert len(const.authority_boundaries.must_escalate) == 1
        assert const.authority_boundaries.must_escalate[0].condition == "decisions involving PII"
        assert const.authority_boundaries.must_escalate[0].target.type == "webhook"
        assert const.authority_boundaries.must_escalate[0].target.url == "https://hooks.example.com"
        assert const.authority_boundaries.can_execute == ["query knowledge base"]
        assert const.authority_boundaries.default_escalation == "webhook"

    def test_parse_constitution_without_authority_boundaries(self):
        from sanna.constitution import parse_constitution

        data = {
            "sanna_constitution": "1.0.0",
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "test@test.com",
                "approved_by": ["approver@test.com"],
                "approval_date": "2026-01-01",
                "approval_method": "test",
            },
            "boundaries": [{"id": "B001", "description": "Test", "category": "scope", "severity": "medium"}],
        }
        const = parse_constitution(data)
        assert const.authority_boundaries is None

    def test_parse_must_escalate_without_target(self):
        from sanna.constitution import parse_constitution

        data = {
            "sanna_constitution": "1.0.0",
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "test@test.com",
                "approved_by": ["approver@test.com"],
                "approval_date": "2026-01-01",
                "approval_method": "test",
            },
            "boundaries": [{"id": "B001", "description": "Test", "category": "scope", "severity": "medium"}],
            "authority_boundaries": {
                "must_escalate": [{"condition": "sensitive action"}],
            },
        }
        const = parse_constitution(data)
        assert const.authority_boundaries.must_escalate[0].target is None

    def test_constitution_to_dict_roundtrip(self):
        from sanna.constitution import constitution_to_dict, parse_constitution

        ab = AuthorityBoundaries(
            cannot_execute=["send email"],
            must_escalate=[
                EscalationRule(
                    condition="PII",
                    target=EscalationTargetConfig(type="webhook", url="https://example.com"),
                ),
            ],
            can_execute=["query db"],
            default_escalation="webhook",
        )
        const = _make_constitution(ab)
        data = constitution_to_dict(const)

        assert "authority_boundaries" in data
        assert data["authority_boundaries"]["cannot_execute"] == ["send email"]
        assert data["escalation_targets"]["default"] == "webhook"

        # Round-trip: parse back
        reparsed = parse_constitution(data)
        assert reparsed.authority_boundaries is not None
        assert reparsed.authority_boundaries.cannot_execute == ["send email"]
        assert reparsed.authority_boundaries.default_escalation == "webhook"

    def test_hash_includes_authority_boundaries(self):
        from sanna.constitution import compute_constitution_hash

        const_without = _make_constitution(authority_boundaries=None)
        const_with = _make_constitution(authority_boundaries=_make_ab(
            cannot_execute=["send email"],
        ))

        hash_without = compute_constitution_hash(const_without)
        hash_with = compute_constitution_hash(const_with)

        assert hash_without != hash_with

    def test_hash_stable_for_same_authority_boundaries(self):
        from sanna.constitution import compute_constitution_hash

        ab = _make_ab(cannot_execute=["send email", "delete records"])
        const1 = _make_constitution(ab)
        const2 = _make_constitution(ab)

        assert compute_constitution_hash(const1) == compute_constitution_hash(const2)
