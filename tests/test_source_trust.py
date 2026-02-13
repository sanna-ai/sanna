"""
Tests for C1 source-aware context evaluation and trusted source tiers.

Covers:
- C1 backward compatibility (plain string context → v0.6.x behavior)
- C1 with tier_1 sources (full trust, contradiction = fail)
- C1 with tier_2 sources (evidence, contradiction = fail + verification note)
- C1 with tier_3 sources only (reference only, contradiction = pass)
- C1 with untrusted sources (excluded from checking)
- C1 with mixed tiers (correct per-source evaluation)
- Constitution trusted_sources parsing and hashing
- Middleware structured context integration
- No trusted_sources → all sources treated as tier_1
"""

import json
from pathlib import Path

import pytest

from sanna.receipt import (
    check_c1_context_contradiction,
    CheckResult,
)
from sanna.constitution import (
    load_constitution,
    parse_constitution,
    compute_constitution_hash,
    TrustedSources,
    Constitution,
)
from sanna.middleware import (
    _to_str,
    _extract_structured_context,
    _resolve_source_tiers,
    _build_source_trust_evaluations,
    _build_trace_data,
    _generate_constitution_receipt,
)
from sanna.enforcement import configure_checks
from sanna.verify import verify_receipt, verify_fingerprint, load_schema

# =============================================================================
# PATHS
# =============================================================================

CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"
WITH_TRUSTED_SOURCES = str(CONSTITUTIONS_DIR / "with_trusted_sources.yaml")
ALL_WARN_CONST = str(CONSTITUTIONS_DIR / "all_warn.yaml")

# =============================================================================
# CONTEXT FIXTURES
# =============================================================================

# Contradictory context: says "non-refundable" for digital products
CONTRADICTORY_CONTEXT = (
    "Our refund policy: Physical products can be returned within 30 days. "
    "Digital products are non-refundable once downloaded. "
    "Subscriptions can be cancelled anytime."
)

# Output that contradicts the context
CONTRADICTORY_OUTPUT = (
    "Based on your purchase history, you are eligible to request a refund. "
    "However, since the software was downloaded, processing may take 5-7 "
    "business days."
)

# Non-contradictory context and output
SAFE_CONTEXT = "France is a country in Western Europe. Its capital is Paris."
SAFE_OUTPUT = "The capital of France is Paris."


def _struct_ctx(text: str, source: str, tier: str) -> dict:
    """Helper to build a structured context item."""
    return {"text": text, "source": source, "tier": tier}


# =============================================================================
# 1. C1 backward compatibility — plain string context
# =============================================================================

class TestC1BackwardCompat:
    def test_plain_string_contradiction_fails(self):
        """v0.6.x behavior: plain string context with contradiction fails."""
        result = check_c1_context_contradiction(
            CONTRADICTORY_CONTEXT, CONTRADICTORY_OUTPUT
        )
        assert not result.passed
        assert result.severity == "critical"

    def test_plain_string_no_contradiction_passes(self):
        result = check_c1_context_contradiction(SAFE_CONTEXT, SAFE_OUTPUT)
        assert result.passed

    def test_plain_string_empty_context_passes(self):
        result = check_c1_context_contradiction("", SAFE_OUTPUT)
        assert result.passed

    def test_plain_string_ignores_structured_context_when_none(self):
        """When structured_context is None, plain string behavior is identical."""
        result = check_c1_context_contradiction(
            CONTRADICTORY_CONTEXT, CONTRADICTORY_OUTPUT,
            structured_context=None,
        )
        assert not result.passed
        assert result.severity == "critical"


# =============================================================================
# 2. C1 with tier_1 sources — full trust
# =============================================================================

class TestC1Tier1:
    def test_tier_1_contradiction_fails(self):
        """tier_1 source contradiction → critical failure."""
        ctx = [_struct_ctx(CONTRADICTORY_CONTEXT, "knowledge_base", "tier_1")]
        result = check_c1_context_contradiction(
            CONTRADICTORY_CONTEXT, CONTRADICTORY_OUTPUT,
            structured_context=ctx,
        )
        assert not result.passed
        assert result.severity == "critical"
        assert "tier_1" in result.evidence

    def test_tier_1_no_contradiction_passes(self):
        ctx = [_struct_ctx(SAFE_CONTEXT, "knowledge_base", "tier_1")]
        result = check_c1_context_contradiction(
            SAFE_CONTEXT, SAFE_OUTPUT,
            structured_context=ctx,
        )
        assert result.passed

    def test_tier_1_source_name_in_evidence(self):
        ctx = [_struct_ctx(CONTRADICTORY_CONTEXT, "product_docs", "tier_1")]
        result = check_c1_context_contradiction(
            CONTRADICTORY_CONTEXT, CONTRADICTORY_OUTPUT,
            structured_context=ctx,
        )
        assert "product_docs" in result.evidence


# =============================================================================
# 3. C1 with tier_2 sources — evidence with verification
# =============================================================================

class TestC1Tier2:
    def test_tier_2_contradiction_fails_with_verification(self):
        """tier_2 contradiction → fail but with verification note."""
        ctx = [_struct_ctx(CONTRADICTORY_CONTEXT, "team_slack", "tier_2")]
        result = check_c1_context_contradiction(
            CONTRADICTORY_CONTEXT, CONTRADICTORY_OUTPUT,
            structured_context=ctx,
        )
        assert not result.passed
        assert result.severity == "critical"
        assert "verification" in result.evidence.lower() or "verification" in result.details.lower()

    def test_tier_2_no_contradiction_passes(self):
        ctx = [_struct_ctx(SAFE_CONTEXT, "team_slack", "tier_2")]
        result = check_c1_context_contradiction(
            SAFE_CONTEXT, SAFE_OUTPUT,
            structured_context=ctx,
        )
        assert result.passed


# =============================================================================
# 4. C1 with tier_3 only — reference only
# =============================================================================

class TestC1Tier3Only:
    def test_tier_3_only_contradiction_passes(self):
        """tier_3-only contradiction → passes (reference sources can't fail C1)."""
        ctx = [_struct_ctx(CONTRADICTORY_CONTEXT, "customer_links", "tier_3")]
        result = check_c1_context_contradiction(
            CONTRADICTORY_CONTEXT, CONTRADICTORY_OUTPUT,
            structured_context=ctx,
        )
        assert result.passed
        assert "tier_3" in result.evidence
        assert "reference" in result.details.lower()

    def test_tier_3_no_contradiction_passes(self):
        ctx = [_struct_ctx(SAFE_CONTEXT, "customer_links", "tier_3")]
        result = check_c1_context_contradiction(
            SAFE_CONTEXT, SAFE_OUTPUT,
            structured_context=ctx,
        )
        assert result.passed


# =============================================================================
# 5. C1 with untrusted sources — excluded
# =============================================================================

class TestC1Untrusted:
    def test_untrusted_only_passes_even_with_contradiction(self):
        """Untrusted sources are excluded from C1 → always passes."""
        ctx = [_struct_ctx(CONTRADICTORY_CONTEXT, "social_media", "untrusted")]
        result = check_c1_context_contradiction(
            CONTRADICTORY_CONTEXT, CONTRADICTORY_OUTPUT,
            structured_context=ctx,
        )
        assert result.passed

    def test_untrusted_no_evidence(self):
        ctx = [_struct_ctx(CONTRADICTORY_CONTEXT, "social_media", "untrusted")]
        result = check_c1_context_contradiction(
            CONTRADICTORY_CONTEXT, CONTRADICTORY_OUTPUT,
            structured_context=ctx,
        )
        # Should pass with no contradiction evidence
        assert "No obvious contradiction" in result.details


# =============================================================================
# 6. C1 with mixed tiers
# =============================================================================

class TestC1MixedTiers:
    def test_tier_1_contradiction_fails_even_with_safe_untrusted(self):
        """tier_1 contradiction wins over safe untrusted."""
        ctx = [
            _struct_ctx(CONTRADICTORY_CONTEXT, "knowledge_base", "tier_1"),
            _struct_ctx(SAFE_CONTEXT, "social_media", "untrusted"),
        ]
        result = check_c1_context_contradiction(
            CONTRADICTORY_CONTEXT, CONTRADICTORY_OUTPUT,
            structured_context=ctx,
        )
        assert not result.passed
        assert "tier_1" in result.evidence

    def test_tier_2_with_safe_tier_3(self):
        """tier_2 contradiction with safe tier_3 → fail."""
        ctx = [
            _struct_ctx(CONTRADICTORY_CONTEXT, "team_slack", "tier_2"),
            _struct_ctx(SAFE_CONTEXT, "customer_links", "tier_3"),
        ]
        result = check_c1_context_contradiction(
            CONTRADICTORY_CONTEXT, CONTRADICTORY_OUTPUT,
            structured_context=ctx,
        )
        assert not result.passed
        assert "tier_2" in result.evidence

    def test_only_tier_3_and_untrusted_passes(self):
        """No tier_1 or tier_2 sources → tier_3 contradiction is just a note."""
        ctx = [
            _struct_ctx(CONTRADICTORY_CONTEXT, "customer_links", "tier_3"),
            _struct_ctx(CONTRADICTORY_CONTEXT, "social_media", "untrusted"),
        ]
        result = check_c1_context_contradiction(
            CONTRADICTORY_CONTEXT, CONTRADICTORY_OUTPUT,
            structured_context=ctx,
        )
        assert result.passed
        assert "tier_3" in result.evidence

    def test_all_safe_sources_passes(self):
        ctx = [
            _struct_ctx(SAFE_CONTEXT, "knowledge_base", "tier_1"),
            _struct_ctx(SAFE_CONTEXT, "team_slack", "tier_2"),
            _struct_ctx(SAFE_CONTEXT, "customer_links", "tier_3"),
        ]
        result = check_c1_context_contradiction(
            SAFE_CONTEXT, SAFE_OUTPUT,
            structured_context=ctx,
        )
        assert result.passed


# =============================================================================
# 7. Constitution trusted_sources parsing
# =============================================================================

class TestConstitutionTrustedSources:
    def test_loads_trusted_sources(self):
        c = load_constitution(WITH_TRUSTED_SOURCES, validate=True)
        assert c.trusted_sources is not None
        assert "knowledge_base" in c.trusted_sources.tier_1
        assert "product_docs" in c.trusted_sources.tier_1
        assert "team_slack" in c.trusted_sources.tier_2
        assert "customer_links" in c.trusted_sources.tier_3
        assert "social_media" in c.trusted_sources.untrusted

    def test_constitution_without_trusted_sources_is_none(self):
        c = load_constitution(ALL_WARN_CONST, validate=True)
        assert c.trusted_sources is None

    def test_trusted_sources_changes_hash(self):
        """Adding trusted_sources changes the constitution hash."""
        c_without = load_constitution(ALL_WARN_CONST, validate=True)
        c_with = load_constitution(WITH_TRUSTED_SOURCES, validate=True)
        assert c_without.policy_hash != c_with.policy_hash

    def test_absent_trusted_sources_preserves_hash(self):
        """Constitution without trusted_sources has the same hash as before."""
        c = load_constitution(ALL_WARN_CONST, validate=True)
        computed = compute_constitution_hash(c)
        assert computed == c.policy_hash

    def test_parse_empty_trusted_sources(self):
        data = {
            "sanna_constitution": "1.0.0",
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "a@b.com",
                "approved_by": ["b@b.com"],
                "approval_date": "2026-01-01",
                "approval_method": "test",
            },
            "boundaries": [{"id": "B001", "description": "t", "category": "scope", "severity": "medium"}],
            "trusted_sources": {
                "tier_1": [],
                "tier_2": [],
                "tier_3": [],
                "untrusted": [],
            },
        }
        c = parse_constitution(data)
        assert c.trusted_sources is not None
        assert c.trusted_sources.tier_1 == []

    def test_schema_validates_trusted_sources(self):
        """Constitution with trusted_sources passes JSON schema validation."""
        c = load_constitution(WITH_TRUSTED_SOURCES, validate=True)
        # If we got here without exception, validation passed
        assert c.trusted_sources is not None


# =============================================================================
# 8. Middleware helpers
# =============================================================================

class TestMiddlewareHelpers:
    def test_to_str_with_structured_context(self):
        ctx = [
            {"text": "First document", "source": "db"},
            {"text": "Second document", "source": "api"},
        ]
        result = _to_str(ctx)
        assert "First document" in result
        assert "Second document" in result
        assert "source" not in result  # no dict repr

    def test_to_str_with_plain_string(self):
        assert _to_str("hello") == "hello"

    def test_to_str_with_plain_list(self):
        assert _to_str(["a", "b"]) == "a\nb"

    def test_extract_structured_context_with_valid_list(self):
        ctx = [
            {"text": "doc1", "source": "db"},
            {"text": "doc2", "source": "api"},
        ]
        result = _extract_structured_context(ctx)
        assert result is not None
        assert len(result) == 2

    def test_extract_structured_context_with_string_returns_none(self):
        assert _extract_structured_context("plain string") is None

    def test_extract_structured_context_with_empty_list_returns_none(self):
        assert _extract_structured_context([]) is None

    def test_extract_structured_context_with_non_dict_list_returns_none(self):
        assert _extract_structured_context(["a", "b"]) is None

    def test_extract_structured_context_with_missing_text_key_returns_none(self):
        assert _extract_structured_context([{"source": "db"}]) is None

    def test_resolve_source_tiers_with_constitution_mapping(self):
        ts = TrustedSources(
            tier_1=["knowledge_base"],
            tier_2=["team_slack"],
            tier_3=["customer_links"],
            untrusted=["social_media"],
        )
        ctx = [
            {"text": "doc", "source": "knowledge_base"},
            {"text": "doc", "source": "team_slack"},
            {"text": "doc", "source": "unknown_source"},
        ]
        resolved = _resolve_source_tiers(ctx, ts)
        assert resolved[0]["tier"] == "tier_1"
        assert resolved[1]["tier"] == "tier_2"
        assert resolved[2]["tier"] == "unclassified"  # unknown sources default to unclassified

    def test_resolve_source_tiers_with_no_constitution(self):
        ctx = [{"text": "doc", "source": "any"}]
        resolved = _resolve_source_tiers(ctx, None)
        assert resolved[0]["tier"] == "unclassified"  # no constitution → unclassified

    def test_resolve_source_tiers_explicit_tier_takes_precedence(self):
        ts = TrustedSources(tier_1=["db"])
        ctx = [{"text": "doc", "source": "db", "tier": "tier_3"}]
        resolved = _resolve_source_tiers(ctx, ts)
        assert resolved[0]["tier"] == "tier_3"  # explicit wins

    def test_build_source_trust_evaluations(self):
        ctx = [
            {"text": "doc1", "source": "kb", "tier": "tier_1"},
            {"text": "doc2", "source": "slack", "tier": "tier_2"},
            {"text": "doc3", "source": "social", "tier": "untrusted"},
        ]
        evals = _build_source_trust_evaluations(ctx)
        assert len(evals) == 3

        by_source = {e["source_name"]: e for e in evals}
        assert by_source["kb"]["trust_tier"] == "tier_1"
        assert by_source["kb"]["verification_flag"] is False
        assert by_source["kb"]["context_used"] is True

        assert by_source["slack"]["trust_tier"] == "tier_2"
        assert by_source["slack"]["verification_flag"] is True
        assert by_source["slack"]["context_used"] is True

        assert by_source["social"]["trust_tier"] == "untrusted"
        assert by_source["social"]["verification_flag"] is False
        assert by_source["social"]["context_used"] is False

    def test_build_source_trust_evaluations_deduplicates(self):
        ctx = [
            {"text": "doc1", "source": "kb", "tier": "tier_1"},
            {"text": "doc2", "source": "kb", "tier": "tier_1"},
        ]
        evals = _build_source_trust_evaluations(ctx)
        assert len(evals) == 1

    def test_unclassified_tier_context_used_false(self):
        """Unclassified sources should have context_used=False (C1 ignores them)."""
        ctx = [
            {"text": "doc1", "source": "unknown_src", "tier": "unclassified"},
        ]
        evals = _build_source_trust_evaluations(ctx)
        assert len(evals) == 1
        assert evals[0]["trust_tier"] == "unclassified"
        assert evals[0]["context_used"] is False


# =============================================================================
# 9. Middleware integration — structured context through decorator
# =============================================================================

class TestMiddlewareIntegration:
    def test_receipt_with_structured_context_has_source_trust_evals(self):
        constitution = load_constitution(WITH_TRUSTED_SOURCES, validate=True)
        constitution_ref = constitution_to_receipt_ref(constitution)
        check_configs, custom_records = configure_checks(constitution)

        ctx = [
            _struct_ctx(SAFE_CONTEXT, "knowledge_base", "tier_1"),
            _struct_ctx(SAFE_CONTEXT, "team_slack", "tier_2"),
        ]
        resolved = _resolve_source_tiers(ctx, constitution.trusted_sources)
        evals = _build_source_trust_evaluations(resolved)

        trace_data = _build_trace_data(
            trace_id="test-structured",
            query="test query",
            context=_to_str(ctx),
            output=SAFE_OUTPUT,
        )

        receipt = _generate_constitution_receipt(
            trace_data,
            check_configs=check_configs,
            custom_records=custom_records,
            constitution_ref=constitution_ref,
            constitution_version=constitution.schema_version,
            source_trust_evaluations=evals,
            structured_context=resolved,
        )

        assert "source_trust_evaluations" in receipt
        assert len(receipt["source_trust_evaluations"]) == 2

    def test_receipt_with_structured_context_passes_verification(self):
        constitution = load_constitution(WITH_TRUSTED_SOURCES, validate=True)
        constitution_ref = constitution_to_receipt_ref(constitution)
        check_configs, custom_records = configure_checks(constitution)

        ctx = [_struct_ctx(SAFE_CONTEXT, "knowledge_base", "tier_1")]
        resolved = _resolve_source_tiers(ctx, constitution.trusted_sources)
        evals = _build_source_trust_evaluations(resolved)

        trace_data = _build_trace_data(
            trace_id="test-verify-structured",
            query="test query",
            context=_to_str(ctx),
            output=SAFE_OUTPUT,
        )

        receipt = _generate_constitution_receipt(
            trace_data,
            check_configs=check_configs,
            custom_records=custom_records,
            constitution_ref=constitution_ref,
            constitution_version=constitution.schema_version,
            source_trust_evaluations=evals,
            structured_context=resolved,
        )

        schema = load_schema()
        result = verify_receipt(receipt, schema)
        assert result.valid, f"Verification failed: {result.errors}"

    def test_receipt_without_structured_context_has_no_source_trust(self):
        constitution = load_constitution(WITH_TRUSTED_SOURCES, validate=True)
        constitution_ref = constitution_to_receipt_ref(constitution)
        check_configs, custom_records = configure_checks(constitution)

        trace_data = _build_trace_data(
            trace_id="test-no-structured",
            query="test query",
            context=SAFE_CONTEXT,
            output=SAFE_OUTPUT,
        )

        receipt = _generate_constitution_receipt(
            trace_data,
            check_configs=check_configs,
            custom_records=custom_records,
            constitution_ref=constitution_ref,
            constitution_version=constitution.schema_version,
        )

        assert "source_trust_evaluations" not in receipt


# =============================================================================
# 10. No trusted_sources → all sources tier_1 (backward compat)
# =============================================================================

class TestNoTrustedSources:
    def test_no_trusted_sources_treats_all_as_tier_1(self):
        """Constitution without trusted_sources → all sources default to tier_1."""
        ctx = [_struct_ctx(CONTRADICTORY_CONTEXT, "any_source", "tier_1")]
        resolved = _resolve_source_tiers(ctx, None)
        assert resolved[0]["tier"] == "tier_1"

    def test_no_trusted_sources_contradiction_fails(self):
        """Without trusted_sources, structured context still gets tier_1 treatment."""
        ctx = [_struct_ctx(CONTRADICTORY_CONTEXT, "any_source", "tier_1")]
        result = check_c1_context_contradiction(
            CONTRADICTORY_CONTEXT, CONTRADICTORY_OUTPUT,
            structured_context=ctx,
        )
        assert not result.passed
        assert "tier_1" in result.evidence

    def test_source_without_explicit_tier_defaults_to_tier_1(self):
        """Source dict without 'tier' key defaults to tier_1."""
        ctx = [{"text": CONTRADICTORY_CONTEXT, "source": "unknown"}]
        result = check_c1_context_contradiction(
            CONTRADICTORY_CONTEXT, CONTRADICTORY_OUTPUT,
            structured_context=ctx,
        )
        assert not result.passed
        assert "tier_1" in result.evidence


# Need this import for the integration test
from sanna.constitution import constitution_to_receipt_ref
