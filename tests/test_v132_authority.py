"""Tests for v0.13.2 authority + tool name hardening (Prompt 4)."""

import pytest
from sanna.enforcement.authority import normalize_authority_name, _matches_action


class TestUnicodeNormalization:
    def test_fullwidth_f_matches(self):
        """deleteFile (fullwidth F) normalizes same as delete_file."""
        assert normalize_authority_name("delete\uff26ile") == normalize_authority_name("delete_file")

    def test_casefold_german_eszett(self):
        """casefold handles eszett -> ss."""
        result = normalize_authority_name("stra\u00dfe")
        assert "ss" in result

    def test_standard_camel_case(self):
        """deleteFile -> delete.file."""
        result = normalize_authority_name("deleteFile")
        assert result == "delete.file"

    def test_underscore_separator(self):
        """delete_file -> delete.file."""
        result = normalize_authority_name("delete_file")
        assert result == "delete.file"


class TestEmptyToolNames:
    def test_empty_action_returns_false(self):
        """Empty action name should never match any pattern."""
        assert _matches_action("", "delete_file") is False

    def test_whitespace_action_returns_false(self):
        """Whitespace-only action should never match."""
        assert _matches_action("   ", "delete_file") is False

    def test_empty_pattern_returns_false(self):
        """Empty pattern should never match any action."""
        assert _matches_action("delete_file", "") is False

    def test_both_empty_returns_false(self):
        """Both empty should return False."""
        assert _matches_action("", "") is False


class TestCorrelationIdPipe:
    def test_pipe_in_correlation_id_rejected(self):
        from sanna.middleware import build_trace_data
        with pytest.raises(ValueError, match="pipe"):
            build_trace_data(
                correlation_id="test|bad",
                query="test",
                context="ctx",
                output="out",
            )

    def test_valid_correlation_id_accepted(self):
        from sanna.middleware import build_trace_data
        result = build_trace_data(
            correlation_id="test-good-id",
            query="test",
            context="ctx",
            output="out",
        )
        assert result["correlation_id"] == "test-good-id"
