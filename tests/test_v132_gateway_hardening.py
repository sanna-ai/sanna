"""Tests for v0.13.2 gateway hardening (Prompt 6)."""

import json
import pytest
import asyncio

mcp = pytest.importorskip("mcp")

from sanna.gateway.server import SannaGateway, EscalationStore


def _run(coro):
    """Run an async coroutine synchronously."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _extract_text(result):
    """Extract text content from a CallToolResult."""
    return result.content[0].text


class TestMetaToolValidation:
    """FIX-38: Meta-tool type confusion crashes gateway."""

    def test_approve_with_list_escalation_id(self, tmp_path):
        gw = SannaGateway.for_single_server(
            name="test", command="echo", args=["hello"],
        )
        result = _run(gw._handle_approve({"escalation_id": [], "approval_token": "test"}))
        parsed = json.loads(_extract_text(result))
        assert "error" in parsed
        assert parsed["error"] == "escalation_id must be a string"
        assert result.isError is True

    def test_approve_with_none_escalation_id(self, tmp_path):
        gw = SannaGateway.for_single_server(
            name="test", command="echo", args=["hello"],
        )
        result = _run(gw._handle_approve({"escalation_id": None, "approval_token": "test"}))
        parsed = json.loads(_extract_text(result))
        assert "error" in parsed
        assert parsed["error"] == "escalation_id must be a string"

    def test_approve_with_int_escalation_id(self, tmp_path):
        gw = SannaGateway.for_single_server(
            name="test", command="echo", args=["hello"],
        )
        result = _run(gw._handle_approve({"escalation_id": 42, "approval_token": "test"}))
        parsed = json.loads(_extract_text(result))
        assert "error" in parsed
        assert parsed["error"] == "escalation_id must be a string"

    def test_approve_with_dict_token(self, tmp_path):
        gw = SannaGateway.for_single_server(
            name="test", command="echo", args=["hello"],
        )
        result = _run(gw._handle_approve({"escalation_id": "esc_abc", "approval_token": {}}))
        parsed = json.loads(_extract_text(result))
        assert "error" in parsed
        assert parsed["error"] == "approval_token must be a string"

    def test_approve_with_list_token(self, tmp_path):
        gw = SannaGateway.for_single_server(
            name="test", command="echo", args=["hello"],
        )
        result = _run(gw._handle_approve({"escalation_id": "esc_abc", "approval_token": [1, 2]}))
        parsed = json.loads(_extract_text(result))
        assert "error" in parsed
        assert parsed["error"] == "approval_token must be a string"

    def test_approve_with_none_token_allowed(self, tmp_path):
        """None approval_token is allowed (handled downstream by token requirement logic)."""
        gw = SannaGateway.for_single_server(
            name="test", command="echo", args=["hello"],
        )
        # This should NOT trigger the type check -- None means "not provided"
        # It should fail later with ESCALATION_NOT_FOUND instead
        result = _run(gw._handle_approve({"escalation_id": "esc_abc"}))
        parsed = json.loads(_extract_text(result))
        assert parsed["error"] == "ESCALATION_NOT_FOUND"

    def test_approve_bad_format(self, tmp_path):
        gw = SannaGateway.for_single_server(
            name="test", command="echo", args=["hello"],
        )
        result = _run(gw._handle_approve({"escalation_id": "bad-format", "approval_token": "tok"}))
        parsed = json.loads(_extract_text(result))
        assert "error" in parsed
        assert parsed["error"] == "invalid escalation_id format"

    def test_approve_empty_string_id_rejected(self, tmp_path):
        """Empty string passes isinstance check but fails startswith('esc_')."""
        gw = SannaGateway.for_single_server(
            name="test", command="echo", args=["hello"],
        )
        result = _run(gw._handle_approve({"escalation_id": "", "approval_token": "tok"}))
        parsed = json.loads(_extract_text(result))
        assert "error" in parsed
        assert parsed["error"] == "invalid escalation_id format"

    def test_deny_with_int_escalation_id(self, tmp_path):
        gw = SannaGateway.for_single_server(
            name="test", command="echo", args=["hello"],
        )
        result = _run(gw._handle_deny({"escalation_id": 123}))
        parsed = json.loads(_extract_text(result))
        assert "error" in parsed
        assert parsed["error"] == "escalation_id must be a string"
        assert result.isError is True

    def test_deny_with_list_escalation_id(self, tmp_path):
        gw = SannaGateway.for_single_server(
            name="test", command="echo", args=["hello"],
        )
        result = _run(gw._handle_deny({"escalation_id": ["a", "b"]}))
        parsed = json.loads(_extract_text(result))
        assert "error" in parsed
        assert parsed["error"] == "escalation_id must be a string"

    def test_deny_bad_format(self, tmp_path):
        gw = SannaGateway.for_single_server(
            name="test", command="echo", args=["hello"],
        )
        result = _run(gw._handle_deny({"escalation_id": "bad-format"}))
        parsed = json.loads(_extract_text(result))
        assert "error" in parsed
        assert parsed["error"] == "invalid escalation_id format"

    def test_deny_empty_string_rejected(self, tmp_path):
        """Empty string passes isinstance but fails startswith('esc_')."""
        gw = SannaGateway.for_single_server(
            name="test", command="echo", args=["hello"],
        )
        result = _run(gw._handle_deny({"escalation_id": ""}))
        parsed = json.loads(_extract_text(result))
        assert "error" in parsed
        assert parsed["error"] == "invalid escalation_id format"


class TestArgumentsDeepCopy:
    """FIX-42: Escalation arguments mutable by reference."""

    def test_mutating_original_does_not_affect_stored_sync(self, tmp_path):
        store = EscalationStore(persist_path=str(tmp_path / "esc.json"))
        original_args = {"key": "value", "nested": {"a": 1}}

        entry = store.create(
            prefixed_name="srv_test_tool",
            original_name="test_tool",
            arguments=original_args,
            server_name="srv",
            reason="test",
        )

        # Mutate original
        original_args["key"] = "mutated"
        original_args["nested"]["a"] = 999
        # Stored args should be unchanged
        assert entry.arguments["key"] == "value"
        assert entry.arguments["nested"]["a"] == 1

    def test_mutating_original_does_not_affect_stored_async(self, tmp_path):
        store = EscalationStore(persist_path=str(tmp_path / "esc.json"))
        original_args = {"key": "value", "nested": {"a": 1}}

        entry = _run(store.create_async(
            prefixed_name="srv_test_tool",
            original_name="test_tool",
            arguments=original_args,
            server_name="srv",
            reason="test",
        ))

        # Mutate original
        original_args["key"] = "mutated"
        original_args["nested"]["a"] = 999
        # Stored args should be unchanged
        assert entry.arguments["key"] == "value"
        assert entry.arguments["nested"]["a"] == 1

    def test_stored_entry_independent_of_input(self, tmp_path):
        """Deep nested mutations should not propagate."""
        store = EscalationStore(persist_path=str(tmp_path / "esc.json"))
        original_args = {"list": [1, 2, {"deep": True}]}

        entry = store.create(
            prefixed_name="srv_tool",
            original_name="tool",
            arguments=original_args,
            server_name="srv",
            reason="test",
        )

        # Mutate deeply nested structure
        original_args["list"][2]["deep"] = False
        original_args["list"].append(99)

        assert entry.arguments["list"][2]["deep"] is True
        assert len(entry.arguments["list"]) == 3
