"""Block D tests — @sanna_observe execution order: reasoning BEFORE execution."""

from __future__ import annotations

import os
import tempfile

import pytest

from sanna.middleware import sanna_observe, SannaHaltError, SannaResult


def _write_constitution(path: str, *, reasoning: bool = True) -> str:
    """Write a minimal signed constitution YAML for testing."""
    import yaml
    from sanna.constitution import (
        load_constitution,
        sign_constitution,
        save_constitution,
    )
    from sanna.crypto import generate_keypair

    # Generate keypair
    key_dir = os.path.dirname(path)
    priv_path, pub_path = generate_keypair(key_dir)

    data = {
        "sanna_constitution": "1.1",
        "identity": {"agent_name": "test-agent", "domain": "testing"},
        "provenance": {
            "authored_by": "test@dev.com",
            "approved_by": ["approver@dev.com"],
            "approval_date": "2026-01-01",
            "approval_method": "manual-sign-off",
        },
        "boundaries": [
            {"id": "B001", "description": "Test boundary", "category": "scope", "severity": "high"},
        ],
        "invariants": [],
    }

    if reasoning:
        data["reasoning"] = {
            "require_justification_for": ["must_escalate", "cannot_execute"],
            "on_missing_justification": "block",
            "auto_deny_on_reasoning_failure": True,
            "checks": {
                "glc_002_minimum_substance": {
                    "enabled": True,
                    "min_length": 20,
                },
            },
        }

    with open(path, "w") as f:
        yaml.safe_dump(data, f)

    # Load → sign → save back
    constitution = load_constitution(path)
    signed = sign_constitution(constitution, priv_path)
    save_constitution(signed, path)
    return path


class TestObserveHaltBeforeExecution:
    def test_observe_halts_before_execution(self, tmp_path):
        """Reasoning fails at halt → func NOT called, SannaHaltError raised."""
        const_path = str(tmp_path / "constitution.yaml")
        _write_constitution(const_path, reasoning=True)

        func_called = False

        @sanna_observe(constitution_path=const_path, strict=False)
        def my_agent(query, context, _justification=""):
            nonlocal func_called
            func_called = True
            return "result"

        # Short justification fails glc_002 (min_length=20)
        with pytest.raises(SannaHaltError):
            my_agent(
                query="test",
                context="test context",
                _justification="ok",  # Too short → fails substance check
            )

        # Function was NOT called
        assert not func_called

    def test_observe_passes_then_executes(self, tmp_path):
        """Reasoning passes → func is called, result returned."""
        const_path = str(tmp_path / "constitution.yaml")
        _write_constitution(const_path, reasoning=True)

        func_called = False

        @sanna_observe(constitution_path=const_path, strict=False)
        def my_agent(query, context, _justification=""):
            nonlocal func_called
            func_called = True
            return "agent result"

        result = my_agent(
            query="test",
            context="test context",
            _justification="This action is needed because we must comply with the data retention policy",
        )

        assert func_called
        assert isinstance(result, SannaResult)
        assert result.output == "agent result"

    def test_observe_no_reasoning_config(self, tmp_path):
        """No reasoning config → func called normally (backward compat)."""
        const_path = str(tmp_path / "constitution.yaml")
        _write_constitution(const_path, reasoning=False)

        func_called = False

        @sanna_observe(constitution_path=const_path, strict=False)
        def my_agent(query, context):
            nonlocal func_called
            func_called = True
            return "agent result"

        result = my_agent(query="test", context="test context")

        assert func_called
        assert isinstance(result, SannaResult)
        assert result.output == "agent result"


class TestObserveLogButExecute:
    def test_observe_logs_but_executes(self, tmp_path):
        """Reasoning fails but auto_deny=False → func IS called."""
        import yaml
        from sanna.crypto import generate_keypair
        from sanna.constitution import load_constitution, sign_constitution, save_constitution

        const_path = str(tmp_path / "constitution.yaml")
        key_dir = str(tmp_path)
        priv_path, pub_path = generate_keypair(key_dir)

        data = {
            "sanna_constitution": "1.1",
            "identity": {"agent_name": "test-agent", "domain": "testing"},
            "provenance": {
                "authored_by": "test@dev.com",
                "approved_by": ["approver@dev.com"],
                "approval_date": "2026-01-01",
                "approval_method": "manual-sign-off",
            },
            "boundaries": [
                {"id": "B001", "description": "Test", "category": "scope", "severity": "high"},
            ],
            "invariants": [],
            "reasoning": {
                "require_justification_for": ["must_escalate"],
                "on_missing_justification": "allow",  # Don't block
                "auto_deny_on_reasoning_failure": False,  # Don't deny
                "checks": {
                    "glc_002_minimum_substance": {
                        "enabled": True,
                        "min_length": 20,
                    },
                },
            },
        }

        with open(const_path, "w") as f:
            yaml.safe_dump(data, f)
        constitution = load_constitution(const_path)
        signed = sign_constitution(constitution, priv_path)
        save_constitution(signed, const_path)

        func_called = False

        @sanna_observe(constitution_path=const_path, strict=False)
        def my_agent(query, context, _justification=""):
            nonlocal func_called
            func_called = True
            return "agent result"

        # Short justification fails but auto_deny is False
        result = my_agent(
            query="test",
            context="test context",
            _justification="ok",  # Too short → fails, but doesn't halt
        )

        # Function WAS called despite reasoning failure
        assert func_called
        assert isinstance(result, SannaResult)
        assert result.output == "agent result"
