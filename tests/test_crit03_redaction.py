"""Tests for CRIT-03: Redaction Pipeline Fix.

Covers three bugs:
  a) pattern_redact config raises GatewayConfigError at load time
  b) outputs["response"] actually gets redacted (was "output" -- wrong key)
  c) When redaction enabled: only .redacted.json on disk, no unredacted file
     When redaction disabled: normal .json file, no .redacted.json

Uses unittest.mock and tmp directories for file persistence tests.
"""

import hashlib
import json
import os
import textwrap
from pathlib import Path
from unittest import mock

import pytest


# =============================================================================
# HELPERS
# =============================================================================

def _create_signed_constitution(tmp_path):
    """Create a signed constitution and keypair. Returns (const_path, key_path)."""
    from sanna.crypto import generate_keypair
    from sanna.constitution import (
        Constitution,
        AgentIdentity,
        Provenance,
        Boundary,
        sign_constitution,
        save_constitution,
    )

    keys_dir = tmp_path / "keys"
    private_key_path, _ = generate_keypair(str(keys_dir))

    constitution = Constitution(
        schema_version="0.1.0",
        identity=AgentIdentity(agent_name="test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="test@example.com",
            approved_by=["approver@example.com"],
            approval_date="2024-01-01",
            approval_method="manual-sign-off",
        ),
        boundaries=[
            Boundary(id="B001", description="Test", category="scope",
                     severity="high"),
        ],
    )
    signed = sign_constitution(
        constitution, private_key_path=str(private_key_path),
    )
    const_path = tmp_path / "constitution.yaml"
    save_constitution(signed, const_path)
    return str(const_path), str(private_key_path)


def _write_config(tmp_path, content, filename="gateway.yaml"):
    """Write YAML config content to a temp file. Returns path."""
    p = tmp_path / filename
    p.write_text(textwrap.dedent(content))
    return str(p)


def _minimal_config(const_path, key_path):
    """Return minimal valid config YAML content."""
    return f"""\
    gateway:
      constitution: {const_path}
      signing_key: {key_path}

    downstream:
      - name: mock
        command: echo
    """


def _make_receipt(receipt_id="test-rcpt-001", response_text="sensitive output"):
    """Build a minimal receipt dict matching gateway receipt structure."""
    return {
        "schema_version": "0.1",
        "tool_version": "0.13.0",
        "receipt_id": receipt_id,
        "correlation_id": "corr-001",
        "timestamp": "2025-01-15T10:30:00+00:00",
        "inputs": {
            "query": "What is the patient status?",
            "context": "Patient John Doe, SSN 123-45-6789",
        },
        "outputs": {
            "response": response_text,
        },
        "context_hash": "abc123",
        "output_hash": "def456",
        "status": "PASS",
        "checks": [],
        "checks_passed": 0,
        "checks_failed": 0,
        "receipt_fingerprint": "fingerprint-placeholder",
    }


# =============================================================================
# a) pattern_redact config raises GatewayConfigError at load time
# =============================================================================

class TestPatternRedactRejected:
    """pattern_redact mode must be rejected at config load time."""

    def test_pattern_redact_raises_config_error(self, tmp_path):
        """Loading a config with mode=pattern_redact raises GatewayConfigError."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import GatewayConfigError, load_gateway_config

        const_path, key_path = _create_signed_constitution(tmp_path)
        config_yaml = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}
          redaction:
            enabled: true
            mode: pattern_redact

        downstream:
          - name: mock
            command: echo
        """
        config_path = _write_config(tmp_path, config_yaml)
        with pytest.raises(GatewayConfigError, match="pattern_redact.*not yet implemented"):
            load_gateway_config(config_path)

    def test_hash_only_mode_accepted(self, tmp_path):
        """hash_only mode is accepted without error."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import load_gateway_config

        const_path, key_path = _create_signed_constitution(tmp_path)
        config_yaml = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}
          redaction:
            enabled: true
            mode: hash_only

        downstream:
          - name: mock
            command: echo
        """
        config_path = _write_config(tmp_path, config_yaml)
        config = load_gateway_config(config_path)
        assert config.redaction.enabled is True
        assert config.redaction.mode == "hash_only"

    def test_redact_for_storage_rejects_pattern_redact(self):
        """Defense in depth: _redact_for_storage raises on pattern_redact."""
        pytest.importorskip("mcp")
        from sanna.gateway.server import _redact_for_storage

        with pytest.raises(ValueError, match="pattern_redact.*not yet implemented"):
            _redact_for_storage("some content", mode="pattern_redact")


# =============================================================================
# b) outputs["response"] actually gets redacted
# =============================================================================

class TestOutputsResponseRedaction:
    """Redaction must target outputs['response'], not outputs['output']."""

    def test_response_field_redacted(self, tmp_path):
        """outputs['response'] is replaced with [REDACTED ...] placeholder."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec

        const_path, key_path = _create_signed_constitution(tmp_path)
        store_dir = tmp_path / "receipts"
        store_dir.mkdir()

        redaction = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments", "result_text"],
        )

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            receipt_store_path=str(store_dir),
            redaction_config=redaction,
        )

        receipt = _make_receipt(response_text="Patient has elevated BP 180/110")
        gw._persist_receipt(receipt)

        # Only a .redacted.json file should exist
        files = list(store_dir.glob("*.json"))
        redacted_files = [f for f in files if ".redacted.json" in f.name]
        assert len(redacted_files) == 1, (
            f"Expected exactly 1 redacted file, got {[f.name for f in files]}"
        )

        content = json.loads(redacted_files[0].read_text())
        response_val = content.get("outputs", {}).get("response", "")
        assert "[REDACTED" in response_val, (
            f"Expected outputs.response to be redacted, got: {response_val!r}"
        )
        assert "Patient" not in response_val
        assert "180/110" not in response_val

    def test_context_field_also_redacted(self, tmp_path):
        """inputs['context'] is also redacted when 'arguments' in fields."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec

        const_path, key_path = _create_signed_constitution(tmp_path)
        store_dir = tmp_path / "receipts"
        store_dir.mkdir()

        redaction = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments", "result_text"],
        )

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            receipt_store_path=str(store_dir),
            redaction_config=redaction,
        )

        receipt = _make_receipt()
        gw._persist_receipt(receipt)

        files = list(store_dir.glob("*.redacted.json"))
        assert len(files) == 1

        content = json.loads(files[0].read_text())
        context_val = content.get("inputs", {}).get("context", "")
        assert "[REDACTED" in context_val
        assert "John Doe" not in context_val
        assert "123-45-6789" not in context_val


# =============================================================================
# c) Unredacted receipt NOT persisted when redaction is enabled
# =============================================================================

class TestRedactionPersistence:
    """Only redacted receipts should be on disk when redaction is enabled."""

    def test_redaction_enabled_only_redacted_file(self, tmp_path):
        """When redaction enabled: no .json original, only .redacted.json."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec

        const_path, key_path = _create_signed_constitution(tmp_path)
        store_dir = tmp_path / "receipts"
        store_dir.mkdir()

        redaction = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments", "result_text"],
        )

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            receipt_store_path=str(store_dir),
            redaction_config=redaction,
        )

        receipt = _make_receipt()
        gw._persist_receipt(receipt)

        all_files = list(store_dir.glob("*.json"))
        # Only the .redacted.json file should exist
        plain_files = [f for f in all_files if ".redacted.json" not in f.name]
        redacted_files = [f for f in all_files if ".redacted.json" in f.name]

        assert len(plain_files) == 0, (
            f"Unredacted receipt should NOT be on disk, found: "
            f"{[f.name for f in plain_files]}"
        )
        assert len(redacted_files) == 1, (
            f"Expected exactly 1 redacted file, got: "
            f"{[f.name for f in redacted_files]}"
        )

    def test_redaction_disabled_normal_file(self, tmp_path):
        """When redaction disabled: normal .json, no .redacted.json."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec

        const_path, key_path = _create_signed_constitution(tmp_path)
        store_dir = tmp_path / "receipts"
        store_dir.mkdir()

        redaction = RedactionConfig(enabled=False)

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            receipt_store_path=str(store_dir),
            redaction_config=redaction,
        )

        receipt = _make_receipt()
        gw._persist_receipt(receipt)

        all_files = list(store_dir.glob("*.json"))
        plain_files = [f for f in all_files if ".redacted.json" not in f.name]
        redacted_files = [f for f in all_files if ".redacted.json" in f.name]

        assert len(plain_files) == 1, (
            f"Expected exactly 1 normal receipt file, got: "
            f"{[f.name for f in all_files]}"
        )
        assert len(redacted_files) == 0, (
            f"No redacted files expected when redaction disabled, found: "
            f"{[f.name for f in redacted_files]}"
        )

    def test_redacted_receipt_valid_json_structure(self, tmp_path):
        """Redacted receipt loads as valid JSON with required fields."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec

        const_path, key_path = _create_signed_constitution(tmp_path)
        store_dir = tmp_path / "receipts"
        store_dir.mkdir()

        redaction = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments", "result_text"],
        )

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            receipt_store_path=str(store_dir),
            redaction_config=redaction,
        )

        receipt = _make_receipt()
        gw._persist_receipt(receipt)

        files = list(store_dir.glob("*.redacted.json"))
        assert len(files) == 1

        content = json.loads(files[0].read_text())

        # Required fields present
        assert "receipt_id" in content
        assert "correlation_id" in content
        assert "timestamp" in content
        assert "inputs" in content
        assert "outputs" in content
        assert "status" in content

        # Redaction notice present
        assert "_redaction_notice" in content
        assert "redacted" in content["_redaction_notice"].lower()

        # Receipt ID preserved
        assert content["receipt_id"] == "test-rcpt-001"

    def test_no_store_path_skips_persistence(self, tmp_path):
        """When receipt_store_path is None, no files are written."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec

        const_path, key_path = _create_signed_constitution(tmp_path)

        redaction = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments", "result_text"],
        )

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            receipt_store_path=None,
            redaction_config=redaction,
        )

        receipt = _make_receipt()
        # Should not raise, just silently return
        gw._persist_receipt(receipt)
