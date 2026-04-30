"""SAN-206: content_mode redaction + hashes_only shape tests with schema validation."""

import json
import uuid
from pathlib import Path

import jsonschema
import pytest

from sanna.constitution import (
    AgentIdentity,
    ApiEndpoint,
    ApiPermissions,
    AuthorityBoundaries,
    Boundary,
    CliCommand,
    CliPermissions,
    Constitution,
    EscalationRule,
    Provenance,
)
from sanna.hashing import hash_text
from sanna.manifest import generate_manifest

_SCHEMA = json.loads(
    (Path(__file__).parent.parent / "spec" / "schemas" / "receipt.schema.json").read_text()
)

_HASH_64 = "a" * 64
_HASH_16 = "a" * 16


def _con(
    cannot_execute=None,
    must_escalate=None,
    escalation_visibility="visible",
    cli_permissions=None,
    api_permissions=None,
) -> Constitution:
    return Constitution(
        schema_version="1.0.0",
        identity=AgentIdentity(agent_name="test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="tester@test.com",
            approved_by=["approver@test.com"],
            approval_date="2026-01-01",
            approval_method="test",
        ),
        boundaries=[
            Boundary(id="B001", description="Test", category="scope", severity="medium"),
        ],
        authority_boundaries=AuthorityBoundaries(
            cannot_execute=cannot_execute or [],
            must_escalate=must_escalate or [],
            can_execute=[],
            escalation_visibility=escalation_visibility,
        ),
        cli_permissions=cli_permissions,
        api_permissions=api_permissions,
    )


def _bare_receipt(manifest_ext: dict, enforcement_surface: str = "gateway") -> dict:
    return {
        "spec_version": "1.5",
        "tool_version": "1.5.0",
        "tool_name": "sanna",
        "checks_version": "9",
        "receipt_id": str(uuid.uuid4()),
        "receipt_fingerprint": _HASH_16,
        "full_fingerprint": _HASH_64,
        "correlation_id": "test-001",
        "timestamp": "2026-04-30T12:00:00Z",
        "inputs": {"query": "session_manifest"},
        "outputs": {"response": ""},
        "context_hash": _HASH_64,
        "output_hash": _HASH_64,
        "checks": [],
        "checks_passed": 0,
        "checks_failed": 0,
        "status": "PASS",
        "invariants_scope": "none",
        "event_type": "session_manifest",
        "enforcement": None,
        "enforcement_surface": enforcement_surface,
        "extensions": {"com.sanna.manifest": manifest_ext},
    }


# =============================================================================
# Redacted mode
# =============================================================================

class TestRedactedMode:
    def test_tool_names_become_redacted_marker(self):
        cons = _con(cannot_execute=["delete_all"])
        out = generate_manifest(cons, mcp_tools=["delete_all", "read_data"], content_mode="redacted")
        mcp = out["surfaces"]["mcp"]
        assert mcp["tools_delivered"] == ["<redacted>"]
        assert mcp["tools_suppressed"] == ["<redacted>"]

    def test_suppression_reasons_omitted(self):
        cons = _con(cannot_execute=["delete_all"])
        out = generate_manifest(cons, mcp_tools=["delete_all", "read_data"], content_mode="redacted")
        assert "suppression_reasons" not in out["surfaces"]["mcp"]

    def test_aggregate_suppression_reasons_aligned_with_sorted_suppressed(self):
        cons = _con(cannot_execute=["delete_all"])
        out = generate_manifest(cons, mcp_tools=["delete_all", "read_data"], content_mode="redacted")
        mcp = out["surfaces"]["mcp"]
        # cleartext suppressed list was ["delete_all"] -> reason "cannot_execute"
        assert mcp["aggregate_suppression_reasons"] == ["cannot_execute"]

    def test_aggregate_absent_when_no_suppressions(self):
        cons = _con()
        out = generate_manifest(cons, mcp_tools=["read_data"], content_mode="redacted")
        mcp = out["surfaces"]["mcp"]
        assert "aggregate_suppression_reasons" not in mcp

    def test_schema_validates_redacted_mcp_receipt(self):
        cons = _con(cannot_execute=["delete_all"])
        manifest_ext = generate_manifest(
            cons, mcp_tools=["delete_all", "read_data"], content_mode="redacted"
        )
        receipt = _bare_receipt(manifest_ext)
        receipt["content_mode"] = "redacted"
        receipt["content_mode_source"] = "local_config"
        jsonschema.validate(instance=receipt, schema=_SCHEMA)

    def test_cli_patterns_also_redacted(self):
        cli = CliPermissions(
            mode="strict",
            commands=[
                CliCommand(id="c1", binary="git", authority="can_execute"),
                CliCommand(id="c2", binary="rm", authority="cannot_execute"),
            ],
        )
        cons = _con(cli_permissions=cli)
        out = generate_manifest(cons, content_mode="redacted")
        cli_surf = out["surfaces"]["cli"]
        assert cli_surf["patterns_delivered"] == ["<redacted>"]
        assert cli_surf["patterns_suppressed"] == ["<redacted>"]
        assert "suppression_reasons" not in cli_surf
        # CLI surface suppression_reasons dict has no keys (cli uses "unknown" fallback)
        assert cli_surf["aggregate_suppression_reasons"] == ["unknown"]

    def test_schema_validates_redacted_cli_receipt(self):
        cli = CliPermissions(
            mode="strict",
            commands=[
                CliCommand(id="c1", binary="git", authority="can_execute"),
                CliCommand(id="c2", binary="rm", authority="cannot_execute"),
            ],
        )
        cons = _con(cli_permissions=cli)
        manifest_ext = generate_manifest(cons, content_mode="redacted")
        receipt = _bare_receipt(manifest_ext, enforcement_surface="cli_interceptor")
        receipt["content_mode"] = "redacted"
        receipt["content_mode_source"] = "local_config"
        jsonschema.validate(instance=receipt, schema=_SCHEMA)


# =============================================================================
# Hashes-only mode
# =============================================================================

class TestHashesOnlyMode:
    def test_tool_names_hashed(self):
        cons = _con(cannot_execute=["delete_all"])
        out = generate_manifest(cons, mcp_tools=["delete_all", "read_data"], content_mode="hashes_only")
        mcp = out["surfaces"]["mcp"]
        assert mcp["tools_delivered"] == sorted([hash_text("read_data")])
        assert mcp["tools_suppressed"] == sorted([hash_text("delete_all")])

    def test_suppression_reasons_keys_hashed_values_cleartext(self):
        cons = _con(cannot_execute=["delete_all"])
        out = generate_manifest(cons, mcp_tools=["delete_all", "read_data"], content_mode="hashes_only")
        mcp = out["surfaces"]["mcp"]
        hashed_key = hash_text("delete_all")
        assert hashed_key in mcp["suppression_reasons"]
        assert mcp["suppression_reasons"][hashed_key] == "cannot_execute"
        assert "delete_all" not in mcp["suppression_reasons"]

    def test_lists_sorted_by_hash_alphabetically(self):
        cons = _con(cannot_execute=["delete_all"])
        out = generate_manifest(
            cons, mcp_tools=["delete_all", "read_data", "zebra"], content_mode="hashes_only"
        )
        mcp = out["surfaces"]["mcp"]
        delivered_hashes = sorted([hash_text("read_data"), hash_text("zebra")])
        assert mcp["tools_delivered"] == delivered_hashes

    def test_schema_validates_hashes_only_receipt(self):
        cons = _con(cannot_execute=["delete_all"])
        manifest_ext = generate_manifest(
            cons, mcp_tools=["delete_all", "read_data"], content_mode="hashes_only"
        )
        receipt = _bare_receipt(manifest_ext)
        receipt["content_mode"] = "hashes_only"
        receipt["content_mode_source"] = "local_config"
        jsonschema.validate(instance=receipt, schema=_SCHEMA)


# =============================================================================
# Full mode (no content_mode) -- cleartext unchanged
# =============================================================================

class TestFullModeUnchanged:
    def test_cleartext_preserved(self):
        cons = _con(cannot_execute=["delete_all"])
        out = generate_manifest(cons, mcp_tools=["delete_all", "read_data"])
        mcp = out["surfaces"]["mcp"]
        assert mcp["tools_delivered"] == ["read_data"]
        assert mcp["tools_suppressed"] == ["delete_all"]
        assert mcp["suppression_reasons"] == {"delete_all": "cannot_execute"}
        assert "aggregate_suppression_reasons" not in mcp

    def test_schema_validates_full_mode_receipt(self):
        cons = _con(cannot_execute=["delete_all"])
        manifest_ext = generate_manifest(cons, mcp_tools=["delete_all", "read_data"])
        receipt = _bare_receipt(manifest_ext)
        jsonschema.validate(instance=receipt, schema=_SCHEMA)


# =============================================================================
# Surfaces filter
# =============================================================================

class TestSurfacesFilter:
    def test_surfaces_filter_mcp_only_drops_cli(self):
        cli = CliPermissions(
            mode="strict",
            commands=[CliCommand(id="c1", binary="git", authority="can_execute")],
        )
        cons = _con(cli_permissions=cli)
        out = generate_manifest(cons, mcp_tools=["read_data"], surfaces=["mcp"])
        assert "mcp" in out["surfaces"]
        assert "cli" not in out["surfaces"]

    def test_surfaces_filter_none_includes_all(self):
        cli = CliPermissions(
            mode="strict",
            commands=[CliCommand(id="c1", binary="git", authority="can_execute")],
        )
        cons = _con(cli_permissions=cli)
        out = generate_manifest(cons, mcp_tools=["read_data"], surfaces=None)
        assert "mcp" in out["surfaces"]
        assert "cli" in out["surfaces"]

    def test_surfaces_filter_cli_only_drops_mcp(self):
        cli = CliPermissions(
            mode="strict",
            commands=[CliCommand(id="c1", binary="git", authority="can_execute")],
        )
        cons = _con(cli_permissions=cli)
        out = generate_manifest(cons, mcp_tools=["read_data"], surfaces=["cli"])
        assert "cli" in out["surfaces"]
        assert "mcp" not in out["surfaces"]
