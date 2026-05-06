"""SAN-206: invocation_anomaly receipt parent-chain integrity tests."""

import asyncio
import sys

import pytest

pytest.importorskip("mcp", reason="mcp extra not installed")

from sanna.verify_manifest import verify_session_manifest_receipt, verify_invocation_anomaly_receipt

from sanna.constitution import (
    AgentIdentity,
    AuthorityBoundaries,
    Boundary,
    Constitution,
    Provenance,
)


def _con(cannot_execute=None) -> Constitution:
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
            must_escalate=[],
            can_execute=[],
            escalation_visibility="visible",
        ),
    )


def _make_gateway(constitution, captured_receipts):
    """Build a minimal SannaGateway stub for parent-chain testing."""
    from sanna.gateway.server import SannaGateway, DownstreamSpec, _DownstreamState
    from sanna.constitution import sign_constitution, constitution_to_receipt_ref

    gw = object.__new__(SannaGateway)

    spec = DownstreamSpec(name="mock", command=sys.executable, args=[])
    ds_state = _DownstreamState(spec=spec)

    class _FakeConn:
        tools = [
            {"name": "delete_all", "description": "d", "inputSchema": {"type": "object"}},
            {"name": "read_data", "description": "d", "inputSchema": {"type": "object"}},
        ]

    ds_state.connection = _FakeConn()
    gw._downstream_states = {"mock": ds_state}

    # SAN-396: sign constitution so _constitution_ref.policy_hash is present in
    # emitted receipts (constitution_ref is required by the SAN-358 verifier).
    signed_con = sign_constitution(constitution)
    gw._constitution = signed_con
    gw._constitution_ref = constitution_to_receipt_ref(signed_con)

    gw._reasoning_evaluator = None
    gw._manifest_emitted = False
    gw._manifest_full_fingerprint = None
    gw._suppressed_tool_names = set()
    gw._signing_key_path = None
    gw._content_mode = ""
    gw._content_mode_source = None
    gw._tool_to_downstream = {}

    async def _fake_persist(receipt):
        captured_receipts.append(receipt)

    gw._persist_receipt_async = _fake_persist
    return gw


class TestSessionManifestParentChain:
    def test_anomaly_chains_to_manifest(self):
        """invocation_anomaly.parent_receipts == [manifest.full_fingerprint]."""
        captured = []
        cons = _con(cannot_execute=["delete_all"])
        gw = _make_gateway(cons, captured)

        async def _run():
            tool_list = gw._build_tool_list()
            await gw._emit_session_manifest(tool_list)

            manifest_receipts = [r for r in captured if r.get("event_type") == "session_manifest"]
            assert len(manifest_receipts) == 1
            manifest_fp = manifest_receipts[0]["full_fingerprint"]
            assert manifest_fp == gw._manifest_full_fingerprint

            # "mock_delete_all" was suppressed -- should emit anomaly
            assert "mock_delete_all" in gw._suppressed_tool_names

            await gw._emit_invocation_anomaly("mock_delete_all", {})

            anomaly_receipts = [r for r in captured if r.get("event_type") == "invocation_anomaly"]
            assert len(anomaly_receipts) == 1
            anomaly = anomaly_receipts[0]
            assert anomaly["status"] == "FAIL"
            assert anomaly["enforcement"]["action"] == "halted"
            assert anomaly["enforcement"]["enforcement_mode"] == "halt"
            assert anomaly["parent_receipts"] == [manifest_fp]
            assert anomaly["extensions"]["com.sanna.anomaly"]["attempted_tool"] == "mock_delete_all"
            assert anomaly["extensions"]["com.sanna.anomaly"]["suppression_basis"] == "session_manifest"

            # SAN-396: bidirectional emission-verifier integration
            for r in manifest_receipts:
                checks = verify_session_manifest_receipt(r)
                fails = [c for c in checks if c.status == "FAIL"]
                assert not fails, f"Emitted manifest fails verifier: {[(c.name, c.message) for c in fails]}"

            for r in anomaly_receipts:
                checks = verify_invocation_anomaly_receipt(r, receipt_set=captured)
                fails = [c for c in checks if c.status == "FAIL"]
                assert not fails, f"Emitted anomaly fails verifier: {[(c.name, c.message) for c in fails]}"

        asyncio.run(_run())

    def test_forward_call_suppressed_tool_emits_anomaly(self):
        """_forward_call to a suppressed tool triggers anomaly emission."""
        captured = []
        cons = _con(cannot_execute=["delete_all"])
        gw = _make_gateway(cons, captured)

        async def _run():
            tool_list = gw._build_tool_list()
            await gw._emit_session_manifest(tool_list)
            manifest_fp = gw._manifest_full_fingerprint

            result = await gw._forward_call("mock_delete_all", {})
            assert result.isError

            anomaly_receipts = [r for r in captured if r.get("event_type") == "invocation_anomaly"]
            assert len(anomaly_receipts) == 1
            assert anomaly_receipts[0]["parent_receipts"] == [manifest_fp]

            # SAN-396: bidirectional emission-verifier integration
            manifest_receipts = [r for r in captured if r.get("event_type") == "session_manifest"]
            for r in manifest_receipts:
                checks = verify_session_manifest_receipt(r)
                fails = [c for c in checks if c.status == "FAIL"]
                assert not fails, f"Emitted manifest fails verifier: {[(c.name, c.message) for c in fails]}"

            for r in anomaly_receipts:
                checks = verify_invocation_anomaly_receipt(r, receipt_set=captured)
                fails = [c for c in checks if c.status == "FAIL"]
                assert not fails, f"Emitted anomaly fails verifier: {[(c.name, c.message) for c in fails]}"

        asyncio.run(_run())

    def test_typo_does_not_emit_anomaly(self):
        """_forward_call with a tool name not in suppressed set emits no anomaly."""
        captured = []
        cons = _con(cannot_execute=["delete_all"])
        gw = _make_gateway(cons, captured)

        async def _run():
            tool_list = gw._build_tool_list()
            await gw._emit_session_manifest(tool_list)

            result = await gw._forward_call("garbage_typo_name_xyz", {})
            assert result.isError

            anomaly_receipts = [r for r in captured if r.get("event_type") == "invocation_anomaly"]
            assert len(anomaly_receipts) == 0

        asyncio.run(_run())

    def test_no_anomaly_before_manifest_emitted(self):
        """_forward_call does not emit anomaly if manifest_full_fingerprint is None."""
        captured = []
        cons = _con(cannot_execute=["delete_all"])
        gw = _make_gateway(cons, captured)

        async def _run():
            # Build tool list (populates _suppressed_tool_names) but don't emit manifest
            gw._build_tool_list()
            assert gw._manifest_full_fingerprint is None

            result = await gw._forward_call("mock_delete_all", {})
            assert result.isError

            anomaly_receipts = [r for r in captured if r.get("event_type") == "invocation_anomaly"]
            assert len(anomaly_receipts) == 0

        asyncio.run(_run())

    def test_suppressed_tool_names_populated_by_build_tool_list(self):
        """_build_tool_list populates _suppressed_tool_names with prefixed names."""
        captured = []
        cons = _con(cannot_execute=["delete_all"])
        gw = _make_gateway(cons, captured)

        gw._build_tool_list()

        assert "mock_delete_all" in gw._suppressed_tool_names
        assert "mock_read_data" not in gw._suppressed_tool_names

    def test_build_tool_list_resets_suppressed_on_rebuild(self):
        """_build_tool_list clears _suppressed_tool_names on each call."""
        captured = []
        cons = _con(cannot_execute=["delete_all"])
        gw = _make_gateway(cons, captured)

        # First build
        gw._build_tool_list()
        assert "mock_delete_all" in gw._suppressed_tool_names

        # Switch to no constitution -- set should be empty after rebuild
        gw._constitution = None
        gw._build_tool_list()
        assert gw._suppressed_tool_names == set()

    def test_emitted_receipts_pass_verifier(self):
        """SAN-396: all captured emission outputs pass SAN-358 verifier (zero FAIL)."""
        captured = []
        cons = _con(cannot_execute=["delete_all"])
        gw = _make_gateway(cons, captured)

        async def run():
            tool_list = gw._build_tool_list()
            await gw._emit_session_manifest(tool_list)
            await gw._emit_invocation_anomaly("mock_delete_all", {})

        asyncio.run(run())

        for r in captured:
            et = r.get("event_type")
            if et == "session_manifest":
                checks = verify_session_manifest_receipt(r)
            elif et == "invocation_anomaly":
                checks = verify_invocation_anomaly_receipt(r, receipt_set=captured)
            else:
                continue
            fails = [c for c in checks if c.status == "FAIL"]
            assert not fails, (
                f"Emitted {et} receipt fails verifier check(s): "
                f"{[(c.name, c.message) for c in fails]}"
            )


class TestGatewayAnomalyRedaction:
    """SAN-406: Section 2.22.5 field-level redaction at gateway/server.py emission site."""

    def test_redacted_mode_masks_attempted_tool(self):
        captured = []
        cons = _con(cannot_execute=["delete_all"])
        gw = _make_gateway(cons, captured)
        gw._content_mode = "redacted"

        async def run():
            tool_list = gw._build_tool_list()
            await gw._emit_session_manifest(tool_list)
            await gw._emit_invocation_anomaly("mock_delete_all", {})

        asyncio.run(run())

        anomaly_receipts = [r for r in captured if r.get("event_type") == "invocation_anomaly"]
        assert len(anomaly_receipts) == 1
        ext = anomaly_receipts[0].get("extensions", {}).get("com.sanna.anomaly", {})
        assert ext.get("attempted_tool") == "<redacted>"

    def test_hashes_only_mode_hashes_attempted_tool(self):
        import re
        _SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
        captured = []
        cons = _con(cannot_execute=["delete_all"])
        gw = _make_gateway(cons, captured)
        gw._content_mode = "hashes_only"

        async def run():
            tool_list = gw._build_tool_list()
            await gw._emit_session_manifest(tool_list)
            await gw._emit_invocation_anomaly("mock_delete_all", {})

        asyncio.run(run())

        anomaly_receipts = [r for r in captured if r.get("event_type") == "invocation_anomaly"]
        assert len(anomaly_receipts) == 1
        ext = anomaly_receipts[0].get("extensions", {}).get("com.sanna.anomaly", {})
        val = ext.get("attempted_tool")
        assert _SHA256_HEX_RE.match(val), f"{val!r} not 64-hex lowercase"

    def test_hashes_only_is_deterministic_across_calls(self):
        captured = []
        cons = _con(cannot_execute=["delete_all"])
        gw = _make_gateway(cons, captured)
        gw._content_mode = "hashes_only"

        async def run():
            tool_list = gw._build_tool_list()
            await gw._emit_session_manifest(tool_list)
            await gw._emit_invocation_anomaly("mock_delete_all", {})
            await gw._emit_invocation_anomaly("mock_delete_all", {})

        asyncio.run(run())

        anomaly_receipts = [r for r in captured if r.get("event_type") == "invocation_anomaly"]
        assert len(anomaly_receipts) == 2
        hash1 = anomaly_receipts[0]["extensions"]["com.sanna.anomaly"]["attempted_tool"]
        hash2 = anomaly_receipts[1]["extensions"]["com.sanna.anomaly"]["attempted_tool"]
        assert hash1 == hash2, "Same tool name should hash to same value"

    def test_redacted_mode_passes_verifier(self):
        """SAN-406: redacted receipt passes verifier redaction_markers_correct check."""
        captured = []
        cons = _con(cannot_execute=["delete_all"])
        gw = _make_gateway(cons, captured)
        gw._content_mode = "redacted"

        async def run():
            tool_list = gw._build_tool_list()
            await gw._emit_session_manifest(tool_list)
            await gw._emit_invocation_anomaly("mock_delete_all", {})

        asyncio.run(run())

        for r in captured:
            et = r.get("event_type")
            if et == "session_manifest":
                checks = verify_session_manifest_receipt(r)
            elif et == "invocation_anomaly":
                checks = verify_invocation_anomaly_receipt(r, receipt_set=captured)
            else:
                continue
            fails = [c for c in checks if c.status == "FAIL"]
            assert not fails, (
                f"Emitted {et} receipt (redacted mode) fails verifier: "
                f"{[(c.name, c.message) for c in fails]}"
            )
