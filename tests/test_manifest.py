"""SAN-202: Manifest Phase 1 tests."""

import pytest

from sanna.manifest import (
    generate_manifest,
    SUPPRESSION_REASON_CANNOT_EXECUTE,
    SUPPRESSION_REASON_ESCALATION_SUPPRESSED,
    SUPPRESSION_REASON_CONSTITUTION_INVALID,
    MANIFEST_VERSION,
    VALID_SUPPRESSION_REASONS,
)
from sanna.constitution import (
    Constitution,
    AgentIdentity,
    Provenance,
    Boundary,
    AuthorityBoundaries,
    EscalationRule,
    CliPermissions,
    CliCommand,
    ApiPermissions,
    ApiEndpoint,
)


# =============================================================================
# HELPERS
# =============================================================================

def _bare_constitution(
    cannot_execute: list[str] | None = None,
    must_escalate: list[EscalationRule] | None = None,
    can_execute: list[str] | None = None,
    escalation_visibility: str = "visible",
    cli_permissions: CliPermissions | None = None,
    api_permissions: ApiPermissions | None = None,
    no_authority_boundaries: bool = False,
) -> Constitution:
    """Build a minimal Constitution for manifest tests."""
    if no_authority_boundaries:
        ab = None
    else:
        ab = AuthorityBoundaries(
            cannot_execute=cannot_execute or [],
            must_escalate=must_escalate or [],
            can_execute=can_execute or [],
            escalation_visibility=escalation_visibility,
        )
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
        authority_boundaries=ab,
        cli_permissions=cli_permissions,
        api_permissions=api_permissions,
    )


# =============================================================================
# 1. Top-level structure
# =============================================================================

class TestManifestTopLevel:
    def test_version_and_basis(self):
        c = _bare_constitution()
        out = generate_manifest(c)
        assert out["version"] == MANIFEST_VERSION
        assert out["composition_basis"] == "static"
        assert "surfaces" in out

    def test_no_mcp_tools_omits_mcp_surface(self):
        c = _bare_constitution()
        out = generate_manifest(c, mcp_tools=None)
        assert "mcp" not in out["surfaces"]

    def test_mcp_tools_empty_list_includes_mcp_surface(self):
        c = _bare_constitution()
        out = generate_manifest(c, mcp_tools=[])
        assert "mcp" in out["surfaces"]
        assert out["surfaces"]["mcp"]["tools_delivered"] == []
        assert out["surfaces"]["mcp"]["tools_suppressed"] == []

    def test_no_cli_permissions_omits_cli_surface(self):
        c = _bare_constitution()
        out = generate_manifest(c)
        assert "cli" not in out["surfaces"]

    def test_no_api_permissions_omits_http_surface(self):
        c = _bare_constitution()
        out = generate_manifest(c)
        assert "http" not in out["surfaces"]


# =============================================================================
# 2. MCP surface -- cannot_execute suppression
# =============================================================================

class TestMcpCannotExecute:
    def test_cannot_execute_suppresses_tool(self):
        c = _bare_constitution(cannot_execute=["delete_all"])
        out = generate_manifest(c, mcp_tools=["delete_all", "read_data"])
        mcp = out["surfaces"]["mcp"]
        assert "read_data" in mcp["tools_delivered"]
        assert "delete_all" in mcp["tools_suppressed"]

    def test_cannot_execute_reason(self):
        c = _bare_constitution(cannot_execute=["nuke_db"])
        out = generate_manifest(c, mcp_tools=["nuke_db"])
        mcp = out["surfaces"]["mcp"]
        assert mcp["suppression_reasons"]["nuke_db"] == SUPPRESSION_REASON_CANNOT_EXECUTE

    def test_suppression_reason_in_valid_enum(self):
        c = _bare_constitution(cannot_execute=["forbidden"])
        out = generate_manifest(c, mcp_tools=["forbidden"])
        reason = out["surfaces"]["mcp"]["suppression_reasons"]["forbidden"]
        assert reason in VALID_SUPPRESSION_REASONS


# =============================================================================
# 3. MCP surface -- escalation_visibility
# =============================================================================

class TestMcpEscalationVisibility:
    def test_escalation_visible_includes_must_escalate(self):
        c = _bare_constitution(
            must_escalate=[EscalationRule(condition="anything")],
            escalation_visibility="visible",
        )
        out = generate_manifest(c, mcp_tools=["anything"])
        assert "anything" in out["surfaces"]["mcp"]["tools_delivered"]
        assert "anything" not in out["surfaces"]["mcp"]["tools_suppressed"]

    def test_escalation_suppressed_hides_must_escalate(self):
        c = _bare_constitution(
            must_escalate=[EscalationRule(condition="anything")],
            escalation_visibility="suppressed",
        )
        out = generate_manifest(c, mcp_tools=["anything"])
        mcp = out["surfaces"]["mcp"]
        assert "anything" in mcp["tools_suppressed"]
        assert "anything" not in mcp["tools_delivered"]
        assert mcp["suppression_reasons"]["anything"] == SUPPRESSION_REASON_ESCALATION_SUPPRESSED

    def test_escalation_default_is_visible(self):
        c = _bare_constitution(
            must_escalate=[EscalationRule(condition="review_data")],
        )
        out = generate_manifest(c, mcp_tools=["review_data"])
        assert "review_data" in out["surfaces"]["mcp"]["tools_delivered"]


# =============================================================================
# 4. Fail-closed on no constitution / no authority_boundaries
# =============================================================================

class TestFailClosed:
    def test_none_constitution_suppresses_all(self):
        out = generate_manifest(None, mcp_tools=["x", "y"])
        mcp = out["surfaces"]["mcp"]
        assert mcp["tools_delivered"] == []
        assert sorted(mcp["tools_suppressed"]) == ["x", "y"]

    def test_none_constitution_reason_is_constitution_invalid(self):
        out = generate_manifest(None, mcp_tools=["x"])
        mcp = out["surfaces"]["mcp"]
        assert mcp["suppression_reasons"]["x"] == SUPPRESSION_REASON_CONSTITUTION_INVALID

    def test_no_authority_boundaries_suppresses_all(self):
        c = _bare_constitution(no_authority_boundaries=True)
        out = generate_manifest(c, mcp_tools=["a", "b"])
        mcp = out["surfaces"]["mcp"]
        assert mcp["tools_delivered"] == []
        for name in ["a", "b"]:
            assert name in mcp["tools_suppressed"]
            assert mcp["suppression_reasons"][name] == SUPPRESSION_REASON_CONSTITUTION_INVALID

    def test_none_constitution_omits_cli_and_http(self):
        out = generate_manifest(None)
        assert "cli" not in out["surfaces"]
        assert "http" not in out["surfaces"]


# =============================================================================
# 5. Determinism and no-overlap invariants
# =============================================================================

class TestDeterminism:
    def test_delivered_sorted(self):
        c = _bare_constitution(can_execute=["aaa", "mmm", "zzz"])
        out = generate_manifest(c, mcp_tools=["zzz", "mmm", "aaa"])
        mcp = out["surfaces"]["mcp"]
        assert mcp["tools_delivered"] == sorted(mcp["tools_delivered"])

    def test_suppressed_sorted(self):
        c = _bare_constitution(cannot_execute=["zzz", "mmm"])
        out = generate_manifest(c, mcp_tools=["zzz", "mmm", "aaa"])
        mcp = out["surfaces"]["mcp"]
        assert mcp["tools_suppressed"] == sorted(mcp["tools_suppressed"])

    def test_no_overlap_delivered_suppressed(self):
        c = _bare_constitution(
            cannot_execute=["x"],
            can_execute=["y"],
        )
        out = generate_manifest(c, mcp_tools=["x", "y"])
        mcp = out["surfaces"]["mcp"]
        assert set(mcp["tools_delivered"]).isdisjoint(set(mcp["tools_suppressed"]))

    def test_idempotent_same_inputs(self):
        c = _bare_constitution(cannot_execute=["del"], can_execute=["get"])
        tools = ["get", "del", "set"]
        out1 = generate_manifest(c, mcp_tools=tools)
        out2 = generate_manifest(c, mcp_tools=tools)
        assert out1 == out2


# =============================================================================
# 6. CLI surface
# =============================================================================

class TestCliSurface:
    def _make_cli(self, commands: list[CliCommand], mode: str = "strict") -> CliPermissions:
        return CliPermissions(mode=mode, commands=commands)

    def test_can_execute_delivered(self):
        cli = self._make_cli([
            CliCommand(id="c1", binary="ls", authority="can_execute"),
        ])
        c = _bare_constitution(cli_permissions=cli)
        out = generate_manifest(c)
        assert "ls" in out["surfaces"]["cli"]["patterns_delivered"]
        assert out["surfaces"]["cli"]["suppression_reasons"] == {}

    def test_cannot_execute_suppressed(self):
        cli = self._make_cli([
            CliCommand(id="c1", binary="rm", authority="cannot_execute"),
        ])
        c = _bare_constitution(cli_permissions=cli)
        out = generate_manifest(c)
        assert "rm" in out["surfaces"]["cli"]["patterns_suppressed"]
        assert "rm" not in out["surfaces"]["cli"]["patterns_delivered"]
        assert out["surfaces"]["cli"]["suppression_reasons"] == {"rm": "cannot_execute"}

    def test_must_escalate_visible(self):
        cli = self._make_cli([
            CliCommand(id="c1", binary="sudo", authority="must_escalate"),
        ])
        c = _bare_constitution(cli_permissions=cli, escalation_visibility="visible")
        out = generate_manifest(c)
        assert "sudo" in out["surfaces"]["cli"]["patterns_delivered"]
        assert out["surfaces"]["cli"]["suppression_reasons"] == {}

    def test_must_escalate_suppressed(self):
        cli = self._make_cli([
            CliCommand(id="c1", binary="sudo", authority="must_escalate"),
        ])
        c = _bare_constitution(cli_permissions=cli, escalation_visibility="suppressed")
        out = generate_manifest(c)
        assert "sudo" in out["surfaces"]["cli"]["patterns_suppressed"]
        assert out["surfaces"]["cli"]["suppression_reasons"] == {"sudo": "escalation_suppressed"}

    def test_mode_passed_through(self):
        cli = self._make_cli([], mode="permissive")
        c = _bare_constitution(cli_permissions=cli)
        out = generate_manifest(c)
        assert out["surfaces"]["cli"]["mode"] == "permissive"

    def test_patterns_sorted(self):
        cli = self._make_cli([
            CliCommand(id="c1", binary="zzz", authority="can_execute"),
            CliCommand(id="c2", binary="aaa", authority="can_execute"),
        ])
        c = _bare_constitution(cli_permissions=cli)
        delivered = out = generate_manifest(c)["surfaces"]["cli"]["patterns_delivered"]
        assert delivered == sorted(delivered)


# =============================================================================
# 7. HTTP surface
# =============================================================================

class TestHttpSurface:
    def _make_api(self, endpoints: list[ApiEndpoint], mode: str = "strict") -> ApiPermissions:
        return ApiPermissions(mode=mode, endpoints=endpoints)

    def test_can_execute_delivered(self):
        api = self._make_api([
            ApiEndpoint(id="e1", url_pattern="/api/read", authority="can_execute"),
        ])
        c = _bare_constitution(api_permissions=api)
        out = generate_manifest(c)
        assert "/api/read" in out["surfaces"]["http"]["patterns_delivered"]
        assert out["surfaces"]["http"]["suppression_reasons"] == {}

    def test_cannot_execute_suppressed(self):
        api = self._make_api([
            ApiEndpoint(id="e1", url_pattern="/admin/*", authority="cannot_execute"),
        ])
        c = _bare_constitution(api_permissions=api)
        out = generate_manifest(c)
        assert "/admin/*" in out["surfaces"]["http"]["patterns_suppressed"]
        assert out["surfaces"]["http"]["suppression_reasons"] == {"/admin/*": "cannot_execute"}

    def test_must_escalate_visible(self):
        api = self._make_api([
            ApiEndpoint(id="e1", url_pattern="/api/delete", authority="must_escalate"),
        ])
        c = _bare_constitution(api_permissions=api, escalation_visibility="visible")
        out = generate_manifest(c)
        assert "/api/delete" in out["surfaces"]["http"]["patterns_delivered"]
        assert out["surfaces"]["http"]["suppression_reasons"] == {}

    def test_must_escalate_suppressed(self):
        api = self._make_api([
            ApiEndpoint(id="e1", url_pattern="/api/delete", authority="must_escalate"),
        ])
        c = _bare_constitution(api_permissions=api, escalation_visibility="suppressed")
        out = generate_manifest(c)
        assert "/api/delete" in out["surfaces"]["http"]["patterns_suppressed"]
        assert out["surfaces"]["http"]["suppression_reasons"] == {"/api/delete": "escalation_suppressed"}

    def test_mode_passed_through(self):
        api = self._make_api([], mode="permissive")
        c = _bare_constitution(api_permissions=api)
        out = generate_manifest(c)
        assert out["surfaces"]["http"]["mode"] == "permissive"


# =============================================================================
# 8. Gateway _build_tool_list filtering (SAN-202 scope item 2)
# =============================================================================

class TestGatewayFilteringUnit:
    """Unit-level tests for _build_tool_list authority filtering.

    Uses SannaGateway._build_tool_list() directly with a mocked
    _downstream_states so no actual subprocess is launched. This
    validates the filtering logic independently of the full gateway
    lifecycle.
    """

    def _make_gateway_with_mocked_downstream(
        self,
        tools: list[dict],
        constitution: Constitution | None,
    ):
        """Build a SannaGateway with an injected mock downstream."""
        pytest.importorskip("mcp", reason="mcp extra not installed")

        import sys
        from sanna.gateway.server import SannaGateway, DownstreamSpec, _DownstreamState

        gw = object.__new__(SannaGateway)

        # Minimal gateway state required by _build_tool_list
        spec = DownstreamSpec(name="mock", command=sys.executable, args=[])
        ds_state = _DownstreamState(spec=spec)

        # Inject a fake connection with the given tool dicts
        class _FakeConnection:
            pass

        fake_conn = _FakeConnection()
        fake_conn.tools = tools
        ds_state.connection = fake_conn

        gw._downstream_states = {"mock": ds_state}
        gw._constitution = constitution
        gw._reasoning_evaluator = None

        return gw

    def test_no_constitution_passes_all_through(self):
        pytest.importorskip("mcp", reason="mcp extra not installed")
        from sanna.gateway.server import _META_TOOL_NAMES

        tools = [
            {"name": "get_data", "description": "d", "inputSchema": {"type": "object"}},
            {"name": "delete_all", "description": "d", "inputSchema": {"type": "object"}},
        ]
        gw = self._make_gateway_with_mocked_downstream(tools, constitution=None)
        result = gw._build_tool_list()
        names = {t.name for t in result if t.name not in _META_TOOL_NAMES}
        assert "mock_get_data" in names
        assert "mock_delete_all" in names

    def test_cannot_execute_suppressed_from_list(self):
        pytest.importorskip("mcp", reason="mcp extra not installed")
        from sanna.gateway.server import _META_TOOL_NAMES

        tools = [
            {"name": "get_data", "description": "d", "inputSchema": {"type": "object"}},
            {"name": "delete_all", "description": "d", "inputSchema": {"type": "object"}},
        ]
        c = _bare_constitution(cannot_execute=["delete_all"])
        gw = self._make_gateway_with_mocked_downstream(tools, constitution=c)
        result = gw._build_tool_list()
        names = {t.name for t in result if t.name not in _META_TOOL_NAMES}
        assert "mock_get_data" in names
        assert "mock_delete_all" not in names

    def test_must_escalate_visible_included(self):
        pytest.importorskip("mcp", reason="mcp extra not installed")
        from sanna.gateway.server import _META_TOOL_NAMES

        tools = [
            {"name": "review_data", "description": "d", "inputSchema": {"type": "object"}},
        ]
        c = _bare_constitution(
            must_escalate=[EscalationRule(condition="review_data")],
            escalation_visibility="visible",
        )
        gw = self._make_gateway_with_mocked_downstream(tools, constitution=c)
        result = gw._build_tool_list()
        names = {t.name for t in result if t.name not in _META_TOOL_NAMES}
        assert "mock_review_data" in names

    def test_must_escalate_suppressed_excluded(self):
        pytest.importorskip("mcp", reason="mcp extra not installed")
        from sanna.gateway.server import _META_TOOL_NAMES

        tools = [
            {"name": "review_data", "description": "d", "inputSchema": {"type": "object"}},
        ]
        c = _bare_constitution(
            must_escalate=[EscalationRule(condition="review_data")],
            escalation_visibility="suppressed",
        )
        gw = self._make_gateway_with_mocked_downstream(tools, constitution=c)
        result = gw._build_tool_list()
        names = {t.name for t in result if t.name not in _META_TOOL_NAMES}
        assert "mock_review_data" not in names


# =============================================================================
# 9. Single-emission semantics (_manifest_emitted flag)
# =============================================================================

class TestManifestEmittedFlag:
    """Tests that _manifest_emitted prevents duplicate session_manifest receipts."""

    def test_manifest_emitted_false_on_init(self):
        pytest.importorskip("mcp", reason="mcp extra not installed")
        import sys
        from sanna.gateway.server import SannaGateway

        with pytest.warns(DeprecationWarning):
            gw = SannaGateway(
                server_name="test",
                command=sys.executable,
                args=[],
            )
        assert gw._manifest_emitted is False

    def test_emit_session_manifest_sets_flag(self):
        """Calling handle_list_tools sets _manifest_emitted=True on first call."""
        pytest.importorskip("mcp", reason="mcp extra not installed")
        import asyncio
        import sys
        from sanna.gateway.server import SannaGateway, _DownstreamState, DownstreamSpec

        gw = object.__new__(SannaGateway)
        spec = DownstreamSpec(name="mock", command=sys.executable, args=[])
        ds_state = _DownstreamState(spec=spec)

        class _FakeConn:
            tools = []

        ds_state.connection = _FakeConn()
        gw._downstream_states = {"mock": ds_state}
        gw._constitution = _bare_constitution()
        gw._reasoning_evaluator = None
        gw._manifest_emitted = False

        emitted_receipts = []

        async def _fake_persist(receipt):
            emitted_receipts.append(receipt)

        gw._persist_receipt_async = _fake_persist
        gw._constitution_ref = None
        gw._signing_key_path = None
        gw._content_mode = ""  # SAN-206: required by _emit_session_manifest

        async def _run():
            # Simulate what handle_list_tools does
            tool_list = gw._build_tool_list()
            if not gw._manifest_emitted and gw._constitution is not None:
                await gw._emit_session_manifest(tool_list)
                gw._manifest_emitted = True

            assert gw._manifest_emitted is True
            assert len(emitted_receipts) == 1

            # Second call -- should not emit
            tool_list2 = gw._build_tool_list()
            if not gw._manifest_emitted and gw._constitution is not None:
                await gw._emit_session_manifest(tool_list2)
                gw._manifest_emitted = True

            assert len(emitted_receipts) == 1  # still 1, not 2

        asyncio.run(_run())

    def test_session_manifest_receipt_has_correct_event_type(self):
        """Emitted receipt has event_type='session_manifest'."""
        pytest.importorskip("mcp", reason="mcp extra not installed")
        import asyncio
        import sys
        from sanna.gateway.server import SannaGateway, _DownstreamState, DownstreamSpec

        gw = object.__new__(SannaGateway)
        spec = DownstreamSpec(name="mock", command=sys.executable, args=[])
        ds_state = _DownstreamState(spec=spec)

        class _FakeConn:
            tools = []

        ds_state.connection = _FakeConn()
        gw._downstream_states = {"mock": ds_state}
        gw._constitution = _bare_constitution()
        gw._reasoning_evaluator = None
        gw._manifest_emitted = False

        captured = []

        async def _fake_persist(receipt):
            captured.append(receipt)

        gw._persist_receipt_async = _fake_persist
        gw._constitution_ref = None
        gw._signing_key_path = None
        gw._content_mode = ""  # SAN-206: required by _emit_session_manifest

        async def _run():
            await gw._emit_session_manifest([])
            assert len(captured) == 1
            receipt = captured[0]
            assert receipt.get("event_type") == "session_manifest"
            assert receipt.get("invariants_scope") == "none"
            assert "enforcement" not in receipt or receipt.get("enforcement") is None
            assert receipt.get("status") == "PASS"

        asyncio.run(_run())

    def test_no_constitution_no_emission(self):
        """No manifest receipt when constitution is None."""
        pytest.importorskip("mcp", reason="mcp extra not installed")
        import sys
        from sanna.gateway.server import SannaGateway, _DownstreamState, DownstreamSpec

        gw = object.__new__(SannaGateway)
        spec = DownstreamSpec(name="mock", command=sys.executable, args=[])
        ds_state = _DownstreamState(spec=spec)

        class _FakeConn:
            tools = []

        ds_state.connection = _FakeConn()
        gw._downstream_states = {"mock": ds_state}
        gw._constitution = None
        gw._reasoning_evaluator = None
        gw._manifest_emitted = False

        # Simulate handle_list_tools logic
        gw._build_tool_list()
        # The condition "gateway._constitution is not None" should block emission
        assert gw._manifest_emitted is False


# =============================================================================
# SAN-487: get_suppressed_patterns helper unit tests
# =============================================================================

class TestGetSuppressedPatterns:
    """SAN-487: unit tests for the get_suppressed_patterns helper.

    Validates the helper returns the RAW (unredacted) set of suppressed
    patterns directly from constitution data, regardless of content_mode.
    The integration tests in test_cli_anomaly.py and test_http_anomaly.py
    cover the end-to-end path; these tests cover the helper in isolation.
    """

    def test_cli_cannot_execute_returns_binary(self):
        from sanna.manifest import get_suppressed_patterns
        constitution = _bare_constitution(
            cli_permissions=CliPermissions(
                commands=[CliCommand(id="c1", binary="rm", authority="cannot_execute")]
            ),
            escalation_visibility="visible",
        )
        result = get_suppressed_patterns(constitution, "cli")
        assert result == {"rm"}

    def test_cli_must_escalate_visible_NOT_suppressed(self):
        from sanna.manifest import get_suppressed_patterns
        constitution = _bare_constitution(
            cli_permissions=CliPermissions(
                commands=[CliCommand(id="c1", binary="sudo", authority="must_escalate")]
            ),
            escalation_visibility="visible",
        )
        result = get_suppressed_patterns(constitution, "cli")
        assert result == set(), "must_escalate + visibility=visible should NOT suppress"

    def test_cli_must_escalate_suppressed_visibility_IS_suppressed(self):
        from sanna.manifest import get_suppressed_patterns
        constitution = _bare_constitution(
            cli_permissions=CliPermissions(
                commands=[CliCommand(id="c1", binary="curl", authority="must_escalate")]
            ),
            escalation_visibility="suppressed",
        )
        result = get_suppressed_patterns(constitution, "cli")
        assert result == {"curl"}, "must_escalate + visibility=suppressed MUST suppress"

    def test_cli_can_execute_NOT_suppressed(self):
        from sanna.manifest import get_suppressed_patterns
        constitution = _bare_constitution(
            cli_permissions=CliPermissions(
                commands=[CliCommand(id="c1", binary="ls", authority="can_execute")]
            ),
            escalation_visibility="visible",
        )
        result = get_suppressed_patterns(constitution, "cli")
        assert result == set()

    def test_cli_no_permissions_returns_empty(self):
        from sanna.manifest import get_suppressed_patterns
        constitution = _bare_constitution()
        result = get_suppressed_patterns(constitution, "cli")
        assert result == set()

    def test_http_cannot_execute_returns_url_pattern(self):
        from sanna.manifest import get_suppressed_patterns
        constitution = _bare_constitution(
            api_permissions=ApiPermissions(
                endpoints=[ApiEndpoint(
                    id="e1",
                    url_pattern="https://internal.evil.com/*",
                    authority="cannot_execute",
                )]
            ),
            escalation_visibility="visible",
        )
        result = get_suppressed_patterns(constitution, "http")
        assert result == {"https://internal.evil.com/*"}

    def test_http_no_permissions_returns_empty(self):
        from sanna.manifest import get_suppressed_patterns
        constitution = _bare_constitution()
        result = get_suppressed_patterns(constitution, "http")
        assert result == set()

    def test_invalid_surface_raises(self):
        from sanna.manifest import get_suppressed_patterns
        constitution = _bare_constitution()
        with pytest.raises(ValueError, match="unknown surface"):
            get_suppressed_patterns(constitution, "mcp")  # type: ignore

    def test_no_content_mode_parameter(self):
        """SAN-487 design: helper does NOT take content_mode. Enforcement state
        is content-mode-independent. This test guards against accidentally
        adding a content_mode parameter in a future refactor.
        """
        import inspect
        from sanna.manifest import get_suppressed_patterns
        sig = inspect.signature(get_suppressed_patterns)
        params = set(sig.parameters.keys())
        assert "content_mode" not in params, (
            "SAN-487: get_suppressed_patterns MUST NOT take content_mode -- "
            "enforcement state is content-mode-independent"
        )
        assert params == {"constitution", "surface"}, (
            f"unexpected parameters: {params}"
        )
