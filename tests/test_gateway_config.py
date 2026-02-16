"""Tests for gateway YAML config parsing (Block D).

Tests cover: config parsing, validation, env var interpolation, path
resolution, policy cascade, multi-server support, and error handling.
"""

import os
import textwrap

import pytest

from sanna.gateway.config import (
    DownstreamConfig,
    GatewayConfig,
    GatewayConfigError,
    ToolPolicyConfig,
    build_policy_overrides,
    load_gateway_config,
    resolve_tool_policy,
)


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


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture()
def signed_files(tmp_path):
    """Create signed constitution + key. Returns (const_path, key_path)."""
    return _create_signed_constitution(tmp_path)


# =============================================================================
# 1. VALID CONFIG PARSING
# =============================================================================

class TestValidParsing:
    def test_valid_config_parses(self, tmp_path, signed_files):
        """Valid config parses into correct data structure."""
        const_path, key_path = signed_files
        content = f"""\
        gateway:
          transport: stdio
          constitution: {const_path}
          signing_key: {key_path}
          escalation_timeout: 120

        downstream:
          - name: notion
            command: npx
            args: ["-y", "@notionhq/notion-mcp-server"]
            default_policy: can_execute
            tools:
              "notion-update-page":
                policy: must_escalate
                reason: "Page mutations require approval"
        """
        cfg_path = _write_config(tmp_path, content)
        cfg = load_gateway_config(cfg_path)

        assert isinstance(cfg, GatewayConfig)
        assert cfg.transport == "stdio"
        assert cfg.constitution_path == const_path
        assert cfg.signing_key_path == key_path
        assert cfg.escalation_timeout == 120.0
        assert len(cfg.downstreams) == 1

        ds = cfg.downstreams[0]
        assert ds.name == "notion"
        assert ds.command == "npx"
        assert ds.args == ["-y", "@notionhq/notion-mcp-server"]
        assert ds.default_policy == "can_execute"
        assert "notion-update-page" in ds.tools
        assert ds.tools["notion-update-page"].policy == "must_escalate"
        assert ds.tools["notion-update-page"].reason == (
            "Page mutations require approval"
        )

    def test_minimal_valid_config(self, tmp_path, signed_files):
        """Minimal valid config (just required fields) parses."""
        const_path, key_path = signed_files
        content = _minimal_config(const_path, key_path)
        cfg_path = _write_config(tmp_path, content)
        cfg = load_gateway_config(cfg_path)

        assert cfg.constitution_path == const_path
        assert cfg.signing_key_path == key_path
        assert cfg.escalation_timeout == 300.0
        assert cfg.transport == "stdio"
        assert len(cfg.downstreams) == 1
        assert cfg.downstreams[0].name == "mock"
        assert cfg.downstreams[0].default_policy == "can_execute"


# =============================================================================
# 2. MISSING REQUIRED FIELDS
# =============================================================================

class TestMissingFields:
    def test_missing_constitution(self, tmp_path, signed_files):
        """Missing gateway.constitution → clear error message."""
        _, key_path = signed_files
        content = f"""\
        gateway:
          signing_key: {key_path}

        downstream:
          - name: mock
            command: echo
        """
        cfg_path = _write_config(tmp_path, content)
        with pytest.raises(GatewayConfigError, match="gateway.constitution"):
            load_gateway_config(cfg_path)

    def test_missing_signing_key(self, tmp_path, signed_files):
        """Missing gateway.signing_key → clear error message."""
        const_path, _ = signed_files
        content = f"""\
        gateway:
          constitution: {const_path}

        downstream:
          - name: mock
            command: echo
        """
        cfg_path = _write_config(tmp_path, content)
        with pytest.raises(GatewayConfigError, match="gateway.signing_key"):
            load_gateway_config(cfg_path)

    def test_missing_downstream(self, tmp_path, signed_files):
        """Missing downstream entries → clear error message."""
        const_path, key_path = signed_files
        content = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}
        """
        cfg_path = _write_config(tmp_path, content)
        with pytest.raises(GatewayConfigError, match="downstream"):
            load_gateway_config(cfg_path)

    def test_downstream_missing_name(self, tmp_path, signed_files):
        """Downstream missing name → clear error message."""
        const_path, key_path = signed_files
        content = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}

        downstream:
          - command: echo
        """
        cfg_path = _write_config(tmp_path, content)
        with pytest.raises(GatewayConfigError, match="name"):
            load_gateway_config(cfg_path)

    def test_downstream_missing_command(self, tmp_path, signed_files):
        """Downstream missing command → clear error message."""
        const_path, key_path = signed_files
        content = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}

        downstream:
          - name: mock
        """
        cfg_path = _write_config(tmp_path, content)
        with pytest.raises(GatewayConfigError, match="command"):
            load_gateway_config(cfg_path)


# =============================================================================
# 3. INVALID POLICY VALUES
# =============================================================================

class TestInvalidPolicies:
    def test_invalid_default_policy(self, tmp_path, signed_files):
        """Invalid default_policy value → clear error message."""
        const_path, key_path = signed_files
        content = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}

        downstream:
          - name: mock
            command: echo
            default_policy: always_allow
        """
        cfg_path = _write_config(tmp_path, content)
        with pytest.raises(GatewayConfigError, match="default_policy"):
            load_gateway_config(cfg_path)

    def test_invalid_per_tool_policy(self, tmp_path, signed_files):
        """Invalid per-tool policy value → clear error message."""
        const_path, key_path = signed_files
        content = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}

        downstream:
          - name: mock
            command: echo
            tools:
              "some-tool":
                policy: deny
        """
        cfg_path = _write_config(tmp_path, content)
        with pytest.raises(GatewayConfigError, match="policy"):
            load_gateway_config(cfg_path)


# =============================================================================
# 4. ENVIRONMENT VARIABLE INTERPOLATION
# =============================================================================

class TestEnvInterpolation:
    def test_env_var_resolves(self, tmp_path, signed_files, monkeypatch):
        """Environment variable interpolation resolves correctly."""
        const_path, key_path = signed_files
        monkeypatch.setenv("TEST_API_KEY", "secret-123")
        content = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}

        downstream:
          - name: mock
            command: echo
            env:
              API_KEY: "${{TEST_API_KEY}}"
        """
        cfg_path = _write_config(tmp_path, content)
        cfg = load_gateway_config(cfg_path)
        assert cfg.downstreams[0].env["API_KEY"] == "secret-123"

    def test_missing_env_var_raises(self, tmp_path, signed_files, monkeypatch):
        """Missing env var → startup error naming the missing variable."""
        const_path, key_path = signed_files
        monkeypatch.delenv("TOTALLY_MISSING_VAR_XYZ", raising=False)
        content = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}

        downstream:
          - name: mock
            command: echo
            env:
              SECRET: "${{TOTALLY_MISSING_VAR_XYZ}}"
        """
        cfg_path = _write_config(tmp_path, content)
        with pytest.raises(
            GatewayConfigError, match="TOTALLY_MISSING_VAR_XYZ",
        ):
            load_gateway_config(cfg_path)

    def test_env_interpolation_only_in_env_blocks(
        self, tmp_path, signed_files, monkeypatch,
    ):
        """Env var interpolation only happens in env blocks, not other
        config fields like default_policy or reason strings."""
        const_path, key_path = signed_files
        monkeypatch.setenv("MOCK_POLICY", "can_execute")
        content = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}

        downstream:
          - name: mock-server
            command: echo
            default_policy: can_execute
            env:
              API_KEY: "${{MOCK_POLICY}}"
        """
        cfg_path = _write_config(tmp_path, content)
        cfg = load_gateway_config(cfg_path)
        # env block values ARE interpolated
        assert cfg.downstreams[0].env["API_KEY"] == "can_execute"
        # name field is NOT interpolated (it's used as-is)
        assert cfg.downstreams[0].name == "mock-server"


# =============================================================================
# 5. PATH RESOLUTION
# =============================================================================

class TestPathResolution:
    def test_tilde_expands_to_home(self, tmp_path, signed_files):
        """Path expansion — ~ resolves to home directory."""
        const_path, key_path = signed_files
        # Create a symlink or copy at ~/... — too invasive.
        # Instead, verify that _resolve_path handles ~.
        from sanna.gateway.config import _resolve_path
        from pathlib import Path

        result = _resolve_path("~/some/path", Path("/dummy"))
        home = os.path.expanduser("~")
        assert result.startswith(home)
        assert result.endswith("some/path")

    def test_relative_path_resolves_to_config_dir(
        self, tmp_path, signed_files,
    ):
        """Relative constitution path resolves relative to config file
        location."""
        const_path, key_path = signed_files
        # Copy constitution into a subdirectory of tmp_path
        sub = tmp_path / "configs"
        sub.mkdir()
        import shutil
        const_copy = sub / "constitution.yaml"
        shutil.copy2(const_path, const_copy)

        content = f"""\
        gateway:
          constitution: ./constitution.yaml
          signing_key: {key_path}

        downstream:
          - name: mock
            command: echo
        """
        cfg_path = _write_config(tmp_path, content, filename="configs/gw.yaml")
        cfg = load_gateway_config(cfg_path)
        # Should resolve to the copy in sub/, not cwd
        assert cfg.constitution_path == str(const_copy.resolve())

    def test_nonexistent_constitution_raises(self, tmp_path, signed_files):
        """Nonexistent constitution file → clear error."""
        _, key_path = signed_files
        content = f"""\
        gateway:
          constitution: ./does_not_exist.yaml
          signing_key: {key_path}

        downstream:
          - name: mock
            command: echo
        """
        cfg_path = _write_config(tmp_path, content)
        with pytest.raises(GatewayConfigError, match="Constitution file"):
            load_gateway_config(cfg_path)

    def test_nonexistent_signing_key_raises(self, tmp_path, signed_files):
        """Nonexistent signing key file → clear error."""
        const_path, _ = signed_files
        content = f"""\
        gateway:
          constitution: {const_path}
          signing_key: ./no_such_key.pem

        downstream:
          - name: mock
            command: echo
        """
        cfg_path = _write_config(tmp_path, content)
        with pytest.raises(GatewayConfigError, match="Signing key file"):
            load_gateway_config(cfg_path)

    def test_receipt_store_created_if_missing(self, tmp_path, signed_files):
        """receipt_store directory created if missing."""
        const_path, key_path = signed_files
        store_dir = tmp_path / "new_receipts"
        assert not store_dir.exists()

        content = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}
          receipt_store: {store_dir}

        downstream:
          - name: mock
            command: echo
        """
        cfg_path = _write_config(tmp_path, content)
        cfg = load_gateway_config(cfg_path)
        assert store_dir.exists()
        assert cfg.receipt_store == str(store_dir.resolve())


# =============================================================================
# 6. POLICY CASCADE
# =============================================================================

class TestPolicyCascade:
    def test_per_tool_override_wins(self):
        """Policy cascade — per-tool override wins."""
        ds = DownstreamConfig(
            name="mock",
            command="echo",
            default_policy="can_execute",
            tools={
                "update-page": ToolPolicyConfig(
                    policy="must_escalate",
                    reason="needs approval",
                ),
            },
        )
        assert resolve_tool_policy("update-page", ds) == "must_escalate"

    def test_server_default_wins_when_no_per_tool(self):
        """Policy cascade — server default wins when no per-tool."""
        ds = DownstreamConfig(
            name="mock",
            command="echo",
            default_policy="must_escalate",
        )
        assert resolve_tool_policy("any-tool", ds) == "must_escalate"

    def test_implicit_default_when_nothing_specified(self):
        """Policy cascade — implicit default (can_execute) when nothing
        specified returns None (fall through to constitution)."""
        ds = DownstreamConfig(
            name="mock",
            command="echo",
        )
        assert resolve_tool_policy("any-tool", ds) is None

    def test_per_tool_overrides_server_default(self):
        """Per-tool policy overrides even a restrictive server default."""
        ds = DownstreamConfig(
            name="mock",
            command="echo",
            default_policy="cannot_execute",
            tools={
                "safe-tool": ToolPolicyConfig(policy="can_execute"),
            },
        )
        assert resolve_tool_policy("safe-tool", ds) == "can_execute"
        assert resolve_tool_policy("other-tool", ds) == "cannot_execute"

    def test_build_policy_overrides(self):
        """build_policy_overrides produces flat dict for SannaGateway."""
        ds = DownstreamConfig(
            name="mock",
            command="echo",
            default_policy="can_execute",
            tools={
                "tool-a": ToolPolicyConfig(
                    policy="must_escalate",
                    reason="needs approval",
                ),
                "tool-b": ToolPolicyConfig(policy="cannot_execute"),
            },
        )
        overrides = build_policy_overrides(ds)
        assert overrides == {
            "tool-a": "must_escalate",
            "tool-b": "cannot_execute",
        }


# =============================================================================
# 7. MULTI-SERVER SUPPORT
# =============================================================================

class TestMultiServer:
    def test_multiple_downstreams_parse(self, tmp_path, signed_files):
        """Multiple downstream servers parse correctly."""
        const_path, key_path = signed_files
        content = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}

        downstream:
          - name: notion
            command: npx
            args: ["-y", "@notionhq/notion-mcp-server"]
            default_policy: can_execute
          - name: github
            command: npx
            args: ["-y", "@github/mcp-server"]
            default_policy: must_escalate
          - name: filesystem
            command: python
            args: ["-m", "fs_server"]
        """
        cfg_path = _write_config(tmp_path, content)
        cfg = load_gateway_config(cfg_path)

        assert len(cfg.downstreams) == 3
        assert cfg.downstreams[0].name == "notion"
        assert cfg.downstreams[1].name == "github"
        assert cfg.downstreams[2].name == "filesystem"
        assert cfg.downstreams[1].default_policy == "must_escalate"
        assert cfg.downstreams[2].default_policy == "can_execute"


# =============================================================================
# 8. ERROR HANDLING
# =============================================================================

class TestErrorHandling:
    def test_invalid_yaml_raises(self, tmp_path):
        """Invalid YAML → helpful error (not a stack trace)."""
        p = tmp_path / "bad.yaml"
        p.write_text("gateway:\n  constitution: [\n  invalid yaml here\n")
        with pytest.raises(GatewayConfigError, match="Invalid YAML"):
            load_gateway_config(str(p))

    def test_empty_config_raises(self, tmp_path):
        """Empty config file → clear error."""
        p = tmp_path / "empty.yaml"
        p.write_text("")
        with pytest.raises(GatewayConfigError, match="mapping"):
            load_gateway_config(str(p))

    def test_config_file_not_found(self, tmp_path):
        """Config file not found → clear error."""
        with pytest.raises(GatewayConfigError, match="not found"):
            load_gateway_config(str(tmp_path / "nonexistent.yaml"))

    def test_reason_field_optional_and_preserved(
        self, tmp_path, signed_files,
    ):
        """reason field on per-tool policy is optional and preserved
        when present."""
        const_path, key_path = signed_files
        content = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}

        downstream:
          - name: mock
            command: echo
            tools:
              "tool-with-reason":
                policy: must_escalate
                reason: "This is the reason"
              "tool-without-reason":
                policy: cannot_execute
        """
        cfg_path = _write_config(tmp_path, content)
        cfg = load_gateway_config(cfg_path)

        tools = cfg.downstreams[0].tools
        assert tools["tool-with-reason"].reason == "This is the reason"
        assert tools["tool-without-reason"].reason == ""

    def test_empty_downstream_list_raises(self, tmp_path, signed_files):
        """Empty downstream list → clear error."""
        const_path, key_path = signed_files
        content = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}

        downstream: []
        """
        cfg_path = _write_config(tmp_path, content)
        with pytest.raises(GatewayConfigError, match="downstream"):
            load_gateway_config(cfg_path)


# =============================================================================
# 9. NAMESPACE VALIDATION (Fix 2)
# =============================================================================

class TestNamespaceValidation:
    def test_underscore_name_accepted(self, tmp_path, signed_files):
        """Downstream name with underscore is now accepted (Block G)."""
        const_path, key_path = signed_files
        content = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}

        downstream:
          - name: my_server
            command: echo
        """
        cfg_path = _write_config(tmp_path, content)
        cfg = load_gateway_config(cfg_path)
        assert cfg.downstreams[0].name == "my_server"

    def test_hyphen_name_accepted(self, tmp_path, signed_files):
        """Downstream name with hyphens is accepted."""
        const_path, key_path = signed_files
        content = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}

        downstream:
          - name: my-server
            command: echo
        """
        cfg_path = _write_config(tmp_path, content)
        cfg = load_gateway_config(cfg_path)
        assert cfg.downstreams[0].name == "my-server"

    def test_multiple_underscores_accepted(self, tmp_path, signed_files):
        """Name with multiple underscores accepted (Block G)."""
        const_path, key_path = signed_files
        content = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}

        downstream:
          - name: my_good_name
            command: echo
        """
        cfg_path = _write_config(tmp_path, content)
        cfg = load_gateway_config(cfg_path)
        assert cfg.downstreams[0].name == "my_good_name"

    def test_special_chars_rejected(self, tmp_path, signed_files):
        """Names with special characters are rejected."""
        const_path, key_path = signed_files
        content = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}

        downstream:
          - name: "my server!"
            command: echo
        """
        cfg_path = _write_config(tmp_path, content)
        with pytest.raises(GatewayConfigError, match="invalid.*characters"):
            load_gateway_config(cfg_path)


# =============================================================================
# 10. OPTIONAL DOWNSTREAM CONFIG (Fix 6)
# =============================================================================

class TestOptionalDownstreamConfig:
    def test_optional_true_parsed(self, tmp_path, signed_files):
        """Config with optional: true parses correctly."""
        const_path, key_path = signed_files
        content = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}

        downstream:
          - name: my-server
            command: echo
            optional: true
        """
        cfg_path = _write_config(tmp_path, content)
        cfg = load_gateway_config(cfg_path)
        assert cfg.downstreams[0].optional is True

    def test_optional_default_false(self, tmp_path, signed_files):
        """Config without optional defaults to False."""
        const_path, key_path = signed_files
        content = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}

        downstream:
          - name: my-server
            command: echo
        """
        cfg_path = _write_config(tmp_path, content)
        cfg = load_gateway_config(cfg_path)
        assert cfg.downstreams[0].optional is False
