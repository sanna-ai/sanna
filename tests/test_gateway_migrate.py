"""Tests for gateway migration CLI (sanna-gateway migrate).

Tests cover: client adapter detection, config parsing, secret detection,
migration planning, execution with filesystem operations, dry-run mode,
idempotency, template loading, and CLI dispatch.
"""

import json
import platform
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from sanna.gateway.migrate import (
    ClaudeDesktopAdapter,
    ClaudeCodeAdapter,
    CursorAdapter,
    MigrationPlan,
    ServerEntry,
    WindsurfAdapter,
    _GATEWAY_TEMPLATES,
    _append_reasoning_comment,
    detect_installed_clients,
    detect_secrets,
    execute_migration,
    format_plan,
    get_adapter,
    load_gateway_template,
    plan_migration,
)


# =============================================================================
# HELPERS
# =============================================================================

def _write_client_config(tmp_path, servers, filename="config.json"):
    """Write a Claude Desktop-style config file. Returns path."""
    config = {"mcpServers": servers}
    path = tmp_path / filename
    path.write_text(json.dumps(config, indent=2))
    return path


def _sample_servers():
    """Return a sample mcpServers dict with 3 servers."""
    return {
        "notion": {
            "command": "npx",
            "args": ["-y", "@notionhq/notion-mcp-server"],
            "env": {
                "OPENAPI_MCP_HEADERS": '{"Authorization":"Bearer ntn_abc123def456ghi789"}',
            },
        },
        "github": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
            "env": {
                "GITHUB_TOKEN": "ghp_abcdef1234567890abcdef1234567890ab",
            },
        },
        "filesystem": {
            "command": "npx",
            "args": [
                "-y", "@modelcontextprotocol/server-filesystem",
                "/Users/me/Documents",
            ],
        },
    }


# =============================================================================
# 1. ADAPTER TESTS
# =============================================================================

class TestClaudeDesktopAdapter:
    def test_name(self):
        adapter = ClaudeDesktopAdapter()
        assert adapter.name == "claude-desktop"

    def test_config_paths_macos(self):
        with patch("sanna.gateway.migrate.platform.system", return_value="Darwin"):
            adapter = ClaudeDesktopAdapter()
            paths = adapter.config_paths()
            assert len(paths) == 1
            assert "Application Support" in str(paths[0])
            assert "claude_desktop_config.json" in str(paths[0])

    def test_config_paths_linux(self):
        with patch("sanna.gateway.migrate.platform.system", return_value="Linux"):
            adapter = ClaudeDesktopAdapter()
            paths = adapter.config_paths()
            assert len(paths) == 1
            assert ".config/claude" in str(paths[0])

    def test_config_paths_windows(self, monkeypatch):
        monkeypatch.setenv("APPDATA", "C:\\Users\\test\\AppData\\Roaming")
        with patch("sanna.gateway.migrate.platform.system", return_value="Windows"):
            adapter = ClaudeDesktopAdapter()
            paths = adapter.config_paths()
            assert len(paths) == 1
            assert "Claude" in str(paths[0])

    def test_config_paths_unknown_platform(self):
        with patch("sanna.gateway.migrate.platform.system", return_value="FreeBSD"):
            adapter = ClaudeDesktopAdapter()
            paths = adapter.config_paths()
            assert paths == []

    def test_parse_servers_basic(self):
        adapter = ClaudeDesktopAdapter()
        config = {"mcpServers": _sample_servers()}
        servers = adapter.parse_servers(config)
        assert len(servers) == 3
        names = {s.name for s in servers}
        assert names == {"notion", "github", "filesystem"}

    def test_parse_servers_empty(self):
        adapter = ClaudeDesktopAdapter()
        servers = adapter.parse_servers({"mcpServers": {}})
        assert servers == []

    def test_parse_servers_no_mcp_key(self):
        adapter = ClaudeDesktopAdapter()
        servers = adapter.parse_servers({})
        assert servers == []

    def test_parse_servers_preserves_env(self):
        adapter = ClaudeDesktopAdapter()
        config = {"mcpServers": _sample_servers()}
        servers = adapter.parse_servers(config)
        notion = next(s for s in servers if s.name == "notion")
        assert "OPENAPI_MCP_HEADERS" in notion.env

    def test_parse_servers_preserves_args(self):
        adapter = ClaudeDesktopAdapter()
        config = {"mcpServers": _sample_servers()}
        servers = adapter.parse_servers(config)
        fs = next(s for s in servers if s.name == "filesystem")
        assert "/Users/me/Documents" in fs.args

    def test_build_migrated_config(self):
        adapter = ClaudeDesktopAdapter()
        original = {"mcpServers": _sample_servers(), "otherKey": "preserved"}
        result = adapter.build_migrated_config(
            original, "sanna-gateway", ["--config", "/path/to/gw.yaml"],
        )
        assert "sanna-gateway" in result["mcpServers"]
        assert len(result["mcpServers"]) == 1
        assert result["otherKey"] == "preserved"
        entry = result["mcpServers"]["sanna-gateway"]
        assert entry["command"] == "sanna-gateway"
        assert entry["args"] == ["--config", "/path/to/gw.yaml"]

    def test_is_already_migrated_true(self):
        adapter = ClaudeDesktopAdapter()
        config = {"mcpServers": {"sanna-gateway": {"command": "sanna-gateway"}}}
        assert adapter.is_already_migrated(config) is True

    def test_is_already_migrated_false(self):
        adapter = ClaudeDesktopAdapter()
        config = {"mcpServers": _sample_servers()}
        assert adapter.is_already_migrated(config) is False

    def test_detect_config_exists(self, tmp_path):
        """detect_config returns path when file exists."""
        cfg = tmp_path / "claude_desktop_config.json"
        cfg.write_text("{}")
        with patch.object(
            ClaudeDesktopAdapter, "config_paths", return_value=[cfg],
        ):
            adapter = ClaudeDesktopAdapter()
            assert adapter.detect_config() == cfg

    def test_detect_config_missing(self, tmp_path):
        """detect_config returns None when no file exists."""
        missing = tmp_path / "nonexistent.json"
        with patch.object(
            ClaudeDesktopAdapter, "config_paths", return_value=[missing],
        ):
            adapter = ClaudeDesktopAdapter()
            assert adapter.detect_config() is None


class TestAdapterRegistry:
    def test_get_adapter_claude_desktop(self):
        adapter = get_adapter("claude-desktop")
        assert isinstance(adapter, ClaudeDesktopAdapter)

    def test_get_adapter_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown client"):
            get_adapter("vscode")

    def test_unimplemented_claude_code(self):
        with pytest.raises(NotImplementedError, match="v0.12.0"):
            ClaudeCodeAdapter().config_paths()

    def test_unimplemented_cursor(self):
        with pytest.raises(NotImplementedError, match="v0.12.0"):
            CursorAdapter().config_paths()

    def test_unimplemented_windsurf(self):
        with pytest.raises(NotImplementedError, match="v0.12.0"):
            WindsurfAdapter().config_paths()

    def test_detect_installed_clients(self, tmp_path):
        """Auto-detect finds only clients with existing configs."""
        cfg = tmp_path / "claude_desktop_config.json"
        cfg.write_text('{"mcpServers": {}}')
        with patch.object(
            ClaudeDesktopAdapter, "config_paths", return_value=[cfg],
        ):
            found = detect_installed_clients()
            names = [name for name, _ in found]
            assert "claude-desktop" in names
            # Unimplemented adapters are silently skipped
            assert "cursor" not in names


# =============================================================================
# 2. SECRET DETECTION TESTS
# =============================================================================

class TestSecretDetection:
    def test_detect_api_token_prefix(self):
        secrets = detect_secrets({"KEY": "ntn_abc123"})
        assert "KEY" in secrets

    def test_detect_long_string(self):
        secrets = detect_secrets({
            "TOKEN": "abcdefghijklmnopqrstuvwxyz12345",
        })
        assert "TOKEN" in secrets

    def test_skip_already_interpolated(self):
        secrets = detect_secrets({"VAR": "${MY_SECRET}"})
        assert secrets == {}

    def test_skip_short_value(self):
        secrets = detect_secrets({"PORT": "8080"})
        assert secrets == {}

    def test_skip_empty_value(self):
        secrets = detect_secrets({"VAR": ""})
        assert secrets == {}

    def test_empty_env(self):
        assert detect_secrets({}) == {}

    def test_detect_bearer_prefix(self):
        secrets = detect_secrets({"AUTH": "Bearer xyz"})
        assert "AUTH" in secrets

    def test_detect_github_token(self):
        secrets = detect_secrets({
            "GH": "ghp_abcdef1234567890abcdef1234567890ab",
        })
        assert "GH" in secrets


# =============================================================================
# 3. TEMPLATE TESTS
# =============================================================================

class TestTemplates:
    @pytest.mark.parametrize("name", sorted(_GATEWAY_TEMPLATES.keys()))
    def test_load_gateway_template(self, name):
        """Each bundled template loads successfully."""
        content = load_gateway_template(name)
        assert len(content) > 100
        assert "identity" in content
        assert "invariants" in content

    def test_load_unknown_template_raises(self):
        with pytest.raises(ValueError, match="Unknown template"):
            load_gateway_template("nonexistent")

    @pytest.mark.parametrize("name", sorted(_GATEWAY_TEMPLATES.keys()))
    def test_template_is_valid_constitution(self, name):
        """Each template is a valid, loadable constitution."""
        from sanna.constitution import load_constitution

        content = load_gateway_template(name)
        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False,
        ) as f:
            f.write(content)
            f.flush()
            const = load_constitution(f.name)
            assert const.identity.agent_name
            assert len(const.invariants) > 0


# =============================================================================
# 4. PLAN TESTS
# =============================================================================

class TestPlanMigration:
    def test_plan_basic(self, tmp_path):
        """Single server produces a valid plan."""
        config = {"mcpServers": {
            "notion": {
                "command": "npx",
                "args": ["-y", "@notionhq/notion-mcp-server"],
            },
        }}
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(json.dumps(config))

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(
            adapter, cfg_path,
            sanna_dir=tmp_path / ".sanna",
        )
        assert len(plan.migratable) == 1
        assert plan.migratable[0].name == "notion"
        assert plan.client_name == "claude-desktop"
        assert not plan.already_migrated

    def test_plan_multiple_servers(self, tmp_path):
        """Multiple servers all end up in migratable list."""
        cfg_path = _write_client_config(tmp_path, _sample_servers())
        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(
            adapter, cfg_path,
            sanna_dir=tmp_path / ".sanna",
        )
        assert len(plan.migratable) == 3

    def test_plan_already_migrated(self, tmp_path):
        """Detects existing sanna-gateway entry."""
        servers = _sample_servers()
        servers["sanna-gateway"] = {"command": "sanna-gateway"}
        cfg_path = _write_client_config(tmp_path, servers)

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(
            adapter, cfg_path,
            sanna_dir=tmp_path / ".sanna",
        )
        assert plan.already_migrated is True
        # sanna-gateway itself is skipped, not migratable
        names = [s.name for s in plan.migratable]
        assert "sanna-gateway" not in names

    def test_plan_detects_secrets(self, tmp_path):
        """Hardcoded secrets detected in env vars."""
        cfg_path = _write_client_config(tmp_path, _sample_servers())
        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(
            adapter, cfg_path,
            sanna_dir=tmp_path / ".sanna",
        )
        assert len(plan.detected_secrets) > 0
        assert "GITHUB_TOKEN" in plan.detected_secrets

    def test_plan_template_selection(self, tmp_path):
        """--template flag controls constitution template name."""
        cfg_path = _write_client_config(tmp_path, {"mock": {
            "command": "echo", "args": [],
        }})
        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(
            adapter, cfg_path,
            template="openclaw-personal",
            sanna_dir=tmp_path / ".sanna",
        )
        assert plan.constitution_template == "openclaw-personal"
        assert "openclaw-personal" in str(plan.constitution_path)

    def test_plan_default_template_claude_desktop(self, tmp_path):
        """Default template for Claude Desktop is cowork-personal."""
        cfg_path = _write_client_config(tmp_path, {"mock": {
            "command": "echo", "args": [],
        }})
        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(
            adapter, cfg_path,
            sanna_dir=tmp_path / ".sanna",
        )
        assert plan.constitution_template == "cowork-personal"

    def test_plan_missing_config_raises(self, tmp_path):
        """Missing config file raises FileNotFoundError."""
        adapter = ClaudeDesktopAdapter()
        with pytest.raises(FileNotFoundError, match="No claude-desktop"):
            plan_migration(
                adapter,
                tmp_path / "nonexistent.json",
                sanna_dir=tmp_path / ".sanna",
            )

    def test_plan_invalid_json_raises(self, tmp_path):
        """Malformed JSON raises JSONDecodeError."""
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text("not valid json{{{")
        adapter = ClaudeDesktopAdapter()
        with pytest.raises(json.JSONDecodeError):
            plan_migration(
                adapter, cfg_path,
                sanna_dir=tmp_path / ".sanna",
            )

    def test_plan_empty_servers(self, tmp_path):
        """No servers → empty migratable list."""
        cfg_path = _write_client_config(tmp_path, {})
        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(
            adapter, cfg_path,
            sanna_dir=tmp_path / ".sanna",
        )
        assert plan.migratable == []

    def test_plan_skips_no_command(self, tmp_path):
        """Server with empty command is skipped."""
        cfg_path = _write_client_config(tmp_path, {
            "broken": {"command": "", "args": []},
        })
        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(
            adapter, cfg_path,
            sanna_dir=tmp_path / ".sanna",
        )
        assert len(plan.migratable) == 0
        assert len(plan.skipped) == 1
        assert "no command" in plan.skipped[0][1]


# =============================================================================
# 5. EXECUTION TESTS
# =============================================================================

class TestExecuteMigration:
    def test_full_migration(self, tmp_path):
        """End-to-end migration: backup, gateway.yaml, keys, constitution."""
        cfg_path = _write_client_config(tmp_path, _sample_servers())
        original_content = cfg_path.read_text()
        sanna_dir = tmp_path / ".sanna"

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(
            adapter, cfg_path, sanna_dir=sanna_dir,
        )
        result = execute_migration(plan)

        assert result.success is True

        # Backup created
        assert plan.backup_path.is_file()
        assert plan.backup_path.read_text() == original_content

        # Gateway config created
        assert plan.gateway_config_path.is_file()
        import yaml
        gw_config = yaml.safe_load(plan.gateway_config_path.read_text())
        assert "gateway" in gw_config
        assert "downstream" in gw_config
        assert len(gw_config["downstream"]) == 3

        # Constitution signed
        assert plan.constitution_path.is_file()
        from sanna.constitution import load_constitution
        const = load_constitution(str(plan.constitution_path))
        assert const.policy_hash is not None
        assert len(const.policy_hash) > 0

        # Keypair generated
        assert result.private_key_path is not None
        assert result.private_key_path.is_file()
        assert result.public_key_path.is_file()

        # Client config updated
        new_config = json.loads(cfg_path.read_text())
        assert "sanna-gateway" in new_config["mcpServers"]
        assert len(new_config["mcpServers"]) == 1

    def test_backup_preserves_original(self, tmp_path):
        """Backup is byte-identical to original config."""
        servers = {"mock": {"command": "echo", "args": ["hello"]}}
        cfg_path = _write_client_config(tmp_path, servers)
        original_bytes = cfg_path.read_bytes()
        sanna_dir = tmp_path / ".sanna"

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        execute_migration(plan)

        assert plan.backup_path.read_bytes() == original_bytes

    def test_gateway_yaml_has_all_servers(self, tmp_path):
        """gateway.yaml contains all migratable servers as downstreams."""
        cfg_path = _write_client_config(tmp_path, _sample_servers())
        sanna_dir = tmp_path / ".sanna"

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        execute_migration(plan)

        import yaml
        gw = yaml.safe_load(plan.gateway_config_path.read_text())
        ds_names = {d["name"] for d in gw["downstream"]}
        assert ds_names == {"notion", "github", "filesystem"}

    def test_secret_interpolation(self, tmp_path):
        """Detected secrets become ${VAR} in gateway.yaml."""
        cfg_path = _write_client_config(tmp_path, _sample_servers())
        sanna_dir = tmp_path / ".sanna"

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        execute_migration(plan)

        import yaml
        gw = yaml.safe_load(plan.gateway_config_path.read_text())
        github_ds = next(
            d for d in gw["downstream"] if d["name"] == "github"
        )
        assert github_ds["env"]["GITHUB_TOKEN"] == "${GITHUB_TOKEN}"

    def test_dry_run_writes_nothing(self, tmp_path):
        """--dry-run does not create or modify any files."""
        cfg_path = _write_client_config(tmp_path, _sample_servers())
        original_content = cfg_path.read_text()
        sanna_dir = tmp_path / ".sanna"

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        result = execute_migration(plan, dry_run=True)

        assert result.success is True
        # No files were created
        assert not plan.gateway_config_path.exists()
        assert not plan.constitution_path.exists()
        assert not plan.backup_path.exists()
        # Original not modified
        assert cfg_path.read_text() == original_content

    def test_idempotent_second_run(self, tmp_path):
        """Running migrate twice: second run reuses existing resources."""
        cfg_path = _write_client_config(tmp_path, _sample_servers())
        sanna_dir = tmp_path / ".sanna"

        adapter = ClaudeDesktopAdapter()

        # First migration
        plan1 = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        result1 = execute_migration(plan1)
        assert result1.success is True

        # Second migration on the updated config
        plan2 = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        assert plan2.already_migrated is True
        assert plan2.keypair_exists is True
        assert plan2.constitution_exists is True

    def test_existing_keypair_reused(self, tmp_path):
        """Existing gateway keypair is not overwritten."""
        cfg_path = _write_client_config(tmp_path, {"mock": {
            "command": "echo", "args": [],
        }})
        sanna_dir = tmp_path / ".sanna"
        keys_dir = sanna_dir / "keys"
        keys_dir.mkdir(parents=True)

        # Pre-create a gateway keypair
        from sanna.crypto import generate_keypair
        priv, pub = generate_keypair(str(keys_dir), label="gateway")

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        assert plan.keypair_exists is True

        result = execute_migration(plan)
        assert result.success is True
        # Same key reused
        assert result.private_key_path == Path(priv)
        assert any("existing" in w.lower() for w in result.warnings)

    def test_existing_constitution_reused(self, tmp_path):
        """Existing constitution is not overwritten."""
        cfg_path = _write_client_config(tmp_path, {"mock": {
            "command": "echo", "args": [],
        }})
        sanna_dir = tmp_path / ".sanna"
        const_dir = sanna_dir / "constitutions"
        const_dir.mkdir(parents=True)

        # Pre-create a constitution file
        const_path = const_dir / "cowork-personal.yaml"
        const_path.write_text("# existing constitution\nidentity:\n")

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        assert plan.constitution_exists is True

        result = execute_migration(plan)
        assert result.success is True
        # Constitution not overwritten
        assert "existing" in const_path.read_text()

    def test_no_servers_returns_failure(self, tmp_path):
        """Empty server list → migration fails gracefully."""
        cfg_path = _write_client_config(tmp_path, {})
        sanna_dir = tmp_path / ".sanna"

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        result = execute_migration(plan)

        assert result.success is False
        assert any("No MCP servers" in w for w in result.warnings)

    def test_gateway_yaml_default_policy(self, tmp_path):
        """Each downstream has default_policy: can_execute."""
        cfg_path = _write_client_config(tmp_path, _sample_servers())
        sanna_dir = tmp_path / ".sanna"

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        execute_migration(plan)

        import yaml
        gw = yaml.safe_load(plan.gateway_config_path.read_text())
        for ds in gw["downstream"]:
            assert ds["default_policy"] == "can_execute"

    def test_client_config_single_gateway_entry(self, tmp_path):
        """Updated client config has exactly one mcpServers entry."""
        cfg_path = _write_client_config(tmp_path, _sample_servers())
        sanna_dir = tmp_path / ".sanna"

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        execute_migration(plan)

        new = json.loads(cfg_path.read_text())
        assert list(new["mcpServers"].keys()) == ["sanna-gateway"]
        entry = new["mcpServers"]["sanna-gateway"]
        assert entry["command"] == "sanna-gateway"
        assert "--config" in entry["args"]

    def test_receipt_store_dir_created(self, tmp_path):
        """Receipt store directory is created during migration."""
        cfg_path = _write_client_config(tmp_path, {"mock": {
            "command": "echo", "args": [],
        }})
        sanna_dir = tmp_path / ".sanna"

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        execute_migration(plan)

        assert plan.receipt_store_dir.is_dir()


# =============================================================================
# 6. FORMAT OUTPUT TESTS
# =============================================================================

class TestFormatPlan:
    def test_format_basic(self, tmp_path):
        """format_plan includes server names and paths."""
        cfg_path = _write_client_config(tmp_path, _sample_servers())
        sanna_dir = tmp_path / ".sanna"

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        output = format_plan(plan)

        assert "notion" in output
        assert "github" in output
        assert "filesystem" in output
        assert "Migrating 3" in output

    def test_format_with_secrets(self, tmp_path):
        """Secret detection info appears in output."""
        cfg_path = _write_client_config(tmp_path, _sample_servers())
        sanna_dir = tmp_path / ".sanna"

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        output = format_plan(plan)

        assert "GITHUB_TOKEN" in output
        assert "export" in output

    def test_format_empty_servers(self, tmp_path):
        """Empty server list shows appropriate message."""
        cfg_path = _write_client_config(tmp_path, {})
        sanna_dir = tmp_path / ".sanna"

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        output = format_plan(plan)

        assert "No MCP servers found" in output

    def test_format_already_migrated(self, tmp_path):
        """Already-migrated warning appears in output."""
        servers = _sample_servers()
        servers["sanna-gateway"] = {"command": "sanna-gateway"}
        cfg_path = _write_client_config(tmp_path, servers)
        sanna_dir = tmp_path / ".sanna"

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        output = format_plan(plan)

        assert "already contains" in output

    def test_format_next_steps(self, tmp_path):
        """Output includes next steps."""
        cfg_path = _write_client_config(tmp_path, _sample_servers())
        sanna_dir = tmp_path / ".sanna"

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        output = format_plan(plan)

        assert "Next steps" in output
        assert "Claude Desktop" in output


# =============================================================================
# 7. CLI DISPATCH TESTS
# =============================================================================

class TestCLIDispatch:
    def test_dispatch_migrate_subcommand(self):
        """'migrate' in argv dispatches to migrate_command."""
        import sanna.gateway
        with patch("sanna.gateway.migrate.migrate_command", return_value=0) as mock:
            with patch("sys.argv", ["sanna-gateway", "migrate", "--auto"]):
                with pytest.raises(SystemExit) as exc_info:
                    sanna.gateway.main()
                assert exc_info.value.code == 0
            mock.assert_called_once()

    def test_dispatch_legacy_config(self):
        """'--config' dispatches to run_gateway (not migrate)."""
        import sanna.gateway
        with patch("sanna.gateway.server.run_gateway") as mock:
            with patch("sys.argv", ["sanna-gateway", "--config", "gw.yaml"]):
                sanna.gateway.main()
            mock.assert_called_once()

    def test_migrate_command_dry_run(self, tmp_path):
        """CLI --dry-run exits 0 and writes nothing."""
        cfg_path = _write_client_config(tmp_path, _sample_servers())
        sanna_dir = tmp_path / ".sanna"

        with patch.object(
            ClaudeDesktopAdapter, "detect_config", return_value=cfg_path,
        ):
            from sanna.gateway.migrate import migrate_command
            code = migrate_command([
                "--client", "claude-desktop",
                "--dry-run",
                "--sanna-dir", str(sanna_dir),
            ])
            assert code == 0
            assert not (sanna_dir / "gateway.yaml").exists()

    def test_migrate_command_full(self, tmp_path):
        """CLI runs full migration and exits 0."""
        cfg_path = _write_client_config(tmp_path, _sample_servers())
        sanna_dir = tmp_path / ".sanna"

        with patch.object(
            ClaudeDesktopAdapter, "detect_config", return_value=cfg_path,
        ):
            from sanna.gateway.migrate import migrate_command
            code = migrate_command([
                "--client", "claude-desktop",
                "--sanna-dir", str(sanna_dir),
            ])
            assert code == 0
            assert (sanna_dir / "gateway.yaml").is_file()

    def test_migrate_command_template_override(self, tmp_path):
        """CLI --template flag overrides default."""
        cfg_path = _write_client_config(tmp_path, {"mock": {
            "command": "echo", "args": [],
        }})
        sanna_dir = tmp_path / ".sanna"

        with patch.object(
            ClaudeDesktopAdapter, "detect_config", return_value=cfg_path,
        ):
            from sanna.gateway.migrate import migrate_command
            code = migrate_command([
                "--client", "claude-desktop",
                "--template", "openclaw-personal",
                "--sanna-dir", str(sanna_dir),
            ])
            assert code == 0
            const_path = sanna_dir / "constitutions" / "openclaw-personal.yaml"
            assert const_path.is_file()

    def test_migrate_command_missing_config(self, tmp_path):
        """CLI exits 1 when client config not found."""
        with patch.object(
            ClaudeDesktopAdapter, "detect_config", return_value=None,
        ):
            from sanna.gateway.migrate import migrate_command
            code = migrate_command([
                "--client", "claude-desktop",
                "--sanna-dir", str(tmp_path / ".sanna"),
            ])
            assert code == 1

    def test_migrate_command_unimplemented_client(self):
        """CLI exits 1 for unimplemented adapter."""
        from sanna.gateway.migrate import migrate_command
        code = migrate_command(["--client", "cursor"])
        assert code == 1


# =============================================================================
# NAMESPACE SANITIZATION (Fix 2)
# =============================================================================

class TestNamespaceSanitization:
    def test_underscore_names_sanitized_in_gateway_yaml(self, tmp_path):
        """Server names with underscores become hyphens in gateway.yaml."""
        import yaml
        from sanna.gateway.migrate import _build_gateway_yaml

        server = ServerEntry(
            name="my_notion_server",
            command="npx",
            args=["-y", "notion-mcp"],
        )
        plan = MigrationPlan(
            client_name="claude-desktop",
            config_path=tmp_path / "config.json",
            backup_path=tmp_path / "config.json.bak",
            servers=[server],
            sanna_dir=tmp_path / ".sanna",
            keys_dir=tmp_path / ".sanna" / "keys",
            constitution_path=tmp_path / ".sanna" / "constitution.yaml",
            constitution_template="openclaw-personal",
            gateway_config_path=tmp_path / ".sanna" / "gateway.yaml",
            receipt_store_dir=tmp_path / ".sanna" / "receipts",
            migratable=[server],
            skipped=[],
            detected_secrets={},
            already_migrated=False,
            keypair_exists=False,
            constitution_exists=False,
        )

        yaml_str = _build_gateway_yaml(plan, signing_key_path=None)
        config = yaml.safe_load(yaml_str)
        ds_name = config["downstream"][0]["name"]
        assert "_" not in ds_name
        assert ds_name == "my-notion-server"


# =============================================================================
# CONSTITUTION PUBLIC KEY IN CONFIG (Fix 4)
# =============================================================================

class TestConstitutionKeyInConfig:
    def test_gateway_yaml_includes_public_key(self, tmp_path):
        """Generated gateway.yaml includes constitution_public_key."""
        import yaml
        from sanna.gateway.migrate import _build_gateway_yaml

        pub_key = tmp_path / "keys" / "gateway.pub"

        server = ServerEntry(name="mock", command="echo")
        plan = MigrationPlan(
            client_name="claude-desktop",
            config_path=tmp_path / "config.json",
            backup_path=tmp_path / "config.json.bak",
            servers=[server],
            sanna_dir=tmp_path / ".sanna",
            keys_dir=tmp_path / ".sanna" / "keys",
            constitution_path=tmp_path / ".sanna" / "constitution.yaml",
            constitution_template="openclaw-personal",
            gateway_config_path=tmp_path / ".sanna" / "gateway.yaml",
            receipt_store_dir=tmp_path / ".sanna" / "receipts",
            migratable=[server],
            skipped=[],
            detected_secrets={},
            already_migrated=False,
            keypair_exists=False,
            constitution_exists=False,
        )

        yaml_str = _build_gateway_yaml(
            plan,
            signing_key_path=tmp_path / "keys" / "gateway.key",
            public_key_path=pub_key,
        )
        config = yaml.safe_load(yaml_str)
        assert "constitution_public_key" in config["gateway"]
        assert str(pub_key) in config["gateway"]["constitution_public_key"]

    def test_no_public_key_omits_field(self, tmp_path):
        """Without public_key_path, field is omitted."""
        import yaml
        from sanna.gateway.migrate import _build_gateway_yaml

        server = ServerEntry(name="mock", command="echo")
        plan = MigrationPlan(
            client_name="claude-desktop",
            config_path=tmp_path / "config.json",
            backup_path=tmp_path / "config.json.bak",
            servers=[server],
            sanna_dir=tmp_path / ".sanna",
            keys_dir=tmp_path / ".sanna" / "keys",
            constitution_path=tmp_path / ".sanna" / "constitution.yaml",
            constitution_template="openclaw-personal",
            gateway_config_path=tmp_path / ".sanna" / "gateway.yaml",
            receipt_store_dir=tmp_path / ".sanna" / "receipts",
            migratable=[server],
            skipped=[],
            detected_secrets={},
            already_migrated=False,
            keypair_exists=False,
            constitution_exists=False,
        )

        yaml_str = _build_gateway_yaml(plan, signing_key_path=None)
        config = yaml.safe_load(yaml_str)
        assert "constitution_public_key" not in config["gateway"]


# =============================================================================
# ATOMIC WRITES (Fix 7)
# =============================================================================

class TestAtomicWrites:
    def test_atomic_write_creates_file(self, tmp_path):
        """_atomic_write creates file with correct content."""
        from sanna.gateway.migrate import _atomic_write

        filepath = tmp_path / "test.txt"
        _atomic_write(filepath, "hello world")
        assert filepath.read_text() == "hello world"

    def test_atomic_write_rejects_symlink(self, tmp_path):
        """_atomic_write refuses to write through a symlink."""
        import os
        from sanna.gateway.migrate import _atomic_write

        real_file = tmp_path / "real.txt"
        real_file.write_text("original")
        link = tmp_path / "link.txt"
        os.symlink(str(real_file), str(link))

        with pytest.raises(ValueError, match="symlink"):
            _atomic_write(link, "injected")

        # Original content unchanged
        assert real_file.read_text() == "original"

    @pytest.mark.skipif(
        platform.system() == "Windows",
        reason="POSIX-only permissions",
    )
    def test_atomic_write_sets_permissions(self, tmp_path):
        """On POSIX, _atomic_write sets 0o600 permissions."""
        import os
        from sanna.gateway.migrate import _atomic_write

        filepath = tmp_path / "secure.txt"
        _atomic_write(filepath, "secret data")
        mode = os.stat(filepath).st_mode & 0o777
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"

    def test_atomic_write_no_partial_on_target(self, tmp_path):
        """If target didn't exist and write fails, target remains absent."""
        import os
        from unittest.mock import patch
        from sanna.gateway.migrate import _atomic_write

        filepath = tmp_path / "never.txt"

        with patch("os.replace", side_effect=OSError("disk full")):
            with pytest.raises(OSError, match="disk full"):
                _atomic_write(filepath, "data")

        assert not filepath.exists()


# =============================================================================
# MIGRATION REASONING COMMENT (v0.11.0)
# =============================================================================

class TestMigrationReasoningComment:
    def test_migration_appends_reasoning_comment(self, tmp_path):
        """execute_migration() appends commented reasoning section to new constitutions."""
        servers = {"mock": {"command": "echo", "args": ["test"]}}
        cfg_path = _write_client_config(tmp_path, servers)
        sanna_dir = tmp_path / ".sanna"

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        result = execute_migration(plan)

        assert result.success is True
        content = plan.constitution_path.read_text()
        assert "Reasoning governance" in content
        assert "require_justification_for" in content
        assert "glc_002_minimum_substance" in content
        assert "glc_005_llm_coherence" in content
        assert "SANNA_LLM_MODEL" in content

    def test_reasoning_comment_is_yaml_comment(self, tmp_path):
        """Reasoning section is commented out (all lines start with #)."""
        servers = {"mock": {"command": "echo", "args": ["test"]}}
        cfg_path = _write_client_config(tmp_path, servers)
        sanna_dir = tmp_path / ".sanna"

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        execute_migration(plan)

        content = plan.constitution_path.read_text()
        # Find the reasoning block
        in_reasoning = False
        for line in content.splitlines():
            if "Reasoning governance" in line:
                in_reasoning = True
            if in_reasoning and line.strip():
                assert line.strip().startswith("#"), (
                    f"Non-comment line in reasoning block: {line!r}"
                )

    def test_reasoning_comment_idempotent(self, tmp_path):
        """_append_reasoning_comment is idempotent — no duplicate on second call."""
        from sanna.gateway.migrate import _append_reasoning_comment

        filepath = tmp_path / "const.yaml"
        filepath.write_text("sanna_constitution: '1.0.0'\n")

        _append_reasoning_comment(filepath)
        content_first = filepath.read_text()
        count_first = content_first.count("Reasoning governance")
        assert count_first == 1

        _append_reasoning_comment(filepath)
        content_second = filepath.read_text()
        count_second = content_second.count("Reasoning governance")
        assert count_second == 1
        assert content_first == content_second

    def test_constitution_still_loadable_with_comment(self, tmp_path):
        """Constitution with appended reasoning comment still loads and verifies."""
        servers = {"mock": {"command": "echo", "args": ["test"]}}
        cfg_path = _write_client_config(tmp_path, servers)
        sanna_dir = tmp_path / ".sanna"

        adapter = ClaudeDesktopAdapter()
        plan = plan_migration(adapter, cfg_path, sanna_dir=sanna_dir)
        execute_migration(plan)

        from sanna.constitution import load_constitution
        const = load_constitution(str(plan.constitution_path))
        assert const.policy_hash is not None


# =============================================================================
# EXAMPLE CONSTITUTION VALIDATION
# =============================================================================

class TestExampleReasoningConstitution:
    def test_reasoning_example_is_valid_yaml(self):
        """examples/constitutions/reasoning-example.yaml is valid YAML."""
        import yaml
        example_path = (
            Path(__file__).parent.parent
            / "examples" / "constitutions" / "reasoning-example.yaml"
        )
        assert example_path.is_file(), f"Missing: {example_path}"
        data = yaml.safe_load(example_path.read_text())
        assert data["sanna_constitution"] == "1.1"
        assert "reasoning" in data
        assert "require_justification_for" in data["reasoning"]

    def test_reasoning_example_has_all_checks(self):
        """Example constitution includes all three configurable checks."""
        import yaml
        example_path = (
            Path(__file__).parent.parent
            / "examples" / "constitutions" / "reasoning-example.yaml"
        )
        data = yaml.safe_load(example_path.read_text())
        checks = data["reasoning"]["checks"]
        assert "glc_002_minimum_substance" in checks
        assert "glc_003_no_parroting" in checks
        assert "glc_005_llm_coherence" in checks

    def test_reasoning_example_no_model_strings(self):
        """Example constitution has no hardcoded model strings."""
        example_path = (
            Path(__file__).parent.parent
            / "examples" / "constitutions" / "reasoning-example.yaml"
        )
        content = example_path.read_text()
        # Must not contain specific model identifiers
        assert "claude-sonnet" not in content.lower()
        assert "claude-3" not in content.lower()
        assert "claude-4" not in content.lower()
        assert "sonnet-4" not in content.lower()
        assert "SANNA_LLM_MODEL" in content
