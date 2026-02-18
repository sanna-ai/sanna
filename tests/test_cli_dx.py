"""Block 6 tests — CLI + DX Features.

Covers: sanna demo, sanna inspect, sanna-init gateway config,
keygen default location, check-config validation, unified CLI dispatch.
"""

import json
import os
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from sanna.cli import (
    main_demo,
    main_inspect,
    main_check_config,
    main_keygen,
    main_sanna,
    TOOL_VERSION,
)
from sanna.constitution import (
    Constitution, AgentIdentity, Boundary, Invariant, Provenance,
    sign_constitution, save_constitution,
)
from sanna.crypto import generate_keypair
from sanna.middleware import sanna_observe


# =============================================================================
# HELPERS
# =============================================================================

def _make_receipt(tmp_path):
    """Generate a valid receipt for inspection tests."""
    priv_path, pub_path = generate_keypair(str(tmp_path / "keys"))
    const = Constitution(
        schema_version="0.1.0",
        identity=AgentIdentity(agent_name="test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="test@test.com",
            approved_by=["lead@test.com"],
            approval_date="2026-01-01",
            approval_method="test",
        ),
        boundaries=[Boundary(id="B001", description="Test", category="scope", severity="medium")],
        invariants=[Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt")],
    )
    signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="tester")
    const_path = tmp_path / "constitution.yaml"
    save_constitution(signed, const_path)

    @sanna_observe(require_constitution_sig=False, constitution_path=str(const_path), private_key_path=str(priv_path))
    def agent(query, context):
        return "Grounded answer."

    result = agent(query="test", context="Context")
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(result.receipt, indent=2))
    return receipt_path, result.receipt


def _make_gateway_config(tmp_path, constitution_path=None, signing_key=None):
    """Create a minimal gateway config for check-config tests."""
    config = {
        "gateway": {
            "constitution": str(constitution_path) if constitution_path else "nonexistent.yaml",
        },
        "downstream": [
            {
                "name": "test-server",
                "command": "echo",
                "args": ["hello"],
                "timeout": 30,
            }
        ],
    }
    if signing_key:
        config["gateway"]["signing_key"] = str(signing_key)
    config_path = tmp_path / "gateway.yaml"
    with open(config_path, "w") as f:
        yaml.dump(config, f)
    return config_path


# =============================================================================
# 1. sanna demo (#20)
# =============================================================================

class TestDemo:
    def test_demo_runs_without_error(self, tmp_path):
        """sanna-demo should exit 0 and create receipt file."""
        out_dir = tmp_path / "demo-out"
        with patch("sys.argv", ["sanna-demo", "--output-dir", str(out_dir)]):
            result = main_demo()
        assert result == 0
        # Should have created files
        assert out_dir.exists()
        receipts = list(out_dir.glob("receipt-demo-*.json"))
        assert len(receipts) == 1

    def test_demo_receipt_verifies(self, tmp_path):
        """Receipt from demo should be valid."""
        out_dir = tmp_path / "demo-out"
        with patch("sys.argv", ["sanna-demo", "--output-dir", str(out_dir)]):
            main_demo()

        receipt_files = list(out_dir.glob("receipt-demo-*.json"))
        receipt = json.loads(receipt_files[0].read_text())

        from sanna.verify import verify_receipt, load_schema
        schema = load_schema()
        vr = verify_receipt(receipt, schema)
        assert vr.valid


# =============================================================================
# 2. sanna inspect (#21)
# =============================================================================

class TestInspect:
    def test_inspect_formats_receipt(self, tmp_path, capsys):
        """sanna-inspect should pretty-print receipt contents."""
        receipt_path, receipt = _make_receipt(tmp_path)

        with patch("sys.argv", ["sanna-inspect", str(receipt_path)]):
            result = main_inspect()

        assert result == 0
        captured = capsys.readouterr()
        assert "SANNA RECEIPT" in captured.out
        assert receipt.get("receipt_id", "")[:16] in captured.out
        assert "CHECKS" in captured.out

    def test_inspect_json_mode(self, tmp_path, capsys):
        """sanna-inspect --json should output raw JSON."""
        receipt_path, receipt = _make_receipt(tmp_path)

        with patch("sys.argv", ["sanna-inspect", str(receipt_path), "--json"]):
            result = main_inspect()

        assert result == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["receipt_id"] == receipt["receipt_id"]

    def test_inspect_file_not_found(self, tmp_path, capsys):
        """sanna-inspect on nonexistent file should give clean error."""
        with patch("sys.argv", ["sanna-inspect", str(tmp_path / "nope.json")]):
            result = main_inspect()

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.err.lower()


# =============================================================================
# 3. sanna-init gateway config (#22)
# =============================================================================

class TestInitGatewayConfig:
    def test_init_generates_gateway_config(self, tmp_path):
        """_maybe_generate_gateway_config should create a gateway.yaml."""
        from sanna.init_constitution import _maybe_generate_gateway_config
        const_path = tmp_path / "constitution.yaml"
        const_path.write_text("placeholder")

        with patch("builtins.input", return_value="y"):
            gw_path = _maybe_generate_gateway_config(const_path)

        assert gw_path is not None
        assert gw_path.exists()
        content = gw_path.read_text()
        assert "constitution:" in content
        assert "downstream:" in content
        assert "my-server" in content

    def test_init_skips_gateway_on_no(self, tmp_path):
        """Answering 'n' should skip gateway config generation."""
        from sanna.init_constitution import _maybe_generate_gateway_config
        const_path = tmp_path / "constitution.yaml"
        const_path.write_text("placeholder")

        with patch("builtins.input", return_value="n"):
            gw_path = _maybe_generate_gateway_config(const_path)

        assert gw_path is None
        assert not (tmp_path / "gateway.yaml").exists()

    def test_init_skips_if_gateway_exists(self, tmp_path, capsys):
        """Should skip if gateway.yaml already exists."""
        from sanna.init_constitution import _maybe_generate_gateway_config
        const_path = tmp_path / "constitution.yaml"
        const_path.write_text("placeholder")
        gw_file = tmp_path / "gateway.yaml"
        gw_file.write_text("existing")

        with patch("builtins.input", return_value="y"):
            gw_path = _maybe_generate_gateway_config(const_path)

        assert gw_path is None
        assert gw_file.read_text() == "existing"


# =============================================================================
# 4. keygen default location (#23)
# =============================================================================

class TestKeygenDefaultDir:
    @pytest.mark.skipif(os.name == "nt", reason="POSIX paths")
    def test_keygen_default_dir_is_home_sanna(self, tmp_path, monkeypatch):
        """Default keygen should create keys in ~/.sanna/keys/."""
        fake_home = tmp_path / "fakehome"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        # Also patch Path.home() to use our fake home
        monkeypatch.setattr(Path, "home", lambda: fake_home)

        with patch("sys.argv", ["sanna-keygen"]):
            result = main_keygen()

        assert result == 0
        key_dir = fake_home / ".sanna" / "keys"
        assert key_dir.exists()
        # Should have created .key and .pub files
        keys = list(key_dir.glob("*.key"))
        pubs = list(key_dir.glob("*.pub"))
        assert len(keys) == 1
        assert len(pubs) == 1

    def test_keygen_explicit_dir_still_works(self, tmp_path):
        """--output-dir flag should override the default."""
        out_dir = tmp_path / "custom-keys"
        with patch("sys.argv", ["sanna-keygen", "--output-dir", str(out_dir)]):
            result = main_keygen()

        assert result == 0
        keys = list(out_dir.glob("*.key"))
        assert len(keys) == 1


# =============================================================================
# 5. check-config (#24)
# =============================================================================

class TestCheckConfig:
    def test_check_config_valid(self, tmp_path, capsys):
        """Valid gateway config should pass check."""
        priv_path, _ = generate_keypair(str(tmp_path / "keys"))
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="test", domain="testing"),
            provenance=Provenance(
                authored_by="t@t.com", approved_by=["a@t.com"],
                approval_date="2026-01-01", approval_method="test",
            ),
            boundaries=[Boundary(id="B001", description="T", category="scope", severity="medium")],
            invariants=[Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt")],
        )
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="tester")
        const_path = tmp_path / "constitution.yaml"
        save_constitution(signed, const_path)

        config_path = _make_gateway_config(tmp_path, constitution_path=const_path,
                                           signing_key=priv_path)

        with patch("sys.argv", ["sanna-check-config", str(config_path)]):
            result = main_check_config()

        assert result == 0
        captured = capsys.readouterr()
        assert "VALID" in captured.out

    def test_check_config_missing_constitution(self, tmp_path, capsys):
        """Config referencing nonexistent constitution should fail."""
        config_path = _make_gateway_config(tmp_path)  # default: nonexistent.yaml

        with patch("sys.argv", ["sanna-check-config", str(config_path)]):
            result = main_check_config()

        assert result == 1
        captured = capsys.readouterr()
        assert "INVALID" in captured.out or "not found" in captured.out.lower()

    def test_check_config_unsigned_constitution_warns(self, tmp_path, capsys):
        """Config with unsigned constitution should warn."""
        # Create unsigned constitution (hash only)
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="test", domain="testing"),
            provenance=Provenance(
                authored_by="t@t.com", approved_by=["a@t.com"],
                approval_date="2026-01-01", approval_method="test",
            ),
            boundaries=[Boundary(id="B001", description="T", category="scope", severity="medium")],
            invariants=[],
        )
        signed = sign_constitution(const)  # hash only, no Ed25519
        const_path = tmp_path / "constitution.yaml"
        save_constitution(signed, const_path)

        config_path = _make_gateway_config(tmp_path, constitution_path=const_path)

        with patch("sys.argv", ["sanna-check-config", str(config_path)]):
            result = main_check_config()

        assert result == 0  # Warning, not error
        captured = capsys.readouterr()
        assert "WARN" in captured.out

    def test_check_config_file_not_found(self, tmp_path, capsys):
        """Nonexistent config file should give clean error."""
        with patch("sys.argv", ["sanna-check-config", str(tmp_path / "nope.yaml")]):
            result = main_check_config()

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.err.lower()


# =============================================================================
# 6. Unified CLI (#25)
# =============================================================================

class TestUnifiedCLI:
    def test_help_shows_subcommands(self, capsys):
        """sanna --help should list all subcommands."""
        with patch("sys.argv", ["sanna", "--help"]):
            result = main_sanna()

        assert result == 0
        captured = capsys.readouterr()
        assert "Commands:" in captured.out
        assert "init" in captured.out
        assert "keygen" in captured.out
        assert "verify" in captured.out
        assert "demo" in captured.out
        assert "inspect" in captured.out
        assert "gateway" in captured.out

    def test_version_flag(self, capsys):
        """sanna --version should print version."""
        with patch("sys.argv", ["sanna", "--version"]):
            result = main_sanna()

        assert result == 0
        captured = capsys.readouterr()
        assert TOOL_VERSION in captured.out

    def test_unknown_command_errors(self, capsys):
        """sanna unknown-cmd should give clean error."""
        with patch("sys.argv", ["sanna", "nonexistent-thing"]):
            result = main_sanna()

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown command" in captured.err

    def test_dispatches_to_demo(self, tmp_path):
        """sanna demo should dispatch to main_demo."""
        out_dir = tmp_path / "dispatch-test"
        with patch("sys.argv", ["sanna", "demo", "--output-dir", str(out_dir)]):
            result = main_sanna()

        assert result == 0
        assert out_dir.exists()
        receipts = list(out_dir.glob("receipt-demo-*.json"))
        assert len(receipts) == 1
