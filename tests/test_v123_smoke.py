"""v0.12.5 integration smoke tests — Block 8 final validation.

These tests verify the complete v0.12.5 release works end-to-end:
demo, inspect, check-config, verify, unified CLI, imports, async.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from sanna.cli import main_demo, main_inspect, main_check_config, main_verify, main_sanna, TOOL_VERSION
from sanna.constitution import (
    Constitution, AgentIdentity, Boundary, Invariant, Provenance,
    sign_constitution, save_constitution,
)
from sanna.crypto import generate_keypair


# =============================================================================
# 1. Version
# =============================================================================

class TestVersion:
    def test_version_is_0_12_3(self):
        import sanna
        assert sanna.__version__ == "0.13.4"

    def test_tool_version_is_0_12_3(self):
        assert TOOL_VERSION == "0.13.4"


# =============================================================================
# 2. sanna demo end-to-end
# =============================================================================

class TestDemoSmoke:
    def test_demo_completes_and_receipt_verifies(self, tmp_path):
        """Full demo: generate → verify round-trip."""
        out_dir = tmp_path / "demo"
        with patch("sys.argv", ["sanna-demo", "-o", str(out_dir)]):
            rc = main_demo()
        assert rc == 0

        # Receipt exists
        receipts = list(out_dir.glob("receipt-demo-*.json"))
        assert len(receipts) == 1

        # Receipt verifies
        receipt = json.loads(receipts[0].read_text())
        from sanna.verify import verify_receipt, load_schema
        vr = verify_receipt(receipt, load_schema())
        assert vr.valid

    def test_inspect_on_demo_receipt(self, tmp_path, capsys):
        """sanna inspect on demo receipt produces formatted output."""
        out_dir = tmp_path / "demo"
        with patch("sys.argv", ["sanna-demo", "-o", str(out_dir)]):
            main_demo()

        receipt_path = list(out_dir.glob("receipt-demo-*.json"))[0]
        with patch("sys.argv", ["sanna-inspect", str(receipt_path)]):
            rc = main_inspect()

        assert rc == 0
        captured = capsys.readouterr()
        assert "SANNA RECEIPT" in captured.out
        assert "CHECKS" in captured.out


# =============================================================================
# 3. check-config smoke
# =============================================================================

class TestCheckConfigSmoke:
    def test_valid_config_passes(self, tmp_path, capsys):
        priv, _ = generate_keypair(str(tmp_path / "keys"))
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="t", domain="t"),
            provenance=Provenance(authored_by="t@t", approved_by=["a@t"],
                                  approval_date="2026-01-01", approval_method="t"),
            boundaries=[Boundary(id="B001", description="T", category="scope", severity="medium")],
            invariants=[],
        )
        signed = sign_constitution(const, private_key_path=str(priv), signed_by="t")
        cp = tmp_path / "c.yaml"
        save_constitution(signed, cp)

        cfg = {"gateway": {"constitution": str(cp), "signing_key": str(priv)},
               "downstream": [{"name": "s", "command": "echo"}]}
        cfg_path = tmp_path / "gw.yaml"
        cfg_path.write_text(yaml.dump(cfg))

        with patch("sys.argv", ["sanna-check-config", str(cfg_path)]):
            rc = main_check_config()
        assert rc == 0

    def test_unsigned_constitution_warns(self, tmp_path, capsys):
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="t", domain="t"),
            provenance=Provenance(authored_by="t@t", approved_by=["a@t"],
                                  approval_date="2026-01-01", approval_method="t"),
            boundaries=[Boundary(id="B001", description="T", category="scope", severity="medium")],
            invariants=[],
        )
        signed = sign_constitution(const)  # hash only
        cp = tmp_path / "c.yaml"
        save_constitution(signed, cp)

        cfg = {"gateway": {"constitution": str(cp)},
               "downstream": [{"name": "s", "command": "echo"}]}
        cfg_path = tmp_path / "gw.yaml"
        cfg_path.write_text(yaml.dump(cfg))

        with patch("sys.argv", ["sanna-check-config", str(cfg_path)]):
            rc = main_check_config()
        assert rc == 0
        captured = capsys.readouterr()
        assert "WARN" in captured.out


# =============================================================================
# 4. sanna verify round-trip
# =============================================================================

class TestVerifySmoke:
    def test_verify_on_demo_receipt(self, tmp_path, capsys):
        out_dir = tmp_path / "demo"
        with patch("sys.argv", ["sanna-demo", "-o", str(out_dir)]):
            main_demo()

        # Flush demo output before verifying
        capsys.readouterr()

        receipt_path = list(out_dir.glob("receipt-demo-*.json"))[0]
        with patch("sys.argv", ["sanna-verify", str(receipt_path), "--format", "json"]):
            rc = main_verify()

        assert rc == 0
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["valid"] is True


# =============================================================================
# 5. Unified CLI
# =============================================================================

class TestUnifiedCLISmoke:
    def test_help_shows_subcommands(self, capsys):
        with patch("sys.argv", ["sanna", "--help"]):
            rc = main_sanna()
        assert rc == 0
        out = capsys.readouterr().out
        for cmd in ["init", "keygen", "sign", "verify", "demo", "inspect",
                     "check-config", "gateway", "drift-report"]:
            assert cmd in out

    def test_version(self, capsys):
        with patch("sys.argv", ["sanna", "--version"]):
            rc = main_sanna()
        assert rc == 0
        assert "0.13.4" in capsys.readouterr().out


# =============================================================================
# 6. Import surface
# =============================================================================

class TestImportSmoke:
    def test_top_level_imports(self):
        from sanna import sanna_observe, SannaReceipt, verify_receipt
        assert callable(sanna_observe)
        assert callable(verify_receipt)

    def test_removed_export_helpful_error(self):
        import sanna
        with pytest.raises(AttributeError, match="sanna.constitution"):
            sanna.Constitution

    def test_submodule_import_works(self):
        from sanna.constitution import Constitution
        assert Constitution is not None


# =============================================================================
# 7. Async @sanna_observe
# =============================================================================

class TestAsyncSmoke:
    def test_async_sanna_observe_generates_receipt(self, tmp_path):
        from sanna.middleware import sanna_observe

        priv, _ = generate_keypair(str(tmp_path / "keys"))
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="async-agent", domain="test"),
            provenance=Provenance(authored_by="t@t", approved_by=["a@t"],
                                  approval_date="2026-01-01", approval_method="t"),
            boundaries=[Boundary(id="B001", description="T", category="scope", severity="medium")],
            invariants=[Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt")],
        )
        signed = sign_constitution(const, private_key_path=str(priv), signed_by="t")
        cp = tmp_path / "c.yaml"
        save_constitution(signed, cp)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(cp), private_key_path=str(priv))
        async def async_agent(query, context):
            return f"Answer: {context}"

        result = asyncio.run(async_agent(query="q", context="c"))
        assert result.receipt is not None
        assert result.receipt.get("status") in ("PASS", "WARN", "FAIL")
