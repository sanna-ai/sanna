"""Tests for version consistency across the Sanna package.

Ensures __version__, TOOL_VERSION, receipts, and CLI all report the same version.
"""

import subprocess
import sys

import sanna
from sanna.receipt import TOOL_VERSION
from sanna.middleware import sanna_observe


class TestVersionConsistency:

    def test_version_value(self):
        assert sanna.__version__ == "0.8.1"

    def test_version_matches_tool_version(self):
        assert sanna.__version__ == TOOL_VERSION

    def test_receipt_contains_correct_version(self, tmp_path):
        """Generated receipt has tool_version matching __version__."""
        from sanna.constitution import (
            Constitution, AgentIdentity, Provenance, Boundary, Invariant,
            sign_constitution, save_constitution,
        )

        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="v-test", domain="testing"),
            provenance=Provenance(
                authored_by="t@t.com",
                approved_by=["a@t.com"],
                approval_date="2026-01-01",
                approval_method="test",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="medium")],
            invariants=[
                Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt"),
            ],
        )
        signed = sign_constitution(const)
        path = tmp_path / "const.yaml"
        save_constitution(signed, path)

        @sanna_observe(constitution_path=str(path))
        def agent(query, context):
            return "Grounded answer."

        result = agent(query="test", context="Context")
        assert result.receipt["tool_version"] == sanna.__version__

    def test_cli_uses_tool_version(self):
        """CLI module references TOOL_VERSION which matches __version__."""
        from sanna.cli import TOOL_VERSION as cli_tool_version
        assert cli_tool_version == sanna.__version__

    def test_version_from_version_module(self):
        """version.py is the single source of truth."""
        from sanna.version import __version__
        assert __version__ == sanna.__version__
        assert __version__ == TOOL_VERSION
