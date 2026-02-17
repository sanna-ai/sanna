"""Block 5 tests — API Surface Trim.

Covers: top-level export trimming, helpful migration errors,
C3MReceipt removal, gateway constructor deprecation + factory method,
MCP tool naming consistency, CLI entry point cleanup.
"""

import warnings

import pytest


# =============================================================================
# 1. Top-level exports are minimal
# =============================================================================

class TestTopLevelExportsMinimal:
    def test_all_has_exactly_10_names(self):
        """sanna.__all__ should contain exactly 10 curated names."""
        import sanna
        assert len(sanna.__all__) == 10

    def test_expected_names_present(self):
        """All 10 curated names should be in __all__."""
        import sanna
        expected = {
            "__version__", "sanna_observe", "SannaHaltError", "SannaResult",
            "generate_receipt", "SannaReceipt", "verify_receipt",
            "VerificationResult", "ReceiptStore", "DriftAnalyzer",
        }
        assert set(sanna.__all__) == expected

    def test_imports_actually_work(self):
        """All 10 exports should be importable."""
        from sanna import (
            __version__, sanna_observe, SannaHaltError, SannaResult,
            generate_receipt, SannaReceipt, verify_receipt,
            VerificationResult, ReceiptStore, DriftAnalyzer,
        )
        assert callable(sanna_observe)
        assert callable(generate_receipt)
        assert callable(verify_receipt)


# =============================================================================
# 2. Removed exports give helpful errors
# =============================================================================

class TestRemovedExportGivesHelpfulError:
    def test_constitution_points_to_submodule(self):
        """Accessing sanna.Constitution should raise with migration hint."""
        import sanna
        with pytest.raises(AttributeError, match="sanna.constitution"):
            sanna.Constitution

    def test_generate_keypair_points_to_crypto(self):
        import sanna
        with pytest.raises(AttributeError, match="sanna.crypto"):
            sanna.generate_keypair

    def test_hash_text_points_to_hashing(self):
        import sanna
        with pytest.raises(AttributeError, match="sanna.hashing"):
            sanna.hash_text

    def test_check_config_points_to_enforcement(self):
        import sanna
        with pytest.raises(AttributeError, match="sanna.enforcement"):
            sanna.CheckConfig

    def test_build_trace_data_points_to_middleware(self):
        import sanna
        with pytest.raises(AttributeError, match="sanna.middleware"):
            sanna.build_trace_data

    def test_unknown_name_raises_plain_attribute_error(self):
        import sanna
        with pytest.raises(AttributeError, match="no attribute"):
            sanna.totally_nonexistent_name


# =============================================================================
# 3. C3MReceipt alias removed
# =============================================================================

class TestC3MReceiptAliasRemoved:
    def test_c3m_receipt_raises_attribute_error(self):
        """sanna.C3MReceipt should raise AttributeError with migration hint."""
        import sanna
        with pytest.raises(AttributeError, match="SannaReceipt"):
            sanna.C3MReceipt

    def test_sanna_receipt_still_works(self):
        from sanna import SannaReceipt
        assert SannaReceipt is not None


# =============================================================================
# 4. Gateway constructor deprecation + factory method
# =============================================================================

class TestGatewayConstructorDeprecation:
    def test_legacy_args_emit_deprecation_warning(self):
        """Passing server_name/command directly should emit DeprecationWarning."""
        mcp_mod = pytest.importorskip("mcp", reason="mcp extra not installed")

        from sanna.gateway.server import SannaGateway
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            try:
                gw = SannaGateway(
                    server_name="test",
                    command="echo",
                )
            except Exception:
                pass  # May fail without full config, that's OK
            # Check that at least one DeprecationWarning was emitted
            dep_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(dep_warnings) >= 1
            assert "deprecated" in str(dep_warnings[0].message).lower()

    def test_for_single_server_exists(self):
        """SannaGateway.for_single_server() factory method should exist."""
        mcp_mod = pytest.importorskip("mcp", reason="mcp extra not installed")

        from sanna.gateway.server import SannaGateway
        assert hasattr(SannaGateway, "for_single_server")
        assert callable(SannaGateway.for_single_server)

    def test_for_single_server_creates_gateway(self):
        """for_single_server() should create a SannaGateway without deprecation."""
        mcp_mod = pytest.importorskip("mcp", reason="mcp extra not installed")

        from sanna.gateway.server import SannaGateway
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            try:
                gw = SannaGateway.for_single_server(
                    name="test",
                    command="echo",
                )
            except Exception:
                pass
            dep_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(dep_warnings) == 0, "Factory should not emit DeprecationWarning"


# =============================================================================
# 5. MCP tool naming consistency
# =============================================================================

class TestMCPToolNamingConsistent:
    def test_all_mcp_tools_have_sanna_prefix(self):
        """All MCP server tools should start with sanna_."""
        pytest.importorskip("mcp", reason="mcp extra not installed")
        try:
            from sanna.mcp.server import (
                sanna_verify_receipt,
                sanna_generate_receipt,
                sanna_list_checks,
                sanna_evaluate_action,
                sanna_check_constitution_approval,
            )
        except TypeError:
            pytest.skip("MCP SDK version incompatible (known issue)")
        # All are callable
        for fn in [
            sanna_verify_receipt,
            sanna_generate_receipt,
            sanna_list_checks,
            sanna_evaluate_action,
            sanna_check_constitution_approval,
        ]:
            assert callable(fn)
            assert fn.__name__.startswith("sanna_"), (
                f"{fn.__name__} does not have sanna_ prefix"
            )

    def test_old_name_not_importable(self):
        """check_constitution_approval (without prefix) should not be importable."""
        pytest.importorskip("mcp", reason="mcp extra not installed")
        try:
            from sanna.mcp import server as _srv  # trigger MCP registration
        except TypeError:
            pytest.skip("MCP SDK version incompatible (known issue)")

        with pytest.raises(ImportError):
            from sanna.mcp.server import check_constitution_approval


# =============================================================================
# 6. CLI entry point cleanup
# =============================================================================

class TestCLIEntryPointCleanup:
    def test_pyproject_has_no_c3m_aliases(self):
        """pyproject.toml should not contain c3m-receipt or c3m-verify."""
        from pathlib import Path
        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        content = pyproject.read_text()
        assert "c3m-receipt" not in content
        assert "c3m-verify" not in content

    def test_pyproject_has_no_init_constitution(self):
        """pyproject.toml should not have sanna-init-constitution entry."""
        from pathlib import Path
        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        content = pyproject.read_text()
        assert "sanna-init-constitution" not in content

    def test_pyproject_has_no_hash_constitution(self):
        """pyproject.toml should not have sanna-hash-constitution entry."""
        from pathlib import Path
        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        content = pyproject.read_text()
        assert "sanna-hash-constitution" not in content

    def test_core_cli_still_present(self):
        """Core CLI entry points should still be present."""
        from pathlib import Path
        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        content = pyproject.read_text()
        assert "sanna-verify" in content
        assert "sanna-sign-constitution" in content
        assert "sanna-keygen" in content
        assert "sanna-gateway" in content
        assert "sanna-init" in content


# =============================================================================
# 7. Check function visibility
# =============================================================================

class TestCheckFunctionVisibility:
    def test_private_check_functions_exist(self):
        """_check_c1 through _check_c5 should be importable."""
        from sanna.receipt import (
            _check_c1_context_contradiction,
            _check_c2_unmarked_inference,
            _check_c3_false_certainty,
            _check_c4_conflict_collapse,
            _check_c5_premature_compression,
        )
        assert callable(_check_c1_context_contradiction)
        assert callable(_check_c5_premature_compression)

    def test_backward_compat_aliases_exist(self):
        """Non-prefixed check_c1 through check_c5 should still be importable."""
        from sanna.receipt import (
            check_c1_context_contradiction,
            check_c2_unmarked_inference,
            check_c3_false_certainty,
            check_c4_conflict_collapse,
            check_c5_premature_compression,
        )
        # They should be the same functions
        from sanna.receipt import _check_c1_context_contradiction
        assert check_c1_context_contradiction is _check_c1_context_contradiction
