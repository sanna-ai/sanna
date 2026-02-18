"""Integration tests: glc_005-enabled receipts sign and verify correctly.

Catches the float serialization bug where glc_005 check.details contained
raw floats (score, threshold) which break RFC 8785 canonical JSON used by
sign_receipt() / sanitize_for_signing().

Uses actual gateway with mock downstream + monkeypatched httpx for LLM calls.
"""

import asyncio
import json
import sys
import textwrap
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("mcp", reason="mcp extra not installed")
httpx = pytest.importorskip("httpx")

from sanna.gateway.server import SannaGateway


# =============================================================================
# MOCK SERVER SCRIPT
# =============================================================================

MOCK_SERVER_SCRIPT = textwrap.dedent("""\
    import json
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("mock_downstream")

    @mcp.tool()
    def get_status() -> str:
        \"\"\"Get the current server status.\"\"\"
        return json.dumps({"status": "ok"})

    @mcp.tool()
    def search(query: str) -> str:
        \"\"\"Search for items.\"\"\"
        return json.dumps({"query": query, "results": ["a", "b"]})

    @mcp.tool()
    def delete_database(db_name: str) -> str:
        \"\"\"Delete a database by name.\"\"\"
        return json.dumps({"deleted": True, "db_name": db_name})

    mcp.run(transport="stdio")
""")


# =============================================================================
# HELPERS
# =============================================================================

def _create_signed_constitution_with_llm(tmp_path):
    """Create a signed v1.1 constitution with glc_005 LLM coherence enabled.

    Returns (constitution_path, private_key_path, public_key_path).
    """
    from sanna.constitution import (
        parse_constitution, sign_constitution, save_constitution,
    )
    from sanna.crypto import generate_keypair

    keys_dir = tmp_path / "keys"
    private_key_path, public_key_path = generate_keypair(str(keys_dir))

    data = {
        "sanna_constitution": "1.1",
        "identity": {"agent_name": "test-agent", "domain": "testing"},
        "provenance": {
            "authored_by": "dev@test.com",
            "approved_by": ["approver@test.com"],
            "approval_date": "2026-01-01",
            "approval_method": "manual-sign-off",
        },
        "boundaries": [
            {
                "id": "B001",
                "description": "Test boundary",
                "category": "scope",
                "severity": "high",
            },
        ],
        "version": "1.1",
        "authority_boundaries": {
            "cannot_execute": [],
            "must_escalate": [
                {"condition": "delete"},
            ],
            "can_execute": ["get_status", "search"],
        },
        "reasoning": {
            "require_justification_for": ["must_escalate"],
            "on_missing_justification": "block",
            "on_check_error": "block",
            "checks": {
                "glc_002_minimum_substance": {"enabled": True, "min_length": 20},
                "glc_003_no_parroting": {"enabled": True},
                "glc_005_llm_coherence": {
                    "enabled": True,
                    "enabled_for": ["must_escalate"],
                    "score_threshold": 0.6,
                },
            },
        },
    }

    constitution = parse_constitution(data)
    signed = sign_constitution(
        constitution, private_key_path=str(private_key_path),
    )

    const_path = tmp_path / "constitution.yaml"
    save_constitution(signed, const_path)

    return str(const_path), str(private_key_path), str(public_key_path)


def _make_mock_response(text: str) -> MagicMock:
    """Build a mock httpx response returning the given text."""
    resp = MagicMock()
    resp.json.return_value = {"content": [{"text": text}]}
    resp.raise_for_status.return_value = None
    return resp


def _patch_post(mock_client_cls, response):
    """Wire up mock_client_cls so async context manager + post() works."""
    mock_instance = AsyncMock()
    mock_instance.post.return_value = response
    mock_client_cls.return_value.__aenter__.return_value = mock_instance
    return mock_instance


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture()
def mock_server_path(tmp_path):
    """Write the mock server script to a temp file."""
    path = tmp_path / "mock_server.py"
    path.write_text(MOCK_SERVER_SCRIPT)
    return str(path)


@pytest.fixture()
def llm_constitution(tmp_path):
    """Constitution with glc_005 LLM coherence enabled."""
    return _create_signed_constitution_with_llm(tmp_path)


# =============================================================================
# RECEIPT SIGNING WITH glc_005
# =============================================================================

class TestGlc005ReceiptSigning:
    """CRITICAL: Verify receipts with glc_005 results sign and verify correctly."""

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    def test_high_score_receipt_signs_and_verifies(
        self, mock_client_cls, mock_server_path, llm_constitution, monkeypatch,
    ):
        """Receipt with passing glc_005 (score=0.85) signs and verifies."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")
        _patch_post(mock_client_cls, _make_mock_response("0.85"))

        const_path, key_path, pub_key_path = llm_constitution

        async def _test():
            from sanna.crypto import verify_receipt_signature

            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                # delete_database matches must_escalate — triggers glc_005
                # Since it escalates, we need to test a can_execute tool
                # that also has LLM enabled, OR test the must_escalate
                # path. Let's use the escalation path receipt.
                result = await gw._forward_call(
                    "mock_delete_database",
                    {
                        "db_name": "stale_test_db",
                        "_justification": (
                            "Removing stale test data per retention policy"
                        ),
                    },
                )

                # This is must_escalate, so result is an escalation
                # But a receipt is still generated with reasoning evaluation
                receipt = gw.last_receipt
                assert receipt is not None

                # Verify receipt was signed
                assert "receipt_signature" in receipt
                assert receipt["receipt_signature"]["signature"] != ""

                # CRITICAL: verify Ed25519 signature
                # This would fail if floats leaked into check.details
                assert verify_receipt_signature(receipt, pub_key_path), (
                    "Receipt signature verification failed — "
                    "possible float serialization bug in glc_005 details"
                )

                # Verify reasoning evaluation is in receipt
                gw_v2 = receipt["extensions"]["com.sanna.gateway"]
                assert "reasoning_evaluation" in gw_v2

                reasoning = gw_v2["reasoning_evaluation"]
                assert reasoning["passed"] is True
                assert reasoning["assurance"] == "full"

                # Verify glc_005 check is present
                check_ids = [c["check_id"] for c in reasoning["checks"]]
                assert "glc_005_llm_coherence" in check_ids

                # Verify NO floats in any check details
                for check in reasoning["checks"]:
                    if check.get("details"):
                        for key, value in check["details"].items():
                            assert not isinstance(value, float), (
                                f"Float found in {check['check_id']}"
                                f".details[{key!r}] = {value}"
                            )

            finally:
                await gw.shutdown()

        asyncio.run(_test())

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    def test_low_score_receipt_signs_and_verifies(
        self, mock_client_cls, mock_server_path, llm_constitution, monkeypatch,
    ):
        """Receipt with failing glc_005 (score=0.3) still signs correctly."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")
        _patch_post(mock_client_cls, _make_mock_response("0.3"))

        const_path, key_path, pub_key_path = llm_constitution

        async def _test():
            from sanna.crypto import verify_receipt_signature

            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_delete_database",
                    {
                        "db_name": "important_db",
                        "_justification": (
                            "Removing stale test data per retention policy"
                        ),
                    },
                )

                receipt = gw.last_receipt
                assert receipt is not None
                assert "receipt_signature" in receipt

                # Signature must still verify even with failed glc_005
                assert verify_receipt_signature(receipt, pub_key_path), (
                    "Receipt signature verification failed on low-score "
                    "glc_005 — possible float in details"
                )

                # Reasoning should show failure (score below threshold)
                gw_v2 = receipt["extensions"]["com.sanna.gateway"]
                reasoning = gw_v2["reasoning_evaluation"]
                assert reasoning["passed"] is False
                assert reasoning["assurance"] == "partial"

                # Verify basis points (not floats) in glc_005 details
                glc_005 = [
                    c for c in reasoning["checks"]
                    if c["check_id"] == "glc_005_llm_coherence"
                ]
                assert len(glc_005) == 1
                details = glc_005[0].get("details") or {}
                if "score_bp" in details:
                    assert isinstance(details["score_bp"], int)
                    assert details["score_bp"] == 3000  # 0.3 * 10000
                if "threshold_bp" in details:
                    assert isinstance(details["threshold_bp"], int)
                    assert details["threshold_bp"] == 6000  # 0.6 * 10000

            finally:
                await gw.shutdown()

        asyncio.run(_test())

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    def test_llm_error_receipt_signs_and_verifies(
        self, mock_client_cls, mock_server_path, llm_constitution, monkeypatch,
    ):
        """Receipt generated when LLM call errors still signs correctly."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")

        # Make the LLM call raise a timeout
        mock_instance = AsyncMock()
        mock_instance.post.side_effect = httpx.TimeoutException("timeout")
        mock_client_cls.return_value.__aenter__.return_value = mock_instance

        const_path, key_path, pub_key_path = llm_constitution

        async def _test():
            from sanna.crypto import verify_receipt_signature

            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_delete_database",
                    {
                        "db_name": "test_db",
                        "_justification": (
                            "Removing stale test data per retention policy"
                        ),
                    },
                )

                receipt = gw.last_receipt
                assert receipt is not None
                assert "receipt_signature" in receipt

                # Signature must verify even with LLM error
                assert verify_receipt_signature(receipt, pub_key_path), (
                    "Receipt signature failed with LLM timeout error"
                )

                # No floats anywhere in the receipt extensions
                self._assert_no_floats(
                    receipt["extensions"], "extensions",
                )

            finally:
                await gw.shutdown()

        asyncio.run(_test())

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    def test_full_verification_with_schema(
        self, mock_client_cls, mock_server_path, llm_constitution, monkeypatch,
    ):
        """Full verify_receipt() passes for glc_005-enabled receipt."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")
        _patch_post(mock_client_cls, _make_mock_response("0.9"))

        const_path, key_path, pub_key_path = llm_constitution

        async def _test():
            from sanna.crypto import verify_receipt_signature
            from sanna.verify import verify_receipt, load_schema

            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_delete_database",
                    {
                        "db_name": "test_db",
                        "_justification": (
                            "Removing stale test data per retention policy"
                        ),
                    },
                )

                receipt = gw.last_receipt
                assert receipt is not None

                # Signature check
                assert verify_receipt_signature(receipt, pub_key_path)

                # Full receipt verification (schema + fingerprint + sig)
                schema = load_schema()
                vr = verify_receipt(
                    receipt, schema, public_key_path=pub_key_path,
                )
                assert vr.valid, (
                    f"Full receipt verification failed: {vr.errors}"
                )

            finally:
                await gw.shutdown()

        asyncio.run(_test())

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    def test_tampering_detected_after_signing(
        self, mock_client_cls, mock_server_path, llm_constitution, monkeypatch,
    ):
        """Tampered glc_005 receipt fails signature verification."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")
        _patch_post(mock_client_cls, _make_mock_response("0.85"))

        const_path, key_path, pub_key_path = llm_constitution

        async def _test():
            from sanna.crypto import verify_receipt_signature

            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_delete_database",
                    {
                        "db_name": "test_db",
                        "_justification": (
                            "Removing stale test data per retention policy"
                        ),
                    },
                )

                receipt = gw.last_receipt
                assert receipt is not None

                # Verify original is valid
                assert verify_receipt_signature(receipt, pub_key_path)

                # Tamper with reasoning evaluation
                gw_v2 = receipt["extensions"]["com.sanna.gateway"]
                gw_v2["reasoning_evaluation"]["passed"] = False

                # Verification must now fail
                assert not verify_receipt_signature(receipt, pub_key_path), (
                    "Tampered receipt should fail signature verification"
                )

            finally:
                await gw.shutdown()

        asyncio.run(_test())

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def _assert_no_floats(self, obj, path: str = "$") -> None:
        """Recursively assert no float values exist in a dict/list tree."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                self._assert_no_floats(v, f"{path}.{k}")
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                self._assert_no_floats(v, f"{path}[{i}]")
        elif isinstance(obj, float):
            # Allow 0.0 and 1.0 which are exact integers
            # (sanitize_for_signing converts these)
            # But flag any truly lossy float
            if obj != int(obj):
                raise AssertionError(
                    f"Lossy float at {path}: {obj!r} — "
                    f"would break RFC 8785 canonical JSON"
                )
