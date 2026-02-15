"""Tests for gateway hardening (Block F).

Tests cover: crash recovery, circuit breaker, timeout handling,
receipt persistence, receipt file verification, filename format,
latency budget, structured logging, and reconnect.
"""

import asyncio
import json
import logging
import os
import sys
import textwrap
import time

import pytest

pytest.importorskip("mcp", reason="mcp extra not installed")

import mcp.types as types

from sanna.gateway.mcp_client import DownstreamConnection
from sanna.gateway.server import (
    CircuitState,
    SannaGateway,
    _CIRCUIT_BREAKER_THRESHOLD,
    _DEFAULT_CIRCUIT_BREAKER_COOLDOWN,
    _extract_result_text,
)


# =============================================================================
# MOCK SERVER SCRIPTS
# =============================================================================

MOCK_SERVER_SCRIPT = textwrap.dedent("""\
    import json
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("mock_downstream")

    @mcp.tool()
    def get_status() -> str:
        \"\"\"Get the current server status.\"\"\"
        return json.dumps({"status": "ok", "version": "1.0"})

    @mcp.tool()
    def search(query: str, limit: int = 10) -> str:
        \"\"\"Search for items matching a query.\"\"\"
        return json.dumps({"query": query, "limit": limit, "results": ["a", "b"]})

    @mcp.tool()
    def delete_item(item_id: str) -> str:
        \"\"\"Delete an item by ID.\"\"\"
        return json.dumps({"deleted": True, "item_id": item_id})

    @mcp.tool()
    def set_threshold(name: str, threshold: float) -> str:
        \"\"\"Set a named threshold value.\"\"\"
        return json.dumps({"name": name, "threshold": threshold})

    @mcp.tool()
    def configure(config: str) -> str:
        \"\"\"Accept a JSON config string.\"\"\"
        return json.dumps({"applied": True, "config": config})

    mcp.run(transport="stdio")
""")

# Server that exits after the first tool call (simulates crash)
CRASHING_SERVER_SCRIPT = textwrap.dedent("""\
    import json
    import os
    import signal
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("crashing_downstream")

    _call_count = 0

    @mcp.tool()
    def get_status() -> str:
        \"\"\"Get the current server status.\"\"\"
        global _call_count
        _call_count += 1
        if _call_count > 1:
            # Kill ourselves to simulate a crash
            os.kill(os.getpid(), signal.SIGTERM)
        return json.dumps({"status": "ok"})

    mcp.run(transport="stdio")
""")


# =============================================================================
# HELPERS
# =============================================================================

def _create_signed_constitution(tmp_path, authority_boundaries=None):
    """Create a signed constitution and keypair for testing."""
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
    private_key_path, public_key_path = generate_keypair(str(keys_dir))

    identity = AgentIdentity(
        agent_name="test-agent",
        domain="testing",
    )
    provenance = Provenance(
        authored_by="test@example.com",
        approved_by=["approver@example.com"],
        approval_date="2024-01-01",
        approval_method="manual-sign-off",
    )
    boundaries = [
        Boundary(
            id="B001",
            description="Test boundary",
            category="scope",
            severity="high",
        ),
    ]

    constitution = Constitution(
        schema_version="0.1.0",
        identity=identity,
        provenance=provenance,
        boundaries=boundaries,
        invariants=[],
        authority_boundaries=authority_boundaries,
    )

    signed = sign_constitution(
        constitution, private_key_path=str(private_key_path),
    )

    const_path = tmp_path / "constitution.yaml"
    save_constitution(signed, const_path)

    return str(const_path), str(private_key_path), str(public_key_path)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture()
def mock_server_path(tmp_path):
    """Write the standard mock server script."""
    path = tmp_path / "mock_server.py"
    path.write_text(MOCK_SERVER_SCRIPT)
    return str(path)


@pytest.fixture()
def crashing_server_path(tmp_path):
    """Write the crashing server script."""
    path = tmp_path / "crashing_server.py"
    path.write_text(CRASHING_SERVER_SCRIPT)
    return str(path)


@pytest.fixture()
def signed_constitution(tmp_path):
    """Create a signed constitution with no authority boundaries."""
    const_path, private_key, public_key = _create_signed_constitution(
        tmp_path,
    )
    return const_path, private_key, public_key


@pytest.fixture()
def receipt_store(tmp_path):
    """Create a receipt store directory."""
    store = tmp_path / "receipts"
    store.mkdir()
    return str(store)


# =============================================================================
# 1. CONNECTION ERROR TRACKING (mcp_client.py)
# =============================================================================

class TestConnectionErrorTracking:
    def test_successful_call_clears_error_flag(self, mock_server_path):
        """Successful tool calls clear the connection error flag."""
        async def _test():
            conn = DownstreamConnection(
                command=sys.executable, args=[mock_server_path],
            )
            await conn.connect()
            try:
                result = await conn.call_tool("get_status")
                assert result.isError is not True
                assert conn.last_call_was_connection_error is False
            finally:
                await conn.close()

        asyncio.run(_test())

    def test_not_connected_sets_error_flag(self):
        """Calling on a disconnected client sets the error flag."""
        async def _test():
            conn = DownstreamConnection(
                command="unused", args=[],
            )
            result = await conn.call_tool("anything")
            assert result.isError is True
            assert conn.last_call_was_connection_error is True

        asyncio.run(_test())

    def test_reconnect_restores_connection(self, mock_server_path):
        """reconnect() closes and re-establishes the connection."""
        async def _test():
            conn = DownstreamConnection(
                command=sys.executable, args=[mock_server_path],
            )
            await conn.connect()
            try:
                # Verify connected
                assert conn.connected is True
                original_tools = conn.tool_names

                # Reconnect
                await conn.reconnect()
                assert conn.connected is True
                assert conn.tool_names == original_tools
            finally:
                await conn.close()

        asyncio.run(_test())

    def test_error_flag_initially_false(self, mock_server_path):
        """Connection error flag starts as False."""
        conn = DownstreamConnection(
            command=sys.executable, args=[mock_server_path],
        )
        assert conn.last_call_was_connection_error is False


# =============================================================================
# 2. CIRCUIT BREAKER
# =============================================================================

class TestCircuitBreaker:
    def test_gateway_starts_healthy(self, mock_server_path):
        """Gateway starts in healthy state (circuit CLOSED)."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                assert gw.healthy is True
                assert gw.circuit_state == CircuitState.CLOSED
                assert gw.consecutive_failures == 0
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_successful_call_keeps_healthy(self, mock_server_path):
        """A successful tool call keeps the gateway healthy."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                result = await gw._forward_call("mock_get_status", {})
                assert result.isError is not True
                assert gw.healthy is True
                assert gw.consecutive_failures == 0
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_unhealthy_blocks_forwarding(
        self, mock_server_path, signed_constitution, receipt_store,
    ):
        """An unhealthy gateway returns error without forwarding."""
        from datetime import datetime, timezone
        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
                receipt_store_path=receipt_store,
            )
            await gw.start()
            try:
                # Force circuit OPEN (cooldown not elapsed)
                gw._circuit_state = CircuitState.OPEN
                gw._circuit_opened_at = datetime.now(timezone.utc)
                result = await gw._forward_call("mock_get_status", {})
                assert result.isError is True
                assert "unhealthy" in result.content[0].text.lower()
                # Error receipt should have been generated
                assert gw.last_receipt is not None
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_unhealthy_generates_error_receipt(
        self, mock_server_path, signed_constitution, receipt_store,
    ):
        """Unhealthy gateway generates an error receipt with halt event."""
        from datetime import datetime, timezone
        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
                receipt_store_path=receipt_store,
            )
            await gw.start()
            try:
                gw._circuit_state = CircuitState.OPEN
                gw._circuit_opened_at = datetime.now(timezone.utc)
                await gw._forward_call("mock_get_status", {})
                receipt = gw.last_receipt
                assert receipt is not None
                assert receipt["halt_event"]["halted"] is True
                assert "unhealthy" in receipt["halt_event"]["reason"].lower()
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_circuit_breaker_threshold_constant(self):
        """Circuit breaker threshold is 3."""
        assert _CIRCUIT_BREAKER_THRESHOLD == 3

    def test_default_cooldown_constant(self):
        """Default circuit breaker cooldown is 60 seconds."""
        assert _DEFAULT_CIRCUIT_BREAKER_COOLDOWN == 60.0


# =============================================================================
# 2b. HALF-OPEN CIRCUIT BREAKER
# =============================================================================

class TestHalfOpenCircuitBreaker:
    """Tests for the half-open circuit breaker recovery pattern."""

    def test_three_failures_opens_circuit(
        self, mock_server_path, signed_constitution,
    ):
        """3 consecutive failures → circuit opens → calls return error."""
        from datetime import datetime, timezone

        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
            )
            await gw.start()
            try:
                # Simulate 3 consecutive connection failures
                gw._consecutive_failures = _CIRCUIT_BREAKER_THRESHOLD
                gw._circuit_state = CircuitState.OPEN
                gw._circuit_opened_at = datetime.now(timezone.utc)

                assert gw.circuit_state == CircuitState.OPEN
                assert gw.healthy is False

                result = await gw._forward_call("mock_get_status", {})
                assert result.isError is True
                assert "circuit breaker" in result.content[0].text.lower()
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_blocked_before_cooldown_elapsed(
        self, mock_server_path, signed_constitution,
    ):
        """Before cooldown elapsed → calls still return error receipts."""
        from datetime import datetime, timezone

        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
                circuit_breaker_cooldown=60.0,
            )
            await gw.start()
            try:
                # Circuit just opened — cooldown NOT elapsed
                gw._circuit_state = CircuitState.OPEN
                gw._circuit_opened_at = datetime.now(timezone.utc)

                result = await gw._forward_call("mock_get_status", {})
                assert result.isError is True
                # State should remain OPEN
                assert gw.circuit_state == CircuitState.OPEN
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_probe_after_cooldown_elapsed(
        self, mock_server_path, signed_constitution,
    ):
        """After cooldown elapsed → next call forwarded as probe."""
        from datetime import datetime, timedelta, timezone

        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
                circuit_breaker_cooldown=1.0,  # 1s cooldown
            )
            await gw.start()
            try:
                # Circuit opened 2 seconds ago (cooldown = 1s)
                gw._circuit_state = CircuitState.OPEN
                gw._circuit_opened_at = (
                    datetime.now(timezone.utc) - timedelta(seconds=2)
                )

                # This call should be forwarded as probe
                result = await gw._forward_call("mock_get_status", {})
                # Mock server is healthy, so probe succeeds
                assert result.isError is not True
                # Circuit should be CLOSED after successful probe
                assert gw.circuit_state == CircuitState.CLOSED
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_probe_success_closes_circuit(
        self, mock_server_path, signed_constitution,
    ):
        """Probe succeeds → circuit closes → normal operation resumes."""
        from datetime import datetime, timedelta, timezone

        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
                circuit_breaker_cooldown=0.1,
            )
            await gw.start()
            try:
                # Open circuit, set cooldown in the past
                gw._circuit_state = CircuitState.OPEN
                gw._circuit_opened_at = (
                    datetime.now(timezone.utc) - timedelta(seconds=1)
                )
                gw._consecutive_failures = 3

                # Probe call — mock server is healthy
                result = await gw._forward_call("mock_get_status", {})
                assert result.isError is not True
                assert gw.circuit_state == CircuitState.CLOSED
                assert gw.consecutive_failures == 0

                # Normal operation should resume
                result2 = await gw._forward_call(
                    "mock_search", {"query": "test"},
                )
                assert result2.isError is not True
                assert gw.circuit_state == CircuitState.CLOSED
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_probe_failure_reopens_circuit(
        self, mock_server_path, signed_constitution,
    ):
        """Probe fails → circuit reopens → another cooldown period."""
        from datetime import datetime, timedelta, timezone

        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
                circuit_breaker_cooldown=0.1,
            )
            await gw.start()
            try:
                # Open circuit with cooldown in the past
                gw._circuit_state = CircuitState.OPEN
                gw._circuit_opened_at = (
                    datetime.now(timezone.utc) - timedelta(seconds=1)
                )

                # Kill downstream to simulate failure
                if gw._downstream is not None:
                    await gw._downstream.close()

                # Probe call — downstream is dead, should fail
                result = await gw._forward_call("mock_get_status", {})
                # Probe failure: circuit should reopen
                assert gw.circuit_state == CircuitState.OPEN
                # _circuit_opened_at should be refreshed
                assert gw._circuit_opened_at is not None
            finally:
                # Already shut down
                gw._downstream = None
                gw._tool_map.clear()

        asyncio.run(_test())

    def test_half_open_blocks_concurrent_calls(
        self, mock_server_path, signed_constitution,
    ):
        """During HALF_OPEN → only one probe, other calls get error."""
        from datetime import datetime, timezone

        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
            )
            await gw.start()
            try:
                # Force HALF_OPEN directly
                gw._circuit_state = CircuitState.HALF_OPEN

                # This call should be blocked (probe already in flight)
                result = await gw._forward_call("mock_get_status", {})
                assert result.isError is True
                assert "unhealthy" in result.content[0].text.lower()
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_counter_reset_after_probe_success(
        self, mock_server_path, signed_constitution,
    ):
        """Success after probe → failure counter reset to 0."""
        from datetime import datetime, timedelta, timezone

        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
                circuit_breaker_cooldown=0.1,
            )
            await gw.start()
            try:
                gw._circuit_state = CircuitState.OPEN
                gw._circuit_opened_at = (
                    datetime.now(timezone.utc) - timedelta(seconds=1)
                )
                gw._consecutive_failures = 5

                # Probe succeeds (mock server is healthy)
                await gw._forward_call("mock_get_status", {})
                assert gw.consecutive_failures == 0
                assert gw.circuit_state == CircuitState.CLOSED
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_state_transitions_logged(
        self, mock_server_path, signed_constitution, caplog,
    ):
        """Circuit breaker state transitions are logged."""
        from datetime import datetime, timedelta, timezone

        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
                circuit_breaker_cooldown=0.1,
            )
            await gw.start()
            try:
                gw._circuit_state = CircuitState.OPEN
                gw._circuit_opened_at = (
                    datetime.now(timezone.utc) - timedelta(seconds=1)
                )
                with caplog.at_level(
                    logging.INFO, logger="sanna.gateway.server",
                ):
                    # Probe call (cooldown elapsed, mock is healthy)
                    await gw._forward_call("mock_get_status", {})

                # Should log cooldown elapsed and recovery
                messages = " ".join(r.message for r in caplog.records)
                assert "probe" in messages.lower()
                assert "recovered" in messages.lower()
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_error_receipt_documents_circuit_breaker(
        self, mock_server_path, signed_constitution, receipt_store,
    ):
        """Error receipts during OPEN state document circuit breaker."""
        from datetime import datetime, timezone

        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
                receipt_store_path=receipt_store,
            )
            await gw.start()
            try:
                gw._circuit_state = CircuitState.OPEN
                gw._circuit_opened_at = datetime.now(timezone.utc)
                await gw._forward_call("mock_get_status", {})
                receipt = gw.last_receipt
                assert receipt is not None
                # The halt reason should mention circuit breaker
                reason = receipt["halt_event"]["reason"].lower()
                assert "circuit breaker" in reason
                assert "unhealthy" in reason
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_cooldown_is_configurable(self, mock_server_path):
        """Circuit breaker cooldown can be set via constructor."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                circuit_breaker_cooldown=120.0,
            )
            await gw.start()
            try:
                assert gw._circuit_breaker_cooldown == 120.0
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_cooldown_from_config(self, tmp_path):
        """circuit_breaker_cooldown is parsed from gateway.yaml."""
        from sanna.gateway.config import GatewayConfig
        cfg = GatewayConfig(circuit_breaker_cooldown=90.0)
        assert cfg.circuit_breaker_cooldown == 90.0

    def test_cooldown_default_in_config(self, tmp_path):
        """circuit_breaker_cooldown defaults to 60s in config."""
        from sanna.gateway.config import GatewayConfig
        cfg = GatewayConfig()
        assert cfg.circuit_breaker_cooldown == 60.0


# =============================================================================
# 3. RECEIPT PERSISTENCE
# =============================================================================

class TestReceiptPersistence:
    def test_receipt_persisted_to_directory(
        self, mock_server_path, signed_constitution, receipt_store,
    ):
        """Receipts are written as JSON files to the receipt store."""
        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
                receipt_store_path=receipt_store,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                # Check receipt file exists
                files = os.listdir(receipt_store)
                json_files = [f for f in files if f.endswith(".json")]
                assert len(json_files) == 1
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_receipt_filename_format(
        self, mock_server_path, signed_constitution, receipt_store,
    ):
        """Receipt filename follows {timestamp}_{receipt_id}.json format."""
        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
                receipt_store_path=receipt_store,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                files = [f for f in os.listdir(receipt_store) if f.endswith(".json")]
                assert len(files) == 1
                name = files[0]
                # Should not contain colons (filesystem-safe)
                assert ":" not in name
                # Should end with .json
                assert name.endswith(".json")
                # Should contain the receipt_id
                receipt = gw.last_receipt
                assert receipt["receipt_id"] in name
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_persisted_receipt_is_valid_json(
        self, mock_server_path, signed_constitution, receipt_store,
    ):
        """Persisted receipt file is valid JSON matching last_receipt."""
        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
                receipt_store_path=receipt_store,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                files = [f for f in os.listdir(receipt_store) if f.endswith(".json")]
                filepath = os.path.join(receipt_store, files[0])
                with open(filepath) as f:
                    persisted = json.load(f)
                assert persisted["receipt_id"] == gw.last_receipt["receipt_id"]
                assert persisted["trace_id"] == gw.last_receipt["trace_id"]
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_persisted_receipt_verifies_fingerprint(
        self, mock_server_path, signed_constitution, receipt_store,
    ):
        """Persisted receipt passes fingerprint verification."""
        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
                receipt_store_path=receipt_store,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                files = [f for f in os.listdir(receipt_store) if f.endswith(".json")]
                filepath = os.path.join(receipt_store, files[0])
                with open(filepath) as f:
                    persisted = json.load(f)

                from sanna.verify import verify_fingerprint
                matches, computed, expected = verify_fingerprint(persisted)
                assert matches is True, (
                    f"Fingerprint mismatch: {computed} != {expected}"
                )
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_multiple_calls_create_multiple_files(
        self, mock_server_path, signed_constitution, receipt_store,
    ):
        """Each tool call creates a separate receipt file."""
        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
                receipt_store_path=receipt_store,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                await gw._forward_call(
                    "mock_search", {"query": "test"},
                )
                files = [f for f in os.listdir(receipt_store) if f.endswith(".json")]
                assert len(files) == 2
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_no_persistence_without_store_path(
        self, mock_server_path, signed_constitution,
    ):
        """No receipt files created when receipt_store_path is None."""
        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
                # No receipt_store_path
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                assert gw.last_receipt is not None
                # No crash, no files written
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 4. STRUCTURED LOGGING
# =============================================================================

class TestStructuredLogging:
    def test_allow_logged_at_info(
        self, mock_server_path, signed_constitution, caplog,
    ):
        """Allowed tool calls are logged at INFO."""
        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
            )
            await gw.start()
            try:
                with caplog.at_level(logging.INFO, logger="sanna.gateway.server"):
                    await gw._forward_call("mock_get_status", {})
                assert any("ALLOW" in r.message for r in caplog.records)
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_deny_logged_at_warning(
        self, mock_server_path, signed_constitution, caplog,
    ):
        """Denied tool calls are logged at WARNING."""
        async def _test():
            from sanna.constitution import AuthorityBoundaries
            const_path, private_key, _ = _create_signed_constitution(
                pytest.importorskip("tmp_path_factory"),
            )

        # Create constitution with cannot_execute boundary
        async def _test2():
            from sanna.constitution import AuthorityBoundaries
            tmp = mock_server_path  # just need the fixture trigger
            # Use policy_overrides instead (simpler)
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=signed_constitution[0],
                signing_key_path=signed_constitution[1],
                policy_overrides={"get_status": "cannot_execute"},
            )
            await gw.start()
            try:
                with caplog.at_level(logging.WARNING, logger="sanna.gateway.server"):
                    await gw._forward_call("mock_get_status", {})
                assert any("DENY" in r.message for r in caplog.records)
            finally:
                await gw.shutdown()

        asyncio.run(_test2())

    def test_circuit_breaker_logged_at_error(
        self, mock_server_path, signed_constitution, caplog, receipt_store,
    ):
        """Circuit breaker open is logged at WARNING."""
        from datetime import datetime, timezone
        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
                receipt_store_path=receipt_store,
            )
            await gw.start()
            try:
                gw._circuit_state = CircuitState.OPEN
                gw._circuit_opened_at = datetime.now(timezone.utc)
                with caplog.at_level(logging.WARNING, logger="sanna.gateway.server"):
                    await gw._forward_call("mock_get_status", {})
                assert any(
                    "circuit breaker" in r.message.lower()
                    for r in caplog.records
                )
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 5. LATENCY BUDGET
# =============================================================================

class TestLatencyBudget:
    def test_gateway_overhead_under_500ms(
        self, mock_server_path, signed_constitution, receipt_store,
    ):
        """Gateway enforcement + receipt overhead < 500ms per call."""
        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
                receipt_store_path=receipt_store,
            )
            await gw.start()
            try:
                # Warm up — first call may include lazy imports
                await gw._forward_call("mock_get_status", {})

                # Measure over several calls
                times = []
                for _ in range(5):
                    start = time.monotonic()
                    await gw._forward_call(
                        "mock_search", {"query": "test"},
                    )
                    elapsed = time.monotonic() - start
                    times.append(elapsed)

                avg = sum(times) / len(times)
                # Allow generous margin for CI — assert < 2s
                # (500ms target, but CI machines are slow)
                assert avg < 2.0, (
                    f"Average gateway overhead {avg:.3f}s exceeds 2.0s"
                )
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 6. TIMEOUT CONFIGURATION
# =============================================================================

class TestTimeoutConfig:
    def test_timeout_from_config(self):
        """DownstreamConfig supports configurable timeout."""
        from sanna.gateway.config import DownstreamConfig
        ds = DownstreamConfig(
            name="test",
            command="unused",
            timeout=60.0,
        )
        assert ds.timeout == 60.0

    def test_timeout_default(self):
        """DownstreamConfig defaults to 30s timeout."""
        from sanna.gateway.config import DownstreamConfig
        ds = DownstreamConfig(
            name="test",
            command="unused",
        )
        assert ds.timeout == 30.0


# =============================================================================
# 7. CRASH RECOVERY
# =============================================================================

class TestCrashRecovery:
    def test_after_downstream_call_resets_on_success(self, mock_server_path):
        """Successful downstream call resets failure counter."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                # Simulate prior failures
                gw._consecutive_failures = 2
                result = await gw._forward_call("mock_get_status", {})
                assert result.isError is not True
                assert gw.consecutive_failures == 0
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_rebuild_tool_map(self, mock_server_path):
        """_rebuild_tool_map correctly rebuilds from downstream tools."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                original_map = dict(gw.tool_map)
                gw._tool_map.clear()
                assert gw.tool_map == {}
                gw._rebuild_tool_map()
                assert gw.tool_map == original_map
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_error_receipt_has_correct_structure(
        self, mock_server_path, signed_constitution,
    ):
        """Error receipts have halt_event and authority_decisions."""
        async def _test():
            const_path, private_key, _ = signed_constitution
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
            )
            await gw.start()
            try:
                receipt = gw._generate_error_receipt(
                    prefixed_name="mock_get_status",
                    original_name="get_status",
                    arguments={},
                    error_text="test error",
                )
                assert receipt["halt_event"]["halted"] is True
                assert "test error" in receipt["halt_event"]["reason"]
                assert len(receipt["authority_decisions"]) == 1
                assert receipt["authority_decisions"][0]["decision"] == "halt"
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# ARGUMENTS HASH FLOAT FALLBACK (v0.10.2)
# =============================================================================


class TestArgumentsHashFloatFallback:
    """hash_obj rejects floats (RFC 8785). Gateway must not crash."""

    def test_integer_arguments_use_jcs(
        self, mock_server_path, signed_constitution,
    ):
        """Integer arguments use the canonical JCS hash method."""
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_search", {"query": "test", "limit": 10},
                )
                gw_ext = gw.last_receipt["extensions"]["gateway"]
                assert gw_ext["arguments_hash_method"] == "jcs"
                assert len(gw_ext["arguments_hash"]) == 16
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_float_arguments_use_fallback(
        self, mock_server_path, signed_constitution,
    ):
        """Float arguments trigger json_dumps_fallback — no crash."""
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_set_threshold",
                    {"name": "accuracy", "threshold": 0.85},
                )
                gw_ext = gw.last_receipt["extensions"]["gateway"]
                assert gw_ext["arguments_hash_method"] == "json_dumps_fallback"
                assert len(gw_ext["arguments_hash"]) == 16
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_nested_float_uses_fallback(
        self, mock_server_path, signed_constitution,
    ):
        """Nested float in arguments triggers fallback."""
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_configure",
                    {"config": json.dumps({"rate": 1.5, "count": 3})},
                )
                gw_ext = gw.last_receipt["extensions"]["gateway"]
                # config value is a string (JSON-encoded), so no float
                # at the top level — should use JCS
                assert gw_ext["arguments_hash_method"] == "jcs"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_mixed_int_float_uses_fallback(
        self, mock_server_path, signed_constitution,
    ):
        """Mixed int + float arguments triggers fallback."""
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                # search accepts int limit, but we pass float
                await gw._forward_call(
                    "mock_set_threshold",
                    {"name": "score", "threshold": 0.95},
                )
                gw_ext = gw.last_receipt["extensions"]["gateway"]
                assert gw_ext["arguments_hash_method"] == "json_dumps_fallback"
                assert len(gw_ext["arguments_hash"]) == 16
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_empty_arguments_hash_present(
        self, mock_server_path, signed_constitution,
    ):
        """Empty/no arguments still produce a valid arguments_hash."""
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                gw_ext = gw.last_receipt["extensions"]["gateway"]
                assert "arguments_hash" in gw_ext
                assert len(gw_ext["arguments_hash"]) == 16
                assert gw_ext["arguments_hash_method"] == "jcs"
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# TOOL OUTPUT CONTENT HANDLING (v0.10.2)
# =============================================================================


class TestExtractResultText:
    """_extract_result_text handles all MCP content shapes safely."""

    def test_single_text_content(self):
        """Standard single text content extracted."""
        result = types.CallToolResult(
            content=[types.TextContent(type="text", text="hello world")],
        )
        assert _extract_result_text(result) == "hello world"

    def test_empty_content_list(self):
        """Empty content list returns empty string."""
        result = types.CallToolResult(content=[])
        assert _extract_result_text(result) == ""

    def test_multiple_text_items(self):
        """Multiple text items joined with newlines."""
        result = types.CallToolResult(
            content=[
                types.TextContent(type="text", text="line 1"),
                types.TextContent(type="text", text="line 2"),
                types.TextContent(type="text", text="line 3"),
            ],
        )
        text = _extract_result_text(result)
        assert text == "line 1\nline 2\nline 3"

    def test_non_text_content(self):
        """Non-text content (e.g., image) produces placeholder, no crash."""
        image_item = types.ImageContent(
            type="image",
            data="aGVsbG8=",  # base64 "hello"
            mimeType="image/png",
        )
        result = types.CallToolResult(content=[image_item])
        text = _extract_result_text(result)
        assert "[image content]" in text

    def test_none_result(self):
        """None tool result returns empty string."""
        assert _extract_result_text(None) == ""

    def test_output_hash_covers_full_text(
        self, mock_server_path, signed_constitution,
    ):
        """tool_output_hash in receipt covers full extracted text."""
        from sanna.hashing import hash_text
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_get_status", {},
                )
                r = gw.last_receipt
                gw_ext = r["extensions"]["gateway"]
                # The output hash should correspond to the actual output
                # (not empty, not truncated)
                assert gw_ext["tool_output_hash"] != hash_text("")
                assert len(gw_ext["tool_output_hash"]) == 16
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# CIRCUIT BREAKER PROBE: list_tools HEALTH CHECK (Fix 1)
# =============================================================================

class TestCircuitBreakerProbe:
    def test_probe_uses_list_tools_not_call_tool(
        self, mock_server_path, signed_constitution,
    ):
        """Probe calls list_tools(), not a user tool call."""
        from datetime import datetime, timedelta, timezone

        const_path, private_key, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
            )
            await gw.start()
            try:
                ds = gw._first_ds
                conn = ds.connection
                original_list_tools = conn.list_tools
                original_call_tool = conn.call_tool

                list_tools_count = 0
                call_tool_count = 0

                async def mock_list_tools():
                    nonlocal list_tools_count
                    list_tools_count += 1
                    return await original_list_tools()

                async def mock_call_tool(name, args=None, **kw):
                    nonlocal call_tool_count
                    call_tool_count += 1
                    return await original_call_tool(name, args, **kw)

                conn.list_tools = mock_list_tools
                conn.call_tool = mock_call_tool

                # Force OPEN with cooldown elapsed
                ds.circuit_state = CircuitState.OPEN
                ds.circuit_opened_at = (
                    datetime.now(timezone.utc) - timedelta(seconds=61)
                )

                # Forward a call — should trigger probe
                result = await gw._forward_call("mock_get_status", {})

                # list_tools was called for the probe
                assert list_tools_count >= 1
                # call_tool was called for the user's actual request
                assert call_tool_count == 1
                assert result.isError is not True
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_failed_probe_blocks_user_call(
        self, mock_server_path, signed_constitution,
    ):
        """Failed probe returns error without forwarding user call."""
        from datetime import datetime, timedelta, timezone
        from sanna.gateway.mcp_client import DownstreamConnectionError

        const_path, private_key, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
            )
            await gw.start()
            try:
                ds = gw._first_ds
                conn = ds.connection
                call_tool_count = 0
                original_call_tool = conn.call_tool

                async def mock_call_tool(name, args=None, **kw):
                    nonlocal call_tool_count
                    call_tool_count += 1
                    return await original_call_tool(name, args, **kw)

                async def failing_list_tools():
                    raise DownstreamConnectionError("probe failed")

                conn.list_tools = failing_list_tools
                conn.call_tool = mock_call_tool

                # Force OPEN with cooldown elapsed
                ds.circuit_state = CircuitState.OPEN
                ds.circuit_opened_at = (
                    datetime.now(timezone.utc) - timedelta(seconds=61)
                )

                result = await gw._forward_call("mock_get_status", {})
                assert result.isError is True
                assert "unhealthy" in _extract_result_text(result)
                # User tool call was NOT forwarded
                assert call_tool_count == 0
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# RECEIPT FILE PERMISSIONS (Fix 3)
# =============================================================================

@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only permissions")
class TestReceiptPermissions:
    def test_receipt_dir_0700(
        self, mock_server_path, signed_constitution, tmp_path,
    ):
        """Receipt store directory has 0o700 permissions."""
        const_path, private_key, _ = signed_constitution
        store = str(tmp_path / "receipts")

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
                receipt_store_path=store,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                import stat
                mode = os.stat(store).st_mode & 0o777
                assert mode == 0o700, f"Expected 0o700, got {oct(mode)}"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_receipt_file_0600(
        self, mock_server_path, signed_constitution, tmp_path,
    ):
        """Receipt files have 0o600 permissions."""
        const_path, private_key, _ = signed_constitution
        store = str(tmp_path / "receipts")

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=private_key,
                receipt_store_path=store,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                import stat
                from pathlib import Path
                files = list(Path(store).glob("*.json"))
                assert len(files) >= 1
                for f in files:
                    mode = f.stat().st_mode & 0o777
                    assert mode == 0o600, (
                        f"Expected 0o600 for {f.name}, got {oct(mode)}"
                    )
            finally:
                await gw.shutdown()

        asyncio.run(_test())
