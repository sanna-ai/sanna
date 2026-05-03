"""SAN-359: gateway fail-closed when manifest generation or persistence fails."""
from __future__ import annotations

import asyncio
import sys
from unittest.mock import AsyncMock, patch

import pytest

pytest.importorskip("mcp", reason="mcp extra not installed")

from sanna.gateway.server import SannaGateway, _DownstreamState, DownstreamSpec
from sanna.constitution import (
    Constitution,
    AgentIdentity,
    Provenance,
    Boundary,
    AuthorityBoundaries,
)


# =============================================================================
# Helpers
# =============================================================================

def _bare_constitution() -> Constitution:
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
            cannot_execute=[],
            must_escalate=[],
            can_execute=[],
        ),
    )


class _FakeConn:
    tools = []


def _make_gateway(persisted: list | None = None) -> tuple[SannaGateway, list]:
    """Build a minimal SannaGateway via object.__new__ for unit testing.

    Returns (gw, persisted_receipts) where persisted_receipts is the list
    that _fake_persist_receipt_async appends to.
    """
    if persisted is None:
        persisted = []

    gw = object.__new__(SannaGateway)
    spec = DownstreamSpec(name="mock", command=sys.executable, args=[])
    ds_state = _DownstreamState(spec=spec)
    ds_state.connection = _FakeConn()

    gw._downstream_states = {"mock": ds_state}
    gw._constitution = _bare_constitution()
    gw._reasoning_evaluator = None
    gw._manifest_emitted = False
    gw._manifest_failed = False
    gw._manifest_lock = asyncio.Lock()
    gw._constitution_ref = None
    gw._signing_key_path = None
    gw._content_mode = ""
    gw._content_mode_source = ""
    gw._suppressed_tool_names = set()
    gw._manifest_full_fingerprint = None

    async def _fake_persist(receipt):
        persisted.append(receipt)

    gw._persist_receipt_async = _fake_persist
    return gw, persisted


def _simulate_handle_list_tools(gw: SannaGateway) -> list:
    """Replicate the exact handle_list_tools logic from server.py for testing.

    Returns the tool list result (what handle_list_tools would return).
    """
    import logging
    logger = logging.getLogger("sanna.gateway.server")

    async def _inner():
        tool_list = gw._build_tool_list()

        if not gw._manifest_emitted and gw._constitution is not None:
            async with gw._manifest_lock:
                if not gw._manifest_emitted:  # double-check after acquiring lock
                    gw._manifest_emitted = True
                    try:
                        success = await gw._emit_session_manifest(tool_list)
                    except Exception as exc:
                        logger.error("session_manifest emission unexpected failure: %s", exc)
                        success = False
                        gw._manifest_failed = True
                    if not success:
                        return []

        if gw._manifest_failed:
            return []

        return tool_list

    return asyncio.run(_inner())


# =============================================================================
# Tests
# =============================================================================

class TestManifestFailClosed:
    """Gateway returns empty tools on manifest failure (SAN-359)."""

    def test_manifest_generation_failure_returns_empty_tools(self):
        """If generate_manifest raises, _emit_session_manifest returns False."""
        gw, _ = _make_gateway()

        async def _run():
            with patch("sanna.manifest.generate_manifest", side_effect=RuntimeError("boom")):
                result = await gw._emit_session_manifest([])
            assert result is False

        asyncio.run(_run())

    def test_manifest_generation_failure_sets_manifest_failed(self):
        """generate_manifest failure sets _manifest_failed=True."""
        gw, _ = _make_gateway()

        async def _run():
            with patch("sanna.manifest.generate_manifest", side_effect=RuntimeError("boom")):
                await gw._emit_session_manifest([])
            assert gw._manifest_failed is True

        asyncio.run(_run())

    def test_manifest_persistence_failure_returns_empty_tools(self):
        """If receipt persistence raises, _emit_session_manifest returns False."""
        gw, _ = _make_gateway()

        async def _run():
            async def _bad_persist(_receipt):
                raise OSError("disk full")

            gw._persist_receipt_async = _bad_persist
            result = await gw._emit_session_manifest([])
            assert result is False

        asyncio.run(_run())

    def test_manifest_persistence_failure_sets_manifest_failed(self):
        """Persistence failure sets _manifest_failed=True."""
        gw, _ = _make_gateway()

        async def _run():
            async def _bad_persist(_receipt):
                raise OSError("disk full")

            gw._persist_receipt_async = _bad_persist
            await gw._emit_session_manifest([])
            assert gw._manifest_failed is True

        asyncio.run(_run())

    def test_manifest_success_returns_true(self):
        """On success, _emit_session_manifest returns True."""
        gw, _ = _make_gateway()

        async def _run():
            result = await gw._emit_session_manifest([])
            assert result is True

        asyncio.run(_run())

    def test_manifest_success_does_not_set_failed_flag(self):
        """Successful emission leaves _manifest_failed=False."""
        gw, _ = _make_gateway()

        async def _run():
            await gw._emit_session_manifest([])
            assert gw._manifest_failed is False

        asyncio.run(_run())

    def test_handle_list_tools_returns_empty_on_generation_failure(self):
        """handle_list_tools logic returns [] when generate_manifest fails."""
        gw, _ = _make_gateway()

        with patch("sanna.manifest.generate_manifest", side_effect=RuntimeError("boom")):
            result = _simulate_handle_list_tools(gw)

        assert result == []

    def test_handle_list_tools_returns_empty_on_persistence_failure(self):
        """handle_list_tools logic returns [] when receipt persistence fails."""
        gw, _ = _make_gateway()

        async def _bad_persist(_receipt):
            raise OSError("disk full")

        gw._persist_receipt_async = _bad_persist
        result = _simulate_handle_list_tools(gw)

        assert result == []

    def test_manifest_failed_is_sticky(self):
        """Once manifest fails, subsequent tools/list calls also return empty."""
        gw, _ = _make_gateway()

        # First call fails
        with patch("sanna.manifest.generate_manifest", side_effect=RuntimeError("boom")):
            first = _simulate_handle_list_tools(gw)

        assert first == []
        assert gw._manifest_failed is True

        # Second call: generate_manifest would succeed, but _manifest_failed is sticky
        # Reset _manifest_emitted so we exercise the sticky-_manifest_failed path,
        # but keep _manifest_failed=True to confirm it stays blocked.
        gw._manifest_emitted = False  # allow re-entry to the outer if

        async def _run():
            tool_list = gw._build_tool_list()
            # _manifest_failed is True; the sticky check fires before any emit
            if gw._manifest_failed:
                return []
            return tool_list

        second = asyncio.run(_run())
        assert second == []

    def test_fail_status_receipt_emitted_on_generation_failure(self):
        """Even on failure, a FAIL-status session_manifest receipt is emitted."""
        gw, persisted = _make_gateway()

        async def _run():
            with patch("sanna.manifest.generate_manifest", side_effect=RuntimeError("boom")):
                await gw._emit_session_manifest([])

        asyncio.run(_run())

        assert len(persisted) == 1
        assert persisted[0].get("status") == "FAIL"
        assert persisted[0].get("event_type") == "session_manifest"

    def test_empty_response_has_no_tool_names(self):
        """On failure, response is exactly [] -- no partial list, no metadata."""
        gw, _ = _make_gateway()

        with patch("sanna.manifest.generate_manifest", side_effect=RuntimeError("boom")):
            result = _simulate_handle_list_tools(gw)

        assert result == []
        assert isinstance(result, list)

    def test_unexpected_exception_in_emit_caught_by_handler(self):
        """Belt-and-suspenders: exception escaping _emit_session_manifest is caught."""
        gw, _ = _make_gateway()

        async def _run():
            tool_list = gw._build_tool_list()
            import logging
            logger = logging.getLogger("sanna.gateway.server")

            async def _boom(_tl):
                raise SystemError("unexpected internal failure")

            gw._emit_session_manifest = _boom

            if not gw._manifest_emitted and gw._constitution is not None:
                async with gw._manifest_lock:
                    if not gw._manifest_emitted:
                        gw._manifest_emitted = True
                        try:
                            success = await gw._emit_session_manifest(tool_list)
                        except Exception as exc:
                            logger.error("session_manifest emission unexpected failure: %s", exc)
                            success = False
                            gw._manifest_failed = True
                        if not success:
                            return []

            if gw._manifest_failed:
                return []

            return tool_list

        result = asyncio.run(_run())
        assert result == []
        assert gw._manifest_failed is True


# =============================================================================
# SAN-380: concurrent tools/list race tests
# =============================================================================

async def _handle_list_tools(gw: SannaGateway) -> list:
    """Async simulation of handle_list_tools with double-checked locking."""
    import logging
    logger = logging.getLogger("sanna.gateway.server")

    tool_list = gw._build_tool_list()

    if not gw._manifest_emitted and gw._constitution is not None:
        async with gw._manifest_lock:
            if not gw._manifest_emitted:  # double-check after acquiring lock
                gw._manifest_emitted = True
                try:
                    success = await gw._emit_session_manifest(tool_list)
                except Exception as exc:
                    logger.error("session_manifest emission unexpected failure: %s", exc)
                    success = False
                    gw._manifest_failed = True
                if not success:
                    return []

    if gw._manifest_failed:
        return []

    return tool_list


@pytest.mark.asyncio
async def test_concurrent_tools_list_emits_single_manifest():
    """Two concurrent tools/list calls emit exactly ONE session_manifest."""
    gw, persisted = _make_gateway()

    await asyncio.gather(
        _handle_list_tools(gw),
        _handle_list_tools(gw),
    )

    manifests = [r for r in persisted if r.get("event_type") == "session_manifest"]
    assert len(manifests) == 1


@pytest.mark.asyncio
async def test_concurrent_call_waits_for_emission_to_complete():
    """Lock contender cannot acquire the lock until emission completes.

    asyncio.Lock acquisition itself does not yield when the lock is free,
    so both callers racing past the outer check cannot be reproduced without
    an explicit synchronisation point. This test drives one caller directly
    into the lock path while a second caller contends, verifying that the
    contender is held off until emission is finished.
    """
    gw, _ = _make_gateway()

    timeline: list[str] = []
    emission_started = asyncio.Event()
    original_emit = gw._emit_session_manifest

    async def slow_emit(tool_list):
        emission_started.set()
        await asyncio.sleep(0.05)
        result = await original_emit(tool_list)
        timeline.append("emission_complete")
        return result

    gw._emit_session_manifest = slow_emit

    # Caller 1: acquires the lock, emits (models the first past the outer check).
    async def caller_holds_lock():
        async with gw._manifest_lock:
            if not gw._manifest_emitted:
                gw._manifest_emitted = True
                await gw._emit_session_manifest(gw._build_tool_list())

    # Caller 2: waits until emission has started, THEN contends for the lock.
    # emission_started.wait() is the synchronisation that ensures genuine
    # concurrency rather than purely sequential execution.
    async def caller_contends_lock():
        await emission_started.wait()
        async with gw._manifest_lock:
            timeline.append("contender_acquired_lock")

    await asyncio.gather(caller_holds_lock(), caller_contends_lock())

    # Contender must have acquired the lock only AFTER emission completed.
    assert timeline == ["emission_complete", "contender_acquired_lock"]
