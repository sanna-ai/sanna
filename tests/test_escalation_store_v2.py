"""Block E tests — escalation store: purge timer, disk persistence, restart."""

import asyncio
import json
import os
import time

import pytest

mcp = pytest.importorskip("mcp", reason="mcp extra not installed")

from sanna.gateway.server import EscalationStore, PendingEscalation


class TestPurgeTimer:
    def test_purge_timer_removes_expired(self, tmp_path):
        """Create escalation, advance past TTL, verify purged by timer."""
        store = EscalationStore(timeout=1, max_pending=10)
        entry = store.create(
            prefixed_name="ds_update",
            original_name="update",
            arguments={"id": 1},
            server_name="ds",
            reason="test",
        )
        assert len(store) == 1

        # Wait for TTL expiry
        time.sleep(1.1)

        # Manual purge should remove it
        purged = store.purge_expired()
        assert purged == 1
        assert len(store) == 0

    def test_purge_timer_async_loop(self, tmp_path):
        """Async purge loop fires and removes expired entries."""
        persist_path = str(tmp_path / "escalations.json")
        store = EscalationStore(
            timeout=1, max_pending=10, persist_path=persist_path,
        )
        store.create(
            prefixed_name="ds_update",
            original_name="update",
            arguments={},
            server_name="ds",
            reason="test",
        )
        assert len(store) == 1

        async def _test():
            await store.start_purge_timer(interval_seconds=1)
            # Wait for TTL + purge interval
            await asyncio.sleep(2.5)
            await store.stop_purge_timer()

        asyncio.run(_test())

        assert len(store) == 0


class TestDiskPersistence:
    def test_persist_to_disk(self, tmp_path):
        """Create escalation, save, verify file on disk."""
        persist_path = str(tmp_path / "escalations.json")
        store = EscalationStore(
            timeout=300, max_pending=10, persist_path=persist_path,
        )
        store.create(
            prefixed_name="ds_update",
            original_name="update",
            arguments={"key": "value"},
            server_name="ds",
            reason="must escalate",
        )

        assert os.path.exists(persist_path)
        with open(persist_path) as f:
            data = json.load(f)
        assert len(data) == 1
        record = next(iter(data.values()))
        assert record["original_name"] == "update"
        assert record["arguments"] == {"key": "value"}

    def test_persist_atomic_write(self, tmp_path):
        """Verify .tmp file pattern used (no .tmp file left behind)."""
        persist_path = str(tmp_path / "escalations.json")
        store = EscalationStore(
            timeout=300, max_pending=10, persist_path=persist_path,
        )
        store.create(
            prefixed_name="ds_update",
            original_name="update",
            arguments={},
            server_name="ds",
            reason="test",
        )

        # .tmp file should not exist after save completes
        assert not os.path.exists(persist_path + ".tmp")
        assert os.path.exists(persist_path)

    def test_restart_preserves_escalations(self, tmp_path):
        """Save, create new store from same path, verify loaded."""
        persist_path = str(tmp_path / "escalations.json")

        store1 = EscalationStore(
            timeout=300, max_pending=10, persist_path=persist_path,
        )
        entry = store1.create(
            prefixed_name="ds_update",
            original_name="update",
            arguments={"page_id": "abc"},
            server_name="ds",
            reason="must escalate",
        )
        eid = entry.escalation_id

        # Simulate restart: new store, same persist path
        store2 = EscalationStore(
            timeout=300, max_pending=10, persist_path=persist_path,
        )
        assert len(store2) == 1
        loaded = store2.get(eid)
        assert loaded is not None
        assert loaded.original_name == "update"
        assert loaded.arguments == {"page_id": "abc"}

    def test_expired_not_loaded(self, tmp_path):
        """Save expired escalation, reload, verify not present."""
        persist_path = str(tmp_path / "escalations.json")

        store1 = EscalationStore(
            timeout=1, max_pending=10, persist_path=persist_path,
        )
        store1.create(
            prefixed_name="ds_update",
            original_name="update",
            arguments={},
            server_name="ds",
            reason="test",
        )

        # Wait for expiry
        time.sleep(1.1)

        # Reload — expired entry should not be loaded
        store2 = EscalationStore(
            timeout=1, max_pending=10, persist_path=persist_path,
        )
        assert len(store2) == 0
