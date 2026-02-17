"""Tests for ReceiptStore — SQLite persistence for reasoning receipts."""

import json
import logging
import os
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sanna.store import ReceiptStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_receipt(
    *,
    receipt_id="r-001",
    trace_id="sanna-abc123",
    timestamp="2026-02-13T10:00:00+00:00",
    coherence_status="PASS",
    agent_name="my-agent",
    constitution_version="1.0.0",
    checks=None,
    halt_event=None,
):
    if checks is None:
        checks = [
            {"check_id": "C1", "name": "Context Contradiction", "passed": True,
             "severity": "critical", "evidence": None},
            {"check_id": "C2", "name": "Unmarked Inference", "passed": True,
             "severity": "warning", "evidence": None},
        ]
    doc_id = f"{agent_name}/{constitution_version}" if agent_name else None
    constitution_ref = {"document_id": doc_id, "policy_hash": "abc123"} if doc_id else None
    return {
        "receipt_id": receipt_id,
        "trace_id": trace_id,
        "timestamp": timestamp,
        "coherence_status": coherence_status,
        "checks": checks,
        "checks_passed": sum(1 for c in checks if c.get("passed")),
        "checks_failed": sum(1 for c in checks if not c.get("passed")),
        "constitution_ref": constitution_ref,
        "halt_event": halt_event,
    }


@pytest.fixture
def store(tmp_path):
    s = ReceiptStore(str(tmp_path / "test.db"))
    yield s
    s.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSchemaCreation:
    def test_creates_db_file(self, tmp_path):
        db = str(tmp_path / "new.db")
        s = ReceiptStore(db)
        assert os.path.exists(db)
        s.close()

    def test_schema_version(self, store):
        row = store._conn.execute("SELECT version FROM schema_version").fetchone()
        assert row["version"] == 1

    def test_idempotent_open(self, tmp_path):
        db = str(tmp_path / "idem.db")
        s1 = ReceiptStore(db); s1.close()
        s2 = ReceiptStore(db)
        assert s2._conn.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0] == 1
        s2.close()


class TestSave:
    def test_save_returns_id(self, store):
        assert store.save(_make_receipt()) == "r-001"

    def test_round_trip(self, store):
        r = _make_receipt()
        store.save(r)
        results = store.query()
        assert len(results) == 1
        assert results[0]["receipt_id"] == "r-001"

    def test_generates_id_when_missing(self, store):
        r = _make_receipt()
        del r["receipt_id"]
        rid = store.save(r)
        assert isinstance(rid, str) and len(rid) == 16

    def test_multiple_saves(self, store):
        for i in range(5):
            store.save(_make_receipt(receipt_id=f"r-{i}", trace_id=f"t-{i}"))
        assert store.count() == 5


class TestQuery:
    def test_by_agent_id(self, store):
        store.save(_make_receipt(receipt_id="r1", agent_name="alpha"))
        store.save(_make_receipt(receipt_id="r2", agent_name="beta"))
        assert len(store.query(agent_id="alpha")) == 1

    def test_by_status(self, store):
        store.save(_make_receipt(receipt_id="r1", coherence_status="PASS"))
        store.save(_make_receipt(receipt_id="r2", coherence_status="FAIL"))
        assert len(store.query(status="FAIL")) == 1

    def test_by_trace_id(self, store):
        store.save(_make_receipt(receipt_id="r1", trace_id="t-aaa"))
        store.save(_make_receipt(receipt_id="r2", trace_id="t-bbb"))
        assert len(store.query(trace_id="t-aaa")) == 1

    def test_empty_db(self, store):
        assert store.query() == []

    def test_no_match(self, store):
        store.save(_make_receipt())
        assert store.query(agent_id="nonexistent") == []

    def test_since_filter(self, store):
        from datetime import datetime, timezone
        store.save(_make_receipt(receipt_id="old", timestamp="2026-01-01T00:00:00+00:00"))
        store.save(_make_receipt(receipt_id="new", timestamp="2026-02-15T00:00:00+00:00"))
        results = store.query(since=datetime(2026, 2, 1, tzinfo=timezone.utc))
        assert len(results) == 1 and results[0]["receipt_id"] == "new"


class TestCount:
    def test_count_all(self, store):
        for i in range(3):
            store.save(_make_receipt(receipt_id=f"r-{i}"))
        assert store.count() == 3

    def test_count_with_filter(self, store):
        store.save(_make_receipt(receipt_id="r1", coherence_status="PASS"))
        store.save(_make_receipt(receipt_id="r2", coherence_status="FAIL"))
        assert store.count(status="PASS") == 1


class TestContextManager:
    def test_enter_exit(self, tmp_path):
        with ReceiptStore(str(tmp_path / "cm.db")) as s:
            s.save(_make_receipt())
            assert s.count() == 1
        assert s._closed

    def test_close_idempotent(self, store):
        store.close()
        store.close()


class TestThreadSafety:
    def test_concurrent_saves(self, tmp_path):
        store = ReceiptStore(str(tmp_path / "threads.db"))
        errors = []
        def save_batch(start):
            try:
                for i in range(20):
                    store.save(_make_receipt(receipt_id=f"t{start}-{i}", trace_id=f"tr{start}-{i}"))
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=save_batch, args=(t,)) for t in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert not errors
        assert store.count() == 100
        store.close()


class TestAutoCreation:
    def test_nested_dirs(self, tmp_path):
        db = str(tmp_path / "a" / "b" / "c" / "receipts.db")
        s = ReceiptStore(db)
        s.save(_make_receipt())
        assert s.count() == 1
        s.close()


# ---------------------------------------------------------------------------
# Additional tests (Block 1 spec completeness)
# ---------------------------------------------------------------------------

class TestContextManagerDetails:
    def test_enter_returns_self(self, tmp_path):
        s = ReceiptStore(str(tmp_path / "ctx.db"))
        assert s.__enter__() is s
        s.close()

    def test_exit_returns_false(self, tmp_path):
        s = ReceiptStore(str(tmp_path / "ctx2.db"))
        assert s.__exit__(None, None, None) is False

    def test_exception_not_suppressed(self, tmp_path):
        """__exit__ returns False so exceptions propagate."""
        with pytest.raises(ValueError):
            with ReceiptStore(str(tmp_path / "ctx3.db")) as s:
                raise ValueError("boom")


class TestCloseIdempotency:
    def test_close_three_times(self, tmp_path):
        s = ReceiptStore(str(tmp_path / "close.db"))
        s.close()
        s.close()
        s.close()
        assert s._closed

    def test_del_after_close(self, tmp_path):
        s = ReceiptStore(str(tmp_path / "del.db"))
        s.close()
        s.__del__()  # should not raise


class TestThreadSafetyExtended:
    def test_concurrent_saves_and_queries(self, tmp_path):
        """Interleaved saves and queries from multiple threads."""
        store = ReceiptStore(str(tmp_path / "rw.db"))
        errors = []

        def writer(batch):
            try:
                for i in range(10):
                    store.save(_make_receipt(
                        receipt_id=f"w{batch}-{i}",
                        trace_id=f"tw{batch}-{i}",
                    ))
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for _ in range(10):
                    store.query()
                    store.count()
            except Exception as e:
                errors.append(e)

        threads = []
        for b in range(3):
            threads.append(threading.Thread(target=writer, args=(b,)))
        for _ in range(2):
            threads.append(threading.Thread(target=reader))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert store.count() == 30
        store.close()

    def test_concurrent_count_during_saves(self, tmp_path):
        store = ReceiptStore(str(tmp_path / "cnt.db"))
        errors = []
        counts = []

        def writer():
            try:
                for i in range(20):
                    store.save(_make_receipt(
                        receipt_id=f"c-{i}", trace_id=f"tc-{i}",
                    ))
            except Exception as e:
                errors.append(e)

        def counter():
            try:
                for _ in range(20):
                    counts.append(store.count())
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=writer)
        t2 = threading.Thread(target=counter)
        t1.start(); t2.start()
        t1.join(); t2.join()

        assert not errors
        assert store.count() == 20
        # counts should be non-decreasing
        for i in range(1, len(counts)):
            assert counts[i] >= counts[i - 1]
        store.close()


class TestLargeBlobs:
    def test_large_receipt_json(self, store):
        """Store a receipt with a large context string (~100KB)."""
        big_context = "x" * 100_000
        r = _make_receipt()
        r["inputs"] = {"context": big_context}
        store.save(r)
        results = store.query()
        assert len(results) == 1
        assert results[0]["inputs"]["context"] == big_context

    def test_many_checks(self, store):
        """Receipt with 50 checks stores and retrieves correctly."""
        checks = [
            {"check_id": f"C-{i}", "name": f"Check {i}",
             "passed": i % 3 != 0, "severity": "info", "evidence": None}
            for i in range(50)
        ]
        r = _make_receipt(checks=checks)
        store.save(r)
        results = store.query()
        assert len(results[0]["checks"]) == 50


class TestMalformedReceipts:
    def test_minimal_receipt(self, store):
        """Just a receipt_id — everything else null/missing."""
        store.save({"receipt_id": "bare"})
        results = store.query()
        assert len(results) == 1
        assert results[0]["receipt_id"] == "bare"

    def test_empty_dict(self, store):
        """Empty dict generates an ID and stores."""
        rid = store.save({})
        assert isinstance(rid, str) and len(rid) == 16
        assert store.count() == 1

    def test_no_constitution_ref(self, store):
        """Receipt without constitution_ref stores with null agent_id."""
        r = {"receipt_id": "no-ref", "coherence_status": "PASS"}
        store.save(r)
        assert store.query(agent_id="anything") == []
        assert store.count() == 1

    def test_numeric_receipt_id_ignored(self, store):
        """Non-string receipt_id is replaced with generated ID."""
        rid = store.save({"receipt_id": 12345})
        assert isinstance(rid, str) and len(rid) == 16


class TestHaltEventFilter:
    def test_query_halt_events(self, store):
        store.save(_make_receipt(receipt_id="ok", halt_event=None))
        store.save(_make_receipt(
            receipt_id="halted",
            halt_event={"halted": True, "reason": "C1 failed"},
        ))
        results = store.query(halt_event=True)
        assert len(results) == 1
        assert results[0]["receipt_id"] == "halted"

    def test_count_halt_events(self, store):
        store.save(_make_receipt(receipt_id="ok1"))
        store.save(_make_receipt(receipt_id="ok2"))
        store.save(_make_receipt(
            receipt_id="h1",
            halt_event={"halted": True, "reason": "fail"},
        ))
        assert store.count(halt_event=True) == 1

    def test_halt_false_not_matched(self, store):
        """halt_event dict with halted=False is NOT a halt event."""
        store.save(_make_receipt(
            receipt_id="soft",
            halt_event={"halted": False, "reason": "n/a"},
        ))
        assert store.count(halt_event=True) == 0


class TestCheckStatusFilter:
    def test_query_by_check_status_pass(self, store):
        store.save(_make_receipt(receipt_id="r1", checks=[
            {"check_id": "C1", "passed": True, "severity": "info"},
        ]))
        store.save(_make_receipt(receipt_id="r2", checks=[
            {"check_id": "C1", "passed": False, "severity": "critical"},
        ]))
        results = store.query(check_status="PASS")
        assert len(results) == 1
        assert results[0]["receipt_id"] == "r1"

    def test_query_by_check_status_fail(self, store):
        store.save(_make_receipt(receipt_id="r1", checks=[
            {"check_id": "C1", "passed": True, "severity": "info"},
        ]))
        store.save(_make_receipt(receipt_id="r2", checks=[
            {"check_id": "C1", "passed": False, "severity": "critical"},
        ]))
        results = store.query(check_status="FAIL")
        assert len(results) == 1
        assert results[0]["receipt_id"] == "r2"

    def test_query_by_check_status_not_checked(self, store):
        store.save(_make_receipt(receipt_id="r1", checks=[
            {"check_id": "INV_CUSTOM", "status": "NOT_CHECKED",
             "passed": True, "severity": "info"},
        ]))
        store.save(_make_receipt(receipt_id="r2", checks=[
            {"check_id": "C1", "passed": True, "severity": "info"},
        ]))
        results = store.query(check_status="NOT_CHECKED")
        assert len(results) == 1
        assert results[0]["receipt_id"] == "r1"


class TestCombinedFilters:
    def test_agent_and_status(self, store):
        store.save(_make_receipt(receipt_id="r1", agent_name="alpha", coherence_status="PASS"))
        store.save(_make_receipt(receipt_id="r2", agent_name="alpha", coherence_status="FAIL"))
        store.save(_make_receipt(receipt_id="r3", agent_name="beta", coherence_status="FAIL"))
        results = store.query(agent_id="alpha", status="FAIL")
        assert len(results) == 1
        assert results[0]["receipt_id"] == "r2"

    def test_since_and_agent(self, store):
        from datetime import datetime, timezone
        store.save(_make_receipt(
            receipt_id="r1", agent_name="alpha",
            timestamp="2026-01-01T00:00:00+00:00",
        ))
        store.save(_make_receipt(
            receipt_id="r2", agent_name="alpha",
            timestamp="2026-02-15T00:00:00+00:00",
        ))
        store.save(_make_receipt(
            receipt_id="r3", agent_name="beta",
            timestamp="2026-02-15T00:00:00+00:00",
        ))
        results = store.query(
            agent_id="alpha",
            since=datetime(2026, 2, 1, tzinfo=timezone.utc),
        )
        assert len(results) == 1
        assert results[0]["receipt_id"] == "r2"

    def test_until_filter(self, store):
        from datetime import datetime, timezone
        store.save(_make_receipt(receipt_id="old", timestamp="2026-01-01T00:00:00+00:00"))
        store.save(_make_receipt(receipt_id="new", timestamp="2026-03-01T00:00:00+00:00"))
        results = store.query(until=datetime(2026, 2, 1, tzinfo=timezone.utc))
        assert len(results) == 1
        assert results[0]["receipt_id"] == "old"

    def test_all_filters_combined(self, store):
        from datetime import datetime, timezone
        store.save(_make_receipt(
            receipt_id="target", agent_name="alpha",
            coherence_status="FAIL", trace_id="t-target",
            timestamp="2026-02-10T00:00:00+00:00",
        ))
        store.save(_make_receipt(
            receipt_id="decoy", agent_name="alpha",
            coherence_status="PASS", trace_id="t-other",
            timestamp="2026-02-10T00:00:00+00:00",
        ))
        results = store.query(
            agent_id="alpha",
            status="FAIL",
            trace_id="t-target",
            since=datetime(2026, 2, 1, tzinfo=timezone.utc),
            until=datetime(2026, 2, 28, tzinfo=timezone.utc),
        )
        assert len(results) == 1
        assert results[0]["receipt_id"] == "target"


class TestExtraction:
    def test_agent_id_from_real_receipt(self, store):
        """agent_id is extracted from constitution_ref.document_id."""
        r = _make_receipt(receipt_id="r1", agent_name="my-agent", constitution_version="2.0")
        store.save(r)
        results = store.query(agent_id="my-agent")
        assert len(results) == 1

    def test_constitution_id_from_real_receipt(self, store):
        """constitution_id is the full document_id."""
        r = _make_receipt(receipt_id="r1", agent_name="svc", constitution_version="3.1")
        store.save(r)
        results = store.query(constitution_id="svc/3.1")
        assert len(results) == 1

    def test_no_agent_when_no_ref(self, store):
        """Receipts without constitution_ref have NULL agent_id."""
        store.save({"receipt_id": "no-ref", "coherence_status": "PASS"})
        # Should not match any agent_id query
        assert store.query(agent_id="no-ref") == []
        # But should appear in unfiltered query
        assert len(store.query()) == 1

    def test_agent_id_with_slash_in_name(self, store):
        """Agent name containing no slash is extracted correctly."""
        store.save(_make_receipt(receipt_id="r1", agent_name="org/subagent", constitution_version="1.0"))
        # document_id = "org/subagent/1.0", split on first / → agent_id = "org"
        # This tests current behavior: first segment before first slash
        results = store.query(agent_id="org")
        assert len(results) == 1


class TestMiddlewareStoreIntegration:
    """Tests for the store parameter on @sanna_observe."""

    CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"

    def test_store_instance_saves_receipt(self, tmp_path):
        """Passing a ReceiptStore instance auto-saves the receipt."""
        from sanna.middleware import sanna_observe

        store = ReceiptStore(str(tmp_path / "mw.db"))

        @sanna_observe(store=store)
        def agent(query: str, context: str) -> str:
            return "hello"

        result = agent(query="q", context="c")
        assert store.count() == 1
        saved = store.query()[0]
        assert saved["receipt_id"] == result.receipt["receipt_id"]
        store.close()

    def test_store_string_path(self, tmp_path):
        """Passing a db_path string creates a store and saves."""
        from sanna.middleware import sanna_observe

        db = str(tmp_path / "str.db")

        @sanna_observe(store=db)
        def agent(query: str, context: str) -> str:
            return "hello"

        agent(query="q", context="c")
        # Verify by opening the same DB
        s = ReceiptStore(db)
        assert s.count() == 1
        s.close()

    def test_store_failure_swallowed(self, tmp_path, caplog):
        """A broken store logs a warning but doesn't break the decorator."""
        from sanna.middleware import sanna_observe

        broken_store = MagicMock()
        broken_store.save.side_effect = RuntimeError("disk full")

        @sanna_observe(store=broken_store)
        def agent(query: str, context: str) -> str:
            return "hello"

        with caplog.at_level(logging.WARNING, logger="sanna.middleware"):
            result = agent(query="q", context="c")

        # Receipt still returned despite store failure
        assert result.receipt is not None
        assert result.output == "hello"
        assert "Failed to save receipt to store" in caplog.text

    def test_store_none_default(self):
        """Default store=None doesn't change behavior."""
        from sanna.middleware import sanna_observe

        @sanna_observe()
        def agent(query: str, context: str) -> str:
            return "hello"

        result = agent(query="q", context="c")
        assert result.receipt is not None


# =============================================================================
# LIMIT / OFFSET
# =============================================================================

class TestQueryLimitOffset:

    @pytest.fixture(autouse=True)
    def _populate(self, store):
        for i in range(200):
            store.save(_make_receipt(
                receipt_id=f"r-{i:03d}",
                timestamp=f"2026-02-{(i % 28) + 1:02d}T10:00:00+00:00",
            ))

    def test_limit_returns_exact_count(self, store):
        results = store.query(limit=10)
        assert len(results) == 10

    def test_offset_returns_different_results(self, store):
        first = store.query(limit=10, offset=0)
        second = store.query(limit=10, offset=10)
        assert len(first) == 10
        assert len(second) == 10
        first_ids = {r["receipt_id"] for r in first}
        second_ids = {r["receipt_id"] for r in second}
        assert first_ids.isdisjoint(second_ids)

    def test_offset_past_end_returns_empty(self, store):
        results = store.query(limit=10, offset=200)
        assert len(results) == 0

    def test_no_limit_returns_all(self, store):
        results = store.query()
        assert len(results) == 200

    def test_count_unaffected_by_limit(self, store):
        assert store.count() == 200


# =============================================================================
# SCHEMA VERSION GUARD
# =============================================================================

class TestNegativeLimit:
    """FIX 3: Negative limit should not bypass row guards."""

    def test_negative_limit_returns_all(self, store):
        """Negative limit is treated as no limit (returns all rows)."""
        for i in range(10):
            store.save(_make_receipt(receipt_id=f"r-{i}"))
        results = store.query(limit=-1)
        assert len(results) == 10

    def test_zero_limit_returns_zero(self, store):
        """Limit=0 returns 0 rows."""
        for i in range(10):
            store.save(_make_receipt(receipt_id=f"r-{i}"))
        results = store.query(limit=0)
        assert len(results) == 0

    def test_large_negative_limit_safe(self, store):
        """Very large negative limit doesn't crash or bypass."""
        for i in range(5):
            store.save(_make_receipt(receipt_id=f"r-{i}"))
        results = store.query(limit=-1000000)
        assert len(results) == 5


class TestSchemaVersionGuard:

    def test_mismatched_schema_version_raises(self, tmp_path):
        """Opening a DB with wrong schema_version raises ValueError."""
        import sqlite3
        db_path = str(tmp_path / "bad.db")
        # Create a store to init the schema, then close it
        s = ReceiptStore(db_path)
        s.close()
        # Tamper with schema_version
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE schema_version SET version = 999")
        conn.commit()
        conn.close()
        # Reopen should raise
        with pytest.raises(ValueError, match="schema version"):
            ReceiptStore(db_path)

    def test_correct_schema_version_works(self, tmp_path):
        """Normal close/reopen with matching version works fine."""
        db_path = str(tmp_path / "ok.db")
        s = ReceiptStore(db_path)
        s.save(_make_receipt(receipt_id="r1"))
        s.close()
        # Reopen
        s2 = ReceiptStore(db_path)
        assert s2.count() == 1
        s2.close()


class TestSchemaVersionClosesConnection:
    """FIX 6: Schema version mismatch closes DB connection."""

    def test_connection_closed_on_mismatch(self, tmp_path):
        """After schema version mismatch, DB is not left locked."""
        import sqlite3
        db_path = str(tmp_path / "lock.db")
        # Create and close normally
        s = ReceiptStore(db_path)
        s.close()
        # Tamper with schema_version
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE schema_version SET version = 999")
        conn.commit()
        conn.close()
        # Open should fail
        with pytest.raises(ValueError, match="schema version"):
            ReceiptStore(db_path)
        # DB should NOT be locked — prove by opening with raw sqlite3
        conn2 = sqlite3.connect(db_path)
        row = conn2.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        assert row[0] == 999
        conn2.close()


class TestWALMode:
    """FIX 7: SQLite WAL mode is enabled."""

    def test_wal_mode_enabled(self, tmp_path):
        """ReceiptStore enables WAL journal mode."""
        db_path = str(tmp_path / "wal.db")
        store = ReceiptStore(db_path)
        row = store._conn.execute("PRAGMA journal_mode").fetchone()
        assert row[0] == "wal"
        store.close()


# =============================================================================
# Block 4 — SQLite permissions hardening (#9)
# =============================================================================


class TestSQLitePermissions:
    """ReceiptStore hardens directory and file permissions (#9)."""

    def test_receipt_store_dir_permissions(self, tmp_path):
        """Parent directory has 0o700 permissions."""
        import stat
        db_dir = tmp_path / "secure_store"
        db_path = str(db_dir / "receipts.db")
        store = ReceiptStore(db_path)
        mode = db_dir.stat().st_mode & 0o777
        assert mode == 0o700, f"Expected 0o700, got {oct(mode)}"
        store.close()

    def test_receipt_store_file_permissions(self, tmp_path):
        """DB file has 0o600 permissions."""
        import stat
        db_path = str(tmp_path / "secure.db")
        store = ReceiptStore(db_path)
        from pathlib import Path
        mode = Path(db_path).stat().st_mode & 0o777
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"
        store.close()
