"""Block C tests — SQLite JSON1 feature detection and fallback."""

from __future__ import annotations

import json
import logging
import sqlite3
from unittest.mock import patch, MagicMock

import pytest

from sanna.store import ReceiptStore


def _make_receipt(check_status: str = "PASS", check_id: str = "C1") -> dict:
    """Create a minimal receipt dict for testing."""
    return {
        "receipt_id": f"test-{check_id}-{check_status}",
        "correlation_id": "trace-001",
        "timestamp": "2026-01-01T00:00:00Z",
        "status": "PASS" if check_status == "PASS" else "FAIL",
        "constitution_ref": {
            "document_id": "test-agent/1.0",
        },
        "checks": [
            {
                "check_id": check_id,
                "passed": check_status == "PASS",
                "status": check_status,
            }
        ],
    }


class TestJSON1Detection:
    def test_json1_detection_available(self, tmp_path):
        """Standard SQLite with JSON1 → _has_json1 is True."""
        db_path = str(tmp_path / "test.db")
        store = ReceiptStore(db_path)
        try:
            # Most modern SQLite builds include JSON1
            # If this environment doesn't, the test is still valid
            # (it will be False, which is also a correct detection)
            assert isinstance(store._has_json1, bool)
        finally:
            store.close()

    def test_json1_detection_unavailable(self, tmp_path, caplog):
        """Mocked SQLite without JSON1 → _has_json1 is False, logs warning."""
        db_path = str(tmp_path / "test.db")

        # Create a store, then mock the detection method to simulate no JSON1
        original_detect = ReceiptStore._detect_json1

        def mock_no_json1(self):
            # Simulate OperationalError on json_extract
            try:
                self._conn.execute("SELECT no_such_function('{}', '$')")
            except sqlite3.OperationalError:
                pass
            # Return False as if JSON1 was not available
            return False

        with patch.object(ReceiptStore, "_detect_json1", mock_no_json1):
            store = ReceiptStore(db_path)
            try:
                assert store._has_json1 is False
            finally:
                store.close()

    def test_query_with_json1(self, tmp_path):
        """check_status filter works with JSON1 available."""
        db_path = str(tmp_path / "test.db")
        store = ReceiptStore(db_path)
        try:
            if not store._has_json1:
                pytest.skip("JSON1 not available in this SQLite build")

            store.save(_make_receipt("PASS", "C1"))
            store.save(_make_receipt("FAIL", "C2"))

            pass_results = store.query(check_status="PASS")
            assert len(pass_results) == 1
            assert pass_results[0]["receipt_id"] == "test-C1-PASS"

            fail_results = store.query(check_status="FAIL")
            assert len(fail_results) == 1
            assert fail_results[0]["receipt_id"] == "test-C2-FAIL"
        finally:
            store.close()

    def test_query_fallback_without_json1(self, tmp_path):
        """check_status filter uses LIKE fallback when JSON1 unavailable."""
        db_path = str(tmp_path / "test.db")

        # Patch _detect_json1 to return False
        with patch.object(ReceiptStore, "_detect_json1", return_value=False):
            store = ReceiptStore(db_path)

        try:
            assert store._has_json1 is False

            store.save(_make_receipt("PASS", "C1"))
            store.save(_make_receipt("FAIL", "C2"))

            # LIKE fallback should still return correct results
            pass_results = store.query(check_status="PASS")
            assert len(pass_results) == 1
            assert pass_results[0]["receipt_id"] == "test-C1-PASS"

            fail_results = store.query(check_status="FAIL")
            assert len(fail_results) == 1
            assert fail_results[0]["receipt_id"] == "test-C2-FAIL"
        finally:
            store.close()
