"""Tests for Block 3: Token Store Hardening.

Covers:
- File locking prevents race conditions on concurrent writes
- TTL-based pruning of expired tokens
- Size cap enforcement
- expires_at field presence
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time

import pytest


@pytest.fixture
def gateway_with_tokens(tmp_path):
    """Create a minimal SannaGateway with token file delivery."""
    mcp = pytest.importorskip("mcp")
    from sanna.gateway.server import SannaGateway

    gw = object.__new__(SannaGateway)
    gw._escalation_store = type(
        "FakeStore", (), {"timeout": 300},
    )()
    gw._token_delivery = ["file"]
    gw._require_approval_token = True
    gw._gateway_secret = os.urandom(32)
    # Override the token path via monkeypatching in tests
    return gw


# ---------------------------------------------------------------------------
# File locking (Gemini #4)
# ---------------------------------------------------------------------------


class TestTokenFileLocking:

    def test_concurrent_writes_no_token_lost(self, tmp_path, monkeypatch):
        """Simulate concurrent writes — verify no tokens lost."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway.server import SannaGateway

        tokens_path = str(tmp_path / "pending_tokens.json")
        monkeypatch.setattr(
            os.path, "expanduser",
            lambda p: tokens_path if "pending_tokens" in p else p,
        )

        gw = object.__new__(SannaGateway)
        gw._escalation_store = type(
            "FakeStore", (), {"timeout": 300},
        )()
        gw._MAX_PENDING_TOKENS = 1000

        errors = []
        num_threads = 5
        tokens_per_thread = 4

        def writer(thread_id):
            try:
                for i in range(tokens_per_thread):
                    token_info = {
                        "escalation_id": f"esc_{thread_id}_{i}",
                        "token": f"tok_{thread_id}_{i}",
                        "tool_name": "test_tool",
                        "timestamp": "2024-01-01T00:00:00Z",
                        "ttl_remaining": 300,
                        "expires_at": time.time() + 300,
                    }
                    gw._deliver_token_to_file(token_info)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=writer, args=(i,))
            for i in range(num_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during concurrent writes: {errors}"

        # Read back and verify all tokens are present
        with open(tokens_path) as f:
            tokens = json.load(f)

        expected = num_threads * tokens_per_thread
        assert len(tokens) == expected, (
            f"Expected {expected} tokens, got {len(tokens)}"
        )

    def test_lock_blocks_concurrent_access(self, tmp_path, monkeypatch):
        """FileLock prevents interleaved reads/writes."""
        mcp = pytest.importorskip("mcp")
        from filelock import FileLock

        tokens_path = str(tmp_path / "pending_tokens.json")
        lock_path = tokens_path + ".lock"

        # Hold the lock from this thread
        lock = FileLock(lock_path, timeout=0.5)
        lock.acquire()

        blocked = []

        def try_acquire():
            try:
                inner = FileLock(lock_path, timeout=0.5)
                inner.acquire()
                inner.release()
            except Exception as e:
                blocked.append(e)

        t = threading.Thread(target=try_acquire)
        t.start()
        t.join()

        lock.release()

        # The second thread should have been blocked/timed out
        assert len(blocked) == 1


# ---------------------------------------------------------------------------
# TTL pruning (GPT #6)
# ---------------------------------------------------------------------------


class TestTokenTTLPruning:

    def test_expired_tokens_pruned_on_write(self, tmp_path, monkeypatch):
        """Tokens with past expires_at are removed when a new token is added."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway.server import SannaGateway

        tokens_path = str(tmp_path / "pending_tokens.json")
        monkeypatch.setattr(
            os.path, "expanduser",
            lambda p: tokens_path if "pending_tokens" in p else p,
        )

        # Pre-populate with expired tokens
        expired_tokens = [
            {
                "escalation_id": f"old_{i}",
                "token": f"old_tok_{i}",
                "expires_at": time.time() - 100,  # expired
            }
            for i in range(5)
        ]
        with open(tokens_path, "w") as f:
            json.dump(expired_tokens, f)

        gw = object.__new__(SannaGateway)
        gw._escalation_store = type(
            "FakeStore", (), {"timeout": 300},
        )()
        gw._MAX_PENDING_TOKENS = 1000

        # Write a fresh token
        fresh = {
            "escalation_id": "new_1",
            "token": "new_tok",
            "expires_at": time.time() + 300,
        }
        gw._deliver_token_to_file(fresh)

        with open(tokens_path) as f:
            tokens = json.load(f)

        # Only the fresh token should remain
        assert len(tokens) == 1
        assert tokens[0]["escalation_id"] == "new_1"

    def test_tokens_without_expires_at_kept(self, tmp_path, monkeypatch):
        """Legacy tokens without expires_at are not pruned."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway.server import SannaGateway

        tokens_path = str(tmp_path / "pending_tokens.json")
        monkeypatch.setattr(
            os.path, "expanduser",
            lambda p: tokens_path if "pending_tokens" in p else p,
        )

        # Pre-populate with a legacy token (no expires_at)
        legacy = [{"escalation_id": "legacy_1", "token": "tok"}]
        with open(tokens_path, "w") as f:
            json.dump(legacy, f)

        gw = object.__new__(SannaGateway)
        gw._escalation_store = type(
            "FakeStore", (), {"timeout": 300},
        )()
        gw._MAX_PENDING_TOKENS = 1000

        gw._deliver_token_to_file({
            "escalation_id": "new_1",
            "token": "new_tok",
            "expires_at": time.time() + 300,
        })

        with open(tokens_path) as f:
            tokens = json.load(f)

        assert len(tokens) == 2


# ---------------------------------------------------------------------------
# Size cap (GPT #6)
# ---------------------------------------------------------------------------


class TestTokenSizeCap:

    def test_size_cap_enforced(self, tmp_path, monkeypatch):
        """Writing beyond the cap drops the oldest entries."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway.server import SannaGateway

        tokens_path = str(tmp_path / "pending_tokens.json")
        monkeypatch.setattr(
            os.path, "expanduser",
            lambda p: tokens_path if "pending_tokens" in p else p,
        )

        # Pre-populate with exactly cap tokens
        cap = 10  # use small cap for testing
        existing = [
            {
                "escalation_id": f"esc_{i}",
                "token": f"tok_{i}",
                "expires_at": time.time() + 300,
            }
            for i in range(cap)
        ]
        with open(tokens_path, "w") as f:
            json.dump(existing, f)

        gw = object.__new__(SannaGateway)
        gw._escalation_store = type(
            "FakeStore", (), {"timeout": 300},
        )()
        gw._MAX_PENDING_TOKENS = cap  # set low cap for test

        # Write one more token
        gw._deliver_token_to_file({
            "escalation_id": "newest",
            "token": "newest_tok",
            "expires_at": time.time() + 300,
        })

        with open(tokens_path) as f:
            tokens = json.load(f)

        assert len(tokens) == cap
        # Newest should be present (kept at end)
        assert tokens[-1]["escalation_id"] == "newest"
        # Oldest should be dropped
        assert tokens[0]["escalation_id"] != "esc_0"

    def test_size_cap_logs_warning(self, tmp_path, monkeypatch, caplog):
        """Warning logged when cap is exceeded."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway.server import SannaGateway

        tokens_path = str(tmp_path / "pending_tokens.json")
        monkeypatch.setattr(
            os.path, "expanduser",
            lambda p: tokens_path if "pending_tokens" in p else p,
        )

        cap = 5
        existing = [
            {
                "escalation_id": f"esc_{i}",
                "token": f"tok_{i}",
                "expires_at": time.time() + 300,
            }
            for i in range(cap)
        ]
        with open(tokens_path, "w") as f:
            json.dump(existing, f)

        gw = object.__new__(SannaGateway)
        gw._escalation_store = type(
            "FakeStore", (), {"timeout": 300},
        )()
        gw._MAX_PENDING_TOKENS = cap

        with caplog.at_level(logging.WARNING):
            gw._deliver_token_to_file({
                "escalation_id": "overflow",
                "token": "tok",
                "expires_at": time.time() + 300,
            })

        assert any(
            "exceeded" in r.message and "pruned" in r.message
            for r in caplog.records
        )


# ---------------------------------------------------------------------------
# Token metadata (expires_at field)
# ---------------------------------------------------------------------------


class TestTokenMetadata:

    def test_token_has_expires_at(self, tmp_path, monkeypatch):
        """New tokens include the expires_at timestamp."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway.server import SannaGateway

        tokens_path = str(tmp_path / "pending_tokens.json")
        monkeypatch.setattr(
            os.path, "expanduser",
            lambda p: tokens_path if "pending_tokens" in p else p,
        )

        gw = object.__new__(SannaGateway)
        gw._escalation_store = type(
            "FakeStore", (), {"timeout": 300},
        )()
        gw._token_delivery = ["file"]
        gw._require_approval_token = True
        gw._gateway_secret = os.urandom(32)
        gw._MAX_PENDING_TOKENS = 1000

        # Simulate what _deliver_token does
        import time as _time
        ttl = int(gw._escalation_store.timeout)
        token_info = {
            "escalation_id": "esc_test",
            "token": "tok_test",
            "tool_name": "test_tool",
            "timestamp": "2024-01-01T00:00:00Z",
            "ttl_remaining": ttl,
            "expires_at": _time.time() + ttl,
        }
        gw._deliver_token_to_file(token_info)

        with open(tokens_path) as f:
            tokens = json.load(f)

        assert len(tokens) == 1
        assert "expires_at" in tokens[0]
        assert tokens[0]["expires_at"] > _time.time()
