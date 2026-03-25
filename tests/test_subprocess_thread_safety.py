"""Tests for thread-safety of subprocess interceptor [SAN-46].

Verifies that _restore_originals is thread-safe:
- Concurrent threads both produce governance receipts
- Internal call chains (subprocess.run -> Popen) don't deadlock
- Thread-local flag correctly skips governance for internal calls
"""

from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path

import pytest

from sanna.interceptors import patch_subprocess, unpatch_subprocess
from sanna.interceptors.subprocess_interceptor import (
    _restore_lock,
    _restore_originals,
    _thread_local,
)
from sanna.sinks.sink import ReceiptSink, SinkResult


# =============================================================================
# HELPERS
# =============================================================================

CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"
CLI_TEST_CONSTITUTION = str(CONSTITUTIONS_DIR / "cli-test.yaml")


class ThreadSafeCaptureSink(ReceiptSink):
    """Thread-safe sink that captures receipts for inspection."""

    def __init__(self):
        self.receipts: list[dict] = []
        self._lock = threading.Lock()

    def store(self, receipt: dict) -> SinkResult:
        with self._lock:
            self.receipts.append(receipt)
        return SinkResult(stored=1)

    @property
    def count(self) -> int:
        with self._lock:
            return len(self.receipts)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture(autouse=True)
def cleanup():
    """Ensure subprocess is unpatched after every test."""
    yield
    unpatch_subprocess()


@pytest.fixture
def sink():
    return ThreadSafeCaptureSink()


@pytest.fixture
def patched(sink):
    """Patch subprocess with cli-test constitution in enforce mode."""
    patch_subprocess(
        constitution_path=CLI_TEST_CONSTITUTION,
        sink=sink,
        agent_id="test-agent",
        mode="enforce",
    )
    return sink


# =============================================================================
# TESTS
# =============================================================================


class TestConcurrentThreadsProduceReceipts:
    """Two threads calling subprocess.run concurrently both generate receipts."""

    def test_concurrent_subprocess_run_both_governed(self, patched):
        """Both threads should produce governance receipts."""
        errors = []
        results = [None, None]

        def run_echo(idx):
            try:
                result = subprocess.run(
                    ["echo", f"thread-{idx}"],
                    capture_output=True,
                )
                results[idx] = result
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=run_echo, args=(0,))
        t2 = threading.Thread(target=run_echo, args=(1,))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        assert not errors, f"Threads raised exceptions: {errors}"
        assert results[0] is not None
        assert results[1] is not None
        # Both threads should have generated receipts
        assert patched.count == 2


class TestInternalCallChainNoDeadlock:
    """Internal call chains (e.g., subprocess.run -> Popen) must not deadlock."""

    def test_restore_originals_rlock_allows_reentry(self, patched):
        """RLock should allow re-entrant acquisition from the same thread."""
        # This simulates what happens when subprocess.run internally uses Popen:
        # the outer _restore_originals holds the lock, and an inner call from
        # the same thread should not deadlock thanks to RLock + thread-local flag.
        result = subprocess.run(
            ["echo", "no-deadlock"],
            capture_output=True,
        )
        assert result.returncode == 0
        assert patched.count == 1

    def test_rlock_reentry_does_not_deadlock(self):
        """Direct test that RLock allows same-thread re-acquisition."""
        _restore_lock.acquire()
        try:
            # RLock should allow this without deadlock
            acquired = _restore_lock.acquire(timeout=1)
            assert acquired, "RLock did not allow same-thread re-acquisition"
            _restore_lock.release()
        finally:
            _restore_lock.release()


class TestThreadLocalFlag:
    """Thread-local flag correctly skips governance for internal calls."""

    def test_restoring_flag_defaults_false(self):
        """Thread-local 'restoring' should default to False on new threads."""
        flag_values = []

        def check_flag():
            flag_values.append(getattr(_thread_local, 'restoring', False))

        t = threading.Thread(target=check_flag)
        t.start()
        t.join(timeout=5)

        assert flag_values == [False]

    def test_restoring_flag_isolated_per_thread(self, patched):
        """Setting restoring=True in one thread should not affect another."""
        other_thread_flag = []

        def set_flag_and_check():
            _thread_local.restoring = True
            # Give the other thread time to read
            time.sleep(0.05)
            _thread_local.restoring = False

        def read_flag():
            time.sleep(0.02)  # Read while the other thread has restoring=True
            other_thread_flag.append(getattr(_thread_local, 'restoring', False))

        t1 = threading.Thread(target=set_flag_and_check)
        t2 = threading.Thread(target=read_flag)
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        # Thread 2 should see False — the flag is thread-local
        assert other_thread_flag == [False]

    def test_restore_originals_sets_and_clears_flag(self):
        """_restore_originals should set restoring=True on enter, False on exit."""
        assert getattr(_thread_local, 'restoring', False) is False

        with _restore_originals():
            assert _thread_local.restoring is True

        assert _thread_local.restoring is False

    def test_restore_originals_clears_flag_on_exception(self):
        """Flag must be cleared even if an exception occurs inside the block."""
        try:
            with _restore_originals():
                assert _thread_local.restoring is True
                raise RuntimeError("simulated failure")
        except RuntimeError:
            pass

        assert _thread_local.restoring is False


class TestNoUngovernedWindowForOtherThreads:
    """The restore window must not allow ungoverned access from other threads."""

    def test_lock_blocks_concurrent_restore(self):
        """A second thread trying to restore should block until the first releases."""
        entered_first = threading.Event()
        entered_second = threading.Event()
        order = []

        def first():
            with _restore_originals():
                order.append("first_enter")
                entered_first.set()
                # Hold the lock for a bit
                time.sleep(0.1)
                order.append("first_exit")

        def second():
            entered_first.wait(timeout=5)
            # Small delay to ensure we try to acquire after first holds it
            time.sleep(0.02)
            with _restore_originals():
                order.append("second_enter")
                entered_second.set()

        t1 = threading.Thread(target=first)
        t2 = threading.Thread(target=second)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        # second_enter must come after first_exit (lock serialization)
        assert order.index("first_exit") < order.index("second_enter")
