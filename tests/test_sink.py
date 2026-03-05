"""Tests for ReceiptSink ABC, SinkResult, and FailurePolicy."""

import pytest

from sanna.sink import FailurePolicy, ReceiptSink, SinkError, SinkResult


# ---------------------------------------------------------------------------
# SinkResult
# ---------------------------------------------------------------------------

class TestSinkResult:
    def test_ok_when_no_failures(self):
        r = SinkResult(stored=3, failed=0, errors=())
        assert r.ok is True

    def test_not_ok_when_failures(self):
        r = SinkResult(stored=1, failed=2, errors=("err1", "err2"))
        assert r.ok is False

    def test_frozen(self):
        r = SinkResult(stored=1, failed=0, errors=())
        with pytest.raises(AttributeError):
            r.stored = 5  # type: ignore[misc]

    def test_frozen_errors(self):
        r = SinkResult(stored=0, failed=1, errors=("e",))
        with pytest.raises(AttributeError):
            r.errors = ()  # type: ignore[misc]


# ---------------------------------------------------------------------------
# FailurePolicy
# ---------------------------------------------------------------------------

class TestFailurePolicy:
    def test_has_three_values(self):
        assert len(FailurePolicy) == 3

    def test_values(self):
        assert FailurePolicy.LOG_AND_CONTINUE.value == "log_and_continue"
        assert FailurePolicy.RAISE.value == "raise"
        assert FailurePolicy.BUFFER_AND_RETRY.value == "buffer_and_retry"


# ---------------------------------------------------------------------------
# ReceiptSink ABC
# ---------------------------------------------------------------------------

class TestReceiptSinkABC:
    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            ReceiptSink()  # type: ignore[abstract]

    def test_subclass_must_implement_store(self):
        class Incomplete(ReceiptSink):
            def batch_store(self, receipts):
                pass
            def flush(self):
                pass
            def close(self):
                pass

        with pytest.raises(TypeError):
            Incomplete()

    def test_subclass_must_implement_batch_store(self):
        class Incomplete(ReceiptSink):
            def store(self, receipt):
                pass
            def flush(self):
                pass
            def close(self):
                pass

        with pytest.raises(TypeError):
            Incomplete()

    def test_subclass_must_implement_flush(self):
        class Incomplete(ReceiptSink):
            def store(self, receipt):
                pass
            def batch_store(self, receipts):
                pass
            def close(self):
                pass

        with pytest.raises(TypeError):
            Incomplete()

    def test_subclass_must_implement_close(self):
        class Incomplete(ReceiptSink):
            def store(self, receipt):
                pass
            def batch_store(self, receipts):
                pass
            def flush(self):
                pass

        with pytest.raises(TypeError):
            Incomplete()

    def test_complete_subclass_instantiates(self):
        class Complete(ReceiptSink):
            def store(self, receipt):
                return SinkResult(stored=1, failed=0, errors=())
            def batch_store(self, receipts):
                return SinkResult(stored=len(receipts), failed=0, errors=())
            def flush(self):
                pass
            def close(self):
                pass

        sink = Complete()
        assert sink.store({}).ok is True

    def test_context_manager_calls_close(self):
        closed = False

        class TrackClose(ReceiptSink):
            def store(self, receipt):
                return SinkResult(stored=1, failed=0, errors=())
            def batch_store(self, receipts):
                return SinkResult(stored=0, failed=0, errors=())
            def flush(self):
                pass
            def close(self):
                nonlocal closed
                closed = True

        with TrackClose():
            pass
        assert closed is True

    def test_context_manager_calls_close_on_exception(self):
        closed = False

        class TrackClose(ReceiptSink):
            def store(self, receipt):
                return SinkResult(stored=1, failed=0, errors=())
            def batch_store(self, receipts):
                return SinkResult(stored=0, failed=0, errors=())
            def flush(self):
                pass
            def close(self):
                nonlocal closed
                closed = True

        with pytest.raises(RuntimeError):
            with TrackClose():
                raise RuntimeError("boom")
        assert closed is True

    def test_context_manager_returns_self(self):
        class Simple(ReceiptSink):
            def store(self, receipt):
                return SinkResult(stored=1, failed=0, errors=())
            def batch_store(self, receipts):
                return SinkResult(stored=0, failed=0, errors=())
            def flush(self):
                pass
            def close(self):
                pass

        sink = Simple()
        with sink as ctx:
            assert ctx is sink


# ---------------------------------------------------------------------------
# SinkError
# ---------------------------------------------------------------------------

class TestSinkError:
    def test_is_exception(self):
        assert issubclass(SinkError, Exception)

    def test_message(self):
        err = SinkError("something went wrong")
        assert str(err) == "something went wrong"
