"""CompositeSink — fan-out to multiple sinks with failure isolation."""

from __future__ import annotations

from typing import Sequence

from .sink import ReceiptSink, SinkResult


class CompositeSink(ReceiptSink):
    """Fan-out to multiple sinks. Primary use case: local SQLite + Cloud HTTP.

    Failure isolation: a failed sink does not prevent other sinks from
    receiving the receipt. Errors are aggregated across all sinks.
    """

    def __init__(self, sinks: Sequence[ReceiptSink]) -> None:
        if not sinks:
            raise ValueError("CompositeSink requires at least one sink")
        self._sinks = list(sinks)

    def store(self, receipt: dict) -> SinkResult:
        stored, failed, errors = 0, 0, []
        for sink in self._sinks:
            try:
                result = sink.store(receipt)
                stored += result.stored
                failed += result.failed
                errors.extend(result.errors)
            except Exception as e:
                failed += 1
                errors.append(f"{type(sink).__name__}: {e}")
        return SinkResult(stored=stored, failed=failed, errors=tuple(errors))

    def batch_store(self, receipts: list[dict]) -> SinkResult:
        stored, failed, errors = 0, 0, []
        for sink in self._sinks:
            try:
                result = sink.batch_store(receipts)
                stored += result.stored
                failed += result.failed
                errors.extend(result.errors)
            except Exception as e:
                failed += len(receipts)
                errors.append(f"{type(sink).__name__}: {e}")
        return SinkResult(stored=stored, failed=failed, errors=tuple(errors))

    def flush(self) -> None:
        for sink in self._sinks:
            try:
                sink.flush()
            except Exception:
                pass

    def close(self) -> None:
        for sink in self._sinks:
            try:
                sink.close()
            except Exception:
                pass
