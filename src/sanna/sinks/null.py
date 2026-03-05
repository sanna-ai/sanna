"""NullSink — no-op sink for testing and dry-run mode."""

from typing import Sequence

from sanna.sink import ReceiptSink, SinkResult


class NullSink(ReceiptSink):
    """Always succeeds. No side effects."""

    def store(self, receipt: dict) -> SinkResult:
        return SinkResult(stored=1, failed=0, errors=())

    def batch_store(self, receipts: Sequence[dict]) -> SinkResult:
        return SinkResult(stored=len(receipts), failed=0, errors=())

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass
