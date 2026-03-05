"""NullSink — discards receipts (useful for testing and dry-run modes)."""

from __future__ import annotations

from .sink import ReceiptSink, SinkResult


class NullSink(ReceiptSink):
    """Sink that discards all receipts. Always reports success."""

    def store(self, receipt: dict) -> SinkResult:
        return SinkResult(stored=1)
