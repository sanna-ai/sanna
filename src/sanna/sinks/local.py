"""LocalSQLiteSink — persists receipts to a local SQLite database."""

from __future__ import annotations

import logging

from .sink import ReceiptSink, SinkResult, FailurePolicy

logger = logging.getLogger("sanna.sinks.local")


class LocalSQLiteSink(ReceiptSink):
    """Persist receipts to a local SQLite database via ReceiptStore.

    Args:
        db_path: Path to the SQLite database file.
        failure_policy: How to handle persistence failures.
    """

    def __init__(
        self,
        db_path: str = ".sanna/receipts.db",
        failure_policy: FailurePolicy = FailurePolicy.LOG_AND_CONTINUE,
    ) -> None:
        from sanna.store import ReceiptStore
        self._store = ReceiptStore(db_path)
        self._failure_policy = failure_policy

    def store(self, receipt: dict) -> SinkResult:
        try:
            self._store.save(receipt)
            return SinkResult(stored=1)
        except Exception as e:
            msg = f"LocalSQLiteSink: {e}"
            logger.warning(msg)
            if self._failure_policy == FailurePolicy.RAISE:
                raise
            return SinkResult(failed=1, errors=(msg,))

    def close(self) -> None:
        self._store.close()
