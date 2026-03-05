"""LocalSQLiteSink — wraps ReceiptStore for the ReceiptSink interface."""

import logging
from typing import Sequence

from sanna.sink import FailurePolicy, ReceiptSink, SinkError, SinkResult
from sanna.store import ReceiptStore

logger = logging.getLogger(__name__)


class LocalSQLiteSink(ReceiptSink):
    """Persists receipts to a local SQLite database via ReceiptStore."""

    def __init__(
        self,
        db_path: str,
        failure_policy: FailurePolicy = FailurePolicy.LOG_AND_CONTINUE,
    ):
        self._store = ReceiptStore(db_path)
        self._failure_policy = failure_policy

    def store(self, receipt: dict) -> SinkResult:
        try:
            self._store.save(receipt)
            return SinkResult(stored=1, failed=0, errors=())
        except Exception as e:
            if self._failure_policy is FailurePolicy.RAISE:
                raise SinkError(str(e)) from e
            logger.warning("LocalSQLiteSink.store failed: %s", e)
            return SinkResult(stored=0, failed=1, errors=(str(e),))

    def batch_store(self, receipts: Sequence[dict]) -> SinkResult:
        stored = 0
        failed = 0
        errors: list[str] = []
        for receipt in receipts:
            try:
                self._store.save(receipt)
                stored += 1
            except Exception as e:
                failed += 1
                errors.append(str(e))
                if self._failure_policy is FailurePolicy.RAISE:
                    continue  # finish all, then raise
                logger.warning("LocalSQLiteSink.batch_store failed on receipt: %s", e)
        if failed and self._failure_policy is FailurePolicy.RAISE:
            raise SinkError(
                f"{failed} receipt(s) failed: {'; '.join(errors)}"
            )
        return SinkResult(stored=stored, failed=failed, errors=tuple(errors))

    def flush(self) -> None:
        pass  # SQLite WAL commits are immediate

    def close(self) -> None:
        self.flush()
        self._store.close()
