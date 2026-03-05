"""ReceiptSink ABC — pluggable receipt persistence interface."""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


class FailurePolicy(enum.Enum):
    """How the sink handles persistence failures."""
    LOG_AND_CONTINUE = "log_and_continue"
    RAISE = "raise"
    BUFFER_AND_RETRY = "buffer_and_retry"


@dataclass
class SinkResult:
    """Result of a sink store/batch_store operation."""
    stored: int = 0
    failed: int = 0
    errors: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.failed == 0


class ReceiptSink(ABC):
    """Abstract base class for receipt persistence backends."""

    @abstractmethod
    def store(self, receipt: dict) -> SinkResult:
        """Persist a single receipt. Returns a SinkResult."""

    def batch_store(self, receipts: list[dict]) -> SinkResult:
        """Persist multiple receipts. Default: iterate store()."""
        stored, failed, errors = 0, 0, []
        for receipt in receipts:
            result = self.store(receipt)
            stored += result.stored
            failed += result.failed
            errors.extend(result.errors)
        return SinkResult(stored=stored, failed=failed, errors=tuple(errors))

    def flush(self) -> None:
        """Flush any buffered receipts. Default: no-op."""

    def close(self) -> None:
        """Release resources. Default: no-op."""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
