"""ReceiptSink — abstract interface for receipt persistence backends."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Sequence


class FailurePolicy(Enum):
    LOG_AND_CONTINUE = "log_and_continue"
    RAISE = "raise"
    BUFFER_AND_RETRY = "buffer_and_retry"


@dataclass(frozen=True)
class SinkResult:
    stored: int
    failed: int
    errors: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return self.failed == 0


class SinkError(Exception):
    pass


class ReceiptSink(ABC):
    @abstractmethod
    def store(self, receipt: dict) -> SinkResult:
        """Persist a single receipt. Must contain 'fingerprint' and 'signature' fields."""

    @abstractmethod
    def batch_store(self, receipts: Sequence[dict]) -> SinkResult:
        """Persist multiple receipts. Implementations may fall back to sequential store() calls."""

    @abstractmethod
    def flush(self) -> None:
        """Force any buffered receipts to be persisted. No-op for non-buffered sinks."""

    @abstractmethod
    def close(self) -> None:
        """Release resources. Calls flush() first. Sink must not be used after close()."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
