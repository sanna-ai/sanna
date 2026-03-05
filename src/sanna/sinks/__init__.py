"""Sanna ReceiptSink — pluggable receipt persistence.

Sink implementations receive signed receipts and persist them to one or
more backends (local SQLite, Cloud HTTP, etc.).
"""

from .sink import ReceiptSink, SinkResult, FailurePolicy
from .local import LocalSQLiteSink
from .null import NullSink
from .cloud import CloudHTTPSink
from .composite import CompositeSink

__all__ = [
    "ReceiptSink",
    "SinkResult",
    "FailurePolicy",
    "LocalSQLiteSink",
    "NullSink",
    "CloudHTTPSink",
    "CompositeSink",
]
