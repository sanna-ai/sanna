"""Receipt sink implementations."""

from .local import LocalSQLiteSink
from .null import NullSink

__all__ = ["LocalSQLiteSink", "NullSink"]
