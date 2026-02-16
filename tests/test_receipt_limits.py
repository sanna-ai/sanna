"""Block C tests — receipt payload size limits and truncation."""

from __future__ import annotations

import pytest

from sanna.gateway.receipt_v2 import (
    truncate_for_storage,
    MAX_STORED_PAYLOAD_BYTES,
    _TRUNCATION_MARKER,
)
from sanna.hashing import hash_text


class TestReceiptTruncation:
    def test_receipt_truncation_preserves_hash(self):
        """Full hash is computed before truncation — hashes differ from truncated content."""
        big_content = "x" * 200_000  # 200KB, well over 64KB limit
        full_hash = hash_text(big_content)

        truncated = truncate_for_storage(big_content)
        truncated_hash = hash_text(truncated)

        # The hashes must differ (original was hashed in full)
        assert full_hash != truncated_hash
        # The truncated content is smaller
        assert len(truncated.encode("utf-8")) <= MAX_STORED_PAYLOAD_BYTES + 100  # small margin for marker
        # Full hash is stable regardless of truncation
        assert full_hash == hash_text(big_content)

    def test_receipt_truncation_marker(self):
        """Truncated content ends with the truncation marker."""
        big_content = "x" * 200_000
        truncated = truncate_for_storage(big_content)

        assert truncated.endswith(_TRUNCATION_MARKER)
        assert "[TRUNCATED" in truncated

    def test_small_payload_no_truncation(self):
        """Content under limit is stored in full, unchanged."""
        small_content = "This is a small payload that fits easily."
        result = truncate_for_storage(small_content)
        assert result == small_content
        assert _TRUNCATION_MARKER not in result

    def test_truncation_configurable(self):
        """Custom max_bytes limit is respected."""
        content = "a" * 500
        truncated = truncate_for_storage(content, max_bytes=100)

        assert len(truncated.encode("utf-8")) <= 100 + len(_TRUNCATION_MARKER.encode("utf-8"))
        assert _TRUNCATION_MARKER in truncated

    def test_none_passthrough(self):
        """None input returns None."""
        assert truncate_for_storage(None) is None

    def test_exact_boundary(self):
        """Content at exactly the limit is not truncated."""
        # Create content that is exactly MAX_STORED_PAYLOAD_BYTES in UTF-8
        content = "a" * MAX_STORED_PAYLOAD_BYTES
        result = truncate_for_storage(content)
        assert result == content
        assert _TRUNCATION_MARKER not in result

    def test_unicode_truncation_safety(self):
        """UTF-8 multi-byte chars don't produce invalid truncation."""
        # Each emoji is 4 bytes in UTF-8
        content = "\U0001F600" * 20000  # 80KB > 64KB limit
        truncated = truncate_for_storage(content)

        # Should not crash and should be valid UTF-8
        truncated.encode("utf-8")  # should not raise
        assert _TRUNCATION_MARKER in truncated
