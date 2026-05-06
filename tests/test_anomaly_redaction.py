"""SAN-406: unit tests for anomaly extension field-level redaction helper."""
from __future__ import annotations

import re

import pytest

from sanna.anomaly import redact_attempted_field

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


class TestRedactAttemptedField:
    def test_full_returns_raw(self):
        assert redact_attempted_field("rm", "full") == "rm"

    def test_none_returns_raw(self):
        assert redact_attempted_field("rm", None) == "rm"

    def test_redacted_returns_literal(self):
        assert redact_attempted_field("rm", "redacted") == "<redacted>"

    def test_hashes_only_returns_64_hex_lowercase(self):
        out = redact_attempted_field("rm", "hashes_only")
        assert _SHA256_HEX_RE.match(out), f"{out!r} not 64-hex lowercase"

    def test_hashes_only_is_deterministic(self):
        a = redact_attempted_field("rm", "hashes_only")
        b = redact_attempted_field("rm", "hashes_only")
        assert a == b

    def test_hashes_only_distinguishes_inputs(self):
        a = redact_attempted_field("rm", "hashes_only")
        b = redact_attempted_field("ls", "hashes_only")
        assert a != b

    def test_unknown_mode_raises(self):
        with pytest.raises(ValueError, match="unknown content_mode"):
            redact_attempted_field("rm", "definitely-not-a-mode")

    def test_redacted_url_endpoint(self):
        assert redact_attempted_field("https://internal.evil.com/*", "redacted") == "<redacted>"

    def test_hashes_only_endpoint(self):
        out = redact_attempted_field("https://internal.evil.com/*", "hashes_only")
        assert _SHA256_HEX_RE.match(out)
