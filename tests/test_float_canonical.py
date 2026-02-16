"""Block C tests — float normalization and canonical JSON determinism."""

from __future__ import annotations

import pytest

from sanna.hashing import normalize_floats, canonical_json_bytes, hash_obj


class TestFloatNormalization:
    def test_float_normalization_deterministic(self):
        """Same float gives identical normalized representation across runs."""
        result1 = normalize_floats({"score": 0.85})
        result2 = normalize_floats({"score": 0.85})
        assert result1 == result2
        assert result1["score"] == "0.8500000000"

    def test_float_in_arguments_hashes_correctly(self):
        """Receipt with float args produces stable hash via normalization."""
        args1 = {"name": "test", "threshold": 0.7}
        args2 = {"threshold": 0.7, "name": "test"}
        # hash_obj rejects floats, but normalized versions work
        hash1 = hash_obj(normalize_floats(args1))
        hash2 = hash_obj(normalize_floats(args2))
        assert hash1 == hash2
        assert len(hash1) == 16  # default truncation

    def test_no_json_dumps_fallback(self):
        """canonical_json_bytes raises on raw floats — no silent fallback."""
        with pytest.raises(TypeError, match="Float value"):
            canonical_json_bytes({"score": 0.5})

    def test_canonical_json_after_normalization(self):
        """Normalized data always passes canonical JSON without error."""
        data = {"score": 0.99, "rate": 1.5, "count": 3}
        normalized = normalize_floats(data)
        # Should not raise
        result = canonical_json_bytes(normalized)
        assert isinstance(result, bytes)
        assert b"0.9900000000" in result

    def test_mixed_types_normalization(self):
        """Dict with ints, floats, strings, nested dicts all normalize."""
        data = {
            "name": "test",
            "count": 42,
            "score": 0.7,
            "enabled": True,
            "nothing": None,
            "nested": {
                "rate": 1.5,
                "items": [0.1, 0.2, "text", 3],
            },
        }
        result = normalize_floats(data)

        # Floats become strings
        assert result["score"] == "0.7000000000"
        assert result["nested"]["rate"] == "1.5000000000"
        assert result["nested"]["items"][0] == "0.1000000000"
        assert result["nested"]["items"][1] == "0.2000000000"

        # Non-floats preserved
        assert result["name"] == "test"
        assert result["count"] == 42
        assert result["enabled"] is True
        assert result["nothing"] is None
        assert result["nested"]["items"][2] == "text"
        assert result["nested"]["items"][3] == 3

        # Can be canonicalized
        canonical_json_bytes(result)  # should not raise


class TestFloatFallbackRemoved:
    def test_no_json_dumps_fallback_in_server(self):
        """server.py no longer contains 'json_dumps_fallback' string."""
        pytest.importorskip("mcp")
        import sanna.gateway.server as server_module
        import inspect

        source = inspect.getsource(server_module)
        assert "json_dumps_fallback" not in source

    def test_no_json_dumps_fallback_in_receipt_v2(self):
        """receipt_v2.py no longer contains fallback to json.dumps."""
        import sanna.gateway.receipt_v2 as receipt_v2_module
        import inspect

        source = inspect.getsource(receipt_v2_module)
        assert "json.dumps(obj" not in source
        assert "json_dumps_fallback" not in source
