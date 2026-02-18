"""Block C tests — float handling and canonical JSON determinism.

Since v0.12.2, floats are serialized as JSON numbers (not converted to
strings).  This eliminates the hash collision where a float and its
string representation produced identical canonical bytes.
"""

from __future__ import annotations

import math

import pytest

from sanna.hashing import normalize_floats, canonical_json_bytes, hash_obj


class TestFloatNormalization:
    def test_normalize_floats_is_identity(self):
        """normalize_floats is now a pass-through for backward compat."""
        data = {"score": 0.85, "name": "test", "count": 42}
        result = normalize_floats(data)
        assert result is data  # identity — same object returned

    def test_float_in_arguments_hashes_correctly(self):
        """Receipt with float args produces stable hash."""
        args1 = {"name": "test", "threshold": 0.7}
        args2 = {"threshold": 0.7, "name": "test"}
        # Floats are now accepted directly by hash_obj
        hash1 = hash_obj(args1)
        hash2 = hash_obj(args2)
        assert hash1 == hash2
        assert len(hash1) == 64  # full SHA-256 (v0.13.0 default)

    def test_canonical_json_accepts_floats(self):
        """canonical_json_bytes now accepts finite floats as JSON numbers."""
        result = canonical_json_bytes({"score": 0.5})
        assert isinstance(result, bytes)
        # Float serialized as a JSON number, not a string
        assert b'"score":0.5' in result

    def test_canonical_json_rejects_nan(self):
        """Non-finite floats (NaN) are still rejected."""
        with pytest.raises(TypeError, match="Non-finite"):
            canonical_json_bytes({"score": float("nan")})

    def test_canonical_json_rejects_infinity(self):
        """Non-finite floats (Infinity) are still rejected."""
        with pytest.raises(TypeError, match="Non-finite"):
            canonical_json_bytes({"score": float("inf")})

    def test_float_and_string_produce_different_hashes(self):
        """Critical: float 1.0 and string "1.0" must hash differently."""
        float_hash = hash_obj({"val": 1.0})
        string_hash = hash_obj({"val": "1.0"})
        assert float_hash != string_hash

    def test_float_and_fixed_string_produce_different_hashes(self):
        """Critical: float 1.0 and string "1.0000000000" hash differently.

        This was the specific collision that existed before v0.12.2.
        """
        float_hash = hash_obj({"val": 1.0})
        string_hash = hash_obj({"val": "1.0000000000"})
        assert float_hash != string_hash

    def test_float_canonicalization_deterministic(self):
        """Same float always produces the same canonical bytes."""
        result1 = canonical_json_bytes({"score": 0.85})
        result2 = canonical_json_bytes({"score": 0.85})
        assert result1 == result2

    def test_float_type_preserved_in_canonical_json(self):
        """Canonical JSON contains a number, not a string, for floats."""
        result = canonical_json_bytes({"rate": 1.5})
        # JSON number: "rate":1.5 — no quotes around the value
        assert b'"rate":1.5' in result
        # Not a string: "rate":"1.5" would have extra quotes
        assert b'"rate":"1.5"' not in result

    def test_integer_and_float_distinction(self):
        """Integer 1 and float 1.0 may produce the same JSON representation.

        Python's json.dumps serializes 1.0 as "1.0" (number) and 1 as "1"
        (number), so they will differ in canonical JSON and hash differently.
        """
        int_bytes = canonical_json_bytes({"val": 1})
        float_bytes = canonical_json_bytes({"val": 1.0})
        # Python json.dumps: 1 → "1", 1.0 → "1.0" — these are different
        assert int_bytes != float_bytes

    def test_mixed_types_hashing(self):
        """Dict with ints, floats, strings all hash correctly."""
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
        # Should not raise — floats are now accepted
        result = canonical_json_bytes(data)
        assert isinstance(result, bytes)


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
