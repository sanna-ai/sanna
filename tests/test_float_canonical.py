"""Block C tests — float handling and canonical JSON determinism.

Since v0.13.2, normalize_floats converts exact-integer floats to int,
rejects non-integer floats with ValueError, and rejects non-finite
floats with TypeError.  This ensures ``{"val": 1.0}`` and ``{"val": 1}``
produce identical canonical bytes.
"""

from __future__ import annotations

import math

import pytest

from sanna.hashing import normalize_floats, canonical_json_bytes, hash_obj


class TestNormalizeFloats:
    def test_integer_float_to_int(self):
        """normalize_floats(3.0) → 3 (int)."""
        result = normalize_floats(3.0)
        assert result == 3
        assert isinstance(result, int)

    def test_non_integer_float_raises(self):
        """normalize_floats(3.14) → raises ValueError."""
        with pytest.raises(ValueError, match="Non-integer float"):
            normalize_floats(3.14)

    def test_nan_raises_type_error(self):
        """normalize_floats(NaN) → raises TypeError."""
        with pytest.raises(TypeError, match="Non-finite float"):
            normalize_floats(float("nan"))

    def test_infinity_raises_type_error(self):
        """normalize_floats(Infinity) → raises TypeError."""
        with pytest.raises(TypeError, match="Non-finite float"):
            normalize_floats(float("inf"))

    def test_negative_infinity_raises_type_error(self):
        """normalize_floats(-Infinity) → raises TypeError."""
        with pytest.raises(TypeError, match="Non-finite float"):
            normalize_floats(float("-inf"))

    def test_negative_zero_to_int_zero(self):
        """normalize_floats(-0.0) → 0 (int)."""
        result = normalize_floats(-0.0)
        assert result == 0
        assert isinstance(result, int)

    def test_positive_zero_to_int_zero(self):
        """normalize_floats(0.0) → 0 (int)."""
        result = normalize_floats(0.0)
        assert result == 0
        assert isinstance(result, int)

    def test_recursive_dict(self):
        """Recursively normalizes floats in dicts."""
        result = normalize_floats({"a": [1.0, {"b": 2.0}]})
        assert result == {"a": [1, {"b": 2}]}
        assert isinstance(result["a"][0], int)
        assert isinstance(result["a"][1]["b"], int)

    def test_recursive_list(self):
        """Recursively normalizes floats in lists."""
        result = normalize_floats([1.0, 2.0, 3.0])
        assert result == [1, 2, 3]
        assert all(isinstance(v, int) for v in result)

    def test_bool_preserved(self):
        """Booleans are not treated as floats or ints."""
        result = normalize_floats({"flag": True, "other": False})
        assert result == {"flag": True, "other": False}
        assert isinstance(result["flag"], bool)
        assert isinstance(result["other"], bool)

    def test_string_preserved(self):
        """Strings pass through unchanged."""
        result = normalize_floats({"name": "test"})
        assert result == {"name": "test"}

    def test_none_preserved(self):
        """None passes through unchanged."""
        result = normalize_floats(None)
        assert result is None

    def test_int_preserved(self):
        """Integers pass through unchanged."""
        result = normalize_floats(42)
        assert result == 42
        assert isinstance(result, int)

    def test_large_integer_float(self):
        """Large integer-valued floats are converted."""
        result = normalize_floats(1000000.0)
        assert result == 1000000
        assert isinstance(result, int)

    def test_nested_non_integer_float_raises(self):
        """Non-integer float in nested structure raises ValueError."""
        with pytest.raises(ValueError, match="Non-integer float"):
            normalize_floats({"nested": {"val": 0.5}})


class TestCanonicalJsonBytes:
    def test_negative_zero_determinism(self):
        """-0.0 and 0.0 produce identical canonical bytes."""
        neg_zero = canonical_json_bytes({"v": -0.0})
        pos_zero = canonical_json_bytes({"v": 0.0})
        assert neg_zero == pos_zero

    def test_integer_float_determinism(self):
        """1.0 (float) and 1 (int) produce identical canonical bytes."""
        float_bytes = canonical_json_bytes({"v": 1.0})
        int_bytes = canonical_json_bytes({"v": 1})
        assert float_bytes == int_bytes

    def test_hash_determinism(self):
        """hash_obj of 1.0 and 1 produce identical hashes."""
        float_hash = hash_obj({"v": 1.0})
        int_hash = hash_obj({"v": 1})
        assert float_hash == int_hash

    def test_rejects_nan(self):
        """NaN is rejected."""
        with pytest.raises(TypeError, match="Non-finite"):
            canonical_json_bytes({"score": float("nan")})

    def test_rejects_infinity(self):
        """Infinity is rejected."""
        with pytest.raises(TypeError, match="Non-finite"):
            canonical_json_bytes({"score": float("inf")})

    def test_rejects_non_integer_float(self):
        """Non-integer floats are rejected."""
        with pytest.raises(ValueError, match="Non-integer float"):
            canonical_json_bytes({"score": 0.5})

    def test_integer_float_serialized_as_int(self):
        """Integer-valued float becomes int in canonical JSON."""
        result = canonical_json_bytes({"v": 5.0})
        assert b'"v":5' in result
        assert b'"v":5.0' not in result

    def test_float_and_string_produce_different_hashes(self):
        """float 1.0 (→ int 1) and string "1.0" hash differently."""
        float_hash = hash_obj({"val": 1.0})
        string_hash = hash_obj({"val": "1.0"})
        assert float_hash != string_hash

    def test_float_and_fixed_string_produce_different_hashes(self):
        """float 1.0 (→ int 1) and string "1.0000000000" hash differently."""
        float_hash = hash_obj({"val": 1.0})
        string_hash = hash_obj({"val": "1.0000000000"})
        assert float_hash != string_hash

    def test_mixed_types_hashing(self):
        """Dict with ints, bools, strings, None all hash correctly."""
        data = {
            "name": "test",
            "count": 42,
            "score": 100,  # integers only — no non-integer floats
            "enabled": True,
            "nothing": None,
            "nested": {
                "rate": 150,
                "items": [10, 20, "text", 3],
            },
        }
        result = canonical_json_bytes(data)
        assert isinstance(result, bytes)

    def test_deterministic_across_calls(self):
        """Same input always produces same canonical bytes."""
        result1 = canonical_json_bytes({"count": 42.0})
        result2 = canonical_json_bytes({"count": 42.0})
        assert result1 == result2


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
