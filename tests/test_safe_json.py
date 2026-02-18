"""Tests for duplicate key detection in JSON and YAML parsing.

SEC-9: Duplicate JSON/YAML keys are rejected in security-sensitive paths
to prevent parser-dependent ambiguity in cross-platform verification.
"""

import io
import json
import textwrap

import pytest

from sanna.utils.safe_json import safe_json_loads, safe_json_load
from sanna.utils.safe_yaml import safe_yaml_load


# ===========================================================================
# safe_json_loads
# ===========================================================================


class TestSafeJsonLoads:
    """Tests for safe_json_loads (string input)."""

    def test_valid_json_parses_normally(self):
        """Valid JSON without duplicates still works."""
        data = safe_json_loads('{"status": "PASS", "checks_passed": 5}')
        assert data == {"status": "PASS", "checks_passed": 5}

    def test_nested_valid_json(self):
        """Nested objects parse correctly."""
        data = safe_json_loads(
            '{"outer": {"inner_a": 1, "inner_b": 2}, "list": [1, 2, 3]}'
        )
        assert data["outer"]["inner_a"] == 1
        assert data["list"] == [1, 2, 3]

    def test_duplicate_status_key_raises(self):
        """Receipt JSON with duplicate 'status' key raises ValueError."""
        # This is the core attack vector: two status keys, parsers disagree
        # on which value wins.
        dup_json = '{"status": "PASS", "receipt_id": "abc", "status": "FAIL"}'
        with pytest.raises(ValueError, match="Duplicate JSON key.*status"):
            safe_json_loads(dup_json)

    def test_duplicate_key_at_top_level(self):
        """Any duplicate key at the top level is rejected."""
        dup_json = '{"a": 1, "b": 2, "a": 3}'
        with pytest.raises(ValueError, match="Duplicate JSON key.*'a'"):
            safe_json_loads(dup_json)

    def test_nested_duplicate_keys_rejected(self):
        """Duplicate keys inside nested objects are also rejected."""
        nested_dup = '{"outer": {"x": 1, "x": 2}}'
        with pytest.raises(ValueError, match="Duplicate JSON key.*'x'"):
            safe_json_loads(nested_dup)

    def test_deeply_nested_duplicate_rejected(self):
        """Duplicate keys deeply nested are still caught."""
        deep = '{"a": {"b": {"c": {"d": 1, "d": 2}}}}'
        with pytest.raises(ValueError, match="Duplicate JSON key.*'d'"):
            safe_json_loads(deep)

    def test_different_keys_same_value_ok(self):
        """Different keys with the same value are fine."""
        data = safe_json_loads('{"a": 1, "b": 1}')
        assert data == {"a": 1, "b": 1}

    def test_array_of_objects_no_false_positive(self):
        """Objects in arrays can have the same keys (different scopes)."""
        data = safe_json_loads('[{"id": 1}, {"id": 2}]')
        assert data == [{"id": 1}, {"id": 2}]

    def test_empty_object(self):
        """Empty JSON object parses fine."""
        data = safe_json_loads("{}")
        assert data == {}

    def test_large_valid_json_performance(self):
        """Large valid JSON parses without issue (performance sanity)."""
        # Build a JSON object with 10,000 unique keys
        obj = {f"key_{i}": i for i in range(10_000)}
        json_str = json.dumps(obj)
        result = safe_json_loads(json_str)
        assert len(result) == 10_000
        assert result["key_0"] == 0
        assert result["key_9999"] == 9999

    def test_invalid_json_still_raises_decode_error(self):
        """Malformed JSON still raises JSONDecodeError, not ValueError."""
        with pytest.raises(json.JSONDecodeError):
            safe_json_loads("{invalid")


# ===========================================================================
# safe_json_load (file-like input)
# ===========================================================================


class TestSafeJsonLoad:
    """Tests for safe_json_load (file object input)."""

    def test_valid_file_parses(self, tmp_path):
        """Reading from a file works for valid JSON."""
        f = tmp_path / "test.json"
        f.write_text('{"receipt_id": "abc", "status": "PASS"}')
        with open(f) as fp:
            data = safe_json_load(fp)
        assert data["status"] == "PASS"

    def test_duplicate_key_in_file_raises(self, tmp_path):
        """Duplicate keys in a file are rejected."""
        f = tmp_path / "dup.json"
        f.write_text('{"status": "PASS", "status": "FAIL"}')
        with pytest.raises(ValueError, match="Duplicate JSON key"):
            with open(f) as fp:
                safe_json_load(fp)

    def test_stringio_input(self):
        """Works with StringIO objects."""
        data = safe_json_load(io.StringIO('{"a": 1, "b": 2}'))
        assert data == {"a": 1, "b": 2}


# ===========================================================================
# safe_yaml_load
# ===========================================================================


class TestSafeYamlLoad:
    """Tests for safe_yaml_load (YAML duplicate key detection)."""

    def test_valid_yaml_parses(self):
        """Valid YAML without duplicates works normally."""
        yaml_str = textwrap.dedent("""\
            identity:
              agent_name: test
              domain: test
            boundaries:
              - id: B001
                description: Test
        """)
        data = safe_yaml_load(yaml_str)
        assert data["identity"]["agent_name"] == "test"

    def test_duplicate_top_level_key_raises(self):
        """Duplicate keys at the top level are rejected."""
        yaml_str = textwrap.dedent("""\
            status: PASS
            receipt_id: abc
            status: FAIL
        """)
        with pytest.raises(ValueError, match="Duplicate YAML key.*status"):
            safe_yaml_load(yaml_str)

    def test_duplicate_nested_key_raises(self):
        """Duplicate keys in nested mappings are rejected."""
        yaml_str = textwrap.dedent("""\
            identity:
              agent_name: test
              domain: test
              agent_name: changed
        """)
        with pytest.raises(ValueError, match="Duplicate YAML key.*agent_name"):
            safe_yaml_load(yaml_str)

    def test_constitution_duplicate_invariants_key(self):
        """A constitution YAML with duplicate 'invariants' key is rejected."""
        yaml_str = textwrap.dedent("""\
            sanna_constitution: "0.1.0"
            identity:
              agent_name: test
              domain: test
            invariants:
              - id: INV_NO_FABRICATION
                rule: "Rule 1"
                enforcement: halt
            invariants:
              - id: INV_MARK_INFERENCE
                rule: "Rule 2"
                enforcement: warn
        """)
        with pytest.raises(ValueError, match="Duplicate YAML key.*invariants"):
            safe_yaml_load(yaml_str)

    def test_yaml_from_file_object(self, tmp_path):
        """YAML loading from file objects works."""
        f = tmp_path / "test.yaml"
        f.write_text("a: 1\nb: 2\n")
        with open(f) as fp:
            data = safe_yaml_load(fp)
        assert data == {"a": 1, "b": 2}

    def test_yaml_from_file_with_duplicate_raises(self, tmp_path):
        """YAML loading from file objects detects duplicates."""
        f = tmp_path / "dup.yaml"
        f.write_text("a: 1\na: 2\n")
        with pytest.raises(ValueError, match="Duplicate YAML key"):
            with open(f) as fp:
                safe_yaml_load(fp)

    def test_valid_yaml_with_lists(self):
        """YAML with lists (not mappings) does not false-positive."""
        yaml_str = textwrap.dedent("""\
            items:
              - name: a
              - name: b
        """)
        data = safe_yaml_load(yaml_str)
        assert len(data["items"]) == 2

    def test_empty_yaml(self):
        """Empty YAML (None) is handled."""
        result = safe_yaml_load("")
        assert result is None


# ===========================================================================
# Integration: bundle / verify / constitution paths
# ===========================================================================


class TestIntegrationPaths:
    """Verify that duplicate key rejection is wired into the actual code paths."""

    def test_constitution_json_duplicate_key_rejected(self, tmp_path):
        """Loading a constitution JSON with duplicate keys raises."""
        from sanna.constitution import load_constitution

        const_json = tmp_path / "bad.json"
        const_json.write_text(
            '{"sanna_constitution": "0.1.0", '
            '"identity": {"agent_name": "a", "domain": "d"}, '
            '"identity": {"agent_name": "b", "domain": "d2"}}'
        )
        with pytest.raises(ValueError, match="Duplicate JSON key"):
            load_constitution(str(const_json))

    def test_constitution_yaml_duplicate_key_rejected(self, tmp_path):
        """Loading a constitution YAML with duplicate keys raises."""
        from sanna.constitution import load_constitution

        const_yaml = tmp_path / "bad.yaml"
        const_yaml.write_text(textwrap.dedent("""\
            sanna_constitution: "0.1.0"
            identity:
              agent_name: test
              domain: test
            identity:
              agent_name: evil
              domain: evil
        """))
        with pytest.raises(ValueError, match="Duplicate YAML key"):
            load_constitution(str(const_yaml))

    def test_mcp_verify_receipt_duplicate_key(self):
        """MCP verify tool rejects receipt JSON with duplicate keys."""
        mcp = pytest.importorskip("mcp")
        from sanna.mcp.server import sanna_verify_receipt

        dup_receipt = '{"receipt_id": "abc", "status": "PASS", "status": "FAIL"}'
        result_json = sanna_verify_receipt(dup_receipt)
        result = json.loads(result_json)
        assert result["valid"] is False
        assert any("Duplicate JSON key" in e for e in result["errors"])
