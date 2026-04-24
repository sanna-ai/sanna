"""Cross-SDK authority-matching fixture tests (SAN-242).

Loads the canonical authority-matching-vectors.json from sanna-protocol
(via git submodule at spec/) and runs each vector against the Python SDK's
_matches_action(). This proves cross-SDK fixture parity — the same vectors
run in sanna-ts via authority-matching-fixtures.test.ts.
"""

import json
from pathlib import Path

import pytest

from sanna.enforcement.authority import _matches_action

VECTORS_PATH = Path(__file__).parent.parent / "spec" / "fixtures" / "authority-matching-vectors.json"


def _load_vectors():
    if not VECTORS_PATH.exists():
        return None
    data = json.loads(VECTORS_PATH.read_text())
    return data["vectors"]


_VECTORS = _load_vectors()


def pytest_collect_file(parent, file_path):
    pass


class TestAuthorityMatchingFixtures:
    """Cross-SDK contract: authority-matching-vectors.json."""

    def test_fixture_file_present(self):
        """Submodule initialized and fixture file reachable."""
        if _VECTORS is None:
            pytest.skip(
                "sanna-protocol submodule not initialized — run: "
                "git submodule update --init --recursive"
            )
        assert len(_VECTORS) > 0, "No vectors found in fixture"

    @pytest.mark.parametrize(
        "vector",
        _VECTORS if _VECTORS is not None else [],
        ids=[v["id"] for v in _VECTORS] if _VECTORS is not None else [],
    )
    def test_vector(self, vector):
        """Each fixture vector must return the expected boolean from _matches_action."""
        result = _matches_action(vector["pattern"], vector["action"])
        assert result == vector["expected"], (
            f"[{vector['id']}] _matches_action({vector['pattern']!r}, {vector['action']!r}) "
            f"returned {result}, expected {vector['expected']}. "
            f"Rationale: {vector['rationale']}"
        )
