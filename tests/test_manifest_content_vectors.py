"""SAN-206: Manifest content vector tests using SAN-376 cross-SDK fixtures."""

import json
from pathlib import Path

import pytest

from sanna.constitution import parse_constitution
from sanna.manifest import generate_manifest

VECTORS_PATH = (
    Path(__file__).parent.parent / "spec" / "fixtures" / "manifest-content-vectors.json"
)


def _load_vectors():
    return json.loads(VECTORS_PATH.read_text())["vectors"]


@pytest.mark.parametrize("vec", _load_vectors(), ids=lambda v: v["id"])
def test_manifest_content_vector(vec):
    inp = vec["input"]
    expected = vec["expected"]
    cons_dict = inp["constitution"]
    cons = parse_constitution(cons_dict) if cons_dict is not None else None

    actual = generate_manifest(
        cons,
        mcp_tools=inp.get("mcp_tools"),
        surfaces=inp.get("surfaces_filter"),
    )

    assert actual == expected, (
        f"\nVector {vec['id']} ({vec['description']}) failed.\n"
        f"Expected: {json.dumps(expected, indent=2, sort_keys=True)}\n"
        f"Actual:   {json.dumps(actual, indent=2, sort_keys=True)}"
    )
