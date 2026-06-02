"""SAN-667: enforce spec-submodule integrity invariants that were previously true only by luck.

1. The bundled schema mirrors (src/sanna/spec/*) are byte-identical to the pinned submodule
   schemas (spec/schemas/*) -- prevents the SDK shipping a stale schema after a submodule bump.
2. The pinned spec commit is reachable on sanna-protocol origin/main -- prevents pinning to a
   dangling/unmerged PR-branch HEAD (supply-chain: the spec we bundle must pass protocol's
   review+merge gate). SAN-665 once pinned to a PR-branch HEAD that auto-deleted post-merge;
   SAN-745 cleared that instance, and this makes it enforced rather than coincidental.
"""
import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCHEMAS = ["receipt.schema.json", "constitution.schema.json"]


def test_spec_schema_mirrors_match_submodule():
    for name in SCHEMAS:
        mirror = (REPO / "src" / "sanna" / "spec" / name).read_bytes()
        source = (REPO / "spec" / "schemas" / name).read_bytes()
        assert mirror == source, (
            f"{name}: src/sanna/spec mirror has drifted from the pinned spec/schemas/. "
            f"Re-copy the mirror after any spec submodule bump."
        )


def test_spec_pin_is_on_protocol_main():
    # Committed gitlink (source of truth), independent of checkout cleanliness.
    ls = subprocess.run(["git", "-C", str(REPO), "ls-tree", "HEAD", "spec"],
                        capture_output=True, text=True, check=True).stdout.split()
    pin = ls[2]
    spec = str(REPO / "spec")
    fetch = subprocess.run(["git", "-C", spec, "fetch", "origin", "main"],
                           capture_output=True, text=True)
    if fetch.returncode != 0:
        # Never silently skip in the enforcement environment; a CI network blip must fail loudly.
        if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"):
            pytest.fail(f"could not fetch sanna-protocol origin/main to verify pin: {fetch.stderr}")
        pytest.skip("offline: cannot fetch protocol main to verify spec pin reachability")
    reachable = subprocess.run(
        ["git", "-C", spec, "merge-base", "--is-ancestor", pin, "origin/main"]
    ).returncode == 0
    assert reachable, (
        f"spec submodule pin {pin} is NOT reachable on sanna-protocol origin/main "
        f"(dangling/unmerged PR-branch commit). Re-pin to a commit merged to protocol main."
    )
