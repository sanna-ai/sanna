"""SAN-493: regression guard that state.md header does not embed git SHA.

Pre-fix, tools/generate_state_doc.py embedded `git-sha: <12-char>` in
the state.md header. The SHA was always one-commit-stale because regen
runs pre-commit (per the sealed-gate pattern, HEAD at regen time is
the parent commit's SHA, never the SHA of the commit landing the
state.md update). Post-fix, the SHA is dropped entirely; commit SHAs
live only in git log.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from generate_state_doc import generate_full, repo_root


def test_state_md_header_does_not_contain_git_sha():
    """state.md header must NOT contain `git-sha:` substring."""
    content = generate_full(repo_root(), "2026-05-10T00:00:00Z")
    header = "\n".join(content.splitlines()[:5])
    assert "git-sha" not in header, (
        f"state.md header still contains 'git-sha' substring; "
        f"SAN-493 dropped this. Header:\n{header}"
    )
