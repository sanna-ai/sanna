#!/usr/bin/env python3
"""
Generate docs/state.md for sanna-repo.

Reads sources of truth and writes a deterministic state document.
Never hand-edit docs/state.md — regenerate with this script.

Usage:
    python3 tools/generate_state_doc.py          # regenerate docs/state.md
    python3 tools/generate_state_doc.py --check  # exit 1 if docs/state.md is stale
"""

import argparse
import datetime
import difflib
import re
import subprocess
import sys
from pathlib import Path
from datetime import timezone


def repo_root() -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, check=True,
    )
    return Path(result.stdout.strip())


def git_sha(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True, text=True, cwd=root,
    )
    return result.stdout.strip()[:12] if result.returncode == 0 else "unknown"


def get_version(root: Path) -> str:
    version_file = root / "src" / "sanna" / "version.py"
    if not version_file.exists():
        return "(not found)"
    m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', version_file.read_text())
    return m.group(1) if m else "(parse error)"


def get_receipt_constants(root: Path) -> dict:
    receipt_file = root / "src" / "sanna" / "receipt.py"
    if not receipt_file.exists():
        return {}
    text = receipt_file.read_text()
    constants = {}
    for name in ("SPEC_VERSION", "CHECKS_VERSION", "TOOL_NAME"):
        m = re.search(rf'^{name}\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
        if m:
            constants[name] = m.group(1)
    return constants


def count_test_files(root: Path) -> int:
    result = subprocess.run(
        ["git", "ls-files", "tests/"],
        capture_output=True, text=True, cwd=root,
    )
    if result.returncode != 0:
        return 0
    return sum(1 for f in result.stdout.splitlines() if f.endswith(".py") and "/test_" in f)


def get_source_layout(root: Path) -> str:
    result = subprocess.run(
        ["git", "ls-files", "src/sanna/"],
        capture_output=True, text=True, cwd=root,
    )
    if result.returncode != 0:
        return "(unavailable)"

    prefix = "src/sanna/"
    items: set[str] = set()
    for f in result.stdout.strip().splitlines():
        rel = f[len(prefix):]
        if not rel:
            continue
        parts = rel.split("/")
        items.add(parts[0] + "/" if len(parts) > 1 else parts[0])

    dirs = sorted(i for i in items if i.endswith("/"))
    files = sorted(i for i in items if not i.endswith("/"))
    return "\n".join(f"  {i}" for i in dirs + files)


def get_optional_deps(root: Path) -> list[str]:
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return ["(pyproject.toml not found)"]
    text = pyproject.read_text()
    found = []
    # detect which optional extras are defined
    if "mcp>=" in text or '"mcp"' in text:
        found.append("mcp (FastMCP server + gateway)")
    if "opentelemetry" in text:
        found.append("opentelemetry (OTel bridge — sanna[otel])")
    if "httpx" in text:
        found.append("httpx (reasoning LLM client — optional)")
    return found if found else ["(none detected)"]


def get_latest_changelog(root: Path) -> str:
    changelog = root / "CHANGELOG.md"
    if not changelog.exists():
        return "(no CHANGELOG.md)"
    entry, in_entry = [], False
    for line in changelog.read_text().splitlines():
        if line.startswith("## "):
            if in_entry:
                break
            in_entry = True
        if in_entry:
            entry.append(line)
        if len(entry) >= 12:
            break
    return "\n".join(entry) if entry else "(no entries found)"


def generate_body(root: Path) -> str:
    version = get_version(root)
    constants = get_receipt_constants(root)
    spec_version = constants.get("SPEC_VERSION", "(not found)")
    checks_version = constants.get("CHECKS_VERSION", "(not found)")
    tool_name = constants.get("TOOL_NAME", "(not found)")
    test_count = count_test_files(root)
    optional_deps = get_optional_deps(root)
    changelog = get_latest_changelog(root)

    sections = [
        "# Sanna Python SDK — State",
        "",
        "## Version",
        "",
        f"Package: `{version}` (source of truth: `src/sanna/version.py`)",
        "",
        "## Protocol Constants (`src/sanna/receipt.py`)",
        "",
        f"| Constant | Value |",
        f"|----------|-------|",
        f"| `SPEC_VERSION` | `\"{spec_version}\"` |",
        f"| `CHECKS_VERSION` | `\"{checks_version}\"` |",
        f"| `TOOL_NAME` | `\"{tool_name}\"` |",
        f"| `TOOL_VERSION` | `\"{version}\"` (from `version.py`) |",
        "",
        "## Test Files",
        "",
        f"Count: {test_count} (`tests/test_*.py` + `tests/reasoning/test_*.py`)",
        "",
        "## Source Layout (`src/sanna/`)",
        "",
        "```",
        get_source_layout(root),
        "```",
        "",
        "## Optional Dependencies",
        "",
        *(f"- {dep}" for dep in optional_deps),
        "",
        "## Latest CHANGELOG Entry",
        "",
        changelog,
        "",
    ]
    return "\n".join(sections)


def generate_full(root: Path, sha: str, timestamp: str) -> str:
    header = (
        f"<!-- auto-generated by tools/generate_state_doc.py — do not edit manually -->\n"
        f"<!-- generated: {timestamp}  git-sha: {sha} -->\n"
        f"\n"
    )
    return header + generate_body(root)


def _comparable(content: str) -> str:
    """Strip the volatile timestamp line before comparing."""
    lines = [l for l in content.splitlines() if not l.startswith("<!-- generated:")]
    return "\n".join(lines).strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate or validate docs/state.md")
    parser.add_argument(
        "--check", action="store_true",
        help="Exit 1 if docs/state.md would change on regeneration",
    )
    args = parser.parse_args()

    root = repo_root()
    state_path = root / "docs" / "state.md"

    if args.check:
        if not state_path.exists():
            print("ERROR: docs/state.md does not exist.")
            print("Run: python3 tools/generate_state_doc.py")
            sys.exit(1)

        current = state_path.read_text()
        sha = git_sha(root)
        timestamp = datetime.datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        fresh = generate_full(root, sha, timestamp)

        if _comparable(current) == _comparable(fresh):
            print("docs/state.md is up to date.")
            sys.exit(0)

        diff = list(difflib.unified_diff(
            _comparable(current).splitlines(keepends=True),
            _comparable(fresh).splitlines(keepends=True),
            fromfile="docs/state.md (committed)",
            tofile="docs/state.md (would regenerate)",
            n=3,
        ))
        print("ERROR: docs/state.md is stale. Regenerate with:")
        print("  python3 tools/generate_state_doc.py\n")
        sys.stdout.writelines(diff[:60])
        sys.exit(1)
    else:
        sha = git_sha(root)
        timestamp = datetime.datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        content = generate_full(root, sha, timestamp)
        (root / "docs").mkdir(exist_ok=True)
        state_path.write_text(content)
        print(
            f"Generated docs/state.md "
            f"(sha={sha}, version={get_version(root)}, tests={count_test_files(root)})"
        )


if __name__ == "__main__":
    main()
