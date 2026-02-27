"""Template matrix tests — declarative enforcement tests for all gateway templates.

Covers action categories across templates from two families:

**OpenClaw templates** (exec/bash/write/edit/browser/web_fetch tools):
  - openclaw-personal: lenient, broad workspace access
  - openclaw-developer: balanced, escalation for dangerous patterns
  - openclaw-team: strict, file modification requires escalation

**Cowork + Claude Code templates** (read_file/write_file/search/summarize tools):
  - cowork-personal: knowledge workers with Claude Desktop
  - cowork-team: shared MCP infrastructure
  - claude-code-standard: developers with MCP connectors
"""

from pathlib import Path

import pytest

from sanna.constitution import load_constitution
from sanna.enforcement.authority import evaluate_authority

# ---------------------------------------------------------------------------
# Template paths
# ---------------------------------------------------------------------------

_TEMPLATES_DIR = Path(__file__).parent.parent / "examples" / "constitutions"

_TEMPLATE_PATHS = {
    "openclaw-personal": _TEMPLATES_DIR / "openclaw-personal.yaml",
    "openclaw-developer": _TEMPLATES_DIR / "openclaw-developer.yaml",
    "openclaw-team": _TEMPLATES_DIR / "openclaw-team.yaml",
    "cowork-personal": _TEMPLATES_DIR / "cowork-personal.yaml",
    "cowork-team": _TEMPLATES_DIR / "cowork-team.yaml",
    "claude-code-standard": _TEMPLATES_DIR / "claude-code-standard.yaml",
}


# ---------------------------------------------------------------------------
# 1. Template loading tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("template_name", list(_TEMPLATE_PATHS.keys()))
def test_template_loads(template_name):
    """Every template loads without errors via load_constitution()."""
    path = _TEMPLATE_PATHS[template_name]
    c = load_constitution(str(path))
    assert c.identity.agent_name
    assert c.authority_boundaries is not None


@pytest.mark.parametrize("template_name", list(_TEMPLATE_PATHS.keys()))
def test_template_has_authority_boundaries(template_name):
    """Every template defines all three authority boundary tiers."""
    c = load_constitution(str(_TEMPLATE_PATHS[template_name]))
    ab = c.authority_boundaries
    assert len(ab.can_execute) > 0
    assert len(ab.cannot_execute) > 0
    assert len(ab.must_escalate) > 0


# ---------------------------------------------------------------------------
# 2. Enforcement matrix tests
# ---------------------------------------------------------------------------

_ENFORCEMENT_MATRIX = [
    # ===================================================================
    # openclaw-personal: lenient governance for personal use
    # ===================================================================

    # Core tools → allow
    ("openclaw-personal", "exec", "allow"),
    ("openclaw-personal", "bash", "allow"),
    ("openclaw-personal", "write", "allow"),
    ("openclaw-personal", "edit", "allow"),
    ("openclaw-personal", "browser", "allow"),
    ("openclaw-personal", "web_fetch", "allow"),
    ("openclaw-personal", "web_search", "allow"),
    ("openclaw-personal", "apply_patch", "allow"),

    # Messaging / process control → escalate
    ("openclaw-personal", "message", "escalate"),
    ("openclaw-personal", "process", "escalate"),

    # Infrastructure tools → halt
    ("openclaw-personal", "nodes", "halt"),
    ("openclaw-personal", "cron", "halt"),
    ("openclaw-personal", "gateway", "halt"),

    # ===================================================================
    # openclaw-developer: balanced governance for development
    # ===================================================================

    # Core tools → allow
    ("openclaw-developer", "exec", "allow"),
    ("openclaw-developer", "bash", "allow"),
    ("openclaw-developer", "write", "allow"),
    ("openclaw-developer", "edit", "allow"),
    ("openclaw-developer", "browser", "allow"),
    ("openclaw-developer", "web_fetch", "allow"),
    ("openclaw-developer", "web_search", "allow"),
    ("openclaw-developer", "apply_patch", "allow"),

    # Messaging / process / sessions → escalate
    ("openclaw-developer", "message", "escalate"),
    ("openclaw-developer", "process", "escalate"),

    # Infrastructure tools → halt
    ("openclaw-developer", "nodes", "halt"),
    ("openclaw-developer", "cron", "halt"),
    ("openclaw-developer", "gateway", "halt"),

    # ===================================================================
    # openclaw-team: strict governance for shared team agents
    # ===================================================================

    # Narrow direct execution → allow
    ("openclaw-team", "exec", "allow"),
    ("openclaw-team", "bash", "allow"),
    ("openclaw-team", "web_search", "allow"),

    # File modification tools → escalate
    ("openclaw-team", "write", "escalate"),
    ("openclaw-team", "edit", "escalate"),
    ("openclaw-team", "browser", "escalate"),
    ("openclaw-team", "apply_patch", "escalate"),

    # Messaging → escalate
    ("openclaw-team", "message", "escalate"),

    # Infrastructure + process → halt
    ("openclaw-team", "nodes", "halt"),
    ("openclaw-team", "cron", "halt"),
    ("openclaw-team", "gateway", "halt"),
    ("openclaw-team", "process", "halt"),

    # ===================================================================
    # cowork-personal: knowledge workers with Claude Desktop
    # ===================================================================

    # File ops and drafting → allow
    ("cowork-personal", "read_file", "allow"),
    ("cowork-personal", "search_files", "allow"),
    ("cowork-personal", "draft_response", "allow"),

    # External communications → escalate
    ("cowork-personal", "send_email", "escalate"),

    # File deletion → escalate
    ("cowork-personal", "delete_file", "escalate"),

    # Financial → escalate (knowledge workers manage expenses)
    ("cowork-personal", "purchase_item", "escalate"),
    ("cowork-personal", "transfer_funds", "escalate"),

    # Calendar → escalate
    ("cowork-personal", "create_event", "escalate"),

    # Database/CRM writes → escalate
    ("cowork-personal", "update_page", "escalate"),

    # Sensitive data → halt
    ("cowork-personal", "read_credentials", "halt"),
    ("cowork-personal", "read_pii", "halt"),

    # Data exfiltration → halt
    ("cowork-personal", "upload_external", "halt"),

    # Destructive → halt
    ("cowork-personal", "delete_repo", "halt"),

    # ===================================================================
    # cowork-team: shared MCP infrastructure
    # ===================================================================

    # File ops → allow
    ("cowork-team", "read_file", "allow"),
    ("cowork-team", "search_files", "allow"),

    # External communications → escalate
    ("cowork-team", "send_email", "escalate"),

    # Shared resources → escalate
    ("cowork-team", "shared_drive_write", "escalate"),
    ("cowork-team", "team_channel_post", "escalate"),

    # File deletion → escalate
    ("cowork-team", "delete_file", "escalate"),

    # Financial → escalate
    ("cowork-team", "purchase_item", "escalate"),

    # Team configuration → halt
    ("cowork-team", "modify_team_config", "halt"),
    ("cowork-team", "modify_access_control", "halt"),
    ("cowork-team", "modify_permissions", "halt"),

    # Sensitive data → halt
    ("cowork-team", "read_credentials", "halt"),

    # Data exfiltration → halt
    ("cowork-team", "upload_external", "halt"),

    # Destructive → halt
    ("cowork-team", "delete_repo", "halt"),

    # ===================================================================
    # claude-code-standard: developers with MCP connectors
    # ===================================================================

    # Code ops → allow
    ("claude-code-standard", "read_file", "allow"),
    ("claude-code-standard", "git_commit", "allow"),
    ("claude-code-standard", "run_tests", "allow"),

    # Git push to main → escalate
    ("claude-code-standard", "git_push_main", "escalate"),

    # External communications → escalate
    ("claude-code-standard", "send_email", "escalate"),

    # File deletion → escalate
    ("claude-code-standard", "delete_file", "escalate"),

    # Package publishing → escalate
    ("claude-code-standard", "npm_publish", "escalate"),

    # Staging DB writes → escalate
    ("claude-code-standard", "database_write_staging", "escalate"),

    # System configuration → escalate
    ("claude-code-standard", "modify_settings", "escalate"),

    # Calendar → escalate
    ("claude-code-standard", "create_event", "escalate"),

    # Production ops → halt
    ("claude-code-standard", "deploy_production", "halt"),
    ("claude-code-standard", "database_write_production", "halt"),

    # Sensitive data → halt
    ("claude-code-standard", "read_credentials", "halt"),

    # Destructive → halt
    ("claude-code-standard", "force_push", "halt"),
    ("claude-code-standard", "terraform_apply", "halt"),
    ("claude-code-standard", "delete_repo", "halt"),
]


@pytest.mark.parametrize(
    "template,action,expected",
    _ENFORCEMENT_MATRIX,
    ids=[f"{t}/{a}" for t, a, _ in _ENFORCEMENT_MATRIX],
)
def test_template_enforcement(template, action, expected):
    """Authority boundary evaluation matches expected enforcement level."""
    c = load_constitution(str(_TEMPLATE_PATHS[template]))
    decision = evaluate_authority(action, {}, c)
    assert decision.decision == expected, (
        f"{template}/{action}: expected {expected}, "
        f"got {decision.decision} (reason: {decision.reason})"
    )


# ---------------------------------------------------------------------------
# 3. Universal invariant tests (scoped to template families)
# ---------------------------------------------------------------------------

# Cowork + Claude Code templates share generic tool names
_COWORK_TEMPLATES = ["cowork-personal", "cowork-team", "claude-code-standard"]

_COWORK_UNIVERSAL_HALTS = [
    "read_credentials",
    "upload_external",
    "delete_repo",
]

_COWORK_UNIVERSAL_ALLOWS = [
    "read_file",
]


@pytest.mark.parametrize("template_name", _COWORK_TEMPLATES)
@pytest.mark.parametrize("action", _COWORK_UNIVERSAL_HALTS)
def test_cowork_universal_halt(template_name, action):
    """Sensitive data, exfiltration, and destructive ops are halted in cowork/claude-code templates."""
    c = load_constitution(str(_TEMPLATE_PATHS[template_name]))
    decision = evaluate_authority(action, {}, c)
    assert decision.decision == "halt", (
        f"{template_name}/{action}: expected halt, "
        f"got {decision.decision} (reason: {decision.reason})"
    )


@pytest.mark.parametrize("template_name", _COWORK_TEMPLATES)
@pytest.mark.parametrize("action", _COWORK_UNIVERSAL_ALLOWS)
def test_cowork_universal_allow(template_name, action):
    """File reads are allowed in all cowork/claude-code templates."""
    c = load_constitution(str(_TEMPLATE_PATHS[template_name]))
    decision = evaluate_authority(action, {}, c)
    assert decision.decision == "allow", (
        f"{template_name}/{action}: expected allow, "
        f"got {decision.decision} (reason: {decision.reason})"
    )


# OpenClaw templates share exec/bash/web_search tool names
_OPENCLAW_TEMPLATES = ["openclaw-personal", "openclaw-developer", "openclaw-team"]

_OPENCLAW_UNIVERSAL_HALTS = [
    "nodes",
    "cron",
    "gateway",
]

_OPENCLAW_UNIVERSAL_ALLOWS = [
    "exec",
    "bash",
    "web_search",
]


@pytest.mark.parametrize("template_name", _OPENCLAW_TEMPLATES)
@pytest.mark.parametrize("action", _OPENCLAW_UNIVERSAL_HALTS)
def test_openclaw_universal_halt(template_name, action):
    """Infrastructure tools are halted in all OpenClaw templates."""
    c = load_constitution(str(_TEMPLATE_PATHS[template_name]))
    decision = evaluate_authority(action, {}, c)
    assert decision.decision == "halt", (
        f"{template_name}/{action}: expected halt, "
        f"got {decision.decision} (reason: {decision.reason})"
    )


@pytest.mark.parametrize("template_name", _OPENCLAW_TEMPLATES)
@pytest.mark.parametrize("action", _OPENCLAW_UNIVERSAL_ALLOWS)
def test_openclaw_universal_allow(template_name, action):
    """Core execution tools are allowed in all OpenClaw templates."""
    c = load_constitution(str(_TEMPLATE_PATHS[template_name]))
    decision = evaluate_authority(action, {}, c)
    assert decision.decision == "allow", (
        f"{template_name}/{action}: expected allow, "
        f"got {decision.decision} (reason: {decision.reason})"
    )


# ---------------------------------------------------------------------------
# 4. Sensitive file read escalation tests (OpenClaw templates)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("template_name", _OPENCLAW_TEMPLATES)
@pytest.mark.parametrize("path_fragment", [
    ".ssh/id_rsa",
    ".sanna/keys/signing.key",
    ".env",
])
def test_openclaw_sensitive_read_escalated(template_name, path_fragment):
    """Reading sensitive file paths triggers escalation in all OpenClaw templates."""
    c = load_constitution(str(_TEMPLATE_PATHS[template_name]))
    decision = evaluate_authority("read", {"path": f"/home/user/{path_fragment}"}, c)
    assert decision.decision == "escalate", (
        f"{template_name}/read {path_fragment}: expected escalate, "
        f"got {decision.decision} (reason: {decision.reason})"
    )
