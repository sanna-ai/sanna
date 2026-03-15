"""Tests for cli_permissions and api_permissions validation in validate_constitution_data()."""

import pytest

from sanna.constitution import validate_constitution_data


def _minimal_constitution(**overrides):
    """Return a minimal valid constitution dict, with optional overrides merged in."""
    base = {
        "identity": {"agent_name": "test-agent", "domain": "testing"},
        "provenance": {
            "authored_by": "test@test.com",
            "approved_by": ["lead@test.com"],
            "approval_date": "2026-01-01",
            "approval_method": "manual",
        },
        "boundaries": [
            {
                "id": "B001",
                "description": "Test boundary",
                "category": "scope",
                "severity": "medium",
            }
        ],
    }
    base.update(overrides)
    return base


def _valid_cli_permissions():
    return {
        "mode": "strict",
        "justification_required": True,
        "commands": [
            {
                "id": "CLI_GIT",
                "binary": "git",
                "authority": "can_execute",
            },
            {
                "id": "CLI_NPM",
                "binary": "npm",
                "authority": "must_escalate",
            },
        ],
        "invariants": [
            {
                "id": "CLI_INV_01",
                "description": "No sudo",
                "verdict": "halt",
            },
        ],
    }


def _valid_api_permissions():
    return {
        "mode": "permissive",
        "justification_required": False,
        "endpoints": [
            {
                "id": "API_GITHUB",
                "url_pattern": "https://api.github.com/**",
                "methods": ["GET", "POST"],
                "authority": "can_execute",
            },
            {
                "id": "API_INTERNAL",
                "url_pattern": "https://internal.example.com/api/*",
                "methods": ["*"],
                "authority": "must_escalate",
            },
        ],
        "invariants": [
            {
                "id": "API_INV_01",
                "description": "No credential leak",
                "verdict": "halt",
            },
        ],
    }


# ── cli_permissions validation tests ──────────────────────────────────────────


class TestCliPermissionsValidation:
    def test_valid_cli_permissions_passes(self):
        data = _minimal_constitution(cli_permissions=_valid_cli_permissions())
        errors = validate_constitution_data(data)
        assert errors == []

    def test_cli_permissions_not_dict_fails(self):
        data = _minimal_constitution(cli_permissions="invalid")
        errors = validate_constitution_data(data)
        assert "cli_permissions must be a dict" in errors

    def test_cli_permissions_invalid_mode_fails(self):
        perms = _valid_cli_permissions()
        perms["mode"] = "unknown"
        data = _minimal_constitution(cli_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("cli_permissions.mode 'unknown'" in e for e in errors)

    def test_cli_permissions_missing_binary_fails(self):
        perms = _valid_cli_permissions()
        perms["commands"] = [{"id": "CLI_01", "authority": "can_execute"}]
        data = _minimal_constitution(cli_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("binary is required" in e for e in errors)

    def test_cli_permissions_invalid_authority_fails(self):
        perms = _valid_cli_permissions()
        perms["commands"] = [
            {"id": "CLI_01", "binary": "git", "authority": "maybe"}
        ]
        data = _minimal_constitution(cli_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("authority 'maybe'" in e for e in errors)

    def test_cli_permissions_duplicate_id_fails(self):
        perms = _valid_cli_permissions()
        perms["commands"] = [
            {"id": "CLI_DUP", "binary": "git", "authority": "can_execute"},
            {"id": "CLI_DUP", "binary": "npm", "authority": "can_execute"},
        ]
        data = _minimal_constitution(cli_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("Duplicate cli_permissions command ID: CLI_DUP" in e for e in errors)

    def test_cli_permissions_binary_with_path_fails(self):
        perms = _valid_cli_permissions()
        perms["commands"] = [
            {"id": "CLI_01", "binary": "/usr/bin/git", "authority": "can_execute"}
        ]
        data = _minimal_constitution(cli_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("must not contain path separators or wildcards" in e for e in errors)

    def test_cli_permissions_binary_with_backslash_fails(self):
        perms = _valid_cli_permissions()
        perms["commands"] = [
            {"id": "CLI_01", "binary": "C:\\git", "authority": "can_execute"}
        ]
        data = _minimal_constitution(cli_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("must not contain path separators or wildcards" in e for e in errors)

    def test_cli_permissions_binary_with_wildcard_fails(self):
        perms = _valid_cli_permissions()
        perms["commands"] = [
            {"id": "CLI_01", "binary": "git*", "authority": "can_execute"}
        ]
        data = _minimal_constitution(cli_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("must not contain path separators or wildcards" in e for e in errors)

    def test_cli_permissions_invariant_invalid_verdict_fails(self):
        perms = _valid_cli_permissions()
        perms["invariants"] = [
            {"id": "CLI_INV_01", "description": "test", "verdict": "ignore"}
        ]
        data = _minimal_constitution(cli_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("verdict 'ignore'" in e for e in errors)

    def test_cli_permissions_justification_required_not_bool_fails(self):
        perms = _valid_cli_permissions()
        perms["justification_required"] = "yes"
        data = _minimal_constitution(cli_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("justification_required must be a boolean" in e for e in errors)

    def test_cli_permissions_commands_not_list_fails(self):
        perms = _valid_cli_permissions()
        perms["commands"] = "not-a-list"
        data = _minimal_constitution(cli_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("cli_permissions.commands must be a list" in e for e in errors)

    def test_cli_permissions_invariants_not_list_fails(self):
        perms = _valid_cli_permissions()
        perms["invariants"] = "not-a-list"
        data = _minimal_constitution(cli_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("cli_permissions.invariants must be a list" in e for e in errors)

    def test_cli_permissions_missing_command_id_fails(self):
        perms = _valid_cli_permissions()
        perms["commands"] = [{"binary": "git", "authority": "can_execute"}]
        data = _minimal_constitution(cli_permissions=perms)
        errors = validate_constitution_data(data)
        assert any(".id is required" in e for e in errors)

    def test_cli_permissions_missing_invariant_description_fails(self):
        perms = _valid_cli_permissions()
        perms["invariants"] = [{"id": "CLI_INV_01", "verdict": "halt"}]
        data = _minimal_constitution(cli_permissions=perms)
        errors = validate_constitution_data(data)
        assert any(".description is required" in e for e in errors)


# ── api_permissions validation tests ──────────────────────────────────────────


class TestApiPermissionsValidation:
    def test_valid_api_permissions_passes(self):
        data = _minimal_constitution(api_permissions=_valid_api_permissions())
        errors = validate_constitution_data(data)
        assert errors == []

    def test_api_permissions_not_dict_fails(self):
        data = _minimal_constitution(api_permissions="invalid")
        errors = validate_constitution_data(data)
        assert "api_permissions must be a dict" in errors

    def test_api_permissions_invalid_mode_fails(self):
        perms = _valid_api_permissions()
        perms["mode"] = "unknown"
        data = _minimal_constitution(api_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("api_permissions.mode 'unknown'" in e for e in errors)

    def test_api_permissions_missing_url_pattern_fails(self):
        perms = _valid_api_permissions()
        perms["endpoints"] = [
            {"id": "API_01", "methods": ["GET"], "authority": "can_execute"}
        ]
        data = _minimal_constitution(api_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("url_pattern is required" in e for e in errors)

    def test_api_permissions_invalid_authority_fails(self):
        perms = _valid_api_permissions()
        perms["endpoints"] = [
            {
                "id": "API_01",
                "url_pattern": "https://example.com/**",
                "authority": "maybe",
            }
        ]
        data = _minimal_constitution(api_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("authority 'maybe'" in e for e in errors)

    def test_api_permissions_invalid_method_fails(self):
        perms = _valid_api_permissions()
        perms["endpoints"] = [
            {
                "id": "API_01",
                "url_pattern": "https://example.com/**",
                "methods": ["DESTROY"],
                "authority": "can_execute",
            }
        ]
        data = _minimal_constitution(api_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("'DESTROY' is not a valid HTTP method" in e for e in errors)

    def test_api_permissions_duplicate_id_fails(self):
        perms = _valid_api_permissions()
        perms["endpoints"] = [
            {
                "id": "API_DUP",
                "url_pattern": "https://a.com/**",
                "authority": "can_execute",
            },
            {
                "id": "API_DUP",
                "url_pattern": "https://b.com/**",
                "authority": "can_execute",
            },
        ]
        data = _minimal_constitution(api_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("Duplicate api_permissions endpoint ID: API_DUP" in e for e in errors)

    def test_api_permissions_invariant_invalid_verdict_fails(self):
        perms = _valid_api_permissions()
        perms["invariants"] = [
            {"id": "API_INV_01", "description": "test", "verdict": "ignore"}
        ]
        data = _minimal_constitution(api_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("verdict 'ignore'" in e for e in errors)

    def test_api_permissions_justification_required_not_bool_fails(self):
        perms = _valid_api_permissions()
        perms["justification_required"] = 1
        data = _minimal_constitution(api_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("justification_required must be a boolean" in e for e in errors)

    def test_api_permissions_endpoints_not_list_fails(self):
        perms = _valid_api_permissions()
        perms["endpoints"] = "not-a-list"
        data = _minimal_constitution(api_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("api_permissions.endpoints must be a list" in e for e in errors)

    def test_api_permissions_invariants_not_list_fails(self):
        perms = _valid_api_permissions()
        perms["invariants"] = "not-a-list"
        data = _minimal_constitution(api_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("api_permissions.invariants must be a list" in e for e in errors)

    def test_api_permissions_missing_endpoint_id_fails(self):
        perms = _valid_api_permissions()
        perms["endpoints"] = [
            {"url_pattern": "https://example.com/**", "authority": "can_execute"}
        ]
        data = _minimal_constitution(api_permissions=perms)
        errors = validate_constitution_data(data)
        assert any(".id is required" in e for e in errors)

    def test_api_permissions_methods_not_list_fails(self):
        perms = _valid_api_permissions()
        perms["endpoints"] = [
            {
                "id": "API_01",
                "url_pattern": "https://example.com/**",
                "methods": "GET",
                "authority": "can_execute",
            }
        ]
        data = _minimal_constitution(api_permissions=perms)
        errors = validate_constitution_data(data)
        assert any("methods must be a list" in e for e in errors)


# ── Cross-block tests ─────────────────────────────────────────────────────────


class TestCrossBlockValidation:
    def test_all_three_blocks_valid(self):
        data = _minimal_constitution(
            authority_boundaries={
                "can_execute": ["read_file"],
                "cannot_execute": [],
                "must_escalate": [],
            },
            cli_permissions=_valid_cli_permissions(),
            api_permissions=_valid_api_permissions(),
        )
        errors = validate_constitution_data(data)
        assert errors == []

    def test_cli_and_api_without_authority_valid(self):
        data = _minimal_constitution(
            cli_permissions=_valid_cli_permissions(),
            api_permissions=_valid_api_permissions(),
        )
        errors = validate_constitution_data(data)
        assert errors == []

    def test_absent_cli_api_still_valid(self):
        data = _minimal_constitution()
        errors = validate_constitution_data(data)
        assert errors == []
