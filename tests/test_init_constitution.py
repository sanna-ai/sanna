"""Tests for sanna init-constitution CLI and template system."""

from pathlib import Path

import yaml
import pytest

from sanna.init_constitution import (
    load_template,
    render_template,
    validate_generated,
    run_interactive,
    TEMPLATES,
    ENFORCEMENT_LEVELS,
)
from sanna.constitution import (
    load_constitution,
    sign_constitution,
    validate_constitution_data,
    validate_against_schema,
)
from sanna.middleware import sanna_observe


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _render(template_name, agent_name="test-agent", description="Test agent",
            enforcement=None):
    """Render a template with defaults."""
    if enforcement is None:
        if template_name == "blank":
            enforcement = "advisory"
        else:
            enforcement = TEMPLATES[template_name]["default_enforcement"]
    content = load_template(template_name)
    return render_template(
        content,
        agent_name=agent_name,
        description=description,
        enforcement=enforcement,
    )


def _write_and_sign(yaml_content, tmp_path, filename="constitution.yaml"):
    """Write YAML to file, compute hash, inject policy_hash, return path.

    Avoids save_constitution round-trip (which serializes null fields
    that fail strict schema validation). Instead, computes the hash
    and patches the original YAML text.
    """
    from sanna.constitution import compute_constitution_hash
    path = tmp_path / filename
    path.write_text(yaml_content)
    const = load_constitution(str(path))
    policy_hash = compute_constitution_hash(const)
    # Replace policy_hash: null with actual hash in the original text
    signed_content = yaml_content.replace("policy_hash: null", f"policy_hash: {policy_hash}")
    signed_path = tmp_path / f"signed_{filename}"
    signed_path.write_text(signed_content)
    return str(signed_path)


# ---------------------------------------------------------------------------
# Template loading
# ---------------------------------------------------------------------------

class TestTemplateLoading:
    def test_load_enterprise_it(self):
        content = load_template("enterprise-it")
        assert "{agent_name}" in content
        assert "Enterprise IT" in content

    def test_load_customer_facing(self):
        content = load_template("customer-facing")
        assert "{agent_name}" in content
        assert "Customer-Facing" in content

    def test_load_general_purpose(self):
        content = load_template("general-purpose")
        assert "{agent_name}" in content
        assert "General Purpose" in content

    def test_load_blank(self):
        content = load_template("blank")
        assert "{agent_name}" in content
        assert "Blank Template" in content

    def test_package_data_accessible(self):
        """Templates are findable via importlib.resources."""
        import importlib.resources
        for info in TEMPLATES.values():
            ref = importlib.resources.files("sanna.templates").joinpath(info["file"])
            assert ref.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Template validation
# ---------------------------------------------------------------------------

class TestTemplateValidation:
    @pytest.mark.parametrize("name", ["enterprise-it", "customer-facing", "general-purpose", "blank"])
    def test_template_validates(self, name):
        """Each rendered template passes schema + data validation."""
        rendered = _render(name)
        errors = validate_generated(rendered)
        assert errors == [], f"Validation errors for {name}: {errors}"

    @pytest.mark.parametrize("name", ["enterprise-it", "customer-facing", "general-purpose", "blank"])
    def test_template_yaml_well_formed(self, name):
        """Each template produces valid YAML with no syntax errors."""
        rendered = _render(name)
        data = yaml.safe_load(rendered)
        assert isinstance(data, dict)
        assert "identity" in data
        assert "invariants" in data

    @pytest.mark.parametrize("name", ["enterprise-it", "customer-facing", "general-purpose", "blank"])
    def test_template_round_trip(self, name, tmp_path):
        """Rendered template can be loaded and parsed by constitution loader."""
        rendered = _render(name)
        path = tmp_path / "constitution.yaml"
        path.write_text(rendered)
        const = load_constitution(str(path))
        assert const.identity.agent_name == "test-agent"


# ---------------------------------------------------------------------------
# Agent name / description substitution
# ---------------------------------------------------------------------------

class TestSubstitution:
    def test_agent_name_substituted(self):
        rendered = _render("general-purpose", agent_name="my-custom-agent")
        data = yaml.safe_load(rendered)
        assert data["identity"]["agent_name"] == "my-custom-agent"

    def test_description_substituted(self):
        rendered = _render("general-purpose", description="Does amazing things")
        data = yaml.safe_load(rendered)
        assert data["identity"]["description"] == "Does amazing things"

    def test_empty_description(self):
        rendered = _render("general-purpose", description="")
        data = yaml.safe_load(rendered)
        assert data["identity"]["description"] == ""

    def test_today_date_substituted(self):
        from datetime import datetime, timezone
        rendered = _render("enterprise-it")
        data = yaml.safe_load(rendered)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        assert data["provenance"]["approval_date"] == today


# ---------------------------------------------------------------------------
# Enforcement level override
# ---------------------------------------------------------------------------

class TestEnforcementOverride:
    def test_strict_all_halt(self):
        rendered = _render("general-purpose", enforcement="strict")
        data = yaml.safe_load(rendered)
        for inv in data["invariants"]:
            assert inv["enforcement"] == "halt", f"{inv['id']} should be halt"

    def test_standard_mixed(self):
        rendered = _render("enterprise-it", enforcement="standard")
        data = yaml.safe_load(rendered)
        by_id = {inv["id"]: inv["enforcement"] for inv in data["invariants"]}
        assert by_id["INV_NO_FABRICATION"] == "halt"
        assert by_id["INV_MARK_INFERENCE"] == "halt"
        assert by_id["INV_NO_FALSE_CERTAINTY"] == "halt"
        assert by_id["INV_PRESERVE_TENSION"] == "warn"
        assert by_id["INV_NO_PREMATURE_COMPRESSION"] == "warn"

    def test_advisory_c1_halt_rest_warn(self):
        rendered = _render("enterprise-it", enforcement="advisory")
        data = yaml.safe_load(rendered)
        by_id = {inv["id"]: inv["enforcement"] for inv in data["invariants"]}
        assert by_id["INV_NO_FABRICATION"] == "halt"
        for inv_id in ["INV_MARK_INFERENCE", "INV_NO_FALSE_CERTAINTY",
                       "INV_PRESERVE_TENSION", "INV_NO_PREMATURE_COMPRESSION"]:
            assert by_id[inv_id] == "warn"

    def test_default_enforcement_per_template(self):
        """Each template has a sensible default enforcement."""
        assert TEMPLATES["enterprise-it"]["default_enforcement"] == "strict"
        assert TEMPLATES["customer-facing"]["default_enforcement"] == "standard"
        assert TEMPLATES["general-purpose"]["default_enforcement"] == "advisory"


# ---------------------------------------------------------------------------
# sanna_observe integration
# ---------------------------------------------------------------------------

class TestSannaObserveIntegration:
    @pytest.mark.parametrize("name", ["enterprise-it", "customer-facing", "general-purpose"])
    def test_template_works_with_sanna_observe(self, name, tmp_path):
        """Signed template constitution works with @sanna_observe."""
        rendered = _render(name)
        signed_path = _write_and_sign(rendered, tmp_path)

        @sanna_observe(constitution_path=signed_path)
        def agent(query: str, context: str) -> str:
            return "Based on the context, the answer is yes."

        result = agent(query="test?", context="The answer is yes.")
        assert result.receipt is not None
        assert result.receipt["coherence_status"] in ("PASS", "WARN", "PARTIAL", "FAIL")

    def test_blank_template_works_with_sanna_observe(self, tmp_path):
        """Blank template also works end-to-end."""
        rendered = _render("blank")
        signed_path = _write_and_sign(rendered, tmp_path)

        @sanna_observe(constitution_path=signed_path)
        def agent(query: str, context: str) -> str:
            return "Hello."

        result = agent(query="hi", context="Greetings.")
        assert result.receipt is not None


# ---------------------------------------------------------------------------
# CLI interactive flow
# ---------------------------------------------------------------------------

class TestCLI:
    def test_cli_enterprise_it(self, tmp_path, monkeypatch):
        """CLI generates valid file for enterprise-it template."""
        out = str(tmp_path / "out.yaml")
        inputs = iter(["1", "my-it-agent", "IT helper", "", out])
        monkeypatch.setattr("builtins.input", lambda _="": next(inputs))

        rc = run_interactive()
        assert rc == 0
        assert Path(out).exists()

        data = yaml.safe_load(Path(out).read_text())
        assert data["identity"]["agent_name"] == "my-it-agent"

    def test_cli_customer_facing(self, tmp_path, monkeypatch):
        out = str(tmp_path / "out.yaml")
        inputs = iter(["2", "cx-bot", "", "", out])
        monkeypatch.setattr("builtins.input", lambda _="": next(inputs))

        rc = run_interactive()
        assert rc == 0
        data = yaml.safe_load(Path(out).read_text())
        assert data["identity"]["agent_name"] == "cx-bot"

    def test_cli_general_purpose(self, tmp_path, monkeypatch):
        out = str(tmp_path / "out.yaml")
        inputs = iter(["3", "gp-agent", "General helper", "", out])
        monkeypatch.setattr("builtins.input", lambda _="": next(inputs))

        rc = run_interactive()
        assert rc == 0

    def test_cli_blank(self, tmp_path, monkeypatch):
        out = str(tmp_path / "out.yaml")
        inputs = iter(["4", "blank-agent", "", "", out])
        monkeypatch.setattr("builtins.input", lambda _="": next(inputs))

        rc = run_interactive()
        assert rc == 0
        data = yaml.safe_load(Path(out).read_text())
        assert data["identity"]["agent_name"] == "blank-agent"

    def test_cli_enforcement_override(self, tmp_path, monkeypatch):
        """User overrides template's default enforcement."""
        out = str(tmp_path / "out.yaml")
        inputs = iter(["1", "my-agent", "", "advisory", out])
        monkeypatch.setattr("builtins.input", lambda _="": next(inputs))

        rc = run_interactive()
        assert rc == 0
        data = yaml.safe_load(Path(out).read_text())
        by_id = {inv["id"]: inv["enforcement"] for inv in data["invariants"]}
        # Advisory: C1 halt, rest warn
        assert by_id["INV_NO_FABRICATION"] == "halt"
        assert by_id["INV_MARK_INFERENCE"] == "warn"

    def test_cli_default_output_path(self, tmp_path, monkeypatch):
        """Empty output path defaults to ./constitution.yaml."""
        monkeypatch.chdir(tmp_path)
        inputs = iter(["3", "agent", "", "", ""])
        monkeypatch.setattr("builtins.input", lambda _="": next(inputs))

        rc = run_interactive()
        assert rc == 0
        assert (tmp_path / "constitution.yaml").exists()

    def test_cli_invalid_choice(self, monkeypatch):
        inputs = iter(["9"])
        monkeypatch.setattr("builtins.input", lambda _="": next(inputs))
        rc = run_interactive()
        assert rc == 1

    def test_cli_empty_agent_name(self, monkeypatch):
        inputs = iter(["1", ""])
        monkeypatch.setattr("builtins.input", lambda _="": next(inputs))
        rc = run_interactive()
        assert rc == 1

    def test_cli_invalid_enforcement(self, monkeypatch):
        inputs = iter(["1", "agent", "", "extreme"])
        monkeypatch.setattr("builtins.input", lambda _="": next(inputs))
        rc = run_interactive()
        assert rc == 1


# ---------------------------------------------------------------------------
# Comments preserved in output
# ---------------------------------------------------------------------------

class TestCommentsPreserved:
    def test_enterprise_it_has_comments(self, tmp_path, monkeypatch):
        out = str(tmp_path / "out.yaml")
        inputs = iter(["1", "agent", "", "", out])
        monkeypatch.setattr("builtins.input", lambda _="": next(inputs))
        run_interactive()
        content = Path(out).read_text()
        assert "# --- Agent Identity ---" in content
        assert "# C1: Context Contradiction" in content

    def test_blank_has_comments(self, tmp_path, monkeypatch):
        out = str(tmp_path / "out.yaml")
        inputs = iter(["4", "agent", "", "", out])
        monkeypatch.setattr("builtins.input", lambda _="": next(inputs))
        run_interactive()
        content = Path(out).read_text()
        assert "# Sanna Constitution" in content
