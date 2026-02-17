"""
Interactive CLI for generating a Sanna constitution from templates.

Guides users through template selection, agent identity, and enforcement
level configuration. Produces a valid, well-commented YAML file ready
for signing and use with @sanna_observe.
"""

import importlib.resources
import sys
from datetime import datetime, timezone
from pathlib import Path


# ============================================================================
# Template definitions
# ============================================================================

TEMPLATES = {
    "enterprise-it": {
        "file": "enterprise_it.yaml",
        "label": "Enterprise IT / ServiceNow-style",
        "default_enforcement": "strict",
    },
    "customer-facing": {
        "file": "customer_facing.yaml",
        "label": "Customer-Facing / Salesforce-style",
        "default_enforcement": "standard",
    },
    "general-purpose": {
        "file": "general_purpose.yaml",
        "label": "General Purpose / Starter",
        "default_enforcement": "advisory",
    },
}

# Enforcement levels map to per-check enforcement settings
ENFORCEMENT_LEVELS = {
    "strict": {
        "enforcement_c1": "halt",
        "enforcement_c2": "halt",
        "enforcement_c3": "halt",
        "enforcement_c4": "halt",
        "enforcement_c5": "halt",
    },
    "standard": {
        "enforcement_c1": "halt",
        "enforcement_c2": "halt",
        "enforcement_c3": "halt",
        "enforcement_c4": "warn",
        "enforcement_c5": "warn",
    },
    "advisory": {
        "enforcement_c1": "halt",
        "enforcement_c2": "warn",
        "enforcement_c3": "warn",
        "enforcement_c4": "warn",
        "enforcement_c5": "warn",
    },
}

# Minimal blank template (no authority_boundaries, no trusted_sources)
_BLANK_TEMPLATE = """\
# =============================================================================
# Sanna Constitution — Blank Template
# =============================================================================
#
# Minimal valid constitution. Customize everything to fit your agent.
#
# Workflow:
#   1. Edit this file with your agent's boundaries and governance details
#   2. Sign it:  sanna-sign-constitution constitution.yaml --private-key <your-key-id>.key
#   3. Wire it:  @sanna_observe(constitution_path="constitution.yaml")

sanna_constitution: "1.0.0"

identity:
  agent_name: "{agent_name}"
  domain: "general"
  description: "{description}"

provenance:
  authored_by: "team@company.com"
  approved_by:
    - "lead@company.com"
  approval_date: "{today}"
  approval_method: "manual-sign-off"
  change_history: []

boundaries:
  - id: "B001"
    description: "Operate within the defined domain and task scope"
    category: "scope"
    severity: "medium"

trust_tiers:
  autonomous: []
  requires_approval: []
  prohibited: []

halt_conditions: []

invariants:
  - id: "INV_NO_FABRICATION"
    rule: "Do not claim facts absent from provided sources."
    enforcement: "{enforcement_c1}"
  - id: "INV_MARK_INFERENCE"
    rule: "Clearly mark inferences and speculation as such."
    enforcement: "{enforcement_c2}"
  - id: "INV_NO_FALSE_CERTAINTY"
    rule: "Do not express certainty exceeding evidence strength."
    enforcement: "{enforcement_c3}"
  - id: "INV_PRESERVE_TENSION"
    rule: "Do not collapse conflicting evidence without explicit justification."
    enforcement: "{enforcement_c4}"
  - id: "INV_NO_PREMATURE_COMPRESSION"
    rule: "Do not issue unconditional conclusions when evidence is mixed."
    enforcement: "{enforcement_c5}"

policy_hash: null
"""


# ============================================================================
# Template loading
# ============================================================================

def load_template(name: str) -> str:
    """Load a template YAML string by name.

    For named templates, reads from the bundled package data.
    For 'blank', returns the inline minimal template.
    """
    if name == "blank":
        return _BLANK_TEMPLATE

    info = TEMPLATES[name]
    filename = info["file"]

    # importlib.resources: Python 3.10+ with files() API
    ref = importlib.resources.files("sanna.templates").joinpath(filename)
    return ref.read_text(encoding="utf-8")


def render_template(
    template_content: str,
    *,
    agent_name: str,
    description: str,
    enforcement: str,
) -> str:
    """Substitute placeholders in template content."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    levels = ENFORCEMENT_LEVELS[enforcement]

    return template_content.format(
        agent_name=agent_name,
        description=description or "",
        today=today,
        **levels,
    )


def validate_generated(yaml_content: str) -> list[str]:
    """Validate generated YAML against the constitution schema.

    Returns a list of errors (empty = valid).
    """
    import yaml
    from .constitution import validate_constitution_data, validate_against_schema

    data = yaml.safe_load(yaml_content)
    errors = validate_against_schema(data)
    errors.extend(validate_constitution_data(data))
    return errors


# ============================================================================
# Gateway config generation
# ============================================================================

_GATEWAY_TEMPLATE = """\
# Sanna Gateway Configuration
# Generated by sanna-init
#
# Start with: sanna-gateway --config {gateway_path}

gateway:
  constitution: {constitution_path}
  # signing_key: ~/.sanna/keys/<your-key-id>.key
  # escalation_timeout: 300

downstream:
  - name: my-server
    command: npx
    args: ["-y", "@your/mcp-server"]
    # env:
    #   API_KEY: "${{API_KEY}}"
    timeout: 30
    default_policy: can_execute
    # tools:
    #   "write-tool":
    #     policy: must_escalate
    #     reason: "Write operations require approval"
"""


def _maybe_generate_gateway_config(constitution_path: Path) -> Path | None:
    """Ask user whether to generate a gateway.yaml alongside the constitution."""
    try:
        answer = input("\nGenerate a gateway configuration? [Y/n] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return None

    if answer and answer not in ("y", "yes"):
        return None

    gateway_path = constitution_path.parent / "gateway.yaml"
    if gateway_path.exists():
        print(f"  Skipped: {gateway_path} already exists.")
        return None

    # Use relative filename when gateway and constitution are in the same dir
    if gateway_path.parent.resolve() == constitution_path.parent.resolve():
        config_constitution_ref = constitution_path.name
    else:
        config_constitution_ref = str(constitution_path)
    content = _GATEWAY_TEMPLATE.format(
        gateway_path=gateway_path,
        constitution_path=config_constitution_ref,
    )
    from .utils.safe_io import atomic_write_text_sync
    atomic_write_text_sync(gateway_path, content)
    print(f"  Gateway config created: {gateway_path}")
    return gateway_path


# ============================================================================
# Interactive CLI
# ============================================================================

def run_interactive() -> int:
    """Run the interactive constitution generator.

    Returns 0 on success, 1 on error.
    """
    print()
    print("Sanna Constitution Generator")
    print("=" * 40)
    print()

    # 1. Template selection
    print("Choose a template:")
    print("  1) Enterprise IT / ServiceNow-style  (strict enforcement)")
    print("  2) Customer-Facing / Salesforce-style (standard enforcement)")
    print("  3) General Purpose / Starter          (advisory enforcement)")
    print("  4) Blank                              (minimal, customize everything)")
    print()

    choice = input("Template [1-4]: ").strip()
    template_map = {
        "1": "enterprise-it",
        "2": "customer-facing",
        "3": "general-purpose",
        "4": "blank",
    }
    template_name = template_map.get(choice)
    if not template_name:
        print(f"Error: Invalid choice: {choice!r}", file=sys.stderr)
        return 1

    # 2. Agent name
    agent_name = input("Agent name: ").strip()
    if not agent_name:
        print("Error: Agent name is required.", file=sys.stderr)
        return 1

    # 3. Description (optional)
    description = input("Agent description (Enter to skip): ").strip()

    # 4. Enforcement level
    if template_name == "blank":
        default_enforcement = "advisory"
    else:
        default_enforcement = TEMPLATES[template_name]["default_enforcement"]

    enforcement = input(
        f"Enforcement level — strict / standard / advisory [{default_enforcement}]: "
    ).strip().lower()
    if not enforcement:
        enforcement = default_enforcement
    if enforcement not in ENFORCEMENT_LEVELS:
        print(f"Error: Invalid enforcement level: {enforcement!r}", file=sys.stderr)
        return 1

    # 5. Output path
    output_path_str = input("Output path [./constitution.yaml]: ").strip()
    if not output_path_str:
        output_path_str = "./constitution.yaml"
    output_path = Path(output_path_str)

    # Load and render template
    template_content = load_template(template_name)
    rendered = render_template(
        template_content,
        agent_name=agent_name,
        description=description,
        enforcement=enforcement,
    )

    # Validate before writing
    errors = validate_generated(rendered)
    if errors:
        print(f"\nError: Generated constitution has validation errors:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    # Write output (atomic)
    from .utils.safe_io import atomic_write_text_sync
    output_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text_sync(output_path, rendered)

    print()
    print(f"Constitution created: {output_path}")
    print("Validation: PASSED")

    # Offer gateway config generation
    gateway_path = _maybe_generate_gateway_config(output_path)

    print()
    print("Next steps:")
    print(f"  1. Review and customize: {output_path}")
    print(f"  2. Sign it:  sanna-sign-constitution {output_path} --private-key <your-key-id>.key")
    print(f'  3. Wire it:  @sanna_observe(constitution_path="{output_path}")')
    if gateway_path:
        print(f"  4. Start gateway:  sanna-gateway --config {gateway_path}")
    return 0


def main():
    """Entry point for sanna-init CLI command."""
    sys.exit(run_interactive())
