# Cookbook

Focused recipes for flows not already covered in the README quickstarts. For the observe decorator basics and the gateway setup, see the [README Quick Start sections](https://github.com/sanna-ai/sanna#quick-start--library-mode).

## 1. Subprocess and HTTP interceptors

Enforce governance on subprocess and HTTP calls made by your agent process without modifying call sites. Each intercepted call is evaluated against the constitution and produces a signed receipt.

```python
from sanna import (
    patch_subprocess, unpatch_subprocess,
    patch_http, unpatch_http,
    LocalSQLiteSink,
)

CONSTITUTION = "constitution.yaml"
AGENT_ID = "my-agent/1.0"
sink = LocalSQLiteSink(".sanna/receipts.db")

# Activate both interceptors before the agent runs
patch_subprocess(CONSTITUTION, sink, agent_id=AGENT_ID, mode="enforce")
patch_http(CONSTITUTION, sink, agent_id=AGENT_ID, mode="enforce")

try:
    # Your agent logic here — subprocess and HTTP calls are now governed
    import subprocess
    result = subprocess.run(["ls", "-la"], capture_output=True, text=True)
    # Each call generates and persists a receipt automatically
    print(result.stdout)
finally:
    # Always unpatch in a finally block for clean teardown
    unpatch_subprocess()
    unpatch_http()
```

**Enforcement modes:**
- `"enforce"` — violations raise `FileNotFoundError` (subprocess) or `ConnectionError` (HTTP) and halt the call.
- `"audit"` — violations raise `PermissionError` but generate a receipt and continue.
- `"passthrough"` — generates receipts, never blocks.

**Important:** The interceptors use in-process monkeypatching (cooperative code only). For untrusted or adversarial code, use the gateway (out-of-process MCP proxy). See [docs/deployment-tiers.md](https://github.com/sanna-ai/sanna/blob/main/docs/deployment-tiers.md).

**Gateway / MCP transport:** The interceptors themselves do not require the `sanna[mcp]` extra. The MCP gateway (`sanna gateway`) requires it.

## 2. Register a custom invariant evaluator

Add domain-specific checks alongside the built-in C1–C5 heuristics. The evaluator runs automatically when its invariant ID appears in the constitution.

### Step 1 — Write and register the evaluator

```python
from sanna.evaluators import register_invariant_evaluator, clear_evaluators
from sanna.receipt import CheckResult

@register_invariant_evaluator("INV_NO_SSN")
def check_no_ssn(context: str, output: str, constitution: dict, check_config: dict) -> CheckResult:
    import re
    pattern = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    has_ssn = bool(pattern.search(output))
    return CheckResult(
        check_id="INV_NO_SSN",
        name="No SSN in Output",
        passed=not has_ssn,
        severity="critical",
        evidence="SSN pattern detected in output" if has_ssn else "",
    )
```

The evaluator signature is `(context: str, output: str, constitution: dict, check_config: dict) -> CheckResult`. Raise an exception on internal failure (do not return a failed `CheckResult` — that triggers a false halt).

### Step 2 — Add the invariant to the constitution

```yaml
invariants:
  - id: INV_NO_SSN
    rule: Never include Social Security Numbers in output
    enforcement: halt
```

### Step 3 — Use with `@sanna_observe`

```python
from sanna import sanna_observe, SannaHaltError

@sanna_observe(
    constitution_path="constitution.yaml",
    constitution_public_key_path="~/.sanna/keys/<key-id>.pub",
)
def my_agent(query: str, context: str) -> str:
    return "Here is the customer record."

try:
    result = my_agent(query="Show customer data", context="Name: Alice")
    print(result.status)  # "PASS" if no SSN found
except SannaHaltError as e:
    print(f"HALTED: {e}")
```

**Test isolation:** Always call `clear_evaluators()` in test fixtures. The registry is module-level; leaked registrations cause `ValueError` on duplicate `invariant_id` in later tests.

## 3. Drift report

Analyze per-agent failure rate trends from stored receipts and identify agents approaching the failure threshold.

### Via the library

```python
from sanna import ReceiptStore, DriftAnalyzer

store = ReceiptStore(".sanna/receipts.db")
analyzer = DriftAnalyzer(store)

report = analyzer.analyze(
    window_days=30,
    threshold=0.15,       # 15% failure rate = critical
    projection_days=90,   # how far ahead to project breach
)

print(f"Fleet status: {report.fleet_status}")

for agent in report.agents:
    if agent.status != "HEALTHY":
        print(f"\nAgent: {agent.agent_id}  status={agent.status}")
        for check in agent.checks:
            if check.status != "HEALTHY":
                print(f"  {check.check_id}: fail_rate={check.fail_rate:.1%}  "
                      f"slope={check.trend_slope:+.4f}/day  "
                      f"breach_in={check.projected_breach_days}d")
```

### Via the CLI

```bash
# Human-readable report
sanna drift-report --db .sanna/receipts.db --window 30

# JSON output for downstream processing
sanna drift-report --db .sanna/receipts.db --window 30 --json

# Filter to a single agent
sanna drift-report --db .sanna/receipts.db --agent support-agent
```

### Export to file

```python
from sanna.drift import export_drift_report_to_file

export_drift_report_to_file(report, "drift-2026-06.json")
```

## 4. Build and verify an evidence bundle

Evidence bundles are self-contained zip archives for auditors, regulators, and third parties — receipt, constitution, and public key(s) in one file. Verification requires no network access.

### Build the bundle

```python
from sanna.bundle import create_bundle

bundle_path = create_bundle(
    receipt_path="receipt.json",
    constitution_path="constitution.yaml",
    public_key_path="~/.sanna/keys/<key-id>.pub",
    output_path="evidence.zip",
    description="Q2 2026 governance audit — support-agent",
    # Optional: include constitution signer's public key
    constitution_public_key_path="~/.sanna/keys/<author-key-id>.pub",
)
print(f"Bundle created: {bundle_path}")
```

### Verify the bundle

```python
from sanna.bundle import verify_bundle

result = verify_bundle("evidence.zip")
print(f"Valid: {result.valid}")
for check in result.checks:
    status = "PASS" if check.passed else "FAIL"
    print(f"  [{status}] {check.name}: {check.detail}")

if result.errors:
    for err in result.errors:
        print(f"ERROR: {err}")
```

### Via the CLI

```bash
# Create a bundle
sanna bundle-create \
  --receipt receipt.json \
  --constitution constitution.yaml \
  --public-key ~/.sanna/keys/<key-id>.pub \
  --output evidence.zip

# Verify it (7-step check: format, schema, hashes, signature, chain, triad, keys)
sanna bundle-verify evidence.zip

# Verbose output with per-step results
sanna bundle-verify evidence.zip --verbose
```

Bundles are suitable for handing to auditors who have the `sanna` CLI but no access to your key store. The bundle is self-contained — the public key is embedded and used automatically by `bundle-verify`.
