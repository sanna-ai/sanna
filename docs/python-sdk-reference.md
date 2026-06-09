# Python SDK Reference

The `sanna` Python library provides trust infrastructure for AI agents: constitution enforcement, cryptographic receipts, and offline verification.

**Framing:** `@sanna_observe` is **post-execution detection and attestation** — the wrapped function executes and returns before output checks run. Side effects of the function are not prevented by `@sanna_observe`. Pre-execution prevention is handled by the gateway (out-of-process MCP proxy) and the interceptor surfaces (`patch_subprocess`, `patch_http`). An opt-in pre-execution reasoning gate in `@sanna_observe` activates only when a constitution defines reasoning checks and `_justification` is supplied at call time.

## Install

```bash
pip install sanna               # Core library (Python 3.10+)
pip install "sanna[mcp]"        # Adds MCP enforcement gateway and server
pip install "sanna[otel]"       # Adds OpenTelemetry bridge
```

## Top-Level Exports

All 23 names are importable directly from `sanna`:

| Name | Domain | Description |
|------|--------|-------------|
| `__version__` | Meta | Package version string (e.g. `"1.5.0"`) |
| `sanna_observe` | Observe | Decorator: wraps agent functions with governance checks |
| `SannaResult` | Observe | Return type from decorated functions; `.output` + `.receipt` |
| `SannaHaltError` | Observe | Raised when a `halt`-enforcement invariant fails |
| `generate_receipt` | Receipts | Generate a receipt from assembled trace data |
| `receipt_to_dict` | Receipts | Serialize a `SannaReceipt` dataclass to a plain dict |
| `SannaReceipt` | Receipts | Receipt dataclass |
| `verify_receipt` | Verification | Offline receipt verification (schema + hashes + signature + chain) |
| `VerificationResult` | Verification | Structured verification result dataclass |
| `ReceiptStore` | Store | SQLite-backed receipt persistence and querying |
| `DriftAnalyzer` | Drift | Per-agent failure-rate trending with breach projection |
| `ReceiptSink` | Sinks | Abstract base class for receipt persistence backends |
| `SinkResult` | Sinks | Result from a sink `store()` call |
| `FailurePolicy` | Sinks | Enum: `LOG_AND_CONTINUE`, `RAISE`, `BUFFER_AND_RETRY` |
| `NullSink` | Sinks | No-op sink (drops receipts silently) |
| `LocalSQLiteSink` | Sinks | SQLite-backed local persistence |
| `CloudHTTPSink` | Sinks | HTTP endpoint with retry and buffer-on-failure |
| `CompositeSink` | Sinks | Fan-out to multiple sinks |
| `patch_subprocess` | Interceptors | Patch Python's subprocess module for governance enforcement |
| `unpatch_subprocess` | Interceptors | Restore original subprocess functions |
| `patch_http` | Interceptors | Patch Python HTTP libraries for governance enforcement |
| `unpatch_http` | Interceptors | Restore original HTTP functions |
| `RedactionConfig` | Redaction | PII redaction controls for receipt content |

## Observe

### `sanna_observe`

```python
def sanna_observe(
    _func=None,
    *,
    constitution_path: str | None = None,
    constitution_public_key_path: str | None = None,
    private_key_path: str | None = None,
    receipt_dir: str | None = None,
    store=None,
    sink=None,
    context_param: str | None = None,
    query_param: str | None = None,
    identity_provider_keys: dict[str, str] | None = None,
    require_constitution_sig: bool = True,
    strict: bool = True,
    error_policy: str = "fail_closed",
    parent_receipts: list | None = None,
    workflow_id: str | None = None,
    redaction_config: RedactionConfig | None = None,
) -> SannaResult | Callable
```

Wraps an agent function. Returns `SannaResult` on success; raises `SannaHaltError` when a `halt`-enforcement invariant fails.

- `constitution_path` — Path to signed constitution YAML. The constitution's `invariants` list drives which checks run and at what enforcement level.
- `constitution_public_key_path` — Path to the Ed25519 public key for verifying the constitution signature. Required when `require_constitution_sig=True` (the default).
- `require_constitution_sig` — Set to `False` for local development only.
- `receipt_dir` — Write receipt JSON files to this directory (optional).
- `store` — `ReceiptStore` instance or path string; auto-saves receipts after generation.
- `sink` — `ReceiptSink` instance; alternative to `store` for pluggable backends.
- `context_param` / `query_param` — Override parameter name auto-detection.

```python
from sanna import sanna_observe, SannaResult, SannaHaltError

@sanna_observe(
    constitution_path="constitution.yaml",
    constitution_public_key_path="~/.sanna/keys/<key-id>.pub",
)
def my_agent(query: str, context: str) -> str:
    return "Answer grounded in context."

try:
    result: SannaResult = my_agent(
        query="What is the policy?",
        context="All sales are final.",
    )
    print(result.output)   # original function return value
    print(result.receipt)  # governance receipt dict
    print(result.status)   # "PASS" / "WARN" / "FAIL" / "PARTIAL"
except SannaHaltError as e:
    print(f"HALTED: {e}")
    print(e.receipt)       # receipt dict attached to the error
```

### `SannaResult`

```python
class SannaResult:
    output: Any          # original function return value
    receipt: dict        # governance receipt
    status: str          # receipt["status"]: "PASS" / "WARN" / "FAIL" / "PARTIAL"
    passed: bool         # True iff status == "PASS"
```

### `SannaHaltError`

```python
class SannaHaltError(Exception):
    receipt: dict        # receipt dict for the halted execution
```

## Receipts

### `generate_receipt`

```python
def generate_receipt(
    trace_data: dict,
    constitution: ConstitutionProvenance | None = None,
    enforcement: HaltEvent | None = None,
    constitution_ref_override: dict | None = None,
    parent_receipts: list[str] | None = None,
    workflow_id: str | None = None,
    content_mode: str | None = None,
    skip_default_checks: bool = False,
    enforcement_surface: str = "middleware",
    invariants_scope: str = "full",
    agent_model: str | None = None,
    agent_model_provider: str | None = None,
    agent_model_version: str | None = None,
    agent_identity: dict | None = None,
) -> SannaReceipt
```

Assembles a receipt from trace data. `@sanna_observe` calls this internally; use it directly when building integrations for non-decorator surfaces. `enforcement_surface` must be one of `"middleware"`, `"gateway"`, `"cli_interceptor"`, `"http_interceptor"`.

### `receipt_to_dict`

```python
def receipt_to_dict(receipt: SannaReceipt) -> dict
```

Converts a `SannaReceipt` dataclass to a plain JSON-serializable dict.

### Version constants (from `sanna.receipt`)

```python
from sanna.receipt import SPEC_VERSION, CHECKS_VERSION, TOOL_VERSION, TOOL_NAME
# SPEC_VERSION = "1.5"
# CHECKS_VERSION = "10"
# TOOL_VERSION = "1.5.0"    # mirrors sanna.__version__
# TOOL_NAME = "sanna"
```

For the receipt format, field definitions, and the Receipt Triad specification, see the [README Receipt Format section](https://github.com/sanna-ai/sanna#receipt-format) and the [v1.5 specification](https://github.com/sanna-ai/sanna-protocol/blob/main/spec/sanna-specification-v1.5.md).

## Verification

### `verify_receipt`

```python
def verify_receipt(
    receipt: dict,
    schema: dict,
    public_key_path: str | None = None,
    public_key_pem: bytes | str | None = None,
    constitution_path: str | None = None,
    constitution_public_key_path: str | None = None,
    approver_public_key_path: str | None = None,
) -> VerificationResult
```

Offline receipt verification. Checks schema validity, content hashes (tamper detection), Ed25519 signature (authenticity), and the constitution chain (provenance). `public_key_path` and `public_key_pem` are mutually exclusive.

```python
import json
from sanna import verify_receipt
from sanna.verify import load_schema

with open("receipt.json") as f:
    receipt = json.load(f)

schema = load_schema()
result = verify_receipt(
    receipt,
    schema,
    public_key_path="~/.sanna/keys/<key-id>.pub",
    constitution_path="constitution.yaml",
    constitution_public_key_path="~/.sanna/keys/<author-key-id>.pub",
)
print(result.valid)        # True / False
print(result.errors)       # list of error strings
print(result.exit_code)    # 0 (valid), 2 (schema), 3 (hash), 4 (consistency), 5 (other)
```

## Store

### `ReceiptStore`

```python
class ReceiptStore:
    def __init__(self, db_path: str = ".sanna/receipts.db") -> None
    def save(self, receipt: dict) -> str           # returns receipt_id
    def query(
        self,
        *,
        limit: int | None = None,
        offset: int = 0,
        agent_id: str = ...,
        constitution_id: str = ...,
        correlation_id: str = ...,
        status: str = ...,          # "PASS" / "WARN" / "FAIL" / "PARTIAL"
        enforcement: bool = ...,
        check_status: str = ...,
        since: datetime | str = ...,
        until: datetime | str = ...,
    ) -> list[dict]
    def close(self) -> None
```

SQLite-backed receipt persistence. The constructor rejects `/tmp` paths in production (use `SANNA_ALLOW_TEMP_DB=1` for CI only). Also works as a context manager.

```python
from sanna import ReceiptStore

with ReceiptStore(".sanna/receipts.db") as store:
    store.save(result.receipt)
    failing = store.query(status="FAIL", limit=20)
```

## Drift

### `DriftAnalyzer`

```python
class DriftAnalyzer:
    def __init__(self, store: ReceiptStore) -> None
    def analyze(
        self,
        window_days: int = 30,
        agent_id: str | None = None,
        threshold: float = 0.15,
        projection_days: int = 90,
    ) -> DriftReport
```

Computes per-agent, per-check failure rates with linear regression trend analysis and breach-day projection. Pure Python (no numpy/scipy).

```python
from sanna import ReceiptStore, DriftAnalyzer

store = ReceiptStore(".sanna/receipts.db")
analyzer = DriftAnalyzer(store)
report = analyzer.analyze(window_days=30, threshold=0.15)

print(report.fleet_status)             # "HEALTHY" / "WARNING" / "CRITICAL"
for agent in report.agents:
    print(agent.agent_id, agent.status)
    for check in agent.checks:
        print(f"  {check.check_id}: fail_rate={check.fail_rate:.1%}")
```

### Drift data classes (from `sanna.drift`)

| Class | Purpose |
|-------|---------|
| `DriftReport` | Fleet-level report: `window_days`, `threshold`, `generated_at`, `agents`, `fleet_status` |
| `AgentDriftSummary` | Per-agent: `agent_id`, `constitution_id`, `status`, `total_receipts`, `checks`, `projected_breach_days` |
| `CheckDriftDetail` | Per-check stats: `check_id`, `fail_rate`, `trend_slope`, `projected_breach_days`, `status` |

## Sinks

### `ReceiptSink` (ABC)

```python
class ReceiptSink(ABC):
    @abstractmethod
    def store(self, receipt: dict) -> SinkResult: ...
    def batch_store(self, receipts: list[dict]) -> SinkResult: ...
    def flush(self) -> None: ...
    def close(self) -> None: ...
```

### `FailurePolicy`

```python
class FailurePolicy(enum.Enum):
    LOG_AND_CONTINUE = "log_and_continue"   # default
    RAISE = "raise"
    BUFFER_AND_RETRY = "buffer_and_retry"
```

### Concrete sinks

```python
from sanna import LocalSQLiteSink, CloudHTTPSink, CompositeSink, NullSink, FailurePolicy

# Local SQLite (same engine as ReceiptStore, no extra deps)
local = LocalSQLiteSink(".sanna/receipts.db")

# HTTP endpoint — retries on 429/5xx; treats 409 as success (duplicate)
cloud = CloudHTTPSink(
    "https://governance.example.com/receipts",
    api_key="<your-key>",
    failure_policy=FailurePolicy.BUFFER_AND_RETRY,
)

# Fan-out
sink = CompositeSink([local, cloud])

result = sink.store(receipt_dict)
print(result.ok, result.stored, result.failed)
```

## Interceptors

### `patch_subprocess` / `unpatch_subprocess`

```python
def patch_subprocess(
    constitution_path: str,
    sink: ReceiptSink,
    agent_id: str,
    mode: str = "enforce",          # "enforce" | "audit" | "passthrough"
    signing_key: bytes | None = None,
    content_mode: str | None = None,
    workflow_id: str | None = None,
    parent_fingerprint: str | None = None,
) -> None

def unpatch_subprocess() -> None
```

Patches `subprocess.run`, `Popen`, `os.system`, `os.exec*`, `os.spawn*`, `os.popen`. Evaluates each call against the constitution's `cli_permissions`; halts (`FileNotFoundError`) or escalates (`PermissionError`) on policy violation.

**Security model:** In-process monkeypatching — defense-in-depth for cooperative code only. For untrusted code, use the SannaGateway (out-of-process). See [docs/deployment-tiers.md](https://github.com/sanna-ai/sanna/blob/main/docs/deployment-tiers.md).

### `patch_http` / `unpatch_http`

```python
def patch_http(
    constitution_path: str,
    sink: ReceiptSink,
    agent_id: str,
    mode: str = "enforce",          # "enforce" | "audit" | "passthrough"
    signing_key: bytes | None = None,
    content_mode: str | None = None,
    workflow_id: str | None = None,
    parent_fingerprint: str | None = None,
    exclude_urls: list | None = None,
) -> None

def unpatch_http() -> None
```

Patches `requests`, `httpx`, `urllib.request`, and `urllib3`. Evaluates each request against the constitution's `api_permissions`. Sanna Cloud endpoints are always excluded to prevent infinite recursion.

See [docs/cookbook.md](https://github.com/sanna-ai/sanna/blob/main/docs/cookbook.md) for a complete interceptor example.

## Redaction

### `RedactionConfig`

```python
@dataclass
class RedactionConfig:
    enabled: bool = False
    mode: str = "hash_only"           # "hash_only" | "pattern_redact" (reserved)
    fields: list[str] = ["arguments", "result_text"]
```

When `enabled=True`, replaces the specified receipt fields with deterministic markers **before** signing. The receipt signature covers the markers, not the original content. `content_mode` is set to `"redacted"` in the receipt metadata.

```python
from sanna import sanna_observe, RedactionConfig

@sanna_observe(
    constitution_path="constitution.yaml",
    constitution_public_key_path="~/.sanna/keys/<key-id>.pub",
    redaction_config=RedactionConfig(enabled=True, fields=["arguments"]),
)
def my_agent(query: str, context: str) -> str:
    return "Answer."
```

## Submodules

Non-top-level public APIs live in:

| Submodule | Key exports |
|-----------|-------------|
| `sanna.constitution` | `Constitution`, `load_constitution`, `parse_constitution`, `sign_constitution`, `approve_constitution`, `save_constitution`, `scaffold_constitution`, `AgentIdentity`, `Boundary`, `Invariant`, `Provenance`, `ConstitutionSignature`, `HaltCondition`, `TrustTiers`, `TrustedSources`, `AuthorityBoundaries`, `EscalationRule`, `ApprovalRecord`, `ApprovalChain`, `IdentityClaim`, `ReasoningConfig`, `constitution_to_receipt_ref`, `constitution_to_dict`, `compute_constitution_hash`, `compute_content_hash`, `validate_constitution_data`, `SannaConstitutionError` |
| `sanna.crypto` | `generate_keypair`, `load_key_metadata`, `sign_receipt`, `verify_receipt_signature`, `sign_constitution_full`, `verify_constitution_full`, `sanitize_for_signing` |
| `sanna.enforcement` | `CheckConfig`, `CustomInvariantRecord`, `configure_checks`, `INVARIANT_CHECK_MAP`, `CHECK_REGISTRY`, `AuthorityDecision`, `evaluate_authority`, `EscalationTarget`, `EscalationResult`, `execute_escalation`, `register_escalation_callback`, `clear_escalation_callbacks` |
| `sanna.evaluators` | `register_invariant_evaluator`, `get_evaluator`, `list_evaluators`, `clear_evaluators` |
| `sanna.bundle` | `create_bundle`, `verify_bundle`, `BundleVerificationResult`, `BundleCheck` |
| `sanna.hashing` | `hash_text`, `hash_obj`, `canonicalize_text` |
| `sanna.drift` | `DriftReport`, `AgentDriftSummary`, `CheckDriftDetail`, `export_drift_report`, `export_drift_report_to_file` |
| `sanna.receipt` | `CheckResult`, `FinalAnswerProvenance`, `ConstitutionProvenance`, `HaltEvent`, `Enforcement`, `TOOL_VERSION`, `SPEC_VERSION`, `CHECKS_VERSION`, `extract_trace_data` |
| `sanna.verify` | `load_schema`, `verify_constitution_chain` |
| `sanna.constitution_diff` | `diff_constitutions`, `DiffResult`, `DiffEntry` |
| `sanna.sinks` | Full sink hierarchy (also available via top-level `sanna.*`) |

For the constitution document format and YAML schema, see the [README Constitution Format section](https://github.com/sanna-ai/sanna#constitution-format). For cryptographic construction details, see the [v1.5 specification](https://github.com/sanna-ai/sanna-protocol/blob/main/spec/sanna-specification-v1.5.md) — do not restate the canonicalization claim locally.

## CLI commands

For the full CLI command table, see the [README CLI Reference section](https://github.com/sanna-ai/sanna#cli-reference).
