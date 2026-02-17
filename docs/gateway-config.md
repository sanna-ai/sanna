# Gateway Configuration Reference

The Sanna gateway is configured via a YAML file passed with `--config`. Validate your config before deploying with `sanna check-config gateway.yaml`.

## Complete Example

```yaml
gateway:
  constitution: ./constitution.yaml
  signing_key: ~/.sanna/keys/gateway.key
  constitution_public_key: ~/.sanna/keys/author.pub  # optional
  receipt_store: ./receipts/
  escalation_timeout: 300
  max_pending_escalations: 100
  circuit_breaker_cooldown: 60
  approval_requires_reason: false
  token_delivery: [file, stderr]
  redaction:
    enabled: false
    mode: hash_only
    fields: [arguments, result_text]

downstream:
  - name: notion
    command: npx
    args: ["-y", "@notionhq/notion-mcp-server"]
    env:
      OPENAPI_MCP_HEADERS: "${OPENAPI_MCP_HEADERS}"
    timeout: 30
    default_policy: can_execute
    tools:
      "API-patch-page":
        policy: must_escalate
        reason: "Page mutations require approval"
      "API-post-page":
        policy: must_escalate
        reason: "Page creation requires approval"
      "API-delete-block":
        policy: cannot_execute
        reason: "Block deletion is prohibited"

  - name: filesystem
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
    timeout: 10
    default_policy: can_execute
```

## `gateway` Section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `constitution` | string | **required** | Path to signed constitution YAML. Relative paths resolved from config file location. |
| `signing_key` | string | — | Path to Ed25519 private key for receipt signing. `~` expanded. If omitted, receipts are unsigned. |
| `constitution_public_key` | string | — | Path to public key for verifying constitution signature on startup. |
| `receipt_store` | string | — | Directory for receipt JSON files. Created automatically. |
| `escalation_timeout` | float | `300` | Seconds before pending escalations expire. |
| `max_pending_escalations` | int | `100` | Maximum concurrent pending escalations. New ones rejected when full. |
| `circuit_breaker_cooldown` | float | `60` | Seconds before retrying a downstream server after circuit breaker opens. |
| `gateway_secret_path` | string | `~/.sanna/gateway_secret` | Path to HMAC secret file for escalation token binding. Auto-generated if missing. |
| `escalation_persist_path` | string | `~/.sanna/escalations.json` | Path for persisting pending escalations across restarts. |
| `approval_requires_reason` | bool | `false` | Whether escalation approvals must include a reason string. |
| `token_delivery` | list | `[file, stderr]` | How escalation approval tokens are delivered to the user. Options: `file`, `stderr`. |

### `gateway.redaction`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable PII redaction in stored receipts. |
| `mode` | string | `hash_only` | Redaction mode. `hash_only` replaces content with HMAC-SHA256 hash. |
| `fields` | list | `[arguments, result_text]` | Receipt fields to redact. |

When redaction is enabled, the original signed receipt is stored alongside a separate redacted copy. Signature verification requires the original file.

## `downstream` Section

Each entry defines a downstream MCP server that the gateway manages.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | **required** | Unique identifier. Used as tool namespace prefix (`{name}_{tool}`). Alphanumeric, hyphens, underscores only. |
| `command` | string | **required** | Executable to spawn. |
| `args` | list | `[]` | Command-line arguments. |
| `env` | dict | — | Environment variables for the child process. Supports `${VAR}` interpolation from the gateway's environment. |
| `timeout` | float | `30` | Per-call timeout in seconds. |
| `default_policy` | string | `can_execute` | Default policy for tools not listed in `tools:`. One of: `can_execute`, `must_escalate`, `cannot_execute`. |
| `tools` | dict | `{}` | Per-tool policy overrides. Keys are the original (unprefixed) tool names. |
| `optional` | bool | `false` | If true, gateway starts even if this downstream fails to connect. |

### Per-Tool Override

```yaml
tools:
  "API-patch-page":
    policy: must_escalate
    reason: "Page mutations require approval"
```

| Field | Type | Description |
|-------|------|-------------|
| `policy` | string | One of: `can_execute`, `must_escalate`, `cannot_execute` |
| `reason` | string | Human-readable reason displayed in escalation prompts and receipts |

## Policy Cascade

When the gateway receives a tool call, it resolves the policy in this order:

1. **Per-tool override** — exact match on the original (unprefixed) tool name
2. **Server `default_policy`** — the downstream server's default
3. **Constitution fallthrough** — `evaluate_authority()` against constitution's `authority_boundaries` using keyword matching

Most specific wins. If no match at any level, the tool call is allowed.

## Environment Variable Interpolation

Use `${VAR_NAME}` syntax in `env` blocks. Variables are resolved from the gateway process's environment at config load time. Unresolved variables raise an error.

```yaml
env:
  OPENAPI_MCP_HEADERS: "${OPENAPI_MCP_HEADERS}"
  API_KEY: "${MY_API_KEY}"
```

Never commit secrets to config files. Use environment variables or a secrets manager.

## Tool Namespace

Gateway prefixes all downstream tools with `{server_name}_`. Example: Notion's `API-patch-page` becomes `notion_API-patch-page`. This complies with Claude Desktop's tool name pattern: `^[a-zA-Z0-9_-]{1,64}$`.

## Meta-Tools

Two gateway meta-tools are always registered (not prefixed):

| Tool | Description |
|------|-------------|
| `sanna_escalation_respond` | User approval/denial for `must_escalate` tool calls |
| `sanna_gateway_status` | Gateway health and downstream connection status |
