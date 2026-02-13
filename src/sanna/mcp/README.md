# Sanna MCP Server

Model Context Protocol (MCP) server that exposes Sanna's governance capabilities as tools for Claude Desktop, Cursor, and other MCP-compatible clients.

## Installation

```bash
pip install sanna[mcp]
```

## Usage

```bash
sanna-mcp                    # via entry point
python -m sanna.mcp           # via module
```

The server uses stdio transport and is designed to be launched by an MCP client (not run standalone).

## Tools

### `sanna_verify_receipt`

Verify a Sanna reasoning receipt offline. Checks schema validity, fingerprint integrity, content hashes, and status consistency.

**Input:** `receipt_json` (string) — JSON string of the receipt to verify.

**Output:** JSON with `valid`, `exit_code`, `errors`, `warnings`, computed/expected fingerprints and status.

### `sanna_generate_receipt`

Generate a receipt from a query/context/response triple. When `constitution_path` is provided, the constitution's invariants drive which checks run (C1-C5) and at what enforcement level.

**Input:**
- `query` (string) — User query
- `context` (string) — Retrieved context
- `response` (string) — Agent response
- `constitution_path` (string, optional) — Path to signed constitution YAML

**Output:** JSON receipt with check results, fingerprint, and provenance.

### `sanna_list_checks`

List all C1-C5 coherence checks with descriptions, invariant mappings, severity levels, and default enforcement.

**Input:** None required.

**Output:** JSON array of check metadata.

### `sanna_evaluate_action`

Evaluate whether an action is permitted under a constitution's authority boundaries. Returns halt/allow/escalate decision with reason and boundary type.

**Input:**
- `action` (string) — Action name to evaluate (e.g., "send_email")
- `params` (object, optional) — Action parameters
- `constitution_path` (string) — Path to constitution YAML with authority_boundaries

**Output:** JSON with `decision`, `reason`, `boundary_type`, optional `escalation_target`.

## Claude Desktop Configuration

Add to your Claude Desktop `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sanna": {
      "command": "sanna-mcp",
      "args": []
    }
  }
}
```

See [examples/CLAUDE_DESKTOP_SETUP.md](../../../examples/CLAUDE_DESKTOP_SETUP.md) for detailed setup instructions.

## Constitution-Driven Enforcement

When a constitution path is provided to `sanna_generate_receipt` or `sanna_evaluate_action`, the constitution's rules drive enforcement:

- **Invariants** determine which C1-C5 checks run and at what level (halt/warn/log)
- **Authority boundaries** determine which actions are allowed, halted, or escalated
- **Trusted sources** affect C1 context contradiction evaluation

All decisions are recorded in the receipt for offline verification.
