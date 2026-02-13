# Sanna MCP Server — Claude Desktop Setup

## Install

```bash
pip install sanna[mcp]
```

This installs the `sanna-mcp` command-line entry point.

## Configure Claude Desktop

Copy `claude_desktop_config.json` into your Claude Desktop settings, or merge
the `sanna` block into your existing MCP configuration:

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

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

Restart Claude Desktop after saving.

## Available Tools

Once connected, Claude Desktop exposes four Sanna tools:

### `sanna_verify_receipt`

Verify a reasoning receipt offline. Validates schema, fingerprint, content
hashes, and status consistency.

### `sanna_generate_receipt`

Generate a receipt from a query/context/response triple. When a constitution
path is provided, the constitution's invariants drive which coherence checks
run (C1-C5) and at what enforcement level.

### `sanna_list_checks`

List all C1-C5 coherence checks with descriptions, invariant mappings, and
default enforcement levels.

### `sanna_evaluate_action`

Evaluate whether an action is permitted under a constitution's authority
boundaries. Returns `allow`, `halt`, or `escalate` with the matching rule.

## Example Prompts

Try these after connecting:

**List available checks:**
> What coherence checks does Sanna support?

**Generate a receipt:**
> Generate a Sanna receipt for this interaction:
> Query: "What is our refund policy?"
> Context: "Physical products: 30-day returns. Digital products: non-refundable."
> Response: "You can return physical products within 30 days. Digital products cannot be refunded."

**Verify a receipt:**
> Verify this Sanna receipt: [paste receipt JSON]

**Evaluate an action (requires a constitution file):**
> Can the agent execute "delete_database" under the constitution at /path/to/constitution.yaml?

## Constitution Setup

To use `sanna_generate_receipt` and `sanna_evaluate_action` with full
enforcement, you need a signed constitution:

```bash
# 1. Scaffold a constitution
sanna-init-constitution my_agent.yaml

# 2. Edit invariants, authority boundaries, trusted sources

# 3. Generate a keypair
sanna-keygen --signed-by "your-name" keys/

# 4. Sign the constitution
sanna-sign-constitution my_agent.yaml --private-key keys/sanna_ed25519.key

# 5. Use the signed constitution path in your prompts
```
