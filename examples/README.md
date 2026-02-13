# Sanna Examples

## Demos

### Three Constitutions Demo (`three_constitutions_demo.py`)

Same input, three different constitutions, three different enforcement outcomes.
Demonstrates how the constitution drives check behavior and Ed25519 provenance.

```bash
python examples/three_constitutions_demo.py
```

### One More Connector Demo (`one_more_connector_demo.py`)

An agent uses multiple MCP tools. Sanna is the governance connector.
Four scenarios show the full governance lifecycle:

| Scenario | Action | Authority Decision | Sources |
|----------|--------|--------------------|---------|
| 01 Query Database | `query_database` | ALLOW (can_execute) | tier_1: internal_database |
| 02 Send Email | `send_email` | HALT (cannot_execute) | tier_1: internal_database |
| 03 PII Access | `access_customer_record` | ESCALATE (must_escalate) | tier_2: partner_api |
| 04 Generate Report | `generate_report` | ALLOW (can_execute) | tier_1 + tier_2 + tier_3 |

```bash
python examples/one_more_connector_demo.py
```

Generates four receipt JSON files in `demo_receipts/`, each showing:
- **Authority decisions** — whether the action was allowed, halted, or escalated
- **Escalation events** — logged escalation details when PII is detected
- **Source trust evaluations** — per-source trust tier classification
- **Coherence checks** — C1 (context contradiction) and C2 (unmarked inference) results
- **Ed25519 signatures** — cryptographic provenance on both constitution and receipt

## Constitutions

Sample constitutions in `constitutions/`:

| File | Domain | Enforcement |
|------|--------|-------------|
| `strict_financial_analyst.yaml` | Finance | All invariants at HALT |
| `permissive_support_agent.yaml` | Support | 2 at WARN + 1 custom |
| `research_assistant.yaml` | Research | C1=HALT, rest=LOG |
| `governance_connector.yaml` | Enterprise | Authority boundaries + trusted sources |

## Output

Generated receipts are written to:
- `output/` — from `three_constitutions_demo.py`
- `demo_receipts/` — from `one_more_connector_demo.py`

Each receipt is a portable JSON artifact that can be verified offline:

```bash
sanna-verify demo_receipts/01_query_database_allow.json
```
