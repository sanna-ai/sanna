# Production Deployment

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SANNA_PRIVATE_KEY_PATH` | Ed25519 private key for receipt signing | `~/.sanna/keys/<key-id>.key` |
| `SANNA_CONSTITUTION_PATH` | Path to signed constitution YAML | `./constitution.yaml` |
| `SANNA_GATEWAY_CONFIG_PATH` | Path to gateway config YAML | `./gateway.yaml` |
| `SANNA_GATEWAY_SECRET` | Hex-encoded HMAC secret for escalation tokens (32 bytes) | Auto-generated |
| `OPENAPI_MCP_HEADERS` | JSON-encoded headers for Notion MCP server | — |

## Docker

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN sanna check-config gateway.yaml
CMD ["sanna", "gateway", "--config", "gateway.yaml"]
```

```yaml
# docker-compose.yml
services:
  sanna-gateway:
    build: .
    volumes:
      - ./constitution.yaml:/app/constitution.yaml:ro
      - ./gateway.yaml:/app/gateway.yaml:ro
      - ./keys:/app/keys:ro
      - sanna-data:/app/.sanna
    environment:
      - SANNA_GATEWAY_SECRET
      - OPENAPI_MCP_HEADERS
    healthcheck:
      test: ["CMD", "python", "-c", "import sanna; print(sanna.__version__)"]
      interval: 30s
      timeout: 5s

volumes:
  sanna-data:
```

Key points:
- Mount constitution and keys as read-only volumes
- Use a named volume for `.sanna/` (receipts, escalation state, gateway secret)
- Pass secrets via environment variables, not files in the image

## Logging

Sanna uses Python's `logging` module. Configure levels per namespace:

```python
import logging
logging.getLogger("sanna").setLevel(logging.INFO)
logging.getLogger("sanna.gateway").setLevel(logging.DEBUG)
logging.getLogger("sanna.gateway.config").setLevel(logging.WARNING)
```

For structured logging with an aggregator (Datadog, Splunk, ELK):

```python
import logging, json

class JSONFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        })

handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logging.getLogger("sanna").addHandler(handler)
```

## Receipt Retention

**Filesystem receipts** (gateway default): Stored as JSON files in `receipt_store` directory. Rotate with standard log rotation tools.

**SQLite receipts** (`ReceiptStore`): Stored in `.sanna/receipts.db` with WAL mode. Back up the DB file periodically. Use `store.query(since=..., until=...)` for time-bounded exports.

Retention strategy:
1. Keep hot receipts in SQLite for 90 days (drift analysis window)
2. Export to cold storage (S3, GCS) via `sanna drift-report --export json`
3. Archive evidence bundles for compliance retention periods

## Failure Modes

| Failure | Behavior | Recovery |
|---------|----------|----------|
| Downstream MCP server offline | Circuit breaker opens after 3 failures; error receipt generated | Automatic probe-based recovery (half-open state) |
| Constitution file missing | Gateway refuses to start | Fix path in config, restart |
| Constitution signature invalid | Gateway refuses to start (when public key configured) | Re-sign constitution |
| Signing key missing | Receipts generated unsigned | Generate key with `sanna keygen` |
| SQLite lock contention | WAL mode handles concurrent reads; writes serialized | Normal operation |
| Escalation store full | New escalations rejected with error receipt | Increase `max_pending_escalations` or reduce `escalation_timeout` |
| Disk full | Atomic writes fail; error logged | Free disk space |

## Upgrade Steps

1. Check the [CHANGELOG](../CHANGELOG.md) for breaking changes
2. Update: `pip install --upgrade sanna`
3. Run `sanna check-config gateway.yaml` to validate config
4. Verify existing receipts still validate: `sanna verify <recent-receipt>.json`
5. Restart gateway

**Breaking change policy**: Schema changes bump `CHECKS_VERSION` or `SCHEMA_VERSION`. Receipts generated with older versions remain verifiable — the schema is additive. Constitution schema changes are backward-compatible within the same `sanna_constitution` version.
