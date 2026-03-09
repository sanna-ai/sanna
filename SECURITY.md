# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | Yes                |
| < 1.0   | No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in Sanna, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email **security@sanna.dev** with:

- A description of the vulnerability
- Steps to reproduce or a proof-of-concept
- The affected version(s)
- Any potential impact assessment

You can expect:

- **Acknowledgement** within 48 hours
- **Initial assessment** within 5 business days
- **Resolution timeline** communicated after assessment

We will coordinate disclosure with you and credit reporters in the release notes (unless you prefer to remain anonymous).

## Scope

The following are in scope for security reports:

- **Cryptographic receipt integrity** — fingerprint computation, signing, verification
- **Constitution enforcement** — policy bypass, authority boundary evasion
- **Gateway proxy** — SSRF, tool namespace injection, escalation bypass, PII redaction leaks
- **SQLite store** — injection, path traversal, permission issues
- **Key management** — private key exposure, signature forgery
- **Input validation** — JSON/YAML parsing exploits, prompt injection via audit tags

The following are out of scope:

- Vulnerabilities in downstream MCP servers (Notion, GitHub, etc.)
- Denial of service against local CLI tools
- Issues requiring physical access to the machine running Sanna

## Security Design

Sanna is built with defense-in-depth:

- **Ed25519 signatures** on constitutions, receipts, and approval records
- **RFC 8785 canonical JSON** for deterministic hashing
- **SSRF protection** on all webhook endpoints (DNS rebinding, IP blocklists, HTTPS enforcement)
- **Symlink-safe atomic writes** via `O_NOFOLLOW` and `os.replace()`
- **SQLite hardening** — ownership checks, permission enforcement, WAL sidecar validation
- **Prompt injection isolation** — XML entity escaping in `<audit>` tags for LLM evaluator inputs
- **NaN/Infinity/duplicate-key rejection** in security-sensitive JSON and YAML parsing

For more details, see the [specification](spec/sanna-specification-v1.0.md) and [ARCHITECTURE.md](ARCHITECTURE.md).
