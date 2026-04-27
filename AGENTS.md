# Sanna Python SDK — AGENTS.md

AI agent context file (cross-tool standard: Claude Code, Cursor, Codex CLI,
Copilot CLI, Gemini CLI all read this). Primary Python SDK + CLI + middleware
+ gateway + interceptors for the Sanna governance platform.

## Critical rules

- Never skip hooks (`--no-verify`). On hook failure: diagnose root cause, fix, create a **new** commit — do not amend.
- Never use `git add -f`. If `.gitignore` blocks a file, stop and ask.
- Never force-push. Never push directly to main.
- Never embed notion.so URLs in any committed file (repos are public; reference tickets by ID only: SAN-NNN).
- One branch = one scope. Do not bundle unrelated work in a single branch or PR.
- Follow instructions exactly as written. Do not reinterpret, skip steps, or combine separately specified steps.
- When a prerequisite is missing, STOP and ask — do not silently work around it.
- Never blindly retry or suggest "refresh" — diagnose root cause.
- Trace the full call path before proposing a fix.

## Context — read these

- [ARCHITECTURE.md](ARCHITECTURE.md) — system architecture, all key modules, data models, data flow diagrams
- [docs/security-hardening.md](docs/security-hardening.md) — security model, 12 key design invariants (load-bearing safety doc)
- [docs/conventions.md](docs/conventions.md) — env vars, testing rules, common pitfalls, post-release checklist
- [docs/state.md](docs/state.md) — auto-generated: version, protocol constants, test count, source layout
- [src/sanna/version.py](src/sanna/version.py) — package version (single source of truth)
- [sanna-protocol/VERSIONING.md](../sanna-protocol/VERSIONING.md) (cross-repo) — versioning discipline; PyPI immutability rule
- `sanna-protocol/docs/decisions/` (forthcoming) — ADRs for cross-SDK protocol decisions

## Per-developer notes

For personal scratch (machine-specific paths, WIP rule overrides), use
`CLAUDE.local.md` (gitignored). The committed `AGENTS.md` is the canonical
shared file.
