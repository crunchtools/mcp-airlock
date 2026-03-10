# mcp-airlock-crunchtools Constitution

> **Version:** 1.0.0
> **Ratified:** 2026-03-09
> **Status:** Active
> **Inherits:** [crunchtools/constitution](https://github.com/crunchtools/constitution) v1.1.0
> **Profile:** MCP Server

This constitution establishes the core principles, constraints, and workflows that govern all development on mcp-airlock-crunchtools.

---

## I. Core Principles

### 1. Five-Layer Security Model

Every change MUST preserve all five security layers.

**Layer 1 — Credential Protection:**
- GEMINI_API_KEY stored as Pydantic SecretStr
- API key scrubbed from all error messages via errors.py
- Separate env file from mcp-gemini for cost isolation

**Layer 2 — Input Validation:**
- Pydantic models enforce strict data types with `extra="forbid"`
- URL scheme validation (http/https only)
- Path traversal prevention
- Content size limits enforced before processing

**Layer 3 — API Hardening:**
- TLS to Gemini REST API (mandatory)
- Timeouts on all outbound HTTP calls (web fetch and Gemini)
- Response size limits on web fetches (5 MB)
- Content truncation before Q-Agent (configurable, default 100K chars)

**Layer 4 — Dangerous Operation Prevention:**
- **EXCEPTION:** This server is a security gateway, not an API wrapper. It fetches and processes untrusted web content by design. Layer 4 compliance is achieved by ensuring the server itself never executes arbitrary code, never shells out, and limits filesystem access to read-only on text files.
- No shell execution or code evaluation
- No `eval()`/`exec()` functions
- No `safe_exec` tool — permanently out of scope (incompatible with MCP Server profile)
- File reading scoped to text files only — binary rejected, read-only, no writes

**Layer 5 — Supply Chain Security:**
- Weekly automated CVE scanning via GitHub Actions
- Hummingbird container base images (minimal CVE surface)
- Gourmand AI slop detection gating all PRs
- No google-genai SDK — architectural enforcement of Q-Agent quarantine

### 2. Two-Layer Defense Architecture

The server implements defense-in-depth against prompt injection:

- **Layer 1 (Deterministic):** 7-stage sanitization pipeline strips known injection vectors
- **Layer 2 (Q-Agent):** Quarantined Gemini Flash-Lite LLM for semantic extraction — NO tools, NO memory, NO SDK

The Q-Agent quarantine is enforced architecturally:
- Raw httpx REST calls to Gemini API (no google-genai SDK)
- No function declarations in API requests
- No memory beyond single request
- Structured JSON output via Gemini responseSchema

### 3. Two-Layer Tool Architecture

Tools follow a strict two-layer pattern:
- `server.py` — `@mcp.tool()` decorated functions that validate args and delegate
- `tools/*.py` — Async functions that orchestrate sanitization, Q-Agent, and database

Never put business logic in `server.py`. Never put MCP registration in `tools/*.py`.

### 4. SQLite Blocklist Integrity

The SQLite blocklist is write-accessible by deterministic code ONLY:
- The Q-Agent cannot write to the database
- Q-Agent output is parsed by deterministic code which decides whether to record
- This prevents a compromised Q-Agent from manipulating the blocklist

### 5. Trust Allowlist

Trust decisions are administrator-set, NOT agent-controlled:
- Server-side JSON config file
- Trusted domains skip Q-Agent (Layer 1 only) to reduce cost
- Untrusted sources get full Layer 1 + Layer 2 treatment
- A compromised agent cannot override trust levels

### 6. Three Distribution Channels

Every release MUST be available through all three channels simultaneously:

| Channel | Command | Use Case |
|---------|---------|----------|
| uvx | `uvx mcp-airlock-crunchtools` | Zero-install, Claude Code |
| pip | `pip install mcp-airlock-crunchtools` | Virtual environments |
| Container | `podman run quay.io/crunchtools/mcp-airlock` | Isolated, systemd |

### 7. Three Transport Modes

The server MUST support all three MCP transports:
- **stdio** (default) — spawned per-session by Claude Code
- **SSE** — legacy HTTP transport
- **streamable-http** — production HTTP, systemd-managed containers

### 8. Semantic Versioning

Follow [Semantic Versioning 2.0.0](https://semver.org/) strictly.

### 9. AI Code Quality

All code MUST pass Gourmand checks before merge. Zero violations required.

---

## II. Technology Stack

| Layer | Technology | Version |
|-------|------------|---------|
| Language | Python | 3.10+ |
| MCP Framework | FastMCP | Latest |
| HTTP Client | httpx | Latest |
| Validation | Pydantic | v2 |
| HTML Parsing | beautifulsoup4 | Latest |
| HTML-to-Markdown | markdownify | Latest |
| Database | SQLite | Built-in |
| Q-Agent Backend | Gemini REST API (raw httpx) | gemini-2.0-flash-lite |
| Container Base | Hummingbird | Latest |
| Package Manager | uv | Latest |
| Build System | hatchling | Latest |
| Linter | ruff | Latest |
| Type Checker | mypy (strict) | Latest |
| Tests | pytest + pytest-asyncio | Latest |
| Slop Detector | gourmand | Latest |

---

## III. Testing Standards

### Mocked Tests (MANDATORY)

All tests use mocked httpx — no live API calls. Test categories:
- Sanitization unit tests (one file per module)
- Pipeline integration tests
- Q-Agent tests (mock Gemini responses, verify no function declarations)
- Scan tests (quarantine_scan)
- File read tests (binary rejection, size limits)
- Adversarial tests (injection vectors)

### Tool count assertion

`test_tool_count` MUST be updated whenever tools are added or removed.

---

## IV. Code Quality Gates

1. **Lint** — `uv run ruff check src tests`
2. **Type Check** — `uv run mypy src`
3. **Tests** — `uv run pytest -v`
4. **Gourmand** — `gourmand --full .`
5. **Container Build** — `podman build -f Containerfile .`

---

## V. Naming Conventions

| Context | Name |
|---------|------|
| GitHub repo | `crunchtools/mcp-airlock` |
| PyPI package | `mcp-airlock-crunchtools` |
| CLI command | `mcp-airlock-crunchtools` |
| Python module | `mcp_airlock_crunchtools` |
| Container image | `quay.io/crunchtools/mcp-airlock` |
| systemd service | `mcp-airlock.service` |
| HTTP port | 8019 |
| License | AGPL-3.0-or-later |

---

## VI. Ratification History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-03-09 | Initial constitution |
