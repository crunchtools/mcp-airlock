# Specification: [Feature Name]

> **Spec ID:** XXX-feature-name
> **Status:** Draft | In Progress | Implemented
> **Version:** 0.1.0
> **Author:** [Name]
> **Date:** YYYY-MM-DD

## Overview

[2-3 sentence description of what this feature does and why it matters]

---

## New Tools

| Tool | Method | Endpoint | Description |
|------|--------|----------|-------------|
| `tool_name` | GET/POST/PUT/DELETE | `/api/v4/...` | [What it does] |

---

## Security Considerations

### Layer 1 — Token Protection
- [Any new token handling?]

### Layer 2 — Input Validation
- [New Pydantic models needed?]
- [New allowlists or constants?]

### Layer 3 — API Hardening
- [New endpoints to validate?]
- [URL encoding requirements?]

### Layer 4 — Dangerous Operation Prevention
- [Any risk of file/shell/eval access?]

---

## Module Changes

### New Files

| File | Purpose |
|------|---------|
| `tools/new_group.py` | [Description] |

### Modified Files

| File | Changes |
|------|---------|
| `tools/__init__.py` | Add exports |
| `server.py` | Add `@mcp.tool()` wrappers |

---

## Testing Requirements

### Mocked API Tests
- [ ] `TestNewGroupTools` class in `test_tools.py`
- [ ] One test per tool with mock response
- [ ] Error case coverage (404, 401, etc.)

### Input Validation Tests
- [ ] New Pydantic model tests in `test_validation.py`
- [ ] Injection prevention tests

### Tool Count Update
- [ ] Update `test_tool_count` assertion

---

## Dependencies

- Depends on: [Spec ID or external dependency]
- Blocks: [Spec ID that depends on this]

---

## Open Questions

1. [Question that needs resolution before implementation]

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | YYYY-MM-DD | Initial draft |
