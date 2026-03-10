"""MCP server registration for mcp-airlock-crunchtools."""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from .tools import (
    get_airlock_stats,
    quarantine_fetch,
    quarantine_read,
    quarantine_scan,
    safe_fetch,
    safe_read,
)

mcp = FastMCP(
    "mcp-airlock-crunchtools",
    version="0.1.0",
    instructions=(
        "Quarantined web content extraction with two-layer prompt injection defense. "
        "Layer 1: deterministic sanitization strips hidden HTML, invisible unicode, "
        "encoded payloads, exfiltration URLs, and LLM delimiters. "
        "Layer 2: quarantined Gemini Flash-Lite LLM extracts content with NO tool access. "
        "Use safe_fetch for trusted content (fails on injection), "
        "quarantine_fetch for untrusted content (warns but proceeds), "
        "quarantine_scan for pre-flight threat assessment."
    ),
)


@mcp.tool()
async def safe_fetch_tool(url: str) -> dict[str, Any]:
    """Fetch URL with Layer 1 sanitization. Fails if injection detected.

    Trusted domains: Layer 1 only (no Q-Agent cost).
    Untrusted domains: Layer 1 + Q-Agent detection scan. Fails and blocks if detected.

    Args:
        url: URL to fetch (http:// or https://)
    """
    return await safe_fetch(url)


@mcp.tool()
async def quarantine_fetch_tool(
    url: str,
    prompt: str = "Extract the main content from this page.",
) -> dict[str, Any]:
    """Fetch URL with full quarantine: Layer 1 sanitization + Layer 2 Q-Agent extraction.

    Warns if source is in blocklist but proceeds anyway. Use this for untrusted content
    where you need structured extraction despite the risk.

    Args:
        url: URL to fetch (http:// or https://)
        prompt: Extraction instruction for the Q-Agent
    """
    return await quarantine_fetch(url, prompt)


@mcp.tool()
async def safe_read_tool(path: str) -> dict[str, Any]:
    """Read local file with Layer 1 sanitization. Fails if injection detected.

    Text files only (markdown, source code, config). Binary files rejected.

    Args:
        path: Path to the file to read
    """
    return await safe_read(path)


@mcp.tool()
async def quarantine_read_tool(
    path: str,
    prompt: str = "Extract the main content from this file.",
) -> dict[str, Any]:
    """Read local file with full quarantine: Layer 1 + Layer 2 Q-Agent extraction.

    Text files only. Warns if file is in blocklist but proceeds anyway.

    Args:
        path: Path to the file to read
        prompt: Extraction instruction for the Q-Agent
    """
    return await quarantine_read(path, prompt)


@mcp.tool()
async def quarantine_scan_tool(
    url: str | None = None,
    path: str | None = None,
) -> dict[str, Any]:
    """Pre-flight security scan: detect injection vectors WITHOUT returning content.

    Provide either url or path (not both). Returns threat assessment with risk level,
    vector counts, and Q-Agent observations. Always runs full detection regardless
    of trust level.

    Args:
        url: URL to scan (optional)
        path: File path to scan (optional)
    """
    return await quarantine_scan(url=url, path=path)


@mcp.tool()
async def quarantine_stats_tool() -> dict[str, Any]:
    """Get airlock configuration, Q-Agent status, and blocklist summary."""
    return await get_airlock_stats()
