"""Layer 2: Q-Agent quarantine for mcp-airlock-crunchtools."""

from __future__ import annotations

from .agent import quarantine_detect, quarantine_extract

__all__ = [
    "quarantine_detect",
    "quarantine_extract",
]
