"""Stats tool — quarantine_stats for session and blocklist information."""

from __future__ import annotations

from typing import Any

from ..config import get_config
from ..database import get_blocklist_stats


async def get_airlock_stats() -> dict[str, Any]:
    """Get airlock session stats, configuration, and blocklist summary."""
    config = get_config()

    blocklist = get_blocklist_stats()

    return {
        "config": {
            "model": config.model,
            "fallback": config.fallback,
            "max_content": config.max_content,
            "has_api_key": config.has_api_key,
        },
        "blocklist": blocklist,
    }
