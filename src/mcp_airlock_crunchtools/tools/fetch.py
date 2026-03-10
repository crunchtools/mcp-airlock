"""Fetch tools — quarantine_fetch and safe_fetch."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from ..client import fetch_url
from ..config import get_config
from ..database import is_blocked, record_detection
from ..errors import BlockedSourceError
from ..quarantine.agent import quarantine_detect, quarantine_extract
from ..sanitize.pipeline import PipelineResult, looks_like_html, sanitize, sanitize_text


def _build_sanitization_metadata(pipeline_result: PipelineResult) -> dict[str, Any]:
    """Build the sanitization section of tool response."""
    return {
        "input_size": pipeline_result.input_size,
        "output_size": pipeline_result.output_size,
        "stripped": pipeline_result.stats.to_flat_dict(),
    }


async def safe_fetch(url: str) -> dict[str, Any]:
    """Fetch URL with Layer 1 sanitization. Fails if injection detected.

    For untrusted sources, also runs Q-Agent detection scan.
    Trusted sources get Layer 1 only (no Q-Agent cost).
    """
    config = get_config()

    blocked = is_blocked(url)
    if blocked:
        raise BlockedSourceError(url, blocked["detected_at"])

    content, _content_type = await fetch_url(url)

    pipeline_result = sanitize(content) if looks_like_html(content) else sanitize_text(content)

    is_trusted = config.is_trusted_domain(url)

    if not is_trusted and config.has_api_key:
        detection = await quarantine_detect(pipeline_result.content)
        if detection.get("injection_detected"):
            domain = urlparse(url).hostname
            record_detection(
                source_type="url",
                source=url,
                domain=domain,
                layer1_stats=pipeline_result.stats.to_flat_dict(),
                risk_level=detection.get("risk_level", "high"),
                qagent_assessment=detection,
            )
            raise BlockedSourceError(url, "just detected")

    if pipeline_result.stats.total_detections() > 0 and not is_trusted:
        risk = pipeline_result.stats.risk_level()
        if risk in ("high", "critical"):
            domain = urlparse(url).hostname
            record_detection(
                source_type="url",
                source=url,
                domain=domain,
                layer1_stats=pipeline_result.stats.to_flat_dict(),
                risk_level=risk,
            )
            raise BlockedSourceError(url, "just detected")

    trust_level = "trusted-sanitized" if is_trusted else "sanitized-only"

    return {
        "content": pipeline_result.content,
        "trust": {
            "level": trust_level,
            "source": "layer1",
            "source_url": url,
        },
        "sanitization": _build_sanitization_metadata(pipeline_result),
    }


async def quarantine_fetch(url: str, prompt: str) -> dict[str, Any]:
    """Fetch URL with Layer 1 + Layer 2 (Q-Agent) extraction.

    Warns but proceeds if source is in blocklist.
    """
    config = get_config()

    blocked = is_blocked(url)
    blocklist_warning = None
    if blocked:
        blocklist_warning = (
            f"Warning: source previously flagged at {blocked['detected_at']}. "
            "Proceeding in quarantine mode."
        )

    content, _content_type = await fetch_url(url)

    pipeline_result = sanitize(content) if looks_like_html(content) else sanitize_text(content)

    is_trusted = config.is_trusted_domain(url)

    if is_trusted:
        return {
            "content": {"extracted_text": pipeline_result.content},
            "trust": {
                "level": "trusted-sanitized",
                "source": "layer1",
                "source_url": url,
            },
            "sanitization": _build_sanitization_metadata(pipeline_result),
            "blocklist_warning": blocklist_warning,
        }

    if not config.has_api_key:
        if config.fallback == "fail":
            from ..errors import ConfigError
            raise ConfigError("GEMINI_API_KEY required and QUARANTINE_FALLBACK=fail")
        return {
            "content": {"extracted_text": pipeline_result.content},
            "trust": {
                "level": "sanitized-only",
                "source": "layer1-fallback",
                "source_url": url,
            },
            "sanitization": _build_sanitization_metadata(pipeline_result),
            "blocklist_warning": blocklist_warning,
        }

    truncated = pipeline_result.content[:config.max_content]

    extraction = await quarantine_extract(truncated, prompt)

    return {
        "content": extraction.get("content", {}),
        "trust": {
            "level": "quarantined",
            "source": "q-agent",
            "model": config.model,
            "source_url": url,
        },
        "sanitization": _build_sanitization_metadata(pipeline_result),
        "usage": extraction.get("usage", {}),
        "blocklist_warning": blocklist_warning,
    }
