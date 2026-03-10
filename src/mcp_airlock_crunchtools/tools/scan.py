"""Scan tool — quarantine_scan for detection-only pre-flight."""

from __future__ import annotations

from typing import Any

from ..client import fetch_url
from ..config import get_config
from ..quarantine.agent import quarantine_detect
from ..sanitize.pipeline import looks_like_html, sanitize, sanitize_text
from .read import _validate_file

_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_RECOMMENDATIONS = {
    "low": "Source appears clean. Safe to use safe_fetch/safe_read.",
    "medium": "Minor vectors detected. Consider quarantine_fetch/quarantine_read.",
    "high": "Significant injection vectors. Use quarantine_fetch/quarantine_read.",
    "critical": "Multiple injection vectors detected. Exercise extreme caution.",
}


def _risk_order(level: str) -> int:
    """Return numeric risk order for comparison."""
    return _RISK_ORDER.get(level, 0)


async def quarantine_scan(
    url: str | None = None,
    path: str | None = None,
) -> dict[str, Any]:
    """Scan a URL or file for injection vectors WITHOUT returning content.

    Returns threat assessment only — risk level, vector counts, Q-Agent observations.
    Always runs full detection regardless of trust level.
    """
    if not url and not path:
        return {"error": "Provide either url or path to scan"}

    config = get_config()
    source_type = "url" if url else "file"
    source = url or path or ""

    if url:
        content, _ = await fetch_url(url)
    else:
        assert path is not None
        resolved = _validate_file(path)
        with open(resolved, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        source = resolved

    pipeline_result = (
        sanitize(content) if looks_like_html(content, path) else sanitize_text(content)
    )

    layer1_stats = pipeline_result.stats.to_flat_dict()
    layer1_risk = pipeline_result.stats.risk_level()
    layer1_detections = pipeline_result.stats.total_detections()

    qagent_assessment = None
    if config.has_api_key:
        truncated = pipeline_result.content[:config.max_content]
        qagent_assessment = await quarantine_detect(truncated)

    qagent_risk = "low"
    if qagent_assessment:
        qagent_risk = qagent_assessment.get("risk_level", "low")
        if qagent_assessment.get("injection_detected"):
            qagent_risk = max(qagent_risk, "high", key=_risk_order)

    overall_risk = max(layer1_risk, qagent_risk, key=_risk_order)

    return {
        "source_type": source_type,
        "source": source,
        "risk_level": overall_risk,
        "layer1": {
            "detections": layer1_detections,
            "risk_level": layer1_risk,
            "stats": layer1_stats,
        },
        "qagent": {
            "available": config.has_api_key,
            "assessment": qagent_assessment,
            "risk_level": qagent_risk,
        },
        "recommendation": _RECOMMENDATIONS.get(overall_risk, "Unknown risk level."),
    }
