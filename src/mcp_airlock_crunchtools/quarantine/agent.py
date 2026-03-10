"""Q-Agent — Quarantined Gemini REST API client.

Uses raw httpx to call Gemini REST API. NO google-genai SDK.
This is the architectural enforcement of the Q-Agent quarantine:
- No function declarations (no tools)
- No SDK (no accidental tool configuration)
- No memory (stateless per request)
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from ..config import get_config
from ..errors import QuarantineAgentError
from .prompts import (
    DETECTION_RESPONSE_SCHEMA,
    DETECTION_SYSTEM_PROMPT,
    EXTRACTION_RESPONSE_SCHEMA,
    EXTRACTION_SYSTEM_PROMPT,
)

GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
GEMINI_TIMEOUT = 60.0
MAX_OUTPUT_TOKENS = 4096


def _build_request_body(
    content: str,
    system_prompt: str,
    response_schema: dict[str, Any],
    user_prompt: str | None = None,
) -> dict[str, Any]:
    """Build the Gemini REST API request body.

    CRITICAL: No 'tools' or 'functionDeclarations' key. This is architectural enforcement.
    The Q-Agent has NO tool access.
    """
    user_text = content
    if user_prompt:
        user_text = f"{user_prompt}\n\n---\n\n{content}"

    return {
        "system_instruction": {
            "parts": [{"text": system_prompt}],
        },
        "contents": [
            {
                "role": "user",
                "parts": [{"text": user_text}],
            },
        ],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": response_schema,
            "temperature": 0.1,
            "maxOutputTokens": MAX_OUTPUT_TOKENS,
        },
    }


async def _call_gemini(
    content: str,
    system_prompt: str,
    response_schema: dict[str, Any],
    user_prompt: str | None = None,
) -> dict[str, Any]:
    """Call Gemini REST API and return parsed JSON response."""
    config = get_config()

    if not config.has_api_key:
        raise QuarantineAgentError("GEMINI_API_KEY not configured")

    api_key = config.api_key.get_secret_value()
    model = config.model
    url = f"{GEMINI_API_BASE}/{model}:generateContent?key={api_key}"

    request_body = _build_request_body(content, system_prompt, response_schema, user_prompt)

    assert "tools" not in request_body, "Q-Agent request must not contain tools"
    assert "functionDeclarations" not in request_body, (
        "Q-Agent request must not contain functionDeclarations"
    )

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(GEMINI_TIMEOUT)) as http_client:
            resp = await http_client.post(
                url,
                json=request_body,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()

            resp_json = resp.json()

            candidates = resp_json.get("candidates", [])
            if not candidates:
                raise QuarantineAgentError("No candidates in Gemini response")

            parts = candidates[0].get("content", {}).get("parts", [])
            if not parts:
                raise QuarantineAgentError("No parts in Gemini response")

            text_content = parts[0].get("text", "")
            parsed: dict[str, Any] = json.loads(text_content)

            usage_metadata = resp_json.get("usageMetadata", {})
            parsed["_usage"] = {
                "input_tokens": usage_metadata.get("promptTokenCount", 0),
                "output_tokens": usage_metadata.get("candidatesTokenCount", 0),
            }

            return parsed

    except httpx.HTTPStatusError as exc:
        raise QuarantineAgentError(f"HTTP {exc.response.status_code}") from exc
    except httpx.TimeoutException as exc:
        raise QuarantineAgentError("Request timed out") from exc
    except json.JSONDecodeError as exc:
        raise QuarantineAgentError("Invalid JSON in Gemini response") from exc
    except httpx.RequestError as exc:
        raise QuarantineAgentError(str(exc)) from exc


async def quarantine_extract(content: str, prompt: str) -> dict[str, Any]:
    """Run Q-Agent in extraction mode. Returns structured content."""
    try:
        parsed = await _call_gemini(
            content=content,
            system_prompt=EXTRACTION_SYSTEM_PROMPT,
            response_schema=EXTRACTION_RESPONSE_SCHEMA,
            user_prompt=prompt,
        )
    except QuarantineAgentError:
        config = get_config()
        if config.fallback == "fail":
            raise
        return {
            "content": {
                "extracted_text": content,
                "confidence": "low",
                "injection_detected": False,
            },
            "usage": {},
        }
    else:
        usage = parsed.pop("_usage", {})
        return {
            "content": parsed,
            "usage": usage,
        }


async def quarantine_detect(content: str) -> dict[str, Any]:
    """Run Q-Agent in detection-only mode. Returns threat assessment."""
    try:
        parsed = await _call_gemini(
            content=content,
            system_prompt=DETECTION_SYSTEM_PROMPT,
            response_schema=DETECTION_RESPONSE_SCHEMA,
        )
    except QuarantineAgentError:
        return {
            "injection_detected": False,
            "risk_level": "low",
            "summary": "Q-Agent unavailable, detection skipped",
        }
    else:
        parsed.pop("_usage", None)
        return parsed
