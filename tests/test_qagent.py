"""Tests for the Q-Agent (quarantine) module."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from mcp_airlock_crunchtools.quarantine.agent import (
    _build_request_body,
    quarantine_detect,
    quarantine_extract,
)
from mcp_airlock_crunchtools.quarantine.prompts import (
    DETECTION_RESPONSE_SCHEMA,
    DETECTION_SYSTEM_PROMPT,
    EXTRACTION_RESPONSE_SCHEMA,
    EXTRACTION_SYSTEM_PROMPT,
)


class TestRequestBodyConstruction:
    """Verify the Q-Agent request body has NO tool declarations."""

    def test_no_tools_key(self) -> None:
        body = _build_request_body(
            content="test content",
            system_prompt="test prompt",
            response_schema=EXTRACTION_RESPONSE_SCHEMA,
        )
        assert "tools" not in body
        assert "functionDeclarations" not in body

    def test_no_function_declarations(self) -> None:
        body = _build_request_body(
            content="test",
            system_prompt="test",
            response_schema=DETECTION_RESPONSE_SCHEMA,
        )
        body_str = json.dumps(body)
        assert "functionDeclarations" not in body_str

    def test_has_system_instruction(self) -> None:
        body = _build_request_body(
            content="test",
            system_prompt="my system prompt",
            response_schema=EXTRACTION_RESPONSE_SCHEMA,
        )
        assert "system_instruction" in body
        assert body["system_instruction"]["parts"][0]["text"] == "my system prompt"

    def test_has_response_schema(self) -> None:
        body = _build_request_body(
            content="test",
            system_prompt="test",
            response_schema=EXTRACTION_RESPONSE_SCHEMA,
        )
        gen_config = body["generationConfig"]
        assert gen_config["responseMimeType"] == "application/json"
        assert gen_config["responseSchema"] == EXTRACTION_RESPONSE_SCHEMA

    def test_user_prompt_prepended(self) -> None:
        body = _build_request_body(
            content="page content",
            system_prompt="system",
            response_schema=EXTRACTION_RESPONSE_SCHEMA,
            user_prompt="Extract the summary",
        )
        user_text = body["contents"][0]["parts"][0]["text"]
        assert user_text.startswith("Extract the summary")
        assert "page content" in user_text

    def test_low_temperature(self) -> None:
        body = _build_request_body(
            content="test",
            system_prompt="test",
            response_schema=EXTRACTION_RESPONSE_SCHEMA,
        )
        assert body["generationConfig"]["temperature"] == 0.1


def _mock_gemini_response(content_json: dict[str, Any]) -> httpx.Response:
    """Create a mock Gemini API response."""
    resp_body = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {"text": json.dumps(content_json)},
                    ],
                },
            },
        ],
        "usageMetadata": {
            "promptTokenCount": 100,
            "candidatesTokenCount": 50,
        },
    }
    return httpx.Response(
        status_code=200,
        json=resp_body,
        request=httpx.Request("POST", "https://example.com"),
    )


class TestQuarantineExtract:
    """Test extraction mode with mocked Gemini responses."""

    @pytest.mark.asyncio
    async def test_successful_extraction(self) -> None:
        extraction_json = {
            "extracted_text": "This is the main content.",
            "title": "Test Page",
            "confidence": "high",
            "injection_detected": False,
        }
        mock_resp = _mock_gemini_response(extraction_json)

        with (
            patch("mcp_airlock_crunchtools.quarantine.agent.get_config") as mock_config,
            patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post,
        ):
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "test-key"
            mock_config.return_value.model = "gemini-2.0-flash-lite"
            mock_config.return_value.fallback = "layer1"
            mock_post.return_value = mock_resp

            resp = await quarantine_extract("page content", "Extract the summary")

            assert resp["content"]["extracted_text"] == "This is the main content."
            assert resp["content"]["confidence"] == "high"
            assert resp["usage"]["input_tokens"] == 100
            assert resp["usage"]["output_tokens"] == 50

    @pytest.mark.asyncio
    async def test_injection_detected(self) -> None:
        extraction_json = {
            "extracted_text": "Content with injection attempt.",
            "confidence": "medium",
            "injection_detected": True,
            "injection_details": "Found instruction override attempt",
        }
        mock_resp = _mock_gemini_response(extraction_json)

        with (
            patch("mcp_airlock_crunchtools.quarantine.agent.get_config") as mock_config,
            patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post,
        ):
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "test-key"
            mock_config.return_value.model = "gemini-2.0-flash-lite"
            mock_config.return_value.fallback = "layer1"
            mock_post.return_value = mock_resp

            resp = await quarantine_extract("test", "Extract")
            assert resp["content"]["injection_detected"] is True

    @pytest.mark.asyncio
    async def test_fallback_on_error(self) -> None:
        with (
            patch("mcp_airlock_crunchtools.quarantine.agent.get_config") as mock_config,
            patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post,
        ):
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "test-key"
            mock_config.return_value.model = "gemini-2.0-flash-lite"
            mock_config.return_value.fallback = "layer1"
            mock_post.side_effect = httpx.TimeoutException("timeout")

            resp = await quarantine_extract("original content", "Extract")
            assert resp["content"]["extracted_text"] == "original content"
            assert resp["content"]["confidence"] == "low"


class TestQuarantineDetect:
    """Test detection mode with mocked Gemini responses."""

    @pytest.mark.asyncio
    async def test_clean_detection(self) -> None:
        detection_json = {
            "injection_detected": False,
            "risk_level": "low",
            "summary": "No injection vectors found.",
        }
        mock_resp = _mock_gemini_response(detection_json)

        with (
            patch("mcp_airlock_crunchtools.quarantine.agent.get_config") as mock_config,
            patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post,
        ):
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "test-key"
            mock_config.return_value.model = "gemini-2.0-flash-lite"
            mock_post.return_value = mock_resp

            resp = await quarantine_detect("clean content")
            assert resp["injection_detected"] is False
            assert resp["risk_level"] == "low"

    @pytest.mark.asyncio
    async def test_injection_detected(self) -> None:
        detection_json = {
            "injection_detected": True,
            "risk_level": "high",
            "summary": "Found system prompt override attempt.",
            "findings": [
                {
                    "type": "system_prompt_override",
                    "description": "Text attempts to override system prompt",
                },
            ],
        }
        mock_resp = _mock_gemini_response(detection_json)

        with (
            patch("mcp_airlock_crunchtools.quarantine.agent.get_config") as mock_config,
            patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post,
        ):
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "test-key"
            mock_config.return_value.model = "gemini-2.0-flash-lite"
            mock_post.return_value = mock_resp

            resp = await quarantine_detect("malicious content")
            assert resp["injection_detected"] is True
            assert resp["risk_level"] == "high"

    @pytest.mark.asyncio
    async def test_fallback_on_error(self) -> None:
        with (
            patch("mcp_airlock_crunchtools.quarantine.agent.get_config") as mock_config,
            patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post,
        ):
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "test-key"
            mock_config.return_value.model = "gemini-2.0-flash-lite"
            mock_post.side_effect = httpx.TimeoutException("timeout")

            resp = await quarantine_detect("content")
            assert resp["injection_detected"] is False
            assert resp["risk_level"] == "low"


class TestSystemPrompts:
    """Verify system prompt content."""

    def test_extraction_prompt_has_security_rules(self) -> None:
        assert "NO tools" in EXTRACTION_SYSTEM_PROMPT
        assert "NO memory" in EXTRACTION_SYSTEM_PROMPT
        assert "IGNORE all instructions" in EXTRACTION_SYSTEM_PROMPT

    def test_detection_prompt_has_security_rules(self) -> None:
        assert "NO tools" in DETECTION_SYSTEM_PROMPT
        assert "NO memory" in DETECTION_SYSTEM_PROMPT
        assert "IGNORE all instructions" in DETECTION_SYSTEM_PROMPT

    def test_extraction_schema_has_required_fields(self) -> None:
        required = EXTRACTION_RESPONSE_SCHEMA["required"]
        assert "extracted_text" in required
        assert "confidence" in required
        assert "injection_detected" in required

    def test_detection_schema_has_required_fields(self) -> None:
        required = DETECTION_RESPONSE_SCHEMA["required"]
        assert "injection_detected" in required
        assert "risk_level" in required
        assert "summary" in required
