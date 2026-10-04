"""Optional model abstraction.

The default Aegis path is offline and deterministic.  A mock backend exists for
contract tests.  An external provider may be added behind this interface later;
no network call occurs unless an explicit backend is supplied by the caller.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

from aegis.analysis.schemas import MockModelResponse


@dataclass(frozen=True)
class ChatMessage:
    role: str
    content: str


@dataclass(frozen=True)
class ModelResponse:
    content: str
    metadata: dict[str, Any]


class ModelBackend(Protocol):
    def chat(self, messages: list[ChatMessage], *, model: str) -> ModelResponse: ...


class MockModelBackend:
    """Deterministic mock for tests and local fixture runs."""

    def __init__(self, response: dict[str, Any] | None = None):
        self.response = response or {"conclusion": "evidence recorded", "confidence": 0.8, "rationale": "mock"}

    def chat(self, messages: list[ChatMessage], *, model: str) -> ModelResponse:
        result = MockModelResponse.model_validate(self.response)
        return ModelResponse(result.model_dump_json(), {"backend": "mock", "model_requested": model, "model_actual": "mock"})


def parse_model_json(response: ModelResponse) -> MockModelResponse:
    """Fail closed on non-object/non-schema output."""
    try:
        payload = json.loads(response.content)
        return MockModelResponse.model_validate(payload)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ValueError(f"model response failed Aegis schema validation: {exc}") from exc
