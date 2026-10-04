"""Typed, fail-closed model calls adapted from Trident reliability/structured.py.

The transport is injected through Aegis's model protocol. Aegis writes no
database ledger in v0.1.0; decisions can be recorded as JSONL and replayed,
which preserves the algorithm while keeping million-record runs streamable.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from aegis.analysis.llm import ChatMessage, ModelBackend, ModelResponse

T = TypeVar("T", bound=BaseModel)
PROMPT_VERSION = "aegis-typed-v1"


def parse_llm_json(content: str) -> dict[str, Any]:
    """Accept exactly one object or a JSON fenced object, never prose fragments."""
    text = (content or "").strip()
    if text.startswith("```") and text.endswith("```"):
        lines = text.splitlines()
        if len(lines) < 3 or lines[-1].strip() != "```":
            return {}
        if lines[0].strip()[3:].strip().lower() not in {"", "json"}:
            return {}
        text = "\n".join(lines[1:-1]).strip()
    try:
        value = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def parse_validated(content: str, model: type[T]) -> tuple[T | None, str | None]:
    data = parse_llm_json(content)
    if not data:
        return None, "no JSON object found in response"
    try:
        return model.model_validate(data), None
    except Exception as exc:
        return None, str(exc)


@dataclass
class StructuredResult(Generic[T]):
    obj: T | None
    response: ModelResponse
    error: str | None = None
    llm_calls: int = 0
    status: str = "completed"
    validation_errors: list[str] = field(default_factory=list)
    semantic_errors: list[str] = field(default_factory=list)
    request_id: str | None = None
    replay_source: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == "completed" and self.obj is not None


def _contract(messages: list[ChatMessage], model_cls: type[BaseModel]) -> list[ChatMessage]:
    schema = json.dumps(model_cls.model_json_schema(), sort_keys=True, separators=(",", ":"))
    instruction = ("Return exactly one JSON object with no prose or markdown. "
                   "It must validate against this schema and must use only supplied evidence. "
                   "If evidence is insufficient, express uncertainty. SCHEMA=" + schema)
    return [*messages, ChatMessage("user", instruction)]


def _semantic_validate(obj: BaseModel) -> list[str]:
    data = obj.model_dump()
    errors: list[str] = []
    confidence = data.get("confidence")
    if confidence is not None:
        try:
            if not 0 <= float(confidence) <= 1:
                errors.append("confidence must be between 0 and 1")
        except (TypeError, ValueError):
            errors.append("confidence is not numeric")
    rationale = any(str(data.get(key) or "").strip() for key in ("rationale", "reasoning", "conclusion"))
    if not rationale:
        errors.append("structured observation requires a rationale or conclusion")
    return errors


def request_identity(messages: list[ChatMessage], model: str, context: dict[str, Any]) -> str:
    canonical = {"run_id": context.get("run_id"), "finding_id": context.get("finding_id"),
                 "task_type": context.get("task_type", "structured"), "role": context.get("role"),
                 "iteration": context.get("iteration", 0), "model": model,
                 "messages": [{"role": item.role, "content": item.content} for item in messages]}
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _load_replay(path: str | Path) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("format") != "aegis-llm-decision-replay":
        raise ValueError("unsupported Aegis replay artifact")
    return payload.get("decisions") or []


def replay_decision(model_cls: type[T], *, request_id: str, decisions: list[dict[str, Any]]) -> StructuredResult[T]:
    match = next((item for item in decisions if item.get("request_id") == request_id), None)
    response = ModelResponse("", {"replay": True})
    if not match:
        return StructuredResult(None, response, "no matching decision in replay artifact", status="unresolved_replay_missing", replay_source="parsed")
    data = match.get("accepted_decision")
    try:
        obj = model_cls.model_validate(data)
        semantic = _semantic_validate(obj)
        return StructuredResult(obj, ModelResponse(json.dumps(data), {"replay": True}),
                                "; ".join(semantic) if semantic else None,
                                status="unresolved_semantic" if semantic else "completed",
                                semantic_errors=semantic, replay_source="parsed")
    except Exception as exc:
        return StructuredResult(None, response, str(exc), status="unresolved_parse", replay_source="parsed")


def chat_structured(backend: ModelBackend, messages: list[ChatMessage], model_cls: type[T], *, model: str,
                    context: dict[str, Any] | None = None, max_repair_retries: int = 1,
                    replay_path: str | Path | None = None,
                    call_permit: Any | None = None) -> StructuredResult[T]:
    context = dict(context or {})
    prepared = _contract(messages, model_cls)
    request_id = request_identity(prepared, model, context)
    if replay_path:
        return replay_decision(model_cls, request_id=request_id, decisions=_load_replay(replay_path))
    attempts = 0
    validation_errors: list[str] = []
    semantic_errors: list[str] = []
    current = prepared
    response = ModelResponse("", {})
    last_error = "model did not return a valid structured object"
    while attempts <= max(0, max_repair_retries):
        if call_permit is not None and not call_permit():
            return StructuredResult(None, response, "model-call budget exhausted", llm_calls=attempts,
                                    status="unresolved_budget", validation_errors=validation_errors,
                                    request_id=request_id)
        attempts += 1
        response = backend.chat(current, model=model)
        obj, error = parse_validated(response.content, model_cls)
        if obj is not None:
            semantic_errors = _semantic_validate(obj)
            if not semantic_errors:
                return StructuredResult(obj, response, llm_calls=attempts, validation_errors=validation_errors, request_id=request_id)
            last_error = "; ".join(semantic_errors)
        else:
            last_error = error or last_error
            validation_errors.append(last_error)
        if attempts <= max(0, max_repair_retries):
            current = [*prepared, ChatMessage("assistant", response.content[:4000]), ChatMessage("user", f"Validation failed: {last_error}. Return only the schema-valid JSON object.")]
    return StructuredResult(None, response, last_error, llm_calls=attempts,
                            status="unresolved_semantic" if semantic_errors else "unresolved_parse",
                            validation_errors=validation_errors, semantic_errors=semantic_errors, request_id=request_id)


def decision_record(result: StructuredResult[Any], *, context: dict[str, Any], model: str) -> dict[str, Any]:
    return {"format": PROMPT_VERSION, "request_id": result.request_id, "finding_id": context.get("finding_id"),
            "task_type": context.get("task_type", "structured"), "role": context.get("role"), "model": model,
            "status": result.status, "attempts": result.llm_calls,
            "accepted_decision": result.obj.model_dump(mode="json") if result.obj else None,
            "validation_errors": result.validation_errors, "semantic_errors": result.semantic_errors}
