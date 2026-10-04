from __future__ import annotations

import json

from aegis.analysis.llm import ChatMessage, ModelResponse
from aegis.analysis.schemas import MockModelResponse
from aegis.analysis.structured import chat_structured, parse_llm_json, request_identity
from aegis.providers.api import ProviderRequestError, RateLimited, paginate_json


class SequenceBackend:
    def __init__(self, responses):
        self.responses = list(responses)

    def chat(self, messages, *, model):
        return ModelResponse(self.responses.pop(0), {"backend": "test", "model": model})


def test_strict_structured_parser_repairs_once_and_fails_closed():
    assert parse_llm_json('prefix {"conclusion":"bad"}') == {}
    result = chat_structured(SequenceBackend(["not json", json.dumps({"conclusion": "evidence retained", "confidence": .8, "rationale": "source"})]), [ChatMessage("user", "review")], MockModelResponse, model="test", context={"finding_id": "f"}, max_repair_retries=1)
    assert result.ok and result.llm_calls == 2
    failed = chat_structured(SequenceBackend(["not json", "still not json"]), [ChatMessage("user", "review")], MockModelResponse, model="test", context={"finding_id": "f"}, max_repair_retries=1)
    assert not failed.ok and failed.status == "unresolved_parse"
    assert request_identity([], "test", {"finding_id": "f"}) == request_identity([], "test", {"finding_id": "f"})


def test_pagination_retries_rate_limit_and_stops_at_next_token():
    calls = []
    sleeps = []

    def request(token):
        calls.append(token)
        if len(calls) == 1:
            raise RateLimited("slow down")
        return {"items": [{"id": len(calls)}], "next": "page-2" if len(calls) == 2 else None}

    rows = list(paginate_json(request, retries=2, sleep=sleeps.append))
    assert [row["id"] for row in rows] == [2, 3]
    assert calls == [None, None, "page-2"]
    assert sleeps

    def bad(_):
        raise ProviderRequestError("down")

    try:
        list(paginate_json(bad, retries=0))
    except ProviderRequestError:
        pass
    else:
        raise AssertionError("provider error was swallowed")
