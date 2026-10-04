"""Local structured event sink adapted from Trident's event publisher/bus."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any

from aegis.storage import utc_now


_SENSITIVE = {"token", "access_token", "api_key", "apikey", "password", "secret", "authorization", "client_secret"}


def _safe_payload(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): "[REDACTED]" if str(key).lower().replace("-", "_") in _SENSITIVE or any(part in str(key).lower() for part in ("token", "password", "secret")) else _safe_payload(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_safe_payload(item) for item in value]
    return value


@dataclass
class EventSink:
    path: Path
    sequence: int = 0
    _lock: Lock = field(default_factory=Lock, repr=False)

    def __post_init__(self) -> None:
        if not self.path.exists():
            return
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
            if lines:
                self.sequence = int(json.loads(lines[-1]).get("sequence", 0))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            self.sequence = 0

    def emit(self, event_type: str, *, run_id: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            self.sequence += 1
            event = {"sequence": self.sequence, "event_type": event_type, "run_id": run_id, "at": utc_now(), "payload": _safe_payload(payload or {})}
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":"), default=str) + "\n")
            return event
