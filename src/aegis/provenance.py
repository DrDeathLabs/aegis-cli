"""Bounded source pointers and lossless import provenance.

The JSON-pointer and accounting ideas are intentionally small, deterministic
utilities adapted from the Trident reference audit.  They are independently
maintained here and extended with CSV row/column locations.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def pointer_escape(value: str | int) -> str:
    return str(value).replace("~", "~0").replace("/", "~1")


def join_pointer(base: str, token: str | int) -> str:
    return f"{base}/{pointer_escape(token)}" if base else f"/{pointer_escape(token)}"


def pointer_get(payload: Any, pointer: str) -> Any:
    if pointer == "":
        return payload
    if not pointer.startswith("/"):
        raise ValueError(f"invalid JSON pointer: {pointer!r}")
    value = payload
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(value, list):
            value = value[int(token)]
        elif isinstance(value, dict):
            value = value[token]
        else:
            raise KeyError(pointer)
    return value


def field_provenance(pointer: str, original: Any, *, source_kind: str = "json") -> dict[str, Any]:
    return {"pointer": pointer, "original": original, "source_kind": source_kind}


def report_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def provenance_envelope(*, report_sha256_value: str, record_pointer: str,
                        mapping_identity: str, fields: dict[str, Any],
                        source_format: str, import_run: str | None = None) -> dict[str, Any]:
    return {
        "report_sha256": report_sha256_value,
        "record_pointer": record_pointer,
        "mapping_identity": mapping_identity,
        "source_format": source_format,
        "import_run": import_run,
        "fields": fields,
    }


def csv_provenance(row: int, column: str, original: Any) -> dict[str, Any]:
    return field_provenance(f"/rows/{row}/columns/{pointer_escape(column)}", original, source_kind="csv")


def mapping_hash(mapping: dict[str, Any]) -> str:
    encoded = json.dumps(mapping, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
