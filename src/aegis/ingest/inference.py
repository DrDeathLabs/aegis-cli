"""Bounded, deterministic schema inference adapted from Trident ingestion inference."""

from __future__ import annotations

import re
from typing import Any

from aegis.ingest.contracts import MAPPING_VERSION, MappingValidation
from aegis.ingest.mapping import validate_mapping_against_records


def _selector(path: str) -> str:
    parts = [part for part in path.split(".") if part]
    result = "$"
    for part in parts:
        result += f".{part}" if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", part) else f'[{json_key(part)}]'
    return result


def json_key(value: str) -> str:
    return '"' + value.replace('"', '\\"') + '"'


def infer_mapping(records: list[dict[str, Any]], paths: dict[str, str], *, name: str = "inferred") -> tuple[dict[str, Any], MappingValidation]:
    fields = {field: _selector(path) for field, path in paths.items() if field in {
        "source_record_id", "title", "description", "severity", "cve", "cwe", "cvss_score", "cvss_vector",
        "exploit_available", "exploited_in_wild", "epss", "vendor_risk_score", "asset_id", "hostname", "ip",
        "package", "installed_version", "fixed_version", "status", "solution", "internet_exposed",
        "business_criticality", "tags",
    }}
    if not fields:
        fields = {"title": "$.title"}
    mapping = {"mapping_version": MAPPING_VERSION, "name": name, "records": "$", "fields": fields}
    return mapping, validate_mapping_against_records(mapping, records)
