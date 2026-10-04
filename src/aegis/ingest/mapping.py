"""Safe selector mapping adapted from Trident's token-by-token mapper.

Selectors are data, never Python expressions.  The domain fields are Aegis's
canonical fields, while the safety and provenance mechanics are retained.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from aegis.ingest.contracts import MAPPING_VERSION, MappingValidation, mapping_sha256
from aegis.provenance import join_pointer

_MAX_SELECTOR_LENGTH = 512
_MAX_SELECTOR_TOKENS = 64
_KNOWN_FIELDS = {"source_record_id", "title", "description", "severity", "cve", "cwe", "cvss_score", "cvss_vector", "exploit_available", "exploited_in_wild", "epss", "vendor_risk_score", "asset_id", "hostname", "ip", "package", "installed_version", "fixed_version", "status", "solution", "internet_exposed", "business_criticality", "tags"}
_IDENTIFIER_RE = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[0-9A-Za-z-]+|OSV-[0-9A-Za-z-]+|CWE[-_: ]?\d+)\b", re.I)


class MappingError(ValueError):
    pass


@dataclass(frozen=True)
class Selection:
    value: Any
    pointer: str


def _parse_selector(selector: str) -> list[str | int]:
    if not isinstance(selector, str) or not selector or len(selector) > _MAX_SELECTOR_LENGTH or not selector.startswith("$"):
        raise MappingError("selector must be a non-empty bounded string starting with '$'")
    tokens: list[str | int] = []
    index = 1
    while index < len(selector):
        if selector[index] == ".":
            end = index + 1
            while end < len(selector) and selector[end] not in ".[]":
                end += 1
            key = selector[index + 1:end]
            if not key or key in {"*", ".."} or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_:-]*", key):
                raise MappingError(f"invalid object selector: {selector!r}")
            tokens.append(key)
            index = end
            continue
        if selector[index] != "[":
            raise MappingError(f"invalid selector syntax: {selector!r}")
        end = selector.find("]", index + 1)
        if end < 0:
            raise MappingError(f"unterminated selector token: {selector!r}")
        token = selector[index + 1:end]
        if token == "*":
            tokens.append("*")
        elif token.isdigit():
            tokens.append(int(token))
        elif len(token) >= 2 and token[0] == token[-1] == '"' and "\n" not in token and "\r" not in token:
            tokens.append(token[1:-1])
        else:
            raise MappingError(f"only numeric, wildcard, or quoted indexes are allowed: {selector!r}")
        index = end + 1
    if len(tokens) > _MAX_SELECTOR_TOKENS:
        raise MappingError("selector is too deeply nested")
    return tokens


def select(payload: Any, selector: str, *, base_pointer: str = "") -> list[Selection]:
    nodes = [Selection(payload, base_pointer)]
    for token in _parse_selector(selector):
        next_nodes: list[Selection] = []
        for node in nodes:
            value = node.value
            if token == "*" and isinstance(value, list):
                next_nodes.extend(Selection(item, join_pointer(node.pointer, idx)) for idx, item in enumerate(value))
            elif isinstance(token, int) and isinstance(value, list) and token < len(value):
                next_nodes.append(Selection(value[token], join_pointer(node.pointer, token)))
            elif isinstance(token, str) and isinstance(value, dict) and token in value:
                next_nodes.append(Selection(value[token], join_pointer(node.pointer, token)))
        nodes = next_nodes
        if not nodes:
            break
    return nodes


def validate_mapping(mapping: Any) -> dict[str, Any]:
    if not isinstance(mapping, dict):
        raise MappingError("mapping must be a JSON object")
    allowed = {"mapping_version", "name", "records", "fields"}
    unknown = set(mapping) - allowed
    if unknown or mapping.get("mapping_version") != MAPPING_VERSION:
        raise MappingError(f"invalid mapping keys/version: {sorted(unknown)}")
    if not isinstance(mapping.get("name"), str) or not mapping["name"].strip() or len(mapping["name"]) > 256:
        raise MappingError("mapping name must be bounded and non-empty")
    if not isinstance(mapping.get("records"), str):
        raise MappingError("mapping records must be a selector string")
    _parse_selector(mapping["records"])
    fields = mapping.get("fields")
    if not isinstance(fields, dict) or not fields:
        raise MappingError("mapping fields must be a non-empty object")
    unknown_fields = set(fields) - _KNOWN_FIELDS
    if unknown_fields:
        raise MappingError(f"unsupported mapping fields: {sorted(unknown_fields)}")
    for field, selector in fields.items():
        if not isinstance(selector, str):
            raise MappingError(f"mapping field {field!r} must be a selector string")
        _parse_selector(selector)
    return mapping


def validate_mapping_against_records(mapping: dict[str, Any], records: list[dict[str, Any]]) -> MappingValidation:
    validate_mapping(mapping)
    coverage = {field: 0 for field in mapping["fields"]}
    identifier_count = 0
    errors: list[str] = []
    inspected = len(records)
    for record in records:
        if not isinstance(record, dict):
            errors.append("non-object record encountered")
            continue
        for field, selector in mapping["fields"].items():
            if select(record, selector):
                coverage[field] += 1
        if any(_IDENTIFIER_RE.search(str(value)) for value in record.values()):
            identifier_count += 1
    ratios = {field: (count / inspected if inspected else 0.0) for field, count in coverage.items()}
    required = [ratios.get(field, 0.0) for field in ("title", "severity", "cve", "asset_id") if field in ratios]
    required_coverage = sum(required) / len(required) if required else 0.0
    confidence = max(0.0, min(1.0, 0.45 * required_coverage + 0.35 * (sum(ratios.values()) / len(ratios) if ratios else 0) + 0.2 * (identifier_count / inspected if inspected else 0)))
    return MappingValidation(inspected, ratios, required_coverage, 1.0, identifier_count / inspected if inspected else 0.0, confidence, tuple(errors))


def apply_mapping(payload: Any, mapping: dict[str, Any], *, base_pointer: str = "") -> list[dict[str, Any]]:
    validate_mapping(mapping)
    selected_records = [item.value for item in select(payload, mapping["records"], base_pointer=base_pointer) if isinstance(item.value, dict)]
    validation = validate_mapping_against_records(mapping, selected_records)
    rows: list[dict[str, Any]] = []
    for selected in select(payload, mapping["records"], base_pointer=base_pointer):
        if not isinstance(selected.value, dict):
            continue
        row = {"_mapping_sha256": mapping_sha256(mapping), "_record_pointer": selected.pointer}
        for field, selector in mapping["fields"].items():
            value = select(selected.value, selector, base_pointer=selected.pointer)
            if value:
                row[field] = value[0].value
                row[f"_{field}_pointer"] = value[0].pointer
        row["_mapping_validation"] = validation.as_dict()
        rows.append(row)
    return rows
