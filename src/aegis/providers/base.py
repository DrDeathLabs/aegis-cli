"""Provider adapter base class and safe file readers."""

from __future__ import annotations

import csv
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterator

from aegis.config import settings
from aegis.models import json_safe, normalize_text
from aegis.providers.common import ALIASES, extract_identifiers, get_indexed_value, has_target_identity, index_fields, make_finding

_SETTINGS = settings()
MAX_INPUT_BYTES = _SETTINGS.max_input_bytes
MAX_WHOLE_DOCUMENT_BYTES = min(_SETTINGS.max_input_bytes, _SETTINGS.max_whole_document_bytes)
MAX_JSON_DEPTH = _SETTINGS.max_json_depth
MAX_JSON_NODES = _SETTINGS.max_json_nodes
MAX_RECORD_BYTES = _SETTINGS.max_record_bytes


def _check_size(path: Path) -> None:
    size = path.stat().st_size
    if size > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds safety limit of {MAX_INPUT_BYTES} bytes: {path}")


def _check_whole_document_size(path: Path) -> None:
    size = path.stat().st_size
    if size > MAX_WHOLE_DOCUMENT_BYTES:
        raise ValueError(
            f"whole-document parsing is limited to {MAX_WHOLE_DOCUMENT_BYTES} bytes: "
            f"use JSONL or a streaming provider export for {path}"
        )


def _validate_json(value: Any, depth: int = 0, nodes: list[int] | None = None) -> None:
    nodes = nodes if nodes is not None else [0]
    if depth > MAX_JSON_DEPTH:
        raise ValueError(f"JSON nesting exceeds {MAX_JSON_DEPTH} levels")
    nodes[0] += 1
    if nodes[0] > MAX_JSON_NODES:
        raise ValueError(f"JSON exceeds {MAX_JSON_NODES} structural nodes")
    if isinstance(value, dict):
        for child in value.values():
            _validate_json(child, depth + 1, nodes)
    elif isinstance(value, list):
        for child in value:
            _validate_json(child, depth + 1, nodes)


_SEMANTIC_COLLECTIONS = {"findings", "vulnerabilities", "detections", "results", "issues", "records", "resources", "items", "value", "rows"}
_KNOWN_COLLECTION_WRAPPERS = {"response", "result", "results", "data", "payload", "body", "collection", "export", "page", "pages"}


def _candidate_collections(payload: Any, base: str = "", selectors: tuple[str, ...] | None = None) -> list[tuple[str, list[Any]]]:
    """Return explicit semantic collections without walking opaque metadata.

    A generic document is not a license to recursively promote every list of
    dictionaries.  Root collections and collections below documented envelope
    wrappers are eligible; arbitrary nested metadata remains part of the
    enclosing source record.  Callers with an unknown but intentional schema
    can pass RFC-6901 selectors explicitly.
    """
    if isinstance(payload, list):
        return [(base + "[*]" if base else "$[*]", payload)]
    if not isinstance(payload, dict):
        return []
    found: list[tuple[str, list[Any]]] = []
    selectors = tuple(selectors or ())

    def selected_or_ancestor(path: str) -> bool:
        """Whether an explicit selector names this path or a child path."""
        return any(selector == path or selector.startswith(path.rstrip("/") + "/") for selector in selectors)

    for key in sorted(payload, key=lambda item: str(item).lower()):
        value = payload[key]
        path = f"{base}/{key}" if base else f"/{key}"
        key_name = str(key).lower()
        parent_name = base.rsplit("/", 1)[-1].lower() if base else ""
        explicit = path in selectors
        explicit_path = selected_or_ancestor(path)
        # Automatic discovery may recurse only through documented envelope
        # wrappers.  An explicit selector is the operator's contract and may
        # intentionally traverse an otherwise opaque ancestor such as
        # ``metadata/data/items``.
        collection_eligible = not base or parent_name in _KNOWN_COLLECTION_WRAPPERS
        if isinstance(value, list) and value and (explicit or (collection_eligible and key_name in _SEMANTIC_COLLECTIONS)):
            found.append((path + "[*]", value))
        elif isinstance(value, dict) and (explicit_path or key_name in _KNOWN_COLLECTION_WRAPPERS):
            found.extend(_candidate_collections(value, path, selectors))
    return found


def _candidate_collection(payload: Any) -> tuple[str, list[Any]]:
    """Compatibility helper returning all collections as one deterministic set."""
    candidates = _candidate_collections(payload)
    if candidates:
        records: list[Any] = []
        for _, values in candidates:
            records.extend(values)
        return "$[*]", records
    return "$", [payload]


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    duplicates: list[str] = []
    for key, value in pairs:
        if key in result:
            duplicates.append(key)
        result[key] = value
    if duplicates:
        result["_aegis_duplicate_keys"] = sorted(set(duplicates))
        result["_aegis_original_pairs"] = [[key, json_safe(value)] for key, value in pairs]
    return result


def _iter_top_level_json_array(path: Path) -> Iterator[tuple[dict[str, Any], str]]:
    decoder = json.JSONDecoder(object_pairs_hook=_object_pairs)
    with path.open(encoding="utf-8") as handle:
        buffer = ""
        eof = False
        index = 0

        def fill() -> bool:
            nonlocal buffer, eof
            if eof:
                return False
            chunk = handle.read(1024 * 1024)
            if chunk:
                buffer += chunk
                return True
            eof = True
            return False

        fill()
        while True:
            while buffer and buffer[0].isspace():
                buffer = buffer[1:]
            if not buffer and not fill():
                raise ValueError(f"JSON array ended before a closing bracket: {path}")
            if not buffer:
                continue
            if buffer[0] != "[":
                raise ValueError(f"streaming JSON requires a top-level array: {path}")
            buffer = buffer[1:]
            break

        while True:
            while buffer and buffer[0].isspace():
                buffer = buffer[1:]
            if not buffer and not fill():
                raise ValueError(f"JSON array ended before a closing bracket: {path}")
            if buffer[0] == "]":
                return
            try:
                value, consumed = decoder.raw_decode(buffer)
            except json.JSONDecodeError:
                if fill():
                    continue
                raise ValueError(f"invalid JSON array record near index {index}: {path}")
            buffer = buffer[consumed:]
            _validate_json(value)
            pointer = f"/$/{index}"
            index += 1
            if isinstance(value, dict):
                yield value, pointer
            else:
                yield {"_malformed": json_safe(value)}, pointer
            while buffer and buffer[0].isspace():
                buffer = buffer[1:]
            if not buffer and not fill():
                raise ValueError(f"JSON array ended before a closing bracket: {path}")
            if buffer[0] == ",":
                buffer = buffer[1:]
                continue
            if buffer[0] == "]":
                return
            raise ValueError(f"expected ',' or ']' after JSON array record {index - 1}: {path}")


def iter_json_records(path: Path, *, selectors: tuple[str, ...] | None = None) -> Iterator[tuple[dict[str, Any], str]]:
    _check_size(path)
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        with path.open(encoding="utf-8") as handle:
            for number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                if len(line.encode("utf-8")) > MAX_RECORD_BYTES:
                    yield {"_malformed": line[:256].rstrip("\r\n"), "_parse_error": f"record exceeds {MAX_RECORD_BYTES} bytes", "_line": number}, f"/lines/{number}"
                    continue
                try:
                    value = json.loads(line, object_pairs_hook=_object_pairs)
                except json.JSONDecodeError as exc:
                    yield {"_malformed": line.rstrip("\r\n"), "_parse_error": str(exc), "_line": number}, f"/lines/{number}"
                    continue
                _validate_json(value)
                if not isinstance(value, dict):
                    # Keep scalar JSONL rows lossless; normalization records
                    # them as quarantined rather than losing them at parsing.
                    yield {"_malformed": json_safe(value)}, f"/lines/{number}"
                    continue
                yield value, f"/lines/{number}"
        return
    if path.stat().st_size:
        with path.open(encoding="utf-8") as handle:
            starts_array = handle.read(4096).lstrip().startswith("[")
        if starts_array:
            yield from _iter_top_level_json_array(path)
            return
    _check_whole_document_size(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read JSON input {path}: {exc}") from exc
    _validate_json(payload)
    candidates = _candidate_collections(payload, selectors=selectors)
    if not candidates:
        value = payload
        yield value if isinstance(value, dict) else {"_malformed": json_safe(value)}, ""
        return
    for pointer, records in candidates:
        for index, record in enumerate(records):
            record_pointer = pointer.replace("[*]", f"/{index}")
            if isinstance(record, dict):
                yield record, record_pointer
            else:
                yield {"_malformed": json_safe(record)}, record_pointer


def iter_csv_records(path: Path) -> Iterator[tuple[dict[str, Any], str]]:
    _check_size(path)
    delimiter = "\t" if path.suffix.lower() == ".tsv" else ","
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle, delimiter=delimiter)
        header = next(reader, [])
        if not header:
            raise ValueError(f"CSV has no header: {path}")
        seen: set[str] = set()
        duplicate_headers: list[str] = []
        for value in header:
            if value in seen:
                duplicate_headers.append(value)
            seen.add(value)
        for number, row in enumerate(reader, 2):
            pairs = list(zip(header, row))
            record = {str(k): v for k, v in pairs[:len(header)]}
            if duplicate_headers:
                record["_aegis_duplicate_headers"] = sorted(set(duplicate_headers))
                record["_aegis_csv_pairs"] = [[str(k), v] for k, v in pairs]
            if len(row) > len(header):
                # DictReader stores values beyond the declared header under
                # None. Preserve them explicitly instead of silently
                # discarding source data.
                record["_aegis_csv_extra_columns"] = list(row[len(header):])
            yield record, f"/rows/{number}"


def normalize_xml_leaf_scalars(value: Any) -> Any:
    """Unwrap XML's single ``#text`` leaf representation before mapping.

    XML elements that contain only text are scalar source fields, not nested
    objects.  Attribute-bearing elements remain dictionaries so their source
    attributes are preserved alongside ``#text``.
    """
    if isinstance(value, list):
        return [normalize_xml_leaf_scalars(item) for item in value]
    if not isinstance(value, dict):
        return value
    normalized = {str(key): normalize_xml_leaf_scalars(child) for key, child in value.items()}
    if set(normalized) == {"#text"}:
        return normalized["#text"]
    return normalized


def _xml_dict(element: ET.Element) -> Any:
    value: dict[str, Any] = {f"@{key}": val for key, val in element.attrib.items()}
    text = (element.text or "").strip()
    children = list(element)
    if not children and not value:
        return text or None
    if text:
        value["#text"] = text
    for child in children:
        child_value = _xml_dict(child)
        if child.tag in value:
            if not isinstance(value[child.tag], list):
                value[child.tag] = [value[child.tag]]
            value[child.tag].append(child_value)
        else:
            value[child.tag] = child_value
    return normalize_xml_leaf_scalars(value)


def parse_xml_root(path: Path) -> ET.Element:
    _check_whole_document_size(path)
    raw = path.read_text(encoding="utf-8", errors="replace")
    if re.search(r"<!\s*ENTITY\b", raw, re.I):
        raise ValueError(f"unsafe XML declaration rejected (DOCTYPE/ENTITY): {path}")
    # Qualys documents an external DOCTYPE.  ElementTree does not resolve
    # external resources, and removing the declaration before parsing also
    # prevents network/entity expansion while retaining the source record.
    raw = re.sub(r"<!\s*DOCTYPE\b[^>]*(?:\[[\s\S]*?\]\s*)?>", "", raw, flags=re.I)
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError(f"could not parse XML input {path}: {exc}") from exc
    nodes = 0
    stack: list[tuple[ET.Element, int]] = [(root, 0)]
    while stack:
        element, depth = stack.pop()
        nodes += 1
        if depth > MAX_JSON_DEPTH:
            raise ValueError(f"XML nesting exceeds {MAX_JSON_DEPTH} levels: {path}")
        if nodes > MAX_JSON_NODES:
            raise ValueError(f"XML exceeds {MAX_JSON_NODES} structural nodes: {path}")
        stack.extend((child, depth + 1) for child in reversed(list(element)))
    return root


def iter_xml_records(path: Path, *, tags: tuple[str, ...] = ()) -> Iterator[tuple[dict[str, Any], str]]:
    root = parse_xml_root(path)
    wanted = {tag.lower() for tag in tags}
    found = 0
    for element in root.iter():
        local = element.tag.rsplit("}", 1)[-1].lower() if isinstance(element.tag, str) else ""
        if wanted and local not in wanted:
            continue
        if not wanted and not element.attrib:
            continue
        record_value = _xml_dict(element)
        record = record_value if isinstance(record_value, dict) else ({"#text": record_value} if record_value is not None else {})
        record["_xml_tag"] = local
        found += 1
        yield record, f"/xml/{local}/{found - 1}"
    if found == 0:
        yield _xml_dict(root), "/xml/root"


class ProviderAdapter:
    name = "generic"
    aliases: dict[str, tuple[str, ...]] = {}
    native_fields: tuple[str, ...] = ()
    mapping_version = "aegis-provider-mapping-v1"
    supported_variants: tuple[str, ...] = ("generic",)
    contract_version = "aegis-provider-contract-v1"
    severity_scale: str | None = None

    def records(self, path: Path, *, selectors: tuple[str, ...] | None = None) -> Iterator[tuple[dict[str, Any], str]]:
        suffix = path.suffix.lower()
        if suffix in {".csv", ".tsv"}:
            yield from iter_csv_records(path)
        elif suffix in {".xml", ".nessus"}:
            yield from iter_xml_records(path)
        else:
            yield from iter_json_records(path, selectors=selectors)

    def output_record(self, record: dict[str, Any]) -> dict[str, Any]:
        """Return the source record retained in canonical provenance.

        Adapters may attach parser-only context while mapping nested formats.
        Such context must be retained in provider metadata, not mistaken for
        an unmapped source field or a runtime dependency.
        """
        return record

    def map_record(self, record: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str], list[str], list[str], float, dict[str, Any]]:
        normalized_record = normalize_xml_leaf_scalars(record)
        record = normalized_record if isinstance(normalized_record, dict) else {"#text": normalized_record}
        if record.get("_aegis_duplicate_keys") or record.get("_aegis_duplicate_headers"):
            raise ValueError("semantic validation failed: duplicate source keys/headers require explicit mapping review")
        values: dict[str, Any] = {}
        paths: dict[str, str] = {}
        source_aliases = dict(ALIASES)
        source_aliases.update(self.aliases)
        # Trident's mapping path is retained, but index this record once so
        # the same safe alias semantics scale to a million JSONL rows.
        field_index = self.mapping_index(record)
        for field, aliases in source_aliases.items():
            # Occurrence identity is record-level semantics.  A nested
            # ``asset.id`` or ``vulnerability.id`` is not an occurrence ID,
            # and choosing it through a generic leaf search makes identity
            # depend on object key order.  Provider adapters may opt in to a
            # documented nested occurrence path explicitly.
            lookup_index = (field_index[0], {}) if field == "source_record_id" else field_index
            value, path = get_indexed_value(lookup_index, aliases)
            if path is not None:
                values[field] = value
                paths[field] = path
        warnings: list[str] = []
        if record.get("_aegis_csv_extra_columns"):
            warnings.append("CSV row contains extra columns; preserved as opaque source data")
        if record.get("_aegis_duplicate_keys"):
            warnings.append("duplicate JSON keys detected; original pairs preserved as opaque source data")
        if record.get("_aegis_duplicate_headers"):
            warnings.append("duplicate CSV headers detected; original pairs preserved as opaque source data")
        valid_cves = extract_identifiers(values.get("cve"))[1]
        if values.get("cve") and not valid_cves:
            warnings.append("vulnerability value is not a valid CVE; source value preserved")
            values.pop("cve", None)
            paths.pop("cve", None)
        elif valid_cves:
            values["cve"] = valid_cves
        placeholders = {"", "none", "null", "unknown", "n/a", "na", "not available", "not_applicable", "placeholder", "record", "0", "-"}
        if normalize_text(values.get("source_record_id")).lower() in placeholders:
            values.pop("source_record_id", None)
            paths.pop("source_record_id", None)
        if not values.get("source_record_id") and (values.get("cve") or values.get("vulnerability_identifier")):
            warnings.append("provider occurrence identifier unavailable; import-instance identity uses the source pointer")
        if not values.get("source_record_id") and not values.get("cve") and not values.get("vulnerability_identifier"):
            warnings.append("required vulnerability identity is missing")
        if not values.get("title") and not values.get("cve"):
            warnings.append("title and vulnerability identifier are missing")
        if not values.get("asset_id") and not values.get("hostname") and not values.get("ip"):
            warnings.append("asset identity is missing")
        if not values.get("severity") and not values.get("cvss_score"):
            warnings.append("source severity and CVSS score are missing")
        all_fields = {path for path, value in self._flat(record) if not isinstance(value, (dict, list))}
        mapped_fields = set(paths.values())
        unmapped = sorted(path for path in all_fields if path not in mapped_fields and path not in {"_xml_tag"})
        confidence = 1.0
        if warnings:
            confidence = max(0.55, 1.0 - 0.12 * len(warnings))
        provider_metadata = {
            "contract_version": self.contract_version,
            "supported_variant_contracts": list(self.supported_variants),
            **{field: values.get(field) for field in self.native_fields if values.get(field) not in (None, "", [], {})},
        }
        for field, aliases in self.aliases.items():
            value, path = get_indexed_value(field_index, aliases)
            if path is not None:
                provider_metadata[field] = json_safe(value)
        source_identifiers: dict[str, Any] = {}
        for alias in source_aliases.get("source_record_id", ()):
            value, path = get_indexed_value((field_index[0], {}), (alias,))
            if path is not None and normalize_text(value) and normalize_text(value).lower() not in placeholders:
                source_identifiers[path] = json_safe(value)
        # Preserve provider vulnerability/plugin/QID identifiers as secondary
        # evidence without allowing them to become source occurrence IDs.
        for key, value in record.items():
            compact = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if compact in {"qid", "uniquevulnid", "pluginid", "vulnerabilityid", "vulnid"} or "vulnerabilityid" in compact:
                if normalize_text(value) and normalize_text(value).lower() not in placeholders:
                    source_identifiers.setdefault(str(key), json_safe(value))
        if source_identifiers:
            provider_metadata["source_identifiers"] = source_identifiers
            # Secondary provider identifiers are deliberately retained as
            # metadata, so they are mapped evidence rather than unknown data.
            # This matters when the selected occurrence ID wins the primary
            # alias but a plugin/QID/vulnerability ID is also present.
            unmapped = [field for field in unmapped if field not in source_identifiers]
        invalid_marker = False
        for key, value in self._flat(record):
            compact = re.sub(r"[^a-z0-9]", "", str(key).lower())
            text = normalize_text(value).lower()
            if compact == "isvalid":
                # `isValid=true` is affirmative evidence.  Only an explicit
                # false/invalid value marks a record semantically invalid.
                invalid_marker = invalid_marker or text in {"false", "no", "0", "invalid", "malformed"} or value is False
            elif compact in {"invalidrecordtype", "malformed", "malformedrecord"}:
                invalid_marker = invalid_marker or text in {"true", "yes", "1", "invalid", "malformed"} or value is True
        title_text = normalize_text(values.get("title")).lower()
        if "malformed" in title_text or "invalid record" in title_text:
            invalid_marker = True
        if invalid_marker:
            warnings.append("record contains an explicit malformed/invalid marker")
        return values, paths, warnings, unmapped, confidence, provider_metadata

    @staticmethod
    def mapping_index(record: dict[str, Any]) -> tuple[dict[str, tuple[Any, str]], dict[str, tuple[Any, str]]]:
        """Return the bounded field index used by shared alias mapping.

        Vendor adapters use documented nested paths in their own mapping
        methods. Generic JSON overrides this hook so unknown nested metadata
        cannot be promoted through recursive leaf-name matching.
        """
        return index_fields(record)

    @staticmethod
    def finalize_mapping_diagnostics(values: dict[str, Any], warnings: list[str], confidence: float) -> tuple[list[str], float]:
        """Recompute generic diagnostics after provider-specific mapping.

        Provider adapters intentionally add fields from documented nested
        paths after the shared mapper runs.  Diagnostics produced before that
        step are provisional and must not claim that evidence is missing once
        the adapter has supplied it.
        """
        warnings = list(dict.fromkeys(warnings))
        valid_cves = extract_identifiers(values.get("cve"))[1]
        has_vulnerability = bool(valid_cves or normalize_text(values.get("vulnerability_identifier")))
        has_title = bool(normalize_text(values.get("title")))
        has_target = has_target_identity(values)
        has_severity = bool(normalize_text(values.get("severity")) or values.get("cvss_score") not in (None, ""))
        conditions = {
            "provider occurrence identifier unavailable; import-instance identity uses the source pointer": bool(values.get("source_record_id")),
            "required vulnerability identity is missing": has_vulnerability,
            "title and vulnerability identifier are missing": has_title or has_vulnerability,
            "asset identity is missing": has_target,
            "source severity and CVSS score are missing": has_severity,
        }
        warnings = [warning for warning in warnings if not conditions.get(warning, False)]
        if warnings:
            confidence = max(0.55, 1.0 - 0.12 * len(warnings))
        else:
            confidence = 1.0
        return warnings, confidence

    @staticmethod
    def _flat(record: dict[str, Any]):
        def walk(value: Any, prefix: str = ""):
            if isinstance(value, dict):
                for key, child in value.items():
                    path = f"{prefix}.{key}" if prefix else str(key)
                    yield path, child
                    yield from walk(child, path)
        return walk(record)

    def normalize(self, record: dict[str, Any], *, pointer: str, report_sha256: str,
                  source_type: str = "file", source_record_id: str | None = None,
                  mapping_confidence: float | None = None) -> dict[str, Any]:
        normalized_record = normalize_xml_leaf_scalars(record)
        record = normalized_record if isinstance(normalized_record, dict) else {"#text": normalized_record}
        if len(json.dumps(record, ensure_ascii=False, default=str).encode("utf-8")) > MAX_RECORD_BYTES:
            raise ValueError(f"record exceeds {MAX_RECORD_BYTES} bytes")
        values, paths, warnings, unmapped, confidence, provider_metadata = self.map_record(record)
        warnings, confidence = self.finalize_mapping_diagnostics(values, warnings, confidence)
        unmapped = [field for field in unmapped if field not in set(paths.values())]
        vulnerability_value = normalize_text(values.get("vulnerability_identifier"))
        cve_value = extract_identifiers(values.get("cve"))[1]
        placeholders = {"", "none", "null", "unknown", "n/a", "na", "not available", "not_applicable", "placeholder", "record", "0", "-"}
        if (not cve_value and vulnerability_value.lower() in placeholders):
            raise ValueError("missing required vulnerability identity: provide a validated CVE or provider vulnerability/detection identifier")
        if not has_target_identity(values):
            raise ValueError("missing required target identity: provide a hostname, FQDN, valid IP, or provider-native asset/device ID")
        if any("explicit malformed/invalid marker" in warning for warning in warnings):
            raise ValueError("semantic validation failed: record contains an explicit malformed/invalid marker")
        source_id = normalize_text(source_record_id or values.get("source_record_id")) or None
        return make_finding(
            provider=self.name, source_type=source_type, source_record_id=source_id,
            report_sha256=report_sha256, pointer=pointer, record=self.output_record(record), values=values,
            paths=paths, mapping_confidence=mapping_confidence if mapping_confidence is not None else confidence,
            mapping_version=self.mapping_version, warnings=warnings, unmapped_fields=unmapped,
            provider_metadata=provider_metadata,
            severity_scale=self.severity_scale,
        )


def available_adapters() -> list[str]:
    return ["tenable", "qualys", "rapid7", "defender", "crowdstrike", "nessus", "generic_json", "generic_csv"]


def adapter_for(name: str) -> ProviderAdapter:
    from aegis.providers.crowdstrike import CrowdStrikeAdapter
    from aegis.providers.defender import DefenderAdapter
    from aegis.providers.generic_csv import GenericCSVAdapter
    from aegis.providers.generic_json import GenericJSONAdapter
    from aegis.providers.nessus import NessusAdapter
    from aegis.providers.qualys import QualysAdapter
    from aegis.providers.rapid7 import Rapid7Adapter
    from aegis.providers.tenable import TenableAdapter
    adapters = {
        "tenable": TenableAdapter, "qualys": QualysAdapter, "rapid7": Rapid7Adapter,
        "defender": DefenderAdapter, "microsoft_defender": DefenderAdapter,
        "crowdstrike": CrowdStrikeAdapter, "nessus": NessusAdapter,
        "generic_json": GenericJSONAdapter, "generic_csv": GenericCSVAdapter,
    }
    try:
        return adapters[name.lower().replace("-", "_")]()
    except KeyError as exc:
        raise ValueError(f"unsupported provider adapter: {name}") from exc
