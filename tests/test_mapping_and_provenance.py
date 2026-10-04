from __future__ import annotations

import pytest

from aegis.ingest.contracts import RecordAccounting
from aegis.ingest.mapping import MappingError, apply_mapping, select, validate_mapping
from aegis.provenance import csv_provenance, join_pointer, pointer_get, provenance_envelope


def test_trident_derived_selector_is_bounded_and_preserves_pointers():
    payload = {"results": [{"name": "one"}, {"name": "two"}]}
    selected = select(payload, "$.results[*].name")
    assert [(item.value, item.pointer) for item in selected] == [("one", "/results/0/name"), ("two", "/results/1/name")]
    assert pointer_get(payload, join_pointer("/results", 1)) == {"name": "two"}
    with pytest.raises(MappingError):
        select(payload, "$.results[*].name; import os")


def test_mapping_validation_and_application_are_deterministic():
    mapping = {"mapping_version": "aegis-json-mapping-v1", "name": "fixture", "records": "$.items[*]",
               "fields": {"title": "$.title", "cve": "$.cve", "asset_id": "$.asset"}}
    validate_mapping(mapping)
    rows = apply_mapping({"items": [{"title": "x", "cve": "CVE-2024-1", "asset": "a"}]}, mapping)
    assert rows[0]["title"] == "x"
    assert rows[0]["_record_pointer"] == "/items/0"
    assert rows[0]["_title_pointer"] == "/items/0/title"
    with pytest.raises(MappingError):
        validate_mapping({**mapping, "mapping_version": "wrong"})


def test_record_accounting_enforces_one_terminal_state():
    accounting = RecordAccounting()
    accounting.add("mapped", "/0")
    accounting.add("malformed", "/1", reason="bad row")
    assert accounting.as_dict()["unexplained"] == 0
    assert accounting.as_dict()["total_records"] == 2
    with pytest.raises(ValueError):
        accounting.add("unknown", "/2")


def test_provenance_has_rfc_pointer_and_report_identity():
    assert csv_provenance(2, "CVE/ID", "CVE-2024-1")["pointer"] == "/rows/2/columns/CVE~1ID"
    envelope = provenance_envelope(report_sha256_value="abc", record_pointer="/1", mapping_identity="m", fields={}, source_format="json")
    assert envelope["report_sha256"] == "abc"
