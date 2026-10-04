"""Evidence contract adapted from Trident's evidence envelope.

Evidence is data, not a model instruction: source records remain untrusted,
provider signals remain independent, and missing context is explicit.
"""

from __future__ import annotations

import json
from typing import Any


def evidence_basis(*, has_original_record: bool, has_field_provenance: bool, source_type: str) -> str:
    if has_original_record and has_field_provenance:
        return "scanner_and_source" if source_type in {"api", "provider_api"} else "source_grounded"
    if has_original_record:
        return "report_only"
    return "unresolved"


def untrusted_prompt_payload(finding: dict[str, Any]) -> str:
    """Serialize evidence as a clearly delimited untrusted JSON object."""
    payload = {"finding_id": finding.get("id"), "source": finding.get("source"),
               "vulnerability": finding.get("vulnerability"), "asset": finding.get("asset"),
               "evidence": finding.get("evidence"), "original_record": (finding.get("source_metadata") or {}).get("original_record")}
    return "UNTRUSTED_EVIDENCE_JSON\n" + json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str) + "\nEND_UNTRUSTED_EVIDENCE_JSON"
